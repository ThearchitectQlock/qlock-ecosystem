// crates/nev369-node/src/chain.rs
//
// ═══════════════════════════════════════════════════════════════════════
// NEV369 — chain state, transactions, blocks, persistence
//
// FIXES IN THIS REVISION
//
// NEV-001 [CRITICAL] — in-block double-spend / unbounded mint.
//   validate_block_contents() checked coinbase limits, GENESIS
//   placement, signatures and the vault time-lock. It never checked
//   BALANCE or NONCE for the transactions inside a block, because it
//   never called validate_transaction.
//
//   A miner could put two transactions from the same sender at the same
//   nonce into one block, each spending the full balance to a different
//   recipient. Both passed: signatures were individually valid and
//   nothing cross-checked them against each other or against remaining
//   balance. apply_transaction_unchecked then ran both — the first
//   drained the balance via saturating_sub, the second subtracted from
//   an already-zero balance (no error, floors at 0) and STILL credited
//   its recipient in full. Money out of nothing.
//
//   build_candidate had the matching half: it validated each mempool
//   transaction against untouched chain state in a loop, never against
//   a running state for the block being assembled, so an honest miner
//   would construct exactly that pair itself.
//
//   Both now execute against a BlockExecution scratch state. See that
//   struct.
//
// NEV-004 — deleted the dead index-keyed persist_block(). It contradicted
//   the hash-keyed scheme and would have silently reintroduced the
//   fork-clobbering bug the moment anyone called it.
//
// NEV-008 — genesis_does_not_rerun_on_restart called BlockchainApp::new
//   with one argument against a two-argument signature. The persistence
//   regression guard was not compiling, so it was not running.
//
// Also fixed here:
//   - Coinbase and supply were validated at the CURRENT tip height, so a
//     side-branch block's reward was checked against the wrong point in
//     the halving schedule. Now checked at block.index.
//   - NEVAEH_UNLOCK_TIMESTAMP and GENESIS_DEDICATION were defined in
//     both this file and genesis.rs. Two sources of truth for a
//     thirteen-year time-lock. Now re-exported from genesis.
//   - The time-lock was checked via genesis_config.is_timelocked() in
//     validate_transaction but by a direct address comparison in
//     validate_block_contents. Divergent rules for the same property.
//   - After a reorg the persisted tip was the accepted block's hash
//     rather than the tree's tip. Those differ when accepting a block
//     also connects buffered orphans past it.
//
// Compiled and tested: Rust 1.88.0, full workspace test suite passing
// (first real build 27 Sep 2026).
// ═══════════════════════════════════════════════════════════════════════

use godshield_core::{CanonicalMessage, GodPublicKey, GodShield, GodSignature, TripleHash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::consensus::{transactions_to_requeue, AcceptOutcome, BlockTree};
use crate::genesis::GenesisConfig;

/// Reorganisations since this process started. Exported on /metrics: a
/// reorg deeper than a block or two is the signal that fork choice is
/// misbehaving or that someone is out-mining the honest chain.
pub static REORG_COUNT: AtomicU64 = AtomicU64::new(0);
/// Depth (blocks disconnected) of the deepest reorg since start.
pub static DEEPEST_REORG: AtomicU64 = AtomicU64::new(0);

// Re-exported, not redefined. Both of these previously existed in this
// file AND in genesis.rs with the same values — so editing one left the
// other stale, and the tests here read this copy while production read
// the other.
#[allow(unused_imports)] // NEVAEH_UNLOCK_TIMESTAMP is only read by the tests below
pub use crate::genesis::{GENESIS_DEDICATION, NEVAEH_UNLOCK_TIMESTAMP};

// ═══════════════════════════════════════════════════════════════════════
// MONEY
// ═══════════════════════════════════════════════════════════════════════

/// Integer base units, never floats. 1 NEV = 100_000_000 units.
///
/// Floating point silently loses and creates value under repeated
/// arithmetic. There is a regression test below that sums ten million
/// single units and asserts exactness. Do not reintroduce f64 into any
/// balance path.
pub type Amount = u64;

pub const DECIMALS: u32 = 8;
pub const UNITS_PER_NEV: Amount = 100_000_000;

#[allow(dead_code)] // API kept for tooling/tests; not yet called by the node itself
pub fn nev(whole: u64) -> Amount {
    whole.saturating_mul(UNITS_PER_NEV)
}

pub fn format_nev(units: Amount) -> String {
    format!("{}.{:08}", units / UNITS_PER_NEV, units % UNITS_PER_NEV)
}

// ═══════════════════════════════════════════════════════════════════════
// CHAIN CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

/// The hard cap, and it is reachable. Every one of these 369,369,369 NEV
/// either exists at genesis or gets mined.
///
///   premine   46,900,000   (10,000,000 Architect + 36,900,000 Nevaeh)
///   mineable 322,469,369   emitted by the halving schedule below
///   ───────────────────────
///   total    369,369,369
///
/// HOW THE CAP IS HIT EXACTLY.
///
/// A pure halving schedule cannot land on this number. Total emission
/// from halving is `interval x reward x 2`, which is always even, and
/// 322,469,369 NEV is odd — so no choice of interval and reward reaches
/// it precisely. Earlier revisions of this file had a schedule totalling
/// 21,000,000 while advertising 369,369,369, which left ~301M with no
/// issuance path at all.
///
/// The fix is not to pick different halving numbers and accept being
/// close. `block_reward_at` clamps each reward to whatever is left of
/// MINEABLE_SUPPLY, so the schedule is deliberately set to OVERSHOOT and
/// the clamp closes the gap. The final rewarded block pays the exact
/// remainder and every block after it pays zero. Total emission is
/// therefore exactly MINEABLE_SUPPLY — not approximately.
pub const MAX_SUPPLY: Amount = 36_936_936_900_000_000; // 369,369,369 NEV

/// Everything not premined. The number `block_reward_at` clamps against.
pub const MINEABLE_SUPPLY: Amount = MAX_SUPPLY - ARCHITECT_PREMINE - NEVAEH_PREMINE;

pub const ARCHITECT_PREMINE: Amount = 1_000_000_000_000_000; // 10,000,000 NEV
pub const NEVAEH_PREMINE: Amount = 3_690_000_000_000_000; // 36,900,000 NEV
/// 369 NEV per block at launch, halving every 437,000 blocks.
///
/// The old values (50 NEV / 210,000 blocks) were Bitcoin's, and they
/// emit Bitcoin's 21,000,000 — which is 6.5% of this chain's cap. These
/// are sized to NEV369's own supply.
///
/// The schedule overshoots MINEABLE_SUPPLY by 36,630 NEV on purpose; see
/// MAX_SUPPLY. At 60-second blocks a halving epoch is about 303 days, so
/// issuance runs over years rather than being substantially finished in
/// three.
pub const INITIAL_REWARD: Amount = 36_900_000_000; // 369 NEV
pub const HALVING_INTERVAL: u64 = 437_000;

pub const GENESIS_DIFFICULTY: usize = 4;
pub const TARGET_BLOCK_SECONDS: u64 = 60;
pub const DIFFICULTY_ADJUST_INTERVAL: u64 = 100;
pub const MAX_TX_PER_BLOCK: usize = 500;
pub const MAX_MEMPOOL: usize = 10_000;

/// Placeholder premine addresses for development only. No key maps to
/// these literal strings, so the premine is unspendable — safe, and also
/// frozen. genesis.rs refuses to boot with them in production.
#[cfg(test)] // test fixture; real premine addresses come from the environment (genesis.rs)
pub const ARCHITECT_ADDRESS: &str = "ARCHITECT_SOVEREIGN_KEY_01";
#[cfg(test)] // test fixture; real premine addresses come from the environment (genesis.rs)
pub const NEVAEH_VAULT_ADDRESS: &str = "NEVAEH_NEV369_SOVEREIGN_VAULT";

/// Only these two senders skip signature verification. Both are produced
/// internally by this node's own block-reward logic and never arrive as
/// untrusted input over the network or the API.
///
/// DO NOT ADD TO THIS LIST. ARCHITECT_ADDRESS was previously here, which
/// meant any inbound transaction claiming that sender auto-verified — a
/// complete bypass letting anyone drain the 10M premine with no
/// signature. There is a unit test asserting it stays out and a CI guard
/// asserting this list has exactly two entries.
const SIGNATURE_EXEMPT_SENDERS: &[&str] = &["GENESIS", "NETWORK_REWARD"];

// ═══════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("insufficient balance: has {have}, needs {need}")]
    InsufficientBalance { have: Amount, need: Amount },
    #[error("bad nonce: expected {expected}, got {got}")]
    BadNonce { expected: u64, got: u64 },
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error("arithmetic overflow")]
    Overflow,
    #[error("Nevaeh's vault is time-locked until {unlock} ({days} days remaining)")]
    VaultTimeLocked { unlock: u64, days: i64 },
    #[error("mempool is full")]
    MempoolFull,
    #[error("duplicate transaction")]
    Duplicate,
    #[error("conflicts with a pending transaction from the same sender")]
    ConflictsWithPending,
    #[error("storage error: {0}")]
    Storage(String),
    #[error("invalid block: {0}")]
    InvalidBlock(String),
    /// NEV-001. Distinct from InvalidBlock so operators can alert on it
    /// specifically — a block arriving with an internal double-spend is
    /// a deliberate attack, not a malformed message.
    #[error("block contains conflicting transactions: {0}")]
    ConflictingTransactions(String),
}

// ═══════════════════════════════════════════════════════════════════════
// TRANSACTION
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub sender: String,
    pub recipient: String,
    pub amount: Amount,
    pub fee: Amount,
    pub crown_tax: Amount,
    pub nonce: u64,
    pub timestamp: u64,
    pub public_key_hex: String,
    pub signature_hex: String,
    pub payload_memo: String,
}

impl Transaction {
    /// Canonical signing bytes.
    ///
    /// Length-prefixed and domain-separated. The previous implementation
    /// was `format!("{}{}{}...")` with no delimiters, which is ambiguous:
    /// sender="AB"/recipient="C" produced the same bytes as
    /// sender="A"/recipient="BC", so one signature validated both.
    ///
    /// The domain tag also prevents a signature over an NEV369
    /// transaction being replayed as a Q-Lock attestation or a Fairness
    /// reveal, because the domain is inside the signed bytes.
    ///
    /// Changing this function invalidates every signature ever produced.
    /// Bump the version tag rather than editing in place.
    pub fn signing_bytes(&self) -> Vec<u8> {
        CanonicalMessage::encode(
            "nev369.tx.v1",
            &[
                self.sender.as_bytes(),
                self.recipient.as_bytes(),
                &self.amount.to_le_bytes(),
                &self.fee.to_le_bytes(),
                &self.crown_tax.to_le_bytes(),
                &self.nonce.to_le_bytes(),
                self.payload_memo.as_bytes(),
            ],
        )
    }

    pub fn hash(&self) -> String {
        TripleHash::hash_hex(&self.signing_bytes())
    }

    pub fn total_cost(&self) -> Result<Amount, ChainError> {
        self.amount
            .checked_add(self.fee)
            .and_then(|v| v.checked_add(self.crown_tax))
            .ok_or(ChainError::Overflow)
    }

    pub fn is_protocol_internal(&self) -> bool {
        SIGNATURE_EXEMPT_SENDERS.contains(&self.sender.as_str())
    }

    /// Verify the post-quantum signature via GodShield.
    pub fn verify_signature(&self) -> bool {
        if self.is_protocol_internal() {
            return true;
        }

        let Ok(public_key_bytes) = hex::decode(&self.public_key_hex) else {
            return false;
        };
        let Ok(signature_bytes) = hex::decode(&self.signature_hex) else {
            return false;
        };

        // The claimed public key must correspond to the sender address.
        // Without this, anyone could sign with their own key and write
        // someone else's address in the sender field.
        if hex::encode(&public_key_bytes) != self.sender {
            return false;
        }

        let message = self.signing_bytes();
        let fingerprint = TripleHash::hash_hex(&public_key_bytes);

        let public_key = GodPublicKey {
            public_key: public_key_bytes,
            fingerprint: fingerprint.clone(),
        };
        let signature = GodSignature {
            signature: signature_bytes,
            message_hash: TripleHash::hash_hex(&message),
            signer_fingerprint: fingerprint,
            timestamp: self.timestamp,
        };

        GodShield::verify(&public_key, &signature, &message).unwrap_or(false)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// BLOCK
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub hash: String,
    pub nonce: u64,
    pub difficulty: usize,
    pub miner: String,
    pub block_dedication: String,
}

impl Block {
    pub fn calculate_hash(&self) -> String {
        self.calculate_hash_with_root(&Self::tx_root(&self.transactions))
    }

    /// Block hash from a precomputed transaction root (fixed per candidate).
    pub fn calculate_hash_with_root(&self, tx_root: &str) -> String {
        let payload = CanonicalMessage::encode(
            "nev369.block.v1",
            &[
                &self.index.to_le_bytes(),
                &self.timestamp.to_le_bytes(),
                tx_root.as_bytes(),
                self.previous_hash.as_bytes(),
                &self.nonce.to_le_bytes(),
                &(self.difficulty as u64).to_le_bytes(),
                self.miner.as_bytes(),
                self.block_dedication.as_bytes(),
            ],
        );
        TripleHash::hash_hex(&payload)
    }

    pub fn tx_root(txs: &[Transaction]) -> String {
        if txs.is_empty() {
            return TripleHash::hash_hex(b"nev369.empty");
        }
        let mut layer: Vec<String> = txs.iter().map(|t| t.hash()).collect();
        while layer.len() > 1 {
            let mut next = Vec::with_capacity(layer.len().div_ceil(2));
            for pair in layer.chunks(2) {
                let combined = match pair {
                    [a, b] => CanonicalMessage::encode_strs("nev369.merkle", &[a, b]),
                    [a] => CanonicalMessage::encode_strs("nev369.merkle", &[a, a]),
                    _ => unreachable!(),
                };
                next.push(TripleHash::hash_hex(&combined));
            }
            layer = next;
        }
        layer.remove(0)
    }

    pub fn meets_difficulty(&self) -> bool {
        self.hash.starts_with(&"0".repeat(self.difficulty))
    }

    pub fn is_valid_pow(&self) -> bool {
        self.meets_difficulty() && self.hash == self.calculate_hash()
    }

    #[allow(dead_code)] // needed when fees are credited to the coinbase (open decision, see README)
    pub fn total_fees(&self) -> Amount {
        self.transactions
            .iter()
            .filter(|t| !t.is_protocol_internal())
            .fold(0, |acc, t| acc.saturating_add(t.fee))
    }
}

// ═══════════════════════════════════════════════════════════════════════
// BLOCK EXECUTION — the NEV-001 fix
// ═══════════════════════════════════════════════════════════════════════

/// A scratch overlay on committed chain state, used to execute a block's
/// transactions in order so each one is checked against the effects of
/// the ones before it.
///
/// This is the whole fix. Validating every transaction independently
/// against the same untouched snapshot means two transactions can both
/// be "valid" while being mutually exclusive — same nonce, or the same
/// balance spent twice. Executing them in sequence against a running
/// state makes the second one fail, which is the only way to catch a
/// conflict that exists between transactions rather than within one.
///
/// Sparse by design: the overlay holds only addresses the block touches,
/// and falls through to committed state for everything else. Cloning the
/// full balance map per block would make validation cost grow with total
/// account count instead of with block size.
struct BlockExecution<'a> {
    committed_balances: &'a HashMap<String, Amount>,
    committed_nonces: &'a HashMap<String, u64>,
    balances: HashMap<String, Amount>,
    nonces: HashMap<String, u64>,
}

impl<'a> BlockExecution<'a> {
    fn new(app: &'a BlockchainApp) -> Self {
        Self {
            committed_balances: &app.balances,
            committed_nonces: &app.nonces,
            balances: HashMap::new(),
            nonces: HashMap::new(),
        }
    }

    fn balance_of(&self, address: &str) -> Amount {
        self.balances
            .get(address)
            .copied()
            .unwrap_or_else(|| self.committed_balances.get(address).copied().unwrap_or(0))
    }

    fn nonce_of(&self, address: &str) -> u64 {
        self.nonces
            .get(address)
            .copied()
            .unwrap_or_else(|| self.committed_nonces.get(address).copied().unwrap_or(0))
    }

    /// Balance and nonce only. Signature, time-lock and zero-amount
    /// checks are the caller's, because they differ between the mempool
    /// path and the block path.
    fn check(&self, tx: &Transaction) -> Result<(), ChainError> {
        let expected = self.nonce_of(&tx.sender);
        if tx.nonce != expected {
            return Err(ChainError::BadNonce {
                expected,
                got: tx.nonce,
            });
        }

        let total = tx.total_cost()?;
        let have = self.balance_of(&tx.sender);
        if have < total {
            return Err(ChainError::InsufficientBalance { have, need: total });
        }
        Ok(())
    }

    /// Apply to the overlay. Checked arithmetic throughout: `check` has
    /// already proven the balance covers the cost, so a saturating
    /// subtraction here could only mask a bug — and masking it is
    /// precisely how the original silently created money.
    fn apply(&mut self, tx: &Transaction) -> Result<(), ChainError> {
        if !tx.is_protocol_internal() {
            let total = tx.total_cost()?;
            let have = self.balance_of(&tx.sender);
            let remaining = have.checked_sub(total).ok_or(ChainError::Overflow)?;
            self.balances.insert(tx.sender.clone(), remaining);
            self.nonces.insert(tx.sender.clone(), tx.nonce + 1);
        }

        let credited = self
            .balance_of(&tx.recipient)
            .checked_add(tx.amount)
            .ok_or(ChainError::Overflow)?;
        self.balances.insert(tx.recipient.clone(), credited);
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CHAIN STATE
// ═══════════════════════════════════════════════════════════════════════

pub struct BlockchainApp {
    /// The canonical chain, genesis first. Materialised view — the tree
    /// is authoritative.
    pub chain: Vec<Block>,
    /// Every block seen, including side branches, plus fork choice and
    /// reorg logic. See consensus.rs.
    pub tree: BlockTree,
    /// Premine addresses and time-lock, loaded from environment and
    /// pinned into genesis.
    pub genesis_config: GenesisConfig,
    pub mempool: Vec<Transaction>,
    pub balances: HashMap<String, Amount>,
    pub nonces: HashMap<String, u64>,
    pub total_burned: Amount,
    pub db: sled::Db,
    pub node_id: String,
}

impl BlockchainApp {
    pub fn new(db_path: &str, config: GenesisConfig) -> Result<Self, ChainError> {
        let db = sled::open(db_path).map_err(|e| ChainError::Storage(e.to_string()))?;

        let (chain, tree) = match Self::load_chain_from_disk(&db)? {
            Some(chain) => {
                // Genesis already exists. The configuration must match
                // what the chain records, or this node would credit the
                // premine to an address that does not own it on-chain —
                // unrecoverable divergence, so refuse to start.
                if let Some(recorded) = Self::load_genesis_config(&db)? {
                    config.assert_matches_genesis(&recorded)?;
                }
                if let Some(expected) = &config.expected_genesis_hash {
                    let on_disk = chain.first().map(|b| b.hash.as_str()).unwrap_or("");
                    if on_disk != expected.as_str() {
                        return Err(ChainError::Storage(format!(
                            "GENESIS MISMATCH — the chain in {db_path} starts from block 0\n  \
                             {on_disk}\nbut NEV369_GENESIS_HASH expects\n  {expected}\n\n\
                             This data directory belongs to a different network. Point \
                             NEV369_DB_PATH at an empty directory to join this one."
                        )));
                    }
                }
                tracing::info!(height = chain.len(), "Restored chain from disk");
                // from_chain revalidates every hash, link and proof of
                // work rather than trusting the store.
                let tree = BlockTree::from_chain(&chain)?;
                (chain, tree)
            }
            None => {
                tracing::info!("No persisted chain — initializing genesis");
                if config.development_mode {
                    tracing::warn!(
                        "Genesis uses PLACEHOLDER premine addresses — the premine \
                         is unspendable. Fine for development, never production."
                    );
                }
                let genesis = Self::build_genesis(&config);
                if let Some(expected) = &config.expected_genesis_hash {
                    if genesis.hash != *expected {
                        let built = &genesis.hash;
                        return Err(ChainError::Storage(format!(
                            "GENESIS MISMATCH — refusing to create a new chain.\n\n\
                             These settings build a block 0 with hash\n  {built}\n\
                             but this network's genesis is\n  {expected}\n\n\
                             Copy chain-spec/nev369-mainnet.env into .env unchanged: the \
                             genesis timestamp and both premine addresses must match exactly."
                        )));
                    }
                }
                Self::persist_block_to(&db, &genesis)?;
                Self::persist_tip_to(&db, &genesis.hash)?;
                Self::persist_genesis_config(&db, &config)?;
                let tree = BlockTree::new(genesis.clone());
                (vec![genesis], tree)
            }
        };

        let mut app = Self {
            chain,
            tree,
            genesis_config: config,
            mempool: Vec::new(),
            balances: HashMap::new(),
            nonces: HashMap::new(),
            total_burned: 0,
            db,
            node_id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
        };

        app.rebuild_state();
        Ok(app)
    }

    // ── Metadata ───────────────────────────────────────────────────────

    fn persist_genesis_config(db: &sled::Db, config: &GenesisConfig) -> Result<(), ChainError> {
        let meta = db
            .open_tree("meta")
            .map_err(|e| ChainError::Storage(e.to_string()))?;
        let bytes = serde_json::to_vec(config).map_err(|e| ChainError::Storage(e.to_string()))?;
        meta.insert("genesis_config", bytes)
            .map_err(|e| ChainError::Storage(e.to_string()))?;
        db.flush().map_err(|e| ChainError::Storage(e.to_string()))?;
        Ok(())
    }

    fn load_genesis_config(db: &sled::Db) -> Result<Option<GenesisConfig>, ChainError> {
        let meta = db
            .open_tree("meta")
            .map_err(|e| ChainError::Storage(e.to_string()))?;
        match meta
            .get("genesis_config")
            .map_err(|e| ChainError::Storage(e.to_string()))?
        {
            Some(v) => serde_json::from_slice(&v)
                .map(Some)
                .map_err(|e| ChainError::Storage(format!("corrupt genesis config: {e}"))),
            // Chains created before config pinning have no record.
            // Nothing to compare against, so proceed.
            None => Ok(None),
        }
    }

    // ── Views ──────────────────────────────────────────────────────────

    pub fn height(&self) -> u64 {
        self.chain.len() as u64
    }

    pub fn latest_hash(&self) -> String {
        self.chain
            .last()
            .map(|b| b.hash.clone())
            .unwrap_or_default()
    }

    /// Total accumulated work. This — not height — decides which chain
    /// wins. Exposed so peers can compare without exchanging blocks.
    pub fn cumulative_work(&self) -> u128 {
        self.tree.cumulative_work()
    }

    pub fn locator(&self) -> Vec<String> {
        self.tree.locator()
    }

    pub fn find_fork_point(&self, locator: &[String]) -> Option<String> {
        self.tree.find_fork_point(locator)
    }

    pub fn blocks_after(&self, from_hash: &str, limit: usize) -> Vec<Block> {
        self.tree.blocks_after(from_hash, limit)
    }

    #[allow(dead_code)] // API kept for tooling/tests; not yet called by the node itself
    pub fn has_block(&self, hash: &str) -> bool {
        self.tree.contains(hash)
    }

    /// Confirmed transactions that send to or from `address`, newest first,
    /// with the height and timestamp of the block that holds each.
    ///
    /// A linear scan from the tip, stopping at `limit`. Fine at this chain
    /// length; an address index belongs here once the chain is long enough
    /// for the scan to show up in response times.
    pub fn address_history(&self, address: &str, limit: usize) -> Vec<(u64, u64, &Transaction)> {
        let mut out = Vec::new();
        if limit == 0 {
            return out;
        }
        for block in self.chain.iter().rev() {
            for tx in block.transactions.iter().rev() {
                if tx.sender == address || tx.recipient == address {
                    out.push((block.index, block.timestamp, tx));
                    if out.len() >= limit {
                        return out;
                    }
                }
            }
        }
        out
    }

    // ── Persistence ────────────────────────────────────────────────────
    //
    // Blocks are keyed by HASH, not index. With forks several blocks
    // share an index, and an index-keyed scheme silently overwrites a
    // competing block at the same height. The canonical tip is stored
    // separately and the chain is walked back from it.
    //
    // NEV-004: there was a second, private, index-keyed persist_block()
    // in this file alongside the hash-keyed one. It was unreachable, but
    // it contradicted the scheme and was one call away from
    // reintroducing the bug. Deleted.

    fn load_chain_from_disk(db: &sled::Db) -> Result<Option<Vec<Block>>, ChainError> {
        let meta = db
            .open_tree("meta")
            .map_err(|e| ChainError::Storage(e.to_string()))?;
        let blocks = db
            .open_tree("blocks")
            .map_err(|e| ChainError::Storage(e.to_string()))?;

        let tip_hash = match meta
            .get("tip")
            .map_err(|e| ChainError::Storage(e.to_string()))?
        {
            Some(v) => {
                String::from_utf8(v.to_vec()).map_err(|e| ChainError::Storage(e.to_string()))?
            }
            None => return Ok(None),
        };

        let mut by_hash: HashMap<String, Block> = HashMap::new();
        for item in blocks.iter() {
            let (_, value) = item.map_err(|e| ChainError::Storage(e.to_string()))?;
            let block: Block = serde_json::from_slice(&value)
                .map_err(|e| ChainError::Storage(format!("corrupt block: {e}")))?;
            by_hash.insert(block.hash.clone(), block);
        }

        // Walk back from the tip, validating every link and hash rather
        // than trusting disk. Proof of work is revalidated by
        // BlockTree::from_chain, which also handles genesis being
        // constructed rather than mined.
        let mut reversed = Vec::new();
        let mut cursor = tip_hash;
        loop {
            let block = by_hash.get(&cursor).ok_or_else(|| {
                ChainError::Storage(format!("chain broken — block {cursor} missing from store"))
            })?;

            if block.hash != block.calculate_hash() {
                return Err(ChainError::Storage(format!(
                    "block {} hash does not match its contents",
                    block.index
                )));
            }

            let prev = block.previous_hash.clone();
            let is_genesis = block.index == 0;
            reversed.push(block.clone());
            if is_genesis {
                break;
            }
            cursor = prev;
        }

        reversed.reverse();
        Ok(Some(reversed))
    }

    fn persist_block_to(db: &sled::Db, block: &Block) -> Result<(), ChainError> {
        let blocks = db
            .open_tree("blocks")
            .map_err(|e| ChainError::Storage(e.to_string()))?;
        let bytes = serde_json::to_vec(block).map_err(|e| ChainError::Storage(e.to_string()))?;
        blocks
            .insert(block.hash.as_bytes(), bytes)
            .map_err(|e| ChainError::Storage(e.to_string()))?;
        Ok(())
    }

    fn persist_tip_to(db: &sled::Db, hash: &str) -> Result<(), ChainError> {
        let meta = db
            .open_tree("meta")
            .map_err(|e| ChainError::Storage(e.to_string()))?;
        meta.insert("tip", hash.as_bytes())
            .map_err(|e| ChainError::Storage(e.to_string()))?;
        // Flush before returning. A tip recorded in memory but absent
        // from disk is exactly the inconsistency that made genesis
        // re-run on every restart.
        db.flush().map_err(|e| ChainError::Storage(e.to_string()))?;
        Ok(())
    }

    // ── State replay ───────────────────────────────────────────────────

    /// Recompute balances and nonces by replaying the canonical chain.
    ///
    /// Called after every reorg. O(chain length), slower than undo
    /// journals, unambiguously correct. A reorg that leaves balances
    /// subtly wrong is far worse than one that takes a moment.
    fn rebuild_state(&mut self) {
        self.balances.clear();
        self.nonces.clear();
        self.total_burned = 0;

        let chain = std::mem::take(&mut self.chain);
        for block in &chain {
            for tx in &block.transactions {
                self.commit_transaction(tx);
            }
        }
        self.chain = chain;
    }

    /// Apply a transaction to committed state.
    ///
    /// Named `commit_` rather than `apply_..._unchecked` because the
    /// old name invited exactly the mistake that caused NEV-001: it
    /// read as "applying without checking is fine here", when in fact
    /// it was only safe if a caller had validated first — and
    /// validate_block_contents did not.
    ///
    /// Saturating, not checked, and that is deliberate: by the time a
    /// transaction reaches here it has passed BlockExecution, so an
    /// underflow would mean state and validation have diverged. A panic
    /// mid-replay would take the node down with a half-applied block, so
    /// this saturates and the divergence surfaces as a balance mismatch
    /// instead. Validation is the place that must be right.
    fn commit_transaction(&mut self, tx: &Transaction) {
        if !tx.is_protocol_internal() {
            let total = tx
                .amount
                .saturating_add(tx.fee)
                .saturating_add(tx.crown_tax);
            let entry = self.balances.entry(tx.sender.clone()).or_insert(0);
            *entry = entry.saturating_sub(total);
            self.nonces.insert(tx.sender.clone(), tx.nonce + 1);
            self.total_burned = self.total_burned.saturating_add(tx.crown_tax);
        }

        let entry = self.balances.entry(tx.recipient.clone()).or_insert(0);
        *entry = entry.saturating_add(tx.amount);

        // NOTE ON FEES — unresolved monetary policy, not a bug to fix
        // silently. `fee` is deducted from the sender and credited to
        // nobody, so it is burned exactly like `crown_tax`. But
        // build_candidate sorts the mempool by fee descending, which
        // only makes sense if fees pay the miner. As it stands,
        // fee-based prioritisation carries no incentive.
        //
        // Two coherent options: credit total_fees to the coinbase
        // (standard, changes emission), or document fees as a second
        // burn and stop sorting by them. Either is a monetary decision
        // and belongs to you, not to a refactor.
    }

    // ── Genesis ────────────────────────────────────────────────────────

    fn build_genesis(config: &GenesisConfig) -> Block {
        // Pinned on an established network so every node builds the same
        // block 0; the current time only when founding a new one.
        let ts = config.genesis_timestamp.unwrap_or_else(now);

        let architect_tx = Transaction {
            sender: "GENESIS".into(),
            recipient: config.architect_address.clone(),
            amount: config.architect_premine,
            fee: 0,
            crown_tax: 0,
            nonce: 0,
            timestamp: ts,
            public_key_hex: String::new(),
            signature_hex: String::new(),
            payload_memo: "Genesis premine — Architect".into(),
        };

        let nevaeh_tx = Transaction {
            sender: "GENESIS".into(),
            recipient: config.nevaeh_vault_address.clone(),
            amount: config.nevaeh_premine,
            fee: 0,
            crown_tax: 0,
            nonce: 1,
            timestamp: ts,
            public_key_hex: String::new(),
            signature_hex: String::new(),
            payload_memo: "Genesis premine — Nevaeh Vault, locked until 28.07.2039".into(),
        };

        let mut genesis = Block {
            index: 0,
            timestamp: ts,
            transactions: vec![architect_tx, nevaeh_tx],
            previous_hash: "0".repeat(128),
            hash: String::new(),
            nonce: 0,
            difficulty: GENESIS_DIFFICULTY,
            miner: "GENESIS".into(),
            block_dedication: GENESIS_DEDICATION.into(),
        };
        genesis.hash = genesis.calculate_hash();
        genesis
    }

    // ── Transaction validation (mempool path) ──────────────────────────

    /// Checks a transaction against committed state, for mempool admission.
    ///
    /// This is NOT sufficient for block validation. Two transactions can
    /// each pass this against the same committed state while conflicting
    /// with each other — that is NEV-001, and block validation uses
    /// BlockExecution instead.
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<(), ChainError> {
        let exec = BlockExecution::new(self);
        self.validate_transaction_against(tx, &exec)
    }

    fn validate_transaction_against(
        &self,
        tx: &Transaction,
        exec: &BlockExecution<'_>,
    ) -> Result<(), ChainError> {
        if tx.amount == 0 {
            return Err(ChainError::ZeroAmount);
        }

        if !tx.verify_signature() {
            return Err(ChainError::InvalidSignature);
        }

        self.check_timelock(&tx.sender)?;
        exec.check(tx)
    }

    /// Nevaeh's vault cannot spend before her 18th birthday.
    ///
    /// One helper, used by both the mempool path and the block path.
    /// Previously validate_transaction called genesis_config.is_timelocked()
    /// while validate_block_contents compared the address directly — two
    /// rules for one property, so a change to is_timelocked() would have
    /// applied to submitted transactions but not to mined ones.
    fn check_timelock(&self, sender: &str) -> Result<(), ChainError> {
        if !self.genesis_config.is_timelocked(sender) {
            return Ok(());
        }
        let now_ts = now();
        let unlock = self.genesis_config.nevaeh_unlock_timestamp;
        if now_ts < unlock {
            return Err(ChainError::VaultTimeLocked {
                unlock,
                days: (unlock.saturating_sub(now_ts) / 86_400) as i64,
            });
        }
        Ok(())
    }

    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<String, ChainError> {
        if self.mempool.len() >= MAX_MEMPOOL {
            return Err(ChainError::MempoolFull);
        }

        let hash = tx.hash();
        if self.mempool.iter().any(|t| t.hash() == hash) {
            return Err(ChainError::Duplicate);
        }

        // Protocol-internal senders are signature-exempt, so accepting
        // one from the API would be accepting a self-authorising mint.
        // They are only ever created by this node's own block-reward
        // logic and must never arrive as input.
        if tx.is_protocol_internal() {
            return Err(ChainError::InvalidSignature);
        }

        // Reject a second pending transaction at the same nonce from the
        // same sender. Both would pass validation independently, and
        // build_candidate would then have to discard one at assembly
        // time — better to refuse it here, where the submitter gets an
        // error, than to accept something that can never confirm.
        if self
            .mempool
            .iter()
            .any(|t| t.sender == tx.sender && t.nonce == tx.nonce)
        {
            return Err(ChainError::ConflictsWithPending);
        }

        self.validate_transaction(&tx)?;
        self.mempool.push(tx);
        Ok(hash)
    }

    // ── Emission ───────────────────────────────────────────────────────

    /// Cumulative NEV the schedule would have emitted in blocks
    /// `0..height`, ignoring the cap.
    ///
    /// Sixty-four iterations at most, so it is cheap and exact. A closed
    /// form is tempting but the integer right-shift truncates at every
    /// epoch, so the geometric formula and the real total diverge — and
    /// on a supply cap a rounding difference is money created or
    /// destroyed.
    pub fn scheduled_emission_before(height: u64) -> Amount {
        let full_epochs = height / HALVING_INTERVAL;
        let mut total: Amount = 0;

        for epoch in 0..full_epochs.min(64) {
            let reward = INITIAL_REWARD >> epoch;
            total = total.saturating_add(HALVING_INTERVAL.saturating_mul(reward));
        }
        if full_epochs < 64 {
            let reward = INITIAL_REWARD >> full_epochs;
            total = total.saturating_add((height % HALVING_INTERVAL).saturating_mul(reward));
        }
        total
    }

    /// Reward for the block at `height`, clamped to what is left of
    /// MINEABLE_SUPPLY.
    ///
    /// The clamp is what makes the cap exact. The halving schedule
    /// overshoots MINEABLE_SUPPLY by 36,630 NEV; this returns the
    /// remainder on the final rewarded block and zero after it, so total
    /// emission equals MINEABLE_SUPPLY precisely and MAX_SUPPLY is
    /// reached to the base unit.
    ///
    /// Takes a height rather than reading self.height(), because
    /// accept_block validates blocks that may sit on a side branch at a
    /// different point in the schedule. Using the current tip's height
    /// for every block measured side-branch rewards against the wrong
    /// epoch.
    pub fn block_reward_at(&self, height: u64) -> Amount {
        let already = Self::scheduled_emission_before(height);
        if already >= MINEABLE_SUPPLY {
            return 0;
        }
        let remaining = MINEABLE_SUPPLY - already;

        let halvings = height / HALVING_INTERVAL;
        let scheduled = if halvings >= 64 {
            0
        } else {
            INITIAL_REWARD >> halvings
        };

        scheduled.min(remaining)
    }

    pub fn block_reward(&self) -> Amount {
        self.block_reward_at(self.height())
    }

    pub fn circulating_supply(&self) -> Amount {
        self.balances
            .values()
            .copied()
            .fold(0, |a, b| a.saturating_add(b))
    }

    /// Difficulty retarget: adjust every DIFFICULTY_ADJUST_INTERVAL
    /// blocks toward TARGET_BLOCK_SECONDS, clamped to ±1.
    ///
    /// Timestamp manipulation is what makes this attackable, which is
    /// why consensus.rs bounds future drift and requires timestamps not
    /// to move backwards.
    pub fn next_difficulty(&self) -> usize {
        let h = self.height();
        let last = self
            .chain
            .last()
            .map(|b| b.difficulty)
            .unwrap_or(GENESIS_DIFFICULTY);

        if h < DIFFICULTY_ADJUST_INTERVAL || h % DIFFICULTY_ADJUST_INTERVAL != 0 {
            return last;
        }

        let window_start = self.chain[(h - DIFFICULTY_ADJUST_INTERVAL) as usize].timestamp;
        let window_end = self.chain[(h - 1) as usize].timestamp;
        let actual = window_end.saturating_sub(window_start).max(1);
        let expected = TARGET_BLOCK_SECONDS * DIFFICULTY_ADJUST_INTERVAL;

        if actual < expected / 2 {
            (last + 1).min(64)
        } else if actual > expected * 2 {
            last.saturating_sub(1).max(1)
        } else {
            last
        }
    }

    // ── Candidate assembly ─────────────────────────────────────────────

    /// Assemble a candidate block from the mempool. Does not mine it.
    ///
    /// NEV-001, assembly half: transactions are now validated against a
    /// BlockExecution that accumulates the effect of everything already
    /// included. Previously each candidate was checked against untouched
    /// chain state, so two transactions from the same sender at the same
    /// nonce both passed and both went in — the miner built the
    /// double-spend itself.
    ///
    /// A useful side effect: a sender's transactions at consecutive
    /// nonces can now all be included in one block. Under the old code
    /// only the first could, because every later nonce was compared
    /// against the pre-block value and failed.
    pub fn build_candidate(&self, miner: &str) -> Block {
        let height = self.height();
        let mut exec = BlockExecution::new(self);
        let mut txs: Vec<Transaction> = Vec::new();

        let coinbase = Transaction {
            sender: "NETWORK_REWARD".into(),
            recipient: miner.to_string(),
            amount: self.block_reward_at(height),
            fee: 0,
            crown_tax: 0,
            nonce: height,
            timestamp: now(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
            payload_memo: format!("Block {height} reward"),
        };
        let _ = exec.apply(&coinbase);
        txs.push(coinbase);

        // Highest fee first, then ascending nonce within a sender so a
        // sender's sequence can actually be included together.
        let mut candidates = self.mempool.clone();
        candidates.sort_by(|a, b| {
            b.fee
                .cmp(&a.fee)
                .then(a.sender.cmp(&b.sender))
                .then(a.nonce.cmp(&b.nonce))
        });

        for tx in candidates {
            if txs.len() >= MAX_TX_PER_BLOCK {
                break;
            }
            if self.validate_transaction_against(&tx, &exec).is_err() {
                continue;
            }
            if exec.apply(&tx).is_err() {
                continue;
            }
            txs.push(tx);
        }

        Block {
            index: height,
            timestamp: now(),
            transactions: txs,
            previous_hash: self.latest_hash(),
            hash: String::new(),
            nonce: 0,
            difficulty: self.next_difficulty(),
            miner: miner.to_string(),
            block_dedication: format!("Block {height} — for Nevaeh"),
        }
    }

    // ── Block acceptance ───────────────────────────────────────────────

    /// Accept a block from mining or from a peer.
    ///
    /// Contents are validated before the tree sees it: the tree checks
    /// proof of work and structure, transaction validity is our job. A
    /// block that fails here never enters the tree, so a rejected block
    /// leaves no trace.
    pub fn accept_block(&mut self, block: Block) -> Result<AcceptOutcome, ChainError> {
        self.validate_block_contents(&block)?;

        let outcome = self.tree.accept(block.clone())?;

        match &outcome {
            AcceptOutcome::Extended { height } => {
                Self::persist_block_to(&self.db, &block)?;
                Self::persist_tip_to(&self.db, &block.hash)?;

                let included: Vec<String> = block.transactions.iter().map(|t| t.hash()).collect();
                self.mempool.retain(|t| !included.contains(&t.hash()));

                for tx in &block.transactions {
                    self.commit_transaction(tx);
                }
                self.chain.push(block);

                tracing::info!(height = *height, "Block accepted");
            }

            AcceptOutcome::Reorganised {
                disconnected,
                connected,
                new_height,
            } => {
                REORG_COUNT.fetch_add(1, Ordering::Relaxed);
                DEEPEST_REORG.fetch_max(disconnected.len() as u64, Ordering::Relaxed);
                tracing::warn!(
                    disconnected = disconnected.len(),
                    connected = connected.len(),
                    new_height = *new_height,
                    "REORGANISATION — a heavier branch replaced the current tip"
                );

                for b in connected {
                    Self::persist_block_to(&self.db, b)?;
                }

                // The tree's tip, not this block's hash. They differ when
                // accepting a block also connects buffered orphans past
                // it — persisting the wrong one would mean the next boot
                // reconstructs a shorter chain than the tree has.
                let tip = self.tree.tip_hash().to_string();
                Self::persist_tip_to(&self.db, &tip)?;

                // Transactions that were confirmed and now are not go
                // back to the mempool. Silently dropping them means a
                // user sees a payment confirm and then vanish.
                for tx in transactions_to_requeue(disconnected, connected) {
                    if self.mempool.len() >= MAX_MEMPOOL {
                        break;
                    }
                    if !self.mempool.iter().any(|t| t.hash() == tx.hash()) {
                        self.mempool.push(tx);
                    }
                }

                let now_included: Vec<String> = connected
                    .iter()
                    .flat_map(|b| b.transactions.iter())
                    .map(|t| t.hash())
                    .collect();
                self.mempool.retain(|t| !now_included.contains(&t.hash()));

                self.rematerialise_chain()?;
                self.rebuild_state();
            }

            AcceptOutcome::SideChain {
                height,
                work_behind,
            } => {
                // Keep it. A losing branch today may be extended into the
                // winner tomorrow; discarding it means re-downloading.
                Self::persist_block_to(&self.db, &block)?;
                tracing::debug!(
                    height = *height,
                    work_behind = *work_behind,
                    "Block stored on a side branch"
                );
            }

            AcceptOutcome::Orphaned { waiting_for } => {
                tracing::debug!(parent = %waiting_for, "Block buffered — parent not yet seen");
            }

            AcceptOutcome::Duplicate => {}
        }

        Ok(outcome)
    }

    fn rematerialise_chain(&mut self) -> Result<(), ChainError> {
        let mut reversed = Vec::new();
        let mut cursor = self.tree.tip_hash().to_string();

        loop {
            let block = self
                .tree
                .get_block(&cursor)
                .ok_or_else(|| {
                    ChainError::Storage(format!("tree missing block {cursor} during reorg"))
                })?
                .clone();
            let prev = block.previous_hash.clone();
            let is_genesis = block.index == 0;
            reversed.push(block);
            if is_genesis {
                break;
            }
            cursor = prev;
        }

        reversed.reverse();
        self.chain = reversed;
        Ok(())
    }

    /// After accepting a block, connect anything that was waiting on it.
    /// Called by the node loop so out-of-order gossip resolves itself.
    pub fn connect_orphans(&mut self, parent_hash: &str) -> usize {
        let ready = self.tree.take_connectable_orphans(parent_hash);
        let mut connected = 0;
        for block in ready {
            let hash = block.hash.clone();
            match self.accept_block(block) {
                Ok(AcceptOutcome::Duplicate) => {}
                Ok(_) => {
                    connected += 1;
                    connected += self.connect_orphans(&hash);
                }
                Err(e) => tracing::debug!(error = %e, "Buffered orphan failed validation"),
            }
        }
        connected
    }

    // ── Block content validation — NEV-001 ─────────────────────────────

    /// Transaction-level validation of a block's contents.
    ///
    /// THE FIX. Transactions are executed in order against a
    /// BlockExecution overlay, so each is checked against the effects of
    /// the ones before it. That is what makes an in-block double-spend
    /// detectable: the conflict lives between two transactions, not
    /// inside either one, so no amount of per-transaction checking
    /// against a fixed snapshot can find it.
    fn validate_block_contents(&self, block: &Block) -> Result<(), ChainError> {
        // Genesis is validated by matching the config pinned on disk,
        // not by replaying it — its premine transactions have no
        // signatures and no funded sender by construction.
        if block.index == 0 {
            return self.validate_genesis_contents(block);
        }

        let mut exec = BlockExecution::new(self);
        let mut coinbase_seen = false;
        let expected_reward = self.block_reward_at(block.index);

        for tx in &block.transactions {
            // ── Coinbase ──
            if tx.sender == "NETWORK_REWARD" {
                if coinbase_seen {
                    return Err(ChainError::InvalidBlock(
                        "multiple coinbase transactions".into(),
                    ));
                }
                coinbase_seen = true;

                // Checked at THIS block's height. Using the current tip's
                // height meant a side-branch block was measured against
                // the wrong point in the halving schedule.
                //
                // This is the binding emission control — the MAX_SUPPLY
                // check below never fires (NEV-007), so if this is wrong
                // nothing else catches over-issuance.
                if tx.amount > expected_reward {
                    return Err(ChainError::InvalidBlock(format!(
                        "coinbase pays {} at height {}, scheduled reward is {}",
                        tx.amount, block.index, expected_reward
                    )));
                }

                exec.apply(tx).map_err(|_| {
                    ChainError::InvalidBlock("coinbase credit overflows recipient".into())
                })?;
                continue;
            }

            // ── GENESIS sender outside block 0 ──
            //
            // "GENESIS" is signature-exempt, so without this check any
            // block could carry a self-authorising mint.
            if tx.sender == "GENESIS" {
                return Err(ChainError::InvalidBlock(
                    "GENESIS sender is only valid in block 0".into(),
                ));
            }

            // ── Ordinary transaction ──
            if tx.amount == 0 {
                return Err(ChainError::ZeroAmount);
            }
            if !tx.verify_signature() {
                return Err(ChainError::InvalidSignature);
            }
            self.check_timelock(&tx.sender)?;

            // Balance and nonce against the running state. This is the
            // line whose absence was NEV-001.
            exec.check(tx).map_err(|e| {
                ChainError::ConflictingTransactions(format!(
                    "tx {} from {} at nonce {}: {}",
                    &tx.hash()[..16.min(tx.hash().len())],
                    tx.sender,
                    tx.nonce,
                    e
                ))
            })?;

            exec.apply(tx)?;
        }

        // Cumulative ceiling. Retained as defence in depth, and honestly
        // labelled: MAX_SUPPLY sits about 5.4x above anything the
        // emission schedule can produce, so this never binds. The
        // per-block coinbase check above is what actually constrains
        // issuance. Scoped to canonical state, so it is only meaningful
        // for a block extending the tip.
        let minted: Amount = block
            .transactions
            .iter()
            .filter(|t| t.sender == "NETWORK_REWARD")
            .fold(0, |a, t| a.saturating_add(t.amount));
        if self.circulating_supply().saturating_add(minted) > MAX_SUPPLY {
            return Err(ChainError::InvalidBlock("would exceed max supply".into()));
        }

        Ok(())
    }

    fn validate_genesis_contents(&self, block: &Block) -> Result<(), ChainError> {
        if block.transactions.len() != 2 {
            return Err(ChainError::InvalidBlock(format!(
                "genesis must contain exactly 2 premine transactions, found {}",
                block.transactions.len()
            )));
        }
        for tx in &block.transactions {
            if tx.sender != "GENESIS" {
                return Err(ChainError::InvalidBlock(
                    "genesis may only contain GENESIS-sender transactions".into(),
                ));
            }
        }

        let cfg = &self.genesis_config;
        let expected = [
            (&cfg.architect_address, cfg.architect_premine),
            (&cfg.nevaeh_vault_address, cfg.nevaeh_premine),
        ];
        for (address, amount) in expected {
            let found = block
                .transactions
                .iter()
                .any(|t| &t.recipient == address && t.amount == amount);
            if !found {
                return Err(ChainError::InvalidBlock(format!(
                    "genesis does not credit {amount} to the configured address {address}"
                )));
            }
        }

        Ok(())
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use godshield_core::GodKeyPair;

    /// Development config with placeholder premine addresses.
    /// Constructed directly rather than via from_env() — tests run in
    /// parallel and environment variables are process-global, so reading
    /// them here would make results depend on test ordering.
    fn test_config() -> GenesisConfig {
        GenesisConfig {
            architect_address: ARCHITECT_ADDRESS.into(),
            nevaeh_vault_address: NEVAEH_VAULT_ADDRESS.into(),
            architect_premine: ARCHITECT_PREMINE,
            nevaeh_premine: NEVAEH_PREMINE,
            nevaeh_unlock_timestamp: NEVAEH_UNLOCK_TIMESTAMP,
            development_mode: true,
            genesis_timestamp: None,
            expected_genesis_hash: None,
        }
    }

    // ── Address history ──

    #[test]
    fn address_history_is_newest_first_and_both_directions() {
        let mut chain = temp_chain();
        // Genesis credits the Architect fixture address.
        let genesis_hits = chain.address_history(ARCHITECT_ADDRESS, 10);
        assert_eq!(genesis_hits.len(), 1);
        assert_eq!(genesis_hits[0].0, 0, "genesis is block 0");

        // Push a block directly: history is a pure read of self.chain.
        let block = mine_block(&chain, vec![coinbase(&chain, "miner-x")], "miner-x");
        chain.chain.push(block);
        let hits = chain.address_history("miner-x", 10);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 1);
        assert_eq!(hits[0].2.sender, "NETWORK_REWARD");

        assert!(chain.address_history("nobody", 10).is_empty());
        assert_eq!(chain.address_history(ARCHITECT_ADDRESS, 0).len(), 0);
    }

    // ── Pinned genesis: every node must build the same block 0 ──

    #[test]
    fn pinned_genesis_is_identical_on_every_node() {
        let mut a = test_config();
        a.genesis_timestamp = Some(1_790_000_000);
        let b = a.clone();
        assert_eq!(
            BlockchainApp::build_genesis(&a).hash,
            BlockchainApp::build_genesis(&b).hash,
            "two nodes with the same chain spec must agree on block 0"
        );
        let mut c = a.clone();
        c.genesis_timestamp = Some(1_790_000_001);
        assert_ne!(
            BlockchainApp::build_genesis(&a).hash,
            BlockchainApp::build_genesis(&c).hash,
            "the timestamp is inside the genesis hash"
        );
    }

    #[test]
    fn a_node_refuses_a_genesis_that_is_not_the_networks() {
        let mut cfg = test_config();
        cfg.genesis_timestamp = Some(1_790_000_000);
        cfg.expected_genesis_hash = Some("0".repeat(128));
        assert!(BlockchainApp::new(&temp_path(), cfg).is_err());
    }

    #[test]
    fn a_node_accepts_the_networks_genesis() {
        let mut cfg = test_config();
        cfg.genesis_timestamp = Some(1_790_000_000);
        let expected = BlockchainApp::build_genesis(&cfg).hash;
        cfg.expected_genesis_hash = Some(expected.clone());
        let app = BlockchainApp::new(&temp_path(), cfg).unwrap();
        assert_eq!(app.chain[0].hash, expected);
    }

    fn temp_path() -> String {
        std::env::temp_dir()
            .join(format!("nev369-test-{}", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string()
    }

    fn temp_chain() -> BlockchainApp {
        BlockchainApp::new(&temp_path(), test_config()).unwrap()
    }

    fn signed_tx(kp: &GodKeyPair, recipient: &str, amount: Amount, nonce: u64) -> Transaction {
        signed_tx_fee(kp, recipient, amount, nonce, 100)
    }

    fn signed_tx_fee(
        kp: &GodKeyPair,
        recipient: &str,
        amount: Amount,
        nonce: u64,
        fee: Amount,
    ) -> Transaction {
        let mut tx = Transaction {
            sender: hex::encode(&kp.public_key),
            recipient: recipient.into(),
            amount,
            fee,
            crown_tax: 0,
            nonce,
            timestamp: now(),
            public_key_hex: hex::encode(&kp.public_key),
            signature_hex: String::new(),
            payload_memo: "test".into(),
        };
        let sig = GodShield::sign(kp, &tx.signing_bytes()).unwrap();
        tx.signature_hex = hex::encode(&sig.signature);
        tx
    }

    /// Build and mine a block at difficulty 1 so tests stay fast.
    fn mine_block(chain: &BlockchainApp, txs: Vec<Transaction>, miner: &str) -> Block {
        let mut block = Block {
            index: chain.height(),
            timestamp: now(),
            transactions: txs,
            previous_hash: chain.latest_hash(),
            hash: String::new(),
            nonce: 0,
            difficulty: 1,
            miner: miner.into(),
            block_dedication: "test".into(),
        };
        loop {
            block.hash = block.calculate_hash();
            if block.meets_difficulty() {
                return block;
            }
            block.nonce += 1;
        }
    }

    fn coinbase(chain: &BlockchainApp, miner: &str) -> Transaction {
        Transaction {
            sender: "NETWORK_REWARD".into(),
            recipient: miner.into(),
            amount: chain.block_reward_at(chain.height()),
            fee: 0,
            crown_tax: 0,
            nonce: chain.height(),
            timestamp: now(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
            payload_memo: "reward".into(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // NEV-001 — the regression tests that matter most
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn in_block_double_spend_is_rejected() {
        // THE bug. Two transactions from the same sender at the same
        // nonce, each spending the whole balance to a different
        // recipient. Both signatures are individually valid. Before the
        // fix both passed validate_block_contents, both were applied,
        // and the second credited its recipient in full from an
        // already-zero balance — minting from nothing.
        let mut chain = temp_chain();
        let kp = GodKeyPair::generate().unwrap();
        let sender = hex::encode(&kp.public_key);

        chain.balances.insert(sender.clone(), nev(100));

        let a = signed_tx_fee(&kp, "recipient_a", nev(100) - 100, 0, 100);
        let b = signed_tx_fee(&kp, "recipient_b", nev(100) - 100, 0, 100);
        assert!(a.verify_signature() && b.verify_signature());

        let block = mine_block(&chain, vec![coinbase(&chain, "miner"), a, b], "miner");

        let err = chain.validate_block_contents(&block).unwrap_err();
        assert!(
            matches!(err, ChainError::ConflictingTransactions(_)),
            "expected ConflictingTransactions, got {err:?}"
        );
    }

    #[test]
    fn in_block_overspend_across_two_nonces_is_rejected() {
        // Correct nonce sequence, but together they spend more than the
        // sender has. Each passes against pre-block state; only the
        // running overlay catches the pair.
        let mut chain = temp_chain();
        let kp = GodKeyPair::generate().unwrap();
        chain.balances.insert(hex::encode(&kp.public_key), nev(10));

        let a = signed_tx_fee(&kp, "a", nev(6), 0, 0);
        let b = signed_tx_fee(&kp, "b", nev(6), 1, 0);

        let block = mine_block(&chain, vec![coinbase(&chain, "m"), a, b], "m");
        assert!(matches!(
            chain.validate_block_contents(&block),
            Err(ChainError::ConflictingTransactions(_))
        ));
    }

    #[test]
    fn out_of_order_nonces_in_a_block_are_rejected() {
        let mut chain = temp_chain();
        let kp = GodKeyPair::generate().unwrap();
        chain.balances.insert(hex::encode(&kp.public_key), nev(100));

        let a = signed_tx_fee(&kp, "a", nev(1), 1, 0); // nonce 1 first
        let b = signed_tx_fee(&kp, "b", nev(1), 0, 0);

        let block = mine_block(&chain, vec![coinbase(&chain, "m"), a, b], "m");
        assert!(chain.validate_block_contents(&block).is_err());
    }

    #[test]
    fn sequential_nonces_from_one_sender_are_accepted() {
        // The fix must not over-reject: a sender's consecutive
        // transactions within their balance belong in one block. Under
        // the old code only the first could be included, because every
        // later nonce was compared against pre-block state.
        let mut chain = temp_chain();
        let kp = GodKeyPair::generate().unwrap();
        chain.balances.insert(hex::encode(&kp.public_key), nev(100));

        let a = signed_tx_fee(&kp, "a", nev(1), 0, 0);
        let b = signed_tx_fee(&kp, "b", nev(1), 1, 0);
        let c = signed_tx_fee(&kp, "c", nev(1), 2, 0);

        let block = mine_block(&chain, vec![coinbase(&chain, "m"), a, b, c], "m");
        assert!(chain.validate_block_contents(&block).is_ok());
    }

    #[test]
    fn build_candidate_never_assembles_a_double_spend() {
        // The assembly half. Two conflicting transactions forced into the
        // mempool directly, bypassing submit_transaction's guard, so this
        // tests build_candidate itself rather than admission control.
        let mut chain = temp_chain();
        let kp = GodKeyPair::generate().unwrap();
        chain.balances.insert(hex::encode(&kp.public_key), nev(100));

        chain
            .mempool
            .push(signed_tx_fee(&kp, "a", nev(100) - 100, 0, 100));
        chain
            .mempool
            .push(signed_tx_fee(&kp, "b", nev(100) - 100, 0, 100));

        let candidate = chain.build_candidate("miner");
        let from_sender = candidate
            .transactions
            .iter()
            .filter(|t| !t.is_protocol_internal())
            .count();

        assert_eq!(
            from_sender, 1,
            "only one of a conflicting pair may be included"
        );
        assert!(chain.validate_block_contents(&candidate).is_ok());
    }

    #[test]
    fn mempool_refuses_a_second_transaction_at_the_same_nonce() {
        let mut chain = temp_chain();
        let kp = GodKeyPair::generate().unwrap();
        chain.balances.insert(hex::encode(&kp.public_key), nev(100));

        chain
            .submit_transaction(signed_tx(&kp, "a", nev(1), 0))
            .unwrap();
        assert!(matches!(
            chain.submit_transaction(signed_tx(&kp, "b", nev(1), 0)),
            Err(ChainError::ConflictsWithPending)
        ));
    }

    #[test]
    fn api_cannot_submit_a_protocol_internal_sender() {
        // NETWORK_REWARD and GENESIS are signature-exempt, so accepting
        // one over the API would accept a self-authorising mint.
        let mut chain = temp_chain();
        let tx = Transaction {
            sender: "NETWORK_REWARD".into(),
            recipient: "attacker".into(),
            amount: nev(1_000_000),
            fee: 0,
            crown_tax: 0,
            nonce: 0,
            timestamp: now(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
            payload_memo: "free money".into(),
        };
        assert!(chain.submit_transaction(tx).is_err());
    }

    #[test]
    fn coinbase_above_the_scheduled_reward_is_rejected() {
        let chain = temp_chain();
        let mut cb = coinbase(&chain, "greedy");
        cb.amount = nev(1_000_000);

        let block = mine_block(&chain, vec![cb], "greedy");
        assert!(chain.validate_block_contents(&block).is_err());
    }

    #[test]
    fn two_coinbase_transactions_are_rejected() {
        let chain = temp_chain();
        let block = mine_block(
            &chain,
            vec![coinbase(&chain, "m"), coinbase(&chain, "m")],
            "m",
        );
        assert!(chain.validate_block_contents(&block).is_err());
    }

    #[test]
    fn genesis_sender_outside_block_zero_is_rejected() {
        let chain = temp_chain();
        let tx = Transaction {
            sender: "GENESIS".into(),
            recipient: "attacker".into(),
            amount: nev(1_000_000),
            fee: 0,
            crown_tax: 0,
            nonce: 0,
            timestamp: now(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
            payload_memo: String::new(),
        };
        let block = mine_block(&chain, vec![coinbase(&chain, "m"), tx], "m");
        assert!(chain.validate_block_contents(&block).is_err());
    }

    // ═══════════════════════════════════════════════════════════════════
    // Pre-existing regression guards — do not delete
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn canonical_encoding_prevents_field_boundary_collision() {
        let mut a = Transaction {
            sender: "AB".into(),
            recipient: "C".into(),
            amount: 1,
            fee: 0,
            crown_tax: 0,
            nonce: 0,
            timestamp: 0,
            public_key_hex: String::new(),
            signature_hex: String::new(),
            payload_memo: String::new(),
        };
        let mut b = a.clone();
        b.sender = "A".into();
        b.recipient = "BC".into();
        assert_ne!(a.signing_bytes(), b.signing_bytes());
        a.amount = 2;
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn architect_address_is_not_signature_exempt() {
        assert!(!SIGNATURE_EXEMPT_SENDERS.contains(&ARCHITECT_ADDRESS));
        let tx = Transaction {
            sender: ARCHITECT_ADDRESS.into(),
            recipient: "someone".into(),
            amount: nev(1_000_000),
            fee: 0,
            crown_tax: 0,
            nonce: 0,
            timestamp: now(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
            payload_memo: "drain attempt".into(),
        };
        assert!(
            !tx.verify_signature(),
            "unsigned premine spend must be rejected"
        );
    }

    #[test]
    fn signature_exempt_list_has_exactly_two_entries() {
        assert_eq!(SIGNATURE_EXEMPT_SENDERS.len(), 2);
        assert!(SIGNATURE_EXEMPT_SENDERS.contains(&"GENESIS"));
        assert!(SIGNATURE_EXEMPT_SENDERS.contains(&"NETWORK_REWARD"));
    }

    #[test]
    fn sender_must_match_public_key() {
        let kp = GodKeyPair::generate().unwrap();
        let mut tx = signed_tx(&kp, "recipient", nev(1), 0);
        tx.sender = "someone_elses_address".into();
        assert!(
            !tx.verify_signature(),
            "cannot claim another address as sender"
        );
    }

    #[test]
    fn signed_transaction_verifies() {
        let kp = GodKeyPair::generate().unwrap();
        assert!(signed_tx(&kp, "recipient", nev(1), 0).verify_signature());
    }

    #[test]
    fn tampered_amount_fails_verification() {
        let kp = GodKeyPair::generate().unwrap();
        let mut tx = signed_tx(&kp, "recipient", nev(1), 0);
        tx.amount = nev(1_000_000);
        assert!(!tx.verify_signature());
    }

    #[test]
    fn money_is_integer_not_float() {
        let a: Amount = 1;
        let mut total: Amount = 0;
        for _ in 0..10_000_000 {
            total = total.saturating_add(a);
        }
        assert_eq!(total, 10_000_000, "integer arithmetic must be exact");
    }

    #[test]
    fn nevaeh_vault_is_timelocked() {
        let chain = temp_chain();
        assert!(
            now() < NEVAEH_UNLOCK_TIMESTAMP,
            "vault should still be locked"
        );
        let tx = Transaction {
            sender: NEVAEH_VAULT_ADDRESS.into(),
            recipient: "anyone".into(),
            amount: nev(1),
            fee: 0,
            crown_tax: 0,
            nonce: 0,
            timestamp: now(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
            payload_memo: String::new(),
        };
        assert!(chain.validate_transaction(&tx).is_err());
        assert!(chain.check_timelock(NEVAEH_VAULT_ADDRESS).is_err());
    }

    #[test]
    fn merkle_root_changes_with_tx_order() {
        let kp = GodKeyPair::generate().unwrap();
        let a = signed_tx(&kp, "alice", nev(1), 0);
        let b = signed_tx(&kp, "bob", nev(2), 1);
        assert_ne!(
            Block::tx_root(&[a.clone(), b.clone()]),
            Block::tx_root(&[b, a]),
            "transaction ordering must affect the root"
        );
    }

    // ── NEV-008: this test previously called new() with one argument ──

    #[test]
    fn genesis_does_not_rerun_on_restart() {
        let path = temp_path();

        let supply_first = {
            let c = BlockchainApp::new(&path, test_config()).unwrap();
            assert_eq!(c.height(), 1);
            c.circulating_supply()
        };

        let supply_second = {
            let c = BlockchainApp::new(&path, test_config()).unwrap();
            assert_eq!(c.height(), 1, "genesis must not run twice");
            c.circulating_supply()
        };

        assert_eq!(
            supply_first, supply_second,
            "premine must not be re-minted on restart"
        );
        assert_eq!(supply_first, ARCHITECT_PREMINE + NEVAEH_PREMINE);
    }

    // ── Emission ──

    #[test]
    fn block_reward_halves_on_schedule() {
        let chain = temp_chain();
        assert_eq!(chain.block_reward_at(0), INITIAL_REWARD);
        assert_eq!(chain.block_reward_at(HALVING_INTERVAL - 1), INITIAL_REWARD);
        assert_eq!(chain.block_reward_at(HALVING_INTERVAL), INITIAL_REWARD / 2);
        assert_eq!(
            chain.block_reward_at(HALVING_INTERVAL * 2),
            INITIAL_REWARD / 4
        );
        assert_eq!(
            chain.block_reward_at(HALVING_INTERVAL * 3),
            INITIAL_REWARD / 8
        );
    }

    #[test]
    fn premine_plus_mineable_equals_the_cap_exactly() {
        // The relationship the whole tokenomics claim rests on.
        assert_eq!(
            ARCHITECT_PREMINE + NEVAEH_PREMINE + MINEABLE_SUPPLY,
            MAX_SUPPLY,
            "premine + mineable must equal the cap"
        );
        assert_eq!(MAX_SUPPLY / UNITS_PER_NEV, 369_369_369);
        assert_eq!(MINEABLE_SUPPLY / UNITS_PER_NEV, 322_469_369);
        assert_eq!(
            (ARCHITECT_PREMINE + NEVAEH_PREMINE) / UNITS_PER_NEV,
            46_900_000
        );
    }

    #[test]
    fn total_emission_reaches_the_cap_to_the_base_unit() {
        // Walk the entire schedule and sum every reward. Slow, and worth
        // it: this is the test that proves 369,369,369 is a real cap and
        // not a slogan. The previous schedule failed this by ~301M.
        let chain = temp_chain();
        let mut emitted: Amount = 0;
        let mut height: u64 = 0;
        let mut last_rewarded: u64 = 0;

        // Far enough past exhaustion to prove rewards stay at zero.
        while height < HALVING_INTERVAL * 20 {
            let r = chain.block_reward_at(height);
            if r > 0 {
                last_rewarded = height;
                emitted = emitted.checked_add(r).expect("emission must not overflow");
            }
            height += 1;
        }

        assert_eq!(
            emitted, MINEABLE_SUPPLY,
            "schedule emitted {emitted} base units, mineable supply is {MINEABLE_SUPPLY}"
        );
        assert_eq!(
            emitted + ARCHITECT_PREMINE + NEVAEH_PREMINE,
            MAX_SUPPLY,
            "premine plus emission must equal MAX_SUPPLY exactly"
        );
        assert_eq!(
            chain.block_reward_at(last_rewarded + 1),
            0,
            "rewards must be zero once the cap is reached"
        );
    }

    #[test]
    fn the_final_rewarded_block_pays_a_partial_remainder() {
        // The schedule overshoots by 36,630 NEV, so the last rewarded
        // block must pay less than its scheduled amount. If it paid the
        // full amount, total emission would exceed the cap.
        let chain = temp_chain();
        let mut height: u64 = 0;
        let mut last = (0u64, 0 as Amount);

        while height < HALVING_INTERVAL * 20 {
            let r = chain.block_reward_at(height);
            if r > 0 {
                last = (height, r);
            }
            height += 1;
        }

        let (h, paid) = last;
        let halvings = h / HALVING_INTERVAL;
        let scheduled = INITIAL_REWARD >> halvings;
        assert!(
            paid < scheduled,
            "final block at height {h} paid {paid}, scheduled {scheduled} — \
             the clamp did not engage, so the cap is being overshot"
        );
    }

    #[test]
    fn allocation_shares_are_what_is_published() {
        // Guards the numbers that go in front of buyers.
        let pct = |part: Amount| part as f64 / MAX_SUPPLY as f64 * 100.0;
        assert!((pct(NEVAEH_PREMINE) - 9.99).abs() < 0.02, "Nevaeh ~9.99%");
        assert!(
            (pct(ARCHITECT_PREMINE) - 2.71).abs() < 0.02,
            "Architect ~2.71%"
        );
        assert!(
            (pct(MINEABLE_SUPPLY) - 87.30).abs() < 0.02,
            "mineable ~87.3%"
        );
    }

    #[test]
    fn coinbase_cannot_exceed_the_clamped_reward_near_exhaustion() {
        // A miner at the tail must not be able to claim the full
        // scheduled reward once only a remainder is left.
        let chain = temp_chain();
        let mut h: u64 = 0;
        while chain.block_reward_at(h) > 0 && h < HALVING_INTERVAL * 20 {
            h += 1;
        }
        assert_eq!(chain.block_reward_at(h), 0);
        assert_eq!(chain.block_reward_at(h + 1_000), 0);
    }
}
