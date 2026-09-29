// crates/nev369-node/src/consensus.rs
//
// ═══════════════════════════════════════════════════════════════════════
// MULTI-NODE CONSENSUS — fork choice, reorganisation, orphan handling
//
// WHAT WAS MISSING BEFORE:
//
// accept_block() only accepted blocks at exactly height(), and rejected
// everything else. That works for one node talking to itself. With two or
// more miners it fails immediately:
//
//   - Two nodes mine block N at the same time. Each rejects the other's.
//     The network permanently forks and never heals.
//   - A block arriving out of order (N+1 before N) was dropped entirely,
//     with no buffering, so a brief network hiccup lost blocks.
//   - A new node joining had no way to obtain history. It would start from
//     its own genesis and diverge from the network on block 1.
//
// WHAT THIS ADDS:
//
//   - Cumulative-work fork choice (heaviest chain, not longest)
//   - Full reorganisation: disconnect, reconnect, return orphaned txs to
//     the mempool
//   - Orphan pool so out-of-order blocks are buffered and connected later
//   - Finality depth — reorgs deeper than N blocks are refused outright
//
// READ THE SECURITY NOTE AT THE BOTTOM OF THIS FILE. Fork choice makes the
// network converge. It does not make a low-hashrate chain safe.
// ═══════════════════════════════════════════════════════════════════════

use crate::chain::{now, Block, ChainError, Transaction};
use std::collections::{HashMap, HashSet, VecDeque};

/// Reorgs deeper than this are refused.
///
/// WHY THIS EXISTS: without a bound, an attacker who accumulates more work
/// in private can rewrite arbitrarily deep history — reversing settled
/// transactions months after the fact. For a chain intended to hold value
/// for 13 years, that is not survivable.
///
/// The trade-off is real and worth stating: if the network genuinely
/// produces a heavier chain beyond this depth, nodes will refuse it and
/// partition permanently rather than reorganise. That is the correct choice
/// for custody — a permanent visible split is recoverable by human
/// intervention; a silent deep reorg that reverses the premine is not.
///
/// 100 blocks at a 60s target is roughly 100 minutes of finality.
pub const MAX_REORG_DEPTH: u64 = 100;

/// Orphans are dropped past this to bound memory. A peer flooding us with
/// unconnectable blocks must not be able to exhaust the node.
const MAX_ORPHANS: usize = 500;

/// Per missing parent. See the note at the buffering site — the parent
/// hash an orphan claims is attacker-controlled, so a global cap alone
/// lets one fabricated parent consume the entire pool.
const MAX_ORPHANS_PER_PARENT: usize = 32;

/// How far into the future a block's timestamp may sit.
///
/// MERGED IN: this file validated proof of work but not time, and the two
/// are not the same check. `is_valid_pow()` cannot catch a lying
/// timestamp, because the hash commits to whatever timestamp the miner
/// chose — a backdated block produces a perfectly valid hash.
///
/// That matters here specifically because chain.rs::next_difficulty
/// retargets on elapsed time across a 100-block window. A miner who
/// backdates makes the window look slow, which drives difficulty DOWN,
/// which makes the next blocks cheaper to mine. Left unchecked it is a
/// self-reinforcing way to lower the cost of attacking the chain.
const MAX_FUTURE_DRIFT_SECS: u64 = 2 * 60 * 60;

/// Expected hashes to find a block with `difficulty` leading hex zeros.
///
/// Fork choice uses cumulative WORK, not chain length. Length alone is
/// exploitable: an attacker can mine many low-difficulty blocks faster than
/// the honest chain mines few high-difficulty ones, and win on length while
/// having done far less work.
pub fn block_work(difficulty: usize) -> u128 {
    // 16^difficulty, saturating at u128::MAX. 16^31 = 2^124 still fits;
    // 16^32 = 2^128 is the first that overflows. Either is far beyond any
    // reachable difficulty — this only has to not panic.
    u32::try_from(difficulty)
        .ok()
        .and_then(|d| 16u128.checked_pow(d))
        .unwrap_or(u128::MAX)
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // hash/difficulty kept for diagnostics and future retarget checks
pub struct BlockIndexEntry {
    pub hash: String,
    pub previous_hash: String,
    pub height: u64,
    pub difficulty: usize,
    /// Total work from genesis to and including this block.
    pub cumulative_work: u128,
}

/// The block tree. Tracks every block we have seen, including those on
/// branches that are not currently canonical — a branch that loses today
/// may win tomorrow if it is extended.
pub struct BlockTree {
    /// hash → index entry (all known blocks, canonical or not)
    index: HashMap<String, BlockIndexEntry>,
    /// hash → full block
    blocks: HashMap<String, Block>,
    /// Current canonical tip hash.
    tip: String,
    /// parent_hash → blocks waiting for that parent to arrive.
    orphans: HashMap<String, Vec<Block>>,
    orphan_count: usize,
}

/// What accepting a block did to the canonical chain.
#[derive(Debug)]
pub enum AcceptOutcome {
    /// Extended the current tip directly.
    Extended { height: u64 },
    /// Triggered a reorganisation.
    Reorganised {
        disconnected: Vec<Block>,
        connected: Vec<Block>,
        new_height: u64,
    },
    /// Valid, stored, but on a lighter branch. Kept in case it is extended.
    SideChain { height: u64, work_behind: u128 },
    /// Parent unknown — buffered until it arrives.
    Orphaned { waiting_for: String },
    /// Already known.
    Duplicate,
}

impl BlockTree {
    pub fn new(genesis: Block) -> Self {
        let hash = genesis.hash.clone();
        let entry = BlockIndexEntry {
            hash: hash.clone(),
            previous_hash: genesis.previous_hash.clone(),
            height: 0,
            difficulty: genesis.difficulty,
            cumulative_work: block_work(genesis.difficulty),
        };

        let mut index = HashMap::new();
        index.insert(hash.clone(), entry);
        let mut blocks = HashMap::new();
        blocks.insert(hash.clone(), genesis);

        Self {
            index,
            blocks,
            tip: hash,
            orphans: HashMap::new(),
            orphan_count: 0,
        }
    }

    /// Rebuild from a persisted canonical chain (node restart).
    pub fn from_chain(chain: &[Block]) -> Result<Self, ChainError> {
        let genesis = chain
            .first()
            .ok_or_else(|| ChainError::InvalidBlock("empty chain".into()))?
            .clone();
        let mut tree = Self::new(genesis);

        for block in chain.iter().skip(1) {
            tree.insert_index(block)?;
            tree.blocks.insert(block.hash.clone(), block.clone());
            tree.tip = block.hash.clone();
        }
        Ok(tree)
    }

    pub fn tip_hash(&self) -> &str {
        &self.tip
    }

    pub fn tip_entry(&self) -> &BlockIndexEntry {
        self.index.get(&self.tip).expect("tip is always indexed")
    }

    pub fn height(&self) -> u64 {
        self.tip_entry().height
    }

    pub fn cumulative_work(&self) -> u128 {
        self.tip_entry().cumulative_work
    }

    #[allow(dead_code)] // API kept for tooling/tests; not yet called by the node itself
    pub fn contains(&self, hash: &str) -> bool {
        self.index.contains_key(hash)
    }

    pub fn get_block(&self, hash: &str) -> Option<&Block> {
        self.blocks.get(hash)
    }

    fn insert_index(&mut self, block: &Block) -> Result<(), ChainError> {
        let parent = self.index.get(&block.previous_hash).ok_or_else(|| {
            ChainError::InvalidBlock(format!("parent {} not indexed", block.previous_hash))
        })?;

        let entry = BlockIndexEntry {
            hash: block.hash.clone(),
            previous_hash: block.previous_hash.clone(),
            height: parent.height + 1,
            difficulty: block.difficulty,
            cumulative_work: parent
                .cumulative_work
                .saturating_add(block_work(block.difficulty)),
        };
        self.index.insert(block.hash.clone(), entry);
        Ok(())
    }

    /// Walk back from a hash to collect the canonical path.
    fn path_to_genesis(&self, from: &str) -> Vec<String> {
        let mut path = Vec::new();
        let mut cursor = from.to_string();
        while let Some(entry) = self.index.get(&cursor) {
            path.push(cursor.clone());
            if entry.height == 0 {
                break;
            }
            cursor = entry.previous_hash.clone();
        }
        path
    }

    /// Lowest common ancestor of two branch tips.
    fn common_ancestor(&self, a: &str, b: &str) -> Option<String> {
        let path_a: HashSet<String> = self.path_to_genesis(a).into_iter().collect();
        let mut cursor = b.to_string();
        loop {
            if path_a.contains(&cursor) {
                return Some(cursor);
            }
            let entry = self.index.get(&cursor)?;
            if entry.height == 0 {
                return None;
            }
            cursor = entry.previous_hash.clone();
        }
    }

    /// Blocks from (exclusive) ancestor up to (inclusive) tip, in order.
    fn branch_from(&self, ancestor: &str, tip: &str) -> Vec<Block> {
        let mut branch = Vec::new();
        let mut cursor = tip.to_string();
        while cursor != ancestor {
            match self.blocks.get(&cursor) {
                Some(b) => {
                    branch.push(b.clone());
                    cursor = b.previous_hash.clone();
                }
                None => break,
            }
        }
        branch.reverse();
        branch
    }

    /// Add a block to the tree and decide what it means for the canonical
    /// chain. This does NOT mutate ledger state — the caller applies the
    /// returned outcome. Separating "what should happen" from "make it
    /// happen" is what allows the whole reorg to be validated before any of
    /// it is committed.
    pub fn accept(&mut self, block: Block) -> Result<AcceptOutcome, ChainError> {
        if self.index.contains_key(&block.hash) {
            return Ok(AcceptOutcome::Duplicate);
        }

        if !block.is_valid_pow() {
            return Err(ChainError::InvalidBlock("proof of work invalid".into()));
        }

        // Parent unknown — buffer it. Out-of-order arrival is normal on a
        // gossip network; dropping these loses blocks on any hiccup.
        if !self.index.contains_key(&block.previous_hash) {
            if self.orphan_count >= MAX_ORPHANS {
                return Err(ChainError::InvalidBlock(
                    "orphan pool full — refusing to buffer more".into(),
                ));
            }
            let parent = block.previous_hash.clone();
            let bucket = self.orphans.entry(parent.clone()).or_default();

            // MERGED: per-parent bound, not just the global one.
            //
            // The global cap alone leaves a gap: every orphan is keyed on
            // the parent hash the block CLAIMS, and that hash is
            // attacker-controlled and costs nothing to fabricate. One peer
            // can therefore fill all MAX_ORPHANS slots under a single
            // invented parent, after which legitimately-early blocks from
            // honest peers are refused. Bounding per parent means a flood
            // costs an attacker one distinct fabricated parent per 32
            // slots and cannot starve the rest of the pool.
            if bucket.len() >= MAX_ORPHANS_PER_PARENT {
                return Err(ChainError::InvalidBlock(
                    "too many orphans buffered for that parent".into(),
                ));
            }
            if bucket.iter().any(|b| b.hash == block.hash) {
                return Ok(AcceptOutcome::Duplicate);
            }
            bucket.push(block);
            self.orphan_count += 1;
            return Ok(AcceptOutcome::Orphaned {
                waiting_for: parent,
            });
        }

        // MERGED IN: timestamp sanity. Consensus-relevant, not cosmetic —
        // see MAX_FUTURE_DRIFT_SECS above.
        // Height from the index entry (cheap), timestamp from the full
        // block (the index deliberately does not carry one).
        let parent_height = self
            .index
            .get(&block.previous_hash)
            .map(|e| e.height)
            .ok_or_else(|| ChainError::InvalidBlock("parent vanished between checks".into()))?;
        let parent_timestamp = self
            .blocks
            .get(&block.previous_hash)
            .map(|b| b.timestamp)
            .ok_or_else(|| {
                ChainError::InvalidBlock("parent indexed but its block is missing".into())
            })?;

        if block.timestamp > now().saturating_add(MAX_FUTURE_DRIFT_SECS) {
            return Err(ChainError::InvalidBlock(format!(
                "block timestamp {} is more than {}s in the future",
                block.timestamp, MAX_FUTURE_DRIFT_SECS
            )));
        }
        if block.timestamp < parent_timestamp {
            return Err(ChainError::InvalidBlock(format!(
                "block {} timestamp {} precedes its parent's {}",
                block.index, block.timestamp, parent_timestamp
            )));
        }
        if block.index != parent_height + 1 {
            return Err(ChainError::InvalidBlock(format!(
                "block index {} does not follow parent height {}",
                block.index, parent_height
            )));
        }

        self.insert_index(&block)?;
        let hash = block.hash.clone();
        self.blocks.insert(hash.clone(), block.clone());

        let new_work = self.index[&hash].cumulative_work;
        let new_height = self.index[&hash].height;
        let tip_work = self.cumulative_work();

        // Simple extension of the current tip.
        if block.previous_hash == self.tip {
            self.tip = hash;
            return Ok(AcceptOutcome::Extended { height: new_height });
        }

        // Heavier branch — reorganise.
        if new_work > tip_work {
            let ancestor = self
                .common_ancestor(&self.tip, &hash)
                .ok_or_else(|| ChainError::InvalidBlock("no common ancestor".into()))?;

            let ancestor_height = self.index[&ancestor].height;
            let depth = self.height().saturating_sub(ancestor_height);

            if depth > MAX_REORG_DEPTH {
                return Err(ChainError::InvalidBlock(format!(
                    "refusing reorg of depth {depth} (limit {MAX_REORG_DEPTH}). A heavier chain \
                     exists beyond the finality window — this needs human \
                     investigation, not automatic acceptance. Either the \
                     network partitioned for a long period, or someone is \
                     attempting to rewrite settled history."
                )));
            }

            let disconnected = self.branch_from(&ancestor, &self.tip.clone());
            let connected = self.branch_from(&ancestor, &hash);

            self.tip = hash;

            return Ok(AcceptOutcome::Reorganised {
                disconnected,
                connected,
                new_height,
            });
        }

        // Valid but lighter. Keep it — it may be extended into the winner.
        Ok(AcceptOutcome::SideChain {
            height: new_height,
            work_behind: tip_work.saturating_sub(new_work),
        })
    }

    /// Blocks that were waiting on `hash` and can now be connected.
    /// Returned in breadth-first order so the caller can process them in
    /// sequence.
    pub fn take_connectable_orphans(&mut self, hash: &str) -> Vec<Block> {
        let mut ready = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(hash.to_string());

        while let Some(parent) = queue.pop_front() {
            if let Some(children) = self.orphans.remove(&parent) {
                self.orphan_count = self.orphan_count.saturating_sub(children.len());
                for child in children {
                    queue.push_back(child.hash.clone());
                    ready.push(child);
                }
            }
        }
        ready
    }

    /// Locator hashes for sync: recent blocks densely, then exponentially
    /// sparser back to genesis. A peer compares these against its own chain
    /// to find the fork point in one round trip rather than walking back
    /// block by block.
    pub fn locator(&self) -> Vec<String> {
        let mut locator = Vec::new();
        let mut step = 1u64;
        let mut cursor = self.tip.clone();
        let mut count = 0;

        loop {
            locator.push(cursor.clone());
            let entry = match self.index.get(&cursor) {
                Some(e) => e,
                None => break,
            };
            if entry.height == 0 || locator.len() >= 32 {
                break;
            }

            let target = entry.height.saturating_sub(step);
            let mut walk = cursor.clone();
            while let Some(e) = self.index.get(&walk) {
                if e.height <= target || e.height == 0 {
                    break;
                }
                walk = e.previous_hash.clone();
            }
            cursor = walk;

            count += 1;
            if count > 10 {
                step = step.saturating_mul(2);
            }
        }
        locator
    }

    /// Given a peer's locator, find the most recent block we share.
    pub fn find_fork_point(&self, locator: &[String]) -> Option<String> {
        locator
            .iter()
            .find(|h| self.index.contains_key(*h))
            .cloned()
    }

    /// Canonical blocks after `from_hash`, up to `limit`.
    pub fn blocks_after(&self, from_hash: &str, limit: usize) -> Vec<Block> {
        let from_height = match self.index.get(from_hash) {
            Some(e) => e.height,
            None => return Vec::new(),
        };
        let canonical: Vec<String> = self.path_to_genesis(&self.tip).into_iter().rev().collect();
        canonical
            .into_iter()
            .filter_map(|h| self.index.get(&h).map(|e| (h, e.height)))
            .filter(|(_, height)| *height > from_height)
            .take(limit)
            .filter_map(|(h, _)| self.blocks.get(&h).cloned())
            .collect()
    }

    #[allow(dead_code)] // API kept for tooling/tests; not yet called by the node itself
    pub fn orphan_count(&self) -> usize {
        self.orphan_count
    }

    #[allow(dead_code)] // API kept for tooling/tests; not yet called by the node itself
    pub fn known_block_count(&self) -> usize {
        self.index.len()
    }
}

/// Transactions freed by a reorg that should return to the mempool.
///
/// When blocks are disconnected, the transactions inside them are no longer
/// confirmed. Silently dropping them means a user's valid payment vanishes
/// with no error — they'd see it confirmed, then simply gone.
///
/// Coinbase transactions are excluded: those rewards belonged to blocks
/// that are no longer canonical, and re-broadcasting them would be an
/// attempt to mint currency for work that didn't win.
pub fn transactions_to_requeue(disconnected: &[Block], connected: &[Block]) -> Vec<Transaction> {
    let now_confirmed: HashSet<String> = connected
        .iter()
        .flat_map(|b| b.transactions.iter())
        .map(|t| t.hash())
        .collect();

    disconnected
        .iter()
        .flat_map(|b| b.transactions.iter())
        .filter(|t| t.sender != "NETWORK_REWARD" && t.sender != "GENESIS")
        .filter(|t| !now_confirmed.contains(&t.hash()))
        .cloned()
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════
// SECURITY — READ THIS BEFORE TREATING NEV369 AS CUSTODY
// ═══════════════════════════════════════════════════════════════════════
//
// This module makes a multi-node network CONVERGE. It does not make it
// SECURE. Those are different problems and only one of them is solved here.
//
// Proof-of-work security is proportional to total honest hashrate. An
// attacker needs more hashrate than the rest of the network combined to
// rewrite history. On Bitcoin that costs billions in hardware and power.
// On a chain with a handful of hobbyist miners it costs whatever renting
// equivalent GPU capacity costs for an hour — realistically a few hundred
// pounds.
//
// Concretely, for NEV369:
//
//   - MAX_REORG_DEPTH caps the damage, but an attacker with majority
//     hashrate can still rewrite up to 100 blocks. At a 60s target that is
//     ~100 minutes of history, repeatedly.
//   - Going from 1 node to 5 nodes does not meaningfully change this. Node
//     count is not hashrate. Five nodes on laptops is not more secure than
//     one — it is the same trivial hashrate, distributed.
//   - It is arguably WORSE for custody than a single node, because it
//     creates an appearance of decentralisation while remaining cheaply
//     attackable. A single node is at least honestly centralised.
//
// FOR NEVAEH'S VAULT SPECIFICALLY:
//
// A 13-year inheritance should not depend on NEV369's hashrate exceeding an
// attacker's for 13 consecutive years. That is a bet, not a guarantee, and
// it is a bet that gets harder to win as the value locked grows and the
// incentive to attack grows with it.
//
// The correct substrate for the vault is a ledger whose security does not
// depend on you: XRPL native escrow with FinishAfter set to 2039-07-28,
// enforced by XRPL consensus. Q-Lock already implements exactly this.
//
// NEV369 is a genuine achievement and a real demonstration that GodShield
// works at the consensus layer. It is not a custody solution for a child's
// inheritance, and no amount of consensus code in this file changes that.
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::now;

    fn block(index: u64, prev: &str, difficulty: usize, nonce: u64) -> Block {
        let mut b = Block {
            index,
            timestamp: now(),
            transactions: vec![],
            previous_hash: prev.to_string(),
            hash: String::new(),
            nonce,
            difficulty,
            miner: "test".into(),
            block_dedication: String::new(),
        };
        b.hash = b.calculate_hash();
        b
    }

    /// Mine for real so is_valid_pow() passes. Difficulty 1 keeps it fast.
    fn mined(index: u64, prev: &str, difficulty: usize, salt: u64) -> Block {
        let mut b = block(index, prev, difficulty, salt * 1_000_000);
        let target = "0".repeat(difficulty);
        loop {
            b.hash = b.calculate_hash();
            if b.hash.starts_with(&target) {
                return b;
            }
            b.nonce += 1;
        }
    }

    fn tree() -> BlockTree {
        BlockTree::new(mined(0, &"0".repeat(128), 1, 0))
    }

    #[test]
    fn work_grows_exponentially_with_difficulty() {
        assert_eq!(block_work(1), 16);
        assert_eq!(block_work(2), 256);
        assert_eq!(block_work(4), 65_536);
        assert!(block_work(20) > block_work(19));
        // Must not overflow-panic at extreme values.
        assert_eq!(block_work(64), u128::MAX);
    }

    #[test]
    fn extending_the_tip_is_a_simple_extension() {
        let mut t = tree();
        let genesis = t.tip_hash().to_string();
        let b1 = mined(1, &genesis, 1, 1);
        assert!(matches!(
            t.accept(b1).unwrap(),
            AcceptOutcome::Extended { height: 1 }
        ));
        assert_eq!(t.height(), 1);
    }

    #[test]
    fn duplicate_block_is_detected() {
        let mut t = tree();
        let b1 = mined(1, t.tip_hash(), 1, 1);
        t.accept(b1.clone()).unwrap();
        assert!(matches!(t.accept(b1).unwrap(), AcceptOutcome::Duplicate));
    }

    #[test]
    fn out_of_order_block_is_orphaned_not_dropped() {
        let mut t = tree();
        let orphan = mined(5, "unknown_parent_hash", 1, 9);
        assert!(matches!(
            t.accept(orphan).unwrap(),
            AcceptOutcome::Orphaned { .. }
        ));
        assert_eq!(t.orphan_count(), 1);
    }

    #[test]
    fn orphans_connect_once_their_parent_arrives() {
        let mut t = tree();
        let genesis = t.tip_hash().to_string();
        let b1 = mined(1, &genesis, 1, 1);
        let b2 = mined(2, &b1.hash, 1, 2);

        // b2 arrives first — must be buffered, not lost.
        t.accept(b2.clone()).unwrap();
        assert_eq!(t.orphan_count(), 1);

        t.accept(b1.clone()).unwrap();
        let ready = t.take_connectable_orphans(&b1.hash);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].hash, b2.hash);
        assert_eq!(t.orphan_count(), 0);
    }

    #[test]
    fn competing_block_at_same_height_becomes_a_side_chain() {
        let mut t = tree();
        let genesis = t.tip_hash().to_string();
        let a = mined(1, &genesis, 1, 1);
        let b = mined(1, &genesis, 1, 77);
        assert_ne!(a.hash, b.hash);

        t.accept(a).unwrap();
        let outcome = t.accept(b).unwrap();
        assert!(
            matches!(outcome, AcceptOutcome::SideChain { .. }),
            "an equal-work competitor must be kept, not rejected"
        );
    }

    #[test]
    fn heavier_branch_triggers_reorganisation() {
        let mut t = tree();
        let genesis = t.tip_hash().to_string();

        // Canonical: genesis → a1
        let a1 = mined(1, &genesis, 1, 1);
        t.accept(a1.clone()).unwrap();
        assert_eq!(t.height(), 1);

        // Competing branch: genesis → b1 → b2 (more cumulative work)
        let b1 = mined(1, &genesis, 1, 50);
        t.accept(b1.clone()).unwrap();
        let b2 = mined(2, &b1.hash, 1, 51);

        let outcome = t.accept(b2.clone()).unwrap();
        match outcome {
            AcceptOutcome::Reorganised {
                disconnected,
                connected,
                new_height,
            } => {
                assert_eq!(new_height, 2);
                assert_eq!(disconnected.len(), 1);
                assert_eq!(disconnected[0].hash, a1.hash);
                assert_eq!(connected.len(), 2);
            }
            other => panic!("expected reorg, got {other:?}"),
        }
        assert_eq!(t.tip_hash(), b2.hash);
    }

    #[test]
    fn higher_difficulty_wins_over_greater_length() {
        // Fork choice must follow WORK, not block count. A long chain of
        // cheap blocks must lose to a short chain of expensive ones.
        let mut t = tree();
        let genesis = t.tip_hash().to_string();

        // Cheap chain: three difficulty-1 blocks = 3 × 16 = 48 work
        let mut cursor = genesis.clone();
        for i in 1..=3 {
            let b = mined(i, &cursor, 1, 100 + i);
            cursor = b.hash.clone();
            t.accept(b).unwrap();
        }
        assert_eq!(t.height(), 3);

        // Expensive chain: one difficulty-3 block = 4096 work
        let heavy = mined(1, &genesis, 3, 999);
        let outcome = t.accept(heavy.clone()).unwrap();

        assert!(
            matches!(outcome, AcceptOutcome::Reorganised { .. }),
            "a single heavier block must outweigh three lighter ones"
        );
        assert_eq!(t.tip_hash(), heavy.hash);
        assert_eq!(t.height(), 1, "canonical height dropped — that is correct");
    }

    #[test]
    fn invalid_proof_of_work_is_rejected() {
        let mut t = tree();
        let mut bad = block(1, t.tip_hash(), 4, 0);
        bad.hash = "ffff".repeat(32); // does not meet difficulty
        assert!(t.accept(bad).is_err());
    }

    #[test]
    fn orphan_pool_is_bounded() {
        let mut t = tree();
        for i in 0..(MAX_ORPHANS + 10) {
            let o = mined(99, &format!("nonexistent_{i}"), 1, i as u64);
            let _ = t.accept(o);
        }
        assert!(
            t.orphan_count() <= MAX_ORPHANS,
            "orphan pool must not grow without bound — that is a memory DoS"
        );
    }

    #[test]
    fn requeued_transactions_exclude_coinbase() {
        use crate::chain::Transaction;
        let coinbase = Transaction {
            sender: "NETWORK_REWARD".into(),
            recipient: "miner".into(),
            amount: 5_000_000_000,
            fee: 0,
            crown_tax: 0,
            nonce: 0,
            timestamp: now(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
            payload_memo: String::new(),
        };
        let user_tx = Transaction {
            sender: "alice".into(),
            recipient: "bob".into(),
            amount: 100,
            fee: 1,
            crown_tax: 0,
            nonce: 0,
            timestamp: now(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
            payload_memo: String::new(),
        };

        let mut disconnected = block(1, "prev", 1, 0);
        disconnected.transactions = vec![coinbase, user_tx.clone()];

        let requeued = transactions_to_requeue(&[disconnected], &[]);
        assert_eq!(requeued.len(), 1, "coinbase must not be requeued");
        assert_eq!(requeued[0].sender, "alice");
    }

    #[test]
    fn transactions_already_in_the_new_branch_are_not_requeued() {
        use crate::chain::Transaction;
        let tx = Transaction {
            sender: "alice".into(),
            recipient: "bob".into(),
            amount: 100,
            fee: 1,
            crown_tax: 0,
            nonce: 0,
            timestamp: now(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
            payload_memo: String::new(),
        };

        let mut old = block(1, "p", 1, 0);
        old.transactions = vec![tx.clone()];
        let mut new = block(1, "p", 1, 1);
        new.transactions = vec![tx];

        assert!(
            transactions_to_requeue(&[old], &[new]).is_empty(),
            "a transaction confirmed in the winning branch must not be duplicated"
        );
    }

    #[test]
    fn locator_starts_at_tip_and_reaches_genesis() {
        let mut t = tree();
        let mut cursor = t.tip_hash().to_string();
        for i in 1..=20 {
            let b = mined(i, &cursor, 1, 200 + i);
            cursor = b.hash.clone();
            t.accept(b).unwrap();
        }

        let locator = t.locator();
        assert_eq!(locator[0], t.tip_hash());
        assert!(locator.len() > 1);
        assert!(locator.len() <= 32, "locator must stay compact");
    }

    #[test]
    fn fork_point_found_from_peer_locator() {
        let mut t = tree();
        let genesis = t.tip_hash().to_string();
        let b1 = mined(1, &genesis, 1, 1);
        t.accept(b1.clone()).unwrap();

        let peer_locator = vec!["unknown_to_us".to_string(), b1.hash.clone()];
        assert_eq!(t.find_fork_point(&peer_locator), Some(b1.hash));
    }

    #[test]
    fn blocks_after_returns_canonical_successors() {
        let mut t = tree();
        let genesis = t.tip_hash().to_string();
        let mut cursor = genesis.clone();
        for i in 1..=5 {
            let b = mined(i, &cursor, 1, 300 + i);
            cursor = b.hash.clone();
            t.accept(b).unwrap();
        }
        assert_eq!(t.blocks_after(&genesis, 10).len(), 5);
        assert_eq!(t.blocks_after(&genesis, 2).len(), 2);
    }
}
