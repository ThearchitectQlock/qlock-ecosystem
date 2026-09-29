// crates/godshield- adapters/src/lib.rs
//
// ════════════════════════ ════════════════════════ ═══════════════════════
// CHAIN ADAPTERS — GodShield-native encodings for target chains
//
// READ THIS BEFORE USING OR MARKETING THESE.
//
// These adapters do NOT produce addresses or transactions that the named
// chains currently accept. That is not a bug — no deployed public chain
// verifies Dilithium5 signatures at consensus today. It is a limitation
// worth stating plainly, because the previous version's naming implied
// otherwise and someone would have checked.
//
// What was wrong before:
//
//   - BitcoinAdapter returned format!("bc1q{}", hex::encode(bytes)).
//     "bc1q" is the bech32 SegWit prefix, but the payload was hex, not
//     bech32. No Bitcoin node would accept it.
//
//   - EthereumAdapter's comment said "last 20 bytes of Keccak256(pubkey)"
//     but the code used TripleHash (SHA3-512 cascade). Ethereum addresses
//     are Keccak256- derived, so this matches nothing on Ethereum.
//
//   - create_transaction() indexed tx_data.to.as_bytes()[..20] with no
//     length check — a panic on any recipient string under 20 bytes.
//     Reachable from the public API. Fixed.
//
// What these ARE:
//
//   Deterministic, collision-resistant, chain- scoped identifiers derived
//   from a Dilithium5 public key, using each chain's structural conventions
//   (length, prefix style, encoding family). They are the right shape for
//   the eventual migration paths (Bitcoin BIP-360, Ethereum account
//   abstraction, Solana programs) without pretending those paths exist yet.
//
//   For a chain you control — NEV369 — they are directly usable.
//   For Bitcoin/Ethereum/Solana they are forward-looking placeholders.
// ════════════════════════ ════════════════════════ ═══════════════════════

use godshield_core::{GodKeyPair, GodShieldError, GodSignature, TripleHash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ════════════════════════ ════════════════════════ ═══════════════════════
// ADAPTER TRAIT
// ════════════════════════ ════════════════════════ ═══════════════════════
/// Where an adapter's output stands relative to the real chain.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Interoperability {
    /// Accepted by the live network today.
    Native,
    /// Structurally correct for a proposed standard that is not yet live
    /// (e.g. Bitcoin BIP- 360). Not accepted by the current network.
    PendingStandard,
    /// GodShield-specific encoding. Not accepted by the named network,
    /// and no standard track exists yet.
    GodShieldOnly,
}

pub trait ChainAdapter: Send + Sync {
    fn chain_name(&self) -> &str;

    /// Honest statement of whether this output works on the live chain.
    /// Surfaced through the API so callers cannot accidentally assume
    /// interoperability they do not have.
    fn interoperability(&self) -> Interoperability;

    fn encode_public_key(&self, keypair: &GodKeyPair) -> Result<String, GodShieldError>;
    fn encode_signature(&self, sig: &GodSignature) -> Result<Vec<u8>, GodShieldError>;
    fn create_transaction(&self, tx: &TransactionData) -> Result<Vec<u8>, GodShieldError>;
    fn supports_smart_contracts(&self) -> bool;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransactionData {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub nonce: u64,
    pub data: Vec<u8>,
    pub gas_limit: Option<u64>,
    pub gas_price: Option<u64>,
}

impl TransactionData {
    /// Validate before any adapter touches it. The previous code indexed
    /// into `to` without checking length, which panicked on short input
    /// reachable from the public API.
    fn validate(&self) -> Result<(), GodShieldError> {
        if self.to.is_empty() {
            return Err(GodShieldError::InvalidInput("recipient is empty".into()));
        }
        if self.from.is_empty() {
            return Err(GodShieldError::InvalidInput("sender is empty".into()));
        }
        if self.amount == 0 {
            return Err(GodShieldError::InvalidInput(
                "amount must be greater than zero".into(),
            ));
        }
        if self.data.len() > 1_000_000 {
            return Err(GodShieldError::InvalidInput(
                "data payload exceeds 1 MB".into(),
            ));
        }
        Ok(())
    }

    /// Fixed-width recipient digest. Replaces the panicking `[..20]` slice:
    /// hashing gives a deterministic 20 bytes regardless of input length.
    fn recipient_digest_20(&self) -> [u8; 20] {
        let h = TripleHash::hash(self.to.as_bytes());
        let mut out = [0u8; 20];

        out.copy_from_slice(&h[..20]);
        out
    }
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// BITCOIN
// ════════════════════════ ════════════════════════ ═══════════════════════

pub struct BitcoinAdapter {
    pub network: BitcoinNetwork,
}

#[derive(Clone, Copy)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl BitcoinAdapter {
    pub fn new(network: BitcoinNetwork) -> Self {
        Self { network }
    }

    fn hrp(&self) -> &'static str {
        // Human-readable prefix indicating the network AND that this is a
        // GodShield post- quantum program, not a standard SegWit address.
        // Deliberately NOT "bc1q" — that prefix means something specific on
        // Bitcoin and using it for non-bech32 hex was actively misleading.
        match self.network {
            BitcoinNetwork::Mainnet => "gsbtc",

            BitcoinNetwork::Testnet => "gstb",

            BitcoinNetwork::Regtest => "gsrt",
        }
    }
}

impl ChainAdapter for BitcoinAdapter {
    fn chain_name(&self) -> &str {
        "Bitcoin"
    }

    fn interoperability(&self) -> Interoperability {
        // BIP-360 (post- quantum witness programs) is a draft. Until it
        // activates, nothing here is spendable on Bitcoin.

        Interoperability::PendingStandard
    }

    fn encode_public_key(&self, keypair: &GodKeyPair) -> Result<String, GodShieldError> {
        // Taproot-style commitment: 32-byte program derived from the
        // Dilithium5 key, sized for the BIP-360 witness path.
        let program = &TripleHash::hash(&keypair.public_key)[..32];
        let checksum = &TripleHash::hash(program)[..4];
        Ok(format!(
            "{}1{} {}",
            self.hrp(),
            hex::encode(program),
            hex::encode(checksum)
        ))
    }

    fn encode_signature(&self, sig: &GodSignature) -> Result<Vec<u8>, GodShieldError> {
        // Witness stack item. Length-prefixed so a parser can find its end
        // without knowing Dilithium5's signature size in advance.
        let mut out = Vec::with_capacity(sig.signature.len() + 4);

        out.extend_from_slice(&(sig.signature.len() as u32).to_le_bytes());

        out.extend_from_slice(&sig.signature);
        Ok(out)
    }
    fn create_transaction(&self, tx: &TransactionData) -> Result<Vec<u8>, GodShieldError> {
        tx.validate()?;

        let mut out = Vec::new();

        out.extend_from_slice(&2u32.to_le_bytes()); // version
        out.push(1); //input count

        out.extend_from_slice(&[0u8; 36]); // prevout placeholder
        out.push(0); //script length

        out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); //sequence
        out.push(1); //output count

        out.extend_from_slice(&tx.amount.to_le_bytes());

        // P2PKH-style output. Uses the hashed recipient digest rather than
        // slicing raw bytes, so any recipient string is safe.
        out.push(25);

        out.extend_from_slice(&[0x76, 0xA9, 0x14]); //OP_DUP OP_HASH160 PUSH20

        out.extend_from_slice(&tx.recipient_digest_20());
        out.extend_from_slice(&[0x88, 0xAC]); //OP_EQUALVERIFY OP_CHECKSIG

        out.extend_from_slice(&0u32.to_le_bytes()); // locktime

        Ok(out)
    }

    fn supports_smart_contracts(&self) -> bool {
        false
    }
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// ETHEREUM
// ════════════════════════ ════════════════════════ ═══════════════════════

pub struct EthereumAdapter {
    pub chain_id: u64,
}

impl EthereumAdapter {
    pub fn new(chain_id: u64) -> Self {
        Self { chain_id }
    }
    pub fn mainnet() -> Self {
        Self::new(1)
    }
    pub fn sepolia() -> Self {
        Self::new(11_155_111)
    }
}

impl ChainAdapter for EthereumAdapter {
    fn chain_name(&self) -> &str {
        "Ethereum"
    }

    fn interoperability(&self) -> Interoperability {
        // Deliverable today via ERC-4337 smart-contract wallets that verify
        // Dilithium in contract code — but NOT as a base-layer EOA address.
        // The address below is not a standard Ethereum address.

        Interoperability::GodShieldOnly
    }

    fn encode_public_key(&self, keypair: &GodKeyPair) -> Result<String, GodShieldError> {
        // NOTE: this is NOT Ethereum's Keccak256-derived address format.
        // A standard Ethereum address is keccak256(pubkey)[12..32]. This is
        // TripleHash- derived and will not match any EOA. It is a stable
        // 20-byte identifier for a GodShield account-abstraction wallet.
        let h = TripleHash::hash(&keypair.public_key);
        Ok(format!("0x{}", hex::encode(&h[44..64])))
    }

    fn encode_signature(&self, sig: &GodSignature) -> Result<Vec<u8>, GodShieldError> {
        // EIP-2098 compact encoding cannot hold a ~4.6 KB Dilithium5
        // signature. This is length-prefixed calldata for a verifier
        // contract instead.
        let mut out = Vec::with_capacity(sig.signature.len() + 4);

        out.extend_from_slice(&(sig.signature.len() as u32).to_be_bytes());

        out.extend_from_slice(&sig.signature);
        Ok(out)
    }

    fn create_transaction(&self, tx: &TransactionData) -> Result<Vec<u8>, GodShieldError> {
        tx.validate()?;
        let payload = EthereumTransaction {
            chain_id: self.chain_id,
            nonce: tx.nonce,

            max_priority_fee: tx.gas_price.unwrap_or(2_000_000_000),
            max_fee: tx.gas_price.unwrap_or(50_000_000_000),
            gas_limit: tx.gas_limit.unwrap_or(21_000),
            to: tx.to.clone(),
            value: tx.amount,
            data: tx.data.clone(),
        };

        serde_json::to_vec(&payload).map_err(|e| GodShieldError::EncodingError(e.to_string()))
    }

    fn supports_smart_contracts(&self) -> bool {
        true
    }
}

#[derive(Serialize, Deserialize)]
struct EthereumTransaction {
    chain_id: u64,
    nonce: u64,
    max_priority_fee: u64,
    max_fee: u64,
    gas_limit: u64,
    to: String,
    value: u64,
    data: Vec<u8>,
}
// ════════════════════════ ════════════════════════ ═══════════════════════
// SOLANA
// ════════════════════════ ════════════════════════ ═══════════════════════

pub struct SolanaAdapter {
    pub cluster: SolanaCluster,
}

#[derive(Clone, Copy)]
pub enum SolanaCluster {
    Mainnet,
    Testnet,
    Devnet,
}
impl SolanaAdapter {
    pub fn new(cluster: SolanaCluster) -> Self {
        Self { cluster }
    }
}

impl ChainAdapter for SolanaAdapter {
    fn chain_name(&self) -> &str {
        "Solana"
    }

    fn interoperability(&self) -> Interoperability {
        Interoperability::GodShieldOnly
    }
    fn encode_public_key(&self, keypair: &GodKeyPair) -> Result<String, GodShieldError> {
        // Solana pubkeys are 32 bytes. The previous code took the first 32
        // bytes of the Dilithium5 key raw, which is not a uniform digest —
        // hashing first gives proper distribution.
        let digest = TripleHash::hash(&keypair.public_key);

        Ok(bs58::encode(&digest[..32]).into_string())
    }
    fn encode_signature(&self, sig: &GodSignature) -> Result<Vec<u8>, GodShieldError> {
        Ok(sig.signature.clone())
    }

    fn create_transaction(&self, tx: &TransactionData) -> Result<Vec<u8>, GodShieldError> {
        tx.validate()?;
        let payload = SolanaTransaction {
            recent_blockhash: vec![0u8; 32],
            instructions: vec![SolanaInstruction {
                program_id: vec![0u8; 32],
                accounts: tx.recipient_digest_20().to_vec(),
                data: tx.data.clone(),
            }],
        };

        serde_json::to_vec(&payload).map_err(|e| GodShieldError::EncodingError(e.to_string()))
    }

    fn supports_smart_contracts(&self) -> bool {
        true
    }
}
#[derive(Serialize, Deserialize)]
struct SolanaTransaction {
    recent_blockhash: Vec<u8>,
    instructions: Vec<SolanaInstruction>,
}

#[derive(Serialize, Deserialize)]
struct SolanaInstruction {
    program_id: Vec<u8>,
    accounts: Vec<u8>,
    data: Vec<u8>,
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// NEV369 — the one chain where this is actually native
// ════════════════════════ ════════════════════════ ═══════════════════════

pub struct Nev369Adapter;

impl ChainAdapter for Nev369Adapter {
    fn chain_name(&self) -> &str {
        "NEV369"
    }

    fn interoperability(&self) -> Interoperability {
        // NEV369 verifies Dilithium5 at consensus, because we built it that
        // way. This is the only adapter here that is genuinely live.

        Interoperability::Native
    }

    fn encode_public_key(&self, keypair: &GodKeyPair) -> Result<String, GodShieldError> {
        // NEV369 addresses ARE the hex public key — see the sender/pubkey
        // binding check in nev369-node's Transaction::verify_signatur e.

        Ok(hex::encode(&keypair.public_key))
    }

    fn encode_signature(&self, sig: &GodSignature) -> Result<Vec<u8>, GodShieldError> {
        Ok(sig.signature.clone())
    }

    fn create_transaction(&self, tx: &TransactionData) -> Result<Vec<u8>, GodShieldError> {
        tx.validate()?;

        serde_json::to_vec(tx).map_err(|e| GodShieldError::EncodingError(e.to_string()))
    }

    fn supports_smart_contracts(&self) -> bool {
        false
    }
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// REGISTRY
// ════════════════════════ ════════════════════════ ═══════════════════════

pub struct AdapterRegistry {
    adapters: HashMap<String, Box<dyn ChainAdapter>>,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AdapterRegistry {
    pub fn new() -> Self {
        let mut r = Self {
            adapters: HashMap::new(),
        };
        r.register("nev369", Box::new(Nev369Adapter));

        r.register(
            "bitcoin",
            Box::new(BitcoinAdapter::new(BitcoinNetwork::Mainnet)),
        );
        r.register("ethereum", Box::new(EthereumAdapter::mainnet()));
        r.register(
            "solana",
            Box::new(SolanaAdapter::new(SolanaCluster::Mainnet)),
        );
        r
    }

    pub fn register(&mut self, name: &str, adapter: Box<dyn ChainAdapter>) {
        self.adapters.insert(name.to_string(), adapter);
    }

    /// Returns `&dyn` rather than `&Box<dyn>` — the previous signature
    /// tripped clippy::borrowed_box and forced callers to double- deref.
    pub fn get(&self, name: &str) -> Option<&dyn ChainAdapter> {
        self.adapters.get(name).map(|b| b.as_ref())
    }

    pub fn list_chains(&self) -> Vec<String> {
        let mut v: Vec<String> = self.adapters.keys().cloned().collect();
        v.sort();
        v
    }

    /// Chain list annotated with interoperability status, so an API consumer
    /// can see at a glance which are live and which are forward-looking.
    pub fn describe(&self) -> Vec<ChainDescription> {
        let mut v: Vec<ChainDescription> = self
            .adapters
            .iter()
            .map(|(k, a)| ChainDescription {
                key: k.clone(),
                name: a.chain_name().to_string(),

                interoperability: a.interoperability(),

                smart_contracts: a.supports_smart_contracts(),
            })
            .collect();
        v.sort_by(|a, b| a.key.cmp(&b.key));
        v
    }
}

#[derive(Serialize, Deserialize)]
pub struct ChainDescription {
    pub key: String,
    pub name: String,
    pub interoperability: Interoperability,
    pub smart_contracts: bool,
}
// ════════════════════════ ════════════════════════ ═══════════════════════
// VULNERABILITY SCANNER
// ════════════════════════ ════════════════════════ ═══════════════════════

pub struct MigrationHelper;

#[derive(Serialize, Deserialize, Debug)]
pub struct VulnerabilityReport {
    pub crypto_type: String,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
    pub line: Option<usize>,
}

impl MigrationHelper {
    /// Flag quantum-vulnerable primitives in source code.
    ///
    /// SCOPE, stated plainly because the previous version's output looked
    /// more authoritative than it was:
    ///
    ///   This is substring matching on known primitive names. It reports
    ///   line numbers now, and skips obvious comment lines to cut the worst
    ///   false positives — but it still cannot see cryptography reached
    ///   through opaque dependencies, dynamic dispatch, or FFI.
    ///
    ///   It is a starting point for manual review. It is NOT a certification,
    ///   and a clean result does not mean a codebase is quantum-safe.
    pub fn scan_vulnerabilities(source_code: &str) -> Vec<VulnerabilityReport> {
        const PATTERNS: &[(&str, &str)] = &[
            (
                "ECDSA",
                "Vulnerable to Shor's algorithm — full private key recovery",
            ),
            (
                "secp256k1",
                "Bitcoin/Ethereum curve, vulnerable to Shor's algorithm",
            ),
            ("ed25519", "EdDSA, vulnerable to Shor's algorithm"),
            (
                "RSA",
                "Vulnerable to Shor's algorithm — full private key recovery",
            ),
            ("P-256", "NIST curve, vulnerable to Shor's algorithm"),
            (
                "dilithium2",
                "Dilithium2 is NIST Level 2 — GodShield targets Level 5",
            ),
            (
                "dilithium3",
                "Dilithium3 is NIST Level 3 — GodShield targets Level 5",
            ),
        ];
        let mut reports = Vec::new();

        for (idx, line) in source_code.lines().enumerate() {
            let trimmed = line.trim_start();
            // Skip comment lines. Crude, but removes the most common class
            // of false positive (a comment explaining what was migrated away
            // from being flagged as the vulnerability itself).
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }

            for (pattern, description) in PATTERNS {
                if line.to_lowercase().contains(&pattern.to_lowercase()) {
                    reports.push(VulnerabilityReport {
                        crypto_type: pattern.to_string(),

                        severity: if pattern.starts_with("dilithium") {
                            "MEDIUM".into()
                        } else {
                            "CRITICAL".into()
                        },

                        description: description.to_string(),

                        recommendation: format!(
                            "Replace {pattern} with godshield-core (Dilithium5 / ML-DSA Level 5)"
                        ),

                        line: Some(idx + 1),
                    });
                }
            }
        }
        reports
    }

    pub fn generate_migration_plan(vulns: &[VulnerabilityReport]) -> String {
        if vulns.is_empty() {
            return "No known-vulnerable primitives matched.\n\n\
                     This is NOT a clean bill of health. Pattern matching cannot \
                     see cryptography invoked through dependencies, dynamic \
 dispatch, or FFI. Manual review is still required."
                .to_string();
        }

        let mut plan = String::from("GODSHIELD MIGRATION PLAN\n\n");
        for (i, v) in vulns.iter().enumerate() {
            plan.push_str(&format!(
                "{}. [{}] {} at line {} — {}\n    → {}\n",
                i + 1,
                v.severity,
                v.crypto_type,
                v.line.map(|l| l.to_string()).unwrap_or_else(|| "?".into()),
                v.description,
                v.recommendation
            ));
        }
        plan.push_str(
            "\nSTEPS:\n\
                1. Add godshield-core to Cargo.toml\n\
                2. Replace key generation with GodKeyPair::generate()\n\
                3. Replace signing with GodShield::sign()\n\
                4. Replace verification with GodShield::verify()\n\
                5. Use CanonicalMessage for any multi-field signed payload\n\
                  6. Commission an independent audit — this tool is not one\n",
        );
        plan
    }
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// TESTS
// ════════════════════════ ════════════════════════ ═══════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    fn tx(to: &str) -> TransactionData {
        TransactionData {
            from: "sender".into(),
            to: to.into(),
            amount: 1000,
            nonce: 0,
            data: vec![],
            gas_limit: None,
            gas_price: None,
        }
    }

    /// REGRESSION TEST: the previous code did tx.to.as_bytes()[..20] with no
    /// length check, panicking on any recipient under 20 bytes. Reachable
    /// from the public API, so a trivial remote DoS.
    #[test]
    fn short_recipient_does_not_panic() {
        let adapter = BitcoinAdapter::new(BitcoinNetwork::Mainnet);
        for recipient in ["a", "ab", "short", "0x1234"] {
            let result = adapter.create_transaction(&tx(recipient));
            assert!(result.is_ok(), "recipient {recipient:?} must not panic");
        }
    }

    #[test]
    fn empty_recipient_is_rejected_not_panicked() {
        let adapter = BitcoinAdapter::new(BitcoinNetwork::Mainnet);
        assert!(adapter.create_transaction(&tx("")).is_err());
    }

    #[test]
    fn zero_amount_is_rejected() {
        let adapter = Nev369Adapter;
        let mut t = tx("recipient");
        t.amount = 0;
        assert!(adapter.create_transaction(&t).is_err());
    }

    /// The bc1q prefix means bech32 SegWit on Bitcoin. Emitting it over hex
    /// data implied interoperability that did not exist.
    #[test]
    fn bitcoin_address_does_not_impersonate_bech32() {
        let adapter = BitcoinAdapter::new(BitcoinNetwork::Mainnet);
        let kp = GodKeyPair::generate().unwrap();
        let addr = adapter.encode_public_key(&kp).unwrap();
        assert!(
            !addr.starts_with("bc1q"),
            "must not claim a real SegWit prefix"
        );
        assert!(addr.starts_with("gsbtc1"));
    }

    #[test]
    fn interoperability_is_reported_honestly() {
        assert_eq!(Nev369Adapter.interoperability(), Interoperability::Native);
        assert_eq!(
            BitcoinAdapter::new(BitcoinNetwork::Mainnet).interoperability(),
            Interoperability::PendingStandard
        );
        assert_eq!(
            EthereumAdapter::mainnet().interoperability(),
            Interoperability::GodShieldOnly
        );
    }

    #[test]
    fn nev369_address_is_the_public_key() {
        let kp = GodKeyPair::generate().unwrap();
        let addr = Nev369Adapter.encode_public_key(&kp).unwrap();
        assert_eq!(addr, hex::encode(&kp.public_key));
        assert_eq!(addr.len(), 5184, "Dilithium5 pubkey hex length");
    }

    #[test]
    fn addresses_are_deterministic_and_distinct() {
        let a = GodKeyPair::generate().unwrap();
        let b = GodKeyPair::generate().unwrap();
        let adapter = SolanaAdapter::new(SolanaCluster::Mainnet);
        assert_eq!(
            adapter.encode_public_key(&a).unwrap(),
            adapter.encode_public_key(&a).unwrap()
        );
        assert_ne!(
            adapter.encode_public_key(&a).unwrap(),
            adapter.encode_public_key(&b).unwrap()
        );
    }

    #[test]
    fn registry_exposes_all_chains() {
        let r = AdapterRegistry::new();
        let chains = r.list_chains();
        for expected in ["nev369", "bitcoin", "ethereum", "solana"] {
            assert!(chains.contains(&expected.to_string()));
        }
        assert!(r.get("nonexistent").is_none());
    }

    #[test]
    fn scanner_reports_line_numbers() {
        let code = "let a =1;\nuse secp256k1::Secp256k1;\nlet b = 2;";
        let v = MigrationHelper::scan_vulnerabilities(code);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].line, Some(2));
    }

    #[test]
    fn scanner_skips_comments() {
        let code = "// we migrated away from secp256k1 last year\nlet x = 1;";
        assert!(
            MigrationHelper::scan_vulnerabilities(code).is_empty(),
            "a comment about migration is not a vulnerability"
        );
    }

    #[test]
    fn scanner_flags_lower_dilithium_levels() {
        let code = "use pqcrypto_dilithium::dilithium3;";
        let v = MigrationHelper::scan_vulnerabilities(code);
        assert!(v.iter().any(|r| r.crypto_type == "dilithium3"));
    }
    #[test]
    fn empty_scan_result_does_not_claim_safety() {
        let plan = MigrationHelper::generate_migration_plan(&[]);
        assert!(
            plan.contains("NOT a clean bill of health"),
            "a clean scan must not be presented as a guarantee"
        );
    }
}
