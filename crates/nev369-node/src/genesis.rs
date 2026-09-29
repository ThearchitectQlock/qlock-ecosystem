// crates/nev369- node/src/genesis.rs
//
// ════════════════════════ ════════════════════════ ═══════════════════════
// GENESIS CONFIGURATION
//
// The premine addresses used to be hardcoded placeholder strings
// ("ARCHITECT_SOVEREIGN_KEY_01 "). No Dilithium5 key maps to those, so the
// premine was unspendable — safe, but meaningless.
//
// They are now runtime configuration, loaded from environment, validated
// as genuine Dilithium5 public keys, and PINNED INTO THE GENESIS BLOCK.
//
// The pinning matters more than it might look. Once genesis exists on disk,
// changing NEV369_ARCHITECT_ADDRESS in the environment would mean the
// running node's idea of who owns the premine no longer matches what the
// chain actually records. That is a silent, catastrophic state divergence.
// So: on every boot, the configured addresses are checked against what
// genesis says, and a mismatch is a hard refusal to start.
// ════════════════════════ ════════════════════════ ═══════════════════════

use crate::chain::{Amount, ChainError, ARCHITECT_PREMINE, NEVAEH_PREMINE};
use serde::{Deserialize, Serialize};

/// Dilithium5 public key: 2592 bytes = 5184 hex characters.
const DILITHIUM5_PUBKEY_HEX_LEN: usize = 5184;
/// 2039-07-28 00:00:00 UTC — Nevaeh's 18th birthday.
/// Verify independently: date -u -d @2195424000
pub const NEVAEH_UNLOCK_TIMESTAMP: u64 = 2_195_424_000;

pub const GENESIS_DEDICATION: &str ="Nevaeh, my daughter. To secure your freedom against a broken system, I taught myself Rust—the hardest computer language in the world—to build this unyielding sovereign node for you. I faced the worst of life's struggles so you would never have to. I love you infinitely, forever by your side.";

/// Placeholder values that must never survive into production.
const PLACEHOLDERS: &[&str] = &[
    "ARCHITECT_SOVEREIGN_KEY_01",
    "NEVAEH_NEV369_SOVEREIGN_VAULT",
    "",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GenesisConfig {
    /// Hex-encoded Dilithium5 public key from `godshield vault create`.
    pub architect_address: String,
    /// Hex-encoded Dilithium5 public key from `godshield vault create`.
    pub nevaeh_vault_address: String,
    pub architect_premine: Amount,
    pub nevaeh_premine: Amount,
    pub nevaeh_unlock_timestamp: u64,
    /// True when running with placeholder addresses. Permitted in
    /// development so the node is runnable before the ceremony; refused
    /// outright in production.
    pub development_mode: bool,
    /// Fixed block-0 timestamp. Every node on one network must build the
    /// identical genesis block; left unset, genesis is stamped with the
    /// current time, which only makes sense when starting a new network.
    /// Published for NEV369 mainnet in `chain-spec/nev369-mainnet.env`.
    #[serde(default)]
    pub genesis_timestamp: Option<u64>,
    /// The network's block-0 hash. When set, a node refuses to create or
    /// load any other genesis.
    #[serde(default)]
    pub expected_genesis_hash: Option<String>,
}

impl GenesisConfig {
    /// Load from environment.
    ///
    /// Production (NEV369_ENV=production) requires real addresses and will
    /// panic rather than start with placeholders. Development falls back to
    /// unspendable placeholder strings so you can run a node before the
    /// vault ceremony has happened.
    pub fn from_env(environment: &str) -> Result<Self, ChainError> {
        let architect = std::env::var("NEV369_ARCHITECT_ADDRESS").unwrap_or_default();
        let nevaeh = std::env::var("NEV369_NEVAEH_VAULT_ADDRESS").unwrap_or_default();

        let is_production = environment == "production";
        let placeholders_present = is_placeholder(&architect) || is_placeholder(&nevaeh);

        // Pinned genesis: the timestamp every node uses for block 0, and the
        // hash that result must have. Without them each new node would stamp
        // genesis with its own clock and start a separate chain.
        let genesis_timestamp = match std::env::var("NEV369_GENESIS_TIMESTAMP") {
            Ok(v) if !v.trim().is_empty() => Some(v.trim().parse::<u64>().map_err(|_| {
                ChainError::Storage(format!("NEV369_GENESIS_TIMESTAMP is not a number: {v}"))
            })?),
            _ => None,
        };
        let expected_genesis_hash = match std::env::var("NEV369_GENESIS_HASH") {
            Ok(v) if !v.trim().is_empty() => {
                let h = v.trim().to_ascii_lowercase();
                if h.len() != 128 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
                    return Err(ChainError::Storage(
                        "NEV369_GENESIS_HASH must be the 128-character hex hash of block 0".into(),
                    ));
                }
                Some(h)
            }
            _ => None,
        };
        if is_production && (genesis_timestamp.is_none() || expected_genesis_hash.is_none()) {
            return Err(ChainError::Storage(
                "Refusing to start in production without a pinned genesis.\n\
                 \n\
                 Set NEV369_GENESIS_TIMESTAMP and NEV369_GENESIS_HASH — copy them,\n\
                 with both premine addresses, from chain-spec/nev369-mainnet.env.\n\
                 Without them this node would create a new, separate network."
                    .into(),
            ));
        }

        if is_production && placeholders_present {
            return Err(ChainError::Storage(
                "Refusing to start in production with placeholder premine addresses.\n\
                 \n\
                 Run the vault ceremony first:\n\
                 \n\
                      godshield vault create --label architect-wallet ...\n\
                      godshield vault create --label nevaeh-vault ...\n\
                 \n\
                 Then set the printed addresses:\n\
                 \n\
                     NEV369_ARCHITECT_ADDRESS=<hex public key>\n\
                     NEV369_NEVAEH_VAULT_ADDRESS=<hex public key>\n\
                 \n\
                 Do NOT generate these keys anywhere other than a machine you\n\
                 control. Not in a browser, not over SSH to someone else's box,\n\
                 not by pasting into any chat or AI assistant."
                    .into(),
            ));
        }

        let config = if placeholders_present {
            tracing::warn!(
                "Running with PLACEHOLDER premine addresses — the premine is \
                   unspendable and this chain has no real ownership. Fine for \
 development. Never for production."
            );
            Self {
                architect_address: "ARCHITECT_SOVEREIGN_KEY_01".into(),

                nevaeh_vault_address: "NEVAEH_NEV369_SOVEREIGN_VAULT".into(),

                architect_premine: ARCHITECT_PREMINE,

                nevaeh_premine: NEVAEH_PREMINE,

                nevaeh_unlock_timestamp: NEVAEH_UNLOCK_TIMESTAMP,

                development_mode: true,
                genesis_timestamp,
                expected_genesis_hash,
            }
        } else {
            Self {
                architect_address: architect,

                nevaeh_vault_address: nevaeh,

                architect_premine: ARCHITECT_PREMINE,
                nevaeh_premine: NEVAEH_PREMINE,

                nevaeh_unlock_timestamp: NEVAEH_UNLOCK_TIMESTAMP,

                development_mode: false,
                genesis_timestamp,
                expected_genesis_hash,
            }
        };

        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ChainError> {
        if self.development_mode {
            // Placeholders are intentionally not valid keys. Nothing to check
            // beyond confirming they really are the known placeholders and
            // not some third arbitrary string someone typed in.
            if !is_placeholder(&self.architect_address)
                || !is_placeholder(&self.nevaeh_vault_address)
            {
                return Err(ChainError::Storage(
                    "development_mode is set but addresses are not the known \
 placeholders — refusing to guess what was intended"
                        .into(),
                ));
            }
            return Ok(());
        }

        validate_dilithium_address(" architect", &self.architect_address)?;

        validate_dilithium_address(" nevaeh vault", &self.nevaeh_vault_address)?;

        if self.architect_address == self.nevaeh_vault_address {
            return Err(ChainError::Storage(
                "Architect and Nevaeh vault addresses are identical. These must \
                     be two separate keys withseparately-held shares — if one is \
                     compromised the other must survive."
                    .into(),
            ));
        }

        let total = self
            .architect_premine
            .checked_add(self.nevaeh_premine)
            .ok_or_else(|| ChainError::Storage("premine total overflows".into()))?;
        if total > crate::chain::MAX_SUPPLY {
            return Err(ChainError::Storage("premine exceeds max supply".into()));
        }

        if self.nevaeh_unlock_timestamp <= crate::chain::now() {
            tracing::warn!(
                "Nevaeh's vault unlock timestamp is in the past — the vault is \
                   already spendable. If that is not intended, check \
 NEVAEH_UNLOCK_TIMESTAMP."
            );
        }
        Ok(())
    }

    /// Compare against the configuration recorded in the genesis block.
    ///
    /// Called on every boot. A mismatch means the environment has drifted
    /// from what the chain actually records, which would leave the node
    /// crediting the premine to an address that does not own it on-chain.
    /// That is not recoverable by restarting, so we refuse to run.
    pub fn assert_matches_genesis(&self, recorded: &GenesisConfig) -> Result<(), ChainError> {
        if self.architect_address != recorded.architect_address
            || self.nevaeh_vault_address != recorded.nevaeh_vault_address
        {
            return Err(ChainError::Storage(format!(
                "GENESIS MISMATCH — refusing to start.\n\
                   \n\
                   The genesis block on disk records:\n\
                     architect: {}\n\
                     nevaeh:    {}\n\
                   \n\
                   The current environment specifies:\n\
                     architect: {}\n\
                     nevaeh:    {}\n\
                   \n\
                   Either fix the environment variables to match the existing \
                   chain, or delete the database to start a NEW chain from a new \
                   genesis. Deleting the database destroys all history — be sure \
                   that is what you want.",
                truncate(&recorded.architect_address),
                truncate(&recorded.nevaeh_vault_address),
                truncate(&self.architect_address),
                truncate(&self.nevaeh_vault_address),
            )));
        }

        if self.nevaeh_unlock_timestamp != recorded.nevaeh_unlock_timestamp {
            return Err(ChainError::Storage(format!(
                "Time-lock mismatch: genesis records unlock at {}, environment \
                   specifies {}. The unlock date cannot be changed after genesis \
                   without invalidating the commitment made to the beneficiary.",
                recorded.nevaeh_unlock_timestamp, self.nevaeh_unlock_timestamp
            )));
        }

        Ok(())
    }

    /// True when this address is subject to the 2039 time-lock.
    pub fn is_timelocked(&self, address: &str) -> bool {
        address == self.nevaeh_vault_address
    }
}

fn is_placeholder(s: &str) -> bool {
    PLACEHOLDERS.contains(&s)
}

fn validate_dilithium_address(label: &str, addr: &str) -> Result<(), ChainError> {
    if is_placeholder(addr) {
        return Err(ChainError::Storage(format!(
            "{label} address is still a placeholder — run the vault ceremony first"
        )));
    }

    if addr.len() != DILITHIUM5_PUBKEY_HEX_LEN {
        return Err(ChainError::Storage(format!(
            "{} address must be a {}-character hex Dilithium5 public key, got {} \
                  characters. This should be the `public_key_hex` value printed by \
                  `godshield vault create`.",
            label,
            DILITHIUM5_PUBKEY_HEX_LEN,
            addr.len()
        )));
    }

    if !addr.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ChainError::Storage(format!(
            "{label} address contains non-hex characters"
        )));
    }

    // Confirm it round- trips as bytes of the right length, so a hex string
    // that is the right length but structurally wrong still gets caught.
    let bytes = hex::decode(addr)
        .map_err(|e| ChainError::Storage(format!("{label} address is not valid hex: {e}")))?;
    if bytes.len() != 2592 {
        return Err(ChainError::Storage(format!(
            "{} address decodes to {} bytes,expected 2592 (Dilithium5 public key)",
            label,
            bytes.len()
        )));
    }
    Ok(())
}

fn truncate(s: &str) -> String {
    if s.len() > 24 {
        format!("{}...{}", &s[..12], &s[s.len() - 8..])
    } else {
        s.to_string()
    }
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// TESTS
// ════════════════════════ ════════════════════════ ═══════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use godshield_core::GodKeyPair;

    fn real_address() -> String {
        hex::encode(&GodKeyPair::generate().unwrap().public_key)
    }

    fn valid_config() -> GenesisConfig {
        GenesisConfig {
            architect_address: real_address(),
            nevaeh_vault_address: real_address(),

            architect_premine: ARCHITECT_PREMINE,
            nevaeh_premine: NEVAEH_PREMINE,

            nevaeh_unlock_timestamp: NEVAEH_UNLOCK_TIMESTAMP,

            development_mode: false,
            genesis_timestamp: None,
            expected_genesis_hash: None,
        }
    }

    #[test]
    fn real_dilithium_addresses_validate() {
        assert!(valid_config().validate().is_ok());
    }

    #[test]
    fn generated_pubkey_is_expected_hex_length() {
        assert_eq!(real_address().len(), DILITHIUM5_PUBKEY_HEX_LEN);
    }

    #[test]
    fn placeholder_addresses_rejected_in_non_dev_config() {
        let mut c = valid_config();
        c.architect_address = "ARCHITECT_SOVEREIGN_KEY_01".into();
        assert!(
            c.validate().is_err(),
            "placeholders must not validate as real"
        );
    }

    #[test]
    fn short_address_rejected() {
        let mut c = valid_config();
        c.architect_address = "deadbeef".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn non_hex_address_rejected() {
        let mut c = valid_config();
        c.architect_address = "z".repeat(DILITHIUM5_PUBKEY_HEX_LEN);
        assert!(c.validate().is_err());
    }

    #[test]
    fn identical_addresses_rejected() {
        let mut c = valid_config();

        c.nevaeh_vault_address = c.architect_address.clone();
        assert!(
            c.validate().is_err(),
            "reusing one key for both vaults defeats the separation"
        );
    }

    #[test]
    fn production_refuses_placeholders() {
        std::env::remove_var("NEV369_ARCHITECT_ADDRESS");

        std::env::remove_var("NEV369_NEVAEH_VAULT_ADDRESS");
        let result = GenesisConfig::from_env("production");
        assert!(
            result.is_err(),
            "production must not boot with placeholders"
        );
    }
    #[test]
    fn development_permits_placeholders() {
        std::env::remove_var("NEV369_ARCHITECT_ADDRESS");

        std::env::remove_var("NEV369_NEVAEH_VAULT_ADDRESS");
        let c = GenesisConfig::from_env("development").unwrap();
        assert!(c.development_mode);
    }

    #[test]
    fn genesis_mismatch_is_refused() {
        let recorded = valid_config();
        let mut current = recorded.clone();

        current.architect_address = real_address();
        assert!(
            current.assert_matches_genesis(&recorded).is_err(),
            "changing the premine address after genesis must be refused"
        );
    }

    #[test]
    fn genesis_match_is_accepted() {
        let recorded = valid_config();
        assert!(recorded.assert_matches_genesis(&recorded).is_ok());
    }

    #[test]
    fn unlock_date_cannot_be_changed_after_genesis() {
        let recorded = valid_config();
        let mut current = recorded.clone();

        current.nevaeh_unlock_timestamp = 1;
        assert!(
            current.assert_matches_genesis(&recorded).is_err(),
            "the commitment to the beneficiary must not be silently movable"
        );
    }
}
