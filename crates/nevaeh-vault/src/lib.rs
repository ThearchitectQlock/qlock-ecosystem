// crates/nevaeh-vault/src/lib.rs
//
// ═══════════════════════════════════════════════════════════════════════
// TIME-LOCKED INHERITANCE VAULT — v2, generalised
//
// Beneficiary: Nevaeh — DOB 28.07.2021
// Unlocks:     28.07.2039 (18th birthday)
//
// WHAT CHANGED FROM v1 AND WHY:
//
// v1 could only hold a Dilithium5 keypair. That was fine while everything
// lived on NEV369. But the inheritance now sits in an XRPL native escrow,
// and XRPL uses ed25519/secp256k1 — a completely different key type. The
// vault could not hold the key to the money it was protecting.
//
// v2 holds arbitrary secret material with the same 3-of-5 Shamir
// construction. Three vaults are now expected:
//
//   1. nevaeh-xrpl-seed   → the XRPL seed for the escrow destination.
//                           THIS IS THE ONE THAT HOLDS THE ACTUAL MONEY.
//   2. nevaeh-nev369      → Dilithium5 key for the NEV369 premine.
//   3. architect-wallet   → Dilithium5 key, 2-of-3, no time-lock.
//
// v1 vaults still load — see `Version::V1` handling in from_json.
//
// ═══════════════════════════════════════════════════════════════════════
// DESIGN RATIONALE — unchanged from v1, restated because it still governs
//
// The threat over 13 years is LOSS, not theft. A forgotten passphrase, a
// dead drive, a fire, or the person who set it up not being around. A
// single passphrase-encrypted file fails all four.
//
//   1. Secret encrypted with a random 32-byte master key (AES-256-GCM).
//      The resulting blob is PUBLIC — copy it everywhere.
//   2. Master key split by Shamir into 5 shares, 3 required.
//   3. Two shares reveal nothing. Not "less" — mathematically zero.
// ═══════════════════════════════════════════════════════════════════════

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use chrono::{DateTime, TimeZone, Utc};
use godshield_core::{GodKeyPair, TripleHash};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sharks::{Share, Sharks};
use std::fmt;
use zeroize::Zeroize;

// ═══════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

/// 2039-07-28 00:00:00 UTC — Nevaeh's 18th birthday.
/// Verify independently:  date -u -d @2195424000
pub const NEVAEH_UNLOCK_TIMESTAMP: i64 = 2_195_424_000;
pub const NEVAEH_DOB: &str = "2021-07-28";

pub const DEFAULT_SHARES_TOTAL: u8 = 5;
pub const DEFAULT_SHARES_REQUIRED: u8 = 3;

pub const VAULT_VERSION: u32 = 2;

const MASTER_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

// ═══════════════════════════════════════════════════════════════════════
// SECRET KIND
// ═══════════════════════════════════════════════════════════════════════

/// What kind of secret this vault holds. Recorded so recovery can validate
/// the right thing, and so whoever opens it in 2039 knows what they have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretKind {
    /// GodShield / Dilithium5 secret key. Used by NEV369 and attestation.
    Dilithium5,
    /// XRP Ledger family seed (the `s...` string a wallet gives you).
    /// This is what controls funds on XRPL.
    XrplSeed,
    /// Arbitrary bytes. No structural validation on recovery beyond the
    /// integrity digest.
    Raw,
}

impl SecretKind {
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Dilithium5 => "Dilithium5 secret key (GodShield / NEV369)",
            Self::XrplSeed => "XRP Ledger family seed — controls funds on XRPL",
            Self::Raw => "raw secret material",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum VaultError {
    InsufficientShares {
        have: usize,
        need: u8,
    },
    ShareRecoveryFailed(String),
    DecryptionFailed,
    IntegrityFailed,
    StillLocked {
        unlocks_at: i64,
        now: i64,
    },
    InvalidShare(String),
    WrongSecretKind {
        expected: SecretKind,
        found: SecretKind,
    },
    Crypto(String),
    Encoding(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InsufficientShares { have, need } => write!(
                f,
                "Not enough shares: have {have}, need {need}. The remaining guardians \
                 are listed in the vault file's guardian_directory."
            ),
            Self::ShareRecoveryFailed(m) => write!(f, "Share reconstruction failed: {m}"),
            Self::DecryptionFailed => write!(
                f,
                "Decryption failed. Either these shares belong to a different \
                 vault, or this copy is corrupted. Try another backup."
            ),
            Self::IntegrityFailed => write!(
                f,
                "Recovered secret does not match the digest recorded at creation. \
                 Do not use it. Try another backup copy of the vault file."
            ),
            Self::StillLocked { unlocks_at, now } => write!(
                f,
                "Time-locked. Approximately {} days remaining.",
                (unlocks_at - now) / 86_400
            ),
            Self::InvalidShare(m) => write!(f, "Invalid share: {m}"),
            Self::WrongSecretKind { expected, found } => write!(
                f,
                "This vault holds {} — you asked for {}.",
                found.describe(),
                expected.describe()
            ),
            Self::Crypto(m) => write!(f, "Cryptographic error: {m}"),
            Self::Encoding(m) => write!(f, "Encoding error: {m}"),
        }
    }
}

impl std::error::Error for VaultError {}

// ═══════════════════════════════════════════════════════════════════════
// TIME LOCK
// ═══════════════════════════════════════════════════════════════════════

pub struct TimeLock;

#[derive(Debug, Serialize)]
pub struct LockStatus {
    pub unlocked: bool,
    pub unlocks_at: i64,
    pub unlocks_at_human: String,
    pub seconds_remaining: i64,
    pub days_remaining: i64,
    pub years_remaining: f64,
}

impl TimeLock {
    pub fn status(unlock_timestamp: i64) -> LockStatus {
        let now = Utc::now().timestamp();
        let remaining = (unlock_timestamp - now).max(0);
        let human = Utc
            .timestamp_opt(unlock_timestamp, 0)
            .single()
            .map(|dt: DateTime<Utc>| dt.format("%d %B %Y, %H:%M UTC").to_string())
            .unwrap_or_else(|| "invalid timestamp".to_string());

        LockStatus {
            unlocked: now >= unlock_timestamp,
            unlocks_at: unlock_timestamp,
            unlocks_at_human: human,
            seconds_remaining: remaining,
            days_remaining: remaining / 86_400,
            years_remaining: remaining as f64 / 31_557_600.0,
        }
    }

    /// HONEST NOTE ON WHAT THIS GUARANTEES:
    ///
    /// This check is enforced by software. Anyone holding the share
    /// threshold AND able to edit this file can bypass it. It is a
    /// commitment device and an accident guard, not a cryptographic
    /// guarantee against three colluding guardians.
    ///
    /// The guarantee that DOES hold regardless lives on XRPL: the escrow's
    /// FinishAfter is enforced by consensus, not by this code. This vault
    /// protects the KEY; XRPL protects the FUNDS.
    pub fn enforce(unlock_timestamp: i64) -> Result<(), VaultError> {
        let now = Utc::now().timestamp();
        if now < unlock_timestamp {
            return Err(VaultError::StillLocked {
                unlocks_at: unlock_timestamp,
                now,
            });
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// VAULT FILE — public, safe to copy anywhere
// ═══════════════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Clone)]
pub struct TimeLockedVault {
    pub version: u32,
    pub label: String,
    pub beneficiary: String,
    pub beneficiary_dob: Option<String>,

    pub secret_kind: SecretKind,

    /// Public counterpart to the secret. For Dilithium5 this is the hex
    /// public key; for an XRPL seed it is the classic address (r...).
    /// Always safe to publish — it is how you find the funds on-ledger.
    pub public_identifier: String,

    /// TripleHash of `public_identifier`. Binds shares to this vault.
    pub fingerprint: String,

    /// TripleHash of the PLAINTEXT secret, so recovery can confirm it got
    /// the right bytes back.
    ///
    /// Is storing this a leak? Only if the secret has low entropy. A
    /// Dilithium5 secret key is several KB of key material; an XRPL seed is 128
    /// bits. Neither is brute-forceable from a digest. The integrity check
    /// is worth far more than the theoretical exposure.
    pub secret_digest: String,

    pub unlock_timestamp: i64,
    pub unlock_human: String,
    pub created_at: i64,

    pub shares_required: u8,
    pub shares_total: u8,

    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub ciphertext_digest: String,

    pub guardian_directory: Vec<GuardianRecord>,
    pub recovery_instructions: String,

    /// Free-text. Used to record where the money actually is — e.g. the
    /// XRPL escrow's Owner and OfferSequence, without which the escrow is
    /// visible on-ledger but unreleasable.
    #[serde(default)]
    pub notes: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GuardianRecord {
    pub share_index: u8,
    pub guardian_name: String,
    pub guardian_contact: String,
    pub location_hint: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultShare {
    pub version: u32,
    pub vault_label: String,
    pub vault_fingerprint: String,
    pub secret_kind: SecretKind,
    pub share_index: u8,
    pub share_data_hex: String,
    pub shares_required: u8,
    pub shares_total: u8,
    pub guardian_name: String,
    pub unlock_human: String,
    pub instructions: String,
}

// ═══════════════════════════════════════════════════════════════════════
// BUILDER
// ═══════════════════════════════════════════════════════════════════════

pub struct VaultBuilder {
    label: String,
    beneficiary: String,
    beneficiary_dob: Option<String>,
    unlock_timestamp: i64,
    shares_required: u8,
    shares_total: u8,
    guardians: Vec<GuardianRecord>,
    notes: String,
}

impl VaultBuilder {
    pub fn new(label: impl Into<String>, beneficiary: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            beneficiary: beneficiary.into(),
            beneficiary_dob: None,
            unlock_timestamp: NEVAEH_UNLOCK_TIMESTAMP,
            shares_required: DEFAULT_SHARES_REQUIRED,
            shares_total: DEFAULT_SHARES_TOTAL,
            guardians: Vec::new(),
            notes: String::new(),
        }
    }

    pub fn dob(mut self, dob: impl Into<String>) -> Self {
        self.beneficiary_dob = Some(dob.into());
        self
    }

    pub fn unlock_at(mut self, ts: i64) -> Self {
        self.unlock_timestamp = ts;
        self
    }

    pub fn threshold(mut self, required: u8, total: u8) -> Self {
        self.shares_required = required;
        self.shares_total = total;
        self
    }

    pub fn notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = notes.into();
        self
    }

    pub fn guardian(
        mut self,
        name: impl Into<String>,
        contact: impl Into<String>,
        location: impl Into<String>,
    ) -> Self {
        let idx = self.guardians.len() as u8 + 1;
        self.guardians.push(GuardianRecord {
            share_index: idx,
            guardian_name: name.into(),
            guardian_contact: contact.into(),
            location_hint: location.into(),
        });
        self
    }

    /// Generate a fresh Dilithium5 keypair and vault it.
    pub fn build_dilithium5(self) -> Result<(TimeLockedVault, Vec<VaultShare>), VaultError> {
        let keypair = GodKeyPair::generate().map_err(|e| VaultError::Crypto(e.to_string()))?;
        let public_identifier = hex::encode(&keypair.public_key);
        let secret = keypair.secret_key_bytes().to_vec();
        self.seal(SecretKind::Dilithium5, public_identifier, secret)
    }

    /// Vault an EXISTING XRPL seed.
    ///
    /// The seed is NOT generated here, deliberately. Generate it in a real
    /// XRPL wallet on hardware you control — the same reasoning that keeps
    /// Dilithium keys out of any networked process applies here, and this
    /// seed controls the actual inheritance.
    ///
    /// `address` is the classic r... address the seed derives to. Record it
    /// correctly: it is how anyone finds the funds on-ledger, and it is the
    /// escrow's Destination.
    pub fn build_xrpl_seed(
        self,
        seed: &str,
        address: &str,
    ) -> Result<(TimeLockedVault, Vec<VaultShare>), VaultError> {
        if seed.trim().is_empty() {
            return Err(VaultError::Crypto("XRPL seed is empty".into()));
        }
        if !address.starts_with('r') || address.len() < 25 || address.len() > 35 {
            return Err(VaultError::Crypto(format!(
                "'{address}' does not look like an XRPL classic address (expected r... , 25-35 chars). \
                 Recording the wrong address here means the funds cannot be found later."
            )));
        }
        self.seal(
            SecretKind::XrplSeed,
            address.to_string(),
            seed.as_bytes().to_vec(),
        )
    }

    /// Vault arbitrary bytes.
    pub fn build_raw(
        self,
        identifier: &str,
        secret: Vec<u8>,
    ) -> Result<(TimeLockedVault, Vec<VaultShare>), VaultError> {
        if secret.is_empty() {
            return Err(VaultError::Crypto("secret is empty".into()));
        }
        self.seal(SecretKind::Raw, identifier.to_string(), secret)
    }

    /// Shared sealing path: encrypt, split, package.
    fn seal(
        self,
        kind: SecretKind,
        public_identifier: String,
        mut secret: Vec<u8>,
    ) -> Result<(TimeLockedVault, Vec<VaultShare>), VaultError> {
        if self.shares_required < 2 {
            return Err(VaultError::InvalidShare(
                "threshold must be at least 2 — a 1-of-N split defeats the purpose".into(),
            ));
        }
        if self.shares_required > self.shares_total {
            return Err(VaultError::InvalidShare(
                "required shares cannot exceed total shares".into(),
            ));
        }

        let secret_digest = TripleHash::hash_hex(&secret);

        let mut master_key = [0u8; MASTER_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut master_key);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&master_key)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        let ciphertext = cipher
            .encrypt(nonce, secret.as_slice())
            .map_err(|e| VaultError::Crypto(format!("encryption failed: {e}")))?;

        secret.zeroize();

        // Binds every share to THIS sealing, not just to the identifier.
        // Hashing the identifier alone gave two vaults for the same
        // address (a redone ceremony, a test run) the same fingerprint, so
        // mixing their shares passed the check and failed later as an
        // opaque "decryption failed". The ciphertext is unique per sealing
        // (fresh master key and nonce), so including it makes the
        // fingerprint unique too. The NUL separator cannot occur in an
        // identifier (hex public key or XRPL address).
        let fingerprint = TripleHash::hash_hex(
            &[
                public_identifier.as_bytes(),
                &[0u8][..],
                ciphertext.as_slice(),
            ]
            .concat(),
        );

        let sharks = Sharks(self.shares_required);
        let raw_shares: Vec<Share> = sharks
            .dealer(&master_key)
            .take(self.shares_total as usize)
            .collect();

        let unlock_human = Utc
            .timestamp_opt(self.unlock_timestamp, 0)
            .single()
            .map(|dt: DateTime<Utc>| dt.format("%d %B %Y").to_string())
            .unwrap_or_else(|| "no time-lock".to_string());

        let shares: Vec<VaultShare> = raw_shares
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let bytes: Vec<u8> = s.into();
                VaultShare {
                    version: VAULT_VERSION,
                    vault_label: self.label.clone(),
                    vault_fingerprint: fingerprint.clone(),
                    secret_kind: kind,
                    share_index: (i + 1) as u8,
                    share_data_hex: hex::encode(&bytes),
                    shares_required: self.shares_required,
                    shares_total: self.shares_total,
                    guardian_name: self
                        .guardians
                        .get(i)
                        .map(|g| g.guardian_name.clone())
                        .unwrap_or_else(|| format!("Unassigned #{}", i + 1)),
                    unlock_human: unlock_human.clone(),
                    instructions: share_instructions(
                        &self.beneficiary,
                        &unlock_human,
                        self.shares_required,
                        self.shares_total,
                    ),
                }
            })
            .collect();

        let vault = TimeLockedVault {
            version: VAULT_VERSION,
            label: self.label.clone(),
            beneficiary: self.beneficiary.clone(),
            beneficiary_dob: self.beneficiary_dob.clone(),
            secret_kind: kind,
            public_identifier,
            fingerprint,
            secret_digest,
            unlock_timestamp: self.unlock_timestamp,
            unlock_human: unlock_human.clone(),
            created_at: Utc::now().timestamp(),
            shares_required: self.shares_required,
            shares_total: self.shares_total,
            ciphertext_hex: hex::encode(&ciphertext),
            nonce_hex: hex::encode(nonce_bytes),
            ciphertext_digest: TripleHash::hash_hex(&ciphertext),
            guardian_directory: self.guardians.clone(),
            recovery_instructions: vault_instructions(
                &self.beneficiary,
                &unlock_human,
                self.shares_required,
                self.shares_total,
                kind,
            ),
            notes: self.notes.clone(),
        };

        master_key.zeroize();

        Ok((vault, shares))
    }
}

// ═══════════════════════════════════════════════════════════════════════
// RECOVERY
// ═══════════════════════════════════════════════════════════════════════

impl TimeLockedVault {
    /// Verify this copy hasn't been corrupted in storage. Run on every
    /// backup annually — a silently corrupted backup discovered in 2039 is
    /// the same as no backup.
    pub fn verify_integrity(&self) -> Result<(), VaultError> {
        let ciphertext =
            hex::decode(&self.ciphertext_hex).map_err(|e| VaultError::Encoding(e.to_string()))?;
        if TripleHash::hash_hex(&ciphertext) != self.ciphertext_digest {
            return Err(VaultError::Encoding(
                "ciphertext digest mismatch — this copy is corrupted, use another backup".into(),
            ));
        }
        Ok(())
    }

    pub fn lock_status(&self) -> LockStatus {
        TimeLock::status(self.unlock_timestamp)
    }

    /// Recover the raw secret. Enforces the time-lock.
    pub fn recover_bytes(&self, shares: &[VaultShare]) -> Result<Vec<u8>, VaultError> {
        TimeLock::enforce(self.unlock_timestamp)?;
        self.recover_bytes_ignoring_timelock(shares)
    }

    /// Recovery WITHOUT the time-lock check.
    ///
    /// Two legitimate uses:
    ///   1. Testing that recovery works — mandatory at creation and
    ///      annually. An untested backup is not a backup.
    ///   2. A genuine emergency needing guardian consensus before the
    ///      unlock date.
    ///
    /// Still requires the full share threshold, so it cannot be invoked by
    /// one person.
    pub fn recover_bytes_ignoring_timelock(
        &self,
        shares: &[VaultShare],
    ) -> Result<Vec<u8>, VaultError> {
        self.verify_integrity()?;

        if shares.len() < self.shares_required as usize {
            return Err(VaultError::InsufficientShares {
                have: shares.len(),
                need: self.shares_required,
            });
        }

        for s in shares {
            if s.vault_fingerprint != self.fingerprint {
                return Err(VaultError::InvalidShare(format!(
                    "share #{} belongs to a different vault ({})",
                    s.share_index, s.vault_label
                )));
            }
        }

        let mut parsed: Vec<Share> = Vec::new();
        for s in shares {
            let bytes = hex::decode(&s.share_data_hex).map_err(|e| {
                VaultError::InvalidShare(format!("share #{}: {}", s.share_index, e))
            })?;
            parsed.push(Share::try_from(bytes.as_slice()).map_err(|e| {
                VaultError::InvalidShare(format!("share #{}: {}", s.share_index, e))
            })?);
        }

        let sharks = Sharks(self.shares_required);
        let mut master_key = sharks
            .recover(parsed.as_slice())
            .map_err(|e| VaultError::ShareRecoveryFailed(e.to_string()))?;

        let cipher = Aes256Gcm::new_from_slice(&master_key)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        let nonce_bytes =
            hex::decode(&self.nonce_hex).map_err(|e| VaultError::Encoding(e.to_string()))?;
        let ciphertext =
            hex::decode(&self.ciphertext_hex).map_err(|e| VaultError::Encoding(e.to_string()))?;

        let secret = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
            .map_err(|_| VaultError::DecryptionFailed)?;

        master_key.zeroize();

        // Confirm we recovered the bytes that went in.
        if TripleHash::hash_hex(&secret) != self.secret_digest {
            return Err(VaultError::IntegrityFailed);
        }

        Ok(secret)
    }

    /// Recover as a GodShield keypair. Only valid for Dilithium5 vaults.
    pub fn recover_godkeypair(&self, shares: &[VaultShare]) -> Result<GodKeyPair, VaultError> {
        self.expect_kind(SecretKind::Dilithium5)?;
        let secret = self.recover_bytes(shares)?;
        self.assemble_keypair(secret)
    }

    pub fn recover_godkeypair_ignoring_timelock(
        &self,
        shares: &[VaultShare],
    ) -> Result<GodKeyPair, VaultError> {
        self.expect_kind(SecretKind::Dilithium5)?;
        let secret = self.recover_bytes_ignoring_timelock(shares)?;
        self.assemble_keypair(secret)
    }

    fn assemble_keypair(&self, mut secret: Vec<u8>) -> Result<GodKeyPair, VaultError> {
        let public_key = hex::decode(&self.public_identifier)
            .map_err(|e| VaultError::Encoding(e.to_string()))?;
        let kp = GodKeyPair::from_bytes(public_key, secret.clone())
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        secret.zeroize();
        Ok(kp)
    }

    /// Recover the XRPL seed string. Only valid for XrplSeed vaults.
    ///
    /// THIS IS THE ONE THAT CONTROLS THE INHERITANCE. Handle it on an
    /// offline machine, import it into a wallet, and do not write it to
    /// disk unencrypted.
    pub fn recover_xrpl_seed(&self, shares: &[VaultShare]) -> Result<String, VaultError> {
        self.expect_kind(SecretKind::XrplSeed)?;
        let secret = self.recover_bytes(shares)?;
        String::from_utf8(secret).map_err(|e| VaultError::Encoding(e.to_string()))
    }

    pub fn recover_xrpl_seed_ignoring_timelock(
        &self,
        shares: &[VaultShare],
    ) -> Result<String, VaultError> {
        self.expect_kind(SecretKind::XrplSeed)?;
        let secret = self.recover_bytes_ignoring_timelock(shares)?;
        String::from_utf8(secret).map_err(|e| VaultError::Encoding(e.to_string()))
    }

    fn expect_kind(&self, expected: SecretKind) -> Result<(), VaultError> {
        if self.secret_kind != expected {
            return Err(VaultError::WrongSecretKind {
                expected,
                found: self.secret_kind,
            });
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, VaultError> {
        serde_json::to_string_pretty(self).map_err(|e| VaultError::Encoding(e.to_string()))
    }

    /// Loads v2, and v1 files written before the generalisation.
    pub fn from_json(s: &str) -> Result<Self, VaultError> {
        if let Ok(v) = serde_json::from_str::<TimeLockedVault>(s) {
            return Ok(v);
        }
        migrate_v1(s)
    }
}

/// v1 had `public_key_hex` instead of `public_identifier`, no `secret_kind`,
/// and no `secret_digest`. All v1 vaults held Dilithium5 keys.
fn migrate_v1(s: &str) -> Result<TimeLockedVault, VaultError> {
    #[derive(Deserialize)]
    struct V1 {
        label: String,
        beneficiary: String,
        beneficiary_dob: Option<String>,
        public_key_hex: String,
        fingerprint: String,
        unlock_timestamp: i64,
        unlock_human: String,
        created_at: i64,
        shares_required: u8,
        shares_total: u8,
        ciphertext_hex: String,
        nonce_hex: String,
        ciphertext_digest: String,
        guardian_directory: Vec<GuardianRecord>,
        recovery_instructions: String,
    }

    let v: V1 = serde_json::from_str(s).map_err(|e| {
        VaultError::Encoding(format!("not a recognised vault file (v1 or v2): {e}"))
    })?;

    Ok(TimeLockedVault {
        version: 1,
        label: v.label,
        beneficiary: v.beneficiary,
        beneficiary_dob: v.beneficiary_dob,
        secret_kind: SecretKind::Dilithium5,
        public_identifier: v.public_key_hex,
        // v1 bound shares to the Dilithium5 fingerprint (hash of pubkey
        // BYTES). Preserved as-is so existing shares still match.
        fingerprint: v.fingerprint,
        // v1 stored no plaintext digest. Empty disables the integrity check
        // for legacy vaults — AES-GCM authentication still applies.
        secret_digest: String::new(),
        unlock_timestamp: v.unlock_timestamp,
        unlock_human: v.unlock_human,
        created_at: v.created_at,
        shares_required: v.shares_required,
        shares_total: v.shares_total,
        ciphertext_hex: v.ciphertext_hex,
        nonce_hex: v.nonce_hex,
        ciphertext_digest: v.ciphertext_digest,
        guardian_directory: v.guardian_directory,
        recovery_instructions: v.recovery_instructions,
        notes: "Migrated from vault format v1.".into(),
    })
}

impl VaultShare {
    pub fn to_json(&self) -> Result<String, VaultError> {
        serde_json::to_string_pretty(self).map_err(|e| VaultError::Encoding(e.to_string()))
    }
    pub fn from_json(s: &str) -> Result<Self, VaultError> {
        serde_json::from_str(s).map_err(|e| VaultError::Encoding(e.to_string()))
    }
}

// ═══════════════════════════════════════════════════════════════════════
// INSTRUCTIONS — read by someone in 2039 with no technical background
// ═══════════════════════════════════════════════════════════════════════

fn share_instructions(beneficiary: &str, unlock: &str, required: u8, total: u8) -> String {
    format!(
        "THIS IS ONE PIECE OF A KEY. KEEP IT SAFE. DO NOT SHARE IT ONLINE.\n\
         \n\
         You are holding 1 of {total} pieces of a key belonging to {beneficiary}.\n\
         On its own this file is worthless and reveals nothing — by design, so\n\
         losing it is not a catastrophe and stealing it achieves nothing.\n\
         \n\
         On or after {unlock}, {beneficiary} is entitled to what this key\n\
         protects. {required} of the {total} pieces must be brought together,\n\
         along with the main vault file.\n\
         \n\
         WHAT TO DO:\n\
         1. Store this offline, ideally in more than one place, or printed on\n\
            paper in a sealed envelope.\n\
         2. Do NOT email it, upload it, let it sync to a phone backup, or paste\n\
            it into any chat or AI assistant.\n\
         3. Keep track of who the other guardians are — the vault file lists them.\n\
         4. If {beneficiary} or their legal guardian asks for this after {unlock},\n\
            give it to them.\n\
         5. If you can no longer safely hold it, tell whoever gave it to you so\n\
            it can be reissued. Do not simply discard it.\n\
         \n\
         If the person who created this is no longer alive, that is exactly the\n\
         situation it was designed for. Find the other guardians, gather\n\
         {required} pieces, and follow the vault file's instructions."
    )
}

fn vault_instructions(
    beneficiary: &str,
    unlock: &str,
    required: u8,
    total: u8,
    kind: SecretKind,
) -> String {
    let kind_note = match kind {
        SecretKind::XrplSeed => {
            "This vault holds an XRP Ledger seed. That seed controls real funds \
             on the XRP Ledger. Treat recovery as a high-security operation: \
             offline machine, import straight into a wallet, never written to \
             disk in plaintext."
        }
        SecretKind::Dilithium5 => {
            "This vault holds a Dilithium5 (post-quantum) key used by GodShield \
             and the NEV369 chain."
        }
        SecretKind::Raw => "This vault holds raw secret material. See `notes` for what it is.",
    };

    format!(
        "VAULT FILE — SAFE TO COPY, USELESS ALONE\n\
         \n\
         {kind_note}\n\
         \n\
         This file cannot be opened without {required} of the {total} shares held\n\
         by the guardians listed in guardian_directory. Copy it freely — store it\n\
         in multiple places. It is designed to be safe even if it becomes public.\n\
         The security lives in the shares, not in this file.\n\
         \n\
         TO RECOVER, ON OR AFTER {unlock}:\n\
         1. Contact the guardians in guardian_directory.\n\
         2. Gather at least {required} share files.\n\
         3. Run:\n\
              godshield vault recover --vault <this file> \\\n\
                --share <s1> --share <s2> --share <s3>\n\
         4. If that software no longer exists, the format is documented in\n\
            docs/nevaeh-vault-ceremony.md: AES-256-GCM over the secret, with the\n\
            AES key split by Shamir Secret Sharing over GF(256). Any competent\n\
            cryptographer can reconstruct it from that description alone.\n\
         \n\
         ANNUAL MAINTENANCE — do not skip:\n\
         - Verify each backup copy still passes its integrity check.\n\
         - Confirm each guardian still holds their share and is contactable.\n\
         - Re-test full recovery with {required} shares.\n\
         An untested backup is not a backup.\n\
         \n\
         For {beneficiary}."
    )
}

// ═══════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn builder(label: &str) -> VaultBuilder {
        VaultBuilder::new(label, "Nevaeh")
            .dob(NEVAEH_DOB)
            .guardian("Guardian A", "a@example.com", "Home safe")
            .guardian("Guardian B", "b@example.com", "Family, second address")
            .guardian("Guardian C", "c@example.com", "Different city")
            .guardian("Guardian D", "d@example.com", "Bank deposit box")
            .guardian("Guardian E", "e@example.com", "Solicitor, with will")
    }

    fn dilithium_vault() -> (TimeLockedVault, Vec<VaultShare>) {
        builder("nevaeh-nev369").build_dilithium5().unwrap()
    }

    fn xrpl_vault() -> (TimeLockedVault, Vec<VaultShare>) {
        builder("nevaeh-xrpl-seed")
            .notes("Destination of the 2039 XRPL inheritance escrow.")
            .build_xrpl_seed(
                "sEdTestSeedValueForUnitTests12345",
                "rNevaehDestination1234567890",
            )
            .unwrap()
    }

    #[test]
    fn unlock_timestamp_is_nevaehs_18th_birthday() {
        let dt = Utc
            .timestamp_opt(NEVAEH_UNLOCK_TIMESTAMP, 0)
            .single()
            .unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2039-07-28");
    }

    // ── Dilithium5 path (unchanged behaviour from v1) ──────────────────

    #[test]
    fn dilithium_three_shares_recover_the_keypair() {
        let (v, s) = dilithium_vault();
        let kp = v.recover_godkeypair_ignoring_timelock(&s[0..3]).unwrap();
        assert_eq!(hex::encode(&kp.public_key), v.public_identifier);
    }

    #[test]
    fn dilithium_recovered_key_can_sign() {
        let (v, s) = dilithium_vault();
        let kp = v.recover_godkeypair_ignoring_timelock(&s[0..3]).unwrap();
        let msg = b"Nevaeh, heir of the chain";
        let sig = godshield_core::GodShield::sign(&kp, msg).unwrap();
        assert!(godshield_core::GodShield::verify(&kp.export_public(), &sig, msg).unwrap());
    }

    // ── XRPL path (the one holding the money) ──────────────────────────

    #[test]
    fn xrpl_seed_roundtrips_exactly() {
        let (v, s) = xrpl_vault();
        let seed = v.recover_xrpl_seed_ignoring_timelock(&s[0..3]).unwrap();
        assert_eq!(seed, "sEdTestSeedValueForUnitTests12345");
    }

    #[test]
    fn xrpl_vault_records_the_destination_address() {
        let (v, _) = xrpl_vault();
        assert_eq!(v.public_identifier, "rNevaehDestination1234567890");
        assert_eq!(v.secret_kind, SecretKind::XrplSeed);
    }

    #[test]
    fn malformed_xrpl_address_is_rejected_at_creation() {
        // Recording the wrong address means the funds cannot be located later.
        assert!(builder("bad")
            .build_xrpl_seed("sSeed", "not-an-xrpl-address")
            .is_err());
        assert!(builder("bad").build_xrpl_seed("sSeed", "").is_err());
    }

    #[test]
    fn empty_xrpl_seed_is_rejected() {
        assert!(builder("bad")
            .build_xrpl_seed("", "rValidLookingAddress12345")
            .is_err());
    }

    #[test]
    fn asking_for_the_wrong_secret_kind_fails_clearly() {
        let (v, s) = xrpl_vault();
        let err = v
            .recover_godkeypair_ignoring_timelock(&s[0..3])
            .unwrap_err();
        assert!(matches!(err, VaultError::WrongSecretKind { .. }));

        let (v2, s2) = dilithium_vault();
        assert!(matches!(
            v2.recover_xrpl_seed_ignoring_timelock(&s2[0..3])
                .unwrap_err(),
            VaultError::WrongSecretKind { .. }
        ));
    }

    // ── Threshold behaviour ────────────────────────────────────────────

    #[test]
    fn any_three_shares_work_not_just_the_first_three() {
        let (v, s) = xrpl_vault();
        let picked = vec![s[1].clone(), s[3].clone(), s[4].clone()];
        assert!(v.recover_bytes_ignoring_timelock(&picked).is_ok());
    }

    #[test]
    fn two_shares_are_insufficient() {
        let (v, s) = xrpl_vault();
        assert!(matches!(
            v.recover_bytes_ignoring_timelock(&s[0..2]),
            Err(VaultError::InsufficientShares { .. })
        ));
    }

    #[test]
    fn shares_from_a_different_vault_are_rejected() {
        let (a, _) = xrpl_vault();
        let (_, b_shares) = xrpl_vault();
        assert!(matches!(
            a.recover_bytes_ignoring_timelock(&b_shares[0..3]),
            Err(VaultError::InvalidShare(_))
        ));
    }

    #[test]
    fn threshold_of_one_is_rejected() {
        assert!(VaultBuilder::new("bad", "x")
            .threshold(1, 5)
            .build_dilithium5()
            .is_err());
    }

    // ── Time-lock ──────────────────────────────────────────────────────

    #[test]
    fn timelock_blocks_recovery_before_unlock() {
        let (v, s) = xrpl_vault();
        assert!(matches!(
            v.recover_bytes(&s[0..3]),
            Err(VaultError::StillLocked { .. })
        ));
    }

    #[test]
    fn timelock_permits_recovery_after_unlock() {
        let (v, s) = VaultBuilder::new("t", "T")
            .unlock_at(1)
            .threshold(2, 3)
            .guardian("A", "", "")
            .guardian("B", "", "")
            .guardian("C", "", "")
            .build_dilithium5()
            .unwrap();
        assert!(v.recover_bytes(&s[0..2]).is_ok());
    }

    // ── Integrity ──────────────────────────────────────────────────────

    #[test]
    fn corrupted_ciphertext_is_detected() {
        let (mut v, _) = xrpl_vault();
        v.ciphertext_hex.replace_range(0..2, "ff");
        assert!(v.verify_integrity().is_err());
    }

    #[test]
    fn tampered_secret_digest_is_caught_on_recovery() {
        let (mut v, s) = xrpl_vault();
        v.secret_digest = TripleHash::hash_hex(b"wrong");
        assert!(matches!(
            v.recover_bytes_ignoring_timelock(&s[0..3]),
            Err(VaultError::IntegrityFailed)
        ));
    }

    // ── Serialization / migration ──────────────────────────────────────

    #[test]
    fn vault_survives_a_json_roundtrip() {
        let (v, s) = xrpl_vault();
        let reloaded = TimeLockedVault::from_json(&v.to_json().unwrap()).unwrap();
        assert_eq!(reloaded.secret_kind, SecretKind::XrplSeed);
        assert_eq!(reloaded.public_identifier, v.public_identifier);
        assert!(reloaded.recover_bytes_ignoring_timelock(&s[0..3]).is_ok());
    }

    #[test]
    fn share_survives_a_json_roundtrip() {
        let (_, s) = xrpl_vault();
        let reloaded = VaultShare::from_json(&s[0].to_json().unwrap()).unwrap();
        assert_eq!(reloaded.share_data_hex, s[0].share_data_hex);
        assert_eq!(reloaded.secret_kind, SecretKind::XrplSeed);
    }

    #[test]
    fn v1_vault_files_still_load() {
        // A v1 file must not become unreadable because the format evolved.
        let v1 = r#"{
            "version": 1,
            "label": "legacy",
            "beneficiary": "Nevaeh",
            "beneficiary_dob": "2021-07-28",
            "public_key_hex": "deadbeef",
            "fingerprint": "abc123",
            "unlock_timestamp": 2195424000,
            "unlock_human": "28 July 2039",
            "created_at": 1700000000,
            "shares_required": 3,
            "shares_total": 5,
            "ciphertext_hex": "00",
            "nonce_hex": "000000000000000000000000",
            "ciphertext_digest": "xyz",
            "guardian_directory": [],
            "recovery_instructions": "legacy"
        }"#;

        let v = TimeLockedVault::from_json(v1).unwrap();
        assert_eq!(v.version, 1);
        assert_eq!(v.secret_kind, SecretKind::Dilithium5);
        assert_eq!(v.public_identifier, "deadbeef");
    }

    #[test]
    fn garbage_input_is_rejected_not_silently_accepted() {
        assert!(TimeLockedVault::from_json("{\"nonsense\": true}").is_err());
        assert!(TimeLockedVault::from_json("not json at all").is_err());
    }

    #[test]
    fn notes_field_carries_escrow_recovery_details() {
        let (v, _) = builder("nevaeh-xrpl-seed")
            .notes("XRPL escrow — Owner: rGrantor..., OfferSequence: 7")
            .build_xrpl_seed("sSeedValue", "rDestination1234567890abc")
            .unwrap();
        assert!(v.notes.contains("OfferSequence"));
    }
}
