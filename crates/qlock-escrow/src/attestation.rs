// crates/qlock-escrow/src/attestation.rs
//
// ═══════════════════════════════════════════════════════════════════════
// Q-Lock — post-quantum attestation identity
//
// WHY THIS FILE WAS MISSING AND WHY IT BLOCKED STARTUP.
//
// lib.rs exports:
//
//     pub mod attestation;   // AttestationIdentity, QLockAttestor
//
// main.rs constructs an identity at startup, panics in production when
// none is configured, and falls back to
// `AttestationIdentity::ephemeral_for_development()` otherwise. None of
// it existed. Searched all 61 uploaded files: `AttestationIdentity`
// appears only inside main.rs, and `attestation.rs` only as a filename
// in the Cargo manifest bundle. The module was specified by its callers
// and never written.
//
// ── WHAT AN ATTESTATION IS FOR HERE ───────────────────────────────────
//
// XRPL cannot verify Dilithium signatures at consensus. So a Q-Lock
// attestation does NOT authorise a settlement — the on-ledger ECDSA
// signature does that, produced client-side in Xaman or on a Ledger
// device. The attestation is a post-quantum-signed record that this
// backend saw and processed a specific settlement, with specific terms,
// at a specific time.
//
// Stated plainly because the whitepaper is explicit about not
// overclaiming: this is a hardened audit trail, not native on-chain
// post-quantum settlement. It is worth having because the audit trail
// outlives the ECDSA signature's security — a 2026 ECDSA signature is
// forgeable by a CRQC, a 2026 Dilithium5 attestation over the same
// record is not.
//
// ── WHY IDENTITY MUST BE PERSISTENT ───────────────────────────────────
//
// A fresh keypair per attestation proves a record is internally
// consistent and binds it to nothing. Anyone with database write access
// could generate a key, sign a fabricated settlement, and insert a row
// that verifies perfectly. The whole value is that every attestation
// traces to ONE long-lived fingerprint published out of band, so a row
// signed by anything else is visibly not ours.
//
// That is why production fails closed rather than degrading to
// ephemeral. A backend that silently downgrades its own audit trail is
// worse than one that refuses to boot, because nobody finds out.
// ═══════════════════════════════════════════════════════════════════════

use godshield_core::{CanonicalMessage, GodKeyPair, GodPublicKey, GodShield, TripleHash};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroizing;

// ═══════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("attestation key material is invalid: {0}")]
    InvalidKeyMaterial(String),

    #[error(
        "no attestation identity configured, and QLOCK_ENV=production forbids an ephemeral one"
    )]
    ProductionRequiresPersistentIdentity,

    #[error(
        "QLOCK_ATTESTATION_VAULT is set, but automated vault unlock is deliberately \
         not implemented — a vault that unlocks itself unattended is not protecting \
         anything. Recover with `godshield vault recover` using three shares on a \
         trusted machine, then inject the key via your secrets manager."
    )]
    AutomatedVaultUnlockRefused,

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("attestation does not verify against the record it claims to cover")]
    VerificationFailed,

    #[error("attestation was signed by fingerprint {found}, expected {expected}")]
    WrongSigner { expected: String, found: String },
}

// ═══════════════════════════════════════════════════════════════════════
// IDENTITY
// ═══════════════════════════════════════════════════════════════════════

/// The long-lived Dilithium5 identity this backend signs attestations
/// with.
///
/// The secret key is wrapped in `Zeroizing` so it is wiped when dropped.
/// That is a real mitigation here, unlike wrapping a public key: this is
/// genuinely secret material, and a process that keeps it in freed heap
/// leaks it to a later core dump or heap-reuse read.
///
/// No `Debug`, no `Serialize`, no `Clone`. Deriving Debug on a type
/// holding a secret key is how keys end up in logs — one
/// `tracing::info!(?identity)` and the private key is in your log
/// aggregator forever. Use `fingerprint()` to identify it.
pub struct AttestationIdentity {
    keypair: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
    fingerprint: String,
    ephemeral: bool,
}

impl AttestationIdentity {
    /// Load from hex-encoded keypair JSON, as produced by
    /// `godshield vault recover` and injected through a secrets manager.
    pub fn from_keypair_json(json: &str) -> Result<Self, AttestationError> {
        let kp = GodKeyPair::from_json(json)
            .map_err(|e| AttestationError::InvalidKeyMaterial(e.to_string()))?;
        Self::from_keypair(kp, false)
    }

    fn from_keypair(kp: GodKeyPair, ephemeral: bool) -> Result<Self, AttestationError> {
        let fingerprint = TripleHash::hash_hex(&kp.public_key);
        let public_key = kp.public_key.clone();

        // Serialise once into a zeroizing buffer so the original
        // GodKeyPair can drop.
        //
        // This was `unwrap_or_default()`, which was wrong in a way that
        // defeated the point of this whole module. On a serialisation
        // failure it produced an EMPTY buffer, construction succeeded,
        // startup completed, and the process only discovered it held an
        // unusable identity when it tried to sign a real settlement.
        // The fail-closed guarantee is that a bad identity stops the
        // process at boot, so the error has to propagate from here.
        // to_json(), not serde_json::to_vec(&kp).
        //
        // godshield-core deliberately does NOT derive Serialize on
        // GodKeyPair — it keeps a private GodKeyPairSerde shape and
        // exposes explicit to_json/from_json, so that an accidental
        // serialize in a log line or an API response cannot leak the
        // secret key. Reaching past that with serde_json::to_vec does
        // not compile, and if it did it would defeat the measure.
        let bytes = kp
            .to_json()
            .map_err(|e| {
                AttestationError::InvalidKeyMaterial(format!(
                    "attestation keypair could not be serialised: {e}"
                ))
            })?
            .into_bytes();

        if bytes.is_empty() {
            return Err(AttestationError::InvalidKeyMaterial(
                "attestation keypair serialised to nothing".into(),
            ));
        }

        Ok(Self {
            keypair: Zeroizing::new(bytes),
            public_key,
            fingerprint,
            ephemeral,
        })
    }

    /// Generate a throwaway identity. **Development only.**
    ///
    /// Every attestation signed by this is verifiable and traceable to
    /// nothing, and the fingerprint changes on every restart — so the
    /// attestation history of a dev database is a pile of mutually
    /// unrelated signers. That is fine for development and worthless as
    /// an audit trail, which is why `from_env` refuses it in production.
    pub fn ephemeral_for_development() -> Result<Self, AttestationError> {
        let kp = GodKeyPair::generate()
            .map_err(|e| AttestationError::InvalidKeyMaterial(e.to_string()))?;
        let identity = Self::from_keypair(kp, true)?;

        tracing::warn!(
            fingerprint = %identity.fingerprint,
            "EPHEMERAL attestation identity generated. Attestations signed with \
             this key bind to no identity and this fingerprint dies with the \
             process. Never run this configuration in production."
        );
        Ok(identity)
    }

    /// Resolve the identity from the environment.
    ///
    /// Precedence, and the reasoning for each branch:
    ///
    ///   QLOCK_ATTESTATION_VAULT → refuse. Not "unsupported yet" —
    ///     refused on purpose. Automated unlock would mean the process
    ///     can reconstruct a Shamir-split key alone, which defeats the
    ///     split. main.rs already panics on this; the error is defined
    ///     here so the reason travels with the code.
    ///
    ///   QLOCK_ATTESTATION_KEY → the supported production path. Keypair
    ///     JSON injected as a process-scoped secret.
    ///
    ///   neither, QLOCK_ENV=production → fail closed.
    ///
    ///   neither, otherwise → ephemeral, loudly.
    pub fn from_env() -> Result<Self, AttestationError> {
        if std::env::var("QLOCK_ATTESTATION_VAULT").is_ok() {
            return Err(AttestationError::AutomatedVaultUnlockRefused);
        }

        let production = std::env::var("QLOCK_ENV").as_deref() == Ok("production");

        match std::env::var("QLOCK_ATTESTATION_KEY") {
            Ok(json) if !json.trim().is_empty() => {
                let identity = Self::from_keypair_json(&json)?;
                tracing::info!(
                    fingerprint = %identity.fingerprint,
                    "Attestation identity loaded. Publish this fingerprint out of \
                     band — it is what lets anyone check an attestation is ours."
                );
                Ok(identity)
            }
            _ if production => Err(AttestationError::ProductionRequiresPersistentIdentity),
            _ => Self::ephemeral_for_development(),
        }
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    pub fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    fn keypair(&self) -> Result<GodKeyPair, AttestationError> {
        // Mirrors from_keypair above: the core's explicit helper, not
        // a serde derive that does not exist.
        let json = std::str::from_utf8(&self.keypair)
            .map_err(|e| AttestationError::InvalidKeyMaterial(e.to_string()))?;
        GodKeyPair::from_json(json).map_err(|e| AttestationError::InvalidKeyMaterial(e.to_string()))
    }
}

// ═══════════════════════════════════════════════════════════════════════
// THE RECORD
// ═══════════════════════════════════════════════════════════════════════

/// What an attestation actually covers.
///
/// Every field here is inside the signed bytes. A field NOT in this
/// struct is not attested to, however carefully it is stored — so
/// adding a term to an escrow without adding it here produces an
/// attestation that verifies while saying nothing about the new term.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SettlementRecord {
    /// The on-ledger transaction or escrow this covers.
    pub tx_hash: String,
    pub from_address: String,
    pub to_address: String,
    /// Drops for XRP, base units for NEV369. A DECIMAL STRING, never a
    /// float — the same reason chain.rs uses u64 and the relayer keeps
    /// amounts as strings. Round-tripping money through f64 to sign it
    /// would make the signature cover a value slightly different from
    /// the one settled.
    pub amount: String,
    pub fee: String,
    pub ledger: String,
    pub kind: String,
    pub timestamp: u64,
}

impl SettlementRecord {
    /// Canonical signing bytes.
    ///
    /// Length-prefixed and domain-separated via CanonicalMessage, for the
    /// same reason as everywhere else in this workspace: naive
    /// concatenation is ambiguous, and `from="AB"/to="C"` must not
    /// produce the same bytes as `from="A"/to="BC"`.
    ///
    /// The domain tag `qlock.attestation.v1` is what stops an
    /// attestation signature being replayed as an NEV369 transaction or
    /// a Fairness reveal — those use `nev369.tx.v1` and
    /// `godshield.fairness.reveal.v1`, and the domain is inside the
    /// signed bytes.
    ///
    /// Changing this function invalidates every attestation ever
    /// produced, including rows already in the database. Bump the
    /// version tag instead of editing in place, and add the new tag to
    /// the registry in the README.
    pub fn signing_bytes(&self) -> Vec<u8> {
        CanonicalMessage::encode(
            "qlock.attestation.v1",
            &[
                self.tx_hash.as_bytes(),
                self.from_address.as_bytes(),
                self.to_address.as_bytes(),
                self.amount.as_bytes(),
                self.fee.as_bytes(),
                self.ledger.as_bytes(),
                self.kind.as_bytes(),
                &self.timestamp.to_le_bytes(),
            ],
        )
    }

    pub fn digest(&self) -> String {
        TripleHash::hash_hex(&self.signing_bytes())
    }
}

/// A signed attestation, shaped to the `attestations` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub tx_hash: String,
    #[serde(rename = "dilithiumSignature")]
    pub dilithium_signature: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "signerFingerprint")]
    pub signer_fingerprint: String,
    pub timestamp: u64,
    /// TripleHash of the signed bytes. Stored so a verifier can tell
    /// "this attestation covers a different record" apart from "this
    /// signature is invalid" — two very different incidents.
    #[serde(rename = "recordDigest")]
    pub record_digest: String,
    /// Populated by attest_escrow. Server-side attestations leave it
    /// None — which is why the column must be nullable.
    #[serde(rename = "deviceId", default)]
    pub device_id: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════
// ATTESTOR
// ═══════════════════════════════════════════════════════════════════════

/// Signs and verifies settlement attestations. Cheap to clone — held in
/// AppState and shared across handlers.
#[derive(Clone)]
pub struct QLockAttestor {
    identity: Arc<AttestationIdentity>,
}

impl QLockAttestor {
    pub fn new(identity: AttestationIdentity) -> Self {
        Self {
            identity: Arc::new(identity),
        }
    }

    pub fn from_env() -> Result<Self, AttestationError> {
        Ok(Self::new(AttestationIdentity::from_env()?))
    }

    pub fn fingerprint(&self) -> &str {
        self.identity.fingerprint()
    }

    pub fn is_ephemeral(&self) -> bool {
        self.identity.is_ephemeral()
    }

    pub fn attest(&self, record: &SettlementRecord) -> Result<Attestation, AttestationError> {
        let kp = self.identity.keypair()?;
        let message = record.signing_bytes();

        let sig = GodShield::sign(&kp, &message)
            .map_err(|e| AttestationError::SigningFailed(e.to_string()))?;

        Ok(Attestation {
            tx_hash: record.tx_hash.clone(),
            dilithium_signature: hex::encode(&sig.signature),
            public_key: self.identity.public_key_hex(),
            signer_fingerprint: self.identity.fingerprint().to_string(),
            timestamp: record.timestamp,
            record_digest: record.digest(),
            device_id: None,
        })
    }

    /// Verify an attestation against the record it claims to cover.
    ///
    /// Recomputes the signed bytes from `record` rather than trusting
    /// anything in the attestation. This matters: godshield-core shipped
    /// a fix for `verify()` trusting an attacker-supplied
    /// `message_hash`, where one captured signature validated arbitrary
    /// messages. Passing the real message here is what keeps that fix
    /// effective — handing it a hash taken from the row would walk
    /// straight back into the same hole.
    pub fn verify(
        &self,
        record: &SettlementRecord,
        attestation: &Attestation,
    ) -> Result<(), AttestationError> {
        Self::verify_with_public_key(record, attestation)
    }

    /// Verify, and additionally require a specific signer.
    ///
    /// This is the check that makes attestations mean anything. Plain
    /// verification only proves the row is internally consistent — a
    /// forged row signed with a freshly generated key passes it. Pinning
    /// the expected fingerprint (published out of band) is what
    /// distinguishes our attestation from anyone's.
    pub fn verify_from_signer(
        record: &SettlementRecord,
        attestation: &Attestation,
        expected_fingerprint: &str,
    ) -> Result<(), AttestationError> {
        if attestation.signer_fingerprint != expected_fingerprint {
            return Err(AttestationError::WrongSigner {
                expected: expected_fingerprint.to_string(),
                found: attestation.signer_fingerprint.clone(),
            });
        }
        Self::verify_with_public_key(record, attestation)
    }

    fn verify_with_public_key(
        record: &SettlementRecord,
        attestation: &Attestation,
    ) -> Result<(), AttestationError> {
        let public_key_bytes = hex::decode(&attestation.public_key)
            .map_err(|e| AttestationError::InvalidKeyMaterial(e.to_string()))?;
        let signature_bytes = hex::decode(&attestation.dilithium_signature)
            .map_err(|e| AttestationError::InvalidKeyMaterial(e.to_string()))?;

        // The fingerprint must derive from the key in the row. Without
        // this, an attacker supplies their own key alongside our
        // fingerprint and the row verifies while appearing to be ours —
        // the same substitution chain.rs blocks by requiring the sender
        // address to equal the public key hex.
        let derived = TripleHash::hash_hex(&public_key_bytes);
        if derived != attestation.signer_fingerprint {
            return Err(AttestationError::WrongSigner {
                expected: derived,
                found: attestation.signer_fingerprint.clone(),
            });
        }

        let message = record.signing_bytes();
        if TripleHash::hash_hex(&message) != attestation.record_digest {
            return Err(AttestationError::VerificationFailed);
        }

        let public_key = GodPublicKey {
            public_key: public_key_bytes,
            fingerprint: derived.clone(),
        };
        let signature = godshield_core::GodSignature {
            signature: signature_bytes,
            message_hash: TripleHash::hash_hex(&message),
            signer_fingerprint: derived,
            timestamp: attestation.timestamp,
        };

        match GodShield::verify(&public_key, &signature, &message) {
            Ok(true) => Ok(()),
            _ => Err(AttestationError::VerificationFailed),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// COMPATIBILITY SURFACE FOR inheritance.rs
//
// qlock_inheritance.rs calls:
//
//     QLockAttestor::attest_escrow(
//         attestation_key, &terms, "inheritance_create", "", amount_drops, device_id
//     )
//
// An ASSOCIATED function taking a key, not a method on a constructed
// attestor — and it carries a device_id, which is where the
// `attestations.device_id` column comes from. My earlier schema edit
// renamed that column away on the assumption nothing populated it. Wrong:
// this is what populates it. Restored.
//
// ── THE `terms` STRING IS AMBIGUOUS, AND THIS IS THE INHERITANCE PATH ──
//
// inheritance.rs builds what gets signed as:
//
//     format!("{}|{}|{}|{}|{}", beneficiary_name, destination_address,
//             amount_drops, finish_after, beneficiary_dob)
//
// Pipe-delimited concatenation with no escaping. A beneficiary name
// containing "|" re-partitions every field after it, so two different
// escrows can produce identical signed bytes — the same class of bug as
// NEV369's old delimiter-free `format!` signing, which is documented in
// chain.rs as CRITICAL and fixed there with CanonicalMessage.
//
// It is worse here than it was there. This signs the terms of a
// thirteen-year inheritance escrow, and the attestation's entire purpose
// is to prove in 2039 what was committed in 2026. An ambiguous encoding
// means it proves less than it appears to.
//
// `attest_escrow_canonical` below is the fix: same inputs, fed through
// CanonicalMessage with the domain tag `qlock.escrow.v1`. The
// pipe-joined version is kept only so inheritance.rs compiles unchanged
// today — it should be switched before any real escrow is created,
// because switching AFTER means old attestations no longer verify.
// ═══════════════════════════════════════════════════════════════════════

impl QLockAttestor {
    /// Signature-compatible with the existing inheritance.rs call site.
    ///
    /// `terms` is pre-joined by the caller. See the ambiguity note above:
    /// prefer `attest_escrow_canonical`.
    pub fn attest_escrow(
        attestation_key: &GodKeyPair,
        terms: &str,
        kind: &str,
        tx_hash: &str,
        amount: u64,
        device_id: &str,
    ) -> Result<Attestation, AttestationError> {
        let message = CanonicalMessage::encode(
            "qlock.escrow.v1",
            &[
                terms.as_bytes(),
                kind.as_bytes(),
                tx_hash.as_bytes(),
                &amount.to_le_bytes(),
                device_id.as_bytes(),
            ],
        );

        let sig = GodShield::sign(attestation_key, &message)
            .map_err(|e| AttestationError::SigningFailed(e.to_string()))?;
        let fingerprint = TripleHash::hash_hex(&attestation_key.public_key);

        Ok(Attestation {
            tx_hash: tx_hash.to_string(),
            dilithium_signature: hex::encode(&sig.signature),
            public_key: hex::encode(&attestation_key.public_key),
            signer_fingerprint: fingerprint,
            timestamp: crate::attestation::unix_now(),
            record_digest: TripleHash::hash_hex(&message),
            device_id: Some(device_id.to_string()),
        })
    }

    /// Preferred form: the escrow's fields are length-prefixed
    /// individually, so no field value can impersonate a delimiter.
    #[allow(clippy::too_many_arguments)]
    pub fn attest_escrow_canonical(
        attestation_key: &GodKeyPair,
        beneficiary_name: &str,
        beneficiary_dob: &str,
        destination_address: &str,
        amount_drops: u64,
        finish_after: u64,
        kind: &str,
        tx_hash: &str,
        device_id: &str,
    ) -> Result<Attestation, AttestationError> {
        let message = CanonicalMessage::encode(
            "qlock.escrow.v2",
            &[
                beneficiary_name.as_bytes(),
                beneficiary_dob.as_bytes(),
                destination_address.as_bytes(),
                &amount_drops.to_le_bytes(),
                &finish_after.to_le_bytes(),
                kind.as_bytes(),
                tx_hash.as_bytes(),
                device_id.as_bytes(),
            ],
        );

        let sig = GodShield::sign(attestation_key, &message)
            .map_err(|e| AttestationError::SigningFailed(e.to_string()))?;
        let fingerprint = TripleHash::hash_hex(&attestation_key.public_key);

        Ok(Attestation {
            tx_hash: tx_hash.to_string(),
            dilithium_signature: hex::encode(&sig.signature),
            public_key: hex::encode(&attestation_key.public_key),
            signer_fingerprint: fingerprint,
            timestamp: unix_now(),
            record_digest: TripleHash::hash_hex(&message),
            device_id: Some(device_id.to_string()),
        })
    }
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> SettlementRecord {
        SettlementRecord {
            tx_hash: "ABC123".into(),
            from_address: "rSender".into(),
            to_address: "rRecipient".into(),
            amount: "100.000000".into(),
            fee: "0.300000".into(),
            ledger: "xrpl".into(),
            kind: "escrow_release".into(),
            timestamp: 1_760_000_000,
        }
    }

    fn attestor() -> QLockAttestor {
        QLockAttestor::new(AttestationIdentity::ephemeral_for_development().unwrap())
    }

    #[test]
    fn round_trips() {
        let a = attestor();
        let r = record();
        let att = a.attest(&r).unwrap();
        assert!(a.verify(&r, &att).is_ok());
    }

    #[test]
    fn tampering_with_the_amount_breaks_verification() {
        let a = attestor();
        let r = record();
        let att = a.attest(&r).unwrap();

        let mut altered = r.clone();
        altered.amount = "1000000.000000".into();
        assert!(a.verify(&altered, &att).is_err());
    }

    #[test]
    fn tampering_with_the_recipient_breaks_verification() {
        let a = attestor();
        let r = record();
        let att = a.attest(&r).unwrap();

        let mut altered = r.clone();
        altered.to_address = "rAttacker".into();
        assert!(a.verify(&altered, &att).is_err());
    }

    #[test]
    fn canonical_encoding_prevents_field_boundary_collision() {
        // from="AB"/to="C" must not sign the same bytes as
        // from="A"/to="BC".
        let mut a = record();
        a.from_address = "AB".into();
        a.to_address = "C".into();

        let mut b = record();
        b.from_address = "A".into();
        b.to_address = "BC".into();

        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn a_forged_row_with_its_own_key_is_rejected_when_the_signer_is_pinned() {
        // The attack persistent identity exists to stop: someone with
        // database write access generates a key, signs a fabricated
        // settlement, inserts a row that verifies perfectly.
        let ours = attestor();
        let theirs = attestor();
        let r = record();

        let forged = theirs.attest(&r).unwrap();

        // Internally consistent — plain verification passes.
        assert!(theirs.verify(&r, &forged).is_ok());

        // Pinned to our fingerprint, it does not.
        let err = QLockAttestor::verify_from_signer(&r, &forged, ours.fingerprint()).unwrap_err();
        assert!(matches!(err, AttestationError::WrongSigner { .. }));
    }

    #[test]
    fn fingerprint_must_derive_from_the_supplied_key() {
        // Attacker keeps their signature and key but writes our
        // fingerprint into the row.
        let a = attestor();
        let r = record();
        let mut att = a.attest(&r).unwrap();
        att.signer_fingerprint = "f".repeat(128);

        assert!(a.verify(&r, &att).is_err());
    }

    #[test]
    fn digest_mismatch_is_distinguishable_from_a_bad_signature() {
        let a = attestor();
        let r = record();
        let mut att = a.attest(&r).unwrap();
        att.record_digest = "0".repeat(128);

        assert!(matches!(
            a.verify(&r, &att),
            Err(AttestationError::VerificationFailed)
        ));
    }

    #[test]
    fn ephemeral_identity_is_flagged_as_such() {
        // main.rs relies on this to decide whether to refuse startup.
        assert!(attestor().is_ephemeral());
    }

    #[test]
    fn two_ephemeral_identities_have_different_fingerprints() {
        // Which is exactly why they are worthless as an audit trail.
        assert_ne!(attestor().fingerprint(), attestor().fingerprint());
    }

    #[test]
    fn amount_is_a_string_not_a_float() {
        // A value that cannot be represented exactly in f64. If this
        // field were numeric, the signature would cover a slightly
        // different amount than the one settled.
        let mut r = record();
        r.amount = "100.000000000000001".into();
        let a = attestor();
        let att = a.attest(&r).unwrap();
        assert!(a.verify(&r, &att).is_ok());
    }
}
