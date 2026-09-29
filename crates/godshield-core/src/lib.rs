// GodShield Core — Quantum- Proof Cryptographic Engine
//
// ════════════════════════ ════════════════════════ ═══════════════════════
// SECURITY FIX APPLIED — read this before diffing against the old version
// ════════════════════════ ════════════════════════ ═══════════════════════
//
// CRITICAL (fixed): GodShield::verify() previously discarded the message
// recovered from open(), and relied solely on comparing the caller- supplied
// signature.message_hash field against the hash of the message. Since that
// field is attacker- controlled, ANY valid signature from a key could be
// paired with ANY message and would verify. One captured transaction was
// enough to forge acceptance of arbitrary messages from that signer.
//
// The fix binds the recovered message to the actual message being verified.
// See verify() below.
//
// ADDED: CanonicalMessage — length-prefixed, domain- separated encoding.
// Fixes the concatenation- ambiguity class of bug present in both
// NEV369's Transaction::get_message_byt es() and godshield- fairness's
// reveal payload, where "AB"+"C" and "A"+"BC" produce identical bytes.
//
// ADDED: secret_key_bytes() accessor — required by godshield-wasm and the
// CLI vault, both of which referenced it before it existed.
//
// CHANGED: GodKeyPair no longer derives Serialize/Deserialize. The old
// derive silently included the private secret_key field, meaning any
// accidental serialization leaked it. Explicit to_json/from_json remain
// for the cases where that's actually intended.
// ════════════════════════ ════════════════════════ ═══════════════════════

use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, SignedMessage as _};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::error::Error;
use std::fmt;
use subtle::ConstantTimeEq;

// ════════════════════════ ════════════════════════ ═══════════════════════
// ERROR HANDLING
// ════════════════════════ ════════════════════════ ═══════════════════════

#[derive(Debug)]
pub enum GodShieldError {
    KeyGenerationFailed,
    SignatureFailed,
    VerificationFailed,
    InvalidInput(String),
    EncodingError(String),
}

impl fmt::Display for GodShieldError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GodShieldError::KeyGenerationFailed => write!(f, "Key generation failed"),

            GodShieldError::SignatureFailed => write!(f, "Signature generation failed"),
            GodShieldError::VerificationFailed => write!(f, "Signature verification failed"),

            GodShieldError::InvalidInput(msg) => write!(f, "Invalid input: {msg}"),

            GodShieldError::EncodingError(msg) => write!(f, "Encoding error: {msg}"),
        }
    }
}

impl Error for GodShieldError {}

// ════════════════════════ ════════════════════════ ═══════════════════════
// TRIPLE-LAYER HASH DEFENSE
// ════════════════════════ ════════════════════════ ═══════════════════════

pub struct TripleHash;

impl TripleHash {
    /// SHA3-512 → BLAKE3 → SHA3-512 cascade.
    ///
    /// Defense in depth, not a claim of superadditive security: the point
    /// is that a break in any single hash family isn't immediately fatal.
    pub fn hash(data: &[u8]) -> [u8; 64] {
        let mut hasher1 = Sha3_512::new();

        hasher1.update(data);
        let layer1 = hasher1.finalize();

        let layer2 = blake3::hash(&layer1);

        let mut hasher3 = Sha3_512::new();

        hasher3.update(layer2.as_bytes());
        let layer3 = hasher3.finalize();

        let mut result = [0u8; 64];

        result.copy_from_slice(&layer3);
        result
    }

    pub fn hash_hex(data: &[u8]) -> String {
        hex::encode(Self::hash(data))
    }
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// CANONICAL MESSAGE ENCODING
// ════════════════════════ ════════════════════════ ═══════════════════════
/// Length-prefixed, domain- separated message encoding.
///
/// WHY THIS EXISTS: naive concatenation is ambiguous. Given fields joined
/// with no delimiter, sender="AB" recipient="C" produces the same bytes as
/// sender="A" recipient="BC" — so a signature valid for one transaction is
/// valid for a different one. Both NEV369 and godshield-fairness had this
/// pattern. Length prefixes make the encoding injective: distinct field
/// sets can never collide.
///
/// The domain string additionally prevents cross- protocol replay — a
/// signature over an NEV369 transaction can't be replayed as a Fairness
/// round reveal, because the domain differs and is inside the signed bytes.
pub struct CanonicalMessage;

impl CanonicalMessage {
    pub fn encode(domain: &str, fields: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();

        out.extend_from_slice(&(domain.len() as u32).to_le_bytes());
        out.extend_from_slice(domain.as_bytes());

        out.extend_from_slice(&(fields.len() as u32).to_le_bytes());
        for field in fields {
            out.extend_from_slice(&(field.len() as u64).to_le_bytes());

            out.extend_from_slice(field);
        }
        out
    }

    /// Convenience for string fields, which is the common case.
    pub fn encode_strs(domain: &str, fields: &[&str]) -> Vec<u8> {
        let byte_fields: Vec<&[u8]> = fields.iter().map(|s| s.as_bytes()).collect();
        Self::encode(domain, &byte_fields)
    }
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// DILITHIUM5 KEY MANAGEMENT
// ════════════════════════ ════════════════════════ ═══════════════════════
/// Deliberately does NOT derive Serialize/Deserialize — the previous derive
/// included the private secret_key field, so any accidental serialization
/// (logging, an API response, a debug dump) leaked it. Use to_json() only
/// where writing the secret out is genuinely intended, and prefer the
/// encrypted vault format in godshield-cli for anything holding value.
#[derive(Clone)]
pub struct GodKeyPair {
    pub public_key: Vec<u8>,
    secret_key: Vec<u8>,
    pub fingerprint: String,
}

/// Hand-written so the secret can never reach a log line. `{:?}` on a
/// keypair shows the fingerprint and nothing else; `unwrap_err()` and
/// `assert!` failure messages stay safe to print.
impl fmt::Debug for GodKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GodKeyPair")
            .field("fingerprint", &self.fingerprint)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

/// Internal-only shape used by the explicit JSON helpers.
#[derive(Serialize, Deserialize)]
struct GodKeyPairSerde {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    fingerprint: String,
}

impl GodKeyPair {
    pub fn generate() -> Result<Self, GodShieldError> {
        // Fully-qualified: the trait is imported as `_` purely to bring its
        // methods into scope, so every call site names the concrete
        // dilithium5 type. The previous glob import plus aliased traits made
        // `PqSecretKey::from_bytes(..) ` a bare trait call with no concrete
        // type to resolve against.
        let (pk, sk) = dilithium5::keypair();
        let public_key = pk.as_bytes().to_vec();
        let secret_key = sk.as_bytes().to_vec();
        let fingerprint = TripleHash::hash_hex(&public_key);

        Ok(GodKeyPair {
            public_key,
            secret_key,
            fingerprint,
        })
    }

    /// Dilithium5 public key length in bytes (2592), as the linked
    /// implementation defines it.
    pub fn public_key_len() -> usize {
        dilithium5::public_key_bytes()
    }

    /// Dilithium5 secret key length in bytes, as the linked implementation
    /// defines it.
    ///
    /// Deliberately read from the library, never hard-coded. The secret key
    /// encoding differs between Dilithium round 3 (4864) and later
    /// revisions; a hard-coded 4864 here made every key the library
    /// actually generates fail `from_bytes`, which broke `from_json`,
    /// vault recovery, and attestation key loading all at once.
    pub fn secret_key_len() -> usize {
        dilithium5::secret_key_bytes()
    }

    pub fn from_bytes(public_key: Vec<u8>, secret_key: Vec<u8>) -> Result<Self, GodShieldError> {
        // Validate sizes up front rather than failing opaquely at sign time.
        if public_key.len() != Self::public_key_len() {
            return Err(GodShieldError::InvalidInput(format!(
                "Dilithium5 public key must be {} bytes, got {}",
                Self::public_key_len(),
                public_key.len()
            )));
        }
        if secret_key.len() != Self::secret_key_len() {
            return Err(GodShieldError::InvalidInput(format!(
                "Dilithium5 secret key must be {} bytes, got {}",
                Self::secret_key_len(),
                secret_key.len()
            )));
        }
        let fingerprint = TripleHash::hash_hex(&public_key);
        Ok(GodKeyPair {
            public_key,
            secret_key,
            fingerprint,
        })
    }
    /// Raw secret key bytes. Needed by godshield- wasm (browser-side signing)
    /// and godshield-cli's encrypted vault. Kept as an explicit method rather
    /// than a public field so every call site is greppable in an audit.
    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }

    pub fn export_public(&self) -> GodPublicKey {
        GodPublicKey {
            public_key: self.public_key.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }

    /// WARNING: output contains the private key in plaintext.
    pub fn to_json(&self) -> Result<String, GodShieldError> {
        let s = GodKeyPairSerde {
            public_key: self.public_key.clone(),
            secret_key: self.secret_key.clone(),
            fingerprint: self.fingerprint.clone(),
        };

        serde_json::to_string_pretty(&s).map_err(|e| GodShieldError::EncodingError(e.to_string()))
    }

    pub fn from_json(json: &str) -> Result<Self, GodShieldError> {
        let s: GodKeyPairSerde =
            serde_json::from_str(json).map_err(|e| GodShieldError::EncodingError(e.to_string()))?;

        Self::from_bytes(s.public_key, s.secret_key)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct GodPublicKey {
    pub public_key: Vec<u8>,
    pub fingerprint: String,
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// SIGNATURE ENGINE
// ════════════════════════ ════════════════════════ ═══════════════════════

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct GodSignature {
    pub signature: Vec<u8>,
    pub message_hash: String,
    pub signer_fingerprint: String,
    pub timestamp: u64,
}

pub struct GodShield;

impl GodShield {
    /// Sign a message: triple-hash it, then Dilithium5-sign the digest.
    pub fn sign(keypair: &GodKeyPair, message: &[u8]) -> Result<GodSignature, GodShieldError> {
        let message_hash_bytes = TripleHash::hash(message);
        let message_hash = hex::encode(message_hash_bytes);
        let sk = dilithium5::SecretKey::from_bytes(&keypair.secret_key)
            .map_err(|_| GodShieldError::SignatureFailed)?;

        let signed_msg = dilithium5::sign(&message_hash_bytes, &sk);

        Ok(GodSignature {
            signature: signed_msg.as_bytes().to_vec(),
            message_hash,

            signer_fingerprint: keypair.fingerprint.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| GodShieldError::SignatureFailed)?
                .as_secs(),
        })
    }

    /// Verify a signature against a message.
    ///
    /// ════════════════════════ ════════════════════════ ═══════════════════
    /// SECURITY-CRITICAL. Read before modifying.
    ///
    /// The previous implementation did:
    ///        match open(&signed_msg, &pk) { Ok(_) => Ok(true), ... }
    ///
    /// discarding the recovered message and trusting the caller-supplied
    /// signature.message_hash field as the only link between signature and
    /// message. Because that field is attacker- controlled, any valid
    /// signature from a key verified against any message from that key —
    /// a complete forgery bypass requiring only one captured signature.
    ///
    /// The fix: compare what open() actually recovered against the digest
    /// of the message we were asked to verify. That comparison is the only
    /// thing that cryptographically binds signature to message.
    /// ════════════════════════ ════════════════════════ ═══════════════════
    pub fn verify(
        public_key: &GodPublicKey,
        signature: &GodSignature,
        original_message: &[u8],
    ) -> Result<bool, GodShieldError> {
        let expected_hash_bytes = TripleHash::hash(original_message);

        // Cheap consistency check on the advisory field. Constant-time to
        // avoid leaking digest bytes via comparison timing. This is NOT
        // the security- bearing check — the open() comparison below is.
        let claimed = match hex::decode(&signature.message_hash) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(false),
        };
        if claimed.len() != expected_hash_bytes.len() {
            return Ok(false);
        }
        if claimed.ct_eq(&expected_hash_bytes).unwrap_u8() != 1 {
            return Ok(false);
        }

        let pk = dilithium5::PublicKey::from_bytes(&public_key.public_key)
            .map_err(|_| GodShieldError::VerificationFailed)?;

        let signed_msg = dilithium5::SignedMessage::from_bytes(&signature.signature)
            .map_err(|_| GodShieldError::VerificationFailed)?;

        match dilithium5::open(&signed_msg, &pk) {
            // THE security- bearing check: the signature must actually be
            // over this message's digest, not merely valid over something.
            Ok(recovered) => {
                if recovered.len() != expected_hash_bytes.len() {
                    return Ok(false);
                }
                Ok(recovered.ct_eq(&expected_hash_bytes).unwrap_u8() == 1)
            }
            Err(_) => Ok(false),
        }
    }

    pub fn version() -> &'static str {
        "GodShield v1.1.0-QUANTUM-FORTRESS"
    }

    pub fn certify(public_key: &GodPublicKey) -> String {
        let fp = if public_key.fingerprint.len() >= 36 {
            &public_key.fingerprint[..36]
        } else {
            &public_key.fingerprint[..]
        };
        format!(
            "GODSHIELD CERTIFICATION\n\
                 Status:Dilithium5 / ML-DSA Level5\n\
                 Standard:NIST FIPS 204\n\
                 Fingerprint:{fp}...\n\
                 \n\
                 NOTE: This attests to the signature scheme in use. It is NOT\n\
                 an independent security audit of any integration."
        )
    }
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// TESTS
// ════════════════════════ ════════════════════════ ═══════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triple_hash_is_64_bytes() {
        assert_eq!(TripleHash::hash(b"quantum proof test").len(), 64);
    }

    #[test]
    fn key_generation_produces_correct_sizes() {
        let kp = GodKeyPair::generate().unwrap();
        assert_eq!(kp.public_key.len(), 2592, "Dilithium5 public key size");
        assert_eq!(kp.public_key.len(), GodKeyPair::public_key_len());
        assert_eq!(
            kp.secret_key_bytes().len(),
            GodKeyPair::secret_key_len(),
            "Dilithium5 secret key size"
        );
        // A generated key must survive its own serialisation — this is
        // the path every vault and attestation key goes through.
        let back = GodKeyPair::from_json(&kp.to_json().unwrap()).unwrap();
        assert_eq!(back.public_key, kp.public_key);
        assert!(!kp.fingerprint.is_empty());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = GodKeyPair::generate().unwrap();
        let msg = b"The Architect protects Nevaeh forever";
        let sig = GodShield::sign(&kp, msg).unwrap();
        assert!(GodShield::verify(&kp.export_public(), &sig, msg).unwrap());
    }
    #[test]
    fn tampered_message_fails() {
        let kp = GodKeyPair::generate().unwrap();
        let sig = GodShield::sign(&kp, b"original message").unwrap();
        assert!(!GodShield::verify(&kp.export_public(), &sig, b"tampered message").unwrap());
    }

    /// REGRESSION TEST for the forgery bypass.
    ///
    /// Reproduces the original attack: take a genuine signature over message
    /// A, then overwrite the advisory message_hash field to claim it covers
    /// message B. The old implementation returned true here. It must not.
    #[test]
    fn signature_cannot_be_relabelled_onto_another_message() {
        let kp = GodKeyPair::generate().unwrap();
        let real_message = b"send 1 XRP to alice";
        let forged_message = b"send 10000000 XRP to attacker";
        let mut sig = GodShield::sign(&kp, real_message).unwrap();

        // Attacker rewrites the only field the old code checked.
        sig.message_hash = TripleHash::hash_hex(forged_message);

        let result = GodShield::verify(&kp.export_public(), &sig, forged_message).unwrap();
        assert!(
            !result,
            "FORGERY BYPASS: a signature over one message verified against another"
        );
    }
    /// A signature from key A must never verify under key B's public key.
    #[test]
    fn signature_from_wrong_key_fails() {
        let kp_a = GodKeyPair::generate().unwrap();
        let kp_b = GodKeyPair::generate().unwrap();
        let msg = b"authorised by A only";
        let sig = GodShield::sign(&kp_a, msg).unwrap();
        assert!(!GodShield::verify(&kp_b.export_public(), &sig, msg).unwrap());
    }

    /// REGRESSION TEST for the concatenation-ambiguity bug.
    ///
    /// Without length prefixes, ("AB","C") and ("A","BC") encode identically,
    /// so one signature covers both. With CanonicalMessage they must differ.
    #[test]
    fn canonical_encoding_is_unambiguous() {
        let a = CanonicalMessage::encode_strs("nev369.tx.v1", &["AB", "C"]);
        let b = CanonicalMessage::encode_strs("nev369.tx.v1", &["A", "BC"]);
        assert_ne!(a, b, "field boundaries must be preserved");
    }

    /// Domain separation must prevent cross-protocol signature replay.
    #[test]
    fn different_domains_produce_different_encodings() {
        let tx = CanonicalMessage::encode_strs("nev369.tx.v1", &["alice", "bob", "100"]);
        let round = CanonicalMessage::encode_strs("fairness.round.v1", &["alice", "bob", "100"]);
        assert_ne!(tx, round, "domain separation must hold");
    }

    #[test]
    fn rejects_wrong_sized_keys() {
        assert!(
            GodKeyPair::from_bytes(vec![0u8; 100], vec![0u8; GodKeyPair::secret_key_len()])
                .is_err()
        );
        assert!(GodKeyPair::from_bytes(vec![0u8; 2592], vec![0u8; 100]).is_err());
    }
}
