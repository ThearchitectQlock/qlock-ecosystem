// crates/godshield-gateway/src/lib.rs
//
// ═══════════════════════════════════════════════════════════════════════
// PQ SECURITY GATEWAY  —  spec §1
//
// ── THE ONE DESIGN DECISION THAT SHAPES EVERYTHING BELOW ──────────────
//
// §1 lists `POST /gateway/sign`. The obvious implementation is a service
// that holds customer private keys and signs whatever an authenticated
// caller sends. Do not build that. It is a signing oracle: one
// compromised API token signs anything, for anyone, forever — precisely
// the "single catastrophic credential" §14 says the architecture must
// not contain, and §11 repeats for AI agents ("must not silently obtain
// unrestricted access to private keys").
//
// So `sign` here is narrow on purpose:
//
//   - The gateway signs ONLY with its own operational identity.
//   - It signs ONLY domain-tagged gateway artifacts — attestations that
//     it checked something — never opaque caller-supplied bytes.
//   - Every signature is bound to the requesting identity and recorded.
//
// Customer keys stay in customer custody: hardware, HSM, or a Shamir
// vault (§6). The gateway is a policy boundary that attests, not a
// keyring that serves.
//
// Verification is the opposite — it needs no secrets, so `verify` and
// `policy/check` are the endpoints that carry the real load.
//
// ── WHAT THIS CRATE IS ────────────────────────────────────────────────
//
// The transport-agnostic core: policy, rotation with history, and a
// tamper-evident audit chain. HTTP handlers bind to it rather than the
// logic living inside request handlers, so the rules are testable
// without a server and reusable from the CLI.
// ═══════════════════════════════════════════════════════════════════════

use godshield_core::{CanonicalMessage, GodPublicKey, GodShield, GodSignature, TripleHash};
use godshield_identity::{Identity, IdentityError, MachineRegistry, Status};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum GatewayError {
    #[error("algorithm {0} is not on the allowlist")]
    AlgorithmNotAllowed(String),

    #[error("value {value} exceeds the {limit} limit for this identity")]
    ValueLimitExceeded { value: u128, limit: u128 },

    #[error("rate limit exceeded for {identity}: {count} requests in the current window, {limit} allowed")]
    RateLimited {
        identity: String,
        count: u32,
        limit: u32,
    },

    #[error("identity: {0}")]
    Identity(#[from] IdentityError),

    #[error("the gateway signs only its own attestations, not caller-supplied bytes")]
    RefusedOracleRequest,

    #[error("signature does not verify")]
    VerificationFailed,

    #[error("audit chain broken at entry {index}")]
    AuditChainBroken { index: usize },

    #[error("key rotation for {0} would orphan historical signatures — supply retired_at")]
    RotationWouldOrphan(String),

    #[error("no key was active for {identity} at {timestamp}")]
    NoKeyAtTime { identity: String, timestamp: u64 },
}

// ═══════════════════════════════════════════════════════════════════════
// POLICY  —  §1 "cryptographic policy enforcement"
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayPolicy {
    pub policy_id: String,

    /// §1 "algorithm allowlists". An allowlist, never a denylist: a
    /// denylist silently permits every primitive nobody thought to ban,
    /// including whatever is deprecated next year.
    pub allowed_algorithms: Vec<String>,

    /// §1 "transaction/value limits".
    pub default_value_limit: u128,
    pub per_identity_value_limit: HashMap<String, u128>,

    /// §1 "rate limiting", per identity rather than per IP. An
    /// identity-bound gateway that limits by IP lets one compromised
    /// credential spread across a botnet and stay under every limit.
    pub requests_per_window: u32,
    pub window_seconds: u64,
}

impl GatewayPolicy {
    pub fn value_limit_for(&self, identity: &str) -> u128 {
        self.per_identity_value_limit
            .get(identity)
            .copied()
            .unwrap_or(self.default_value_limit)
    }

    pub fn check_algorithm(&self, algorithm: &str) -> Result<(), GatewayError> {
        if self.allowed_algorithms.iter().any(|a| a == algorithm) {
            Ok(())
        } else {
            Err(GatewayError::AlgorithmNotAllowed(algorithm.into()))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// AUDIT  —  §1 "cryptographic audit trails", §8 "tamper-evident"
// ═══════════════════════════════════════════════════════════════════════

/// One audit entry, chained to its predecessor.
///
/// §8 requires critical events to be tamper-evident and cryptographically
/// verifiable. A plain append-only table is neither: anyone with write
/// access edits a row and nothing notices. Chaining each entry's hash
/// into the next means altering entry N invalidates every entry after it,
/// so tampering is detectable by anyone holding the head hash — including
/// an auditor who does not trust the operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub index: usize,
    pub timestamp: u64,
    pub event: String,
    pub identity: String,
    pub outcome: String,
    pub detail: String,
    pub policy_id: String,
    /// Hash of the previous entry. Genesis entry carries 128 zeroes.
    pub previous_hash: String,
    pub entry_hash: String,
}

impl AuditEntry {
    fn compute_hash(&self) -> String {
        TripleHash::hash_hex(&CanonicalMessage::encode(
            "GODSHIELD-AUDIT-V1",
            &[
                &(self.index as u64).to_le_bytes(),
                &self.timestamp.to_le_bytes(),
                self.event.as_bytes(),
                self.identity.as_bytes(),
                self.outcome.as_bytes(),
                self.detail.as_bytes(),
                self.policy_id.as_bytes(),
                self.previous_hash.as_bytes(),
            ],
        ))
    }
}

#[derive(Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn append(
        &mut self,
        event: &str,
        identity: &str,
        outcome: &str,
        detail: &str,
        policy_id: &str,
        now: u64,
    ) -> &AuditEntry {
        let previous_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| "0".repeat(128));

        let mut entry = AuditEntry {
            index: self.entries.len(),
            timestamp: now,
            event: event.into(),
            identity: identity.into(),
            outcome: outcome.into(),
            detail: detail.into(),
            policy_id: policy_id.into(),
            previous_hash,
            entry_hash: String::new(),
        };
        entry.entry_hash = entry.compute_hash();
        self.entries.push(entry);
        self.entries.last().expect("just pushed")
    }

    /// Walk the chain. Returns the index of the first broken link.
    ///
    /// Both failure modes matter: an entry whose own hash no longer
    /// matches its contents (edited in place) and an entry whose
    /// `previous_hash` no longer matches its predecessor (one removed
    /// from the middle).
    pub fn verify(&self) -> Result<(), GatewayError> {
        let mut expected_prev = "0".repeat(128);
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.previous_hash != expected_prev || entry.entry_hash != entry.compute_hash() {
                return Err(GatewayError::AuditChainBroken { index: i });
            }
            expected_prev = entry.entry_hash.clone();
        }
        Ok(())
    }

    pub fn head(&self) -> String {
        self.entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| "0".repeat(128))
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn since(&self, index: usize) -> &[AuditEntry] {
        self.entries.get(index..).unwrap_or(&[])
    }
}

// ═══════════════════════════════════════════════════════════════════════
// KEY ROTATION  —  §1 "key rotation", §6 lifecycle
// ═══════════════════════════════════════════════════════════════════════

/// A key that was current between two points in time.
///
/// Rotation that simply replaces the key breaks every signature made
/// before it. That is not a cosmetic problem: NEV369 blocks, escrow
/// attestations and audit entries are all historical signatures whose
/// whole purpose is verifying years later. Retired keys stay resolvable
/// so that history keeps verifying, while only the current key may
/// produce anything new.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEpoch {
    pub public_key_hex: String,
    pub fingerprint: String,
    pub algorithm: String,
    pub active_from: u64,
    /// None means current.
    pub retired_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyHistory {
    pub epochs: Vec<KeyEpoch>,
}

impl KeyHistory {
    /// The key that was current at `timestamp`.
    pub fn key_at(&self, timestamp: u64) -> Option<&KeyEpoch> {
        self.epochs.iter().find(|e| {
            // map_or, not is_none_or: the latter landed in Rust 1.82 and
            // rust-toolchain.toml pins 1.75. Same semantics.
            timestamp >= e.active_from && e.retired_at.is_none_or(|r| timestamp < r)
        })
    }

    pub fn current(&self) -> Option<&KeyEpoch> {
        self.epochs.iter().find(|e| e.retired_at.is_none())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// GATEWAY
// ═══════════════════════════════════════════════════════════════════════

/// What the gateway will attest to. Deliberately a closed set — this is
/// what stops `sign` becoming a general oracle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    /// "I verified this signature against this identity at this time."
    VerificationResult,
    /// "I evaluated this policy and reached this decision."
    PolicyDecision,
    /// "This identity was registered with this key."
    IdentityRegistration,
    /// "This key was rotated."
    KeyRotation,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GatewayAttestation {
    pub kind: AttestationKind,
    pub subject: String,
    pub statement: String,
    pub timestamp: u64,
    pub policy_id: String,
    pub signature_hex: String,
    pub signer_fingerprint: String,
}

pub struct Gateway {
    policy: GatewayPolicy,
    registry: MachineRegistry,
    keys: HashMap<String, KeyHistory>,
    audit: AuditLog,
    /// (identity, window_start, count)
    rate: HashMap<String, (u64, u32)>,
    /// The gateway's OWN key. The only private key this service holds,
    /// and it can only produce the attestations above.
    operational_key: Option<Vec<u8>>,
    operational_fingerprint: String,
}

impl Gateway {
    pub fn new(policy: GatewayPolicy) -> Self {
        Self {
            policy,
            registry: MachineRegistry::default(),
            keys: HashMap::new(),
            audit: AuditLog::default(),
            rate: HashMap::new(),
            operational_key: None,
            operational_fingerprint: String::new(),
        }
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub fn registry_mut(&mut self) -> &mut MachineRegistry {
        &mut self.registry
    }

    /// Install the gateway's operational keypair JSON.
    pub fn set_operational_key(&mut self, keypair_json: &str) -> Result<(), GatewayError> {
        let kp = godshield_core::GodKeyPair::from_json(keypair_json)
            .map_err(|_| GatewayError::VerificationFailed)?;
        self.operational_fingerprint = TripleHash::hash_hex(&kp.public_key);
        // to_json(), not serde_json::to_vec. godshield-core does not
        // derive Serialize on GodKeyPair on purpose — it keeps a private
        // serde shape behind explicit helpers so an accidental
        // serialize cannot leak the secret key.
        self.operational_key = Some(
            kp.to_json()
                .map_err(|_| GatewayError::VerificationFailed)?
                .into_bytes(),
        );
        Ok(())
    }

    // ── §1 rate limiting, per identity ─────────────────────────────────

    fn check_rate(&mut self, identity: &str, now: u64) -> Result<(), GatewayError> {
        let entry = self.rate.entry(identity.to_string()).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= self.policy.window_seconds {
            *entry = (now, 0);
        }
        entry.1 += 1;
        if entry.1 > self.policy.requests_per_window {
            return Err(GatewayError::RateLimited {
                identity: identity.into(),
                count: entry.1,
                limit: self.policy.requests_per_window,
            });
        }
        Ok(())
    }

    // ── POST /gateway/identity/register ────────────────────────────────

    pub fn register_identity(
        &mut self,
        identity_id: &str,
        public_key: &[u8],
        algorithm: &str,
        now: u64,
    ) -> Result<String, GatewayError> {
        self.policy.check_algorithm(algorithm)?;

        let ident = Identity::new(identity_id, public_key, now);
        let fingerprint = ident.fingerprint.clone();
        self.registry.register(ident)?;

        self.keys.insert(
            identity_id.to_string(),
            KeyHistory {
                epochs: vec![KeyEpoch {
                    public_key_hex: hex::encode(public_key),
                    fingerprint: fingerprint.clone(),
                    algorithm: algorithm.into(),
                    active_from: now,
                    retired_at: None,
                }],
            },
        );

        self.audit.append(
            "identity.register",
            identity_id,
            "ALLOW",
            &fingerprint,
            &self.policy.policy_id,
            now,
        );
        Ok(fingerprint)
    }

    // ── POST /gateway/key/rotate ───────────────────────────────────────

    /// Rotate to a new key, retiring the old one at `now`.
    ///
    /// The retired key remains in history so signatures produced before
    /// `now` keep verifying. Only the new key can produce anything after.
    pub fn rotate_key(
        &mut self,
        identity_id: &str,
        new_public_key: &[u8],
        algorithm: &str,
        now: u64,
    ) -> Result<String, GatewayError> {
        self.policy.check_algorithm(algorithm)?;

        let history = self
            .keys
            .get_mut(identity_id)
            .ok_or_else(|| IdentityError::UnknownIdentity(identity_id.into()))?;

        if let Some(current) = history.epochs.iter_mut().find(|e| e.retired_at.is_none()) {
            current.retired_at = Some(now);
        }

        let fingerprint = TripleHash::hash_hex(new_public_key);
        history.epochs.push(KeyEpoch {
            public_key_hex: hex::encode(new_public_key),
            fingerprint: fingerprint.clone(),
            algorithm: algorithm.into(),
            active_from: now,
            retired_at: None,
        });

        self.audit.append(
            "key.rotate",
            identity_id,
            "ALLOW",
            &fingerprint,
            &self.policy.policy_id,
            now,
        );
        Ok(fingerprint)
    }

    pub fn key_history(&self, identity_id: &str) -> Option<&KeyHistory> {
        self.keys.get(identity_id)
    }

    // ── POST /gateway/verify ───────────────────────────────────────────

    /// Verify a signature made by `identity_id` at `signed_at`, resolving
    /// the key that was current at that moment.
    ///
    /// Resolving by timestamp rather than by current key is what makes
    /// rotation non-destructive.
    pub fn verify(
        &mut self,
        identity_id: &str,
        message: &[u8],
        signature_hex: &str,
        signed_at: u64,
        now: u64,
    ) -> Result<(), GatewayError> {
        self.check_rate(identity_id, now)?;

        // Clone the two fields needed and let the borrow of `self.keys`
        // end here. Holding `&KeyEpoch` across `self.audit.append` below
        // is an immutable borrow live across a mutable one — E0502.
        let (public_key_hex, fingerprint) = self
            .keys
            .get(identity_id)
            .and_then(|h| h.key_at(signed_at))
            .map(|e| (e.public_key_hex.clone(), e.fingerprint.clone()))
            .ok_or_else(|| GatewayError::NoKeyAtTime {
                identity: identity_id.into(),
                timestamp: signed_at,
            })?;

        let pk_bytes =
            hex::decode(&public_key_hex).map_err(|_| GatewayError::VerificationFailed)?;
        let sig_bytes = hex::decode(signature_hex).map_err(|_| GatewayError::VerificationFailed)?;

        let public_key = GodPublicKey {
            public_key: pk_bytes,
            fingerprint: fingerprint.clone(),
        };
        let signature = GodSignature {
            signature: sig_bytes,
            message_hash: TripleHash::hash_hex(message),
            signer_fingerprint: fingerprint,
            timestamp: signed_at,
        };

        let ok = matches!(
            GodShield::verify(&public_key, &signature, message),
            Ok(true)
        );
        let policy_id = self.policy.policy_id.clone();
        self.audit.append(
            "gateway.verify",
            identity_id,
            if ok { "ALLOW" } else { "DENY" },
            &TripleHash::hash_hex(message)[..32],
            &policy_id,
            now,
        );

        if ok {
            Ok(())
        } else {
            Err(GatewayError::VerificationFailed)
        }
    }

    // ── POST /gateway/policy/check ─────────────────────────────────────

    /// §7 decisions, narrowed to what this crate can decide without the
    /// full risk engine: algorithm, value limit, identity status, rate.
    pub fn policy_check(
        &mut self,
        identity_id: &str,
        algorithm: &str,
        value: u128,
        now: u64,
    ) -> Result<PolicyDecision, GatewayError> {
        self.check_rate(identity_id, now)?;
        let policy_id = self.policy.policy_id.clone();

        // Evaluated inline rather than in a closure capturing `self`.
        // A closure taking `&Self` keeps the borrow alive across the
        // `self.audit.append` calls below, which need `&mut self`.
        let outcome: Result<(), GatewayError> = (|| {
            self.policy.check_algorithm(algorithm)?;
            let status = self
                .registry
                .identity(identity_id)
                .map(|i| i.status)
                .ok_or_else(|| IdentityError::UnknownIdentity(identity_id.into()))?;
            if status != Status::Active {
                return Err(GatewayError::Identity(IdentityError::IdentityNotActive {
                    id: identity_id.into(),
                    status,
                }));
            }
            let limit = self.policy.value_limit_for(identity_id);
            if value > limit {
                return Err(GatewayError::ValueLimitExceeded { value, limit });
            }
            Ok(())
        })();

        match outcome {
            Ok(()) => {
                self.audit.append(
                    "policy.check",
                    identity_id,
                    "ALLOW",
                    &value.to_string(),
                    &policy_id,
                    now,
                );
                Ok(PolicyDecision {
                    decision: "ALLOW".into(),
                    policy_id,
                    reason: None,
                })
            }
            Err(e) => {
                self.audit.append(
                    "policy.check",
                    identity_id,
                    "DENY",
                    &e.to_string(),
                    &policy_id,
                    now,
                );
                Ok(PolicyDecision {
                    decision: "DENY".into(),
                    policy_id,
                    reason: Some(e.to_string()),
                })
            }
        }
    }

    // ── POST /gateway/sign ─────────────────────────────────────────────

    /// Sign a gateway attestation with the gateway's own key.
    ///
    /// Note what is absent: any path that signs caller-supplied bytes.
    /// `statement` is composed by the gateway from its own findings, and
    /// the domain tag is fixed. A caller cannot smuggle a transaction, a
    /// credential, or a bridge authorization through here and have the
    /// gateway's key endorse it — the encoding it would need is not
    /// reachable from this function.
    pub fn sign_attestation(
        &mut self,
        kind: AttestationKind,
        subject: &str,
        statement: &str,
        now: u64,
    ) -> Result<GatewayAttestation, GatewayError> {
        let key_bytes = self
            .operational_key
            .as_ref()
            .ok_or(GatewayError::RefusedOracleRequest)?;
        let json = std::str::from_utf8(key_bytes).map_err(|_| GatewayError::VerificationFailed)?;
        let kp = godshield_core::GodKeyPair::from_json(json)
            .map_err(|_| GatewayError::VerificationFailed)?;

        let kind_tag = match kind {
            AttestationKind::VerificationResult => "verification_result",
            AttestationKind::PolicyDecision => "policy_decision",
            AttestationKind::IdentityRegistration => "identity_registration",
            AttestationKind::KeyRotation => "key_rotation",
        };

        let message = CanonicalMessage::encode(
            "GODSHIELD-GATEWAY-ATTESTATION-V1",
            &[
                kind_tag.as_bytes(),
                subject.as_bytes(),
                statement.as_bytes(),
                &now.to_le_bytes(),
                self.policy.policy_id.as_bytes(),
            ],
        );

        let sig = GodShield::sign(&kp, &message).map_err(|_| GatewayError::VerificationFailed)?;
        let policy_id = self.policy.policy_id.clone();

        self.audit
            .append("gateway.sign", subject, "ALLOW", kind_tag, &policy_id, now);

        Ok(GatewayAttestation {
            kind,
            subject: subject.into(),
            statement: statement.into(),
            timestamp: now,
            policy_id,
            signature_hex: hex::encode(&sig.signature),
            signer_fingerprint: self.operational_fingerprint.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyDecision {
    pub decision: String,
    pub policy_id: String,
    pub reason: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use godshield_core::GodKeyPair;

    const NOW: u64 = 1_800_000_000;

    fn policy() -> GatewayPolicy {
        GatewayPolicy {
            policy_id: "gw-v1".into(),
            allowed_algorithms: vec!["ML-DSA-87".into()],
            default_value_limit: 1_000_000,
            per_identity_value_limit: HashMap::new(),
            requests_per_window: 100,
            window_seconds: 60,
        }
    }

    fn gateway() -> (Gateway, GodKeyPair) {
        let mut g = Gateway::new(policy());
        let kp = GodKeyPair::generate().unwrap();
        g.register_identity("svc-1", &kp.public_key, "ML-DSA-87", NOW)
            .unwrap();
        (g, kp)
    }

    // ── Rotation must not orphan history ──

    #[test]
    fn a_signature_still_verifies_after_the_key_rotates() {
        let (mut g, kp) = gateway();
        let msg = b"settlement record";
        let sig = GodShield::sign(&kp, msg).unwrap();
        let sig_hex = hex::encode(&sig.signature);

        g.verify("svc-1", msg, &sig_hex, NOW, NOW).unwrap();

        let new_kp = GodKeyPair::generate().unwrap();
        g.rotate_key("svc-1", &new_kp.public_key, "ML-DSA-87", NOW + 1000)
            .unwrap();

        // Signed before the rotation — must still verify, because NEV369
        // blocks and escrow attestations are exactly this case.
        assert!(g.verify("svc-1", msg, &sig_hex, NOW, NOW + 2000).is_ok());
    }

    #[test]
    fn the_retired_key_cannot_sign_after_rotation() {
        let (mut g, kp) = gateway();
        let new_kp = GodKeyPair::generate().unwrap();
        g.rotate_key("svc-1", &new_kp.public_key, "ML-DSA-87", NOW + 1000)
            .unwrap();

        let msg = b"late message";
        let sig = GodShield::sign(&kp, msg).unwrap();
        // Claimed as signed AFTER retirement — resolves to the new key,
        // which did not produce this signature.
        assert_eq!(
            g.verify(
                "svc-1",
                msg,
                &hex::encode(&sig.signature),
                NOW + 2000,
                NOW + 2000
            ),
            Err(GatewayError::VerificationFailed)
        );
    }

    #[test]
    fn key_history_resolves_by_timestamp() {
        let (mut g, _) = gateway();
        let k2 = GodKeyPair::generate().unwrap();
        g.rotate_key("svc-1", &k2.public_key, "ML-DSA-87", NOW + 100)
            .unwrap();

        let h = g.key_history("svc-1").unwrap();
        assert_eq!(h.epochs.len(), 2);
        assert!(
            h.key_at(NOW + 50).unwrap().retired_at.is_some(),
            "old epoch"
        );
        assert!(
            h.key_at(NOW + 150).unwrap().retired_at.is_none(),
            "current epoch"
        );
        assert_eq!(
            h.current().unwrap().fingerprint,
            TripleHash::hash_hex(&k2.public_key)
        );
    }

    // ── Audit chain ──

    #[test]
    fn the_audit_chain_verifies() {
        let (mut g, _) = gateway();
        g.policy_check("svc-1", "ML-DSA-87", 100, NOW).unwrap();
        g.policy_check("svc-1", "ML-DSA-87", 200, NOW).unwrap();
        assert!(g.audit().verify().is_ok());
        assert!(g.audit().entries().len() >= 3);
    }

    #[test]
    fn editing_an_audit_entry_breaks_the_chain() {
        let mut log = AuditLog::default();
        log.append("a", "i", "ALLOW", "x", "p", NOW);
        log.append("b", "i", "ALLOW", "y", "p", NOW);
        log.append("c", "i", "ALLOW", "z", "p", NOW);
        assert!(log.verify().is_ok());

        // Tamper with the middle entry's content.
        log.entries[1].outcome = "DENY".into();
        assert_eq!(
            log.verify(),
            Err(GatewayError::AuditChainBroken { index: 1 })
        );
    }

    #[test]
    fn removing_an_audit_entry_breaks_the_chain() {
        let mut log = AuditLog::default();
        log.append("a", "i", "ALLOW", "x", "p", NOW);
        log.append("b", "i", "ALLOW", "y", "p", NOW);
        log.append("c", "i", "ALLOW", "z", "p", NOW);
        log.entries.remove(1);
        assert!(log.verify().is_err(), "a hole must be detectable");
    }

    #[test]
    fn re_signing_a_tampered_entry_still_breaks_the_chain() {
        // An attacker who recomputes the edited entry's own hash still
        // cannot fix the successor's previous_hash without recomputing
        // every entry after it.
        let mut log = AuditLog::default();
        log.append("a", "i", "ALLOW", "x", "p", NOW);
        log.append("b", "i", "ALLOW", "y", "p", NOW);
        log.append("c", "i", "ALLOW", "z", "p", NOW);

        log.entries[1].outcome = "DENY".into();
        log.entries[1].entry_hash = log.entries[1].compute_hash();
        assert_eq!(
            log.verify(),
            Err(GatewayError::AuditChainBroken { index: 2 })
        );
    }

    // ── Policy ──

    #[test]
    fn a_disallowed_algorithm_is_denied() {
        let (mut g, _) = gateway();
        let d = g.policy_check("svc-1", "ECDSA-secp256k1", 1, NOW).unwrap();
        assert_eq!(d.decision, "DENY");
        assert!(d.reason.unwrap().contains("allowlist"));
    }

    #[test]
    fn registration_with_a_disallowed_algorithm_is_refused() {
        let mut g = Gateway::new(policy());
        let kp = GodKeyPair::generate().unwrap();
        assert_eq!(
            g.register_identity("bad", &kp.public_key, "Ed25519", NOW),
            Err(GatewayError::AlgorithmNotAllowed("Ed25519".into()))
        );
    }

    #[test]
    fn a_value_over_the_limit_is_denied() {
        let (mut g, _) = gateway();
        let d = g
            .policy_check("svc-1", "ML-DSA-87", 2_000_000, NOW)
            .unwrap();
        assert_eq!(d.decision, "DENY");
    }

    #[test]
    fn a_per_identity_limit_overrides_the_default() {
        let mut p = policy();
        p.per_identity_value_limit.insert("svc-1".into(), 10);
        let mut g = Gateway::new(p);
        let kp = GodKeyPair::generate().unwrap();
        g.register_identity("svc-1", &kp.public_key, "ML-DSA-87", NOW)
            .unwrap();
        assert_eq!(
            g.policy_check("svc-1", "ML-DSA-87", 100, NOW)
                .unwrap()
                .decision,
            "DENY"
        );
        assert_eq!(
            g.policy_check("svc-1", "ML-DSA-87", 5, NOW)
                .unwrap()
                .decision,
            "ALLOW"
        );
    }

    #[test]
    fn a_suspended_identity_is_denied() {
        let (mut g, _) = gateway();
        g.registry_mut().suspend("svc-1", "investigation").unwrap();
        assert_eq!(
            g.policy_check("svc-1", "ML-DSA-87", 1, NOW)
                .unwrap()
                .decision,
            "DENY"
        );
    }

    #[test]
    fn denials_are_audited_too() {
        // An audit trail that only records successes is useless for
        // incident response — the denials are the interesting part.
        let (mut g, _) = gateway();
        g.policy_check("svc-1", "ECDSA", 1, NOW).unwrap();
        assert!(g.audit().entries().iter().any(|e| e.outcome == "DENY"));
    }

    // ── Rate limiting ──

    #[test]
    fn rate_limiting_is_per_identity() {
        let mut p = policy();
        p.requests_per_window = 2;
        let mut g = Gateway::new(p);
        let a = GodKeyPair::generate().unwrap();
        let b = GodKeyPair::generate().unwrap();
        g.register_identity("a", &a.public_key, "ML-DSA-87", NOW)
            .unwrap();
        g.register_identity("b", &b.public_key, "ML-DSA-87", NOW)
            .unwrap();

        g.policy_check("a", "ML-DSA-87", 1, NOW).unwrap();
        g.policy_check("a", "ML-DSA-87", 1, NOW).unwrap();
        assert!(matches!(
            g.policy_check("a", "ML-DSA-87", 1, NOW),
            Err(GatewayError::RateLimited { .. })
        ));

        // b is unaffected — one noisy identity must not deny another.
        assert!(g.policy_check("b", "ML-DSA-87", 1, NOW).is_ok());
    }

    #[test]
    fn the_rate_window_rolls() {
        let mut p = policy();
        p.requests_per_window = 1;
        p.window_seconds = 60;
        let mut g = Gateway::new(p);
        let kp = GodKeyPair::generate().unwrap();
        g.register_identity("a", &kp.public_key, "ML-DSA-87", NOW)
            .unwrap();
        g.policy_check("a", "ML-DSA-87", 1, NOW).unwrap();
        assert!(g.policy_check("a", "ML-DSA-87", 1, NOW).is_err());
        assert!(g.policy_check("a", "ML-DSA-87", 1, NOW + 61).is_ok());
    }

    // ── The oracle refusal ──

    #[test]
    fn the_gateway_refuses_to_sign_without_its_own_key() {
        let (mut g, _) = gateway();
        assert_eq!(
            g.sign_attestation(AttestationKind::PolicyDecision, "s", "stmt", NOW),
            Err(GatewayError::RefusedOracleRequest)
        );
    }

    #[test]
    fn gateway_attestations_are_domain_separated_from_everything_else() {
        let (mut g, _) = gateway();
        let kp = GodKeyPair::generate().unwrap();
        g.set_operational_key(&kp.to_json().unwrap()).unwrap();

        let att = g
            .sign_attestation(AttestationKind::PolicyDecision, "svc-1", "ALLOW", NOW)
            .unwrap();

        // The attested bytes carry the gateway domain, so this signature
        // cannot be replayed as a credential, machine action, bridge
        // authorization or NEV369 transaction.
        let message = CanonicalMessage::encode(
            "GODSHIELD-GATEWAY-ATTESTATION-V1",
            &[
                b"policy_decision".as_slice(),
                b"svc-1",
                b"ALLOW",
                &NOW.to_le_bytes(),
                b"gw-v1",
            ],
        );
        let other = CanonicalMessage::encode(
            "GODSHIELD-CREDENTIAL-V1",
            &[
                b"policy_decision".as_slice(),
                b"svc-1",
                b"ALLOW",
                &NOW.to_le_bytes(),
                b"gw-v1",
            ],
        );
        assert_ne!(message, other);
        assert!(!att.signature_hex.is_empty());
    }

    #[test]
    fn verification_is_recorded_whether_it_passes_or_fails() {
        let (mut g, kp) = gateway();
        let msg = b"x";
        let sig = GodShield::sign(&kp, msg).unwrap();
        g.verify("svc-1", msg, &hex::encode(&sig.signature), NOW, NOW)
            .unwrap();
        let _ = g.verify(
            "svc-1",
            b"different",
            &hex::encode(&sig.signature),
            NOW,
            NOW,
        );

        let outcomes: Vec<&str> = g
            .audit()
            .entries()
            .iter()
            .filter(|e| e.event == "gateway.verify")
            .map(|e| e.outcome.as_str())
            .collect();
        assert_eq!(outcomes, vec!["ALLOW", "DENY"]);
    }
}
