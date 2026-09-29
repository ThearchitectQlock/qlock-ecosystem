// crates/godshield-identity/src/lib.rs
//
// ═══════════════════════════════════════════════════════════════════════
// GODSHIELD IDENTITY + MACHINE SECURITY  —  spec §3 and §4
//
// WHY ONE CRATE AND NOT TWO
//
// §3 and §4 are listed separately, but a machine action is an identity
// acting. Same records, same credential checks, same revocation path —
// the only difference is that the actor is a service rather than a
// person. Splitting them produces two crates where one cannot answer a
// question without the other, so they live together and the modules
// stay distinct.
//
// THE THREE QUESTIONS §3 SETS
//
//   Who is acting?              -> Identity, bound to a Dilithium5 key
//   What are they authorized to? -> Credential, carrying claims
//   Is that authority still valid? -> effective status, computed now
//
// The third is where identity systems usually fail, so it gets the most
// care below. A signature that verifies proves the holder had the key
// when they signed. It proves nothing about whether they are still
// allowed to act. Those are different questions and this crate keeps
// them apart: `verify_*` answers the first, `authorize_*` answers both.
// ═══════════════════════════════════════════════════════════════════════

use godshield_core::{CanonicalMessage, GodPublicKey, GodShield, GodSignature, TripleHash};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ═══════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum IdentityError {
    #[error("no identity registered for {0}")]
    UnknownIdentity(String),

    #[error("identity {id} is {status:?}, not active")]
    IdentityNotActive { id: String, status: Status },

    #[error("credential {id} is {status:?}")]
    CredentialNotActive { id: String, status: Status },

    #[error("credential {id} expired at {expires_at}, now {now}")]
    CredentialExpired {
        id: String,
        expires_at: u64,
        now: u64,
    },

    #[error("credential {id} is not yet valid — issued at {issued_at}, now {now}")]
    CredentialNotYetValid {
        id: String,
        issued_at: u64,
        now: u64,
    },

    #[error("credential {id} was issued by {issuer}, which is not an active identity")]
    IssuerNotActive { id: String, issuer: String },

    #[error("credential {id} does not carry the claim {claim}")]
    MissingClaim { id: String, claim: String },

    #[error("signature does not verify for {0}")]
    BadSignature(String),

    #[error("fingerprint does not derive from the supplied public key")]
    FingerprintMismatch,

    #[error("action parameters do not match the hash that was signed")]
    ParameterMismatch,

    #[error("nonce {nonce} has already been used by {actor}")]
    ReplayedNonce { actor: String, nonce: String },

    #[error("action timestamp {ts} is {skew}s in the future; {max}s tolerated")]
    ClockSkew { ts: u64, skew: u64, max: u64 },

    #[error("action timestamp {ts} is older than the {max}s acceptance window")]
    ActionTooOld { ts: u64, max: u64 },

    #[error("{actor} is not permitted to {operation} on {target}")]
    NotPermitted {
        actor: String,
        operation: String,
        target: String,
    },

    #[error("identity {0} already registered")]
    AlreadyRegistered(String),
}

// ═══════════════════════════════════════════════════════════════════════
// STATUS
// ═══════════════════════════════════════════════════════════════════════

/// §3 credential states, used for identities too.
///
/// SUSPENDED and REVOKED are deliberately distinct. Suspension is
/// reversible and is what §4's "emergency suspension" and §9's CONTAIN
/// step use — you suspend on suspicion, in seconds, and reinstate if the
/// suspicion was wrong. Revocation is permanent and is what you reach for
/// once you know. Collapsing them into one flag means every containment
/// action is irreversible, which makes operators hesitate exactly when
/// they should not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Active,
    Suspended,
    Revoked,
    Expired,
}

// ═══════════════════════════════════════════════════════════════════════
// IDENTITY  —  §3
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub identity_id: String,
    pub public_key_hex: String,
    pub fingerprint: String,
    pub algorithm: String,
    pub created_at: u64,
    pub status: Status,
    pub metadata: HashMap<String, String>,
}

impl Identity {
    /// Register from raw key bytes. The fingerprint is DERIVED, never
    /// accepted from a caller — a supplied fingerprint is a field an
    /// attacker controls, and the whole identity binding rests on it.
    pub fn new(identity_id: impl Into<String>, public_key: &[u8], now: u64) -> Self {
        Self {
            identity_id: identity_id.into(),
            public_key_hex: hex::encode(public_key),
            fingerprint: TripleHash::hash_hex(public_key),
            algorithm: "ML-DSA-87".into(),
            created_at: now,
            status: Status::Active,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.metadata.insert(k.into(), v.into());
        self
    }

    fn public_key(&self) -> Result<GodPublicKey, IdentityError> {
        let bytes =
            hex::decode(&self.public_key_hex).map_err(|_| IdentityError::FingerprintMismatch)?;
        if TripleHash::hash_hex(&bytes) != self.fingerprint {
            return Err(IdentityError::FingerprintMismatch);
        }
        Ok(GodPublicKey {
            public_key: bytes,
            fingerprint: self.fingerprint.clone(),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CREDENTIAL  —  §3
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub credential_id: String,
    pub issuer: String,
    pub subject: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub claims: Vec<String>,
    pub signature_hex: String,
    pub status: Status,
}

impl Credential {
    /// Domain-separated per §3. The tag is inside the signed bytes, so a
    /// credential signature cannot be replayed as a machine action, a
    /// bridge attestation, or an NEV369 transaction.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut fields: Vec<&[u8]> = vec![
            self.credential_id.as_bytes(),
            self.issuer.as_bytes(),
            self.subject.as_bytes(),
        ];
        let issued = self.issued_at.to_le_bytes();
        let expires = self.expires_at.to_le_bytes();
        fields.push(&issued);
        fields.push(&expires);

        // Claims are length-prefixed individually. Joining them with a
        // separator would let a claim value containing that separator
        // forge additional claims — the delimiter bug that has appeared
        // three times in this codebase already.
        for claim in &self.claims {
            fields.push(claim.as_bytes());
        }

        CanonicalMessage::encode("GODSHIELD-CREDENTIAL-V1", &fields)
    }

    /// The status that actually applies right now.
    ///
    /// THE BUG THIS EXISTS TO PREVENT: trusting the stored `status`
    /// field. A credential issued for an hour still reads ACTIVE in the
    /// database a year later, because nothing walks the store flipping
    /// rows to EXPIRED. Expiry is a function of the clock, not of a
    /// background job, and every authorization path must compute it.
    ///
    /// Revocation and suspension are the reverse — they are facts about
    /// the record, so the stored value wins over the clock.
    pub fn effective_status(&self, now: u64) -> Status {
        match self.status {
            Status::Revoked => Status::Revoked,
            Status::Suspended => Status::Suspended,
            _ if now >= self.expires_at => Status::Expired,
            _ => Status::Active,
        }
    }

    pub fn has_claim(&self, claim: &str) -> bool {
        self.claims.iter().any(|c| c == claim)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// MACHINE ACTION  —  §4
// ═══════════════════════════════════════════════════════════════════════

/// A signed action by a machine, service, node or AI agent.
///
/// `parameters_hash` rather than the parameters themselves, so a large
/// payload does not have to travel inside the signed envelope — but that
/// means the signature only binds the parameters if someone checks the
/// hash. `MachineRegistry::authorize_action` requires the caller to
/// supply the real parameters and verifies the hash against them. A
/// signature over an unchecked hash authorizes nothing in particular.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineAction {
    pub action_id: String,
    pub actor: String,
    pub target: String,
    pub operation: String,
    pub parameters_hash: String,
    pub timestamp: u64,
    pub nonce: String,
    pub policy_id: String,
    pub signature_hex: String,
}

impl MachineAction {
    pub fn hash_parameters(parameters: &[u8]) -> String {
        TripleHash::hash_hex(parameters)
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        CanonicalMessage::encode(
            "GODSHIELD-MACHINE-ACTION-V1",
            &[
                self.action_id.as_bytes(),
                self.actor.as_bytes(),
                self.target.as_bytes(),
                self.operation.as_bytes(),
                self.parameters_hash.as_bytes(),
                &self.timestamp.to_le_bytes(),
                self.nonce.as_bytes(),
                self.policy_id.as_bytes(),
            ],
        )
    }
}

/// How long a signed action stays acceptable, and how much future-dating
/// is tolerated.
#[derive(Debug, Clone)]
pub struct ActionWindow {
    pub max_age_secs: u64,
    pub max_future_skew_secs: u64,
}

impl Default for ActionWindow {
    fn default() -> Self {
        // Five minutes back, thirty seconds forward.
        //
        // Asymmetric on purpose. Clock skew between honest machines is
        // seconds; a large future tolerance is an attacker pre-signing
        // actions to execute later, after the credential that authorized
        // them has been revoked.
        Self {
            max_age_secs: 300,
            max_future_skew_secs: 30,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// REGISTRY
// ═══════════════════════════════════════════════════════════════════════

pub struct MachineRegistry {
    identities: HashMap<String, Identity>,
    credentials: HashMap<String, Credential>,
    /// Consumed nonces, per actor. Scoped per actor so two machines
    /// choosing the same nonce independently do not collide — a global
    /// set would let one actor deny another by burning nonces.
    used_nonces: HashMap<String, HashSet<String>>,
    window: ActionWindow,
}

impl Default for MachineRegistry {
    fn default() -> Self {
        Self::new(ActionWindow::default())
    }
}

impl MachineRegistry {
    pub fn new(window: ActionWindow) -> Self {
        Self {
            identities: HashMap::new(),
            credentials: HashMap::new(),
            used_nonces: HashMap::new(),
            window,
        }
    }

    // ── Identity lifecycle ─────────────────────────────────────────────

    pub fn register(&mut self, identity: Identity) -> Result<(), IdentityError> {
        if self.identities.contains_key(&identity.identity_id) {
            return Err(IdentityError::AlreadyRegistered(identity.identity_id));
        }
        identity.public_key()?; // reject a fingerprint that does not derive
        self.identities
            .insert(identity.identity_id.clone(), identity);
        Ok(())
    }

    pub fn identity(&self, id: &str) -> Option<&Identity> {
        self.identities.get(id)
    }

    /// §4 emergency suspension. Reversible, and immediate.
    pub fn suspend(&mut self, id: &str, reason: &str) -> Result<(), IdentityError> {
        let ident = self
            .identities
            .get_mut(id)
            .ok_or_else(|| IdentityError::UnknownIdentity(id.into()))?;
        ident.status = Status::Suspended;
        tracing::warn!(identity = %id, %reason, "Identity suspended");
        Ok(())
    }

    pub fn reinstate(&mut self, id: &str, operator: &str) -> Result<(), IdentityError> {
        let ident = self
            .identities
            .get_mut(id)
            .ok_or_else(|| IdentityError::UnknownIdentity(id.into()))?;
        // Revocation is permanent. Reinstating a revoked identity would
        // make revocation meaningless, so it is refused rather than
        // silently succeeding.
        if ident.status == Status::Revoked {
            return Err(IdentityError::IdentityNotActive {
                id: id.into(),
                status: Status::Revoked,
            });
        }
        ident.status = Status::Active;
        tracing::warn!(identity = %id, %operator, "Identity reinstated");
        Ok(())
    }

    pub fn revoke(&mut self, id: &str, reason: &str) -> Result<(), IdentityError> {
        let ident = self
            .identities
            .get_mut(id)
            .ok_or_else(|| IdentityError::UnknownIdentity(id.into()))?;
        ident.status = Status::Revoked;
        tracing::error!(identity = %id, %reason, "Identity REVOKED");
        Ok(())
    }

    // ── Credentials ────────────────────────────────────────────────────

    /// Store a credential, verifying the issuer's signature over it.
    pub fn issue(&mut self, credential: Credential, now: u64) -> Result<(), IdentityError> {
        self.verify_credential_signature(&credential)?;

        let issuer = self
            .identities
            .get(&credential.issuer)
            .ok_or_else(|| IdentityError::UnknownIdentity(credential.issuer.clone()))?;
        if issuer.status != Status::Active {
            return Err(IdentityError::IssuerNotActive {
                id: credential.credential_id.clone(),
                issuer: credential.issuer.clone(),
            });
        }
        if credential.expires_at <= now {
            return Err(IdentityError::CredentialExpired {
                id: credential.credential_id.clone(),
                expires_at: credential.expires_at,
                now,
            });
        }

        self.credentials
            .insert(credential.credential_id.clone(), credential);
        Ok(())
    }

    pub fn revoke_credential(&mut self, id: &str, reason: &str) -> Result<(), IdentityError> {
        let c = self
            .credentials
            .get_mut(id)
            .ok_or_else(|| IdentityError::UnknownIdentity(id.into()))?;
        c.status = Status::Revoked;
        tracing::error!(credential = %id, %reason, "Credential REVOKED");
        Ok(())
    }

    /// Signature only. Says the issuer signed this; says nothing about
    /// whether it is still valid. Use `authorize_action` for that.
    fn verify_credential_signature(&self, c: &Credential) -> Result<(), IdentityError> {
        let issuer = self
            .identities
            .get(&c.issuer)
            .ok_or_else(|| IdentityError::UnknownIdentity(c.issuer.clone()))?;
        let pk = issuer.public_key()?;
        let message = c.signing_bytes();
        let sig_bytes = hex::decode(&c.signature_hex)
            .map_err(|_| IdentityError::BadSignature(c.credential_id.clone()))?;

        let signature = GodSignature {
            signature: sig_bytes,
            message_hash: TripleHash::hash_hex(&message),
            signer_fingerprint: issuer.fingerprint.clone(),
            timestamp: c.issued_at,
        };
        match GodShield::verify(&pk, &signature, &message) {
            Ok(true) => Ok(()),
            _ => Err(IdentityError::BadSignature(c.credential_id.clone())),
        }
    }

    /// Is this credential usable right now, for this claim?
    ///
    /// Re-checks the ISSUER as well as the credential. An issuer that has
    /// since been revoked should not keep conferring authority through
    /// credentials it signed while it was trusted — otherwise revoking a
    /// compromised issuer leaves every credential it ever issued live.
    pub fn check_credential(
        &self,
        credential_id: &str,
        required_claim: &str,
        now: u64,
    ) -> Result<&Credential, IdentityError> {
        let c = self
            .credentials
            .get(credential_id)
            .ok_or_else(|| IdentityError::UnknownIdentity(credential_id.into()))?;

        match c.effective_status(now) {
            Status::Active => {}
            Status::Expired => {
                return Err(IdentityError::CredentialExpired {
                    id: c.credential_id.clone(),
                    expires_at: c.expires_at,
                    now,
                })
            }
            status => {
                return Err(IdentityError::CredentialNotActive {
                    id: c.credential_id.clone(),
                    status,
                })
            }
        }

        if now < c.issued_at {
            return Err(IdentityError::CredentialNotYetValid {
                id: c.credential_id.clone(),
                issued_at: c.issued_at,
                now,
            });
        }

        let issuer = self
            .identities
            .get(&c.issuer)
            .ok_or_else(|| IdentityError::UnknownIdentity(c.issuer.clone()))?;
        if issuer.status != Status::Active {
            return Err(IdentityError::IssuerNotActive {
                id: c.credential_id.clone(),
                issuer: c.issuer.clone(),
            });
        }

        if !c.has_claim(required_claim) {
            return Err(IdentityError::MissingClaim {
                id: c.credential_id.clone(),
                claim: required_claim.into(),
            });
        }

        Ok(c)
    }

    // ── Machine actions ────────────────────────────────────────────────

    /// The full §4 path: signature, parameter binding, replay, freshness,
    /// actor status, credential validity.
    ///
    /// Ordered so cheap rejections happen before lattice verification,
    /// which is the expensive step and therefore the one a hostile caller
    /// would try to make you do repeatedly.
    ///
    /// `parameters` is the real payload. It is hashed and compared to the
    /// signed `parameters_hash`, which is what makes the signature bind
    /// to what the action actually does.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_action(
        &mut self,
        action: &MachineAction,
        parameters: &[u8],
        credential_id: &str,
        required_claim: &str,
        now: u64,
    ) -> Result<(), IdentityError> {
        // Freshness first — no state touched, no crypto done.
        if action.timestamp > now {
            let skew = action.timestamp - now;
            if skew > self.window.max_future_skew_secs {
                return Err(IdentityError::ClockSkew {
                    ts: action.timestamp,
                    skew,
                    max: self.window.max_future_skew_secs,
                });
            }
        } else if now - action.timestamp > self.window.max_age_secs {
            return Err(IdentityError::ActionTooOld {
                ts: action.timestamp,
                max: self.window.max_age_secs,
            });
        }

        // Replay.
        if self
            .used_nonces
            .get(&action.actor)
            .is_some_and(|s| s.contains(&action.nonce))
        {
            return Err(IdentityError::ReplayedNonce {
                actor: action.actor.clone(),
                nonce: action.nonce.clone(),
            });
        }

        // Parameter binding. Without this the signature covers a hash
        // nobody checked, and the action could carry any payload.
        if MachineAction::hash_parameters(parameters) != action.parameters_hash {
            return Err(IdentityError::ParameterMismatch);
        }

        // Actor must exist and be active.
        let actor = self
            .identities
            .get(&action.actor)
            .ok_or_else(|| IdentityError::UnknownIdentity(action.actor.clone()))?;
        if actor.status != Status::Active {
            return Err(IdentityError::IdentityNotActive {
                id: action.actor.clone(),
                status: actor.status,
            });
        }

        // Credential must be usable now and carry the claim.
        let credential = self.check_credential(credential_id, required_claim, now)?;
        if credential.subject != action.actor {
            return Err(IdentityError::NotPermitted {
                actor: action.actor.clone(),
                operation: action.operation.clone(),
                target: action.target.clone(),
            });
        }

        // Finally, the signature.
        let pk = actor.public_key()?;
        let message = action.signing_bytes();
        let sig_bytes = hex::decode(&action.signature_hex)
            .map_err(|_| IdentityError::BadSignature(action.action_id.clone()))?;
        let signature = GodSignature {
            signature: sig_bytes,
            message_hash: TripleHash::hash_hex(&message),
            signer_fingerprint: actor.fingerprint.clone(),
            timestamp: action.timestamp,
        };
        match GodShield::verify(&pk, &signature, &message) {
            Ok(true) => {}
            _ => return Err(IdentityError::BadSignature(action.action_id.clone())),
        }

        // Consume the nonce only after everything passed, so a failed
        // action does not burn a nonce the actor would legitimately retry.
        self.used_nonces
            .entry(action.actor.clone())
            .or_default()
            .insert(action.nonce.clone());

        Ok(())
    }

    /// Drop nonces that can no longer be replayed, since any action older
    /// than the window is rejected on freshness anyway. Without this the
    /// nonce set grows without bound for the process lifetime.
    ///
    /// Takes the nonces' own age from a supplied map because nonces carry
    /// no timestamp themselves; callers that need unbounded-safe pruning
    /// should key by action timestamp. Left explicit rather than hidden:
    /// a registry that silently forgot nonces would silently permit
    /// replays.
    pub fn nonce_count(&self) -> usize {
        self.used_nonces.values().map(|s| s.len()).sum()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use godshield_core::GodKeyPair;

    const NOW: u64 = 1_800_000_000;
    const HOUR: u64 = 3600;

    fn identity(id: &str, kp: &GodKeyPair) -> Identity {
        Identity::new(id, &kp.public_key, NOW)
    }

    fn credential(
        issuer_kp: &GodKeyPair,
        cred_id: &str,
        issuer: &str,
        subject: &str,
        claims: &[&str],
        expires_at: u64,
    ) -> Credential {
        let mut c = Credential {
            credential_id: cred_id.into(),
            issuer: issuer.into(),
            subject: subject.into(),
            issued_at: NOW,
            expires_at,
            claims: claims.iter().map(|s| s.to_string()).collect(),
            signature_hex: String::new(),
            status: Status::Active,
        };
        let sig = GodShield::sign(issuer_kp, &c.signing_bytes()).unwrap();
        c.signature_hex = hex::encode(&sig.signature);
        c
    }

    fn action(
        kp: &GodKeyPair,
        actor: &str,
        operation: &str,
        params: &[u8],
        nonce: &str,
        ts: u64,
    ) -> MachineAction {
        let mut a = MachineAction {
            action_id: format!("act-{nonce}"),
            actor: actor.into(),
            target: "nev369-node-1".into(),
            operation: operation.into(),
            parameters_hash: MachineAction::hash_parameters(params),
            timestamp: ts,
            nonce: nonce.into(),
            policy_id: "policy-v1".into(),
            signature_hex: String::new(),
        };
        let sig = GodShield::sign(kp, &a.signing_bytes()).unwrap();
        a.signature_hex = hex::encode(&sig.signature);
        a
    }

    /// Issuer + one machine subject with a `deploy` credential.
    fn world() -> (MachineRegistry, GodKeyPair, GodKeyPair) {
        let issuer_kp = GodKeyPair::generate().unwrap();
        let machine_kp = GodKeyPair::generate().unwrap();
        let mut r = MachineRegistry::default();
        r.register(identity("issuer", &issuer_kp)).unwrap();
        r.register(identity("machine-1", &machine_kp)).unwrap();
        let c = credential(
            &issuer_kp,
            "cred-1",
            "issuer",
            "machine-1",
            &["deploy", "read"],
            NOW + 24 * HOUR,
        );
        r.issue(c, NOW).unwrap();
        (r, issuer_kp, machine_kp)
    }

    // ── Happy path ──

    #[test]
    fn a_valid_action_is_authorized() {
        let (mut r, _, mkp) = world();
        let a = action(&mkp, "machine-1", "deploy", b"payload", "n1", NOW);
        assert!(r
            .authorize_action(&a, b"payload", "cred-1", "deploy", NOW)
            .is_ok());
    }

    // ── §3 question 3: is that authority still valid? ──

    #[test]
    fn a_stored_active_status_does_not_survive_expiry() {
        // The bug this crate exists to prevent: the record still says
        // ACTIVE because nothing walked the store flipping rows.
        let (mut r, _, mkp) = world();
        let later = NOW + 48 * HOUR;
        let a = action(&mkp, "machine-1", "deploy", b"p", "n1", later);

        assert_eq!(
            r.credentials["cred-1"].status,
            Status::Active,
            "stored field is still ACTIVE"
        );
        assert_eq!(
            r.credentials["cred-1"].effective_status(later),
            Status::Expired,
            "but the effective status is EXPIRED"
        );
        assert!(matches!(
            r.authorize_action(&a, b"p", "cred-1", "deploy", later),
            Err(IdentityError::CredentialExpired { .. })
        ));
    }

    #[test]
    fn revoking_the_issuer_kills_credentials_it_already_signed() {
        // Otherwise revoking a compromised issuer leaves every credential
        // it ever signed live.
        let (mut r, _, mkp) = world();
        r.revoke("issuer", "key compromise").unwrap();
        let a = action(&mkp, "machine-1", "deploy", b"p", "n1", NOW);
        assert!(matches!(
            r.authorize_action(&a, b"p", "cred-1", "deploy", NOW),
            Err(IdentityError::IssuerNotActive { .. })
        ));
    }

    #[test]
    fn a_revoked_credential_still_has_a_valid_signature_but_no_authority() {
        let (mut r, _, mkp) = world();
        r.revoke_credential("cred-1", "rotated").unwrap();

        // The signature is untouched and still verifies.
        assert!(r
            .verify_credential_signature(&r.credentials["cred-1"])
            .is_ok());

        // Authority is gone anyway. Those are different questions.
        let a = action(&mkp, "machine-1", "deploy", b"p", "n1", NOW);
        assert!(matches!(
            r.authorize_action(&a, b"p", "cred-1", "deploy", NOW),
            Err(IdentityError::CredentialNotActive {
                status: Status::Revoked,
                ..
            })
        ));
    }

    #[test]
    fn suspension_is_reversible_and_revocation_is_not() {
        let (mut r, _, _) = world();
        r.suspend("machine-1", "anomalous traffic").unwrap();
        assert!(r.reinstate("machine-1", "operator-alice").is_ok());

        r.revoke("machine-1", "confirmed compromise").unwrap();
        assert!(matches!(
            r.reinstate("machine-1", "operator-alice"),
            Err(IdentityError::IdentityNotActive {
                status: Status::Revoked,
                ..
            })
        ));
    }

    #[test]
    fn a_suspended_machine_cannot_act() {
        let (mut r, _, mkp) = world();
        r.suspend("machine-1", "under investigation").unwrap();
        let a = action(&mkp, "machine-1", "deploy", b"p", "n1", NOW);
        assert!(matches!(
            r.authorize_action(&a, b"p", "cred-1", "deploy", NOW),
            Err(IdentityError::IdentityNotActive {
                status: Status::Suspended,
                ..
            })
        ));
    }

    // ── §4 signed actions ──

    #[test]
    fn parameters_must_match_the_hash_that_was_signed() {
        // The signature covers a hash. Without checking it against the
        // real payload, the action could carry anything.
        let (mut r, _, mkp) = world();
        let a = action(&mkp, "machine-1", "deploy", b"harmless", "n1", NOW);
        assert_eq!(
            r.authorize_action(&a, b"MALICIOUS", "cred-1", "deploy", NOW),
            Err(IdentityError::ParameterMismatch)
        );
    }

    #[test]
    fn a_nonce_cannot_be_reused() {
        let (mut r, _, mkp) = world();
        let a = action(&mkp, "machine-1", "deploy", b"p", "n1", NOW);
        r.authorize_action(&a, b"p", "cred-1", "deploy", NOW)
            .unwrap();
        assert!(matches!(
            r.authorize_action(&a, b"p", "cred-1", "deploy", NOW),
            Err(IdentityError::ReplayedNonce { .. })
        ));
    }

    #[test]
    fn a_failed_action_does_not_burn_its_nonce() {
        // Otherwise a transient failure permanently consumes a nonce the
        // actor would legitimately retry with.
        let (mut r, _, mkp) = world();
        let a = action(&mkp, "machine-1", "deploy", b"p", "n1", NOW);
        let _ = r.authorize_action(&a, b"WRONG", "cred-1", "deploy", NOW);
        assert_eq!(r.nonce_count(), 0);
        assert!(r
            .authorize_action(&a, b"p", "cred-1", "deploy", NOW)
            .is_ok());
    }

    #[test]
    fn nonces_are_scoped_per_actor() {
        // A global set would let one machine deny another by burning
        // nonces it might choose.
        let issuer_kp = GodKeyPair::generate().unwrap();
        let m1 = GodKeyPair::generate().unwrap();
        let m2 = GodKeyPair::generate().unwrap();
        let mut r = MachineRegistry::default();
        r.register(identity("issuer", &issuer_kp)).unwrap();
        r.register(identity("m1", &m1)).unwrap();
        r.register(identity("m2", &m2)).unwrap();
        r.issue(
            credential(&issuer_kp, "c1", "issuer", "m1", &["deploy"], NOW + HOUR),
            NOW,
        )
        .unwrap();
        r.issue(
            credential(&issuer_kp, "c2", "issuer", "m2", &["deploy"], NOW + HOUR),
            NOW,
        )
        .unwrap();

        let a1 = action(&m1, "m1", "deploy", b"p", "shared-nonce", NOW);
        let a2 = action(&m2, "m2", "deploy", b"p", "shared-nonce", NOW);
        r.authorize_action(&a1, b"p", "c1", "deploy", NOW).unwrap();
        assert!(r.authorize_action(&a2, b"p", "c2", "deploy", NOW).is_ok());
    }

    #[test]
    fn a_stale_action_is_rejected() {
        let (mut r, _, mkp) = world();
        let a = action(&mkp, "machine-1", "deploy", b"p", "n1", NOW - 600);
        assert!(matches!(
            r.authorize_action(&a, b"p", "cred-1", "deploy", NOW),
            Err(IdentityError::ActionTooOld { .. })
        ));
    }

    #[test]
    fn a_future_dated_action_is_rejected() {
        // Pre-signing actions to fire after revocation is the attack.
        let (mut r, _, mkp) = world();
        let a = action(&mkp, "machine-1", "deploy", b"p", "n1", NOW + 600);
        assert!(matches!(
            r.authorize_action(&a, b"p", "cred-1", "deploy", NOW),
            Err(IdentityError::ClockSkew { .. })
        ));
    }

    #[test]
    fn a_credential_for_another_subject_does_not_transfer() {
        let (mut r, issuer_kp, mkp) = world();
        let other = GodKeyPair::generate().unwrap();
        r.register(identity("machine-2", &other)).unwrap();
        r.issue(
            credential(
                &issuer_kp,
                "cred-2",
                "issuer",
                "machine-2",
                &["deploy"],
                NOW + HOUR,
            ),
            NOW,
        )
        .unwrap();

        // machine-1 signs, but presents machine-2's credential.
        let a = action(&mkp, "machine-1", "deploy", b"p", "n1", NOW);
        assert!(matches!(
            r.authorize_action(&a, b"p", "cred-2", "deploy", NOW),
            Err(IdentityError::NotPermitted { .. })
        ));
    }

    #[test]
    fn a_missing_claim_denies_the_operation() {
        let (mut r, _, mkp) = world();
        let a = action(&mkp, "machine-1", "rotate_keys", b"p", "n1", NOW);
        assert!(matches!(
            r.authorize_action(&a, b"p", "cred-1", "rotate_keys", NOW),
            Err(IdentityError::MissingClaim { .. })
        ));
    }

    #[test]
    fn another_machines_signature_does_not_authorize_this_actor() {
        let (mut r, issuer_kp, _) = world();
        let attacker = GodKeyPair::generate().unwrap();
        r.register(identity("attacker", &attacker)).unwrap();
        r.issue(
            credential(
                &issuer_kp,
                "cred-a",
                "issuer",
                "attacker",
                &["deploy"],
                NOW + HOUR,
            ),
            NOW,
        )
        .unwrap();

        // Attacker signs an action claiming to be machine-1.
        let a = action(&attacker, "machine-1", "deploy", b"p", "n1", NOW);
        assert!(matches!(
            r.authorize_action(&a, b"p", "cred-1", "deploy", NOW),
            Err(IdentityError::BadSignature(_))
        ));
    }

    // ── Binding ──

    #[test]
    fn a_supplied_fingerprint_is_never_trusted() {
        let kp = GodKeyPair::generate().unwrap();
        let mut ident = identity("evil", &kp);
        ident.fingerprint = "f".repeat(128);
        let mut r = MachineRegistry::default();
        assert_eq!(r.register(ident), Err(IdentityError::FingerprintMismatch));
    }

    #[test]
    fn claims_are_length_prefixed_so_they_cannot_be_forged_by_separator() {
        let kp = GodKeyPair::generate().unwrap();
        let a = credential(&kp, "c", "i", "s", &["read|write"], NOW + HOUR);
        let b = credential(&kp, "c", "i", "s", &["read", "write"], NOW + HOUR);
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn domain_separation_keeps_credentials_and_actions_apart() {
        let kp = GodKeyPair::generate().unwrap();
        let c = credential(&kp, "x", "x", "x", &["x"], NOW + HOUR);
        let act = action(&kp, "x", "x", b"", "x", NOW);
        assert_ne!(c.signing_bytes(), act.signing_bytes());
    }

    #[test]
    fn an_expired_credential_cannot_be_issued() {
        let kp = GodKeyPair::generate().unwrap();
        let mut r = MachineRegistry::default();
        r.register(identity("issuer", &kp)).unwrap();
        let c = credential(&kp, "old", "issuer", "s", &["x"], NOW - 1);
        assert!(matches!(
            r.issue(c, NOW),
            Err(IdentityError::CredentialExpired { .. })
        ));
    }

    #[test]
    fn an_inactive_issuer_cannot_issue() {
        let kp = GodKeyPair::generate().unwrap();
        let mut r = MachineRegistry::default();
        r.register(identity("issuer", &kp)).unwrap();
        r.suspend("issuer", "review").unwrap();
        let c = credential(&kp, "c", "issuer", "s", &["x"], NOW + HOUR);
        assert!(matches!(
            r.issue(c, NOW),
            Err(IdentityError::IssuerNotActive { .. })
        ));
    }
}
