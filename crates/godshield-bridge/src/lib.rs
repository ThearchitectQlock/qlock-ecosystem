// crates/godshield-bridge/src/lib.rs
//
// ═══════════════════════════════════════════════════════════════════════
// GODSHIELD BRIDGE SECURITY  —  spec §12
//
// WHAT THIS REPLACES
//
// The existing relayer has no chain connection. `POST /api/locks` records
// whatever JSON a caller sends, authenticated by one shared static
// RELAYER_KEY, and `NEV369Bridge.mintFromNEV369` mints against it. So a
// lock "exists" because somebody with the key said so. Anyone holding
// that key can mint wNEV with no NEV369 lock ever occurring, and the
// contract's replay guard cannot tell whether an id ever meant anything.
//
// §12 states the requirement plainly: the bridge must never rely on one
// relayer or one catastrophic signing key. This module is that.
//
// THE FIVE GATES, in the order §12 specifies
//
//   Event verification    the mint names a source block and transaction
//   Finality verification the source block is buried far enough to be
//                         irreversible on the source chain
//   Replay protection     each lock id authorizes exactly one mint, ever
//   Risk & policy         per-window and cumulative exposure limits
//   Threshold auth        m-of-n INDEPENDENT signers over identical bytes
//
// All five must pass. They are separate on purpose: a compromise that
// defeats one should still meet the next.
//
// WHAT THIS MODULE HONESTLY DOES NOT DO
//
// It does not itself observe either chain. It verifies attestations about
// observations, and it is the caller's job to feed it a real chain head
// from a source it trusts. That is a smaller trusted surface than a
// relayer that both observes and authorizes with one key, but it is not
// zero — a light client verifying NEV369 headers on Ethereum is the only
// construction that removes trust entirely, and this is not that.
//
// Say so publicly rather than describing this as trustless.
// ═══════════════════════════════════════════════════════════════════════

use godshield_core::{CanonicalMessage, GodPublicKey, GodShield, GodSignature, TripleHash};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ═══════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum BridgeError {
    #[error("lock {0} has already authorized a mint")]
    Replay(String),

    #[error(
        "source block {height} is only {confirmations} deep; {required} required for finality"
    )]
    NotFinal {
        height: u64,
        confirmations: u64,
        required: u64,
    },

    #[error(
        "threshold not met: {got} valid attestation(s) from distinct signers, {need} required"
    )]
    ThresholdNotMet { got: usize, need: usize },

    #[error("signer {0} is not in the authorized set")]
    UnknownSigner(String),

    #[error("signer {0} attested twice for the same authorization")]
    DuplicateSigner(String),

    #[error("attestation from {signer} does not verify over the authorization it claims")]
    BadAttestation { signer: String },

    #[error("mint of {amount} exceeds the remaining {remaining} in this window")]
    WindowExposureExceeded { amount: u128, remaining: u128 },

    #[error("mint of {amount} exceeds the remaining {remaining} of total bridge exposure")]
    TotalExposureExceeded { amount: u128, remaining: u128 },

    #[error("single mint of {amount} exceeds the per-transaction cap of {cap}")]
    PerMintCapExceeded { amount: u128, cap: u128 },

    #[error("circuit breaker is open: {0}")]
    CircuitOpen(String),

    #[error("amount must be greater than zero")]
    ZeroAmount,

    #[error("threshold {threshold} is unreachable with {signers} authorized signer(s)")]
    ImpossibleThreshold { threshold: usize, signers: usize },

    #[error("threshold of 1 defeats the purpose — that is the single-key model this replaces")]
    ThresholdTooLow,
}

// ═══════════════════════════════════════════════════════════════════════
// THE AUTHORIZATION
// ═══════════════════════════════════════════════════════════════════════

/// What the signers are actually attesting to.
///
/// Every field here is inside the signed bytes. A field NOT in this
/// struct is not attested — so adding a parameter to a mint without
/// adding it here produces signatures that verify while saying nothing
/// about the new parameter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MintAuthorization {
    /// Unique per lock. The replay key.
    pub lock_id: String,
    /// Destination on the minting chain.
    pub recipient: String,
    /// BASE UNITS, as a decimal string.
    ///
    /// A string rather than a number for the same reason NEV369 uses u64
    /// and the relayer keeps amounts as text: JSON numbers go through f64
    /// in many parsers, and a value that survives the round trip changed
    /// is a value the signature no longer covers.
    pub amount: String,
    pub source_chain: String,
    pub source_tx: String,
    /// Height of the block containing the lock. Finality is measured
    /// against this.
    pub source_block_height: u64,
    pub dest_chain: String,
    /// Which signer set and policy version authorized this. §7 requires
    /// every critical decision to reference the policy that produced it.
    pub policy_id: String,
}

impl MintAuthorization {
    /// Length-prefixed, domain-separated. Same construction as everywhere
    /// else in the workspace, for the same reason: naive concatenation is
    /// ambiguous, and `recipient="AB"/chain="C"` must not sign the same
    /// bytes as `recipient="A"/chain="BC"`.
    ///
    /// Bump the version rather than editing this in place. Editing it
    /// invalidates every attestation already collected, including
    /// in-flight ones a signer has produced but not yet delivered.
    pub fn signing_bytes(&self) -> Vec<u8> {
        CanonicalMessage::encode(
            "godshield.bridge.mint.v1",
            &[
                self.lock_id.as_bytes(),
                self.recipient.as_bytes(),
                self.amount.as_bytes(),
                self.source_chain.as_bytes(),
                self.source_tx.as_bytes(),
                &self.source_block_height.to_le_bytes(),
                self.dest_chain.as_bytes(),
                self.policy_id.as_bytes(),
            ],
        )
    }

    pub fn digest(&self) -> String {
        TripleHash::hash_hex(&self.signing_bytes())
    }

    pub fn amount_units(&self) -> Result<u128, BridgeError> {
        self.amount
            .parse::<u128>()
            .map_err(|_| BridgeError::ZeroAmount)
    }
}

/// One signer's attestation that it independently observed the lock.
///
/// Carries BOTH signatures, because the two chains verify different
/// things. Ethereum has no ML-DSA precompile, so the contract can only
/// check secp256k1; the Dilithium5 signature is what survives a future
/// CRQC and is the post-quantum audit trail. A signer that supplies one
/// without the other is only half-useful, so they travel together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerAttestation {
    /// TripleHash of the signer's public key. Identifies the signer.
    pub signer_fingerprint: String,
    pub public_key_hex: String,
    /// Dilithium5 over the canonical MintAuthorization bytes.
    pub signature_hex: String,
    pub observed_at: u64,

    /// secp256k1 over the EIP-712 digest, 65 bytes as r||s||v.
    /// Optional so an off-chain-only deployment still works; required
    /// before a mint can actually be submitted to Ethereum.
    #[serde(default)]
    pub eth_signature_hex: Option<String>,
    /// The signer's Ethereum address, used only to order signatures.
    /// Lying here breaks nothing: the contract recovers the real address
    /// and reverts on an unauthorized signer or a broken ordering.
    #[serde(default)]
    pub eth_address: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════
// POLICY
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgePolicy {
    pub policy_id: String,

    /// Fingerprints permitted to attest. Independence is the whole point:
    /// separate keys on separate infrastructure operated by separate
    /// people. Five keys in one process is a threshold on paper and one
    /// key in practice.
    pub authorized_signers: HashSet<String>,

    /// How many distinct signers must attest.
    pub threshold: usize,

    /// Confirmations required before a source block counts as final.
    /// On a chain with 60-second blocks and modest hashrate this should
    /// be generous — reversing shallow blocks is exactly the attack a
    /// bridge invites.
    pub finality_confirmations: u64,

    pub per_mint_cap: u128,
    pub window_cap: u128,
    pub window_seconds: u64,

    /// Total the bridge may ever have outstanding. The backstop when
    /// every other limit has been worked around.
    pub total_exposure_cap: u128,
}

impl BridgePolicy {
    pub fn validate(&self) -> Result<(), BridgeError> {
        if self.threshold < 2 {
            // A threshold of one is the single-relayer model wearing a
            // different name. Refuse it in code rather than trusting an
            // operator not to configure it.
            return Err(BridgeError::ThresholdTooLow);
        }
        if self.threshold > self.authorized_signers.len() {
            return Err(BridgeError::ImpossibleThreshold {
                threshold: self.threshold,
                signers: self.authorized_signers.len(),
            });
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CIRCUIT BREAKER  —  spec §12 "emergency circuit breakers"
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,
    /// Minting halted. Requires human action to clear — deliberately not
    /// self-healing, because a breaker that resets itself after a
    /// reconciliation failure will reset itself during an ongoing drain.
    Open {
        reason: String,
        opened_at: u64,
    },
}

// ═══════════════════════════════════════════════════════════════════════
// THE AUTHORIZER
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub struct BridgeAuthorizer {
    policy: BridgePolicy,
    processed: HashSet<String>,
    minted_total: u128,
    window_start: u64,
    minted_in_window: u128,
    circuit: CircuitState,
}

/// Result of a successful authorization, for the audit trail (§8).
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationRecord {
    pub lock_id: String,
    pub digest: String,
    pub amount: String,
    pub signers: Vec<String>,
    pub policy_id: String,
    pub authorized_at: u64,
}

impl BridgeAuthorizer {
    pub fn new(policy: BridgePolicy, now: u64) -> Result<Self, BridgeError> {
        policy.validate()?;
        Ok(Self {
            policy,
            processed: HashSet::new(),
            minted_total: 0,
            window_start: now,
            minted_in_window: 0,
            circuit: CircuitState::Closed,
        })
    }

    pub fn circuit_state(&self) -> &CircuitState {
        &self.circuit
    }

    pub fn minted_total(&self) -> u128 {
        self.minted_total
    }

    /// Trip the breaker. Called by reconciliation (§12 "continuous
    /// reconciliation") or by Sentinel (§5).
    pub fn open_circuit(&mut self, reason: impl Into<String>, now: u64) {
        let reason = reason.into();
        tracing::error!(%reason, "BRIDGE CIRCUIT OPEN — minting halted");
        self.circuit = CircuitState::Open {
            reason,
            opened_at: now,
        };
    }

    /// Clear the breaker. Requires an explicit operator act; there is no
    /// timeout that does this automatically.
    pub fn close_circuit(&mut self, operator: &str) {
        tracing::warn!(%operator, "Bridge circuit closed by operator");
        self.circuit = CircuitState::Closed;
    }

    /// Compare minted supply against what is actually locked on the source
    /// chain. A gap is unbacked supply, and the breaker trips.
    ///
    /// §12 lists continuous reconciliation as a requirement, and this is
    /// the check that gives the breaker something to trip on. Without it
    /// the breaker is a manual switch nobody knows to throw.
    pub fn reconcile(&mut self, locked_on_source: u128, now: u64) -> Result<(), BridgeError> {
        if self.minted_total > locked_on_source {
            let gap = self.minted_total - locked_on_source;
            self.open_circuit(
                format!(
                    "minted {} exceeds {} locked on source — {} unbacked",
                    self.minted_total, locked_on_source, gap
                ),
                now,
            );
            return Err(BridgeError::CircuitOpen("reconciliation gap".into()));
        }
        Ok(())
    }

    /// The five gates.
    ///
    /// Ordered cheapest-first so a hostile caller cannot make the node do
    /// expensive lattice verification by sending obvious garbage:
    /// breaker, replay, amount, finality, exposure, then signatures.
    pub fn authorize(
        &mut self,
        auth: &MintAuthorization,
        attestations: &[SignerAttestation],
        source_chain_head: u64,
        now: u64,
    ) -> Result<AuthorizationRecord, BridgeError> {
        // ── Gate 0: circuit breaker ──
        if let CircuitState::Open { reason, .. } = &self.circuit {
            return Err(BridgeError::CircuitOpen(reason.clone()));
        }

        // ── Gate 1: replay ──
        // Before signature work, because a replay is the cheapest attack
        // to mount and should be the cheapest to reject.
        if self.processed.contains(&auth.lock_id) {
            return Err(BridgeError::Replay(auth.lock_id.clone()));
        }

        let amount = auth.amount_units()?;
        if amount == 0 {
            return Err(BridgeError::ZeroAmount);
        }

        // ── Gate 2: finality ──
        // A lock in a block that can still be reorged away is not a lock.
        // Saturating: a source head behind the claimed block yields zero
        // confirmations rather than wrapping into a huge number.
        let confirmations = source_chain_head.saturating_sub(auth.source_block_height);
        if confirmations < self.policy.finality_confirmations {
            return Err(BridgeError::NotFinal {
                height: auth.source_block_height,
                confirmations,
                required: self.policy.finality_confirmations,
            });
        }

        // ── Gate 3: exposure ──
        if amount > self.policy.per_mint_cap {
            return Err(BridgeError::PerMintCapExceeded {
                amount,
                cap: self.policy.per_mint_cap,
            });
        }

        // Roll the window lazily — no keeper, no cron.
        if now.saturating_sub(self.window_start) >= self.policy.window_seconds {
            self.window_start = now;
            self.minted_in_window = 0;
        }
        let window_remaining = self.policy.window_cap.saturating_sub(self.minted_in_window);
        if amount > window_remaining {
            return Err(BridgeError::WindowExposureExceeded {
                amount,
                remaining: window_remaining,
            });
        }

        let total_remaining = self
            .policy
            .total_exposure_cap
            .saturating_sub(self.minted_total);
        if amount > total_remaining {
            return Err(BridgeError::TotalExposureExceeded {
                amount,
                remaining: total_remaining,
            });
        }

        // ── Gate 4: threshold ──
        let signers = self.verify_threshold(auth, attestations)?;

        // Every gate passed. Commit.
        self.processed.insert(auth.lock_id.clone());
        self.minted_in_window = self.minted_in_window.saturating_add(amount);
        self.minted_total = self.minted_total.saturating_add(amount);

        Ok(AuthorizationRecord {
            lock_id: auth.lock_id.clone(),
            digest: auth.digest(),
            amount: auth.amount.clone(),
            signers,
            policy_id: self.policy.policy_id.clone(),
            authorized_at: now,
        })
    }

    /// m-of-n over identical canonical bytes, from DISTINCT signers.
    ///
    /// The distinctness check is the one that matters. A threshold
    /// implementation that counts attestations rather than signers lets
    /// one compromised key submit m copies of its own signature and clear
    /// the bar alone — which is the single-key model again, with extra
    /// steps. Fingerprints are deduplicated before counting.
    fn verify_threshold(
        &self,
        auth: &MintAuthorization,
        attestations: &[SignerAttestation],
    ) -> Result<Vec<String>, BridgeError> {
        let message = auth.signing_bytes();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut valid: Vec<String> = Vec::new();

        for att in attestations {
            if !self
                .policy
                .authorized_signers
                .contains(&att.signer_fingerprint)
            {
                return Err(BridgeError::UnknownSigner(att.signer_fingerprint.clone()));
            }
            if !seen.insert(att.signer_fingerprint.as_str()) {
                return Err(BridgeError::DuplicateSigner(att.signer_fingerprint.clone()));
            }

            let Ok(pk_bytes) = hex::decode(&att.public_key_hex) else {
                return Err(BridgeError::BadAttestation {
                    signer: att.signer_fingerprint.clone(),
                });
            };

            // The fingerprint must derive from the key supplied. Without
            // this an attacker signs with their own key and writes an
            // authorized fingerprint beside it — the same substitution
            // chain.rs blocks by requiring sender == public key hex.
            if TripleHash::hash_hex(&pk_bytes) != att.signer_fingerprint {
                return Err(BridgeError::BadAttestation {
                    signer: att.signer_fingerprint.clone(),
                });
            }

            let Ok(sig_bytes) = hex::decode(&att.signature_hex) else {
                return Err(BridgeError::BadAttestation {
                    signer: att.signer_fingerprint.clone(),
                });
            };

            let public_key = GodPublicKey {
                public_key: pk_bytes,
                fingerprint: att.signer_fingerprint.clone(),
            };
            let signature = GodSignature {
                signature: sig_bytes,
                message_hash: TripleHash::hash_hex(&message),
                signer_fingerprint: att.signer_fingerprint.clone(),
                timestamp: att.observed_at,
            };

            match GodShield::verify(&public_key, &signature, &message) {
                Ok(true) => valid.push(att.signer_fingerprint.clone()),
                _ => {
                    return Err(BridgeError::BadAttestation {
                        signer: att.signer_fingerprint.clone(),
                    })
                }
            }
        }

        if valid.len() < self.policy.threshold {
            return Err(BridgeError::ThresholdNotMet {
                got: valid.len(),
                need: self.policy.threshold,
            });
        }

        valid.sort();
        Ok(valid)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use godshield_core::GodKeyPair;

    const HOUR: u64 = 3600;
    const NOW: u64 = 1_800_000_000;

    fn auth(lock: &str, amount: &str, height: u64) -> MintAuthorization {
        MintAuthorization {
            lock_id: lock.into(),
            recipient: "0xrecipient".into(),
            amount: amount.into(),
            source_chain: "nev369".into(),
            source_tx: "abc123".into(),
            source_block_height: height,
            dest_chain: "ethereum".into(),
            policy_id: "bridge-v1".into(),
        }
    }

    fn sign(kp: &GodKeyPair, a: &MintAuthorization) -> SignerAttestation {
        let fp = TripleHash::hash_hex(&kp.public_key);
        let sig = GodShield::sign(kp, &a.signing_bytes()).unwrap();
        SignerAttestation {
            signer_fingerprint: fp,
            public_key_hex: hex::encode(&kp.public_key),
            signature_hex: hex::encode(&sig.signature),
            observed_at: NOW,
            // These tests exercise the off-chain threshold only; the
            // secp256k1 half is covered in nev369-relayer::eip712.
            eth_signature_hex: None,
            eth_address: None,
        }
    }

    fn setup(threshold: usize, n: usize) -> (BridgeAuthorizer, Vec<GodKeyPair>) {
        let keys: Vec<GodKeyPair> = (0..n).map(|_| GodKeyPair::generate().unwrap()).collect();
        let policy = BridgePolicy {
            policy_id: "bridge-v1".into(),
            authorized_signers: keys
                .iter()
                .map(|k| TripleHash::hash_hex(&k.public_key))
                .collect(),
            threshold,
            finality_confirmations: 20,
            per_mint_cap: 1_000_000,
            window_cap: 5_000_000,
            window_seconds: 24 * HOUR,
            total_exposure_cap: 50_000_000,
        };
        (BridgeAuthorizer::new(policy, NOW).unwrap(), keys)
    }

    // ── The model this replaces ──

    #[test]
    fn a_threshold_of_one_is_refused() {
        // That is the single-relayer design under another name.
        let kp = GodKeyPair::generate().unwrap();
        let policy = BridgePolicy {
            policy_id: "bad".into(),
            authorized_signers: [TripleHash::hash_hex(&kp.public_key)].into(),
            threshold: 1,
            finality_confirmations: 20,
            per_mint_cap: 1,
            window_cap: 1,
            window_seconds: HOUR,
            total_exposure_cap: 1,
        };
        assert_eq!(
            BridgeAuthorizer::new(policy, NOW).unwrap_err(),
            BridgeError::ThresholdTooLow
        );
    }

    #[test]
    fn one_compromised_key_cannot_reach_threshold_by_signing_twice() {
        // The classic threshold bug: counting attestations, not signers.
        let (mut b, keys) = setup(3, 5);
        let a = auth("lock-1", "1000", 100);
        let att = sign(&keys[0], &a);

        let err = b
            .authorize(&a, &[att.clone(), att.clone(), att], 200, NOW)
            .unwrap_err();
        assert_eq!(err, BridgeError::DuplicateSigner(att_fp(&keys[0])));
    }

    fn att_fp(kp: &GodKeyPair) -> String {
        TripleHash::hash_hex(&kp.public_key)
    }

    #[test]
    fn three_distinct_signers_authorize() {
        let (mut b, keys) = setup(3, 5);
        let a = auth("lock-1", "1000", 100);
        let atts: Vec<_> = keys[..3].iter().map(|k| sign(k, &a)).collect();

        let rec = b.authorize(&a, &atts, 200, NOW).unwrap();
        assert_eq!(rec.signers.len(), 3);
        assert_eq!(b.minted_total(), 1000);
    }

    #[test]
    fn two_signers_do_not_meet_a_threshold_of_three() {
        let (mut b, keys) = setup(3, 5);
        let a = auth("lock-1", "1000", 100);
        let atts: Vec<_> = keys[..2].iter().map(|k| sign(k, &a)).collect();
        assert_eq!(
            b.authorize(&a, &atts, 200, NOW).unwrap_err(),
            BridgeError::ThresholdNotMet { got: 2, need: 3 }
        );
    }

    #[test]
    fn an_outside_key_is_rejected_even_with_a_valid_signature() {
        let (mut b, keys) = setup(2, 3);
        let outsider = GodKeyPair::generate().unwrap();
        let a = auth("lock-1", "1000", 100);
        let atts = vec![sign(&keys[0], &a), sign(&outsider, &a)];
        assert!(matches!(
            b.authorize(&a, &atts, 200, NOW),
            Err(BridgeError::UnknownSigner(_))
        ));
    }

    #[test]
    fn a_signer_cannot_borrow_an_authorized_fingerprint() {
        // Attacker signs with their own key, writes an authorized
        // fingerprint beside it.
        let (mut b, keys) = setup(2, 3);
        let attacker = GodKeyPair::generate().unwrap();
        let a = auth("lock-1", "1000", 100);

        let mut forged = sign(&attacker, &a);
        forged.signer_fingerprint = att_fp(&keys[1]);

        let atts = vec![sign(&keys[0], &a), forged];
        assert!(matches!(
            b.authorize(&a, &atts, 200, NOW),
            Err(BridgeError::BadAttestation { .. })
        ));
    }

    #[test]
    fn attestations_over_a_different_authorization_do_not_transfer() {
        // Signers approved a 1000 mint; someone submits them against a
        // 999999 mint.
        let (mut b, keys) = setup(2, 3);
        let approved = auth("lock-1", "1000", 100);
        let atts: Vec<_> = keys[..2].iter().map(|k| sign(k, &approved)).collect();

        let mut swapped = approved.clone();
        swapped.amount = "999999".into();
        assert!(matches!(
            b.authorize(&swapped, &atts, 200, NOW),
            Err(BridgeError::BadAttestation { .. })
        ));
    }

    #[test]
    fn changing_the_recipient_invalidates_the_attestations() {
        let (mut b, keys) = setup(2, 3);
        let approved = auth("lock-1", "1000", 100);
        let atts: Vec<_> = keys[..2].iter().map(|k| sign(k, &approved)).collect();

        let mut redirected = approved.clone();
        redirected.recipient = "0xattacker".into();
        assert!(matches!(
            b.authorize(&redirected, &atts, 200, NOW),
            Err(BridgeError::BadAttestation { .. })
        ));
    }

    // ── Replay ──

    #[test]
    fn the_same_lock_cannot_mint_twice() {
        let (mut b, keys) = setup(2, 3);
        let a = auth("lock-1", "1000", 100);
        let atts: Vec<_> = keys[..2].iter().map(|k| sign(k, &a)).collect();

        b.authorize(&a, &atts, 200, NOW).unwrap();
        assert_eq!(
            b.authorize(&a, &atts, 200, NOW).unwrap_err(),
            BridgeError::Replay("lock-1".into())
        );
        assert_eq!(b.minted_total(), 1000, "a replay must not add supply");
    }

    // ── Finality ──

    #[test]
    fn a_shallow_source_block_is_not_final() {
        let (mut b, keys) = setup(2, 3);
        let a = auth("lock-1", "1000", 195);
        let atts: Vec<_> = keys[..2].iter().map(|k| sign(k, &a)).collect();
        assert_eq!(
            b.authorize(&a, &atts, 200, NOW).unwrap_err(),
            BridgeError::NotFinal {
                height: 195,
                confirmations: 5,
                required: 20
            }
        );
    }

    #[test]
    fn a_source_head_behind_the_block_yields_zero_confirmations() {
        // Saturating, so a stale or lying head cannot wrap into a huge
        // confirmation count.
        let (mut b, keys) = setup(2, 3);
        let a = auth("lock-1", "1000", 500);
        let atts: Vec<_> = keys[..2].iter().map(|k| sign(k, &a)).collect();
        assert!(matches!(
            b.authorize(&a, &atts, 100, NOW),
            Err(BridgeError::NotFinal {
                confirmations: 0,
                ..
            })
        ));
    }

    // ── Exposure ──

    #[test]
    fn a_single_oversized_mint_is_capped() {
        let (mut b, keys) = setup(2, 3);
        let a = auth("lock-1", "2000000", 100);
        let atts: Vec<_> = keys[..2].iter().map(|k| sign(k, &a)).collect();
        assert!(matches!(
            b.authorize(&a, &atts, 200, NOW),
            Err(BridgeError::PerMintCapExceeded { .. })
        ));
    }

    #[test]
    fn the_window_cap_bounds_a_compromised_signer_set() {
        // Even with the threshold met legitimately, a day's damage is
        // bounded. This is the difference between losing a window and
        // losing everything.
        let (mut b, keys) = setup(2, 3);
        for i in 0..5 {
            let a = auth(&format!("lock-{i}"), "1000000", 100);
            let atts: Vec<_> = keys[..2].iter().map(|k| sign(k, &a)).collect();
            b.authorize(&a, &atts, 200, NOW).unwrap();
        }
        let a = auth("lock-over", "1", 100);
        let atts: Vec<_> = keys[..2].iter().map(|k| sign(k, &a)).collect();
        assert!(matches!(
            b.authorize(&a, &atts, 200, NOW),
            Err(BridgeError::WindowExposureExceeded { .. })
        ));
    }

    #[test]
    fn the_window_rolls_after_its_period() {
        let (mut b, keys) = setup(2, 3);
        for i in 0..5 {
            let a = auth(&format!("lock-{i}"), "1000000", 100);
            let atts: Vec<_> = keys[..2].iter().map(|k| sign(k, &a)).collect();
            b.authorize(&a, &atts, 200, NOW).unwrap();
        }
        let later = NOW + 24 * HOUR + 1;
        let a = auth("lock-next-day", "1000", 100);
        let atts: Vec<_> = keys[..2].iter().map(|k| sign(k, &a)).collect();
        assert!(b.authorize(&a, &atts, 200, later).is_ok());
    }

    // ── Circuit breaker ──

    #[test]
    fn reconciliation_gap_opens_the_circuit() {
        let (mut b, keys) = setup(2, 3);
        let a = auth("lock-1", "1000", 100);
        let atts: Vec<_> = keys[..2].iter().map(|k| sign(k, &a)).collect();
        b.authorize(&a, &atts, 200, NOW).unwrap();

        // Source reports less locked than we have minted — unbacked supply.
        assert!(b.reconcile(400, NOW).is_err());
        assert!(matches!(b.circuit_state(), CircuitState::Open { .. }));

        let a2 = auth("lock-2", "1000", 100);
        let atts2: Vec<_> = keys[..2].iter().map(|k| sign(k, &a2)).collect();
        assert!(matches!(
            b.authorize(&a2, &atts2, 200, NOW),
            Err(BridgeError::CircuitOpen(_))
        ));
    }

    #[test]
    fn matching_reconciliation_leaves_the_circuit_closed() {
        let (mut b, keys) = setup(2, 3);
        let a = auth("lock-1", "1000", 100);
        let atts: Vec<_> = keys[..2].iter().map(|k| sign(k, &a)).collect();
        b.authorize(&a, &atts, 200, NOW).unwrap();
        assert!(b.reconcile(1000, NOW).is_ok());
        assert_eq!(b.circuit_state(), &CircuitState::Closed);
    }

    #[test]
    fn the_circuit_does_not_reset_itself() {
        // A breaker that clears on a timer clears during an active drain.
        let (mut b, _) = setup(2, 3);
        b.open_circuit("test", NOW);
        assert!(matches!(b.circuit_state(), CircuitState::Open { .. }));
        b.close_circuit("operator-alice");
        assert_eq!(b.circuit_state(), &CircuitState::Closed);
    }

    // ── Policy ──

    #[test]
    fn a_threshold_above_the_signer_count_is_refused() {
        let kp = GodKeyPair::generate().unwrap();
        let policy = BridgePolicy {
            policy_id: "bad".into(),
            authorized_signers: [TripleHash::hash_hex(&kp.public_key)].into(),
            threshold: 3,
            finality_confirmations: 20,
            per_mint_cap: 1,
            window_cap: 1,
            window_seconds: HOUR,
            total_exposure_cap: 1,
        };
        assert_eq!(
            BridgeAuthorizer::new(policy, NOW).unwrap_err(),
            BridgeError::ImpossibleThreshold {
                threshold: 3,
                signers: 1
            }
        );
    }

    #[test]
    fn canonical_encoding_prevents_field_boundary_collision() {
        let mut a = auth("lock", "1000", 100);
        a.recipient = "AB".into();
        a.source_chain = "C".into();
        let mut b = auth("lock", "1000", 100);
        b.recipient = "A".into();
        b.source_chain = "BC".into();
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn amount_is_a_string_so_it_survives_json_intact() {
        // 2^53 + 1 — a value f64 cannot represent, which any parser
        // routing numbers through f64 would silently change.
        let a = auth("lock", "9007199254740993", 100);
        assert_eq!(a.amount_units().unwrap(), 9_007_199_254_740_993);
    }
}
