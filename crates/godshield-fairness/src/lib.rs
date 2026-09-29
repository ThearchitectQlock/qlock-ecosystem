// crates/godshield- fairness/src/lib.rs
//
// ════════════════════════ ════════════════════════ ═══════════════════════
// GodShield Fairness — commit-reveal RNG with signed outcomes
//
// FIXES vs. the original:
//
// 1. MODULO BIAS (real, and a certification blocker). The original did
//    `rng.next_u64() % outcome_space` and the comment claimed using a
//    CSPRNG "avoids modulo bias". It does not. A CSPRNG gives uniform
//    64-bit values; taking them mod N is still biased whenever N does not
//    divide 2^64 evenly. Low outcomes become marginally more likely.
//
//    For roulette (N=37) the bias is ~2^-59 — undetectable in practice.
//    But a gaming regulator's RNG certification tests for exactly this
//    construction, and "the bias is small" is not an answer that passes.
//    Now uses rejection sampling, which is provably unbiased.
//
// 2. CANONICAL ENCODING. The signed payload was a bare format!() of
//    concatenated fields, so client_seed="abc1"/nonce=23 signed the same
//    bytes as client_seed="abc"/nonce=123. Now uses CanonicalMessage.
//
// 3. UNREVEALED ROUNDS. The original had no answer for an operator who
//    commits and then never reveals — which is the obvious way to cheat
//    (see an unfavourable result coming, go silent). Added an explicit
//    reveal deadline and a verifiable "operator failed to reveal" state.
// ════════════════════════ ════════════════════════ ═══════════════════════

use godshield_core::{
    CanonicalMessage, GodKeyPair, GodPublicKey, GodShield, GodSignature, TripleHash,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

/// Domain tags — prevent a signature over a Fairness round being replayed
/// as an NEV369 transaction or a Q-Lock attestation, and vice versa.
// FIXED: this read "godshield.fairness.reveal.v 1" — a space inside the
// domain separation tag, introduced when this file was reconstructed
// from its PDF render.
//
// It would still have SEPARATED domains correctly, because any
// consistent string does that. The damage is subtler: the tag no longer
// matched the documented registry, and it reads like a typo someone
// would tidy up later — at which point every reveal signature ever
// produced under it stops verifying. Fixed now, while no signature
// exists under either spelling, which is the only moment it is free.
const DOMAIN_REVEAL: &str = "godshield.fairness.reveal.v1";

/// Default window an operator has to reveal after committing. Past this,
/// the round is provably abandoned and should be voided in the player's
/// favour by the operator's own published dispute policy.
pub const DEFAULT_REVEAL_DEADLINE_SECS: u64 = 300;
// ════════════════════════ ════════════════════════ ═══════════════════════
// ERRORS
// ════════════════════════ ════════════════════════ ═══════════════════════

#[derive(Debug)]
pub enum FairnessError {
    CommitmentMismatch,
    OutcomeMismatch,
    InvalidSignature,
    RevealDeadlineMissed { deadline: u64, revealed_at: u64 },
    InvalidOutcomeSpace,
    Crypto(String),
}
impl fmt::Display for FairnessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::CommitmentMismatch => write!(
                f,
                "Revealed seed does not match the published commitment — the \
                   operator changed the seed after committing"
            ),

            Self::OutcomeMismatch => write!(
                f,
                "Replaying the derivation produced a different outcome than the \
                   one published — the reported result was tampered with"
            ),

            Self::InvalidSignature => write!(f, "Outcome signature is invalid"),

            Self::RevealDeadlineMissed {
                deadline,
                revealed_at,
            } => write!(
                f,
                "Reveal came {}s after the deadline ({} vs {}). A late reveal \
                   is indistinguishable from a withheld one — treat this round as void.",
                revealed_at.saturating_sub(*deadline),
                revealed_at,
                deadline
            ),

            Self::InvalidOutcomeSpace => {
                write!(f, "Outcome space must be greater than zero")
            }
            Self::Crypto(m) => write!(f, "Cryptographic error: {m}"),
        }
    }
}

impl Error for FairnessError {}
// ════════════════════════ ════════════════════════ ═══════════════════════
// UNBIASED OUTCOME DERIVATION
// ════════════════════════ ════════════════════════ ═══════════════════════

/// Deterministically derive a round outcome in `[0, outcome_space)`.
///
/// TripleHash(server_seed     ‖ client_seed   ‖ nonce) seeds ChaCha20, which is
/// then sampled with **rejection sampling** to eliminate modulo bias.
///
/// Why rejection sampling rather than `% outcome_space`:
///
///   2^64 is not divisible by most outcome spaces. Taking a uniform 64-bit
///   value mod N makes the first (2^64 mod N) outcomes very slightly more
///   likely than the rest. The effect is tiny — but it is a real, measurable,
///   directional bias, and RNG certification suites test for precisely this.
///
///   Rejection sampling discards values landing in the final partial block,
///   leaving a range that IS an exact multiple of N. The result is provably
///    uniform, with an expected iteration count below 2 for any realistic N.
///
/// Determinism is preserved: identical inputs always produce identical
/// output, including identical rejection sequences. That is what makes the
/// result independently verifiable after the fact.
pub fn derive_outcome(
    server_seed: &[u8],
    client_seed: &str,
    nonce: u64,
    outcome_space: u64,
) -> Result<u64, FairnessError> {
    if outcome_space == 0 {
        return Err(FairnessError::InvalidOutcomeSpace);
    }
    if outcome_space == 1 {
        return Ok(0);
    }

    let preimage = CanonicalMessage::encode(
        "godshield.fairness.outcome.v1",
        &[server_seed, client_seed.as_bytes(), &nonce.to_le_bytes()],
    );
    let hash = TripleHash::hash(&preimage);

    let mut seed_bytes = [0u8; 32];

    seed_bytes.copy_from_slice(&hash[..32]);
    let mut rng = ChaCha20Rng::from_seed(seed_bytes);

    // Largest multiple of outcome_space that fits in u64. Values at or above
    // this are rejected, so the accepted range divides evenly.
    let limit = u64::MAX - (u64::MAX % outcome_space);

    loop {
        let value = rng.next_u64();
        if value < limit {
            return Ok(value % outcome_space);
        }
        // Rejected — draw again. Expected iterations < 2 for any N that
        // isn't pathologically close to u64::MAX.
    }
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// COMMIT PHASE
// ════════════════════════ ════════════════════════ ═══════════════════════

/// Published to the player BEFORE they act. The hash proves the operator
/// fixed the server seed in advance — they cannot change it after seeing
/// the client seed or the bet, because any change breaks this hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedCommitment {
    pub round_id: String,
    pub commitment_hash: String,
    pub committed_at: u64,
    /// The operator must reveal by this time. Published up front so the
    /// player knows exactly when silence becomes provable misconduct.
    pub reveal_deadline: u64,
}

pub struct PendingRound {
    pub round_id: String,
    server_seed: [u8; 32],
    pub commitment: SeedCommitment,
}

impl PendingRound {
    pub fn new(round_id: impl Into<String>) -> Self {
        Self::with_deadline(round_id, DEFAULT_REVEAL_DEADLINE_SECS)
    }

    pub fn with_deadline(round_id: impl Into<String>, deadline_secs: u64) -> Self {
        let round_id = round_id.into();
        let mut server_seed = [0u8; 32];

        rand::thread_rng().fill_bytes(&mut server_seed);

        let committed_at = now();
        let commitment = SeedCommitment {
            round_id: round_id.clone(),
            commitment_hash: TripleHash::hash_hex(&server_seed),
            committed_at,
            reveal_deadline: committed_at + deadline_secs,
        };

        Self {
            round_id,
            server_seed,
            commitment,
        }
    }

    /// Reveal the seed, derive the outcome, and sign the whole record.
    pub fn reveal(
        self,
        keypair: &GodKeyPair,
        client_seed: &str,
        nonce: u64,
        outcome_space: u64,
    ) -> Result<RevealedRound, FairnessError> {
        let outcome = derive_outcome(&self.server_seed, client_seed, nonce, outcome_space)?;
        let revealed_at = now();
        let server_seed_hex = hex::encode(self.server_seed);

        let payload = reveal_payload(
            &self.round_id,
            &server_seed_hex,
            client_seed,
            nonce,
            outcome,
            outcome_space,
            revealed_at,
        );

        let signature =
            GodShield::sign(keypair, &payload).map_err(|e| FairnessError::Crypto(e.to_string()))?;

        Ok(RevealedRound {
            round_id: self.round_id,
            commitment: self.commitment,
            server_seed_hex,
            client_seed: client_seed.to_string(),
            nonce,
            outcome,
            outcome_space,
            revealed_at,
            signature,
        })
    }
}
/// Canonical signed payload. Length-prefixed and domain-separated so no two
/// distinct rounds can produce identical signed bytes.
#[allow(clippy::too_many_arguments)]
fn reveal_payload(
    round_id: &str,
    server_seed_hex: &str,
    client_seed: &str,
    nonce: u64,
    outcome: u64,
    outcome_space: u64,
    revealed_at: u64,
) -> Vec<u8> {
    CanonicalMessage::encode(
        DOMAIN_REVEAL,
        &[
            round_id.as_bytes(),
            server_seed_hex.as_bytes(),
            client_seed.as_bytes(),
            &nonce.to_le_bytes(),
            &outcome.to_le_bytes(),
            &outcome_space.to_le_bytes(),
            &revealed_at.to_le_bytes(),
        ],
    )
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// REVEALED ROUND
// ════════════════════════ ════════════════════════ ═══════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealedRound {
    pub round_id: String,
    pub commitment: SeedCommitment,
    pub server_seed_hex: String,
    pub client_seed: String,
    pub nonce: u64,
    pub outcome: u64,
    pub outcome_space: u64,
    pub revealed_at: u64,
    pub signature: GodSignature,
}

impl RevealedRound {
    /// Full independent verification. Requires no trust in the operator:
    /// recomputes everything from public inputs and checks it against what
    /// was published.
    ///
    /// This is the function a player, auditor, or regulator runs.
    pub fn verify(&self, public_key: &GodPublicKey) -> Result<(), FairnessError> {
        // 1. Did the operator reveal the seed they actually committed to?
        //     This is the core anti-cheat property — the commitment was
        //     published before the player acted.
        let seed_bytes =
            hex::decode(&self.server_seed_hex).map_err(|_| FairnessError::CommitmentMismatch)?;
        if TripleHash::hash_hex(&seed_bytes) != self.commitment.commitment_hash {
            return Err(FairnessError::CommitmentMismatch);
        }
        // 2. Did they reveal on time? A late reveal is indistinguishable
        //      from a withheld one — an operator who waits to see whether the
        //      result suits them has already cheated, even if they eventually
        //      publish the honest seed.
        if self.revealed_at > self.commitment.reveal_deadline {
            return Err(FairnessError::RevealDeadlineMissed {
                deadline: self.commitment.reveal_deadline,
                revealed_at: self.revealed_at,
            });
        }

        // 3. Does replaying the derivation reproduce the published outcome?
        let recomputed = derive_outcome(
            &seed_bytes,
            &self.client_seed,
            self.nonce,
            self.outcome_space,
        )?;
        if recomputed != self.outcome {
            return Err(FairnessError::OutcomeMismatch);
        }

        // 4. Did the operator's key actually attest to this exact record?
        let payload = reveal_payload(
            &self.round_id,
            &self.server_seed_hex,
            &self.client_seed,
            self.nonce,
            self.outcome,
            self.outcome_space,
            self.revealed_at,
        );
        let valid = GodShield::verify(public_key, &self.signature, &payload)
            .map_err(|_| FairnessError::InvalidSignature)?;
        if !valid {
            return Err(FairnessError::InvalidSignature);
        }

        Ok(())
    }
}

/// A round that was committed to but never revealed.
///
/// This is the cheat the commit-reveal scheme cannot prevent cryptographically:
/// an operator who sees an unfavourable result coming can simply go silent.
/// What it CAN do is make the silence provable — the commitment was published
/// with a deadline, and the deadline passed with nothing.
///
/// Handling it is a policy decision, not a cryptographic one. Any operator
/// serious about certification needs a published rule (typically: void the
/// round and return the stake) and this struct is the evidence a player
/// presents to invoke it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbandonedRound {
    pub commitment: SeedCommitment,
    pub observed_at: u64,
}

impl AbandonedRound {
    pub fn from_commitment(commitment: SeedCommitment) -> Option<Self> {
        let observed_at = now();
        if observed_at > commitment.reveal_deadline {
            Some(Self {
                commitment,
                observed_at,
            })
        } else {
            None
        }
    }

    pub fn seconds_overdue(&self) -> u64 {
        self.observed_at
            .saturating_sub(self.commitment.reveal_deadline)
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// TESTS
// ════════════════════════ ════════════════════════ ═══════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_round_lifecycle_verifies() {
        let kp = GodKeyPair::generate().unwrap();
        let round = PendingRound::new("round-001");
        let before = round.commitment.clone();
        let revealed = round.reveal(&kp, "player-seed", 0, 37).unwrap();

        assert_eq!(before.commitment_hash, revealed.commitment.commitment_hash);
        assert!(revealed.verify(&kp.export_public()).is_ok());
    }

    #[test]
    fn tampered_outcome_fails() {
        let kp = GodKeyPair::generate().unwrap();
        let mut revealed = PendingRound::new("r2").reveal(&kp, "seed", 0, 37).unwrap();
        revealed.outcome = (revealed.outcome + 1) % revealed.outcome_space;
        assert!(revealed.verify(&kp.export_public()).is_err());
    }

    #[test]
    fn substituted_seed_fails_commitment_check() {
        let kp = GodKeyPair::generate().unwrap();
        let mut revealed = PendingRound::new("r3").reveal(&kp, "seed", 0, 37).unwrap();

        revealed.server_seed_hex = hex::encode([0xAAu8; 32]);
        assert!(matches!(
            revealed.verify(&kp.export_public()),
            Err(FairnessError::CommitmentMismatch)
        ));
    }

    #[test]
    fn late_reveal_is_rejected() {
        let kp = GodKeyPair::generate().unwrap();
        let mut revealed = PendingRound::new("r4").reveal(&kp, "seed", 0, 37).unwrap();

        revealed.commitment.reveal_deadline = revealed.revealed_at.saturating_sub(1);
        assert!(matches!(
            revealed.verify(&kp.export_public()),
            Err(FairnessError::RevealDeadlineMissed { .. })
        ));
    }

    #[test]
    fn derivation_is_deterministic() {
        let seed = [7u8; 32];
        let a = derive_outcome(&seed, "client", 0, 1000).unwrap();
        let b = derive_outcome(&seed, "client", 0, 1000).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn outcomes_stay_within_range() {
        let seed = [3u8; 32];
        for n in 0..500u64 {
            let o = derive_outcome(&seed, "c", n, 37).unwrap();
            assert!(o < 37, "outcome {o} out of range for 37-slot wheel");
        }
    }
    /// REGRESSION TEST for the modulo-bias fix.
    ///
    /// Not a formal statistical proof — that belongs in a certification
    /// lab's test suite. This is a sanity check that the distribution over a
    /// small outcome space is broadly flat, which the biased version would
    /// still pass at this sample size. Its real value is documenting the
    /// intent so nobody reverts to `% outcome_space` later.
    #[test]
    fn distribution_is_broadly_uniform() {
        const SPACE: u64 = 37;
        const SAMPLES: u64 = 37_000;
        let mut counts = vec![0u32; SPACE as usize];

        for n in 0..SAMPLES {
            let seed = TripleHash::hash(&n.to_le_bytes());
            let o = derive_outcome(&seed[..32], "client", n, SPACE).unwrap();
            counts[o as usize] += 1;
        }

        let expected = (SAMPLES / SPACE) as f64;
        for (slot, &count) in counts.iter().enumerate() {
            let deviation = (count as f64 - expected).abs() / expected;
            assert!(
                deviation < 0.30,
                "slot {} deviated {:.1}% from expected ({} vs {:.0})",
                slot,
                deviation * 100.0,
                count,
                expected
            );
        }
    }

    #[test]
    fn zero_outcome_space_is_rejected() {
        assert!(matches!(
            derive_outcome(&[0u8; 32], "c", 0, 0),
            Err(FairnessError::InvalidOutcomeSpace)
        ));
    }

    #[test]
    fn single_outcome_space_always_returns_zero() {
        assert_eq!(derive_outcome(&[1u8; 32], "c", 0, 1).unwrap(), 0);
    }

    /// REGRESSION TEST for canonical encoding.
    ///
    /// Without length prefixes, client_seed="abc1"/nonce=23 and
    /// client_seed="abc"/nonce=123 produced identical signed bytes.
    #[test]
    fn field_boundaries_cannot_collide() {
        let a = reveal_payload("r", "seed", "abc1", 23, 5, 37, 100);
        let b = reveal_payload("r", "seed", "abc", 123, 5, 37, 100);
        assert_ne!(a, b);
    }
    #[test]
    fn abandoned_round_detected_only_after_deadline() {
        let live = PendingRound::with_deadline("r5", 600);
        assert!(
            AbandonedRound::from_commitment(live.commitment.clone()).is_none(),
            "a round inside its window is not abandoned"
        );

        let mut expired = live.commitment;

        expired.reveal_deadline = now().saturating_sub(10);
        let abandoned = AbandonedRound::from_commitment(expired).unwrap();
        assert!(abandoned.seconds_overdue() >= 10);
    }

    #[test]
    fn signature_from_another_operator_fails() {
        let kp = GodKeyPair::generate().unwrap();
        let other = GodKeyPair::generate().unwrap();
        let revealed = PendingRound::new("r6").reveal(&kp, "seed", 0, 37).unwrap();
        assert!(revealed.verify(&other.export_public()).is_err());
    }
}
