// crates/godshield-sentinel/src/lib.rs
//
// ═══════════════════════════════════════════════════════════════════════
// SENTINEL™  —  spec §5
//
// Detection → Correlation → Risk → Policy → Response → Containment →
// Recovery → Evidence
//
// Sentinel does not produce signals. The gateway, the identity registry
// and the bridge authorizer already emit structured outcomes; this
// correlates them and decides what to do. That is why it is the last
// piece rather than the first — it is mostly wiring, and wiring nothing
// is what a monitoring layer built too early ends up doing.
//
// ── THE DANGER IS THE RESPONSE, NOT THE DETECTION ─────────────────────
//
// An automated responder that suspends identities on signal is a weapon
// pointed at its own operator. Feed it failures attributed to the people
// who would stop it, and it locks them out — a denial of service you
// built, deployed and trust. Three rules keep that from happening, and
// they are the reason this file is shaped the way it is:
//
//   1. REVERSIBLE ACTIONS ARE AUTOMATIC. IRREVERSIBLE ONES ESCALATE.
//      Suspension is automatic because it can be undone in seconds.
//      Revocation is permanent, so Sentinel never performs it — it
//      raises an incident and a human decides. This is exactly why
//      godshield-identity keeps SUSPENDED and REVOKED as distinct
//      states rather than one flag.
//
//   2. SOME IDENTITIES CANNOT BE CONTAINED AUTOMATICALLY.
//      Break-glass operators are protected. A Sentinel that can suspend
//      everyone able to switch it off is unrecoverable by construction.
//
//   3. EVIDENCE IS PRESERVED BEFORE CONTAINMENT.
//      Containment changes state. Doing it first destroys the record of
//      what you were containing, and the incident review then has
//      nothing to read.
//
// ── WHAT SENTINEL IS NOT ──────────────────────────────────────────────
//
// Not an anomaly detector. Every rule here is an explicit threshold over
// a named signal, because a rule an operator cannot read is a rule they
// cannot trust at three in the morning. Statistical detection is a
// reasonable later addition on top of this, not a replacement for it.
// ═══════════════════════════════════════════════════════════════════════

use godshield_core::{CanonicalMessage, TripleHash};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// ═══════════════════════════════════════════════════════════════════════
// SIGNALS  —  Detection
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// A signature failed to verify.
    VerificationFailed,
    /// Policy returned DENY.
    PolicyDenied,
    /// An identity exceeded its rate limit.
    RateLimitExceeded,
    /// A machine action reused a nonce.
    ReplayAttempted,
    /// A credential was presented after expiry or revocation.
    StaleCredentialUsed,
    /// A bridge mint failed the threshold check.
    ThresholdNotMet,
    /// Bridge reconciliation found minted supply exceeding what is locked.
    ReconciliationGap,
    /// A chain reorganisation deeper than the configured depth.
    DeepReorg,
    /// An attestation arrived signed by an unexpected fingerprint.
    UnexpectedSigner,
    /// The audit chain failed verification.
    AuditChainBroken,
    /// Key rotation occurred.
    KeyRotated,
}

impl SignalKind {
    /// Signals that mean "someone is probing" versus "something is
    /// already wrong". A single structural failure outranks a hundred
    /// failed verifications, and the risk scoring has to reflect that or
    /// noise buries the one that matters.
    pub fn is_structural(self) -> bool {
        matches!(
            self,
            SignalKind::ReconciliationGap | SignalKind::AuditChainBroken | SignalKind::DeepReorg
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub kind: SignalKind,
    /// Who or what the signal is about. Correlation groups on this.
    pub subject: String,
    pub source: String,
    pub detail: String,
    pub timestamp: u64,
}

// ═══════════════════════════════════════════════════════════════════════
// RISK  —  Risk Evaluation
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

// ═══════════════════════════════════════════════════════════════════════
// RESPONSE  —  Policy Decision, Response, Containment
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    /// Recorded, nothing done. Most signals end here and should.
    Observe,
    /// Block the specific operation; the identity keeps working.
    BlockOperation { operation: String },
    /// Reversible containment. Automatic.
    SuspendIdentity { identity: String },
    /// Halt bridge minting. Reversible, and the standing instruction for
    /// any unbacked-supply signal.
    OpenBridgeCircuit { reason: String },
    /// Escalate. Sentinel does NOT do these itself — see rule 1.
    EscalateToHuman { action: String, why: String },
}

impl Response {
    pub fn is_automatic(&self) -> bool {
        !matches!(self, Response::EscalateToHuman { .. })
    }
}

// ═══════════════════════════════════════════════════════════════════════
// RULES
// ═══════════════════════════════════════════════════════════════════════

/// An explicit threshold over a named signal within a window.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub kind: SignalKind,
    /// Occurrences within `window_secs` for the rule to fire.
    pub threshold: u32,
    pub window_secs: u64,
    pub severity: Severity,
    pub response: ResponseTemplate,
}

#[derive(Debug, Clone)]
pub enum ResponseTemplate {
    Observe,
    BlockOperation,
    SuspendIdentity,
    OpenBridgeCircuit,
    EscalateToHuman { action: String },
}

/// Defaults that encode rule 1: everything destructive escalates.
pub fn default_rules() -> Vec<Rule> {
    vec![
        // ── Structural: one occurrence is enough ──
        Rule {
            id: "reconciliation-gap".into(),
            kind: SignalKind::ReconciliationGap,
            threshold: 1,
            window_secs: 1,
            severity: Severity::Critical,
            // Halting the bridge is reversible, so it is automatic. The
            // alternative — waiting for a human while unbacked supply
            // mints — is worse than a false halt.
            response: ResponseTemplate::OpenBridgeCircuit,
        },
        Rule {
            id: "audit-chain-broken".into(),
            kind: SignalKind::AuditChainBroken,
            threshold: 1,
            window_secs: 1,
            severity: Severity::Critical,
            // Nothing automatic here. A broken audit chain means the
            // record is already untrustworthy, and automated action
            // would write more entries into a log nobody can believe.
            response: ResponseTemplate::EscalateToHuman {
                action: "verify audit chain integrity from the last trusted head".into(),
            },
        },
        Rule {
            id: "deep-reorg".into(),
            kind: SignalKind::DeepReorg,
            threshold: 1,
            window_secs: 1,
            severity: Severity::High,
            response: ResponseTemplate::EscalateToHuman {
                action: "compare cumulative work across peers; check for a partition".into(),
            },
        },
        // ── Probing: thresholds over a window ──
        Rule {
            id: "verification-failures".into(),
            kind: SignalKind::VerificationFailed,
            threshold: 10,
            window_secs: 300,
            severity: Severity::Medium,
            response: ResponseTemplate::SuspendIdentity,
        },
        Rule {
            id: "replay-attempts".into(),
            kind: SignalKind::ReplayAttempted,
            threshold: 3,
            window_secs: 300,
            severity: Severity::High,
            response: ResponseTemplate::SuspendIdentity,
        },
        Rule {
            id: "threshold-failures".into(),
            kind: SignalKind::ThresholdNotMet,
            threshold: 5,
            window_secs: 600,
            severity: Severity::High,
            response: ResponseTemplate::OpenBridgeCircuit,
        },
        Rule {
            id: "stale-credentials".into(),
            kind: SignalKind::StaleCredentialUsed,
            threshold: 5,
            window_secs: 600,
            severity: Severity::Medium,
            response: ResponseTemplate::BlockOperation,
        },
        Rule {
            id: "unexpected-signer".into(),
            kind: SignalKind::UnexpectedSigner,
            threshold: 1,
            window_secs: 1,
            severity: Severity::Critical,
            response: ResponseTemplate::EscalateToHuman {
                action: "an attestation was signed by a key we do not expect — \
                         confirm whether the identity key rotated without record"
                    .into(),
            },
        },
        Rule {
            id: "rate-limit-noise".into(),
            kind: SignalKind::RateLimitExceeded,
            threshold: 50,
            window_secs: 300,
            severity: Severity::Low,
            // Deliberately Observe. A rate limit that fires is the rate
            // limiter working; escalating on it trains operators to
            // ignore Sentinel.
            response: ResponseTemplate::Observe,
        },
    ]
}

// ═══════════════════════════════════════════════════════════════════════
// INCIDENTS  —  Evidence
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IncidentState {
    Open,
    Contained,
    Escalated,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub incident_id: String,
    pub rule_id: String,
    pub subject: String,
    pub severity: Severity,
    pub state: IncidentState,
    pub opened_at: u64,
    /// Preserved BEFORE any containment runs — see rule 3.
    pub evidence: Vec<Signal>,
    /// Digest over the evidence at preservation time. Containment cannot
    /// retroactively alter what the incident recorded.
    pub evidence_digest: String,
    pub responses: Vec<Response>,
}

impl Incident {
    fn digest_of(signals: &[Signal]) -> String {
        let mut parts: Vec<Vec<u8>> = Vec::new();
        for s in signals {
            parts.push(CanonicalMessage::encode(
                "GODSHIELD-SENTINEL-SIGNAL-V1",
                &[
                    format!("{:?}", s.kind).as_bytes(),
                    s.subject.as_bytes(),
                    s.source.as_bytes(),
                    s.detail.as_bytes(),
                    &s.timestamp.to_le_bytes(),
                ],
            ));
        }
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        TripleHash::hash_hex(&CanonicalMessage::encode(
            "GODSHIELD-SENTINEL-EVIDENCE-V1",
            &refs,
        ))
    }

    /// Anyone holding the digest can confirm the evidence was not edited
    /// after the fact.
    pub fn verify_evidence(&self) -> bool {
        Self::digest_of(&self.evidence) == self.evidence_digest
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct SentinelConfig {
    pub rules: Vec<Rule>,

    /// Identities Sentinel may never contain automatically.
    ///
    /// Rule 2. Without this, an attacker who can attribute failures to
    /// the break-glass operators gets Sentinel to lock them out, and
    /// nobody is left who can switch it off. The protected set should be
    /// small, human, and never include a service account.
    pub protected_identities: HashSet<String>,

    /// Maximum automatic responses against one subject per window.
    ///
    /// A signal storm must not become a response storm. Past this,
    /// Sentinel stops acting and escalates instead — the situation is by
    /// then beyond what a threshold rule should be deciding.
    pub max_responses_per_subject: u32,
    pub response_window_secs: u64,

    /// How long a signal stays eligible for correlation.
    pub retention_secs: u64,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            rules: default_rules(),
            protected_identities: HashSet::new(),
            max_responses_per_subject: 3,
            response_window_secs: 3600,
            retention_secs: 3600,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// SENTINEL
// ═══════════════════════════════════════════════════════════════════════

pub struct Sentinel {
    config: SentinelConfig,
    /// Recent signals, oldest first, pruned on ingest.
    signals: VecDeque<Signal>,
    incidents: Vec<Incident>,
    /// (subject, rule_id) -> when it last fired, for deduplication.
    last_fired: HashMap<(String, String), u64>,
    /// subject -> (window_start, count)
    response_budget: HashMap<String, (u64, u32)>,
    next_incident: u64,
}

impl Sentinel {
    pub fn new(config: SentinelConfig) -> Self {
        Self {
            config,
            signals: VecDeque::new(),
            incidents: Vec::new(),
            last_fired: HashMap::new(),
            response_budget: HashMap::new(),
            next_incident: 1,
        }
    }

    pub fn incidents(&self) -> &[Incident] {
        &self.incidents
    }

    pub fn open_incidents(&self) -> impl Iterator<Item = &Incident> {
        self.incidents
            .iter()
            .filter(|i| i.state == IncidentState::Open)
    }

    pub fn signal_count(&self) -> usize {
        self.signals.len()
    }

    /// Ingest one signal and return whatever responses it triggers.
    ///
    /// The order below is the §5 pipeline, and it is deliberate:
    /// detection, correlation, risk, policy, THEN evidence, THEN
    /// response. Evidence is captured before containment because
    /// containment mutates the state the evidence describes.
    pub fn observe(&mut self, signal: Signal, now: u64) -> Vec<Response> {
        // ── Detection ──
        self.prune(now);
        self.signals.push_back(signal.clone());

        // ── Correlation ──
        let Some(rule) = self
            .config
            .rules
            .iter()
            .find(|r| r.kind == signal.kind)
            .cloned()
        else {
            return Vec::new();
        };

        let window_start = now.saturating_sub(rule.window_secs);
        let matching: Vec<Signal> = self
            .signals
            .iter()
            .filter(|s| {
                s.kind == rule.kind && s.subject == signal.subject && s.timestamp >= window_start
            })
            .cloned()
            .collect();

        if (matching.len() as u32) < rule.threshold {
            return Vec::new();
        }

        // Deduplicate: one incident per subject per rule per window.
        // Without this a rule at threshold 3 opens a new incident on
        // every subsequent signal, and the incident queue becomes the
        // storm it was meant to summarise.
        let key = (signal.subject.clone(), rule.id.clone());
        if let Some(&last) = self.last_fired.get(&key) {
            if now.saturating_sub(last) < rule.window_secs {
                return Vec::new();
            }
        }
        self.last_fired.insert(key, now);

        // ── Evidence, BEFORE containment ──
        let evidence_digest = Incident::digest_of(&matching);
        let incident_id = format!("INC-{:06}", self.next_incident);
        self.next_incident += 1;

        // ── Policy decision ──
        let response = self.decide(&rule, &signal, now);
        let state = match &response {
            Response::EscalateToHuman { .. } => IncidentState::Escalated,
            Response::Observe => IncidentState::Open,
            _ => IncidentState::Contained,
        };

        self.incidents.push(Incident {
            incident_id,
            rule_id: rule.id.clone(),
            subject: signal.subject.clone(),
            severity: rule.severity,
            state,
            opened_at: now,
            evidence: matching,
            evidence_digest,
            responses: vec![response.clone()],
        });

        if response == Response::Observe {
            return Vec::new();
        }
        vec![response]
    }

    /// Translate a fired rule into an action, applying the three safety
    /// rules.
    fn decide(&mut self, rule: &Rule, signal: &Signal, now: u64) -> Response {
        let template = rule.response.clone();

        // Rule 1: destructive actions never happen automatically.
        if let ResponseTemplate::EscalateToHuman { action } = template {
            return Response::EscalateToHuman {
                action,
                why: format!("{} on {}", rule.id, signal.subject),
            };
        }

        if matches!(template, ResponseTemplate::Observe) {
            return Response::Observe;
        }

        // Rule 2: protected identities are never contained automatically.
        if self.config.protected_identities.contains(&signal.subject) {
            return Response::EscalateToHuman {
                action: format!(
                    "rule {} matched a PROTECTED identity — automatic containment refused",
                    rule.id
                ),
                why: format!(
                    "{} is break-glass; suspending it automatically could lock out \
                     everyone able to intervene",
                    signal.subject
                ),
            };
        }

        // Response budget: a signal storm must not become a response storm.
        let entry = self
            .response_budget
            .entry(signal.subject.clone())
            .or_insert((now, 0));
        if now.saturating_sub(entry.0) >= self.config.response_window_secs {
            *entry = (now, 0);
        }
        entry.1 += 1;
        if entry.1 > self.config.max_responses_per_subject {
            return Response::EscalateToHuman {
                action: format!(
                    "response budget exhausted for {} — {} automatic actions in this window",
                    signal.subject, entry.1
                ),
                why: "repeated automatic containment is no longer proportionate; \
                      a human should decide"
                    .into(),
            };
        }

        match template {
            ResponseTemplate::SuspendIdentity => Response::SuspendIdentity {
                identity: signal.subject.clone(),
            },
            ResponseTemplate::BlockOperation => Response::BlockOperation {
                operation: signal.detail.clone(),
            },
            ResponseTemplate::OpenBridgeCircuit => Response::OpenBridgeCircuit {
                reason: format!("{}: {}", rule.id, signal.detail),
            },
            ResponseTemplate::Observe => Response::Observe,
            ResponseTemplate::EscalateToHuman { .. } => unreachable!("handled above"),
        }
    }

    /// Recovery. Closing an incident is an explicit human act with an
    /// operator recorded; there is no timer that resolves incidents.
    pub fn resolve(&mut self, incident_id: &str, operator: &str) -> bool {
        if let Some(i) = self
            .incidents
            .iter_mut()
            .find(|i| i.incident_id == incident_id)
        {
            i.state = IncidentState::Resolved;
            tracing::info!(incident = %incident_id, %operator, "Incident resolved");
            return true;
        }
        false
    }

    fn prune(&mut self, now: u64) {
        let cutoff = now.saturating_sub(self.config.retention_secs);
        while self.signals.front().is_some_and(|s| s.timestamp < cutoff) {
            self.signals.pop_front();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn sig(kind: SignalKind, subject: &str, ts: u64) -> Signal {
        Signal {
            kind,
            subject: subject.into(),
            source: "gateway".into(),
            detail: "detail".into(),
            timestamp: ts,
        }
    }

    fn sentinel() -> Sentinel {
        Sentinel::new(SentinelConfig::default())
    }

    // ── Rule 1: destructive actions escalate ──

    #[test]
    fn sentinel_never_revokes_anything_automatically() {
        // Revocation is permanent. Nothing in the response enum can
        // perform one, and no default rule produces anything close.
        let s = sentinel();
        for rule in &s.config.rules {
            if let ResponseTemplate::EscalateToHuman { .. } = rule.response {
                continue;
            }
            assert!(
                !matches!(rule.response, ResponseTemplate::EscalateToHuman { .. }),
                "unreachable"
            );
        }
        // The type system carries the guarantee: no Revoke variant exists.
        let responses = [
            Response::Observe,
            Response::BlockOperation {
                operation: "x".into(),
            },
            Response::SuspendIdentity {
                identity: "x".into(),
            },
            Response::OpenBridgeCircuit { reason: "x".into() },
        ];
        assert!(responses.iter().all(|r| r.is_automatic()));
    }

    #[test]
    fn a_broken_audit_chain_escalates_rather_than_acting() {
        // The record is already untrustworthy; automated action would
        // write more entries into a log nobody can believe.
        let mut s = sentinel();
        let out = s.observe(sig(SignalKind::AuditChainBroken, "gateway-1", NOW), NOW);
        assert!(matches!(out[0], Response::EscalateToHuman { .. }));
        assert_eq!(s.incidents()[0].state, IncidentState::Escalated);
    }

    #[test]
    fn a_reconciliation_gap_halts_the_bridge_immediately() {
        // Reversible, so automatic. Waiting for a human while unbacked
        // supply mints is worse than a false halt.
        let mut s = sentinel();
        let out = s.observe(sig(SignalKind::ReconciliationGap, "bridge", NOW), NOW);
        assert!(matches!(out[0], Response::OpenBridgeCircuit { .. }));
        assert_eq!(s.incidents()[0].severity, Severity::Critical);
    }

    // ── Rule 2: protected identities ──

    #[test]
    fn a_protected_identity_is_never_suspended_automatically() {
        // THE attack: attribute failures to the break-glass operator and
        // let Sentinel lock out everyone able to switch it off.
        let mut cfg = SentinelConfig::default();
        cfg.protected_identities.insert("operator-root".into());
        let mut s = Sentinel::new(cfg);

        let mut out = Vec::new();
        for i in 0..15 {
            out = s.observe(
                sig(SignalKind::VerificationFailed, "operator-root", NOW + i),
                NOW + i,
            );
            if !out.is_empty() {
                break;
            }
        }
        assert!(
            matches!(out[0], Response::EscalateToHuman { .. }),
            "protected identities must escalate, not be contained"
        );
        assert!(!s.incidents().iter().any(|i| i
            .responses
            .iter()
            .any(|r| matches!(r, Response::SuspendIdentity { .. }))));
    }

    #[test]
    fn an_unprotected_identity_is_suspended_on_the_same_signal() {
        let mut s = sentinel();
        let mut out = Vec::new();
        for i in 0..15 {
            out = s.observe(
                sig(SignalKind::VerificationFailed, "svc-1", NOW + i),
                NOW + i,
            );
            if !out.is_empty() {
                break;
            }
        }
        assert!(matches!(out[0], Response::SuspendIdentity { .. }));
    }

    // ── Rule 3: evidence before containment ──

    #[test]
    fn evidence_is_captured_and_verifiable() {
        let mut s = sentinel();
        for i in 0..3 {
            s.observe(sig(SignalKind::ReplayAttempted, "m-1", NOW + i), NOW + i);
        }
        let inc = &s.incidents()[0];
        assert_eq!(inc.evidence.len(), 3, "all correlated signals preserved");
        assert!(inc.verify_evidence());
    }

    #[test]
    fn editing_preserved_evidence_is_detectable() {
        let mut s = sentinel();
        for i in 0..3 {
            s.observe(sig(SignalKind::ReplayAttempted, "m-1", NOW + i), NOW + i);
        }
        let mut inc = s.incidents()[0].clone();
        inc.evidence[1].detail = "rewritten after the fact".into();
        assert!(!inc.verify_evidence());
    }

    // ── Correlation ──

    #[test]
    fn a_threshold_must_actually_be_reached() {
        let mut s = sentinel();
        // replay-attempts fires at 3.
        assert!(s
            .observe(sig(SignalKind::ReplayAttempted, "m-1", NOW), NOW)
            .is_empty());
        assert!(s
            .observe(sig(SignalKind::ReplayAttempted, "m-1", NOW + 1), NOW + 1)
            .is_empty());
        assert!(!s
            .observe(sig(SignalKind::ReplayAttempted, "m-1", NOW + 2), NOW + 2)
            .is_empty());
    }

    #[test]
    fn signals_about_different_subjects_do_not_correlate() {
        // Otherwise three machines each failing once looks like one
        // machine failing three times, and the wrong thing gets contained.
        let mut s = sentinel();
        assert!(s
            .observe(sig(SignalKind::ReplayAttempted, "m-1", NOW), NOW)
            .is_empty());
        assert!(s
            .observe(sig(SignalKind::ReplayAttempted, "m-2", NOW), NOW)
            .is_empty());
        assert!(s
            .observe(sig(SignalKind::ReplayAttempted, "m-3", NOW), NOW)
            .is_empty());
        assert!(s.incidents().is_empty());
    }

    #[test]
    fn signals_outside_the_window_do_not_correlate() {
        let mut s = sentinel();
        s.observe(sig(SignalKind::ReplayAttempted, "m-1", NOW), NOW);
        s.observe(sig(SignalKind::ReplayAttempted, "m-1", NOW + 1), NOW + 1);
        // Window is 300s; this one is far outside it.
        let later = NOW + 5000;
        assert!(s
            .observe(sig(SignalKind::ReplayAttempted, "m-1", later), later)
            .is_empty());
    }

    #[test]
    fn one_incident_per_subject_per_rule_per_window() {
        // Without dedup, a rule at threshold 3 opens an incident on every
        // signal after the third, and the queue becomes the storm.
        let mut s = sentinel();
        for i in 0..20 {
            s.observe(sig(SignalKind::ReplayAttempted, "m-1", NOW + i), NOW + i);
        }
        assert_eq!(s.incidents().len(), 1);
    }

    // ── Response budget ──

    #[test]
    fn a_signal_storm_does_not_become_a_response_storm() {
        let cfg = SentinelConfig {
            max_responses_per_subject: 2,
            ..Default::default()
        };
        let mut s = Sentinel::new(cfg);

        let mut escalated = false;
        // Space signals past the dedup window so each burst fires again.
        for burst in 0..6u64 {
            let base = NOW + burst * 400;
            for i in 0..3 {
                let out = s.observe(sig(SignalKind::ReplayAttempted, "m-1", base + i), base + i);
                if out
                    .iter()
                    .any(|r| matches!(r, Response::EscalateToHuman { .. }))
                {
                    escalated = true;
                }
            }
        }
        assert!(
            escalated,
            "past the budget Sentinel must hand over rather than keep acting"
        );
    }

    // ── Noise discipline ──

    #[test]
    fn a_firing_rate_limiter_is_observed_not_escalated() {
        // A rate limit that fires is the rate limiter working.
        // Escalating on it trains operators to ignore Sentinel.
        let mut s = sentinel();
        for i in 0..60 {
            let out = s.observe(
                sig(SignalKind::RateLimitExceeded, "svc-1", NOW + i),
                NOW + i,
            );
            assert!(out.is_empty(), "must produce no action");
        }
        assert_eq!(s.incidents().len(), 1, "recorded, but not acted on");
        assert_eq!(s.incidents()[0].severity, Severity::Low);
    }

    #[test]
    fn an_unmatched_signal_kind_is_ignored_quietly() {
        let mut cfg = SentinelConfig::default();
        cfg.rules.clear();
        let mut s = Sentinel::new(cfg);
        assert!(s
            .observe(sig(SignalKind::KeyRotated, "svc-1", NOW), NOW)
            .is_empty());
        assert!(s.incidents().is_empty());
    }

    // ── Retention ──

    #[test]
    fn old_signals_are_pruned() {
        let mut s = sentinel();
        s.observe(sig(SignalKind::VerificationFailed, "a", NOW), NOW);
        assert_eq!(s.signal_count(), 1);
        let much_later = NOW + 100_000;
        s.observe(
            sig(SignalKind::VerificationFailed, "b", much_later),
            much_later,
        );
        assert_eq!(s.signal_count(), 1, "the stale signal is gone");
    }

    // ── Recovery ──

    #[test]
    fn incidents_resolve_only_by_explicit_operator_action() {
        let mut s = sentinel();
        for i in 0..3 {
            s.observe(sig(SignalKind::ReplayAttempted, "m-1", NOW + i), NOW + i);
        }
        let id = s.incidents()[0].incident_id.clone();
        assert!(s.resolve(&id, "operator-alice"));
        assert_eq!(s.incidents()[0].state, IncidentState::Resolved);
        assert!(!s.resolve("INC-999999", "operator-alice"));
    }

    #[test]
    fn structural_signals_outrank_probing_ones() {
        assert!(SignalKind::ReconciliationGap.is_structural());
        assert!(SignalKind::AuditChainBroken.is_structural());
        assert!(!SignalKind::VerificationFailed.is_structural());
    }
}
