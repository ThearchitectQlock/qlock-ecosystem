// crates/godshield-api/src/gateway.rs
//
// ═══════════════════════════════════════════════════════════════════════
// PQ SECURITY GATEWAY — HTTP binding (GodShield spec §1)
//
//   POST /api/v1/gateway/verify             public   identity-bound verification
//   POST /api/v1/gateway/policy/check       public   ALLOW / DENY / REQUIRE_APPROVAL
//   POST /api/v1/gateway/identity/register  admin    register an identity + key
//   POST /api/v1/gateway/key/rotate         admin    rotate, keeping history
//   POST /api/v1/gateway/sign               admin    gateway attestation
//   GET  /api/v1/gateway/audit              public   tamper-evident audit chain
//
// The rules live in godshield-gateway; this file only moves JSON in and
// out. `sign` is the gateway attesting with ITS OWN operational key to
// something it checked — it never signs caller-supplied bytes with a
// caller's key, because a service that does is a signing oracle.
//
// Admin endpoints need `Authorization: Bearer $GODSHIELD_ADMIN_TOKEN`.
// With no token configured they answer 503 — there is no default.
// ═══════════════════════════════════════════════════════════════════════

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use godshield_gateway::{AttestationKind, Gateway, GatewayError, GatewayPolicy};
use serde::Deserialize;
use std::collections::HashMap;
use subtle::ConstantTimeEq;

use crate::AppState;

type ApiResult = Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)>;

fn fail(code: StatusCode, msg: impl ToString) -> (StatusCode, Json<serde_json::Value>) {
    (code, Json(serde_json::json!({ "error": msg.to_string() })))
}

fn gw_err(e: GatewayError) -> (StatusCode, Json<serde_json::Value>) {
    let code = match &e {
        GatewayError::AlgorithmNotAllowed(_) => StatusCode::BAD_REQUEST,
        GatewayError::RefusedOracleRequest => StatusCode::FORBIDDEN,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    fail(code, format!("{e:?}"))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build the gateway from the environment.
///
///   GODSHIELD_POLICY_ID            default "gw-v1"
///   GODSHIELD_ALLOWED_ALGORITHMS   default "ML-DSA-87"
///   GODSHIELD_VALUE_LIMIT          default 0 (no value-bearing operations)
///   GODSHIELD_RATE_PER_WINDOW      default 120
///   GODSHIELD_RATE_WINDOW_SECS     default 60
///   GODSHIELD_GATEWAY_KEY          optional GodKeyPair JSON — enables /sign
pub fn build_from_env() -> anyhow::Result<Gateway> {
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let policy = GatewayPolicy {
        policy_id: env("GODSHIELD_POLICY_ID", "gw-v1"),
        allowed_algorithms: env("GODSHIELD_ALLOWED_ALGORITHMS", "ML-DSA-87")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        default_value_limit: env("GODSHIELD_VALUE_LIMIT", "0").parse().unwrap_or(0),
        per_identity_value_limit: HashMap::new(),
        requests_per_window: env("GODSHIELD_RATE_PER_WINDOW", "120")
            .parse()
            .unwrap_or(120),
        window_seconds: env("GODSHIELD_RATE_WINDOW_SECS", "60")
            .parse()
            .unwrap_or(60),
    };
    let mut gw = Gateway::new(policy);
    if let Ok(json) = std::env::var("GODSHIELD_GATEWAY_KEY") {
        if !json.trim().is_empty() {
            gw.set_operational_key(&json)
                .map_err(|e| anyhow::anyhow!("GODSHIELD_GATEWAY_KEY: {e:?}"))?;
        }
    }
    Ok(gw)
}

fn require_admin(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let Some(expected) = state.admin_token.as_deref() else {
        return Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin endpoints disabled — set GODSHIELD_ADMIN_TOKEN",
        ));
    };
    let supplied = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if supplied.len() == expected.len()
        && bool::from(supplied.as_bytes().ct_eq(expected.as_bytes()))
    {
        Ok(())
    } else {
        Err(fail(StatusCode::UNAUTHORIZED, "invalid admin token"))
    }
}

fn decode_message(
    message: &str,
    encoding: Option<&str>,
) -> Result<Vec<u8>, (StatusCode, Json<serde_json::Value>)> {
    match encoding.unwrap_or("utf8") {
        "utf8" => Ok(message.as_bytes().to_vec()),
        "hex" => {
            hex::decode(message).map_err(|_| fail(StatusCode::BAD_REQUEST, "invalid hex message"))
        }
        other => Err(fail(
            StatusCode::BAD_REQUEST,
            format!("unknown encoding '{other}'"),
        )),
    }
}

// ── verify ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VerifyRequest {
    identity_id: String,
    message: String,
    encoding: Option<String>,
    signature_hex: String,
    /// When the signature was made. Resolves the key that was current
    /// then, so rotation never invalidates old signatures.
    signed_at: u64,
}

pub async fn verify(State(state): State<AppState>, Json(r): Json<VerifyRequest>) -> ApiResult {
    let msg = decode_message(&r.message, r.encoding.as_deref())?;
    let mut gw = state.gateway.lock().await;
    match gw.verify(&r.identity_id, &msg, &r.signature_hex, r.signed_at, now()) {
        Ok(()) => Ok(Json(
            serde_json::json!({ "valid": true, "identity_id": r.identity_id }),
        )),
        Err(GatewayError::VerificationFailed) => Ok(Json(
            serde_json::json!({ "valid": false, "identity_id": r.identity_id }),
        )),
        Err(e) => Err(gw_err(e)),
    }
}

// ── policy/check ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PolicyRequest {
    identity_id: String,
    algorithm: String,
    /// Decimal string so values above 2^53 survive JSON.
    #[serde(default)]
    value: Option<String>,
}

pub async fn policy_check(
    State(state): State<AppState>,
    Json(r): Json<PolicyRequest>,
) -> ApiResult {
    let value: u128 = match r.value.as_deref() {
        None | Some("") => 0,
        Some(v) => v.parse().map_err(|_| {
            fail(
                StatusCode::BAD_REQUEST,
                "value must be a decimal integer string",
            )
        })?,
    };
    let mut gw = state.gateway.lock().await;
    let d = gw
        .policy_check(&r.identity_id, &r.algorithm, value, now())
        .map_err(gw_err)?;
    Ok(Json(serde_json::to_value(d).unwrap_or_default()))
}

// ── identity/register, key/rotate ──────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    identity_id: String,
    public_key_hex: String,
    #[serde(default = "default_alg")]
    algorithm: String,
}

fn default_alg() -> String {
    "ML-DSA-87".into()
}

pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(r): Json<RegisterRequest>,
) -> ApiResult {
    require_admin(&state, &headers)?;
    let pk = hex::decode(&r.public_key_hex)
        .map_err(|_| fail(StatusCode::BAD_REQUEST, "invalid public_key_hex"))?;
    let mut gw = state.gateway.lock().await;
    let fp = gw
        .register_identity(&r.identity_id, &pk, &r.algorithm, now())
        .map_err(gw_err)?;
    Ok(Json(
        serde_json::json!({ "identity_id": r.identity_id, "fingerprint": fp, "status": "ACTIVE" }),
    ))
}

#[derive(Deserialize)]
pub struct RotateRequest {
    identity_id: String,
    new_public_key_hex: String,
    #[serde(default = "default_alg")]
    algorithm: String,
}

pub async fn rotate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(r): Json<RotateRequest>,
) -> ApiResult {
    require_admin(&state, &headers)?;
    let pk = hex::decode(&r.new_public_key_hex)
        .map_err(|_| fail(StatusCode::BAD_REQUEST, "invalid new_public_key_hex"))?;
    let mut gw = state.gateway.lock().await;
    let fp = gw
        .rotate_key(&r.identity_id, &pk, &r.algorithm, now())
        .map_err(gw_err)?;
    Ok(Json(
        serde_json::json!({ "identity_id": r.identity_id, "fingerprint": fp }),
    ))
}

// ── sign (gateway attestation) ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct SignRequest {
    /// verification_result | policy_decision | identity_registration | key_rotation
    kind: AttestationKind,
    subject: String,
    statement: String,
}

pub async fn sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(r): Json<SignRequest>,
) -> ApiResult {
    require_admin(&state, &headers)?;
    let mut gw = state.gateway.lock().await;
    let att = gw
        .sign_attestation(r.kind, &r.subject, &r.statement, now())
        .map_err(gw_err)?;
    Ok(Json(serde_json::to_value(att).unwrap_or_default()))
}

// ── audit ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuditQuery {
    since: Option<usize>,
}

pub async fn audit(State(state): State<AppState>, Query(q): Query<AuditQuery>) -> ApiResult {
    let gw = state.gateway.lock().await;
    let log = gw.audit();
    let since = q.since.unwrap_or(0).min(log.entries().len());
    let page: Vec<_> = log.since(since).iter().take(500).cloned().collect();
    Ok(Json(serde_json::json!({
        "head": log.head(),
        "length": log.entries().len(),
        "chain_intact": log.verify().is_ok(),
        "entries": page,
    })))
}
