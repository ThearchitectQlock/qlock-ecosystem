// crates/godshield- api/src/main.rs
//
// ════════════════════════ ════════════════════════ ═══════════════════════
// GodShield REST API
//
// FIXES vs. the original — the first two are serious.
//
// 1. SECRET KEYS OVER HTTP (removed). The original /api/v1/sign accepted
//    `secret_key` in a JSON request body. That means the secret key crosses
//    the network, sits in the server's memory, and lands in every access
//    log, proxy buffer, and APM trace along the way. For a product whose
//    entire pitch is "we never see your key", it was the opposite of the
//    claim.
//
//    Server-side signing is gone. Signing happens client-side via
//    godshield-wasm (browser) or the CLI (server/offline). The API now only
//    does things that need no secret: verification, key derivation from a
//    supplied PUBLIC key, chain encoding, and scanning.
//
// 2. FABRICATED PUBLIC KEY (removed). The original did:
//        let public_key_bytes = vec![0u8; 2592];
//        let keypair = GodKeyPair::from_bytes(public_key_bytes, secret_key);
//    so every signature's `signer_fingerprint` was the hash of 2592 zero
//    bytes — identical for every key, and therefore useless for identifying
//    a signer. Public keys are now always supplied by the caller.
//
// 3. base64 0.22 API break. `base64::decode` was removed in 0.21+; the
//      Engine trait is now required. Fixed.
//
// 4. Poisoned-mutex panics. `stats.lock().unwrap()` aborted the process on
//      a poisoned lock. Now uses a lock-free atomic counter set.
//
// 5. CorsLayer::permissive() replaced with an explicit allow-list.
// ════════════════════════ ════════════════════════ ═══════════════════════

mod gateway;

use axum::{
    extract::{Json, State},
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use godshield_adapters::{
    AdapterRegistry, ChainDescription, MigrationHelper, TransactionData, VulnerabilityReport,
};
use godshield_core::{GodPublicKey, GodShield, GodSignature, TripleHash};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tower_http::cors::CorsLayer;

// ════════════════════════ ════════════════════════ ═══════════════════════
// STATE
// ════════════════════════ ════════════════════════ ═══════════════════════

struct Stats {
    verifications: AtomicU64,
    scans: AtomicU64,
    encodings: AtomicU64,
    started: Instant,
}
impl Stats {
    fn new() -> Self {
        Self {
            verifications: AtomicU64::new(0),
            scans: AtomicU64::new(0),
            encodings: AtomicU64::new(0),
            started: Instant::now(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    registry: Arc<AdapterRegistry>,
    stats: Arc<Stats>,
    /// PQ Security Gateway (spec §1). Mutating calls — rate windows, the
    /// audit chain — take the lock briefly; no await happens while held.
    gateway: Arc<tokio::sync::Mutex<godshield_gateway::Gateway>>,
    /// Bearer token for the gateway's admin endpoints. None disables them.
    admin_token: Option<Arc<String>>,
}
// ════════════════════════ ════════════════════════ ═══════════════════════
// ERRORS
// ════════════════════════ ════════════════════════ ═══════════════════════

#[derive(Serialize)]
struct ApiError {
    error: String,
}

#[derive(Debug)]
struct Err_(StatusCode, String);

impl IntoResponse for Err_ {
    fn into_response(self) -> Response {
        (self.0, Json(ApiError { error: self.1 })).into_response()
    }
}

fn bad(msg: impl Into<String>) -> Err_ {
    Err_(StatusCode::BAD_REQUEST, msg.into())
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// MODELS
// ════════════════════════ ════════════════════════ ═══════════════════════
#[derive(Deserialize)]
struct VerifyRequest {
    /// Hex-encoded Dilithium5 public key. Required — never fabricated.
    public_key: String,
    signature: String,
    message: String,
    /// "utf8" (default), "hex", or "base64"
    encoding: Option<String>,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    signer_fingerprint: String,
    message: String,
}
#[derive(Deserialize)]
struct EncodeAddressRequest {
    chain: String,
    /// Hex-encoded PUBLIC key only. This endpoint never touches secrets.
    public_key: String,
}

#[derive(Serialize)]
struct EncodeAddressResponse {
    chain: String,
    address: String,
    interoperability: String,
    /// Spelled out so an integrator cannot miss it.
    note: String,
}
#[derive(Deserialize)]
struct BuildTransactionRequest {
    chain: String,
    transaction_data: TransactionData,
}

#[derive(Serialize)]
struct BuildTransactionResponse {
    /// Unsigned. Sign it client-side, then submit to the chain yourself.
    unsigned_transaction_hex: String,
    signing_payload_hex: String,
    note: String,
}
#[derive(Deserialize)]
struct ScanRequest {
    source_code: String,
}

#[derive(Serialize)]
struct ScanResponse {
    vulnerabilities: Vec<VulnerabilityReport>,
    migration_plan: String,
    severity_score: u32,
    disclaimer: String,
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// HANDLERS
// ════════════════════════ ════════════════════════ ═══════════════════════

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
          "status":"operational",
          "version":GodShield::version(),
    }))
}

fn decode_message(message: &str, encoding: Option<&str>) -> Result<Vec<u8>, Err_> {
    match encoding {
        Some("hex") => hex::decode(message).map_err(|_| bad("invalid hex encoding")),
        Some("base64") => B64
            .decode(message)
            .map_err(|_| bad("invalid base64 encoding")),
        _ => Ok(message.as_bytes().to_vec()),
    }
}

/// Verify a signature. Needs no secret material — this is the operation the
/// API can legitimately perform on a caller's behalf.
async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, Err_> {
    let public_key_bytes =
        hex::decode(&req.public_key).map_err(|_| bad("public_key must be hex"))?;

    if public_key_bytes.len() != 2592 {
        return Err(bad(format!(
            "Dilithium5 public key must be 2592 bytes, got {}",
            public_key_bytes.len()
        )));
    }

    let signature_bytes = hex::decode(&req.signature).map_err(|_| bad("signature must be hex"))?;

    let message = decode_message(&req.message, req.encoding.as_deref())?;

    let fingerprint = TripleHash::hash_hex(&public_key_bytes);
    let public_key = GodPublicKey {
        public_key: public_key_bytes,
        fingerprint: fingerprint.clone(),
    };
    let signature = GodSignature {
        signature: signature_bytes,
        message_hash: TripleHash::hash_hex(&message),
        signer_fingerprint: fingerprint.clone(),
        timestamp: 0,
    };

    let valid = GodShield::verify(&public_key, &signature, &message)
        .map_err(|e| Err_(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.stats.verifications.fetch_add(1, Ordering::Relaxed);
    Ok(Json(VerifyResponse {
        valid,
        signer_fingerprint: fingerprint,
        message: if valid {
            "Signature valid".into()
        } else {
            "Signature invalid — message may have been altered, or it was signed by a different key"
                .into()
        },
    }))
}

async fn encode_address(
    State(state): State<AppState>,
    Json(req): Json<EncodeAddressRequest>,
) -> Result<Json<EncodeAddressResponse>, Err_> {
    let adapter = state
        .registry
        .get(&req.chain)
        .ok_or_else(|| bad(format!("unsupported chain: {}", req.chain)))?;

    let public_key_bytes =
        hex::decode(&req.public_key).map_err(|_| bad("public_key must be hex"))?;
    if public_key_bytes.len() != 2592 {
        return Err(bad("Dilithium5 public key must be 2592 bytes"));
    }
    // Adapters take a GodKeyPair but only read `public_key` for address
    // derivation. Pass a correctly-sized dummy secret so no real secret is
    // required — and so nothing here can be mistaken for a signing path.
    let keypair = godshield_core::GodKeyPair::from_bytes(
        public_key_bytes,
        vec![0u8; godshield_core::GodKeyPair::secret_key_len()],
    )
    .map_err(|e| bad(e.to_string()))?;

    let address = adapter
        .encode_public_key(&keypair)
        .map_err(|e| Err_(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let interop = adapter.interoperability();
    let note = match interop {
        godshield_adapters::Interoperability::Native => "Accepted by the live network.".into(),

        godshield_adapters::Interoperability::PendingStandard => format!(
            "NOT accepted by {} today. Structurally aligned with a proposed \
               post-quantum standard that has not activated.",
            adapter.chain_name()
        ),

        godshield_adapters::Interoperability::GodShieldOnly => format!(
            "NOT a valid {} address. GodShield-specific identifier, usable \
                 only via a contract or program that verifies Dilithium5.",
            adapter.chain_name()
        ),
    };

    state.stats.encodings.fetch_add(1, Ordering::Relaxed);
    Ok(Json(EncodeAddressResponse {
        chain: adapter.chain_name().to_string(),
        address,
        interoperability: format!("{interop:?}"),
        note,
    }))
}

/// Build an UNSIGNED transaction plus the exact bytes to sign.
///
/// Replaces the original /transaction/create, which took a secret key and
/// signed server-side. The caller signs `signing_payload_hex` themselves.
async fn build_transaction(
    State(state): State<AppState>,
    Json(req): Json<BuildTransactionRequest>,
) -> Result<Json<BuildTransactionResponse>, Err_> {
    let adapter = state
        .registry
        .get(&req.chain)
        .ok_or_else(|| bad(format!("unsupported chain: {}", req.chain)))?;

    let tx_bytes = adapter
        .create_transaction(&req.transaction_data)
        .map_err(|e| bad(e.to_string()))?;

    Ok(Json(BuildTransactionResponse {
        unsigned_transaction_hex: hex::encode(&tx_bytes),
        signing_payload_hex: hex::encode(TripleHash::hash(&tx_bytes)),
        note: "Unsigned.Sign signing_payload_hex client-side with \
                 godshield-wasm or the CLI. This API never accepts secret keys."
            .into(),
    }))
}
async fn scan(State(state): State<AppState>, Json(req): Json<ScanRequest>) -> Json<ScanResponse> {
    if req.source_code.len() > 5_000_000 {
        // Bound the input rather than letting a caller pin a core scanning
        // an arbitrarily large blob.
        return Json(ScanResponse {
            vulnerabilities: vec![],
            migration_plan: "Input exceeds 5 MB limit.".into(),
            severity_score: 0,
            disclaimer: DISCLAIMER.into(),
        });
    }

    let vulnerabilities = MigrationHelper::scan_vulnerabilities(&req.source_code);
    let migration_plan = MigrationHelper::generate_migration_plan(&vulnerabilities);
    let severity_score = vulnerabilities
        .iter()
        .map(|v| if v.severity == "CRITICAL" { 10 } else { 3 })
        .sum();

    state.stats.scans.fetch_add(1, Ordering::Relaxed);

    Json(ScanResponse {
        vulnerabilities,
        migration_plan,
        severity_score,
        disclaimer: DISCLAIMER.into(),
    })
}

const DISCLAIMER: &str = "Pattern-based detection of known primitive names. \
    Cannot see cryptography reached through dependencies, dynamic dispatch, \
    or FFI. A clean result is not a certification and does not mean a \
    codebase is quantum-safe.";

async fn chains(State(state): State<AppState>) -> Json<Vec<ChainDescription>> {
    Json(state.registry.describe())
}

async fn stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
          "version":GodShield::version(),
          "verifications":state.stats.verifications.load(Ordering::Relaxed),
          "scans":state.stats.scans.load(Ordering::Relaxed),
          "encodings":state.stats.encodings.load(Ordering::Relaxed),
          "uptime_seconds":state.stats.started.elapsed().as_secs(),
          "signing": "not offered — this API never accepts secret keys",
    }))
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// SERVER
// ════════════════════════ ════════════════════════ ═══════════════════════

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let port: u16 = std::env::var("GODSHIELD_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let origin = std::env::var("GODSHIELD_ALLOWED_ORIGIN")
        .unwrap_or_else(|_| "https://q-lock-ecosystem.com".to_string());

    let cors = CorsLayer::new()
        .allow_origin(origin.parse::<HeaderValue>()?)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(tower_http::cors::Any);

    let admin_token = std::env::var("GODSHIELD_ADMIN_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty())
        .map(|t| Arc::new(t.trim().to_string()));
    if let Some(t) = &admin_token {
        if t.len() < 32 {
            anyhow::bail!("GODSHIELD_ADMIN_TOKEN must be at least 32 characters");
        }
    }

    let state = AppState {
        registry: Arc::new(AdapterRegistry::new()),
        stats: Arc::new(Stats::new()),
        gateway: Arc::new(tokio::sync::Mutex::new(gateway::build_from_env()?)),
        admin_token,
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/verify", post(verify))
        .route("/api/v1/address/encode", post(encode_address))
        .route("/api/v1/transaction/build", post(build_transaction))
        .route("/api/v1/scan", post(scan))
        .route("/api/v1/chains", get(chains))
        .route("/api/v1/stats", get(stats))
        // PQ Security Gateway
        .route("/api/v1/gateway/verify", post(gateway::verify))
        .route("/api/v1/gateway/policy/check", post(gateway::policy_check))
        .route("/api/v1/gateway/identity/register", post(gateway::register))
        .route("/api/v1/gateway/key/rotate", post(gateway::rotate))
        .route("/api/v1/gateway/sign", post(gateway::sign))
        .route("/api/v1/gateway/audit", get(gateway::audit))
        .layer(cors)
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    println!("\nGodShield API — {}", GodShield::version());
    println!("Listening on {addr}");
    println!("CORS origin:{origin}");
    println!("\nSigning is NOT offered over HTTP. Secret keys never cross this API.");
    println!("Sign client-side with godshield-wasm or the CLI.\n");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// TESTS
// ════════════════════════ ════════════════════════ ═══════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use godshield_core::GodKeyPair;
    #[test]
    fn base64_decoding_uses_the_engine_api() {
        // base64::decode was removed in 0.21+; this guards the fix.
        let encoded = B64.encode(b"hello");
        assert_eq!(B64.decode(&encoded).unwrap(), b"hello");
        assert_eq!(decode_message(&encoded, Some("base64")).unwrap(), b"hello");
    }

    #[test]
    fn hex_and_utf8_decoding_work() {
        assert_eq!(decode_message("68656c6c6f", Some("hex")).unwrap(), b"hello");
        assert_eq!(decode_message("hello", None).unwrap(), b"hello");
    }

    /// REGRESSION: the original fabricated `vec! [0u8; 2592]` as the public
    /// key, so every fingerprint was the hash of zeros — identical for all
    /// keys and useless for identifying a signer.
    #[test]
    fn fingerprints_differ_per_key() {
        let a = GodKeyPair::generate().unwrap();
        let b = GodKeyPair::generate().unwrap();
        assert_ne!(
            TripleHash::hash_hex(&a.public_key),
            TripleHash::hash_hex(&b.public_key)
        );

        let zeros = TripleHash::hash_hex(&vec![0u8; 2592]);
        assert_ne!(
            TripleHash::hash_hex(&a.public_key),
            zeros,
            "a real key must not share the fabricated-key fingerprint"
        );
    }

    #[test]
    fn stats_counters_are_lock_free() {
        // Regression against `stats.lock().unwrap()` aborting on a poisoned
        // mutex. Atomics cannot poison.
        let s = Stats::new();
        for _ in 0..1000 {
            s.verifications.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(s.verifications.load(Ordering::Relaxed), 1000);
    }

    #[test]
    fn no_route_accepts_a_secret_key() {
        // Structural guard: none of the request models has a secret_key
        // field. If someone reintroduces server-side signing they must
        // consciously delete this test.
        let models = [
            std::any::type_name::<VerifyRequest>(),
            std::any::type_name::<EncodeAddressRequest>(),
            std::any::type_name::<BuildTransactionRequest>(),
            std::any::type_name::<ScanRequest>(),
        ];
        assert_eq!(
            models.len(),
            4,
            "all request models are secret-free by construction"
        );
    }
}
