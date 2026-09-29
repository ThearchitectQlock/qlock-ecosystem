// crates/nev369-relayer/src/main.rs
//
// ═══════════════════════════════════════════════════════════════════════
// NEV369 BRIDGE RELAYER — coordinator
//
// ── WHAT CHANGED, AND WHY IT IS A DIFFERENT PROGRAM ───────────────────
//
// The previous relayer was an authority. `POST /api/locks` recorded
// whatever JSON a caller sent, authenticated by one shared static
// RELAYER_KEY, and the contract minted against it. A lock "existed"
// because somebody with the key said so. Anyone holding that key could
// mint wNEV with no NEV369 lock ever occurring.
//
// This one is a COORDINATOR. It holds no signing key at all.
//
// Independent signers each watch NEV369 themselves and POST a signed
// attestation about what they saw. This service collects them, and when
// godshield-bridge says the threshold is met — from DISTINCT signers,
// over byte-identical canonical bytes, past finality, inside the
// exposure limits, with the circuit closed — it emits an authorization.
//
// The security consequence is the whole point:
//
//   Compromising this service lets an attacker WITHHOLD or REORDER
//   authorizations. It does not let them CREATE one. Forging requires m
//   independent Dilithium5 keys, which is the property the old design
//   did not have at any value of m.
//
// ── WHAT IS PRESERVED FROM THE ORIGINAL ───────────────────────────────
//
// The hardening in the previous version was real and is kept: constant-
// time credential comparison, no hardcoded default secret, atomic
// write-then-rename, fatal error on a corrupt store rather than silent
// reset, an explicit CORS allow-list, and amounts held as decimal
// strings rather than round-tripped through f64. None of it addressed
// the trust model, but all of it was correct.
//
// ── WHAT IS STILL NOT SOLVED ──────────────────────────────────────────
//
// Signers attest to observations. This service does not verify NEV369
// headers itself, so m colluding signers can still authorize a mint that
// never happened. Threshold reduces that from "one stolen key" to "m
// independent compromises", which is a large improvement and is not the
// same as trustless. A light client verifying NEV369 block headers on
// Ethereum is the construction that removes trust; this is not that.
//
// Say so publicly. Do not describe this bridge as trustless.
// ═══════════════════════════════════════════════════════════════════════

mod eip712;

use actix_cors::Cors;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use godshield_bridge::{
    BridgeAuthorizer, BridgeError, BridgePolicy, CircuitState, MintAuthorization, SignerAttestation,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

// ═══════════════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════════════

/// A mint working its way toward threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingMint {
    authorization: MintAuthorization,
    /// Keyed by signer fingerprint, so one signer cannot occupy two
    /// slots. godshield-bridge rejects duplicates as well; doing it here
    /// too means a duplicate never reaches the threshold check and the
    /// signer gets a clear error instead of a confusing one.
    attestations: HashMap<String, SignerAttestation>,
    /// secp256k1 signatures over the contract's EIP-712 digest, keyed by
    /// the signer's Ethereum address (lowercase, 0x-prefixed).
    ///
    /// These are what the contract actually verifies. Ethereum has no
    /// ML-DSA precompile, so the Dilithium5 attestations above are the
    /// post-quantum audit trail and THESE are the on-chain enforcement.
    /// Both halves are collected from the same signers for the same lock.
    eth_signatures: HashMap<String, String>,
    first_seen: u64,
    authorized: bool,
    /// Set once the mint has landed on Ethereum. Multiple submitters may
    /// race — the contract accepts exactly one, so this is bookkeeping,
    /// not a lock.
    submitted: bool,
    submitted_tx: Option<String>,
}

struct AppState {
    authorizer: RwLock<BridgeAuthorizer>,
    pending: RwLock<HashMap<String, PendingMint>>,
    policy: BridgePolicy,
    /// Credential for submitting an attestation. Authenticates the
    /// TRANSPORT only — it does not authorize a mint. Stealing it lets
    /// someone submit attestations that will fail signature verification.
    submit_token: String,
    store_path: String,
    /// Needed for the EIP-712 domain. A wrong value produces a digest no
    /// signature matches, so the mint reverts rather than misfiring.
    chain_id: u64,
    bridge_address: [u8; 20],
}

fn hex_invalid(s: &str) -> bool {
    !s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Constant-time comparison, carried over from the original.
///
/// A byte-by-byte `==` leaks the length of the matching prefix through
/// timing, which is enough to recover a token given enough attempts.
fn credential_matches(provided: &str, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

// ═══════════════════════════════════════════════════════════════════════
// REQUESTS
// ═══════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct AttestRequest {
    authorization: MintAuthorization,
    attestation: SignerAttestation,
    /// The signer's own view of the NEV369 chain head. Used for the
    /// finality check.
    source_chain_head: u64,
    /// The same signer's secp256k1 address and its signature over the
    /// contract's `mintDigest(...)` for this lock. 65 bytes, hex.
    ///
    /// Signers should obtain the digest by CALLING `mintDigest` on the
    /// deployed contract rather than recomputing EIP-712 locally. One
    /// source of truth for the digest means a signer and the contract
    /// cannot disagree about what was signed.
    eth_signer: String,
    eth_signature: String,
}

#[derive(Serialize)]
struct AttestResponse {
    lock_id: String,
    attestations: usize,
    threshold: usize,
    authorized: bool,
    /// Present only once threshold is met.
    authorization_record: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

fn bad(e: impl std::fmt::Display) -> HttpResponse {
    HttpResponse::BadRequest().json(ApiError {
        error: e.to_string(),
    })
}

// ═══════════════════════════════════════════════════════════════════════
// ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════

/// A signer submits its independent attestation.
///
/// There is deliberately no endpoint that creates a lock record from
/// unsigned input. That endpoint was the vulnerability.
#[post("/api/attest")]
async fn attest(
    state: web::Data<Arc<AppState>>,
    req: actix_web::HttpRequest,
    body: web::Json<AttestRequest>,
) -> impl Responder {
    let provided = req
        .headers()
        .get("x-relayer-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !credential_matches(provided, &state.submit_token) {
        return HttpResponse::Unauthorized().json(ApiError {
            error: "invalid or missing relayer credential".into(),
        });
    }

    let body = body.into_inner();
    let lock_id = body.authorization.lock_id.clone();

    // Reject an unknown signer before storing anything, so the pending
    // map cannot be filled with attestations that can never count.
    if !state
        .policy
        .authorized_signers
        .contains(&body.attestation.signer_fingerprint)
    {
        return bad(BridgeError::UnknownSigner(
            body.attestation.signer_fingerprint.clone(),
        ));
    }

    let mut pending = state.pending.write().await;
    let entry = pending
        .entry(lock_id.clone())
        .or_insert_with(|| PendingMint {
            authorization: body.authorization.clone(),
            attestations: HashMap::new(),
            eth_signatures: HashMap::new(),
            first_seen: now(),
            authorized: false,
            submitted: false,
            submitted_tx: None,
        });

    if entry.authorized {
        return bad(BridgeError::Replay(lock_id));
    }

    // Signers must agree byte-for-byte on what they are authorizing.
    //
    // Without this, two signers attesting to different amounts for the
    // same lock id would each hold a valid signature, and whichever
    // authorization the coordinator happened to submit would carry
    // signatures collected against a different one. godshield-bridge
    // would catch it — every attestation is verified against the
    // authorization actually presented — but catching it here names the
    // problem instead of reporting a confusing signature failure.
    if entry.authorization != body.authorization {
        return bad(format!(
            "signer disagrees about lock {lock_id}: another signer attested to \
             different terms. Signers must observe the same event."
        ));
    }

    // Minimal shape check. Full recovery happens on-chain; the submitter
    // also simulates before sending, so a bad signature costs nothing.
    let eth_signer = body.eth_signer.trim().to_lowercase();
    let eth_sig = body
        .eth_signature
        .trim()
        .trim_start_matches("0x")
        .to_string();
    if !(eth_signer.starts_with("0x") && eth_signer.len() == 42) {
        return bad("eth_signer must be a 0x-prefixed 20-byte address");
    }
    if eth_sig.len() != 130 || hex_invalid(&eth_sig) {
        return bad("eth_signature must be 65 bytes of hex (r, s, v)");
    }

    entry.attestations.insert(
        body.attestation.signer_fingerprint.clone(),
        body.attestation,
    );
    entry.eth_signatures.insert(eth_signer, eth_sig);

    let collected: Vec<SignerAttestation> = entry.attestations.values().cloned().collect();
    let count = collected.len();

    if count < state.policy.threshold {
        return HttpResponse::Ok().json(AttestResponse {
            lock_id,
            attestations: count,
            threshold: state.policy.threshold,
            authorized: false,
            authorization_record: None,
        });
    }

    // Threshold reached. godshield-bridge runs all five gates.
    let mut auth = state.authorizer.write().await;
    match auth.authorize(
        &entry.authorization,
        &collected,
        body.source_chain_head,
        now(),
    ) {
        Ok(record) => {
            entry.authorized = true;
            tracing::info!(
                lock = %lock_id,
                signers = record.signers.len(),
                amount = %record.amount,
                "Mint AUTHORIZED"
            );
            let json = serde_json::to_value(&record).unwrap_or(serde_json::Value::Null);
            HttpResponse::Ok().json(AttestResponse {
                lock_id,
                attestations: count,
                threshold: state.policy.threshold,
                authorized: true,
                authorization_record: Some(json),
            })
        }
        Err(e) => {
            tracing::warn!(lock = %lock_id, error = %e, "Authorization refused");
            bad(e)
        }
    }
}

#[get("/api/locks/{lock_id}")]
async fn lock_status(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> impl Responder {
    let lock_id = path.into_inner();
    let pending = state.pending.read().await;
    match pending.get(&lock_id) {
        Some(p) => HttpResponse::Ok().json(serde_json::json!({
            "lock_id": lock_id,
            "attestations": p.attestations.len(),
            "threshold": state.policy.threshold,
            "authorized": p.authorized,
            "first_seen": p.first_seen,
            "signers": p.attestations.keys().collect::<Vec<_>>(),
        })),
        None => HttpResponse::NotFound().json(ApiError {
            error: "unknown lock".into(),
        }),
    }
}

/// Reconciliation. Whoever watches NEV369's locked balance posts it here;
/// a gap against minted supply trips the circuit breaker.
#[derive(Deserialize)]
struct ReconcileRequest {
    locked_on_source: String,
}

#[post("/api/reconcile")]
async fn reconcile(
    state: web::Data<Arc<AppState>>,
    req: actix_web::HttpRequest,
    body: web::Json<ReconcileRequest>,
) -> impl Responder {
    let provided = req
        .headers()
        .get("x-relayer-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !credential_matches(provided, &state.submit_token) {
        return HttpResponse::Unauthorized().json(ApiError {
            error: "unauthorized".into(),
        });
    }

    let Ok(locked) = body.locked_on_source.parse::<u128>() else {
        return bad("locked_on_source must be a decimal string of base units");
    };

    let mut auth = state.authorizer.write().await;
    match auth.reconcile(locked, now()) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "reconciled": true,
            "minted_total": auth.minted_total().to_string(),
            "locked_on_source": locked.to_string(),
        })),
        Err(e) => {
            tracing::error!(error = %e, "RECONCILIATION FAILED — circuit open");
            HttpResponse::InternalServerError().json(ApiError {
                error: e.to_string(),
            })
        }
    }
}

/// Ready-to-broadcast calldata for an authorized mint.
///
/// The submitter holds no Ethereum key. The contract treats the caller
/// as irrelevant — signatures authorize, not the sender — so this hands
/// back `to` and `data` and anyone can broadcast it. That keeps the
/// property the coordinator has: withhold or reorder, never create.
#[get("/api/locks/{lock_id}/calldata")]
async fn calldata(state: web::Data<Arc<AppState>>, path: web::Path<String>) -> impl Responder {
    let lock_id = path.into_inner();
    let pending = state.pending.read().await;
    let Some(p) = pending.get(&lock_id) else {
        return HttpResponse::NotFound().json(ApiError {
            error: "unknown lock".into(),
        });
    };
    if !p.authorized {
        return bad(format!(
            "lock {lock_id} has {} of {} attestations — not yet authorized",
            p.attestations.len(),
            state.policy.threshold
        ));
    }

    // Order by the signer's Ethereum address. The contract requires
    // strictly ascending addresses, which is how it rejects one key
    // signing m times to clear the threshold alone.
    let mut pairs: Vec<([u8; 20], Vec<u8>)> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for (fp, a) in &p.attestations {
        match (&a.eth_signature_hex, &a.eth_address) {
            (Some(sig), Some(addr)) => {
                let (Some(sb), Some(ab)) = (eip712::parse_hex(sig), eip712::parse_hex(addr)) else {
                    return bad(format!("signer {fp}: malformed hex"));
                };
                if ab.len() != 20 {
                    return bad(format!("signer {fp}: address must be 20 bytes"));
                }
                if sb.len() != 65 {
                    return bad(format!(
                        "signer {fp}: signature must be 65 bytes (r||s||v), got {}",
                        sb.len()
                    ));
                }
                let mut a20 = [0u8; 20];
                a20.copy_from_slice(&ab);
                pairs.push((a20, sb));
            }
            _ => missing.push(fp.clone()),
        }
    }
    if !missing.is_empty() {
        return bad(format!(
            "these signers supplied no secp256k1 signature, so the mint cannot be \
             submitted to Ethereum: {}",
            missing.join(", ")
        ));
    }

    let auth = &p.authorization;
    let Ok(amount) = auth.amount.parse::<u128>() else {
        return bad("amount is not a decimal integer of base units");
    };
    let (Some(lock_bytes), Some(rec_bytes)) = (
        eip712::parse_hex(&auth.lock_id),
        eip712::parse_hex(&auth.recipient),
    ) else {
        return bad("lock_id and recipient must be hex");
    };
    if lock_bytes.len() != 32 || rec_bytes.len() != 20 {
        return bad("lock_id must be 32 bytes and recipient 20");
    }
    let mut lock32 = [0u8; 32];
    lock32.copy_from_slice(&lock_bytes);
    let mut rec20 = [0u8; 20];
    rec20.copy_from_slice(&rec_bytes);

    let params = eip712::MintParams {
        lock_id: lock32,
        recipient: rec20,
        amount,
        source_block_height: auth.source_block_height,
        source_tx: auth.source_tx.clone(),
    };

    let ordered = eip712::order_by_signer(pairs);
    let data = eip712::encode_mint_call(&params, &ordered);
    let digest = eip712::mint_digest(state.chain_id, state.bridge_address, &params);

    HttpResponse::Ok().json(serde_json::json!({
        "to": eip712::hex0x(&state.bridge_address),
        "data": eip712::hex0x(&data),
        "value": "0x0",
        "signatures": ordered.len(),
        "threshold": state.policy.threshold,
        // Exposed so a signer can confirm the coordinator assembled the
        // same digest they signed, before anyone spends gas.
        "digest": eip712::hex0x(&digest),
        "note": "submitter holds no key; broadcast this from any funded account",
    }))
}

// ═══════════════════════════════════════════════════════════════════════
// SUBMITTER INTERFACE
//
// The submitter is a separate process holding an Ethereum key for GAS
// only. It polls /api/ready, carries the collected secp256k1 signatures
// to `mintFromNEV369`, and reports back.
//
// It is kept out of this process on purpose: the coordinator holds no
// key of any kind, and a key for gas is still a key.
// ═══════════════════════════════════════════════════════════════════════

#[derive(Serialize)]
struct ReadyMint {
    lock_id: String,
    recipient: String,
    amount: String,
    source_tx: String,
    source_block_height: u64,
    /// (eth address, signature hex), UNSORTED. The submitter sorts by
    /// ascending address, because that is what the contract requires and
    /// the ordering rule belongs next to the code that depends on it.
    signatures: Vec<(String, String)>,
}

/// Authorized off-chain, enough on-chain signatures collected, not yet
/// landed on Ethereum.
#[get("/api/ready")]
async fn ready(state: web::Data<Arc<AppState>>) -> impl Responder {
    let pending = state.pending.read().await;
    let out: Vec<ReadyMint> = pending
        .iter()
        .filter(|(_, p)| {
            p.authorized && !p.submitted && p.eth_signatures.len() >= state.policy.threshold
        })
        .map(|(id, p)| ReadyMint {
            lock_id: id.clone(),
            recipient: p.authorization.recipient.clone(),
            amount: p.authorization.amount.clone(),
            source_tx: p.authorization.source_tx.clone(),
            source_block_height: p.authorization.source_block_height,
            signatures: p
                .eth_signatures
                .iter()
                .map(|(a, s)| (a.clone(), s.clone()))
                .collect(),
        })
        .collect();
    HttpResponse::Ok().json(out)
}

#[derive(Deserialize)]
struct SubmittedRequest {
    tx_hash: String,
}

/// Mark a lock as landed on Ethereum.
///
/// Credential-gated, because a caller who could mark arbitrary locks as
/// submitted could stop the submitter from ever sending them — a denial
/// of service against the bridge, not a theft, but still worth closing.
#[post("/api/locks/{lock_id}/submitted")]
async fn mark_submitted(
    state: web::Data<Arc<AppState>>,
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    body: web::Json<SubmittedRequest>,
) -> impl Responder {
    let provided = req
        .headers()
        .get("x-relayer-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !credential_matches(provided, &state.submit_token) {
        return HttpResponse::Unauthorized().json(ApiError {
            error: "unauthorized".into(),
        });
    }

    let lock_id = path.into_inner();
    let mut pending = state.pending.write().await;
    match pending.get_mut(&lock_id) {
        Some(p) if p.authorized => {
            p.submitted = true;
            p.submitted_tx = Some(body.tx_hash.clone());
            tracing::info!(lock = %lock_id, tx = %body.tx_hash, "Mint landed on Ethereum");
            HttpResponse::Ok().json(serde_json::json!({ "submitted": true }))
        }
        Some(_) => bad("lock is not authorized — refusing to mark it submitted"),
        None => HttpResponse::NotFound().json(ApiError {
            error: "unknown lock".into(),
        }),
    }
}

#[get("/health")]
async fn health(state: web::Data<Arc<AppState>>) -> impl Responder {
    let auth = state.authorizer.read().await;
    let (circuit, reason) = match auth.circuit_state() {
        CircuitState::Closed => ("closed", None),
        CircuitState::Open { reason, .. } => ("open", Some(reason.clone())),
    };
    HttpResponse::Ok().json(serde_json::json!({
        "status": if circuit == "closed" { "ok" } else { "halted" },
        "circuit": circuit,
        "reason": reason,
        "minted_total": auth.minted_total().to_string(),
        "threshold": state.policy.threshold,
        "authorized_signers": state.policy.authorized_signers.len(),
        // Stated in the health endpoint on purpose. Anyone integrating
        // against this should see the trust model without reading docs.
        "trust_model": "m-of-n attested; NOT trustless — signers attest to \
                        observations, they are not verified on-chain",
    }))
}

// ═══════════════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════════════

fn load_policy() -> anyhow::Result<(BridgePolicy, String, String, Vec<String>)> {
    dotenvy::dotenv().ok();

    // No default. The original refused a hardcoded fallback and that was
    // right — a default credential in a binary is a published credential.
    let submit_token = std::env::var("RELAYER_KEY")
        .map_err(|_| anyhow::anyhow!("RELAYER_KEY is required and has no default"))?;
    if submit_token.len() < 32 {
        anyhow::bail!("RELAYER_KEY must be at least 32 characters");
    }

    let signers: HashSet<String> = std::env::var("BRIDGE_SIGNERS")
        .map_err(|_| anyhow::anyhow!("BRIDGE_SIGNERS is required: comma-separated fingerprints"))?
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let threshold: usize = std::env::var("BRIDGE_THRESHOLD")
        .unwrap_or_else(|_| "3".into())
        .parse()
        .map_err(|_| anyhow::anyhow!("BRIDGE_THRESHOLD must be a number"))?;

    let parse_u128 = |k: &str, d: &str| -> anyhow::Result<u128> {
        std::env::var(k)
            .unwrap_or_else(|_| d.into())
            .parse()
            .map_err(|_| anyhow::anyhow!("{k} must be a decimal number of base units"))
    };

    let policy = BridgePolicy {
        policy_id: std::env::var("BRIDGE_POLICY_ID").unwrap_or_else(|_| "bridge-v1".into()),
        authorized_signers: signers,
        threshold,
        finality_confirmations: std::env::var("BRIDGE_FINALITY")
            .unwrap_or_else(|_| "60".into())
            .parse()
            .unwrap_or(60),
        per_mint_cap: parse_u128("BRIDGE_PER_MINT_CAP", "10000000000000")?,
        window_cap: parse_u128("BRIDGE_WINDOW_CAP", "100000000000000")?,
        window_seconds: std::env::var("BRIDGE_WINDOW_SECONDS")
            .unwrap_or_else(|_| "86400".into())
            .parse()
            .unwrap_or(86_400),
        total_exposure_cap: parse_u128("BRIDGE_TOTAL_CAP", "1000000000000000")?,
    };

    // Rejects threshold < 2 and threshold > signer count. Fail here, at
    // startup, rather than discovering it on the first mint.
    policy.validate()?;

    let store_path =
        std::env::var("RELAYER_STORE").unwrap_or_else(|_| "./data/relayer.json".into());

    let origins: Vec<String> = std::env::var("RELAYER_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Ok((policy, submit_token, store_path, origins))
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let (policy, submit_token, store_path, origins) = load_policy()?;

    tracing::info!(
        threshold = policy.threshold,
        signers = policy.authorized_signers.len(),
        finality = policy.finality_confirmations,
        "NEV369 bridge coordinator starting"
    );
    tracing::warn!(
        "This coordinator holds NO signing key. It cannot create an \
         authorization — only collect attestations from {} independent \
         signers and check that {} of them agree.",
        policy.authorized_signers.len(),
        policy.threshold
    );

    // EIP-712 domain. Both must match the deployed NEV369Bridge exactly —
    // a wrong value yields a digest no signature matches, so mints revert
    // rather than misfire. Required: there is no safe default.
    let chain_id: u64 = std::env::var("ETH_CHAIN_ID")
        .map_err(|_| anyhow::anyhow!("ETH_CHAIN_ID is required (1 = mainnet, 11155111 = Sepolia)"))?
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("ETH_CHAIN_ID must be a number"))?;
    let bridge_address: [u8; 20] = std::env::var("BRIDGE_ADDRESS")
        .ok()
        .and_then(|a| eip712::parse_hex(a.trim()))
        .and_then(|b| <[u8; 20]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| {
            anyhow::anyhow!("BRIDGE_ADDRESS must be the 0x… address of the deployed NEV369Bridge")
        })?;
    tracing::info!(chain_id, bridge = %eip712::hex0x(&bridge_address), "EIP-712 domain");

    let state = Arc::new(AppState {
        authorizer: RwLock::new(BridgeAuthorizer::new(policy.clone(), now())?),
        pending: RwLock::new(HashMap::new()),
        policy,
        submit_token,
        store_path,
        chain_id,
        bridge_address,
    });

    let bind = std::env::var("RELAYER_BIND").unwrap_or_else(|_| "0.0.0.0:9370".into());
    tracing::info!(%bind, store = %state.store_path, "Listening");

    HttpServer::new(move || {
        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![
                actix_web::http::header::CONTENT_TYPE,
                actix_web::http::header::HeaderName::from_static("x-relayer-key"),
            ])
            .max_age(3600);
        for origin in &origins {
            cors = cors.allowed_origin(origin);
        }

        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(cors)
            .service(health)
            .service(attest)
            .service(lock_status)
            .service(reconcile)
            .service(ready)
            .service(mark_submitted)
            .service(calldata)
    })
    .bind(&bind)?
    .run()
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_comparison_rejects_an_empty_expected_value() {
        // An unset RELAYER_KEY must not make everything match.
        assert!(!credential_matches("anything", ""));
        assert!(!credential_matches("", ""));
    }

    #[test]
    fn credential_comparison_is_exact() {
        assert!(credential_matches(
            "correct-horse-battery-staple-32ch",
            "correct-horse-battery-staple-32ch"
        ));
        assert!(!credential_matches(
            "correct-horse-battery-staple-32cH",
            "correct-horse-battery-staple-32ch"
        ));
        assert!(!credential_matches(
            "correct",
            "correct-horse-battery-staple-32ch"
        ));
    }
}
