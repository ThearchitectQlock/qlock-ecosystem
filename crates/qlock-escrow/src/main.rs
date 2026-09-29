// crates/qlock- escrow/src/main.rs
//
// ════════════════════════ ════════════════════════ ═══════════════════════
// Q-LOCK ESCROW BACKEND
//
// Non-custodial XRPL escrow with post-quantum attestation.
//
// Design principle throughout: this process never holds a key capable of
// moving user funds. Signing happens in Xaman on the user's phone, or on a
// Ledger device over WebHID. The backend builds unsigned transactions,
// relays signed ones, and records attestations. That is architecture, not
// policy — there is no key here to misuse.
//
// Modules:
//   auth         JWT + API key middleware
//   billing      Stripe checkout and webhook (real signature verification)
//   ratelimit    tower- governor layers
//   (lib.rs) attestation, inheritance, xrpl, xumm
// ════════════════════════ ════════════════════════ ═══════════════════════

use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

mod auth;
mod billing;
mod godshield_billing;
mod ratelimit;

use qlock_escrow::attestation::{
    Attestation, AttestationIdentity, QLockAttestor, SettlementRecord,
};
use qlock_escrow::{xrpl, xumm};
// ════════════════════════ ════════════════════════ ═══════════════════════
// PRICING — single source of truth
//
// These MUST match the published table in README.md. The code previously
// charged everyone 0.3% while the docs advertised tiered discounts, so Pro
// and Enterprise subscribers paid for a benefit they never received.
// ════════════════════════ ════════════════════════ ═══════════════════════
const FEE_RATE_FREE: f64 = 0.003;
const FEE_RATE_PRO: f64 = 0.002;
const FEE_RATE_ENTERPRISE: f64 = 0.0015;
const FREE_TIER_MONTHLY_ESCROW_LIMIT: i64 = 5;

fn fee_rate_for_plan(plan: &str) -> f64 {
    match plan {
        "pro" => FEE_RATE_PRO,
        "enterprise" => FEE_RATE_ENTERPRISE,
        _ => FEE_RATE_FREE,
    }
}

/// Ripple epoch offset: seconds from the Unix epoch to 2000-01-01.
const RIPPLE_EPOCH_OFFSET: i64 = 946_684_800;

fn ripple_time_now() -> u32 {
    (Utc::now().timestamp() - RIPPLE_EPOCH_OFFSET) as u32
}

fn ripple_time_from_now(seconds: i64) -> u32 {
    (Utc::now().timestamp() + seconds - RIPPLE_EPOCH_OFFSET) as u32
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// METRICS — lock-free
//
// Previously a Mutex<Stats> with .unwrap(); a poisoned lock took down the
// process. Atomics cannot poison.
// ════════════════════════ ════════════════════════ ═══════════════════════

static HTTP_REQUESTS: AtomicU64 = AtomicU64::new(0);
static SENDS_TOTAL: AtomicU64 = AtomicU64::new(0);
static ESCROWS_CREATED_TOTAL: AtomicU64 = AtomicU64::new(0);
static XUMM_CONNECTS_TOTAL: AtomicU64 = AtomicU64::new(0);

// ════════════════════════ ════════════════════════ ═══════════════════════
// ERRORS
//
// Serialises as {"error": "..."} JSON. The frontend reads err.error — with
// the old bare (StatusCode, String) tuple that field was always undefined,
// so users only ever saw a generic fallback instead of the real reason.
// ════════════════════════ ════════════════════════ ═══════════════════════

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(serde_json::json!({"error": self.1
            })),
        )
            .into_response()
    }
}

impl From<(StatusCode, String)> for ApiError {
    fn from((code, msg): (StatusCode, String)) -> Self {
        ApiError(code, msg)
    }
}

fn err(code: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError(code, msg.into())
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("DB error: {:?}", e);

    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Database error".into())
}
// ════════════════════════ ════════════════════════ ═══════════════════════
// STATE
// ════════════════════════ ════════════════════════ ═══════════════════════

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub xrpl_node: String,
    /// Where escrow fees land. Without it, escrow creation returns 503
    /// rather than silently discarding the fee — which is what happened
    /// before this was added.
    pub treasury_address: Option<String>,
    /// Cached live XRP price: (usd, 24h change, fetched_at).
    pub price_cache: Arc<RwLock<Option<(f64, f64, Instant)>>>,
    /// Long-lived post- quantum attestation key. A fresh key per attestation
    /// proved a record was self-consistent but bound it to no identity —
    /// anyone with DB write access could forge a verifying row.
    pub attestation: QLockAttestor,
}
#[derive(sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub api_key: String,
    pub plan: String,
    #[allow(dead_code)]
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct TransactionRow {
    hash: String,
    from_address: String,
    to_address: String,
    amount: sqlx::types::BigDecimal,
    status: String,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct EscrowRow {
    id: Uuid,
    from_address: String,
    to_address: String,
    amount: sqlx::types::BigDecimal,
    #[allow(dead_code)]
    fee_paid: sqlx::types::BigDecimal,
    status: String,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    quantum_proof: Option<String>,
}
// ════════════════════════ ════════════════════════ ═══════════════════════
// REQUEST / RESPONSE
// ════════════════════════ ════════════════════════ ═══════════════════════

#[derive(Deserialize)]
struct SendRequest {
    from: String,
    to: String,
    amount: f64,
    #[serde(rename = "cryptoMethod")]
    crypto_method: String,
    /// Hex-encoded, already-signed XRPL blob from a Ledger device. Xumm
    /// sends go through /wallet/xumm/pay instead — Xumm submits itself.
    #[serde(rename = "signedTxBlob")]
    signed_tx_blob: Option<String>,
}

#[derive(Serialize)]
struct SendResponse {
    #[serde(rename = "txHash")]
    tx_hash: String,
    #[serde(rename = "quantumAttestation")]
    quantum_attestation: Option<String>,
    /// "demo" | "submitted" — so nothing downstream can mistake an internal
    /// ledger movement for a real payment.
    status: String,
}

#[derive(Deserialize)]
struct XummPayRequest {
    from: String,
    to: String,
    amount: f64,
}

#[derive(Deserialize)]
struct CreateEscrowRequest {
    from: String,
    to: String,
    amount: f64,
    #[serde(rename = "expiresIn")]
    expires_in: Option<i64>,
}

#[derive(Deserialize)]
struct XrplEscrowCreateRequest {
    from: String,
    to: String,
    amount: f64,
    #[serde(rename = "lockHours")]
    lock_hours: f64,
}

#[derive(Deserialize)]
struct XrplEscrowActionRequest {
    account: String,
}

#[derive(Deserialize)]
struct EstimateGasRequest {
    #[allow(dead_code)]
    from: String,
    #[allow(dead_code)]
    to: String,
    #[allow(dead_code)]
    amount: f64,
}

#[derive(Deserialize)]
struct KeygenRequest {
    algorithm: String,
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// MAIN
// ════════════════════════ ════════════════════════ ═══════════════════════

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Sentry is optional; the guard must outlive main to flush on drop.
    let _sentry = std::env::var("SENTRY_DSN").ok().map(|dsn| {
        sentry::init((
            dsn,
            sentry::ClientOptions {
                release: sentry::release_name!(),

                traces_sample_rate: 0.1,

                ..Default::default()
            },
        ))
    });

    use tracing_subscriber::prelude::*;
    let registry = tracing_subscriber::registry().with(tracing_subscriber::fmt::layer());
    if _sentry.is_some() {
        registry.with(sentry_tracing::layer()).init();
    } else {
        registry.init();
        tracing::warn!("SENTRY_DSN not set — logging to stdout only");
    }

    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set (see .env.example)");
    let xrpl_node = std::env::var("XRPL_NODE").unwrap_or_else(|_| {
        tracing::warn!("XRPL_NODE not set — defaulting to public testnet");

        "https://s.altnet.rippletest.net:51234".into()
    });

    if std::env::var("XUMM_API_KEY").is_err() || std::env::var("XUMM_API_SECRET").is_err() {
        tracing::warn!("XUMM credentials not set — /wallet/xumm/* returns 503");
    }

    let treasury_address = std::env::var("QLOCK_TREASURY_ADDRESS").ok();
    if treasury_address.is_none() {
        tracing::warn!(
            "QLOCK_TREASURY_ADDRESS not set — escrow creation returns 503. \
               Without it, platform fees have nowhere to go."
        );
    }

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await?;

    // Tables added after the database was first initialised.
    godshield_billing::ensure_schema(&pool).await?;

    // Attestation identity. Production demands a persistent key —
    // ephemeral attestations cannot be verified against a published
    // platform fingerprint, which is the whole point of attesting.
    // AttestationIdentity::from_env resolves it: QLOCK_ATTESTATION_KEY
    // (keypair JSON from the vault ceremony) in production, an ephemeral
    // key in development, and a hard refusal for QLOCK_ATTESTATION_VAULT
    // — a vault that unlocks itself unattended is not protected by the
    // vault. Any error here stops startup: fail closed.
    let attestation = QLockAttestor::new(
        AttestationIdentity::from_env()
            .map_err(|e| anyhow::anyhow!("attestation identity: {e:?}"))?,
    );

    tracing::info!(
         fingerprint =%attestation.fingerprint(),
         "Attestation identity ready (GodShield /Dilithium5)"
    );

    let state = AppState {
        db: pool,
        xrpl_node,
        treasury_address,
        price_cache: Arc::new(RwLock::new(None)),
        attestation,
    };

    let frontend_origin =
        std::env::var("FRONTEND_ORIGIN").unwrap_or_else(|_| "https://q-lock-ecosystem.com".into());
    // Comma-separated: the console is served from the nginx root and the
    // marketing domain at the same time, and both call this API.
    let origins: Vec<HeaderValue> = frontend_origin
        .split(',')
        .map(str::trim)
        .filter(|o| !o.is_empty())
        .map(|o| o.parse::<HeaderValue>())
        .collect::<Result<_, _>>()?;
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(tower_http::cors::Any);

    let auth_layer = || middleware::from_fn_with_state(state.clone(), auth::require_auth);

    let app = Router::new()
        // ── Public ──────────────────────── ──────────────────────── ────
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/ledger/status", get(ledger_status))
        .route("/price/xrp", get(get_xrp_price))
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        // ── Wallet ──────────────────────── ──────────────────────── ────
        .route("/wallet/xumm/connect", post(xumm_connect_start))
        .route("/wallet/xumm/connect/:uuid", get(xumm_connect_status))
        .route("/wallet/xumm/pay", post(xumm_pay_start))
        .route("/wallet/xumm/pay/:uuid", get(xumm_pay_status))
        .route("/wallet/:address/balance", get(get_balance))
        .route("/wallet/:address/transactions", get(get_transactions))
        .route("/wallet/:address/sequence", get(get_account_sequence))
        // ── Transactions ──────────────────────── ──────────────────────
        .route("/estimate/gas", post(estimate_gas))
        .route("/quantum/keygen", post(generate_quantum_key))
        .route("/send", post(send_transaction))
        .route("/transaction/:hash/status", get(get_transaction_status))
        // ── Account ──────────────────────── ──────────────────────── ───
        .route("/account/plan", get(get_account_plan).layer(auth_layer()))
        // ── Custodial escrow ──────────────────────── ──────────────────
        .route("/escrow/create", post(create_escrow).layer(auth_layer()))
        .route("/escrow/:id", get(get_escrow_details))
        .route("/escrow/:id/release", post(release_escrow))
        .route("/escrow/:id/refund", post(refund_escrow))
        .route("/escrow/list/:address", get(list_escrows))
        .route("/escrow/stats", get(escrow_stats))
        // ── Native XRPL escrow ──────────────────────── ────────────────
        .route(
            "/escrow/xrpl/create",
            post(xrpl_escrow_create_start).layer(auth_layer()),
        )
        .route("/escrow/xrpl/create/:uuid", get(xrpl_escrow_create_status))
        .route(
            "/escrow/xrpl/:id/lock",
            post(xrpl_escrow_lock_start).layer(auth_layer()),
        )
        .route("/escrow/xrpl/lock/:uuid", get(xrpl_escrow_lock_status))
        .route(
            "/escrow/xrpl/:id/finish",
            post(xrpl_escrow_finish_start).layer(auth_layer()),
        )
        .route("/escrow/xrpl/finish/:uuid", get(xrpl_escrow_finish_status))
        .route(
            "/escrow/xrpl/:id/cancel",
            post(xrpl_escrow_cancel_start).layer(auth_layer()),
        )
        .route("/escrow/xrpl/cancel/:uuid", get(xrpl_escrow_cancel_status))
        .route("/escrow/xrpl/list/:address", get(list_xrpl_escrows))
        // ── Billing ──────────────────────── ──────────────────────── ───
        .route(
            "/billing/checkout",
            post(billing::create_checkout).layer(auth_layer()),
        )
        .route("/billing/webhook", post(billing::stripe_webhook))
        .route("/billing/plans", get(godshield_billing::plans))
        // ── GodShield metering (nginx auth_request) and account ─────────
        .route(
            "/internal/godshield/authorize",
            get(godshield_billing::authorize),
        )
        .route(
            "/godshield/account",
            get(godshield_billing::account).layer(auth_layer()),
        )
        .route(
            "/godshield/account/rotate-key",
            post(godshield_billing::rotate_key).layer(auth_layer()),
        )
        .layer(ratelimit::api_limiter())
        .layer(cors)
        .layer(middleware::from_fn(count_requests))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    println!("\n   🔐 Q-Lock escrow — http://0.0.0.0:8080\n");
    // Connect info feeds the rate limiter's fallback key (ratelimit.rs).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn count_requests(req: Request, next: Next) -> Response {
    HTTP_REQUESTS.fetch_add(1, Ordering::Relaxed);
    next.run(req).await
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// HEALTH / METRICS / PRICE
// ════════════════════════ ════════════════════════ ═══════════════════════

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let db_ok = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    Json(serde_json::json!({
              "status": if db_ok {"ok" } else { "degraded" },
              "database": if db_ok { "connected" } else {"unreachable" },
              "xrplNode":state.xrpl_node,
              "xummConfigured":std::env::var("XUMM_API_KEY").is_ok(),"treasuryConfigured":state.treasury_address.is_some(),

    "attestationFingerprint":state.attestation.fingerprint(),
                "version": "1.4.0",
          }))
}

/// Prometheus text format. Not proxied by nginx — internal scrape only.
async fn metrics() -> impl IntoResponse {
    let body = format!(
        "# TYPE qlock_http_requests_total counter\nqlock_http_requests _total {}\n\
              # TYPEqlock_sends_totalcounter\nqlock_sends_total {}\n\
           # TYPEqlock_escrows_created_totalcounter\nqlock_escrows_created_total {}\n\
           # TYPEqlock_xumm_connects_totalcounter\nqlock_xumm_connects_total {}\n",
        HTTP_REQUESTS.load(Ordering::Relaxed),
        SENDS_TOTAL.load(Ordering::Relaxed),
        ESCROWS_CREATED_TOTAL.load(Ordering::Relaxed),
        XUMM_CONNECTS_TOTAL.load(Ordering::Relaxed),
    );
    ([(header::CONTENT_TYPE, "text/plain;version=0.0.4")], body)
}

async fn ledger_status() -> impl IntoResponse {
    Json(serde_json::json!({"status": "connected" }))
}

/// Live CoinGecko price, cached 60s. This returned a hardcoded 2.15 before,
/// meaning every USD figure shown to users was fabricated.
async fn get_xrp_price(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    {
        let cache = state.price_cache.read().await;
        if let Some((price, change, at)) = *cache {
            if at.elapsed() < Duration::from_secs(60) {
                return Ok(Json(
                    serde_json::json!({"price": price, "change24h":change }),
                ));
            }
        }
    }

    let fetched = async {
          let r =reqwest::Client::new().get("https://api.coingecko.com/api/v3/simple/price?ids=ripple&vs_currencies=usd&include_24hr_change=true")

 .timeout(Duration::from_secs (5))

 .send().await.ok()?
               .json::<serde_json::Value> ().await.ok()?;
           Some((r["ripple"] ["usd"].as_f64()?,r["ripple"] ["usd_24h_change"].as_f64().unwrap_or(0.0)))
       }.await;

    match fetched {
        Some((price, change)) => {
            *state.price_cache.write().await = Some((price, change, Instant::now()));

            Ok(Json(
                serde_json::json!({"price": price, "change24h":change }),
            ))
        }
        None => {
            tracing::warn!("Price fetch failed — serving stale cache if present");
            let cache = state.price_cache.read().await;
            match *cache {
                Some((price, change, _)) => Ok(Json(
                    serde_json::json!({"price": price, "change24h":change }),
                )),
                None => Err(err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Price feed unavailable",
                )),
            }
        }
    }
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// XUMM — real wallet connect and payment
// ════════════════════════ ════════════════════════ ═══════════════════════
async fn xumm_connect_start() -> Result<impl IntoResponse, ApiError> {
    let client = xumm::XummClient::from_env().map_err(|e| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Xumm not configured: {e}"),
        )
    })?;
    let p = client
        .create_signin_request()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("Xumm request failed: {e}")))?;

    Ok(Json(serde_json::json!({
           "uuid": p.uuid,"qrPng": p.refs.qr_png,
           "deeplink":p.next.always,"websocketStatus":p.refs.websocket_status,
    })))
}

async fn xumm_connect_status(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let client = xumm::XummClient::from_env().map_err(|e| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Xumm not configured: {e}"),
        )
    })?;
    let s = client
        .get_payload_status(&uuid)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("Xumm status failed:{e}")))?;

    if s.meta.cancelled || s.meta.expired {
        return Ok(Json(
            serde_json::json!({"connected": false,"cancelled": true }),
        ));
    }
    if !s.meta.resolved || !s.meta.signed {
        return Ok(Json(
            serde_json::json!({"connected": false,"pending": true }),
        ));
    }
    let address = s
        .response
        .and_then(|r| r.account)
        .ok_or(err(StatusCode::BAD_GATEWAY, "Xumm returned no account"))?;

    sqlx::query(
        "INSERT INTO wallets (address, balance, is_live) VALUES ($1, 0, true)
           ON CONFLICT (address) DO UPDATE SET is_live = true",
    )
    .bind(&address)
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    XUMM_CONNECTS_TOTAL.fetch_add(1, Ordering::Relaxed);

    Ok(Json(
        serde_json::json!({"connected": true,"address": address }),
    ))
}

async fn xumm_pay_start(
    State(state): State<AppState>,
    Json(req): Json<XummPayRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let is_live: Option<bool> =
        sqlx::query_scalar::<_, bool>("SELECT is_live FROM wallets WHERE address =$1")
            .bind(&req.from)
            .fetch_optional(&state.db)
            .await
            .map_err(db_err)?;

    if is_live != Some(true) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Sender is not a verified Xumm wallet — connect via /wallet/xumm/connect first",
        ));
    }
    if req.amount <= 0.0 {
        return Err(err(StatusCode::BAD_REQUEST, "Amount must be positive"));
    }

    let drops = (req.amount * 1_000_000.0).round() as u64;
    let client = xumm::XummClient::from_env().map_err(|e| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Xumm not configured: {e}"),
        )
    })?;
    let p = client
        .create_payment_request(&req.from, &req.to, drops)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("Xumm request failed: {e}")))?;

    sqlx::query(
        "INSERT INTO xumm_payloads (uuid,from_address, to_address,amount) VALUES ($1,$2,$3,$4)",
    )
    .bind(&p.uuid)
    .bind(&req.from)
    .bind(&req.to)
    .bind(f64_to_bd(req.amount))
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    Ok(Json(serde_json::json!({
           "uuid": p.uuid,"qrPng": p.refs.qr_png,
           "deeplink":p.next.always,"websocketStatus":p.refs.websocket_status,
    })))
}

async fn xumm_pay_status(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let client = xumm::XummClient::from_env().map_err(|e| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Xumm not configured: {e}"),
        )
    })?;
    let s = client
        .get_payload_status(&uuid)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("Xumm status failed:{e}")))?;

    if s.meta.cancelled || s.meta.expired {
        return Ok(Json(
            serde_json::json!({"confirmed": false,"cancelled": true }),
        ));
    }
    if !s.meta.resolved || !s.meta.signed {
        return Ok(Json(
            serde_json::json!({"confirmed": false,"pending": true }),
        ));
    }

    let txid = s.response.and_then(|r| r.txid).ok_or(err(
        StatusCode::BAD_GATEWAY,
        "Xumm returned no transaction id",
    ))?;

    let row =
        sqlx::query("SELECT from_address, to_address,amount FROM xumm_payloads WHERE uuid = $1")
            .bind(&uuid)
            .fetch_optional(&state.db)
            .await
            .map_err(db_err)?
            .ok_or(err(StatusCode::NOT_FOUND, "Unknown payload"))?;

    let from: String = row.get("from_address");
    let to: String = row.get("to_address");
    let amount: sqlx::types::BigDecimal = row.get("amount");

    sqlx::query(
        "INSERT INTO wallets (address, balance,is_live) VALUES ($1,0,false) ON CONFLICT DO NOTHING",
    )
    .bind(&to)
    .execute(&state.db)
    .await
    .ok();

    sqlx::query(
        "INSERT INTO transactions (hash,from_address, to_address,amount, fee, status,crypto_method, confirmed_at)
         VALUES ($1,$2,$3,$4,0,'confirmed','xumm',NOW()) ON CONFLICT (hash) DO NOTHING",

 ).bind(&txid).bind(&from).bind(&to).bind(&amount)

 .execute(&state.db).await.map_err(db_err)?;

    // Post-quantum attestation over the settlement.
    // Best-effort: the payment already settled on-ledger, so a failed
    // attestation is logged rather than turned into an error for the user.
    let record = settlement(
        &txid,
        &from,
        &to,
        xrp_to_drops(&amount),
        "0".into(),
        "xumm_payment",
    );
    match state.attestation.attest(&record) {
        Ok(a) => {
            if let Err(e) = store_attestation(&state.db, &a).await {
                tracing::error!(tx = %txid, error = %e, "attestation not stored");
            }
        }
        Err(e) => tracing::error!(tx = %txid, error = %e, "attestation failed"),
    }

    Ok(Json(serde_json::json!({"confirmed": true, "txHash":txid })))
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// WALLET
// ════════════════════════ ════════════════════════ ═══════════════════════

/// Live wallets are queried against the real ledger; the cached balance is
/// refreshed opportunistically but never authoritative for them.
async fn get_balance(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let row = sqlx::query("SELECT balance,is_live FROM wallets WHERE address = $1")
        .bind(&address)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let (balance, is_live) = match row {
        Some(r) => {
            let is_live: bool = r.get("is_live");
            let cached: sqlx::types::BigDecimal = r.get("balance");
            if is_live {
                match xrpl::XrplClient::new(&state.xrpl_node)
                    .get_balance(&address)
                    .await
                {
                    Ok(live) => {
                        sqlx::query("UPDATE wallets SET balance = $1 WHERE address = $2")
                            .bind(f64_to_bd(live))
                            .bind(&address)
                            .execute(&state.db)
                            .await
                            .ok();

                        (live, true)
                    }
                    Err(e) => {
                        tracing::warn!(%address,error = ?e, "Live balance fetch failed — serving cache");

                        (bd_to_f64(&cached), true)
                    }
                }
            } else {
                (bd_to_f64(&cached), false)
            }
        }
        None => {
            sqlx::query("INSERT INTO wallets (address, balance,is_live) VALUES ($1,$2,false) ON CONFLICT DO NOTHING")

 .bind(&address).bind(sqlx::types::BigDecimal::from(1000))

 .execute(&state.db).await.ok ();
            (1000.0, false)
        }
    };

    Json(serde_json::json!({"balance": balance,"isLive": is_live }))
}

async fn get_transactions(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let rows = sqlx::query_as::<_, TransactionRow>(
        "SELECT hash,from_address, to_address,amount, status, created_at
          FROM transactions WHERE from_address = $1 OR to_address = $1
            ORDER BY created_at DESC LIMIT 50",
    )
    .bind(&address)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let txs: Vec<_> = rows
        .into_iter()
        .map(|t| {
            serde_json::json!({
                       "type": if t.from_address == address {"sent" } else { "received"
            },
                       "amount":bd_to_f64(&t.amount),
                       "from":t.from_address, "to":t.to_address,
                       "time":relative_time(t.created_at),
                       "status": t.status,"hash": t.hash,
                })
        })
        .collect();

    Json(serde_json::json!({"transactions": txs }))
}

/// Account Sequence — needed to build a Ledger- signed transaction.
async fn get_account_sequence(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let seq = xrpl::XrplClient::new(&state.xrpl_node)
        .get_account_sequence(&address)
        .await
        .map_err(|e| {
            err(
                StatusCode::BAD_GATEWAY,
                format!("Failed to fetch sequence: {e}"),
            )
        })?;

    Ok(Json(serde_json::json!({"sequence": seq })))
}

async fn estimate_gas(Json(_): Json<EstimateGasRequest>) -> impl IntoResponse {
    Json(serde_json::json!({"fee": 0.00001 }))
}

/// Development-only Dilithium5 keypair for testing the console.
///
/// Returns the secret once and stores nothing. Refused when
/// QLOCK_ENV=production: a key generated on a server is a key the server
/// operator could have kept. Real keys come from `godshield vault create`.
async fn generate_quantum_key(
    body: Option<Json<KeygenRequest>>,
) -> Result<impl IntoResponse, ApiError> {
    if std::env::var("QLOCK_ENV").as_deref() == Ok("production") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "key generation is disabled in production — generate keys offline with \
             `godshield vault create`",
        ));
    }
    let algorithm = body
        .map(|Json(r)| r.algorithm)
        .unwrap_or_else(|| "dilithium".to_string());
    if !matches!(algorithm.as_str(), "dilithium" | "dilithium5" | "ml-dsa-87") {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "only Dilithium5 (ML-DSA-87) keys are generated here",
        ));
    }
    let kp = godshield_core::GodKeyPair::generate()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let keypair_json = kp
        .to_json()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({
        "algorithm": "ML-DSA-87 (Dilithium5)",
        "publicKey": hex::encode(&kp.public_key),
        "secretKey": hex::encode(kp.secret_key_bytes()),
        "fingerprint": kp.fingerprint,
        "keypairJson": keypair_json,
        "note": "Development key. Returned once, stored nowhere. Never hold real value with it.",
    })))
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// SEND
// ════════════════════════ ════════════════════════ ═══════════════════════

/// Demo-ledger send, or broadcast of a Ledger-signed blob.
///
/// Live wallets without a blob are refused: their real path is
/// /wallet/xumm/pay, where Xumm holds the key and submits itself.
async fn send_transaction(
    State(state): State<AppState>,
    Json(payload): Json<SendRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let fee = 0.00001_f64;
    let mut tx = state.db.begin().await.map_err(db_err)?;

    let row = sqlx::query("SELECT balance,is_live FROM wallets WHERE address = $1 FOR UPDATE")
        .bind(&payload.from)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or((StatusCode::NOT_FOUND, "Sender wallet not found".to_string()))?;

    let balance: sqlx::types::BigDecimal = row.get("balance");
    let is_live: bool = row.get("is_live");

    if is_live && payload.signed_tx_blob.is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Live wallets must send via /wallet/xumm/pay, or supply a signedTxBlob (Ledger)",
        ));
    }

    let total = payload.amount + fee;
    if !is_live && bd_to_f64(&balance) < total {
        return Err(err(StatusCode::BAD_REQUEST, "Insufficient balance"));
    }

    let (tx_hash, status) = if let Some(blob) = &payload.signed_tx_blob {
        let hash = xrpl::XrplClient::new(&state.xrpl_node)
            .submit(blob)
            .await
            .map_err(|e| {
                err(
                    StatusCode::BAD_GATEWAY,
                    format!("XRPL rejected transaction: {e}"),
                )
            })?;
        (hash, "submitted")
    } else {
        (
            local_tx_hash(&payload.from, &payload.to, payload.amount),
            "demo",
        )
    };

    if !is_live {
        sqlx::query("UPDATE wallets SET balance =balance - $1 WHERE address =$2")
            .bind(f64_to_bd(total))
            .bind(&payload.from)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        sqlx::query(
            "INSERT INTO wallets (address, balance,is_live) VALUES ($1,$2,false)
                 ON CONFLICT (address) DO UPDATE SET balance = wallets.balance +$2",
        )
        .bind(&payload.to)
        .bind(f64_to_bd(payload.amount))
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    }

    sqlx::query(
        "INSERT INTO transactions (hash,from_address, to_address,amount, fee, status,crypto_method, confirmed_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",

 ).bind(&tx_hash).bind(&payload.from).bind(&payload.to)

 .bind(f64_to_bd(payload.amount)).bind(f64_to_bd(fee)).bind(status).bind(&payload.crypto_method)
     .bind(if status =="demo" { Some(Utc::now()) } else { None })
     .execute(&mut *tx).await.map_err(db_err)?;

    let quantum_attestation = if payload.crypto_method == "dilithium" {
        let record = settlement(
            &tx_hash,
            &payload.from,
            &payload.to,
            xrp_to_drops(&f64_to_bd(payload.amount)),
            xrp_to_drops(&f64_to_bd(fee)),
            "payment",
        );
        let a = state
            .attestation
            .attest(&record)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        store_attestation(&mut *tx, &a).await.map_err(db_err)?;
        Some(a.dilithium_signature)
    } else {
        None
    };

    tx.commit().await.map_err(db_err)?;
    SENDS_TOTAL.fetch_add(1, Ordering::Relaxed);

    Ok(Json(SendResponse {
        tx_hash,
        quantum_attestation,
        status: status.into(),
    }))
}

/// Polls XRPL live for real broadcasts rather than trusting our own row.
async fn get_transaction_status(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let current: Option<String> =
        sqlx::query_scalar::<_, String>("SELECT status FROM transactions WHERE hash = $1")
            .bind(&hash)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    let status = match current.as_deref() {
        Some("submitted") => {
            match xrpl::XrplClient::new(&state.xrpl_node)
                .get_tx_status(&hash)
                .await
            {
                Ok(live) => {
                    if live == "confirmed" {
                        sqlx::query("UPDATE transactions SET status='confirmed',confirmed_at=NOW() WHERE hash=$1")

 .bind(&hash).execute(&state.db).await.ok();
                    }
                    live
                }
                Err(e) => {
                    tracing::warn!(%hash, error = ?e, "XRPL status poll failed");

                    "submitted".into()
                }
            }
        }
        Some(other) => other.to_string(),
        None => "pending".into(),
    };

    Json(serde_json::json!({"status": status }))
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// ACCOUNT / QUOTA
// ════════════════════════ ════════════════════════ ═══════════════════════

async fn get_account_plan(
    State(state): State<AppState>,
    Extension(claims): Extension<auth::Claims>,
) -> Result<impl IntoResponse, ApiError> {
    let uid = Uuid::parse_str(&claims.sub)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid user id in token"))?;
    let used = monthly_escrow_count(&state.db, uid).await?;
    let rate = fee_rate_for_plan(&claims.plan);
    let limit = (claims.plan == "free").then_some(FREE_TIER_MONTHLY_ESCROW_LIMIT);

    Ok(Json(serde_json::json!({
                 "plan": claims.plan,"email": claims.email,
                 "feeRate": rate,"feePercent": rate * 100.0,

    "escrowsUsedThisMonth":used, "monthlyLimit": limit,
                 "remaining":limit.map(|l| (l -used).max(0)),
          })))
}

async fn monthly_escrow_count(db: &PgPool, uid: Uuid) -> Result<i64, ApiError> {
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM escrows WHERE user_id=$1 AND created_at >=date_trunc('month', NOW()))
                + (SELECT COUNT(*) FROM xrpl_escrows WHERE user_id=$1 AND created_at >=date_trunc('month',NOW()))",

 ).bind(uid).fetch_one(db).await.map_err(db_err)
}

/// Free plan is capped at 5 escrows/month across both flavours.
async fn check_quota(db: &PgPool, user_id: &str, plan: &str) -> Result<(), ApiError> {
    if plan != "free" {
        return Ok(());
    }
    let uid = Uuid::parse_str(user_id)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid user id in token"))?;
    let used = monthly_escrow_count(db, uid).await?;
    if used >= FREE_TIER_MONTHLY_ESCROW_LIMIT {
        return Err(err(
            StatusCode::PAYMENT_REQUIRED,
            format!(
                "Free plan allows {FREE_TIER_MONTHLY_ESCROW_LIMIT} escrows per month \
                (you've used {used}). Upgrade to Pro for unlimited."
            ),
        ));
    }
    Ok(())
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// CUSTODIAL ESCROW
// ════════════════════════ ════════════════════════ ═══════════════════════
async fn create_escrow(
    State(state): State<AppState>,
    Extension(claims): Extension<auth::Claims>,
    Json(req): Json<CreateEscrowRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let treasury = state.treasury_address.clone().ok_or(err(
        StatusCode::SERVICE_UNAVAILABLE,
        "Platform treasury not configured — set QLOCK_TREASURY_ADDRESS",
    ))?;

    check_quota(&state.db, &claims.sub, &claims.plan).await?;

    let rate = fee_rate_for_plan(&claims.plan);
    let fee = req.amount * rate;
    let total = req.amount + fee;
    let escrow_id = Uuid::new_v4();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid user id in token"))?;

    let mut tx = state.db.begin().await.map_err(db_err)?;
    let row = sqlx::query("SELECT balance,is_live FROM wallets WHERE address=$1 FOR UPDATE")
        .bind(&req.from)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or((StatusCode::NOT_FOUND, "Wallet not found".to_string()))?;

    let balance: sqlx::types::BigDecimal = row.get("balance");
    if row.get::<bool, _>("is_live") {
        return Err(err(
            StatusCode::NOT_IMPLEMENTED,
            "Custodial escrow isn't offered to live wallets — use /escrow/xrpl/create",
        ));
    }
    if bd_to_f64(&balance) < total {
        return Err(err(StatusCode::BAD_REQUEST, "Insufficient balance"));
    }

    sqlx::query("UPDATE wallets SET balance =balance - $1 WHERE address =$2")
        .bind(f64_to_bd(total))
        .bind(&req.from)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query(
        "INSERT INTO wallets (address, balance,is_live) VALUES ($1,0,false) ON CONFLICT DO NOTHING",
    )
    .bind(&req.to)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    // The fee actually lands somewhere now — it was silently discarded before.
    sqlx::query(
        "INSERT INTO wallets (address, balance, is_live) VALUES ($1,$2,false)
            ON CONFLICT (address) DO UPDATE SET balance = wallets.balance +$2",
    )
    .bind(&treasury)
    .bind(f64_to_bd(fee))
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    let expires_at = req
        .expires_in
        .map(|s| Utc::now() + chrono::Duration::seconds(s));

    sqlx::query(
           "INSERT INTO escrows (id, user_id, from_address,to_address, amount,fee_paid, fee_rate, status,expires_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,'locked',$8)",

 ).bind(escrow_id).bind(user_id).bind(&req.from).bind(&req.to)

 .bind(f64_to_bd(req.amount)).bind(f64_to_bd(fee)).bind(f64_to_bd(rate)).bind(expires_at).execute(&mut *tx).await.map_err(db_err)?;

    tx.commit().await.map_err(db_err)?;

    ESCROWS_CREATED_TOTAL.fetch_add(1, Ordering::Relaxed);

    tracing::info!(%escrow_id, amount =req.amount, plan =%claims.plan,
          rate_pct = rate *100.0, fee, "Custodial escrow created");

    Ok(Json(serde_json::json!({
           "escrowId":escrow_id.to_string(),"status": "locked", "fee":fee,
    })))
}

async fn get_escrow_details(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let e = fetch_escrow(&state.db, id).await?;

    Ok(Json(escrow_json(&e)))
}

async fn release_escrow(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.db.begin().await.map_err(db_err)?;
    let e = sqlx::query_as::<_, EscrowRow>(
         "SELECT id,from_address, to_address,amount, fee_paid, status,created_at, expires_at,quantum_proof
          FROM escrows WHERE id=$1 FOR UPDATE",

 ).bind(id).fetch_optional(&mut *tx).await.map_err(db_err)?

 .ok_or((StatusCode::NOT_FOUND, "Escrow not found".to_string()))?;

    if e.status != "locked" {
        return Err(err(StatusCode::BAD_REQUEST, "Escrow not locked"));
    }

    let record = settlement(
        &id.to_string(),
        &e.from_address,
        &e.to_address,
        xrp_to_drops(&e.amount),
        xrp_to_drops(&e.fee_paid),
        "custodial_release",
    );
    let a = state
        .attestation
        .attest(&record)
        .map_err(|err_| err(StatusCode::INTERNAL_SERVER_ERROR, err_.to_string()))?;

    sqlx::query(
        "UPDATE escrows SET status='released',quantum_proof=$1,released_at=NOW() WHERE id=$2",
    )
    .bind(&a.dilithium_signature)
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    sqlx::query(
        "INSERT INTO wallets (address, balance, is_live) VALUES ($1,$2,false)
           ON CONFLICT (address) DO UPDATE SET balance = wallets.balance +$2",
    )
    .bind(&e.to_address)
    .bind(&e.amount)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    store_attestation(&mut *tx, &a).await.map_err(db_err)?;

    tx.commit().await.map_err(db_err)?;
    tracing::info!(%id,"Custodial escrow released");

    Ok(Json(serde_json::json!({
           "released": true,"quantumProof":a.dilithium_signature,
    })))
}

async fn refund_escrow(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.db.begin().await.map_err(db_err)?;
    let e = sqlx::query_as::<_, EscrowRow>(
         "SELECT id,from_address, to_address,amount, fee_paid, status,created_at, expires_at,quantum_proof
          FROM escrows WHERE id=$1 FOR UPDATE",

 ).bind(id).fetch_optional(&mut *tx).await.map_err(db_err)?

 .ok_or((StatusCode::NOT_FOUND, "Escrow not found".to_string()))?;
    if e.status != "locked" {
        return Err(err(StatusCode::BAD_REQUEST, "Escrow not locked"));
    }
    if !e.expires_at.map(|x| Utc::now() >= x).unwrap_or(false) {
        return Err(err(StatusCode::BAD_REQUEST, "Escrow not expired"));
    }

    sqlx::query("UPDATE wallets SET balance =balance + $1 WHERE address =$2")
        .bind(&e.amount)
        .bind(&e.from_address)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query("UPDATE escrows SET status='refunded' WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

    tx.commit().await.map_err(db_err)?;

    Ok(Json(
        serde_json::json!({"refunded": true, "amount":bd_to_f64(&e.amount) }),
    ))
}

async fn list_escrows(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let rows =sqlx::query_as::<_,EscrowRow>(
           "SELECT id,from_address, to_address,amount, fee_paid, status,created_at, expires_at,quantum_proof
            FROM escrows WHERE from_address=$1 OR to_address=$1 ORDER BY created_at DESC",

 ).bind(&address).fetch_all(&state.db).await.unwrap_or_default();

    let escrows: Vec<_> = rows.iter().map(escrow_json).collect();
    // Count before the Vec is moved into the macro — `escrows.len()` after
    // the move is a borrow- after-move and will not compile.
    let total = escrows.len();
    Json(serde_json::json!({"escrows": escrows, "total":total }))
}

async fn escrow_stats(State(state): State<AppState>) -> impl IntoResponse {
    let row = sqlx::query(
        "SELECT COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE status='locked')        AS locked,
                     COUNT(*) FILTER (WHERE status='released') AS released,
                     COUNT(*) FILTER (WHERE status='refunded') AS refunded,

 COALESCE(SUM(amount),0)         AS volume,

 COALESCE(SUM(fee_paid),0) AS fees
            FROM escrows",
    )
    .fetch_one(&state.db)
    .await;

    match row {
        Ok(r) => {
            let total: i64 = r.get("total");
            let volume = bd_to_f64(&r.get::<sqlx::types::BigDecimal, _>("volume"));

            Json(serde_json::json!({

            "totalEscrows": total,
                             "locked":r.get::<i64,_>("locked"),
                             "released":r.get::<i64,_>("released"),
                             "refunded":r.get::<i64,_>("refunded"),

            "totalVolume": volume,
                             "totalFees":bd_to_f64(&r.get::<sqlx::types::BigDecimal,_> ("fees")),

            "avgEscrowSize": if total > 0 { volume / total as f64 } else { 0.0 },
                          }))
        }
        Err(_) => Json(serde_json::json!({"error": "stats unavailable"
        })),
    }
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// NATIVE XRPL ESCROW
//
// Two Xaman approvals: the platform fee as a separate Payment, then the
// EscrowCreate. XRPL's EscrowCreate supports one destination and cannot
// split value, so the fee cannot ride inside it. That is a ledger
// constraint, not a UX oversight.
// ════════════════════════ ════════════════════════ ═══════════════════════

async fn xrpl_escrow_create_start(
    State(state): State<AppState>,
    Extension(claims): Extension<auth::Claims>,
    Json(req): Json<XrplEscrowCreateRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let treasury = state.treasury_address.clone().ok_or(err(
        StatusCode::SERVICE_UNAVAILABLE,
        "Platform treasury not configured",
    ))?;

    check_quota(&state.db, &claims.sub, &claims.plan).await?;

    let is_live: Option<bool> =
        sqlx::query_scalar::<_, bool>("SELECT is_live FROM wallets WHERE address=$1")
            .bind(&req.from)
            .fetch_optional(&state.db)
            .await
            .map_err(db_err)?;
    if is_live != Some(true) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Sender must be a verified live (Xumm) wallet",
        ));
    }
    if req.amount <= 0.0 || req.lock_hours <= 0.0 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Amount and lock duration must be positive",
        ));
    }

    let rate = fee_rate_for_plan(&claims.plan);
    let fee = req.amount * rate;
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid user id"))?;
    let escrow_id = Uuid::new_v4();
    let finish_after = ripple_time_now();
    let cancel_after = ripple_time_from_now((req.lock_hours * 3600.0) as i64);

    sqlx::query(
        "INSERT INTO xrpl_escrows (id, user_id,owner_address,destination_address, amount,
         fee_amount, fee_rate,finish_after, cancel_after,status)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending_fee')",
    )
    .bind(escrow_id)
    .bind(user_id)
    .bind(&req.from)
    .bind(&req.to)
    .bind(f64_to_bd(req.amount))
    .bind(f64_to_bd(fee))
    .bind(f64_to_bd(rate))
    .bind(finish_after as i64)
    .bind(cancel_after as i64)
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    let client = xumm::XummClient::from_env().map_err(|e| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Xumm not configured: {e}"),
        )
    })?;
    let p = client
        .create_payment_request(&req.from, &treasury, (fee * 1_000_000.0).round() as u64)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("Xumm request failed: {e}")))?;

    sqlx::query("INSERT INTO escrow_xumm_payloads (uuid,escrow_id, kind) VALUES ($1,$2,'fee')")
        .bind(&p.uuid)
        .bind(escrow_id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;

    Ok(Json(serde_json::json!({
           "escrowId":escrow_id, "uuid": p.uuid,"qrPng": p.refs.qr_png,
           "deeplink":p.next.always,"websocketStatus":p.refs.websocket_status,
    })))
}

async fn xrpl_escrow_create_status(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let (resolved, txid) = poll_xumm(&uuid).await?;
    if !resolved {
        return Ok(Json(serde_json::json!({"feePaid": false, "pending":true })));
    }
    let Some(txid) = txid else {
        return Ok(Json(
            serde_json::json!({"feePaid": false,"cancelled": true }),
        ));
    };

    let escrow_id = payload_escrow_id(&state.db, &uuid).await?;
    sqlx::query("UPDATE xrpl_escrows SET status='pending_lock',fee_tx_hash=$1 WHERE id=$2")
        .bind(&txid)
        .bind(escrow_id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;

    Ok(Json(
        serde_json::json!({"feePaid": true, "escrowId":escrow_id, "feeTxHash": txid
        }),
    ))
}

async fn xrpl_escrow_lock_start(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let row = sqlx::query(
        "SELECT owner_address,destination_address, amount,finish_after, cancel_after,status
           FROM xrpl_escrows WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?
    .ok_or((StatusCode::NOT_FOUND, "Escrow not found".to_string()))?;

    let status: String = row.get("status");
    if status != "pending_lock" {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("Fee must be confirmed first (status:{status})"),
        ));
    }

    let amount: sqlx::types::BigDecimal = row.get("amount");
    let client = xumm::XummClient::from_env().map_err(|e| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Xumm not configured: {e}"),
        )
    })?;
    let p = client
        .create_escrow_create_request(
            &row.get::<String, _>("owner_address"),
            &row.get::<String, _>("destination_address"),
            (bd_to_f64(&amount) * 1_000_000.0).round() as u64,
            row.get::<i64, _>("finish_after") as u32,
            row.get::<i64, _>("cancel_after") as u32,
        )
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("Xumm request failed: {e}")))?;

    sqlx::query("INSERT INTO escrow_xumm_payloads (uuid,escrow_id, kind) VALUES ($1,$2,'lock')")
        .bind(&p.uuid)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;

    Ok(Json(serde_json::json!({
           "uuid": p.uuid,"qrPng": p.refs.qr_png,
           "deeplink":p.next.always,"websocketStatus":p.refs.websocket_status,
    })))
}

async fn xrpl_escrow_lock_status(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let (resolved, txid) = poll_xumm(&uuid).await?;
    if !resolved {
        return Ok(Json(serde_json::json!({"locked": false, "pending":true })));
    }
    let Some(txid) = txid else {
        return Ok(Json(
            serde_json::json!({"locked": false,"cancelled": true }),
        ));
    };

    let escrow_id = payload_escrow_id(&state.db, &uuid).await?;

    // OfferSequence is required for EscrowFinish/Cancel. Without it the
    // escrow is visible on- ledger and permanently unreleasable.
    let seq = xrpl::XrplClient::new(&state.xrpl_node)
        .get_transaction_sequence(&txid)
        .await
        .map_err(|e| {
            err(
                StatusCode::BAD_GATEWAY,
                format!("Could not resolve escrow sequence yet, retry shortly:{e}"),
            )
        })?;

    sqlx::query(
        "UPDATE xrpl_escrows SET create_tx_hash=$1,create_sequence=$2,status='locked' WHERE id=$3",
    )
    .bind(&txid)
    .bind(seq as i64)
    .bind(escrow_id)
    .execute(&state.db)
    .await
    .map_err(db_err)?;
    ESCROWS_CREATED_TOTAL.fetch_add(1, Ordering::Relaxed);

    Ok(Json(
        serde_json::json!({"locked": true, "escrowId":escrow_id, "txHash": txid
        }),
    ))
}

async fn xrpl_escrow_finish_start(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<XrplEscrowActionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let (owner, seq) = locked_escrow_sequence(&state.db, id).await?;
    let client = xumm::XummClient::from_env().map_err(|e| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Xumm not configured: {e}"),
        )
    })?;
    let p = client
        .create_escrow_finish_request(&req.account, &owner, seq)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("Xumm request failed: {e}")))?;

    sqlx::query("INSERT INTO escrow_xumm_payloads (uuid,escrow_id, kind) VALUES ($1,$2,'finish')")
        .bind(&p.uuid)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;

    Ok(Json(serde_json::json!({
           "uuid": p.uuid,"qrPng": p.refs.qr_png,
           "deeplink":p.next.always,"websocketStatus":p.refs.websocket_status,
    })))
}

async fn xrpl_escrow_finish_status(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let (resolved, txid) = poll_xumm(&uuid).await?;
    if !resolved {
        return Ok(Json(
            serde_json::json!({"released": false,"pending": true }),
        ));
    }
    let Some(txid) = txid else {
        return Ok(Json(
            serde_json::json!({"released": false,"cancelled": true }),
        ));
    };

    let escrow_id = payload_escrow_id(&state.db, &uuid).await?;
    sqlx::query("UPDATE xrpl_escrows SET status='released',finish_tx_hash=$1 WHERE id=$2")
        .bind(&txid)
        .bind(escrow_id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;

    // The attestation covers the escrow's real terms, read back from the
    // row, not just the finish hash.
    let row = sqlx::query(
        "SELECT owner_address, destination_address, amount, fee_amount FROM xrpl_escrows WHERE id=$1",
    )
    .bind(escrow_id)
    .fetch_one(&state.db)
    .await
    .map_err(db_err)?;
    let record = settlement(
        &txid,
        &row.get::<String, _>("owner_address"),
        &row.get::<String, _>("destination_address"),
        xrp_to_drops(&row.get::<sqlx::types::BigDecimal, _>("amount")),
        xrp_to_drops(&row.get::<sqlx::types::BigDecimal, _>("fee_amount")),
        "xrpl_escrow_finish",
    );
    let a = state
        .attestation
        .attest(&record)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Err(e) = store_attestation(&state.db, &a).await {
        tracing::error!(tx = %txid, error = %e, "attestation not stored");
    }
    Ok(Json(serde_json::json!({
           "released": true,"txHash": txid,"quantumProof":a.dilithium_signature,
    })))
}

async fn xrpl_escrow_cancel_start(
    State(state): State<AppState>,
    Extension(claims): Extension<auth::Claims>,
    Path(id): Path<Uuid>,
    Json(req): Json<XrplEscrowActionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let row = sqlx::query(
        "SELECT owner_address,create_sequence, status,cancel_after, user_id
           FROM xrpl_escrows WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?
    .ok_or((StatusCode::NOT_FOUND, "Escrow not found".to_string()))?;

    // Reclaiming returns funds to the originator — only they may start it.
    if let Some(owner_user) = row.get::<Option<Uuid>, _>("user_id") {
        if owner_user.to_string() != claims.sub {
            return Err(err(
                StatusCode::FORBIDDEN,
                "Only the escrow's creator can reclaim it",
            ));
        }
    }
    if row.get::<String, _>("status") != "locked" {
        return Err(err(StatusCode::BAD_REQUEST, "Escrow is not locked"));
    }
    if (ripple_time_now() as i64) < row.get::<i64, _>("cancel_after") {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "CancelAfter has not passed yet",
        ));
    }
    let seq = row.get::<Option<i64>, _>("create_sequence").ok_or(err(
        StatusCode::BAD_REQUEST,
        "Escrow has no recorded sequence yet",
    ))? as u32;

    let client = xumm::XummClient::from_env().map_err(|e| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Xumm not configured: {e}"),
        )
    })?;
    let p = client
        .create_escrow_cancel_request(&req.account, &row.get::<String, _>("owner_address"), seq)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("Xumm request failed: {e}")))?;

    sqlx::query("INSERT INTO escrow_xumm_payloads (uuid,escrow_id, kind) VALUES ($1,$2,'cancel')")
        .bind(&p.uuid)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;

    Ok(Json(serde_json::json!({
           "uuid": p.uuid,"qrPng": p.refs.qr_png,
           "deeplink":p.next.always,"websocketStatus":p.refs.websocket_status,
    })))
}
async fn xrpl_escrow_cancel_status(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let (resolved, txid) = poll_xumm(&uuid).await?;
    if !resolved {
        return Ok(Json(
            serde_json::json!({"refunded": false,"pending": true }),
        ));
    }
    let Some(txid) = txid else {
        return Ok(Json(
            serde_json::json!({"refunded": false,"cancelled": true }),
        ));
    };

    let escrow_id = payload_escrow_id(&state.db, &uuid).await?;
    sqlx::query("UPDATE xrpl_escrows SET status='refunded',cancel_tx_hash=$1 WHERE id=$2")
        .bind(&txid)
        .bind(escrow_id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;

    Ok(Json(serde_json::json!({"refunded": true, "txHash":txid })))
}
async fn list_xrpl_escrows(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let rows = sqlx::query(
        "SELECT id,owner_address,destination_address, amount,cancel_after, status,

 create_tx_hash,create_sequence
          FROM xrpl_escrows WHERE owner_address=$1 OR destination_address=$1
          ORDER BY created_at DESC",
    )
    .bind(&address)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let escrows: Vec<_> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                  "id": r.get::<Uuid,_>("id"),
                  "from": r.get::<String,_>("owner_address"),
                  "to": r.get::<String,_> ("destination_address"),
                  "amount":bd_to_f64(&r.get::<sqlx::types::BigDecimal,_> ("amount")),
                  "canCancel":(ripple_time_now() as i64)>= r.get::<i64,_> ("cancel_after"),
                  "status": r.get::<String,_>("status"),
                "createTxHash":r.get::<Option<String>,_> ("create_tx_hash"),
                // Required to release the escrow — surfaced so it can be recorded.
                "offerSequence":r.get::<Option<i64>,_> ("create_sequence"),
            })
        })
        .collect();

    Json(serde_json::json!({"escrows": escrows }))
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// HELPERS
// ════════════════════════ ════════════════════════ ═══════════════════════

/// Poll a Xumm payload. Returns (resolved, txid) — txid is None when the
/// user cancelled or it expired.
async fn poll_xumm(uuid: &str) -> Result<(bool, Option<String>), ApiError> {
    let client = xumm::XummClient::from_env().map_err(|e| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Xumm not configured: {e}"),
        )
    })?;
    let s = client
        .get_payload_status(uuid)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("Xumm status failed:{e}")))?;

    if s.meta.cancelled || s.meta.expired {
        return Ok((true, None));
    }
    if !s.meta.resolved || !s.meta.signed {
        return Ok((false, None));
    }
    Ok((true, s.response.and_then(|r| r.txid)))
}

async fn payload_escrow_id(db: &PgPool, uuid: &str) -> Result<Uuid, ApiError> {
    sqlx::query_scalar::<_, Uuid>("SELECT escrow_id FROM escrow_xumm_payloads WHERE uuid=$1")
        .bind(uuid)
        .fetch_optional(db)
        .await
        .map_err(db_err)?
        .ok_or(err(StatusCode::NOT_FOUND, "Unknown payload"))
}

async fn locked_escrow_sequence(db: &PgPool, id: Uuid) -> Result<(String, u32), ApiError> {
    let row =
        sqlx::query("SELECT owner_address,create_sequence, status FROM xrpl_escrows WHERE id=$1")
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(db_err)?
            .ok_or(err(StatusCode::NOT_FOUND, "Escrow not found"))?;

    if row.get::<String, _>("status") != "locked" {
        return Err(err(StatusCode::BAD_REQUEST, "Escrow is not locked"));
    }
    let seq = row.get::<Option<i64>, _>("create_sequence").ok_or(err(
        StatusCode::BAD_REQUEST,
        "Escrow has no recorded sequence yet",
    ))? as u32;
    Ok((row.get::<String, _>("owner_address"), seq))
}

async fn fetch_escrow(db: &PgPool, id: Uuid) -> Result<EscrowRow, ApiError> {
    sqlx::query_as::<_,EscrowRow>(
           "SELECT id,from_address, to_address,amount, fee_paid, status,created_at, expires_at,quantum_proof
            FROM escrows WHERE id=$1",

 ).bind(id).fetch_optional(db).await.map_err(db_err)?.ok_or(err(StatusCode::NOT_FOUND, "Escrow not found"))
}

fn escrow_json(e: &EscrowRow) -> serde_json::Value {
    serde_json::json!({
         "id":e.id.to_string(),
         "from":e.from_address, "to":e.to_address,
         "amount":bd_to_f64(&e.amount),"status": e.status,
         "quantumProof":e.quantum_proof,
         "timeRemaining":e.expires_at.map(|x| (x -Utc::now()).num_seconds().max(0)),
    })
}

/// XRP (decimal, 6 places) to drops as an exact integer string. Never via
/// f64: the attestation must cover exactly the amount that settled.
fn xrp_to_drops(xrp: &sqlx::types::BigDecimal) -> String {
    (xrp.clone() * sqlx::types::BigDecimal::from(1_000_000i64))
        .with_scale(0)
        .to_string()
}

/// A settlement record for the attestor. `ledger` is always XRPL here.
fn settlement(
    tx_hash: &str,
    from: &str,
    to: &str,
    amount_drops: String,
    fee_drops: String,
    kind: &str,
) -> SettlementRecord {
    SettlementRecord {
        tx_hash: tx_hash.to_string(),
        from_address: from.to_string(),
        to_address: to.to_string(),
        amount: amount_drops,
        fee: fee_drops,
        ledger: "xrpl".to_string(),
        kind: kind.to_string(),
        timestamp: chrono::Utc::now().timestamp().max(0) as u64,
    }
}

/// Persist an attestation. Idempotent on tx_hash, so a retried handler
/// cannot create a second, different attestation for the same settlement.
async fn store_attestation<'e, E>(db: E, a: &Attestation) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO attestations
            (tx_hash, dilithium_signature, public_key, signer_fingerprint, device_id, timestamp)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (tx_hash) DO NOTHING",
    )
    .bind(&a.tx_hash)
    .bind(&a.dilithium_signature)
    .bind(&a.public_key)
    .bind(&a.signer_fingerprint)
    .bind(&a.device_id)
    .bind(a.timestamp as i64)
    .execute(db)
    .await?;
    Ok(())
}

fn bd_to_f64(b: &sqlx::types::BigDecimal) -> f64 {
    use std::str::FromStr;

    f64::from_str(&b.to_string()).unwrap_or(0.0)
}

fn f64_to_bd(v: f64) -> sqlx::types::BigDecimal {
    use std::str::FromStr;

    sqlx::types::BigDecimal::from_str(&format!("{v:.6}")).unwrap_or_default()
}
/// Local identifier for demo-mode transactions. Never presented as an
/// on-ledger hash — the `status` field distinguishes them.
fn local_tx_hash(from: &str, to: &str, amount: f64) -> String {
    let mut h = Sha256::new();

    h.update(from.as_bytes());
    h.update(to.as_bytes());

    h.update(amount.to_string().as_bytes());

    h.update(
        Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or(0)
            .to_string()
            .as_bytes(),
    );
    format!("0x{}", hex::encode(h.finalize()))
}

fn relative_time(ts: DateTime<Utc>) -> String {
    let d = Utc::now().signed_duration_since(ts).num_seconds();
    if d < 60 {
        "Just now".into()
    } else if d < 3600 {
        format!("{} minutes ago", d / 60)
    } else if d < 86400 {
        format!("{} hours ago", d / 3600)
    } else {
        format!("{} days ago", d / 86400)
    }
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// TESTS
// ════════════════════════ ════════════════════════ ═══════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_tiers_match_the_published_pricing() {
        assert_eq!(fee_rate_for_plan("free"), 0.003);
        assert_eq!(fee_rate_for_plan("pro"), 0.002);
        assert_eq!(fee_rate_for_plan("enterprise"), 0.0015);
        // Anything unrecognised must fall back to the most expensive tier,
        // never the cheapest.
        assert_eq!(fee_rate_for_plan("nonsense "), FEE_RATE_FREE);
    }

    #[test]
    fn pro_is_cheaper_than_free_and_enterprise_cheapest() {
        assert!(fee_rate_for_plan("pro") < fee_rate_for_plan("free"));
        assert!(fee_rate_for_plan("enterprise") < fee_rate_for_plan("pro"));
    }

    #[test]
    fn ripple_epoch_offset_is_correct() {
        assert_eq!(RIPPLE_EPOCH_OFFSET, 946_684_800);
        let now_unix = Utc::now().timestamp();
        assert_eq!(now_unix - ripple_time_now() as i64, RIPPLE_EPOCH_OFFSET);
    }

    #[test]
    fn ripple_time_advances_as_expected() {
        let delta = ripple_time_from_now(3600) as i64 - ripple_time_now() as i64;
        assert!((3598..=3602).contains(&delta));
    }

    #[test]
    fn decimal_conversion_preserves_six_places() {
        for v in [0.0, 1.0, 0.000001, 123.456789] {
            assert!((bd_to_f64(&f64_to_bd(v)) - v).abs() < 0.0000005);
        }
    }

    #[test]
    fn local_hashes_are_unique_and_well_formed() {
        let a = local_tx_hash("alice", "bob", 10.0);
        let b = local_tx_hash("alice", "bob", 10.0);
        assert_ne!(a, b);
        assert!(a.starts_with("0x"));
        assert_eq!(a.len(), 66);
    }

    /// Guards the merge: Q- Lock must use Dilithium5 via godshield-core, not
    /// the Dilithium3 it called directly before.
    #[test]
    fn attestation_uses_dilithium5_not_dilithium3() {
        let kp = godshield_core::GodKeyPair::generate().unwrap();
        assert_eq!(kp.public_key.len(), 2592, "Dilithium5 public key size");
    }
}
