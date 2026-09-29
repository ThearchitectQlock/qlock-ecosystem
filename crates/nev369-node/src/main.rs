// crates/nev369-node/src/main.rs
//
// ═══════════════════════════════════════════════════════════════════════
// NEV369 NODE — HTTP API, background miner, P2P wiring
//
// chain.rs holds the engine (persistence, mempool, candidate assembly,
// block acceptance with fork choice and reorg). p2p.rs holds gossip and
// sync. This binary loads config, builds the engine, starts the network,
// optionally mines, and serves the HTTP surface the explorer, the Q-Lock
// console and Prometheus read.
//
// HTTP surface
//
//   GET  /health                 liveness + height
//   GET  /info                   tip, difficulty, supply, reward, work
//   GET  /chain?limit=N          most recent N blocks (≤ 200), ascending
//   GET  /block/{index|hash}     one block; block 0 carries the dedication
//   GET  /tx/{hash}              a confirmed or pending transaction
//   GET  /balance/{address}      balance in base units and NEV, nonce
//   GET  /mempool                pending transactions (first 100)
//   GET  /vault/nevaeh           the time-locked vault, publicly verifiable
//   GET  /metrics                Prometheus exposition
//   POST /tx/submit              signed transaction (rate limited)
//   POST /mine                   one bounded PoW attempt (dev, or opt-in)
//   POST /wallet/new             development-only keypair generator
//
// Every transaction in a block response carries its `hash`, so the
// explorer can link and search transactions without recomputing
// TripleHash in the browser.
// ═══════════════════════════════════════════════════════════════════════

mod chain;
mod checkpoints;
mod consensus;
mod genesis;
mod p2p;
mod sync;

use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::http::header;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing_subscriber::{fmt, EnvFilter};

use chain::{format_nev, Block, BlockchainApp, Transaction};
use checkpoints::Checkpoints;
use genesis::GenesisConfig;
use p2p::{NetworkCommand, NetworkCommandSender, NetworkConfig, SharedCheckpoints, SharedState};

/// Blocks produced by this process (background miner + /mine).
static BLOCKS_MINED: AtomicU64 = AtomicU64::new(0);
/// Transactions accepted over HTTP.
static TX_ACCEPTED: AtomicU64 = AtomicU64::new(0);
static TX_REJECTED: AtomicU64 = AtomicU64::new(0);

// ═══════════════════════════════════════════════════════════════════════
// CONFIG & LOGGING
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub db_path: String,
    pub bind_addr: String,
    pub bind_port: u16,
    pub allowed_origins: Vec<String>,
    pub mine_rate_limit_per_min: u32,
    pub tx_rate_limit_per_min: u32,
    pub environment: String,
    /// Run the background miner.
    pub mining_enabled: bool,
    /// Where the background miner's block rewards go.
    pub miner_address: Option<String>,
    /// Allow POST /mine. On by default outside production.
    pub http_mining: bool,
}

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_flag(key: &str) -> Option<bool> {
    // Blank counts as unset, so `NEV369_HTTP_MINING=` in a .env keeps the
    // environment default rather than silently meaning "off".
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
}

impl NodeConfig {
    pub fn load() -> Self {
        dotenvy::dotenv().ok();
        let environment = std::env::var("NEV369_ENV").unwrap_or_else(|_| "development".to_string());
        let production = environment == "production";
        let allowed_origins = std::env::var("NEV369_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();

        let config = Self {
            db_path: std::env::var("NEV369_DB_PATH")
                .unwrap_or_else(|_| "./data/nev369.db".to_string()),
            bind_addr: std::env::var("NEV369_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string()),
            bind_port: env_or("NEV369_BIND_PORT", 8080),
            allowed_origins,
            mine_rate_limit_per_min: env_or("NEV369_MINE_RATE_LIMIT", 6),
            tx_rate_limit_per_min: env_or("NEV369_TX_RATE_LIMIT", 60),
            mining_enabled: env_flag("NEV369_MINING").unwrap_or(false),
            miner_address: std::env::var("NEV369_MINER_ADDRESS")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            http_mining: env_flag("NEV369_HTTP_MINING").unwrap_or(!production),
            environment,
        };

        if production {
            if config.allowed_origins.iter().any(|o| o == "*") {
                panic!("NEV369_ALLOWED_ORIGINS cannot be '*' in production.");
            }
            if config
                .allowed_origins
                .iter()
                .any(|o| o.contains("localhost"))
            {
                tracing::warn!("production config still includes a localhost origin");
            }
        }
        if config.mining_enabled && config.miner_address.is_none() {
            panic!(
                "NEV369_MINING is on but NEV369_MINER_ADDRESS is not set — \
                 block rewards would have nowhere to go"
            );
        }
        config
    }

    fn production(&self) -> bool {
        self.environment == "production"
    }
}

fn init_logging(environment: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if environment == "production" {
        fmt()
            .with_env_filter(filter)
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .init();
    } else {
        fmt().with_env_filter(filter).pretty().init();
    }
}

// ═══════════════════════════════════════════════════════════════════════
// JSON HELPERS
// ═══════════════════════════════════════════════════════════════════════

fn tx_json(tx: &Transaction) -> serde_json::Value {
    let mut v = serde_json::to_value(tx).unwrap_or(serde_json::Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.insert("hash".into(), tx.hash().into());
    }
    v
}

/// A block with each transaction annotated by its hash.
fn block_json(b: &Block) -> serde_json::Value {
    let mut v = serde_json::to_value(b).unwrap_or(serde_json::Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.insert(
            "transactions".into(),
            b.transactions
                .iter()
                .map(tx_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    v
}

fn not_found(what: &str) -> HttpResponse {
    HttpResponse::NotFound().json(serde_json::json!({ "error": format!("{what} not found") }))
}

// ═══════════════════════════════════════════════════════════════════════
// READ ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════

#[get("/health")]
async fn health(data: web::Data<SharedState>) -> impl Responder {
    let app = data.read().await;
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "height": app.height(),
        "node_id": app.node_id,
    }))
}

#[get("/info")]
async fn get_info(data: web::Data<SharedState>) -> impl Responder {
    let app = data.read().await;
    let height = app.height();
    let reward = app.block_reward();
    let difficulty = app.next_difficulty();
    HttpResponse::Ok().json(serde_json::json!({
        "chain": "NEV369",
        "height": height,
        "latest_hash": app.latest_hash(),
        "difficulty": difficulty,
        "mempool_size": app.mempool.len(),
        "block_reward": reward,
        "block_reward_nev": format_nev(reward),
        "circulating_supply": app.circulating_supply(),
        "circulating_supply_nev": format_nev(app.circulating_supply()),
        "max_supply": chain::MAX_SUPPLY,
        "mineable_supply": chain::MINEABLE_SUPPLY,
        "total_burned": app.total_burned,
        "cumulative_work": app.cumulative_work().to_string(),
        "target_block_seconds": chain::TARGET_BLOCK_SECONDS,
        "halving_interval": chain::HALVING_INTERVAL,
        "decimals": chain::DECIMALS,
        "node_id": app.node_id,
        "peers": p2p::CONNECTED_PEERS.load(std::sync::atomic::Ordering::Relaxed),
        "signature_scheme": "GodShield (Dilithium5 + SHA3-512 → BLAKE3 → SHA3-512)",
        "canonicalization": "CanonicalMessage v1 (length-prefixed, domain-separated)",
        // Earlier field names, kept so older dashboards keep working.
        "chain_height": height,
        "next_difficulty": difficulty,
    }))
}

#[derive(Deserialize)]
struct ChainQuery {
    limit: Option<usize>,
}

#[get("/chain")]
async fn get_chain(data: web::Data<SharedState>, q: web::Query<ChainQuery>) -> impl Responder {
    let app = data.read().await;
    // Capped: the full chain unbounded is a trivial memory-exhaustion
    // vector once it is long.
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let start = app.chain.len().saturating_sub(limit);
    let blocks: Vec<_> = app.chain[start..].iter().map(block_json).collect();
    HttpResponse::Ok().json(serde_json::json!({
        "height": app.height(),
        "latest_hash": app.latest_hash(),
        "blocks": blocks,
    }))
}

/// Legacy alias for older frontends: same data as /chain.
#[get("/explorer")]
async fn get_explorer(data: web::Data<SharedState>) -> impl Responder {
    let app = data.read().await;
    let start = app.chain.len().saturating_sub(50);
    let blocks: Vec<_> = app.chain[start..].iter().map(block_json).collect();
    HttpResponse::Ok().json(serde_json::json!({
        "chain_height": app.height(),
        "latest_block_hash": app.latest_hash(),
        "chain": blocks,
    }))
}

#[get("/block/{id}")]
async fn get_block(data: web::Data<SharedState>, id: web::Path<String>) -> impl Responder {
    let app = data.read().await;
    let id = id.into_inner();
    let found = match id.parse::<usize>() {
        Ok(i) => app.chain.get(i),
        Err(_) => app.chain.iter().rev().find(|b| b.hash == id),
    };
    match found {
        Some(b) => {
            let mut v = block_json(b);
            if let Some(o) = v.as_object_mut() {
                o.insert(
                    "confirmations".into(),
                    (app.height().saturating_sub(b.index)).into(),
                );
            }
            HttpResponse::Ok().json(v)
        }
        None => not_found("block"),
    }
}

#[get("/tx/{hash}")]
async fn get_tx(data: web::Data<SharedState>, hash: web::Path<String>) -> impl Responder {
    let app = data.read().await;
    let hash = hash.into_inner();
    for b in app.chain.iter().rev() {
        if let Some(tx) = b.transactions.iter().find(|t| t.hash() == hash) {
            return HttpResponse::Ok().json(serde_json::json!({
                "status": "confirmed",
                "block_index": b.index,
                "block_hash": b.hash,
                "confirmations": app.height().saturating_sub(b.index),
                "transaction": tx_json(tx),
            }));
        }
    }
    if let Some(tx) = app.mempool.iter().find(|t| t.hash() == hash) {
        return HttpResponse::Ok().json(serde_json::json!({
            "status": "pending",
            "transaction": tx_json(tx),
        }));
    }
    not_found("transaction")
}

#[get("/balance/{address}")]
async fn get_balance(data: web::Data<SharedState>, address: web::Path<String>) -> impl Responder {
    let app = data.read().await;
    let addr = address.into_inner();
    let units = app.balances.get(&addr).copied().unwrap_or(0);
    let pending_out: u64 = app
        .mempool
        .iter()
        .filter(|t| t.sender == addr)
        .map(|t| t.total_cost().unwrap_or(0))
        .fold(0u64, |a, b| a.saturating_add(b));
    HttpResponse::Ok().json(serde_json::json!({
        "address": addr,
        "balance": format_nev(units),
        "balance_units": units,
        "pending_outgoing_units": pending_out,
        "nonce": app.nonces.get(&addr).copied().unwrap_or(0),
        "timelocked": app.genesis_config.is_timelocked(&addr)
            && chain::now() < app.genesis_config.nevaeh_unlock_timestamp,
    }))
}

#[derive(Deserialize)]
struct HistoryQuery {
    limit: Option<usize>,
}

/// Transactions to and from one address: confirmed (newest first) and
/// pending in the mempool. Read by the wallet and the explorer's address page.
#[get("/address/{address}/transactions")]
async fn get_address_transactions(
    data: web::Data<SharedState>,
    address: web::Path<String>,
    q: web::Query<HistoryQuery>,
) -> impl Responder {
    let addr = address.into_inner();
    if addr.is_empty() || addr.len() > 6000 {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "invalid address" }));
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let app = data.read().await;
    let tip = app.height().saturating_sub(1);
    let direction = |t: &Transaction| {
        if t.sender == addr && t.recipient == addr {
            "self"
        } else if t.sender == addr {
            "out"
        } else {
            "in"
        }
    };
    let confirmed: Vec<_> = app
        .address_history(&addr, limit)
        .into_iter()
        .map(|(height, timestamp, t)| {
            serde_json::json!({
                "hash": t.hash(),
                "height": height,
                "block_timestamp": timestamp,
                "confirmations": tip.saturating_sub(height) + 1,
                "direction": direction(t),
                "sender": t.sender,
                "recipient": t.recipient,
                "amount_units": t.amount,
                "fee_units": t.fee,
                "memo": t.payload_memo,
            })
        })
        .collect();
    let pending: Vec<_> = app
        .mempool
        .iter()
        .filter(|t| t.sender == addr || t.recipient == addr)
        .map(|t| {
            serde_json::json!({
                "hash": t.hash(),
                "direction": direction(t),
                "sender": t.sender,
                "recipient": t.recipient,
                "amount_units": t.amount,
                "fee_units": t.fee,
                "memo": t.payload_memo,
            })
        })
        .collect();
    HttpResponse::Ok().json(serde_json::json!({
        "address": addr,
        "chain_height": app.height(),
        "transactions": confirmed,
        "pending": pending,
    }))
}

/// Top balances, capped. Everything is public on-chain anyway; the cap
/// only stops one request serialising the whole state.
#[get("/wallets")]
async fn get_wallets(data: web::Data<SharedState>) -> impl Responder {
    let app = data.read().await;
    let mut rows: Vec<(&String, &u64)> = app.balances.iter().filter(|(_, v)| **v > 0).collect();
    rows.sort_by(|a, b| b.1.cmp(a.1));
    let top: Vec<_> = rows
        .into_iter()
        .take(100)
        .map(|(a, u)| serde_json::json!({ "address": a, "balance_units": u, "balance": format_nev(*u) }))
        .collect();
    HttpResponse::Ok().json(serde_json::json!({ "wallets": top }))
}

#[get("/mempool")]
async fn get_mempool(data: web::Data<SharedState>) -> impl Responder {
    let app = data.read().await;
    let txs: Vec<_> = app.mempool.iter().take(100).map(tx_json).collect();
    HttpResponse::Ok().json(serde_json::json!({
        "size": app.mempool.len(),
        "transactions": txs,
    }))
}

/// Public status of Nevaeh's vault. Readable by anyone on purpose — the
/// lock being independently verifiable is the point of it.
#[get("/vault/nevaeh")]
async fn get_vault(data: web::Data<SharedState>) -> impl Responder {
    let app = data.read().await;
    let cfg = &app.genesis_config;
    let now = chain::now();
    let remaining = cfg.nevaeh_unlock_timestamp.saturating_sub(now);
    let units = app
        .balances
        .get(&cfg.nevaeh_vault_address)
        .copied()
        .unwrap_or(0);
    HttpResponse::Ok().json(serde_json::json!({
        "address": cfg.nevaeh_vault_address,
        "balance": format_nev(units),
        "balance_units": units,
        "premine_units": cfg.nevaeh_premine,
        "locked": now < cfg.nevaeh_unlock_timestamp,
        "unlocks_at": cfg.nevaeh_unlock_timestamp,
        "unlocks_on": "2039-07-28",
        "days_remaining": remaining / 86_400,
        "dedication": chain::GENESIS_DEDICATION,
    }))
}

#[get("/metrics")]
async fn metrics(data: web::Data<SharedState>) -> impl Responder {
    let app = data.read().await;
    let mut out = String::with_capacity(2048);
    let mut g = |name: &str, help: &str, kind: &str, value: String| {
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        ));
    };
    g(
        "nev369_height",
        "Canonical chain height (blocks).",
        "gauge",
        app.height().to_string(),
    );
    g(
        "nev369_difficulty",
        "Difficulty required for the next block.",
        "gauge",
        app.next_difficulty().to_string(),
    );
    g(
        "nev369_mempool_size",
        "Pending transactions.",
        "gauge",
        app.mempool.len().to_string(),
    );
    g(
        "nev369_mempool_capacity",
        "Mempool capacity.",
        "gauge",
        chain::MAX_MEMPOOL.to_string(),
    );
    g(
        "nev369_cumulative_work",
        "Accumulated proof of work on the canonical chain.",
        "gauge",
        app.cumulative_work().to_string(),
    );
    g(
        "nev369_circulating_supply_units",
        "Circulating supply in base units.",
        "gauge",
        app.circulating_supply().to_string(),
    );
    g(
        "nev369_block_reward_units",
        "Reward for the next block in base units.",
        "gauge",
        app.block_reward().to_string(),
    );
    g(
        "nev369_burned_units_total",
        "Crown tax burned, base units.",
        "counter",
        app.total_burned.to_string(),
    );
    g(
        "nev369_reorgs_total",
        "Reorganisations since start.",
        "counter",
        chain::REORG_COUNT.load(Ordering::Relaxed).to_string(),
    );
    g(
        "nev369_deepest_reorg_blocks",
        "Deepest reorganisation since start.",
        "gauge",
        chain::DEEPEST_REORG.load(Ordering::Relaxed).to_string(),
    );
    g(
        "nev369_blocks_mined_total",
        "Blocks this node produced.",
        "counter",
        BLOCKS_MINED.load(Ordering::Relaxed).to_string(),
    );
    g(
        "nev369_tx_accepted_total",
        "Transactions accepted over HTTP.",
        "counter",
        TX_ACCEPTED.load(Ordering::Relaxed).to_string(),
    );
    g(
        "nev369_tx_rejected_total",
        "Transactions rejected over HTTP.",
        "counter",
        TX_REJECTED.load(Ordering::Relaxed).to_string(),
    );
    let tip_age = app
        .chain
        .last()
        .map(|b| chain::now().saturating_sub(b.timestamp))
        .unwrap_or(0);
    g(
        "nev369_tip_age_seconds",
        "Seconds since the tip block's timestamp.",
        "gauge",
        tip_age.to_string(),
    );
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(out)
}

// ═══════════════════════════════════════════════════════════════════════
// WRITE ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════

async fn submit_transaction(
    data: web::Data<SharedState>,
    network_cmd: web::Data<NetworkCommandSender>,
    tx: web::Json<Transaction>,
) -> impl Responder {
    let tx = tx.into_inner();
    let mut app = data.write().await;
    match app.submit_transaction(tx.clone()) {
        Ok(hash) => {
            drop(app);
            TX_ACCEPTED.fetch_add(1, Ordering::Relaxed);
            let _ = network_cmd.send(NetworkCommand::BroadcastTransaction(tx));
            HttpResponse::Ok()
                .json(serde_json::json!({ "accepted": true, "tx_hash": hash, "hash": hash }))
        }
        Err(e) => {
            TX_REJECTED.fetch_add(1, Ordering::Relaxed);
            HttpResponse::BadRequest()
                .json(serde_json::json!({ "accepted": false, "error": e.to_string() }))
        }
    }
}

#[derive(Debug, Deserialize)]
struct MineRequest {
    #[serde(alias = "miner")]
    miner_address: String,
}

/// Upper bound on one HTTP mining attempt. A request holding a blocking
/// thread indefinitely is a denial of service against the node itself.
const HTTP_MINE_BUDGET: Duration = Duration::from_secs(20);

async fn mine_block(
    data: web::Data<SharedState>,
    network_cmd: web::Data<NetworkCommandSender>,
    config: web::Data<NodeConfig>,
    req: web::Json<MineRequest>,
) -> impl Responder {
    if !config.http_mining {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "HTTP mining is disabled on this node (set NEV369_HTTP_MINING=1 to allow it)"
        }));
    }
    let miner = req.into_inner().miner_address.trim().to_string();
    if miner.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "miner_address is required" }));
    }

    let candidate = data.read().await.build_candidate(&miner);
    let height = candidate.index;
    let mined = web::block(move || mine_until(candidate, Instant::now() + HTTP_MINE_BUDGET)).await;

    let block = match mined {
        Ok((Some(b), _)) => b,
        Ok((None, _)) => {
            return HttpResponse::Accepted().json(serde_json::json!({
                "mined": false,
                "height": height,
                "message": "no valid hash within the time budget — try again",
            }))
        }
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "mining task failed" }))
        }
    };

    let mut app = data.write().await;
    match app.accept_block(block.clone()) {
        Ok(outcome) => {
            BLOCKS_MINED.fetch_add(1, Ordering::Relaxed);
            let body = serde_json::json!({
                "mined": true,
                "height": app.height(),
                "hash": block.hash,
                "latest_hash": app.latest_hash(),
                "outcome": format!("{outcome:?}"),
            });
            drop(app);
            let _ = network_cmd.send(NetworkCommand::BroadcastBlock(block));
            HttpResponse::Ok().json(body)
        }
        // Our candidate failing acceptance means the tip moved under us
        // (a peer's block landed mid-search) — a race, not a bug.
        Err(e) => HttpResponse::Conflict().json(serde_json::json!({
            "mined": false,
            "error": format!("candidate rejected, tip likely moved: {e}"),
        })),
    }
}

/// Development-only keypair generator for testnets and local play.
///
/// Returns the secret exactly once and keeps nothing. Refused in
/// production: a key generated on a server is a key the server operator
/// could have kept. Real keys come from `godshield vault create`, offline.
#[post("/wallet/new")]
async fn new_wallet(config: web::Data<NodeConfig>) -> impl Responder {
    if config.production() {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "wallet generation is disabled in production — generate keys offline \
                      with `godshield vault create`"
        }));
    }
    let kp = match godshield_core::GodKeyPair::generate() {
        Ok(kp) => kp,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": e.to_string() }))
        }
    };
    let keypair_json = match kp.to_json() {
        Ok(j) => j,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": e.to_string() }))
        }
    };
    HttpResponse::Ok().json(serde_json::json!({
        "address": hex::encode(&kp.public_key),
        "public_key_hex": hex::encode(&kp.public_key),
        "secret_key_hex": hex::encode(kp.secret_key_bytes()),
        "fingerprint": kp.fingerprint,
        "keypair_json": keypair_json,
        "environment": config.environment,
        "note": "Development key. Returned once, stored nowhere. Never hold real value with it.",
    }))
}

// ═══════════════════════════════════════════════════════════════════════
// MINING
// ═══════════════════════════════════════════════════════════════════════

/// Search nonces until a hash meets difficulty or the deadline passes.
/// Returns the block if one was found, and how many hashes were tried.
///
/// The transaction root cannot change while only the nonce does, so it is
/// computed once here. Recomputing it on every attempt — a TripleHash of
/// each transaction (the coinbase alone carries a 5,184-character address)
/// plus the Merkle layers — was most of the cost of each hash.
fn mine_until(mut block: Block, deadline: Instant) -> (Option<Block>, u64) {
    let tx_root = Block::tx_root(&block.transactions);
    let mut n: u64 = 0;
    loop {
        block.hash = block.calculate_hash_with_root(&tx_root);
        n += 1;
        if block.meets_difficulty() {
            return (Some(block), n);
        }
        block.nonce = block.nonce.wrapping_add(1);
        if n % 1024 == 0 && Instant::now() >= deadline {
            return (None, n);
        }
    }
}

/// Background proof-of-work loop.
///
/// Hashing runs on the blocking pool — a tight PoW loop on the async
/// executor would starve the HTTP server and the P2P event loop. Each
/// round is bounded, so the miner regularly rebuilds its candidate and
/// never grinds on a height a peer has already filled. A hash rate is
/// logged every 30 seconds so a quiet miner is visibly working.
async fn run_miner(state: SharedState, network_cmd: NetworkCommandSender, miner: String) {
    const ROUND: Duration = Duration::from_secs(5);
    const REPORT_EVERY: Duration = Duration::from_secs(30);
    tracing::info!(
        miner = %&miner[..miner.len().min(16)],
        "background miner started"
    );
    let mut hashes: u64 = 0;
    let mut since = Instant::now();
    loop {
        let candidate = state.read().await.build_candidate(&miner);
        let height = candidate.index;
        let difficulty = candidate.difficulty;
        let mined =
            tokio::task::spawn_blocking(move || mine_until(candidate, Instant::now() + ROUND))
                .await;
        match mined {
            Ok((found, tried)) => {
                hashes += tried;
                if since.elapsed() >= REPORT_EVERY {
                    let rate = hashes as f64 / since.elapsed().as_secs_f64();
                    tracing::info!(height, difficulty, hashes_per_sec = rate as u64, "mining");
                    hashes = 0;
                    since = Instant::now();
                }
                let Some(block) = found else {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                };
                let mut app = state.write().await;
                if block.index != app.height() {
                    // A peer's block arrived while we were hashing.
                    continue;
                }
                let reward = format_nev(app.block_reward());
                match app.accept_block(block.clone()) {
                    Ok(outcome) => {
                        BLOCKS_MINED.fetch_add(1, Ordering::Relaxed);
                        drop(app);
                        tracing::info!(height, %reward, ?outcome, "block mined");
                        let _ = network_cmd.send(NetworkCommand::BroadcastBlock(block));
                    }
                    Err(e) => tracing::warn!(height, error = %e, "self-mined block rejected"),
                }
            }
            Err(e) => {
                tracing::error!(error = ?e, "mining task panicked");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = NodeConfig::load();
    init_logging(&config.environment);
    tracing::info!(environment = %config.environment, db_path = %config.db_path, "NEV369 node starting");

    std::fs::create_dir_all(
        std::path::Path::new(&config.db_path)
            .parent()
            .unwrap_or_else(|| std::path::Path::new(".")),
    )
    .ok();

    let genesis_config = GenesisConfig::from_env(&config.environment)
        .and_then(|c| c.validate().map(|_| c))
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "invalid genesis configuration");
            std::process::exit(1);
        });

    let blockchain = BlockchainApp::new(&config.db_path, genesis_config).unwrap_or_else(|e| {
        tracing::error!(error = %e, "failed to initialize blockchain state");
        std::process::exit(1);
    });
    tracing::info!(
        height = blockchain.height(),
        supply = %format_nev(blockchain.circulating_supply()),
        node_id = %blockchain.node_id,
        "chain loaded"
    );

    let app_state: SharedState = Arc::new(RwLock::new(blockchain));
    let checkpoints: SharedCheckpoints = Arc::new(RwLock::new(Checkpoints::new()));

    let network_cmd = p2p::spawn_network(
        app_state.clone(),
        checkpoints.clone(),
        NetworkConfig::from_env(),
    )
    .await
    .expect("failed to start P2P network layer");

    if config.mining_enabled {
        let miner = config
            .miner_address
            .clone()
            .expect("checked in NodeConfig::load");
        tokio::spawn(run_miner(app_state.clone(), network_cmd.clone(), miner));
    } else {
        tracing::info!("background mining disabled (NEV369_MINING=1 to enable)");
    }

    let mine_governor = GovernorConfigBuilder::default()
        .per_second((60 / config.mine_rate_limit_per_min.max(1) as u64).max(1))
        .burst_size(2)
        .finish()
        .expect("valid governor config");
    let tx_governor = GovernorConfigBuilder::default()
        .per_second((60 / config.tx_rate_limit_per_min.max(1) as u64).max(1))
        .burst_size(10)
        .finish()
        .expect("valid governor config");

    let bind_addr = format!("{}:{}", config.bind_addr, config.bind_port);
    tracing::info!(addr = %bind_addr, "HTTP API listening");
    let shared_config = web::Data::new(config.clone());

    HttpServer::new(move || {
        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![header::CONTENT_TYPE, header::ACCEPT])
            .max_age(3600);
        for origin in &config.allowed_origins {
            cors = if origin == "*" {
                cors.allow_any_origin()
            } else {
                cors.allowed_origin(origin)
            };
        }

        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .app_data(web::Data::new(network_cmd.clone()))
            .app_data(shared_config.clone())
            .wrap(cors)
            .service(health)
            .service(get_info)
            .service(get_chain)
            .service(get_explorer)
            .service(get_block)
            .service(get_tx)
            .service(get_balance)
            .service(get_address_transactions)
            .service(get_wallets)
            .service(get_mempool)
            .service(get_vault)
            .service(metrics)
            .service(new_wallet)
            // Per-route limits on resources, not empty-prefix scopes: a
            // `scope("")` matches every path and never falls through, so a
            // second one after it is unreachable.
            .service(
                web::resource("/tx/submit")
                    .wrap(Governor::new(&tx_governor))
                    .route(web::post().to(submit_transaction)),
            )
            .service(
                web::resource("/mine")
                    .wrap(Governor::new(&mine_governor))
                    .route(web::post().to(mine_block)),
            )
    })
    .bind(&bind_addr)?
    .run()
    .await
}
