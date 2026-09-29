// crates/nev369-submitter/src/main.rs
//
// ═══════════════════════════════════════════════════════════════════════
// NEV369 BRIDGE SUBMITTER
//
// The last link. The coordinator collects m-of-n signatures and decides
// a mint is authorized; this process carries those signatures to
// `NEV369Bridge.mintFromNEV369` on Ethereum.
//
// ── THE KEY THIS HOLDS, AND WHAT IT CANNOT DO ─────────────────────────
//
// It holds an Ethereum private key, and that key exists to PAY GAS.
//
// The contract ignores the caller. The signatures authorize. So this key
// can waste gas, submit late, or withhold a mint entirely — it cannot
// CREATE a mint, because it cannot produce the m secp256k1 signatures the
// contract recovers and checks against the signer set.
//
// That property is why this is a separate binary. The coordinator holds
// no key of any kind, and keeping a gas key out of it keeps that true.
// It is also why you can run several of these at once for redundancy:
// they race, the contract accepts exactly one, and the losers read
// `AlreadyProcessed` as success.
//
// ── ONE SOURCE OF TRUTH FOR THE DIGEST ────────────────────────────────
//
// The submitter never computes EIP-712 itself. It asks the deployed
// contract for `mintDigest(...)`. Signers should do the same. A digest
// computed in two places is a digest that can disagree in two places, and
// the symptom — signatures that recover to strangers — is miserable to
// debug.
//
// ── ORDER OF OPERATIONS ───────────────────────────────────────────────
//
//   1. Poll the coordinator for ready mints
//   2. Skip anything the contract already processed (no gas spent)
//   3. Sort signatures by ascending signer address — the contract
//      requires it, and it is how distinctness is enforced
//   4. SIMULATE with eth_call. A revert here costs nothing; a revert on
//      chain costs the full gas of the attempt
//   5. Send, wait for the receipt
//   6. Tell the coordinator it landed
//
// Written against alloy 0.8 (pinned in Cargo.toml): single-value view
// calls return a struct whose value is `._0`, and contract instances are
// generic over the transport as well as the provider.
// ═══════════════════════════════════════════════════════════════════════

use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    transports::Transport,
};
use serde::Deserialize;
use std::str::FromStr;
use std::time::Duration;

sol! {
    #[sol(rpc)]
    contract NEV369Bridge {
        function mintFromNEV369(
            address user,
            uint256 amount,
            bytes32 nev369LockId,
            string sourceTx,
            uint256 sourceBlockHeight,
            bytes[] signatures
        ) external;

        function mintDigest(
            bytes32 lockId,
            address recipient,
            uint256 amount,
            uint256 sourceBlockHeight,
            string sourceTx
        ) external view returns (bytes32);

        function processedLocks(bytes32 lockId) external view returns (bool);
        function signerThreshold() external view returns (uint256);
        function isSigner(address who) external view returns (bool);
        function paused() external view returns (bool);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════════════

struct Config {
    coordinator: String,
    relayer_key: String,
    rpc_url: String,
    bridge: Address,
    gas_key: String,
    poll: Duration,
    /// Receipt wait before giving up on a submission and retrying later.
    receipt_timeout: Duration,
}

fn load() -> anyhow::Result<Config> {
    dotenvy::dotenv().ok();
    let need = |k: &str| {
        std::env::var(k).map_err(|_| anyhow::anyhow!("{k} is required and has no default"))
    };

    let gas_key = need("SUBMITTER_ETH_KEY")?;
    // Refuse an obvious placeholder rather than failing obscurely at sign
    // time. A 32-byte key is 64 hex characters.
    if gas_key.trim_start_matches("0x").len() != 64 {
        anyhow::bail!("SUBMITTER_ETH_KEY must be a 32-byte hex private key");
    }

    Ok(Config {
        coordinator: std::env::var("COORDINATOR_URL")
            .unwrap_or_else(|_| "http://localhost:9370".into()),
        relayer_key: need("RELAYER_KEY")?,
        rpc_url: need("ETH_RPC_URL")?,
        bridge: Address::from_str(&need("BRIDGE_ADDRESS")?)
            .map_err(|e| anyhow::anyhow!("BRIDGE_ADDRESS: {e}"))?,
        gas_key,
        poll: Duration::from_secs(
            std::env::var("SUBMITTER_POLL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
        ),
        receipt_timeout: Duration::from_secs(
            std::env::var("SUBMITTER_RECEIPT_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(180),
        ),
    })
}

// ═══════════════════════════════════════════════════════════════════════
// COORDINATOR API
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
struct ReadyMint {
    lock_id: String,
    recipient: String,
    amount: String,
    source_tx: String,
    source_block_height: u64,
    signatures: Vec<(String, String)>,
}

// ═══════════════════════════════════════════════════════════════════════
// TRANSLATION — coordinator strings → contract types
// ═══════════════════════════════════════════════════════════════════════

/// Lock ids must be 32-byte hex. Deliberately NOT hashed from an
/// arbitrary string: hashing introduces a second mapping that a signer
/// and the submitter could implement differently, and the result would be
/// valid signatures over a lock id nobody submits.
fn lock_id_bytes(s: &str) -> anyhow::Result<FixedBytes<32>> {
    FixedBytes::<32>::from_str(s.trim()).map_err(|e| {
        anyhow::anyhow!("lock id {s} is not 32-byte hex ({e}) — signers must use bytes32 ids")
    })
}

/// Base units, decimal string. Never through a float.
fn amount_units(s: &str) -> anyhow::Result<U256> {
    U256::from_str_radix(s.trim(), 10)
        .map_err(|e| anyhow::anyhow!("amount {s} is not a base-unit integer: {e}"))
}

/// Ascending by signer address — what the contract enforces, and how a
/// duplicate becomes impossible to express.
///
/// Deduplicates by address first. The coordinator already keys by address
/// so this should be a no-op; doing it here too means a coordinator bug
/// becomes a skipped signature rather than a reverted transaction.
fn ordered_signatures(sigs: &[(String, String)]) -> anyhow::Result<Vec<Bytes>> {
    let mut parsed: Vec<(Address, Bytes)> = Vec::with_capacity(sigs.len());
    for (addr, sig) in sigs {
        let a = Address::from_str(addr.trim())
            .map_err(|e| anyhow::anyhow!("signer address {addr}: {e}"))?;
        let raw = hex::decode(sig.trim().trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("signature from {addr} is not hex: {e}"))?;
        if raw.len() != 65 {
            anyhow::bail!("signature from {addr} is {} bytes, expected 65", raw.len());
        }
        parsed.push((a, Bytes::from(raw)));
    }
    parsed.sort_by_key(|(a, _)| *a);
    parsed.dedup_by_key(|(a, _)| *a);
    Ok(parsed.into_iter().map(|(_, s)| s).collect())
}

// ═══════════════════════════════════════════════════════════════════════
// SUBMIT ONE
// ═══════════════════════════════════════════════════════════════════════

enum Outcome {
    Landed(String),
    AlreadyDone,
    Skipped(String),
}

// alloy 0.8 contract instances carry the transport as a type parameter
// (`Instance<T, P, N>`); the calls below need `P: Provider<T>` over that
// same transport, so both are generic here rather than hard-coded.
async fn submit<T, P>(
    bridge: &NEV369Bridge::NEV369BridgeInstance<T, P>,
    m: &ReadyMint,
    timeout: Duration,
) -> anyhow::Result<Outcome>
where
    T: Transport + Clone,
    P: Provider<T> + Clone,
{
    let lock_id = lock_id_bytes(&m.lock_id)?;
    let recipient = Address::from_str(m.recipient.trim())
        .map_err(|e| anyhow::anyhow!("recipient {}: {e}", m.recipient))?;
    let amount = amount_units(&m.amount)?;
    let height = U256::from(m.source_block_height);

    // ── 2. already processed? ──
    // Another submitter may have won the race. Checking is free; finding
    // out by reverting is not.
    if bridge.processedLocks(lock_id).call().await?._0 {
        return Ok(Outcome::AlreadyDone);
    }

    if bridge.paused().call().await?._0 {
        return Ok(Outcome::Skipped("bridge is paused".into()));
    }

    // ── 3. order ──
    let sigs = ordered_signatures(&m.signatures)?;
    let threshold: U256 = bridge.signerThreshold().call().await?._0;
    if U256::from(sigs.len()) < threshold {
        return Ok(Outcome::Skipped(format!(
            "{} signatures after dedup, threshold {}",
            sigs.len(),
            threshold
        )));
    }

    let call = bridge.mintFromNEV369(
        recipient,
        amount,
        lock_id,
        m.source_tx.clone(),
        height,
        sigs,
    );

    // ── 4. simulate ──
    // Every revert reason the contract has — NotASigner, SignaturesOutOfOrder,
    // ExceedsWindowLimit, MintingDisabled, AlreadyProcessed — surfaces here
    // at zero cost instead of on-chain at full cost.
    if let Err(e) = call.call().await {
        let msg = e.to_string();
        if msg.contains("AlreadyProcessed") {
            return Ok(Outcome::AlreadyDone);
        }
        return Ok(Outcome::Skipped(format!("simulation reverted: {msg}")));
    }

    // ── 5. send ──
    let pending = call.send().await?;
    let tx_hash = format!("{:#x}", pending.tx_hash());
    tracing::info!(lock = %m.lock_id, tx = %tx_hash, "Submitted");

    let receipt = tokio::time::timeout(timeout, pending.get_receipt())
        .await
        .map_err(|_| anyhow::anyhow!("no receipt for {tx_hash} within {timeout:?}"))??;

    if !receipt.status() {
        // Mined but reverted — state changed between simulation and
        // inclusion, most likely another submitter landing first.
        if bridge.processedLocks(lock_id).call().await?._0 {
            return Ok(Outcome::AlreadyDone);
        }
        anyhow::bail!("{tx_hash} was mined but reverted");
    }

    Ok(Outcome::Landed(tx_hash))
}

// ═══════════════════════════════════════════════════════════════════════
// MAIN LOOP
// ═══════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = load()?;

    let signer: PrivateKeySigner = cfg
        .gas_key
        .trim_start_matches("0x")
        .parse()
        .map_err(|e| anyhow::anyhow!("SUBMITTER_ETH_KEY: {e}"))?;
    let gas_address = signer.address();

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(EthereumWallet::from(signer))
        .on_http(cfg.rpc_url.parse()?);

    let bridge = NEV369Bridge::new(cfg.bridge, provider.clone());

    // Refuse to start if the gas key is itself a registered signer.
    //
    // That would put a signing key and a submitting key in one process,
    // which quietly turns an m-of-n threshold into (m-1)-of-n plus
    // whoever controls this box. Signers and submitters must be separate.
    if bridge.isSigner(gas_address).call().await?._0 {
        anyhow::bail!(
            "SUBMITTER_ETH_KEY resolves to {gas_address}, which is a registered bridge \
             SIGNER. Use a separate gas-only key — a signing key in the submitter \
             reduces the threshold by one for anyone who compromises this process."
        );
    }

    tracing::info!(
        bridge = %cfg.bridge,
        gas = %gas_address,
        coordinator = %cfg.coordinator,
        "Submitter running. This key pays gas; it cannot authorize a mint."
    );

    let http = reqwest::Client::new();
    let base = cfg.coordinator.trim_end_matches('/').to_string();

    loop {
        match http.get(format!("{base}/api/ready")).send().await {
            Ok(resp) => match resp.json::<Vec<ReadyMint>>().await {
                Ok(ready) => {
                    for m in &ready {
                        // Resolve to the hash to record, or nothing.
                        //
                        // An earlier draft matched `Landed(tx) | AlreadyDone`
                        // in one arm — invalid, since only one side binds
                        // `tx` — and routed the hash through a helper that
                        // always returned None. Every landed mint would have
                        // been recorded as "already-processed", discarding
                        // the transaction hash that is the only on-chain
                        // proof the mint happened.
                        let record: Option<String> = match submit(&bridge, m, cfg.receipt_timeout)
                            .await
                        {
                            Ok(Outcome::Landed(tx)) => Some(tx),
                            Ok(Outcome::AlreadyDone) => {
                                tracing::info!(lock = %m.lock_id, "Already processed on-chain");
                                Some("already-processed".to_string())
                            }
                            Ok(Outcome::Skipped(why)) => {
                                tracing::warn!(lock = %m.lock_id, %why, "Skipped");
                                None
                            }
                            Err(e) => {
                                tracing::error!(lock = %m.lock_id, error = %e, "Submission failed");
                                None
                            }
                        };

                        if let Some(tx_hash) = record {
                            let res = http
                                .post(format!("{base}/api/locks/{}/submitted", m.lock_id))
                                .header("x-relayer-key", &cfg.relayer_key)
                                .json(&serde_json::json!({ "tx_hash": tx_hash }))
                                .send()
                                .await;
                            if let Err(e) = res {
                                // Not fatal. The mint landed; the coordinator
                                // will re-offer it, processedLocks will say
                                // AlreadyDone, and the next pass records it.
                                tracing::warn!(lock = %m.lock_id, error = %e,
                                    "Landed but could not notify coordinator; will retry");
                            }
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "Coordinator returned unparseable data"),
            },
            Err(e) => tracing::warn!(error = %e, "Coordinator unreachable"),
        }

        tokio::time::sleep(cfg.poll).await;
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(byte: u8) -> String {
        hex::encode([byte; 65])
    }

    #[test]
    fn signatures_are_sorted_by_ascending_address() {
        // The contract requires it; it is how distinctness is enforced.
        let input = vec![
            ("0x3000000000000000000000000000000000000003".into(), sig(3)),
            ("0x1000000000000000000000000000000000000001".into(), sig(1)),
            ("0x2000000000000000000000000000000000000002".into(), sig(2)),
        ];
        let out = ordered_signatures(&input).unwrap();
        assert_eq!(out[0][0], 1);
        assert_eq!(out[1][0], 2);
        assert_eq!(out[2][0], 3);
    }

    #[test]
    fn a_duplicate_signer_is_collapsed_not_submitted() {
        // A coordinator bug becomes a skipped signature rather than a
        // transaction the contract reverts with SignaturesOutOfOrder.
        let a = "0x1000000000000000000000000000000000000001".to_string();
        let out = ordered_signatures(&[(a.clone(), sig(1)), (a, sig(9))]).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn a_short_signature_is_rejected() {
        let bad = vec![(
            "0x1000000000000000000000000000000000000001".into(),
            hex::encode([0u8; 64]),
        )];
        assert!(ordered_signatures(&bad).is_err());
    }

    #[test]
    fn lock_ids_must_be_bytes32_not_arbitrary_strings() {
        // Hashing an arbitrary string would be a second mapping for
        // signers and the submitter to disagree about.
        assert!(lock_id_bytes("lock-1").is_err());
        assert!(lock_id_bytes(&format!("0x{}", "ab".repeat(32))).is_ok());
    }

    #[test]
    fn amounts_are_integers_never_floats() {
        assert_eq!(
            amount_units("100000000").unwrap(),
            U256::from(100_000_000u64)
        );
        assert!(
            amount_units("1.5").is_err(),
            "fractional base units do not exist"
        );
        // 2^64 + 1 — beyond u64, fine in U256, and never through f64.
        assert!(amount_units("18446744073709551617").is_ok());
    }
}
