use anyhow::{anyhow, Result};
use serde_json::json;

/// Thin JSON-RPC client for the XRP Ledger.
///
/// IMPORTANT: This client only handles broadcasting already-signed
/// transactions and reading ledger state. It does NOT sign transactions.
///
/// Signing must happen either:
///   1. Client-side, via a wallet the user controls (Xumm, Ledger hardware,
///      GemWallet, Crossmark) — the frontend gets a signed tx_blob back and
///      this backend just relays it to `submit()`, OR
///   2. Server-side with a securely vaulted seed (HSM, KMS, or equivalent) —
///      never store or accept raw private keys in plain request/response
///      bodies. If you need server-side signing, use `xrpl-rust` or a
///      dedicated signing microservice with strict access controls.
pub struct XrplClient {
    pub node_url: String,
}

impl XrplClient {
    pub fn new(node_url: &str) -> Self {
        Self {
            node_url: node_url.to_string(),
        }
    }

    /// Submit a signed transaction blob to the XRPL via JSON-RPC.
    /// `tx_blob` must be a hex-encoded, already-signed transaction.
    pub async fn submit(&self, tx_blob: &str) -> Result<String> {
        let client = reqwest::Client::new();
        let body = json!({
            "method":"submit",
            "params": [{"tx_blob": tx_blob }]
        });

        let resp = client
            .post(&self.node_url)
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let engine_result = resp["result"]["engine_result"]
            .as_str()
            .unwrap_or("unknown");

        // XRPL success codes start with "tes"
        if !engine_result.starts_with(" tes") {
            return Err(anyhow!("XRPL rejected tx: {engine_result}"));
        }

        let tx_hash = resp["result"]["tx_json"]["hash"]
            .as_str()
            .ok_or(anyhow!("No tx hash in response"))?
            .to_string();

        Ok(tx_hash)
    }

    /// Fetch account balance in XRP (drops / 1_000_000).
    pub async fn get_balance(&self, address: &str) -> Result<f64> {
        let client = reqwest::Client::new();
        let body = json!({
                      "method":"account_info",
                      "params": [{"account": address,"ledger_index": "validated"
        }]
                });

        let resp = client
            .post(&self.node_url)
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        let drops = resp["result"]["account_data"]["Balance"]
            .as_str()
            .ok_or(anyhow!("Account not found"))?
            .parse::<f64>()?;

        Ok(drops / 1_000_000.0)
    }

    /// Poll for transaction validation (call this after submit(), e.g. in a
    /// retry loop with backoff until `validated` is true or timeout).
    pub async fn get_tx_status(&self, tx_hash: &str) -> Result<String> {
        let client = reqwest::Client::new();
        let body = json!({
              "method": "tx",
              "params": [{"transaction": tx_hash }]
        });

        let resp = client
            .post(&self.node_url)
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let validated = resp["result"]["validated"].as_bool().unwrap_or(false);
        Ok(if validated {
            "confirmed".into()
        } else {
            "pending".into()
        })
    }

    /// Fetches the account's current Sequence number — needed both to build
    /// a Ledger-signed transaction client-side and to resolve the
    /// OfferSequence of a native EscrowCreate after it lands on-ledger.
    pub async fn get_account_sequence(&self, address: &str) -> Result<u32> {
        let client = reqwest::Client::new();
        let body = json!({
              "method":"account_info",
              "params": [{"account": address,"ledger_index": "current" }]
        });

        let resp = client
            .post(&self.node_url)
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        resp["result"]["account_data"]["Sequence"]
            .as_u64()
            .map(|s| s as u32)
            .ok_or(anyhow!(
                "Sequence not found — account may not exist or may be unfunded"
            ))
    }

    /// Looks up the Sequence a specific already- validated transaction was
    /// submitted with. Used to resolve OfferSequence for EscrowFinish/Cancel
    /// once we know the EscrowCreate transaction's hash.
    pub async fn get_transaction_sequence(&self, tx_hash: &str) -> Result<u32> {
        let client = reqwest::Client::new();
        let body = json!({
              "method": "tx",
              "params": [{"transaction": tx_hash }]
        });

        let resp = client
            .post(&self.node_url)
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        resp["result"]["Sequence"]
            .as_u64()
            .map(|s| s as u32)
            .ok_or(anyhow!("Sequence not found in transaction response"))
    }
}

// ============================ ============================ ====================
// Wiring example (not auto- included — call this from your /send handler
// once you replace the mock transaction logic with real broadcast):
//
//      let xrpl = xrpl::XrplClient::new(&std:: env::var("XRPL_NODE").unwrap ());
//      let tx_hash = xrpl.submit(&signed_tx_blob) .await?;
//   let status = xrpl.get_tx_status(&tx_hash) .await?;
// ============================ ============================ ====================

// ═══════════════════════════════════════════════════════════════════════
// ESCROW LOOKUP — used by `qlock-inheritance record`
//
// get_transaction_sequence() returns a bare number. That is not enough for
// recording the OfferSequence of an inheritance escrow, because a wrong
// number here is not an error today — it is an unreleasable escrow in 2039.
// This returns enough of the transaction to CHECK it: that it validated,
// that it is an EscrowCreate, and that its destination, amount and
// FinishAfter are the ones that were attested.
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct EscrowCreateInfo {
    pub validated: bool,
    pub transaction_type: String,
    pub result: String,
    pub account: String,
    pub destination: String,
    /// Drops. XRPL returns XRP amounts as a decimal STRING of drops, so this
    /// is parsed from text — never through a float.
    pub amount_drops: Option<u64>,
    pub finish_after: Option<u32>,
    pub cancel_after: Option<u32>,
    pub sequence: u32,
    /// Set when the EscrowCreate consumed a Ticket. In that case the
    /// transaction's Sequence is 0 and the value EscrowFinish needs as
    /// OfferSequence is the TicketSequence instead.
    pub ticket_sequence: Option<u32>,
}

impl EscrowCreateInfo {
    /// The number EscrowFinish must carry as OfferSequence.
    pub fn offer_sequence(&self) -> u32 {
        match self.ticket_sequence {
            Some(t) if self.sequence == 0 => t,
            _ => self.sequence,
        }
    }
}

impl XrplClient {
    pub async fn get_escrow_create(&self, tx_hash: &str) -> Result<EscrowCreateInfo> {
        let client = reqwest::Client::new();
        let body = json!({
            "method": "tx",
            "params": [{ "transaction": tx_hash, "binary": false }]
        });
        let resp = client
            .post(&self.node_url)
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let r = &resp["result"];
        if r["error"].is_string() {
            return Err(anyhow!("ledger returned {} for {}", r["error"], tx_hash));
        }
        let tx = if r["tx_json"].is_object() {
            &r["tx_json"]
        } else {
            r
        };
        let s = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
        let u32_of = |v: &serde_json::Value| v.as_u64().map(|n| n as u32);

        Ok(EscrowCreateInfo {
            validated: r["validated"].as_bool().unwrap_or(false),
            transaction_type: s(&tx["TransactionType"]),
            result: s(&r["meta"]["TransactionResult"]),
            account: s(&tx["Account"]),
            destination: s(&tx["Destination"]),
            amount_drops: tx["Amount"].as_str().and_then(|a| a.parse::<u64>().ok()),
            finish_after: u32_of(&tx["FinishAfter"]),
            cancel_after: u32_of(&tx["CancelAfter"]),
            sequence: u32_of(&tx["Sequence"]).unwrap_or(0),
            ticket_sequence: u32_of(&tx["TicketSequence"]),
        })
    }
}
