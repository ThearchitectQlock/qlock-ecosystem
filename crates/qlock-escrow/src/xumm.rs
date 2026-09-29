use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::json;

const XUMM_BASE: &str = "https://xumm.app/api/v1/platform/payload";

pub struct XummClient {
    api_key: String,
    api_secret: String,
}

#[derive(Deserialize, Debug)]
pub struct PayloadCreated {
    pub uuid: String,
    pub next: NextInfo,
    pub refs: RefsInfo,
}

#[derive(Deserialize, Debug)]
pub struct NextInfo {
    pub always: String,
}

#[derive(Deserialize, Debug)]
pub struct RefsInfo {
    pub qr_png: String,
    pub websocket_status: String,
}

#[derive(Deserialize, Debug)]
pub struct PayloadStatus {
    pub meta: PayloadMeta,
    pub response: Option<PayloadResponseData>,
}

#[derive(Deserialize, Debug)]
pub struct PayloadMeta {
    pub resolved: bool,
    pub signed: bool,
    pub cancelled: bool,
    pub expired: bool,
}

#[derive(Deserialize, Debug)]
pub struct PayloadResponseData {
    /// Present on a resolved SignIn payload — the user's real XRPL address.
    pub account: Option<String>,
    /// Present on a resolved, submitted transaction — the real ledger tx hash.
    pub txid: Option<String>,
    pub dispatched_result: Option<String>,
}

impl XummClient {
    /// Fails fast and explicitly if credentials aren't configured — no
    /// silent fallback to a fake address anywhere in this file.
    pub fn from_env() -> Result<Self> {
        let api_key =
            std::env::var("XUMM_API_KEY").map_err(|_| anyhow!("XUMM_API_KEY is not set"))?;
        let api_secret =
            std::env::var("XUMM_API_SECRET").map_err(|_| anyhow!("XUMM_API_SECRET is not set"))?;
        Ok(Self {
            api_key,
            api_secret,
        })
    }

    fn headers(&self) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            "x-api-key",
            self.api_key
                .parse()
                .expect("invalid XUMM_API_KEY header value"),
        );
        h.insert(
            "x-api-secret",
            self.api_secret
                .parse()
                .expect("invalid XUMM_API_SECRET header value"),
        );
        h.insert("Content-Type", "application/json".parse().unwrap());
        h
    }

    /// Real wallet "connect" — a SignIn pseudo- transaction. The user scans
    /// the QR / opens the deeplink in their real Xaman app, approves, and
    /// we get their actual XRPL account address back. We never generate
    /// an address ourselves.
    pub async fn create_signin_request(&self) -> Result<PayloadCreated> {
        let client = reqwest::Client::new();
        let body = json!({"txjson": {"TransactionType": "SignIn"
} });

        let resp = client
            .post(XUMM_BASE)
            .headers(self.headers())
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Xumm sign-in request rejected ({status}): {text}"));
        }
        Ok(resp.json::<PayloadCreated>().await?)
    }

    /// Real payment sign request. `amount_drops` must already be converted
    /// from XRP (1 XRP = 1,000,000 drops). `Account` is pinned explicitly so
    /// Xumm warns/blocks if a different wallet than the one we verified
    /// tries to sign it. `options.submit: true` means Xumm itself broadcasts
    /// to the real ledger on approval — this backend does not call
    /// xrpl::XrplClient::submit() for this path, Xumm already did it.
    pub async fn create_payment_request(
        &self,
        from: &str,
        to: &str,
        amount_drops: u64,
    ) -> Result<PayloadCreated> {
        let client = reqwest::Client::new();
        let body = json!({
                     "txjson": {

        "TransactionType":"Payment",
                          "Account":from,"Destination": to,
                          "Amount":amount_drops.to_string()
                     },
                     "options": {"submit": true }
               });

        let resp = client
            .post(XUMM_BASE)
            .headers(self.headers())
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Xumm payment request rejected ({status}): {text}"));
        }
        Ok(resp.json::<PayloadCreated>().await?)
    }

    async fn post_payload(&self, txjson: serde_json::Value) -> Result<PayloadCreated> {
        let client = reqwest::Client::new();
        let body = json!({"txjson": txjson, "options":{ "submit": true } });

        let resp = client
            .post(XUMM_BASE)
            .headers(self.headers())
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Xumm request rejected ({status}): {text}"));
        }
        Ok(resp.json::<PayloadCreated>().await?)
    }

    /// Native XRPL EscrowCreate — funds locked on-ledger, not in our
    /// database. `finish_after`/`cancel_after ` are ripple-epoch seconds
    /// (unix seconds - 946684800), matching Q- Lock's existing time-lock
    /// design without needing crypto- condition/fulfillment complexity.
    pub async fn create_escrow_create_request(
        &self,
        from: &str,
        to: &str,
        amount_drops: u64,
        finish_after: u32,
        cancel_after: u32,
    ) -> Result<PayloadCreated> {
        self.post_payload(json!({

        "TransactionType":"EscrowCreate",
                       "Account": from,
                       "Destination":to,
                       "Amount":amount_drops.to_string(),
                       "FinishAfter":finish_after,
                       "CancelAfter":cancel_after
                 }))
        .await
    }

    /// Native EscrowFinish — releases a locked escrow to its destination.
    /// `owner` is the account that ran EscrowCreate; `offer_sequence` is
    /// that transaction's Sequence number (fetched via
    /// xrpl::XrplClient::get_transa ction_sequence once it's validated).
    pub async fn create_escrow_finish_request(
        &self,
        finisher: &str,
        owner: &str,
        offer_sequence: u32,
    ) -> Result<PayloadCreated> {
        self.post_payload(json!({

        "TransactionType":"EscrowFinish",
                      "Account":finisher,
                      "Owner": owner,
                       "OfferSequence":offer_sequence
                 }))
        .await
    }

    /// Native EscrowCancel — reclaims funds to the owner after CancelAfter
    /// has passed. Anyone can technically submit this on XRPL once the time
    /// passes, but Q-Lock only offers it to the owner's own connected wallet.
    pub async fn create_escrow_cancel_request(
        &self,
        canceller: &str,
        owner: &str,
        offer_sequence: u32,
    ) -> Result<PayloadCreated> {
        self.post_payload(json!({

        "TransactionType":"EscrowCancel",
                        "Account":canceller,
                        "Owner": owner,
                        "OfferSequence":offer_sequence
                  }))
        .await
    }

    // ─────────────────────────────────────────────────────────────────
    // RECONSTRUCTED SIGNATURE — verify this line against your original.
    //
    // The source PDF is missing it. A page break fell between the
    // previous function's closing brace and this body, so the render
    // dropped the declaration entirely and the file would not parse.
    //
    // The body determines it unambiguously: it takes a `uuid`, builds
    // `{XUMM_BASE}/{uuid}`, and returns `resp.json::<PayloadStatus>()`.
    // Everything except the exact parameter name is forced.
    // ─────────────────────────────────────────────────────────────────
    pub async fn get_payload_status(&self, uuid: &str) -> Result<PayloadStatus> {
        let client = reqwest::Client::new();
        let url = format!("{XUMM_BASE}/{uuid}");
        let resp = client.get(&url).headers(self.headers()).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            return Err(anyhow!("Failed to fetch Xumm payload status ({status})"));
        }
        Ok(resp.json::<PayloadStatus>().await?)
    }
}
