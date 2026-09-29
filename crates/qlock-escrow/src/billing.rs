// crates/qlock-escrow/src/billing.rs
//
// ═══════════════════════════════════════════════════════════════════════
// Stripe subscriptions — checkout and webhook
//
// Two endpoints:
//
//   POST /billing/checkout   (JWT)  → creates a Checkout Session for the
//                                     signed-in user and returns its URL
//   POST /billing/webhook    (none) → Stripe calls this; the signature on
//                                     the raw body is the only credential
//
// The webhook is the only thing that can change a user's plan, and the
// Stripe-Signature header is the only thing that proves Stripe sent it.
// It is verified here with HMAC-SHA256 over `timestamp.body`, compared in
// constant time, with a five-minute replay window — Stripe's documented
// scheme. Every event id is recorded in `stripe_events`, so a retried
// delivery is acknowledged without being applied twice.
//
// Price IDs come from the environment (STRIPE_PRICE_PRO,
// STRIPE_PRICE_ENTERPRISE). They are the `price_…` identifiers from the
// Stripe dashboard. Checkout for a plan whose price is not configured
// returns 503 rather than charging for the wrong product.
// ═══════════════════════════════════════════════════════════════════════

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{auth::Claims, ApiError, AppState};

/// Stripe's recommended tolerance for the signed timestamp.
const SIGNATURE_TOLERANCE_SECS: i64 = 300;

#[derive(Deserialize)]
pub struct CheckoutRequest {
    /// "pro" | "enterprise"
    pub plan: String,
}

#[derive(Serialize)]
pub struct CheckoutResponse {
    #[serde(rename = "checkoutUrl")]
    pub checkout_url: String,
}

fn err(code: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError::from((code, msg.into()))
}

/// Price ID for a plan, from the environment.
fn price_id_for(plan: &str) -> Result<String, ApiError> {
    let var = match plan {
        "pro" => "STRIPE_PRICE_PRO",
        "enterprise" => "STRIPE_PRICE_ENTERPRISE",
        _ => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "unknown plan — use pro or enterprise",
            ))
        }
    };
    match std::env::var(var) {
        Ok(v) if v.starts_with("price_") => Ok(v),
        _ => Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("billing for '{plan}' is not configured ({var} unset)"),
        )),
    }
}

fn frontend_origin() -> String {
    std::env::var("FRONTEND_ORIGIN")
        .ok()
        .and_then(|v| {
            v.split(',')
                .next()
                .map(|s| s.trim().trim_end_matches('/').to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://q-lock-ecosystem.com".to_string())
}

// ═══════════════════════════════════════════════════════════════════════
// CHECKOUT
// ═══════════════════════════════════════════════════════════════════════

pub async fn create_checkout(
    State(_state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CheckoutRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let price_id = price_id_for(&req.plan)?;
    let secret_key = std::env::var("STRIPE_SECRET_KEY")
        .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "Stripe is not configured"))?;

    let origin = frontend_origin();
    let success = format!("{origin}/billing/success?session_id={{CHECKOUT_SESSION_ID}}");
    let cancel = format!("{origin}/billing/cancel");

    // client_reference_id and metadata carry the user and plan through to
    // the webhook. Without them the webhook has to guess which account to
    // upgrade from an email address, and which plan was bought.
    let params: Vec<(&str, &str)> = vec![
        ("mode", "subscription"),
        ("line_items[0][price]", &price_id),
        ("line_items[0][quantity]", "1"),
        ("success_url", &success),
        ("cancel_url", &cancel),
        ("client_reference_id", &claims.sub),
        ("customer_email", &claims.email),
        ("metadata[user_id]", &claims.sub),
        ("metadata[plan]", &req.plan),
        ("subscription_data[metadata][user_id]", &claims.sub),
        ("subscription_data[metadata][plan]", &req.plan),
    ];

    let resp = reqwest::Client::new()
        .post("https://api.stripe.com/v1/checkout/sessions")
        .basic_auth(secret_key, Some(""))
        .form(&params)
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("Stripe unreachable: {e}")))?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.map_err(|e| {
        err(
            StatusCode::BAD_GATEWAY,
            format!("Stripe returned non-JSON: {e}"),
        )
    })?;

    if !status.is_success() {
        let msg = body["error"]["message"]
            .as_str()
            .unwrap_or("checkout failed");
        return Err(err(StatusCode::BAD_GATEWAY, format!("Stripe: {msg}")));
    }

    let checkout_url = body["url"]
        .as_str()
        .ok_or_else(|| err(StatusCode::BAD_GATEWAY, "Stripe returned no checkout URL"))?
        .to_string();

    tracing::info!(user = %claims.sub, plan = %req.plan, "checkout session created");
    Ok(Json(CheckoutResponse { checkout_url }))
}

// ═══════════════════════════════════════════════════════════════════════
// WEBHOOK
// ═══════════════════════════════════════════════════════════════════════

pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let sig = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let secret = std::env::var("STRIPE_WEBHOOK_SECRET").map_err(|_| {
        tracing::error!("STRIPE_WEBHOOK_SECRET unset — refusing all webhooks");
        StatusCode::SERVICE_UNAVAILABLE
    })?;

    let now = chrono::Utc::now().timestamp();
    if let Err(reason) = verify_stripe_signature(&body, sig, &secret, now) {
        tracing::warn!(%reason, "Stripe webhook signature rejected");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let event: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let event_id = event["id"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let event_type = event["type"].as_str().unwrap_or("");

    // Idempotency: first writer wins. A retry finds the row and is
    // acknowledged with 200 so Stripe stops retrying.
    let inserted = sqlx::query(
        "INSERT INTO stripe_events (id, event_type) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING",
    )
    .bind(event_id)
    .bind(event_type)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "stripe_events insert failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if inserted.rows_affected() == 0 {
        tracing::info!(%event_id, "duplicate Stripe event ignored");
        return Ok(StatusCode::OK);
    }

    let obj = &event["data"]["object"];
    let result = match event_type {
        "checkout.session.completed" => on_checkout_completed(&state, obj).await,
        "customer.subscription.updated" => on_subscription_changed(&state, obj, false).await,
        "customer.subscription.deleted" => on_subscription_changed(&state, obj, true).await,
        _ => Ok(()),
    };

    if let Err(e) = result {
        // Forget the event so Stripe's retry gets another chance to apply it.
        let _ = sqlx::query("DELETE FROM stripe_events WHERE id = $1")
            .bind(event_id)
            .execute(&state.db)
            .await;
        tracing::error!(%event_id, %event_type, error = %e, "Stripe event failed");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    tracing::info!(%event_id, %event_type, "Stripe event applied");
    Ok(StatusCode::OK)
}

fn known_plan(p: &str) -> Option<&'static str> {
    match p {
        "pro" => Some("pro"),
        "enterprise" => Some("enterprise"),
        _ => None,
    }
}

async fn on_checkout_completed(
    state: &AppState,
    obj: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    let user_id = obj["client_reference_id"]
        .as_str()
        .or_else(|| obj["metadata"]["user_id"].as_str())
        .and_then(|s| Uuid::parse_str(s).ok());
    let plan = obj["metadata"]["plan"].as_str().and_then(known_plan);
    let (Some(user_id), Some(plan)) = (user_id, plan) else {
        tracing::warn!("checkout.session.completed without user_id/plan metadata — ignored");
        return Ok(());
    };
    let customer = obj["customer"].as_str();
    let subscription = obj["subscription"].as_str();

    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET plan = $1, updated_at = now() WHERE id = $2")
        .bind(plan)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    if let Some(sub_id) = subscription {
        sqlx::query(
            "INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_subscription_id, plan, status)
             VALUES ($1, $2, $3, $4, 'active')
             ON CONFLICT (stripe_subscription_id)
             DO UPDATE SET plan = EXCLUDED.plan, status = 'active', updated_at = now()",
        )
        .bind(user_id)
        .bind(customer)
        .bind(sub_id)
        .bind(plan)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    tracing::info!(%user_id, %plan, "plan upgraded");
    Ok(())
}

async fn on_subscription_changed(
    state: &AppState,
    obj: &serde_json::Value,
    deleted: bool,
) -> Result<(), sqlx::Error> {
    let Some(sub_id) = obj["id"].as_str() else {
        return Ok(());
    };
    let status = if deleted {
        "canceled"
    } else {
        obj["status"].as_str().unwrap_or("incomplete")
    };
    let period_end = obj["current_period_end"]
        .as_i64()
        .and_then(|t| chrono::DateTime::<chrono::Utc>::from_timestamp(t, 0));

    let mut tx = state.db.begin().await?;
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "UPDATE subscriptions SET status = $1, current_period_end = COALESCE($2, current_period_end),
                updated_at = now()
         WHERE stripe_subscription_id = $3
         RETURNING user_id, plan",
    )
    .bind(status)
    .bind(period_end)
    .bind(sub_id)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some((user_id, plan)) = row {
        // Active or trialing keeps the paid plan; anything else drops to
        // free. past_due keeps it too — Stripe is still retrying the card.
        let keep = matches!(status, "active" | "trialing" | "past_due");
        let new_plan = if keep { plan.as_str() } else { "free" };
        sqlx::query("UPDATE users SET plan = $1, updated_at = now() WHERE id = $2")
            .bind(new_plan)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tracing::info!(%user_id, %status, plan = %new_plan, "subscription changed");
    }
    tx.commit().await?;
    Ok(())
}

/// Stripe webhook signature check.
///
/// Header: `t=1492774577,v1=5257a869…,v1=…` (several v1 during secret
/// rotation). Signed payload: `"{t}.{raw body}"`, HMAC-SHA256 with the
/// endpoint secret, hex-encoded.
pub fn verify_stripe_signature(
    payload: &[u8],
    header: &str,
    secret: &str,
    now: i64,
) -> Result<(), &'static str> {
    let mut timestamp: Option<i64> = None;
    let mut candidates: Vec<Vec<u8>> = Vec::new();
    for part in header.split(',') {
        let Some((k, v)) = part.trim().split_once('=') else {
            continue;
        };
        match k {
            "t" => timestamp = v.parse().ok(),
            "v1" => {
                if let Ok(bytes) = hex::decode(v) {
                    candidates.push(bytes);
                }
            }
            _ => {}
        }
    }
    let t = timestamp.ok_or("no timestamp")?;
    if candidates.is_empty() {
        return Err("no v1 signature");
    }
    if (now - t).abs() > SIGNATURE_TOLERANCE_SECS {
        return Err("timestamp outside tolerance");
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| "bad secret")?;
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    let expected = mac.finalize().into_bytes();

    if candidates
        .iter()
        .any(|c| c.len() == expected.len() && bool::from(c.as_slice().ct_eq(expected.as_slice())))
    {
        Ok(())
    } else {
        Err("signature mismatch")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(secret: &str, t: i64, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{t}.").as_bytes());
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn a_valid_signature_is_accepted() {
        let body = br#"{"id":"evt_1"}"#;
        let h = format!("t=1000,v1={}", sign("whsec_x", 1000, body));
        assert!(verify_stripe_signature(body, &h, "whsec_x", 1100).is_ok());
    }

    #[test]
    fn a_forged_webhook_is_rejected() {
        // The previous version returned `true` unconditionally, so anyone
        // could POST a checkout.session.completed and upgrade any account.
        let body = br#"{"id":"evt_1"}"#;
        let h = format!("t=1000,v1={}", sign("attacker_guess", 1000, body));
        assert!(verify_stripe_signature(body, &h, "whsec_x", 1000).is_err());
    }

    #[test]
    fn a_tampered_body_is_rejected() {
        let h = format!("t=1000,v1={}", sign("whsec_x", 1000, b"original"));
        assert!(verify_stripe_signature(b"tampered", &h, "whsec_x", 1000).is_err());
    }

    #[test]
    fn a_replayed_signature_is_rejected() {
        let body = b"x";
        let h = format!("t=1000,v1={}", sign("whsec_x", 1000, body));
        assert!(verify_stripe_signature(body, &h, "whsec_x", 1000 + 301).is_err());
    }

    #[test]
    fn rotation_accepts_any_listed_signature() {
        let body = b"x";
        let h = format!("t=1000,v1=deadbeef,v1={}", sign("whsec_x", 1000, body));
        assert!(verify_stripe_signature(body, &h, "whsec_x", 1000).is_ok());
    }
}
