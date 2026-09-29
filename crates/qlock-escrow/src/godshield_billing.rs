// crates/qlock-escrow/src/godshield_billing.rs
//
// ═══════════════════════════════════════════════════════════════════════
// GodShield API metering and plans
//
// The GodShield API (a separate service) does not know about accounts.
// nginx asks this module before each metered call:
//
//   GET /internal/godshield/authorize    nginx auth_request only — never
//                                        routed from the internet
//       200  allowed (usage counted)
//       401  X-API-Key given but unknown
//       403  quota reached; the reason is in X-GodShield-Reason
//
//   GET  /godshield/account              (JWT or X-API-Key) plan, usage, key
//   POST /godshield/account/rotate-key   (JWT or X-API-Key) new API key
//   GET  /billing/plans                  public: quotas and display prices
//
// Who is metered:
//   X-API-Key: qlk_…      → that account's monthly quota
//   Authorization: Bearer → the signed-in website user's monthly quota
//   neither               → per-IP daily allowance, for trying it out
//
// Plans are the same Free / Pro / Enterprise the escrow uses, so one
// Stripe subscription (billing.rs) upgrades both: lower escrow fees and a
// bigger GodShield quota. The plan is always read from the database, not
// from a JWT, so an upgrade applies to the very next call.
//
// Counting is one atomic upsert that refuses to go past the limit, so two
// concurrent calls can never both take the last unit of quota.
// ═══════════════════════════════════════════════════════════════════════

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{auth, db_err, ApiError, AppState};

// ── Quotas: MUST match docs/pricing.md ─────────────────────────────────
pub const GS_QUOTA_FREE: i64 = 100;
pub const GS_QUOTA_PRO: i64 = 10_000;
pub const GS_QUOTA_ENTERPRISE: i64 = 250_000;
/// Anonymous calls per IP per UTC day.
pub const GS_ANON_DAILY: i64 = 25;

pub fn gs_quota_for(plan: &str) -> i64 {
    match plan {
        "pro" => GS_QUOTA_PRO,
        "enterprise" => GS_QUOTA_ENTERPRISE,
        _ => GS_QUOTA_FREE,
    }
}

/// Created at startup if missing. The database was initialised from
/// db/schema.sql before this table existed, so it cannot live only there.
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS godshield_usage (
    subject     VARCHAR(80)  NOT NULL,
    period      VARCHAR(10)  NOT NULL,
    calls       BIGINT       NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (subject, period)
)";

pub async fn ensure_schema(db: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(SCHEMA).execute(db).await.map(|_| ())
}

/// Count one call against `subject` for `period`, unless it is already
/// at `limit`. Returns the new count, or None when the limit is reached.
async fn take_one(
    db: &PgPool,
    subject: &str,
    period: &str,
    limit: i64,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "INSERT INTO godshield_usage (subject, period, calls) VALUES ($1, $2, 1)
         ON CONFLICT (subject, period) DO UPDATE
             SET calls = godshield_usage.calls + 1, updated_at = now()
             WHERE godshield_usage.calls < $3
         RETURNING calls",
    )
    .bind(subject)
    .bind(period)
    .bind(limit)
    .fetch_optional(db)
    .await
}

async fn used(db: &PgPool, subject: &str, period: &str) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT calls FROM godshield_usage WHERE subject = $1 AND period = $2",
    )
    .bind(subject)
    .bind(period)
    .fetch_optional(db)
    .await?
    .unwrap_or(0))
}

fn month() -> String {
    chrono::Utc::now().format("%Y-%m").to_string()
}

fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

/// Header values must be plain ASCII without quotes: nginx splices the
/// reason into a JSON body.
fn deny(code: StatusCode, reason: &str) -> Response {
    let clean: String = reason
        .chars()
        .map(|c| {
            if c.is_ascii() && c != '"' && c != '\\' {
                c
            } else {
                ' '
            }
        })
        .collect();
    let mut resp = (code, Json(serde_json::json!({ "error": clean }))).into_response();
    if let Ok(v) = HeaderValue::from_str(&clean) {
        resp.headers_mut().insert("x-godshield-reason", v);
    }
    resp
}

fn allow(plan: &str, remaining: i64) -> Response {
    let mut resp = StatusCode::OK.into_response();
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(plan) {
        h.insert("x-godshield-plan", v);
    }
    if let Ok(v) = HeaderValue::from_str(&remaining.max(0).to_string()) {
        h.insert("x-godshield-remaining", v);
    }
    resp
}

async fn user_by_api_key(db: &PgPool, key: &str) -> Result<Option<(Uuid, String)>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, String)>("SELECT id, plan FROM users WHERE api_key = $1")
        .bind(key)
        .fetch_optional(db)
        .await
}

async fn plan_of(db: &PgPool, id: Uuid) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>("SELECT plan FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
}

/// nginx auth_request target. See the module header.
pub async fn authorize(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let db = &state.db;
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };

    // 1. API key: programmatic customers.
    let account = if let Some(key) = header("x-api-key") {
        match user_by_api_key(db, key).await {
            Ok(Some(u)) => Some(u),
            Ok(None) => return deny(StatusCode::UNAUTHORIZED, "unknown API key"),
            Err(e) => {
                tracing::error!(error = %e, "godshield authorize: key lookup failed");
                return deny(
                    StatusCode::FORBIDDEN,
                    "metering unavailable, try again shortly",
                );
            }
        }
    // 2. Signed-in website user.
    } else if let Some(token) = header("authorization").and_then(|v| v.strip_prefix("Bearer ")) {
        match auth::verify_jwt(token)
            .ok()
            .and_then(|c| Uuid::parse_str(&c.sub).ok())
        {
            Some(id) => match plan_of(db, id).await {
                Ok(Some(plan)) => Some((id, plan)),
                _ => None,
            },
            None => None,
        }
    } else {
        None
    };

    if let Some((id, plan)) = account {
        let limit = gs_quota_for(&plan);
        return match take_one(db, &format!("user:{id}"), &month(), limit).await {
            Ok(Some(n)) => allow(&plan, limit - n),
            Ok(None) => deny(
                StatusCode::FORBIDDEN,
                &format!(
                    "monthly GodShield quota of {limit} calls reached on the {plan} plan. \
                     Upgrade at https://q-lock-ecosystem.com (GodShield tab)"
                ),
            ),
            Err(e) => {
                tracing::error!(error = %e, "godshield authorize: count failed");
                deny(
                    StatusCode::FORBIDDEN,
                    "metering unavailable, try again shortly",
                )
            }
        };
    }

    // 3. Anonymous, by client IP (nginx passes it in X-GS-Client-IP).
    let ip = header("x-gs-client-ip").unwrap_or("unknown");
    match take_one(db, &format!("ip:{ip}"), &today(), GS_ANON_DAILY).await {
        Ok(Some(n)) => allow("anonymous", GS_ANON_DAILY - n),
        Ok(None) => deny(
            StatusCode::FORBIDDEN,
            &format!(
                "free limit of {GS_ANON_DAILY} GodShield calls per day reached. Create a free \
                 account for {GS_QUOTA_FREE} a month, or upgrade for more"
            ),
        ),
        Err(e) => {
            tracing::error!(error = %e, "godshield authorize: anon count failed");
            deny(
                StatusCode::FORBIDDEN,
                "metering unavailable, try again shortly",
            )
        }
    }
}

/// The signed-in account's plan, usage and API key.
pub async fn account(
    State(state): State<AppState>,
    Extension(claims): Extension<auth::Claims>,
) -> Result<impl IntoResponse, ApiError> {
    let id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::from((StatusCode::BAD_REQUEST, "invalid user id".to_string())))?;
    let (email, plan, api_key): (String, String, String) =
        sqlx::query_as("SELECT email, plan, api_key FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(db_err)?
            .ok_or_else(|| {
                ApiError::from((StatusCode::NOT_FOUND, "account not found".to_string()))
            })?;
    let calls = used(&state.db, &format!("user:{id}"), &month())
        .await
        .map_err(db_err)?;
    let quota = gs_quota_for(&plan);
    Ok(Json(serde_json::json!({
        "email": email,
        "plan": plan,
        "apiKey": api_key,
        "godshield": { "period": month(), "used": calls, "quota": quota,
                       "remaining": (quota - calls).max(0) },
    })))
}

/// Replace the account's API key. The old one stops working at once.
pub async fn rotate_key(
    State(state): State<AppState>,
    Extension(claims): Extension<auth::Claims>,
) -> Result<impl IntoResponse, ApiError> {
    let id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::from((StatusCode::BAD_REQUEST, "invalid user id".to_string())))?;
    let key = format!("qlk_{}", Uuid::new_v4().simple());
    sqlx::query("UPDATE users SET api_key = $1, updated_at = now() WHERE id = $2")
        .bind(&key)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;
    tracing::info!(user = %id, "API key rotated");
    Ok(Json(serde_json::json!({ "apiKey": key })))
}

/// Public plan table. Display prices come from the environment so they
/// always match the Stripe prices you created (STRIPE_PRICE_LABEL_PRO,
/// e.g. "£29/month"); a plan without a Stripe price shows as not for sale.
pub async fn plans() -> impl IntoResponse {
    let for_sale = |var: &str| {
        std::env::var(var)
            .map(|v| v.starts_with("price_"))
            .unwrap_or(false)
    };
    let label = |var: &str| std::env::var(var).ok().filter(|v| !v.trim().is_empty());
    Json(serde_json::json!({
        "plans": [
            { "id": "free", "name": "Free", "price": "£0",
              "godshieldCalls": GS_QUOTA_FREE, "escrowFeePercent": 0.30,
              "escrowsPerMonth": 5, "checkout": false },
            { "id": "pro", "name": "Pro",
              "price": label("STRIPE_PRICE_LABEL_PRO"),
              "godshieldCalls": GS_QUOTA_PRO, "escrowFeePercent": 0.20,
              "escrowsPerMonth": null, "checkout": for_sale("STRIPE_PRICE_PRO") },
            { "id": "enterprise", "name": "Enterprise",
              "price": label("STRIPE_PRICE_LABEL_ENTERPRISE"),
              "godshieldCalls": GS_QUOTA_ENTERPRISE, "escrowFeePercent": 0.15,
              "escrowsPerMonth": null, "checkout": for_sale("STRIPE_PRICE_ENTERPRISE") },
        ],
        "anonymousDailyCalls": GS_ANON_DAILY,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotas_rise_with_the_plan() {
        assert!(gs_quota_for("free") < gs_quota_for("pro"));
        assert!(gs_quota_for("pro") < gs_quota_for("enterprise"));
        assert_eq!(gs_quota_for("something-else"), GS_QUOTA_FREE);
        // Checked at compile time (clippy: assertions_on_constants).
        const _: () = assert!(GS_ANON_DAILY < GS_QUOTA_FREE);
    }

    #[test]
    fn deny_reasons_are_safe_to_splice_into_json() {
        let r = deny(StatusCode::FORBIDDEN, "quota \"reached\" — upgrade\\now");
        let v = r
            .headers()
            .get("x-godshield-reason")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(!v.contains('"') && !v.contains('\\') && v.is_ascii());
    }

    #[test]
    fn periods_have_the_expected_shape() {
        assert_eq!(month().len(), 7);
        assert_eq!(today().len(), 10);
    }
}
