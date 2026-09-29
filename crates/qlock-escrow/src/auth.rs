use crate::{ApiError, AppState, UserRow};
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Local shorthand matching main.rs — keeps auth errors JSON-shaped too.
fn err(code: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError::from((code, msg.into()))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub plan: String,
    pub exp: usize,
    pub iat: usize,
}
#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    #[serde(rename = "apiKey")]
    pub api_key: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub plan: String,
}

fn jwt_secret() -> String {
    std::env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set — refusing to run with a default secret")
}

pub fn generate_jwt(user_id: &str, email: &str, plan: &str) -> anyhow::Result<String> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        plan: plan.to_string(),
        iat: now.timestamp() as usize,
        exp: (now + Duration::hours(24)).timestamp() as usize,
    };

    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret().as_bytes()),
    )?)
}

pub fn verify_jwt(token: &str) -> anyhow::Result<Claims> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret().as_bytes()),
        &Validation::default(),
    )?;
    Ok(data.claims)
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if req.password.len() < 8 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Password must be 8+characters",
        ));
    }
    if !req.email.contains('@') {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid email"));
    }

    let password_hash = hash(&req.password, DEFAULT_COST)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let user_id = Uuid::new_v4();
    let api_key = format!("qlk_{}", Uuid::new_v4().simple());

    let result = sqlx::query(
        "INSERT INTO users (id, email, password_hash,api_key, plan) VALUES ($1,$2, $3, $4, 'free')",
    )
    .bind(user_id)
    .bind(&req.email)
    .bind(&password_hash)
    .bind(&api_key)
    .execute(&state.db)
    .await;

    if let Err(e) = result {
        // Postgres unique_violation error code = 23505
        if let Some(db_error) = e.as_database_error() {
            if db_error.code().as_deref() == Some("23505") {
                return Err(err(StatusCode::CONFLICT, "Email already registered"));
            }
        }
        tracing::error!("Register DB error: {:?}", e);
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Registration failed",
        ));
    }

    let token = generate_jwt(&user_id.to_string(), &req.email, "free")
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AuthResponse {
        token,
        api_key,
        user_id: user_id.to_string(),
        plan: "free".to_string(),
    }))
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id, email,password_hash, api_key,plan, created_at FROM users WHERE email = $1",
    )
    .bind(&req.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or(err(StatusCode::UNAUTHORIZED, "Invalid credentials"))?;

    let valid = verify(&req.password, &user.password_hash)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !valid {
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }

    let token = generate_jwt(&user.id.to_string(), &user.email, &user.plan)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AuthResponse {
        token,
        api_key: user.api_key,
        user_id: user.id.to_string(),
        plan: user.plan,
    }))
}
/// Middleware: require a valid JWT OR a valid X-API- Key header.
/// Both paths now hit Postgres — no in-memory user store left.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(api_key) = req.headers().get("x-api-key").and_then(|v| v.to_str().ok()) {
        let user =sqlx::query_as::<_, UserRow> (
              "SELECT id, email, password_hash,api_key, plan, created_at FROM users WHERE api_key =$1",
           )
           .bind(api_key)

 .fetch_optional(&state.db)
           .await
           .map_err(|_|StatusCode::INTERNAL_SERVER_ERROR)?;

        if let Some(user) = user {
            req.extensions_mut().insert(Claims {
                sub: user.id.to_string(),
                email: user.email,
                plan: user.plan,
                exp: 0,
                iat: 0,
            });
            return Ok(next.run(req).await);
        }
    }

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let mut claims = verify_jwt(token).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // The plan in a JWT is a snapshot from login. Read the current one so
    // a Stripe upgrade (or cancellation) applies to the very next request
    // instead of after the token expires.
    if let Ok(id) = Uuid::parse_str(&claims.sub) {
        if let Ok(Some(plan)) =
            sqlx::query_scalar::<_, String>("SELECT plan FROM users WHERE id = $1")
                .bind(id)
                .fetch_optional(&state.db)
                .await
        {
            claims.plan = plan;
        }
    }

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
