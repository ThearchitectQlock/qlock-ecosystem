//! Per-IP rate limiting (tower_governor 0.4).
//!
//! 0.4 holds its config in an `Arc` and names the middleware type, so the
//! layer is `GovernorLayer<KeyExtractor, Middleware>` with no lifetime.
//! Older drafts used 0.3's `GovernorLayer<'static, K>` with `Box::leak`.
//!
//! `SmartIpKeyExtractor` reads X-Forwarded-For / X-Real-IP (nginx sets
//! them) and falls back to the socket address. That fallback needs the
//! server started with `into_make_service_with_connect_info::<SocketAddr>()`
//! (see main.rs), or requests that bypass nginx — container health
//! checks — are rejected.

use std::sync::Arc;

use governor::{clock::QuantaInstant, middleware::NoOpMiddleware};
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};

pub type IpLimiter = GovernorLayer<SmartIpKeyExtractor, NoOpMiddleware<QuantaInstant>>;

fn limiter(per_second: u64, burst: u32) -> IpLimiter {
    let config = GovernorConfigBuilder::default()
        .per_second(per_second)
        .burst_size(burst)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("per_second and burst_size are non-zero constants");
    GovernorLayer {
        config: Arc::new(config),
    }
}

/// General API limiter: 20 req/sec per IP, burst 40.
/// Applied globally to every route in main.rs.
pub fn api_limiter() -> IpLimiter {
    limiter(20, 40)
}

/// Stricter limiter for money-moving endpoints: 5 req/sec, burst 10.
/// Apply it to /escrow/* and /send for extra protection, e.g.:
///
/// .route("/escrow/create", post(create_escrow).layer(ratelimit::escrow_limiter()))
#[allow(dead_code)]
pub fn escrow_limiter() -> IpLimiter {
    limiter(5, 10)
}
