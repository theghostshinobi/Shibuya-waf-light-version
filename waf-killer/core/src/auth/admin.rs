use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
    http::StatusCode,
};
use tracing::{warn, info, error};
use std::sync::Arc;
use crate::state::WafState;

/// Middleware to secure Admin API endpoints.
///
/// Security policy:
/// - If `admin_token` is configured → require valid `X-Admin-Token` header (constant-time comparison)
/// - If `admin_token` is NOT configured → **DENY ALL** (fail-closed)
/// - God Mode bypass is only available via the `WAF_GOD_MODE_KEY` environment variable
///   and is disabled by default in production.
pub async fn admin_auth_middleware(
    State(state): State<Arc<WafState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let config = state.config.load();
    
    // 0. Check for God Mode key (env-var controlled, NOT hardcoded)
    if let Some(god_mode_key) = std::env::var("WAF_GOD_MODE_KEY").ok() {
        if !god_mode_key.is_empty() {
            if let Some(token) = req.headers()
                .get("X-Admin-Token")
                .and_then(|h| h.to_str().ok())
            {
                if constant_time_eq(token, &god_mode_key) {
                    info!("🔓 GOD MODE ACCESS via env-configured key (request: {})", req.uri());
                    return Ok(next.run(req).await);
                }
            }
        }
    }

    // 1. Get configured admin token
    let expected_token = match &config.security.admin_token {
        Some(t) if !t.is_empty() => t,
        _ => {
            // FAIL-CLOSED: No admin token configured = deny all access
            // This prevents accidental exposure of the admin API
            error!(
                "⛔ Admin API: No admin_token configured. All access denied. \
                 Set `security.admin_token` in config or `WAF_GOD_MODE_KEY` env var."
            );
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // 2. Extract header
    let auth_header = req.headers()
        .get("X-Admin-Token")
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(token) if constant_time_eq(token, expected_token) => {
            // 3. Valid token
            Ok(next.run(req).await)
        },
        Some(_) => {
            // 4. Invalid token
            warn!("⛔ Admin API: Invalid token for {:?}", req.uri());
            Err(StatusCode::UNAUTHORIZED)
        },
        None => {
            // 5. Missing token
            warn!("⛔ Admin API: Missing token for {:?}", req.uri());
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Constant time comparison to prevent timing attacks.
/// Uses XOR accumulation — both strings are fully traversed regardless of mismatch position.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("secret123", "secret123"));
        assert!(!constant_time_eq("secret123", "secret456"));
        assert!(!constant_time_eq("short", "longer_string"));
        assert!(constant_time_eq("", ""));
    }
}
