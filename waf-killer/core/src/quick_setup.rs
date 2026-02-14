// ============================================
// File: core/src/quick_setup.rs
// ============================================
//! Quick Setup — Zero-config WAF activation in one API call.
//!
//! Accepts a backend URL + security level, validates connectivity,
//! and hot-reloads the WAF config via ArcSwap.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};
use url::Url;

use crate::state::WafState;
use crate::config::Config;

// ═══════════════════════════════════════════════
// Request / Response Types
// ═══════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct QuickSetupRequest {
    pub backend_url: String,
    pub security_level: String, // "strict" | "moderate" | "permissive"
}

#[derive(Debug, Serialize)]
pub struct QuickSetupResponse {
    pub status: String,
    pub waf_url: String,
    pub backend_url: String,
    pub security_level: String,
    pub anomaly_threshold: i32,
    pub rules_enabled: bool,
    pub ml_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

// ═══════════════════════════════════════════════
// Security Level Presets
// ═══════════════════════════════════════════════

struct SecurityPreset {
    inbound_threshold: i32,
    paranoia_level: u8,
    blocking_threshold: i32,
    challenge_threshold: i32,
}

fn get_preset(level: &str) -> Result<SecurityPreset, String> {
    match level {
        "strict" => Ok(SecurityPreset {
            inbound_threshold: 3,
            paranoia_level: 3,
            blocking_threshold: 15,
            challenge_threshold: 10,
        }),
        "moderate" => Ok(SecurityPreset {
            inbound_threshold: 5,
            paranoia_level: 1,
            blocking_threshold: 25,
            challenge_threshold: 15,
        }),
        "permissive" => Ok(SecurityPreset {
            inbound_threshold: 10,
            paranoia_level: 1,
            blocking_threshold: 40,
            challenge_threshold: 25,
        }),
        _ => Err(format!("Invalid security level '{}'. Must be: strict, moderate, or permissive", level)),
    }
}

// ═══════════════════════════════════════════════
// URL Validation
// ═══════════════════════════════════════════════

fn validate_backend_url(raw: &str) -> Result<Url, String> {
    let parsed = Url::parse(raw).map_err(|e| format!("Invalid URL format: {}", e))?;

    // Must be HTTP or HTTPS
    match parsed.scheme() {
        "http" | "https" => {}
        s => return Err(format!("Unsupported scheme '{}'. Use http:// or https://", s)),
    }

    // Block cloud metadata SSRF
    if let Some(host) = parsed.host_str() {
        if host == "169.254.169.254" || host == "metadata.google.internal" {
            return Err("Cloud metadata endpoints are blocked for security".into());
        }
    } else {
        return Err("Missing hostname".into());
    }

    // Port range
    if let Some(port) = parsed.port() {
        if port == 0 {
            return Err("Port 0 is invalid".into());
        }
    }

    Ok(parsed)
}

// ═══════════════════════════════════════════════
// Connectivity Test
// ═══════════════════════════════════════════════

async fn test_connectivity(url: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true) // Allow self-signed certs during setup
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    match client.get(url).send().await {
        Ok(resp) => {
            info!("🔗 Backend connectivity test: {} → HTTP {}", url, resp.status());
            // Any response (even 404) means the server is reachable
            Ok(())
        }
        Err(e) => {
            warn!("🔗 Backend connectivity test failed: {} → {}", url, e);
            Err(format!("Cannot connect to {}. Is your app running? ({})", url, e))
        }
    }
}

// ═══════════════════════════════════════════════
// Handler
// ═══════════════════════════════════════════════

/// POST /quick-setup - One-click WAF activation
pub async fn quick_setup_handler(
    State(state): State<Arc<WafState>>,
    Json(req): Json<QuickSetupRequest>,
) -> impl IntoResponse {
    info!("🚀 Quick Setup request: url={}, level={}", req.backend_url, req.security_level);

    // 1. Validate URL format
    let parsed_url = match validate_backend_url(&req.backend_url) {
        Ok(u) => u,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": e,
                "code": "INVALID_URL"
            })));
        }
    };

    // 2. Get security preset
    let preset = match get_preset(&req.security_level) {
        Ok(p) => p,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": e,
                "code": "INVALID_LEVEL"
            })));
        }
    };

    // 3. Test backend connectivity
    if let Err(e) = test_connectivity(&req.backend_url).await {
        return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
            "error": e,
            "code": "UNREACHABLE"
        })));
    }

    // 4. Clone and update config
    let current_arc = state.config.load();
    let mut new_config: Config = (**current_arc).clone();

    new_config.upstream.backend_url = req.backend_url.clone();
    new_config.detection.enabled = true;
    new_config.detection.mode = crate::config::DetectionMode::Blocking;
    new_config.detection.crs.enabled = true;
    new_config.detection.crs.inbound_threshold = preset.inbound_threshold;
    new_config.detection.crs.paranoia_level = preset.paranoia_level;
    new_config.detection.blocking_threshold = preset.blocking_threshold;
    new_config.detection.challenge_threshold = preset.challenge_threshold;

    // 5. Hot-reload via ArcSwap (no restart needed!)
    state.config.store(Arc::new(new_config.clone()));

    // 6. Notify modules
    if let Some(ref engine) = state.ml_engine {
        engine.update_threshold(new_config.ml.threshold);
    }

    let http_port = new_config.server.http_port;
    let waf_url = format!("http://localhost:{}", http_port);

    info!(
        "✅ Quick Setup complete: {} → WAF @ {} (level: {}, threshold: {})",
        req.backend_url, waf_url, req.security_level, preset.inbound_threshold
    );

    // 7. Return response
    (StatusCode::OK, Json(serde_json::json!({
        "status": "active",
        "waf_url": waf_url,
        "backend_url": req.backend_url,
        "security_level": req.security_level,
        "anomaly_threshold": preset.inbound_threshold,
        "rules_enabled": true,
        "ml_enabled": new_config.ml.enabled,
    })))
}
