use axum::{Router, Json, extract::State, routing::{get, post}, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::path::Path;

use crate::state::WafState;
use crate::config::Config; // Assuming Config is WafConfig
use crate::rules::engine::{RuleEngine, EngineConfig, EngineMode};
use crate::rules::loader::RuleSet;
use crate::config::DetectionMode;

// Config endpoints
pub fn config_routes() -> Router<Arc<WafState>> {
    Router::new()
        .route("/config", get(get_config))
        .route("/config", post(update_config))
        .route("/config/validate", post(validate_config))
        .route("/config/upload", post(upload_yaml))
        .route("/config/reload", post(reload_config))
}

// GET /api/config - Get current config as JSON
async fn get_config(State(state): State<Arc<WafState>>) -> Result<Json<ConfigResponse>, StatusCode> {
    // Load config from ArcSwap
    let config = state.config.load();
    let path = "config/waf.yaml".to_string(); 
    
    let config_value = serde_json::to_value(&**config)
        .map_err(|e| {
            log::error!("Failed to serialize config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    Ok(Json(ConfigResponse {
        config: config_value,
        file_path: path,
        last_modified: chrono::Utc::now().to_rfc3339(),
    }))
}

// POST /api/config - Update config
async fn update_config(
    State(state): State<Arc<WafState>>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<ApiResponse>, StatusCode> {
    // Validate first (basic check)
    // We can run internal validation here
    
    // Apply to runtime (ArcSwap)
    state.config.store(Arc::new(req.config.clone()));
    
    // Save to file
    // Note: We need to handle error properly
    if let Err(e) = save_config_to_file(&req.config, "config/waf.yaml") {
        log::error!("Failed to save config: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    
    // Reload components
    if let Err(e) = reload_waf_components(&state, &req.config).await {
        log::error!("Failed to reload components: {}", e);
        // We already updated config in memory, so this is a partial failure state
        return Ok(Json(ApiResponse {
            success: false,
            message: format!("Config saved but reload failed: {}", e),
        }));
    }
    
    Ok(Json(ApiResponse {
        success: true,
        message: "Configuration updated successfully".to_string(),
    }))
}

// POST /api/config/validate - Validate without applying
async fn validate_config(
    Json(req): Json<ValidateConfigRequest>,
) -> Json<ValidationResponse> {
    // Parse YAML
    let config_result = serde_yaml::from_str::<Config>(&req.yaml);
    
    match config_result {
        Ok(config) => {
            // Validate structure
            let mut errors = Vec::new();
            
            // Check required fields (example)
            if config.upstream.backend_url.is_empty() {
                errors.push("upstream.backend_url is required".to_string());
            }
            
            // Check threshold ranges
            if config.detection.crs.inbound_threshold < 1 || config.detection.crs.inbound_threshold > 100 {
                errors.push("detection.crs.inbound_threshold must be 1-100".to_string());
            }
            
            if config.ml.threshold < 0.0 || config.ml.threshold > 1.0 {
                errors.push("ml.threshold must be 0.0-1.0".to_string());
            }
            
            Json(ValidationResponse {
                valid: errors.is_empty(),
                errors,
                warnings: vec![],
            })
        }
        Err(e) => Json(ValidationResponse {
            valid: false,
            errors: vec![format!("YAML parse error: {}", e)],
            warnings: vec![],
        })
    }
}

// POST /api/config/upload - Upload YAML file
async fn upload_yaml(
    State(state): State<Arc<WafState>>,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<ApiResponse>, StatusCode> {
    
    let mut yaml_content = String::new();
    
    // Explicit error handling
    while let Ok(Some(field)) = multipart.next_field().await {
        if let Some(name) = field.name() {
            if name == "yaml" || name == "file" {
                match field.text().await {
                    Ok(text) => {
                        yaml_content = text;
                        break;
                    }
                    Err(e) => {
                        log::error!("Failed to read field: {}", e);
                        return Err(StatusCode::BAD_REQUEST);
                    }
                }
            }
        }
    }
    
    if yaml_content.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    // Parse and apply
    let config: Config = match serde_yaml::from_str(&yaml_content) {
        Ok(c) => c,
        Err(e) => {
             log::error!("YAML parse error: {}", e);
             return Err(StatusCode::BAD_REQUEST);
        }
    };
    
    state.config.store(Arc::new(config.clone()));
    
    if let Err(e) = save_config_to_file(&config, "config/waf.yaml") {
         log::error!("Failed to save config: {}", e);
         return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    
    if let Err(e) = reload_waf_components(&state, &config).await {
         log::error!("Failed to reload components: {}", e);
         return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    
    Ok(Json(ApiResponse {
        success: true,
        message: "YAML uploaded and applied".to_string(),
    }))
}

// POST /api/config/reload - Reload from disk
async fn reload_config(
    State(state): State<Arc<WafState>>,
) -> Result<Json<ApiResponse>, StatusCode> {
    // Assuming we reload from default path
    let config = match Config::load("config/waf.yaml").await {
         Ok(c) => c,
         Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    
    state.config.store(Arc::new(config.clone()));
    
    if let Err(_e) = reload_waf_components(&state, &config).await {
         return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    
    Ok(Json(ApiResponse {
        success: true,
        message: "Configuration reloaded from disk".to_string(),
    }))
}

// Helper: Reload WAF components without restart
async fn reload_waf_components(
    state: &Arc<WafState>,
    config: &Config,
) -> Result<(), anyhow::Error> {
    // Reload rule engine settings
    // Note: This changes the settings for the *next* request processing, 
    // but we might need to reload the rules from disk if path changed?
    // For now we assume just settings change or we trigger a full reload if needed.
    // Ideally we re-create the engine logic.
    
    // Update RuleEngine
    let engine_config = EngineConfig {
        paranoia_level: config.detection.crs.paranoia_level,
        inbound_threshold: config.detection.crs.inbound_threshold, 
        outbound_threshold: config.detection.crs.outbound_threshold,
        enabled: config.detection.mode != DetectionMode::Off,
        mode: match config.detection.mode {
             DetectionMode::Blocking => EngineMode::Blocking,
             DetectionMode::Detection => EngineMode::Detection,
             DetectionMode::Off => EngineMode::Off,
        },
    };
    
    // We need to keep existing rules but update config. 
    // Accessing rules from existing engine is tricky if we don't have a way to copy them cheaply.
    // But RuleEngine holds Arc<Vec<Rule>>? No, it holds Vec.
    // So we might need to reload rules from disk to be safe, or cloning is expensive.
    // Let's reload from disk to ensure consistency.
    let rules_path = Path::new(&config.detection.crs.rules_path);
    let rule_set = RuleSet::load_from_dir(rules_path)?;
    
    state.rule_engine.store(Arc::new(RuleEngine::new(rule_set.rules, engine_config)));
    
    // Update ML threshold
    if let Some(ref ml) = state.ml_engine {
        // ml.update_threshold(config.ml.threshold);
    }
    
    // Reload threat intel feeds
    if let Some(ref threat) = state.threat_intel {
        // We need to implement reload_with_config on ThreatClient
        // For now, we manually assume the client handles its own config or we update it.
        // I will add a method `update_config` to ThreatIntelClient.
         threat.update_config(config.threat_intel.clone()).await?;
    }
    
    log::info!("WAF components reloaded successfully");
    Ok(())
}

fn save_config_to_file(config: &Config, path: &str) -> std::io::Result<()> {
    let f = std::fs::File::create(path)?;
    serde_yaml::to_writer(f, config).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

#[derive(Serialize)]
struct ConfigResponse {
    config: serde_json::Value,
    file_path: String,
    last_modified: String,
}

#[derive(Deserialize)]
struct UpdateConfigRequest {
    config: Config,
}

#[derive(Deserialize)]
struct ValidateConfigRequest {
    yaml: String,
    #[allow(dead_code)]
    check_connectivity: bool,
}

#[derive(Serialize)]
struct ValidationResponse {
    valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
}
