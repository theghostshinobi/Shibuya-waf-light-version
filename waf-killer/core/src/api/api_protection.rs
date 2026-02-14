use axum::{
    extract::State,
    http::StatusCode,
    Json,
    response::IntoResponse,
};
use std::sync::Arc;

use crate::api_protection::openapi::OpenApiSpec;

/// Upload OpenAPI spec (YAML format)
pub async fn upload_openapi_spec_handler(
    State(waf_state): State<Arc<crate::state::WafState>>,
    body: String,
) -> impl IntoResponse {
    // Parse the YAML
    let spec = match serde_yaml::from_str::<OpenApiSpec>(&body) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid OpenAPI YAML: {}", e),
            ).into_response();
        }
    };
    
    // Store in state
    let mut spec_lock = waf_state.api_protection_state.openapi_spec.write().await;
    *spec_lock = Some(spec);
    
    (StatusCode::OK, "OpenAPI spec uploaded successfully").into_response()
}

/// Get current OpenAPI spec (if loaded)
pub async fn get_openapi_spec_handler(
    State(waf_state): State<Arc<crate::state::WafState>>,
) -> impl IntoResponse {
    let spec_lock = waf_state.api_protection_state.openapi_spec.read().await;
    
    match &*spec_lock {
        Some(spec) => {
            // Serialize back to YAML
            match serde_yaml::to_string(spec) {
                Ok(yaml) => (StatusCode::OK, yaml).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to serialize spec: {}", e),
                ).into_response(),
            }
        }
        None => (StatusCode::NOT_FOUND, "No OpenAPI spec loaded").into_response(),
    }
}

/// Get API protection statistics
pub async fn get_api_protection_stats_handler(
    State(waf_state): State<Arc<crate::state::WafState>>,
) -> impl IntoResponse {
    let snapshot = waf_state.api_protection_state.stats.get_snapshot();
    Json(snapshot)
}

pub fn routes() -> axum::Router<Arc<crate::state::WafState>> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route(
            "/api-protection/openapi",
            post(upload_openapi_spec_handler).get(get_openapi_spec_handler),
        )
        .route(
            "/api-protection/stats",
            get(get_api_protection_stats_handler),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_protection::state::{ApiProtectionStats, ApiProtectionState};

    #[tokio::test]
    async fn test_upload_openapi_spec() {
        let state = ApiProtectionState::default();
        
        let yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /test:
    get:
      summary: Test endpoint
"#;
        
        // Simulate upload
        let spec = serde_yaml::from_str::<OpenApiSpec>(yaml).unwrap();
        
        let mut lock = state.openapi_spec.write().await;
        *lock = Some(spec);
        drop(lock);
        
        // Verify it's stored
        let lock: tokio::sync::RwLockReadGuard<'_, _> = state.openapi_spec.read().await;
        assert!(lock.is_some());
    }
    
    #[test]
    fn test_stats_increment() {
        let stats = ApiProtectionStats::default();
        
        stats.increment_validation();
        stats.increment_openapi_block();
        
        let snapshot = stats.get_snapshot();
        assert_eq!(snapshot.total_validations, 1);
        assert_eq!(snapshot.openapi_blocks, 1);
    }
}
