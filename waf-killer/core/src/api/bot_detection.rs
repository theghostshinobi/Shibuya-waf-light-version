use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use std::sync::Arc;

use crate::botdetection::{BotStatsSnapshot, BotDetectionConfig};

/// GET /api/bot-detection/stats - Get bot detection statistics
pub async fn get_bot_stats_handler(
    State(state): State<Arc<crate::state::WafState>>,
) -> Json<BotStatsSnapshot> {
    Json(state.bot_stats.get_snapshot())
}

/// GET /api/bot-detection/config - Get current bot detection config
pub async fn get_bot_config_handler(
    State(state): State<Arc<crate::state::WafState>>,
) -> Json<BotDetectionConfig> {
    let lock = state.bot_config.read().await;
    Json(lock.clone())
}

/// POST /api/bot-detection/config - Update bot detection config
pub async fn update_bot_config_handler(
    State(state): State<Arc<crate::state::WafState>>,
    Json(new_config): Json<BotDetectionConfig>,
) -> Result<Json<BotDetectionConfig>, StatusCode> {
    // Validate threshold
    if new_config.block_threshold < 0.0 || new_config.block_threshold > 1.0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let mut lock = state.bot_config.write().await;
    *lock = new_config.clone();
    
    Ok(Json(new_config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::botdetection::BotDetectionStats;

    #[test]
    fn test_bot_stats_increment() {
        let stats = BotDetectionStats::default();
        
        stats.increment_analyzed();
        stats.increment_detected();
        stats.increment_blocked();
        
        let snapshot = stats.get_snapshot();
        assert_eq!(snapshot.total_requests_analyzed, 1);
        assert_eq!(snapshot.bots_detected, 1);
        assert_eq!(snapshot.bots_blocked, 1);
    }
    
    #[test]
    fn test_config_validation() {
        let valid_config = BotDetectionConfig {
            enabled: true,
            fingerprint_check: true,
            behavior_analysis: false,
            block_threshold: 0.75,
        };
        
        assert!(valid_config.block_threshold >= 0.0);
        assert!(valid_config.block_threshold <= 1.0);
    }
}
