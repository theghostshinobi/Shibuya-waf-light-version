// core/src/shadow/mod.rs

pub mod capture;
pub mod replay;
pub mod executor;
pub mod diff;
pub mod rollout;
pub mod watchdog;

use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::rules::engine::{InspectionResult, InspectionAction, RuleMatch};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowConfig {
    pub enabled: bool,
    pub percentage: u8,          // 1-100
    pub duration: Option<Duration>,  // Auto-disable after duration
    pub routes: Option<Vec<String>>, // Only shadow specific routes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowResult {
    pub decision: InspectionResult,
    pub diff_from_prod: DecisionDiff,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionDiff {
    pub request_id: String,
    pub production_action: InspectionAction,
    pub shadow_action: InspectionAction,
    pub action_changed: bool,
    
    pub production_score: i32,
    pub shadow_score: i32,
    pub score_delta: i32,
    
    pub production_rules: Vec<RuleMatch>,
    pub shadow_rules: Vec<RuleMatch>,
    
    pub new_blocks: bool,
    pub new_allows: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowSummary {
    pub total_shadowed: i64,
    pub action_diffs: i64,
    pub new_blocks: i64,
    pub new_allows: i64,
    pub avg_score_delta: f64,
}
