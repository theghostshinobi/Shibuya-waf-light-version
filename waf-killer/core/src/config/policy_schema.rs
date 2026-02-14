// ============================================
// File: core/src/config/policy_schema.rs
// ============================================
//! Policy schema definitions for validation

use serde::{Deserialize, Serialize};

/// Policy schema for validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySchema {
    pub version: String,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
}

impl Default for PolicySchema {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            rules: vec![],
        }
    }
}
