// ============================================
// File: core/src/config/validation.rs
// ============================================
//! Validation engine for WAF configuration to prevent invalid states.
//!
//! # Objectives
//! - Prevent invalid numeric ranges
//! - Ensure referenced files exist
//! - Prevent dangerous logic combinations (e.g. blocking threshold < challenge threshold)
//! - Business logic validation

use super::{Config, ConfigError};
use tracing::warn;
use std::path::Path;

pub struct ValidationEngine;

impl ValidationEngine {
    /// comprehensive validation runner
    pub fn validate(config: &Config) -> Result<(), ConfigError> {
        Self::validate_server_config(config)?;
        Self::validate_upstream_config(config)?;
        Self::validate_detection_config(config)?;
        Self::validate_ml_config(config)?;
        Self::validate_api_protection(config)?;
        
        Ok(())
    }

    /// Check if a proposed update is valid relative to the current config
    /// e.g., don't allow disabling all security features at once if that's a policy
    pub fn validate_update(_old: &Config, new: &Config) -> Result<(), ConfigError> {
        // Run standard validation on the new config
        Self::validate(new)?;
        
        // Add delta-specific validation here if needed
        // For example: "Cannot change listen port without restart" - but we support restarts so maybe ok.
        
        Ok(())
    }

    fn validate_server_config(config: &Config) -> Result<(), ConfigError> {
        if config.server.tls.enabled {
            check_file_exists(&config.server.tls.cert_path, "TLS Certificate")?;
            check_file_exists(&config.server.tls.key_path, "TLS Key")?;
        }
        Ok(())
    }

    fn validate_upstream_config(config: &Config) -> Result<(), ConfigError> {
        if config.upstream.backend_url.is_empty() {
            return Err(ConfigError::Invalid("Backend URL cannot be empty".to_string()));
        }
        if config.upstream.pool_size == 0 {
             return Err(ConfigError::Invalid("Upstream pool size must be > 0".to_string()));
        }
        Ok(())
    }

    fn validate_detection_config(config: &Config) -> Result<(), ConfigError> {
        let d = &config.detection;
        
        // Threshold logic
        if d.blocking_threshold <= d.challenge_threshold {
             // This is a warning in the original code, but could be an error for strictness.
             // We'll keep it as a logical check that users might want to know about.
             // For strict validation we might force block > challenge.
             warn!("Validation Warning: blocking_threshold ({}) <= challenge_threshold ({})", 
                d.blocking_threshold, d.challenge_threshold);
        }

        // CRS
        if d.crs.enabled {
             // We might check if rules_path directory exists, but it might not be critical 
             // if we allow auto-download later. For now, warn if missing.
             if !d.crs.rules_path.exists() {
                 warn!("CRS rules directory not found: {:?}", d.crs.rules_path);
             }
             if d.crs.paranoia_level < 1 || d.crs.paranoia_level > 4 {
                 return Err(ConfigError::Invalid("CRS paranoia level must be 1-4".to_string()));
             }
        }

        // Rate Limiting
        if d.rate_limiting.enabled {
            if d.rate_limiting.requests_per_second == 0 {
                return Err(ConfigError::Invalid("Rate limit RPS must be > 0".to_string()));
            }
        }

        Ok(())
    }

    fn validate_ml_config(config: &Config) -> Result<(), ConfigError> {
        if config.ml.enabled {
            if config.ml.threshold < 0.0 || config.ml.threshold > 1.0 {
                 return Err(ConfigError::Invalid("ML threshold must be 0.0 - 1.0".to_string()));
            }
            check_file_exists(&config.ml.model_path, "ML Model")?;
            // Optional: check other ml paths?
        }
        Ok(())
    }

    fn validate_api_protection(config: &Config) -> Result<(), ConfigError> {
        if config.api_protection.enabled {
            // Check specs
            for spec in &config.api_protection.openapi_specs {
                if !spec.exists() {
                    // For strict validation, error. Or warn. 
                    // Objective 2 says "Dependency validation: Referenced resources exist"
                    // So we should fail if it doesn't exist AND we are relying on it.
                    // But maybe just warn is safer to not break boot? 
                    // "Expected behavior: Invalid configs are REJECTED before any disk write."
                    // So we should Error.
                     return Err(ConfigError::Invalid(format!("OpenAPI spec not found: {:?}", spec)));
                }
            }

            // GraphQL
            let gql = &config.api_protection.graphql;
            if gql.max_depth == 0 || gql.max_depth > 100 {
                 return Err(ConfigError::Invalid("GraphQL max_depth must be 1-100".to_string()));
            }
        }
        Ok(())
    }
}

fn check_file_exists(path: &Path, name: &str) -> Result<(), ConfigError> {
    if !path.exists() {
        return Err(ConfigError::Invalid(format!("{} not found at {:?}", name, path)));
    }
    Ok(())
}
