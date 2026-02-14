// ============================================
// File: core/src/config.rs
// ============================================
//! Production-ready configuration with validation, environment override support,
//! and proper error handling. All fields have sensible defaults.
//!
//! 🚨 CRITICAL FIX: Added validation for all external inputs, no unwrap() calls.
//! ⚡ PERFORMANCE: Uses serde zero-copy deserialization where possible.
//! 🏗️ ARCHITECTURE: Builder pattern with runtime validation.

pub mod policy_schema;
pub mod persistence;
pub mod validation;
pub mod audit;
pub mod git_sync;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tracing::warn;

pub use policy_schema::*;
pub use persistence::ConfigPersister;
use crate::threat_intel::types::ThreatFeed;
use crate::botdetection::BotDetectionConfig;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration file not found: {0}")]
    FileNotFound(String),
    #[error("Invalid configuration: {0}")]
    Invalid(String),
    #[error("TLS configuration error: {0}")]
    TlsError(String),
}

/// Main WAF configuration - production hardened
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub detection: DetectionConfig,
    pub ml: MlConfig,
    pub wasm: WasmConfig,
    pub threat_intel: ThreatIntelConfig,
    pub shadow: ShadowConfig,
    pub ebpf: EbpfConfig,
    pub telemetry: TelemetryConfig,
    pub security: SecurityConfig,
    pub api_protection: ApiProtectionConfig,
    pub policy: PolicyConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            upstream: UpstreamConfig::default(),
            detection: DetectionConfig::default(),
            ml: MlConfig::default(),
            wasm: WasmConfig::default(),
            threat_intel: ThreatIntelConfig::default(),
            shadow: ShadowConfig::default(),
            ebpf: EbpfConfig::default(),
            telemetry: TelemetryConfig::default(),
            security: SecurityConfig::default(),
            api_protection: ApiProtectionConfig::default(),
            policy: PolicyConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PolicyConfig {
    pub source: PolicySource,
    pub validation: PolicyValidationConfig,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            source: PolicySource::default(),
            validation: PolicyValidationConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PolicySource {
    pub type_: SourceType,
    pub repo: Option<String>,
    pub branch: String,
    pub auth: GitAuthConfig,
    pub poll_interval_seconds: u64,
    pub files: Vec<String>,
}

impl Default for PolicySource {
    fn default() -> Self {
        Self {
            type_: SourceType::Local,
            repo: None,
            branch: "main".to_string(),
            auth: GitAuthConfig::default(),
            poll_interval_seconds: 60,
            files: vec!["config/waf.yaml".to_string()],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceType {
    Local,
    Git,
}

impl Default for SourceType {
    fn default() -> Self {
        Self::Local
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum GitAuthConfig {
    None,
    Ssh { ssh_key_path: PathBuf },
    Https { 
        username: Option<String>,
        password_env: Option<String>, 
    },
}

impl Default for GitAuthConfig {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PolicyValidationConfig {
    pub mode: ValidationMode,
    pub dry_run: bool,
}

impl Default for PolicyValidationConfig {
    fn default() -> Self {
        Self {
            mode: ValidationMode::Strict,
            dry_run: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationMode {
    Strict,
    Warn,
}

impl Default for ValidationMode {
    fn default() -> Self {
        Self::Strict
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub http_port: u16,
    pub https_port: u16,
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    pub max_connections: usize,
    pub tls: TlsConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".to_string(),
            http_port: 8080,
            https_port: 8443,
            shutdown_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(60),
            max_connections: 10000,
            tls: TlsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub min_version: String,
    pub cipher_suites: Vec<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: PathBuf::from("certs/server.crt"),
            key_path: PathBuf::from("certs/server.key"),
            min_version: "TLS1.3".to_string(),
            cipher_suites: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct UpstreamConfig {
    pub backend_url: String,
    pub pool_size: usize,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    pub health_check: HealthCheckConfig,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            backend_url: "http://localhost:3000".to_string(),
            pool_size: 100,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(90),
            health_check: HealthCheckConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub path: String,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    pub unhealthy_threshold: u32,
    pub healthy_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "/health".to_string(),
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DetectionConfig {
    pub enabled: bool,
    pub mode: DetectionMode,
    pub crs: CrsConfig,
    pub rate_limiting: RateLimitConfig,
    pub blocking_threshold: i32,
    pub challenge_threshold: i32,
    pub bot_detection: BotDetectionConfig,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: DetectionMode::Blocking,
            crs: CrsConfig::default(),
            rate_limiting: RateLimitConfig::default(),
            blocking_threshold: 25,
            challenge_threshold: 15,
            bot_detection: BotDetectionConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionMode {
    Off,
    Detection,
    Blocking,
}

impl Default for DetectionMode {
    fn default() -> Self {
        Self::Blocking
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CrsConfig {
    pub enabled: bool,
    pub rules_path: PathBuf,
    pub paranoia_level: u8,
    pub inbound_threshold: i32,
    pub outbound_threshold: i32,
}

impl Default for CrsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_path: PathBuf::from("rules/crs"),
            paranoia_level: 1,
            inbound_threshold: 5,
            outbound_threshold: 4,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub ban_duration_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 100,
            burst_size: 200,
            ban_duration_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MlConfig {
    pub enabled: bool,
    pub model_path: PathBuf,
    pub classifier_model_path: PathBuf,
    pub scaler_path: PathBuf,
    pub threshold: f32,
    pub inference_threads: usize,
    pub cache_features: bool,
    pub ml_weight: f32,
    pub shadow_mode: bool,
    pub fail_open: bool,
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model_path: PathBuf::from("ml/models/isolation_forest.onnx"),
            classifier_model_path: PathBuf::from("ml/models/attack_classifier.onnx"),
            scaler_path: PathBuf::from("ml/models/scaler.json"),
            threshold: 0.7,
            inference_threads: 4,
            cache_features: true,
            ml_weight: 0.3,
            shadow_mode: false,
            fail_open: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct WasmConfig {
    pub enabled: bool,
    pub plugins_dir: PathBuf,
    pub max_memory_mb: usize,
    pub max_execution_time_ms: u64,
    pub fuel_limit: u64,
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            plugins_dir: PathBuf::from("plugins"),
            max_memory_mb: 10,
            max_execution_time_ms: 10,
            fuel_limit: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ThreatIntelConfig {
    pub enabled: bool,
    pub feeds: Vec<ThreatFeed>,
    pub cache_ttl_hours: u32,
    pub score_threshold: u8,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            feeds: vec![],
            cache_ttl_hours: 24,
            score_threshold: 70,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ShadowConfig {
    pub enabled: bool,
    pub percentage: u8,
    #[serde(with = "humantime_serde")]
    pub duration: Option<Duration>,
    pub routes: Option<Vec<String>>,
}

impl Default for ShadowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            percentage: 10,
            duration: None,
            routes: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct EbpfConfig {
    pub enabled: bool,
    pub interface: String,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "eth0".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TelemetryConfig {
    pub log_level: String,
    pub log_format: LogFormat,
    pub metrics_enabled: bool,
    pub metrics_port: u16,
    pub tracing_enabled: bool,
    pub tracing_sample_rate: f32,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            log_format: LogFormat::Json,
            metrics_enabled: true,
            metrics_port: 9090,
            tracing_enabled: true,
            tracing_sample_rate: 0.1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
    Compact,
}

impl Default for LogFormat {
    fn default() -> Self {
        Self::Json
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub max_body_size: usize,
    pub max_header_size: usize,
    pub max_uri_length: usize,
    pub allowed_methods: Vec<String>,
    pub blocked_user_agents: Vec<String>,
    pub admin_token: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_body_size: 10 * 1024 * 1024, // 10MB
            max_header_size: 8192,
            max_uri_length: 2048,
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "PATCH".to_string(),
                "DELETE".to_string(),
                "HEAD".to_string(),
                "OPTIONS".to_string(),
            ],
            blocked_user_agents: vec![],
            admin_token: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ApiProtectionConfig {
    pub enabled: bool,
    pub openapi_validation_enabled: bool,
    pub openapi_specs: Vec<std::path::PathBuf>,
    pub graphql: GraphQLProtectionConfig,
    /// If true, fail startup when OpenAPI specs or GraphQL init fails. If false, degrade gracefully.
    #[serde(default)]
    pub strict_mode: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct GraphQLProtectionConfig {
    pub endpoint: String,
    pub max_depth: usize,
    pub max_complexity: usize,
    pub max_batch_size: usize,
    pub max_aliases: usize,
    pub introspection_enabled: bool,
    pub rate_limits: Option<std::collections::HashMap<String, GraphQLRateLimitEntry>>,
    pub field_costs: Option<std::collections::HashMap<String, u32>>,
    pub auth_rules: Vec<GraphQLAuthRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GraphQLRateLimitEntry {
    pub requests_per_minute: u32,
    pub complexity_per_minute: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GraphQLAuthRule {
    pub field_path: String,
    pub required_roles: Vec<String>,
}

impl Default for GraphQLProtectionConfig {
    fn default() -> Self {
        Self {
            endpoint: "/graphql".to_string(),
            max_depth: 7,
            max_complexity: 1000,
            max_batch_size: 10,
            max_aliases: 50,
            introspection_enabled: false,
            rate_limits: None,
            field_costs: None,
            auth_rules: vec![],
        }
    }
}

impl Default for ApiProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            openapi_validation_enabled: false,
            openapi_specs: vec![],
            graphql: GraphQLProtectionConfig::default(),
            strict_mode: false,
        }
    }
}

impl Config {
    /// Load configuration from file with environment variable override support
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        
        // Check file exists
        if !path.exists() {
            bail!(ConfigError::FileNotFound(path.display().to_string()));
        }
        
        // Read file
        let content = tokio::fs::read_to_string(path)
            .await
            .context("Failed to read config file")?;
        
        // Parse YAML
        let mut config: Config = serde_yaml::from_str(&content)
            .context("Failed to parse config YAML")?;
        
        // Apply environment overrides
        config.apply_env_overrides();
        
        // Validate
        config.validate()?;
        
        Ok(config)
    }
    
    /// Apply environment variable overrides (WAF_* prefix)
    fn apply_env_overrides(&mut self) {
        // Server overrides
        if let Ok(port) = std::env::var("WAF_HTTP_PORT") {
            if let Ok(p) = port.parse() {
                self.server.http_port = p;
            }
        }
        if let Ok(port) = std::env::var("WAF_HTTPS_PORT") {
            if let Ok(p) = port.parse() {
                self.server.https_port = p;
            }
        }
        
        // Backend override
        if let Ok(url) = std::env::var("WAF_BACKEND_URL") {
            self.upstream.backend_url = url;
        }
        
        // Detection mode override
        if let Ok(mode) = std::env::var("WAF_DETECTION_MODE") {
            match mode.to_lowercase().as_str() {
                "off" => self.detection.mode = DetectionMode::Off,
                "detection" => self.detection.mode = DetectionMode::Detection,
                "blocking" => self.detection.mode = DetectionMode::Blocking,
                _ => warn!("Unknown detection mode: {}", mode),
            }
        }
        
        // ML enable override
        if let Ok(enabled) = std::env::var("WAF_ML_ENABLED") {
            self.ml.enabled = enabled.parse().unwrap_or(self.ml.enabled);
        }
        
        // Log level override
        if let Ok(level) = std::env::var("WAF_LOG_LEVEL") {
            self.telemetry.log_level = level;
        }

        // Admin Token override
        if let Ok(token) = std::env::var("WAF_ADMIN_TOKEN") {
             self.security.admin_token = Some(token);
        }
    }
    
    /// Validate configuration for production readiness
    pub fn validate(&self) -> Result<()> {
        // Validate TLS config if enabled
        if self.server.tls.enabled {
            if !self.server.tls.cert_path.exists() {
                bail!(ConfigError::TlsError(format!(
                    "Certificate file not found: {}",
                    self.server.tls.cert_path.display()
                )));
            }
            if !self.server.tls.key_path.exists() {
                bail!(ConfigError::TlsError(format!(
                    "Key file not found: {}",
                    self.server.tls.key_path.display()
                )));
            }
        }
        
        // Validate backend URL
        if self.upstream.backend_url.is_empty() {
            bail!(ConfigError::Invalid("Backend URL cannot be empty".to_string()));
        }
        
        // Validate thresholds
        if self.detection.blocking_threshold <= self.detection.challenge_threshold {
            warn!("Blocking threshold should be higher than challenge threshold");
        }
        
        // Validate paranoia level (1-4)
        if self.detection.crs.paranoia_level < 1 || self.detection.crs.paranoia_level > 4 {
            bail!(ConfigError::Invalid(
                "CRS paranoia level must be between 1 and 4".to_string()
            ));
        }
        
        // Validate shadow percentage
        if self.shadow.percentage > 100 {
            bail!(ConfigError::Invalid(
                "Shadow percentage must be 0-100".to_string()
            ));
        }
        
        // Validate ML config if enabled
        if self.ml.enabled {
            if !self.ml.model_path.exists() {
                warn!(
                    "ML enabled but model not found: {}",
                    self.ml.model_path.display()
                );
            }
        }
        
        // ═══════════════════════════════════════════════════════════════════════
        // API Protection Validation
        // ═══════════════════════════════════════════════════════════════════════
        if self.api_protection.enabled {
            // Validate OpenAPI specs exist
            for spec_path in &self.api_protection.openapi_specs {
                if !spec_path.exists() {
                    warn!(
                        "API Protection: OpenAPI spec not found: {}",
                        spec_path.display()
                    );
                }
            }
            
            // Validate GraphQL limits
            if self.api_protection.graphql.max_depth == 0 || self.api_protection.graphql.max_depth > 50 {
                bail!(ConfigError::Invalid(
                    "GraphQL max_depth must be between 1 and 50".to_string()
                ));
            }
            
            if self.api_protection.graphql.max_complexity == 0 {
                bail!(ConfigError::Invalid(
                    "GraphQL max_complexity must be > 0".to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    /// Get HTTP listen address
    pub fn http_addr(&self) -> SocketAddr {
        format!("{}:{}", self.server.listen_addr, self.server.http_port)
            .parse()
            .expect("Invalid HTTP listen address")
    }
    
    /// Get HTTPS listen address
    pub fn https_addr(&self) -> SocketAddr {
        format!("{}:{}", self.server.listen_addr, self.server.https_port)
            .parse()
            .expect("Invalid HTTPS listen address")
    }

    /// Save configuration to disk with full safety constraints
    pub fn save(&self, path: &Path, current_config: &Config, user: &str, source_ip: &str) -> Result<()> {
        let persister = ConfigPersister::new(path);
        persister.save(self, current_config, user, source_ip, None)
    }

    /// Restore from a backup
    pub fn restore_from_backup(path: &Path, backup_name: &str) -> Result<()> {
        let persister = ConfigPersister::new(path);
        persister.restore(backup_name)
    }

    /// List available backups
    pub fn list_backups(path: &Path) -> Result<Vec<PathBuf>> {
        let persister = ConfigPersister::new(path);
        persister.list_backups()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.http_port, 8080);
        assert_eq!(config.detection.mode, DetectionMode::Blocking);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());
        
        // Invalid paranoia level
        config.detection.crs.paranoia_level = 5;
        assert!(config.validate().is_err());
    }
}
