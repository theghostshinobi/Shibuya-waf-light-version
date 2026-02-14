use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct WafConfig {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub telemetry: TelemetryConfig,
    pub rule_engine: RuleEngineConfig,
    pub ml: MlConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ServerConfig {
    pub listen: ListenConfig,
    pub tls: TlsConfig,
    pub shutdown_timeout: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ListenConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct UpstreamConfig {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub pool: PoolConfig,
    pub health_check: HealthCheckConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PoolConfig {
    pub min_connections: usize,
    pub max_connections: usize,
    pub idle_timeout: String,
    pub connection_timeout: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub path: String,
    pub interval: String,
    pub timeout: String,
    pub unhealthy_threshold: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TelemetryConfig {
    pub log_level: String,
    pub log_format: String,
    pub metrics_enabled: bool,
    pub metrics_port: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct RuleEngineConfig {
    pub enabled: bool,
    pub mode: String,
    pub crs_path: String,
    pub custom_rules_path: String,
    pub paranoia_level: u8,
    pub inbound_threshold: i32,
    pub outbound_threshold: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct MlConfig {
    pub enabled: bool,
    pub anomaly_detection: AnomalyDetectionConfig,
    pub classification: ClassificationConfig,
    pub feedback: FeedbackConfig,
    pub baseline: BaselineConfig,
    pub explainability: ExplainabilityConfig,
    pub performance: PerformanceConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AnomalyDetectionConfig {
    pub model_path: String,
    pub threshold: f32,
    pub score_contribution: ScoreContributionConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScoreContributionConfig {
    pub high: i32,
    pub medium: i32,
    pub low: i32,
}

impl Default for ScoreContributionConfig {
    fn default() -> Self {
        Self { high: 5, medium: 3, low: 1 }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ClassificationConfig {
    pub enabled: bool,
    pub model_path: String,
    pub confidence_threshold: f32,
    pub score_contribution: ScoreContributionConfig,
    pub severity_multiplier: SeverityMultiplierConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SeverityMultiplierConfig {
    pub critical: f32,
    pub error: f32,
    pub warning: f32,
}

impl Default for SeverityMultiplierConfig {
    fn default() -> Self {
        Self { critical: 1.0, error: 1.0, warning: 1.0 }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct FeedbackConfig {
    pub enabled: bool,
    pub postgres_url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct BaselineConfig {
    pub path: String,
    pub update_interval: String,
    pub auto_retrain_threshold: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ExplainabilityConfig {
    pub enabled: bool,
    pub top_features: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PerformanceConfig {
    pub max_inference_time: String,
    pub cache_features: bool,
}
