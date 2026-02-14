use std::collections::{VecDeque, HashMap};
use std::sync::atomic::AtomicBool;
use std::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use std::hash::Hash;
use std::fs;
use std::path::Path;
use tracing::{info, error, warn};
use std::sync::Arc;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use arc_swap::ArcSwap;
use crate::config::Config;
use crate::rules::engine::RuleEngine;
use crate::wasm::WasmPluginManager;
use crate::ml::inference::MLInferenceEngine;
use crate::ml::classification::ThreatClassifier;
use crate::vulnerabilities::VulnerabilityManager;
use crate::persistence::WafDatabase;
use sqlx::PgPool;


// ============================================
// Attack Category Enum for Analytics Breakdown
// ============================================
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackCategory {
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    RateLimitExceeded,
    BotDetected,
    MlAnomaly,
    ThreatIntel,
    ProtocolViolation,
    Other,
}

impl AttackCategory {
    /// Categorize based on rule ID ranges (CRS-style)
    pub fn from_rule_id(rule_id: u32) -> Self {
        match rule_id {
            942000..=942999 => AttackCategory::SqlInjection,  // CRS SQLi rules
            941000..=941999 => AttackCategory::Xss,            // CRS XSS rules  
            930000..=930999 => AttackCategory::PathTraversal,  // CRS LFI/RFI rules
            932000..=932999 => AttackCategory::CommandInjection, // CRS RCE rules
            _ => AttackCategory::Other,
        }
    }
    
    /// Categorize based on block reason string (fallback)
    pub fn from_reason(reason: &str) -> Self {
        let reason_lower = reason.to_lowercase();
        if reason_lower.contains("sql") || reason_lower.contains("sqli") {
            AttackCategory::SqlInjection
        } else if reason_lower.contains("xss") || reason_lower.contains("script") {
            AttackCategory::Xss
        } else if reason_lower.contains("path") || reason_lower.contains("traversal") || reason_lower.contains("lfi") {
            AttackCategory::PathTraversal
        } else if reason_lower.contains("rce") || reason_lower.contains("command") || reason_lower.contains("exec") {
            AttackCategory::CommandInjection
        } else if reason_lower.contains("rate") || reason_lower.contains("limit") {
            AttackCategory::RateLimitExceeded
        } else if reason_lower.contains("bot") {
            AttackCategory::BotDetected
        } else if reason_lower.contains("ml") || reason_lower.contains("anomaly") {
            AttackCategory::MlAnomaly
        } else if reason_lower.contains("threat") || reason_lower.contains("intel") {
            AttackCategory::ThreatIntel
        } else {
            AttackCategory::Other
        }
    }
    
    pub fn display_name(&self) -> &'static str {
        match self {
            AttackCategory::SqlInjection => "SQL Injection",
            AttackCategory::Xss => "XSS",
            AttackCategory::PathTraversal => "Path Traversal",
            AttackCategory::CommandInjection => "Command Injection",
            AttackCategory::RateLimitExceeded => "Rate Limit",
            AttackCategory::BotDetected => "Bot Detected",
            AttackCategory::MlAnomaly => "ML Anomaly",
            AttackCategory::ThreatIntel => "Threat Intel",
            AttackCategory::ProtocolViolation => "Protocol Violation",
            AttackCategory::Other => "Other",
        }
    }
    
    /// Get all categories for initialization
    pub fn all() -> Vec<AttackCategory> {
        vec![
            AttackCategory::SqlInjection,
            AttackCategory::Xss,
            AttackCategory::PathTraversal,
            AttackCategory::CommandInjection,
            AttackCategory::RateLimitExceeded,
            AttackCategory::BotDetected,
            AttackCategory::MlAnomaly,
            AttackCategory::ThreatIntel,
            AttackCategory::ProtocolViolation,
            AttackCategory::Other,
        ]
    }
}

/// Represents a single request log entry for the dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLog {
    pub id: String,
    pub timestamp: u64,
    pub client_ip: String,
    pub method: String,
    pub uri: String,
    pub status: u16,
    pub action: String, // "Allow", "Block", "Challenge"
    pub reason: String,
    pub country: String, // Placeholder for GeoIP
    pub ml_features: Option<String>, // Added for feedback loop
    pub headers: Option<Vec<(String, String)>>, // Added for Audit Log
    pub body: Option<String>, // Added for Audit Log
}

/// Shadow event captured when a request would have been blocked in shadow mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowEvent {
    pub rule_id: String,       // e.g. "WAF:85", "ML:0.92", "ThreatIntel"
    pub client_ip: String,
    pub path: String,
    pub timestamp: u64,
    pub payload_sample: String, // First 100 chars of body/path for context
}

/// Aggregated count for shadow report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCount {
    pub rule_id: String,
    pub count: usize,
}

/// Aggregated IP count for shadow report  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpCount {
    pub ip: String,
    pub count: usize,
}

/// Shadow report response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowReport {
    pub total_analyzed: usize,
    pub simulated_blocks: usize,
    pub top_rules: Vec<RuleCount>,
    pub top_ips: Vec<IpCount>,
}

/// Runtime configuration flags that can be toggled via API
#[derive(Debug)]
pub struct RuntimeController {
    pub ebpf_enabled: AtomicBool,
    pub ml_enabled: AtomicBool,
    pub bot_detection_enabled: AtomicBool,
    pub shadow_mode_enabled: AtomicBool,
    pub shadow_sample_rate: std::sync::atomic::AtomicU8,
}

impl Default for RuntimeController {
    fn default() -> Self {
        Self {
            ebpf_enabled: AtomicBool::new(true),
            ml_enabled: AtomicBool::new(true),
            bot_detection_enabled: AtomicBool::new(true),
            shadow_mode_enabled: AtomicBool::new(false),
            shadow_sample_rate: std::sync::atomic::AtomicU8::new(100),
        }
    }
}

/// Maximum number of shadow events to store (circular buffer)
const MAX_SHADOW_EVENTS: usize = 1000;

use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalTrafficStats {
    pub total_requests: u64,
    pub blocked: u64,
    pub allowed: u64,
    pub total_latency_ms: u64,
    pub rule_triggers: u64,
    pub ml_detections: u64,
    pub threat_intel_blocks: u64,
    pub bytes_processed: u64,
    pub total_inference_time_us: u64,
    pub ml_scanned_count: u64,
    pub last_confidence_score: f32,
    /// Attack breakdown by category (for analytics pie chart)
    pub attack_breakdown: HashMap<AttackCategory, u64>,
    /// ML Classifier stats
    pub classifier_predictions: u64,
    pub classifier_detections: u64,
    pub last_attack_type: String,
    pub classifier_distribution: HashMap<String, u64>,
}

impl Default for GlobalTrafficStats {
    fn default() -> Self {
        let mut breakdown = HashMap::new();
        for cat in AttackCategory::all() {
            breakdown.insert(cat, 0);
        }
        Self {
            total_requests: 0,
            blocked: 0,
            allowed: 0,
            total_latency_ms: 0,
            rule_triggers: 0,
            ml_detections: 0,
            threat_intel_blocks: 0,
            bytes_processed: 0,
            total_inference_time_us: 0,
            ml_scanned_count: 0,
            last_confidence_score: 0.0,
            attack_breakdown: breakdown,
            classifier_predictions: 0,
            classifier_detections: 0,
            last_attack_type: "None".to_string(),
            classifier_distribution: HashMap::new(),
        }
    }
}

impl GlobalTrafficStats {
    /// Increment the attack breakdown counter for a given category
    pub fn record_attack(&mut self, category: AttackCategory) {
        *self.attack_breakdown.entry(category).or_insert(0) += 1;
    }
}

/// Shared mutable state between Proxy and Admin API
#[derive(Debug)]
pub struct SharedState {
    pub logs: RwLock<VecDeque<RequestLog>>,
    pub shadow_events: RwLock<VecDeque<ShadowEvent>>,
    pub traffic_stats: Mutex<GlobalTrafficStats>,
    pub traffic_history: RwLock<VecDeque<TrafficTimeSeries>>,
    pub controller: RuntimeController,
    pub db: Option<WafDatabase>,
}

impl std::fmt::Debug for WafDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WafDatabase(sqlite)")
    }
}

impl SharedState {
    /// Create new SharedState with SQLite persistence
    pub async fn new_with_db(db: Option<WafDatabase>) -> Self {
        let (stats, logs, history, shadow_events) = if let Some(ref database) = db {
            let stats = database.load_stats().await;
            let logs = database.load_recent_logs(100).await;
            let history = database.load_history(3600).await;
            let shadow = database.load_shadow_events(MAX_SHADOW_EVENTS).await;
            (stats, logs, history, shadow)
        } else {
            // Fallback to JSON files
            (Self::load_stats(), Self::load_logs(), Self::load_history(), VecDeque::with_capacity(MAX_SHADOW_EVENTS))
        };
        
        Self {
            logs: RwLock::new(logs),
            shadow_events: RwLock::new(shadow_events),
            traffic_stats: Mutex::new(stats),
            traffic_history: RwLock::new(history),
            controller: RuntimeController::default(),
            db,
        }
    }

    /// Fallback constructor (no DB)
    pub fn new() -> Self {
        let history = Self::load_history();
        let stats = Self::load_stats();
        let logs = Self::load_logs();
        Self {
            logs: RwLock::new(logs),
            shadow_events: RwLock::new(VecDeque::with_capacity(MAX_SHADOW_EVENTS)),
            traffic_stats: Mutex::new(stats),
            traffic_history: RwLock::new(history),
            controller: RuntimeController::default(),
            db: None,
        }
    }

    /// Load persisted stats from disk
    fn load_stats() -> GlobalTrafficStats {
        let path = Path::new("data/stats.json");
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(stats) = serde_json::from_str::<GlobalTrafficStats>(&content) {
                    info!("loaded persisted stats from disk (total_requests: {})", stats.total_requests);
                    return stats;
                }
            }
        }
        GlobalTrafficStats::default()
    }

    /// Save current stats to disk
    pub fn save_stats(&self) {
        let stats = self.traffic_stats.lock().unwrap();
        let path = Path::new("data/stats.json");
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string(&*stats) {
            if let Err(e) = fs::write(path, json) {
                error!("Failed to save stats: {}", e);
            }
        }
    }

    /// Load persisted logs from disk
    fn load_logs() -> VecDeque<RequestLog> {
        let path = Path::new("data/logs.json");
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(logs) = serde_json::from_str::<VecDeque<RequestLog>>(&content) {
                    info!("loaded {} persisted logs from disk", logs.len());
                    return logs;
                }
            }
        }
        VecDeque::with_capacity(100)
    }

    /// Save current logs to disk
    fn save_logs_inner(logs: &VecDeque<RequestLog>) {
        let path = Path::new("data/logs.json");
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string(logs) {
            if let Err(e) = fs::write(path, json) {
                error!("Failed to save logs: {}", e);
            }
        }
    }

    fn load_history() -> VecDeque<TrafficTimeSeries> {
        let path = Path::new("data/traffic_history.json");
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(history) = serde_json::from_str::<VecDeque<TrafficTimeSeries>>(&content) {
                    info!("loaded {} traffic history points from disk", history.len());
                    return history;
                }
            }
        }
        VecDeque::with_capacity(3600)
    }

    pub fn save_history(&self) {
        let history = self.traffic_history.read().unwrap();
        // Save only if we have data
        if history.is_empty() { return; }
        
        let path = Path::new("data/traffic_history.json");
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        
        if let Ok(json) = serde_json::to_string(&*history) {
            if let Err(e) = fs::write(path, json) {
                error!("Failed to save traffic history: {}", e);
            }
        }
    }

    pub fn add_log(&self, log: RequestLog) {
        // Persist to SQLite asynchronously
        if let Some(ref db) = self.db {
            let db = db.clone();
            let log_clone = log.clone();
            tokio::spawn(async move {
                db.insert_log(&log_clone).await;
            });
        }
        
        let mut logs = self.logs.write().unwrap();
        if logs.len() >= 100 {
            logs.pop_back(); // Keep buffer size fixed
        }
        logs.push_front(log);
    }

    pub fn get_recent_logs(&self, limit: usize) -> Vec<RequestLog> {
        let logs = self.logs.read().unwrap();
        logs.iter().take(limit).cloned().collect()
    }

    /// Add a shadow event (would-be-blocked request)
    pub fn add_shadow_event(&self, event: ShadowEvent) {
        // Persist to SQLite
        if let Some(ref db) = self.db {
            let db = db.clone();
            let event_clone = event.clone();
            tokio::spawn(async move {
                db.insert_shadow_event(&event_clone).await;
            });
        }
        
        let mut events = self.shadow_events.write().unwrap();
        if events.len() >= MAX_SHADOW_EVENTS {
            events.pop_back(); // Circular buffer
        }
        events.push_front(event);
    }

    /// Generate shadow report with aggregated stats
    pub fn get_shadow_report(&self, total_requests: usize) -> ShadowReport {
        let events = self.shadow_events.read().unwrap();
        
        // Aggregate by rule_id
        let mut rule_counts: HashMap<String, usize> = HashMap::new();
        for event in events.iter() {
            *rule_counts.entry(event.rule_id.clone()).or_insert(0) += 1;
        }
        
        // Aggregate by IP
        let mut ip_counts: HashMap<String, usize> = HashMap::new();
        for event in events.iter() {
            *ip_counts.entry(event.client_ip.clone()).or_insert(0) += 1;
        }
        
        // Sort and take top 5 rules
        let mut top_rules: Vec<RuleCount> = rule_counts
            .into_iter()
            .map(|(rule_id, count)| RuleCount { rule_id, count })
            .collect();
        top_rules.sort_by(|a, b| b.count.cmp(&a.count));
        top_rules.truncate(5);
        
        // Sort and take top 5 IPs
        let mut top_ips: Vec<IpCount> = ip_counts
            .into_iter()
            .map(|(ip, count)| IpCount { ip, count })
            .collect();
        top_ips.sort_by(|a, b| b.count.cmp(&a.count));
        top_ips.truncate(5);
        
        ShadowReport {
            total_analyzed: total_requests,
            simulated_blocks: events.len(),
            top_rules,
            top_ips,
        }
    }

    /// Clear all shadow events (useful after promoting to block mode)
    pub fn clear_shadow_events(&self) {
        let mut events = self.shadow_events.write().unwrap();
        events.clear();
    }

    /// Snapshot current global stats into history buffer (called periodically)
    pub fn snapshot_stats(&self) {
        let stats = self.traffic_stats.lock().unwrap();
        let mut history = self.traffic_history.write().unwrap();
        
        // Use system time for timestamp
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Calculate avg latency safely
        let avg_latency = if stats.total_requests > 0 {
            stats.total_latency_ms as f64 / stats.total_requests as f64
        } else {
            0.0
        };

        let snapshot = TrafficTimeSeries {
            timestamp,
            total_requests: stats.total_requests,
            blocked_requests: stats.blocked,
            bytes_processed: stats.bytes_processed,
            avg_latency,
        };

        // Push and maintain 1-hour window (3600 seconds)
        history.push_back(snapshot.clone());
        if history.len() > 3600 {
            history.pop_front();
        }
        
        // Persist to SQLite every 10 snapshots
        if let Some(ref db) = self.db {
            if stats.total_requests % 10 == 0 {
                let db = db.clone();
                let stats_clone = stats.clone();
                let snap_clone = snapshot.clone();
                tokio::spawn(async move {
                    db.save_stats(&stats_clone).await;
                    db.insert_history_point(&snap_clone).await;
                });
            }
        }
    }
}

/// Time-series data point for traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficTimeSeries {
    pub timestamp: u64,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub bytes_processed: u64,
    pub avg_latency: f64,
}

/// Shared WAF state accessible by admin API
pub struct WafState {
    pub config: Arc<ArcSwap<Config>>,
    pub config_path: PathBuf, // ADDED: Path to config file
    pub rule_engine: Arc<ArcSwap<RuleEngine>>,
    pub shared: Arc<SharedState>, // <--- Shared with Proxy
    pub start_time: Instant,
    pub wasm_manager: Option<Arc<WasmPluginManager>>,
    pub threat_intel: Option<Arc<crate::threat_intel::client::ThreatIntelClient>>,
    pub ml_engine: Option<Arc<MLInferenceEngine>>,
    pub threat_classifier: Option<Arc<ThreatClassifier>>,
    pub vuln_manager: Arc<VulnerabilityManager>,
    pub api_protection_state: Arc<crate::api_protection::state::ApiProtectionState>,
    pub tenant_store: Arc<crate::tenancy::store::TenantStore>,
    pub bot_stats: Arc<crate::botdetection::BotDetectionStats>,
    pub bot_config: Arc<tokio::sync::RwLock<crate::botdetection::BotDetectionConfig>>,
    pub feedback_manager: Option<Arc<crate::ml::feedback::FeedbackManager>>,
    pub endpoint_discovery: Arc<crate::api::shadow_api::EndpointDiscovery>, // ADDED
    pub virtual_patch_store: crate::api::virtual_patches::VirtualPatchStore, // ADDED
    pub db_pool: Option<PgPool>, // ADDED: Database connection pool
}

impl WafState {
    pub fn new(
        config: Arc<ArcSwap<Config>>,
        config_path: PathBuf,
        rule_engine: Arc<ArcSwap<RuleEngine>>,
        shared: Arc<SharedState>,
        wasm_manager: Option<Arc<WasmPluginManager>>,
        threat_intel: Option<Arc<crate::threat_intel::client::ThreatIntelClient>>,
        ml_engine: Option<Arc<MLInferenceEngine>>,
        threat_classifier: Option<Arc<ThreatClassifier>>,
        vuln_manager: Arc<VulnerabilityManager>,
        api_protection_state: Arc<crate::api_protection::state::ApiProtectionState>,
        tenant_store: Arc<crate::tenancy::store::TenantStore>,
        bot_stats: Arc<crate::botdetection::BotDetectionStats>,
        bot_config: Arc<tokio::sync::RwLock<crate::botdetection::BotDetectionConfig>>,
        feedback_manager: Option<Arc<crate::ml::feedback::FeedbackManager>>,
        endpoint_discovery: Arc<crate::api::shadow_api::EndpointDiscovery>, // ADDED
        virtual_patch_store: crate::api::virtual_patches::VirtualPatchStore, // ADDED
        db_pool: Option<PgPool>, // ADDED
    ) -> Self {
        Self {
            config,
            config_path,
            rule_engine,
            shared,
            start_time: Instant::now(),
            wasm_manager,
            threat_intel,
            ml_engine,
            threat_classifier,
            vuln_manager,
            api_protection_state,
            tenant_store,
            bot_stats,
            bot_config,
            feedback_manager,
            endpoint_discovery,
            virtual_patch_store,
            db_pool,
        }
    }

    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}
