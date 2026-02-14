//! SQLite Persistence Layer
//!
//! Provides durable storage for WAF state across restarts.
//! Uses an embedded SQLite database at `data/waf.db`.

use sqlx::sqlite::{SqlitePool, SqlitePoolOptions, SqliteConnectOptions};
use std::str::FromStr;
use tracing::{info, error, warn};
use crate::state::{RequestLog, GlobalTrafficStats, TrafficTimeSeries, ShadowEvent, AttackCategory};
use std::collections::{VecDeque, HashMap};

/// SQLite-backed persistence for WAF state
#[derive(Clone)]
pub struct WafDatabase {
    pool: SqlitePool,
}

impl WafDatabase {
    /// Initialize the database, creating tables if they don't exist
    pub async fn init(db_path: &str) -> Result<Self, sqlx::Error> {
        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(db_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}?mode=rwc", db_path))?
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await?;

        let db = Self { pool };
        db.run_migrations().await?;
        info!("💾 SQLite database initialized at {}", db_path);
        Ok(db)
    }

    /// Create all tables if they don't exist
    async fn run_migrations(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS request_logs (
                id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                client_ip TEXT NOT NULL,
                method TEXT NOT NULL,
                uri TEXT NOT NULL,
                status INTEGER NOT NULL,
                action TEXT NOT NULL,
                reason TEXT NOT NULL,
                country TEXT NOT NULL DEFAULT '',
                ml_features TEXT,
                headers TEXT,
                body TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                total_requests INTEGER NOT NULL DEFAULT 0,
                blocked INTEGER NOT NULL DEFAULT 0,
                allowed INTEGER NOT NULL DEFAULT 0,
                total_latency_ms INTEGER NOT NULL DEFAULT 0,
                rule_triggers INTEGER NOT NULL DEFAULT 0,
                ml_detections INTEGER NOT NULL DEFAULT 0,
                threat_intel_blocks INTEGER NOT NULL DEFAULT 0,
                bytes_processed INTEGER NOT NULL DEFAULT 0,
                total_inference_time_us INTEGER NOT NULL DEFAULT 0,
                ml_scanned_count INTEGER NOT NULL DEFAULT 0,
                last_confidence_score REAL NOT NULL DEFAULT 0.0,
                attack_breakdown TEXT NOT NULL DEFAULT '{}',
                classifier_predictions INTEGER NOT NULL DEFAULT 0,
                classifier_detections INTEGER NOT NULL DEFAULT 0,
                last_attack_type TEXT NOT NULL DEFAULT 'None',
                classifier_distribution TEXT NOT NULL DEFAULT '{}',
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS traffic_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                total_requests INTEGER NOT NULL,
                blocked_requests INTEGER NOT NULL,
                bytes_processed INTEGER NOT NULL,
                avg_latency REAL NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS shadow_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                path TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                payload_sample TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indexes for common queries
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON request_logs(timestamp DESC);")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_history_timestamp ON traffic_history(timestamp DESC);")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_shadow_timestamp ON shadow_events(timestamp DESC);")
            .execute(&self.pool)
            .await?;

        info!("💾 Database schema ready");
        Ok(())
    }

    // ==============================
    // Request Logs
    // ==============================

    /// Insert a request log entry
    pub async fn insert_log(&self, log: &RequestLog) {
        let headers_json = log.headers.as_ref()
            .map(|h| serde_json::to_string(h).unwrap_or_default());

        let result = sqlx::query(
            r#"
            INSERT OR REPLACE INTO request_logs (id, timestamp, client_ip, method, uri, status, action, reason, country, ml_features, headers, body)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&log.id)
        .bind(log.timestamp as i64)
        .bind(&log.client_ip)
        .bind(&log.method)
        .bind(&log.uri)
        .bind(log.status as i32)
        .bind(&log.action)
        .bind(&log.reason)
        .bind(&log.country)
        .bind(&log.ml_features)
        .bind(&headers_json)
        .bind(&log.body)
        .execute(&self.pool)
        .await;

        if let Err(e) = result {
            warn!("Failed to insert log to SQLite: {}", e);
        }
    }

    /// Load the most recent N logs
    pub async fn load_recent_logs(&self, limit: usize) -> VecDeque<RequestLog> {
        let rows = sqlx::query_as::<_, LogRow>(
            "SELECT id, timestamp, client_ip, method, uri, status, action, reason, country, ml_features, headers, body FROM request_logs ORDER BY timestamp DESC LIMIT ?"
        )
        .bind(limit as i32)
        .fetch_all(&self.pool)
        .await;

        match rows {
            Ok(rows) => {
                let mut logs = VecDeque::with_capacity(rows.len());
                for row in rows {
                    logs.push_back(RequestLog {
                        id: row.id,
                        timestamp: row.timestamp as u64,
                        client_ip: row.client_ip,
                        method: row.method,
                        uri: row.uri,
                        status: row.status as u16,
                        action: row.action,
                        reason: row.reason,
                        country: row.country,
                        ml_features: row.ml_features,
                        headers: row.headers.and_then(|h| serde_json::from_str(&h).ok()),
                        body: row.body,
                    });
                }
                info!("💾 Loaded {} logs from SQLite", logs.len());
                logs
            }
            Err(e) => {
                warn!("Failed to load logs from SQLite: {}", e);
                VecDeque::with_capacity(100)
            }
        }
    }

    /// Keep only the most recent N logs (cleanup old entries)
    pub async fn cleanup_old_logs(&self, keep: usize) {
        let _ = sqlx::query(
            "DELETE FROM request_logs WHERE id NOT IN (SELECT id FROM request_logs ORDER BY timestamp DESC LIMIT ?)"
        )
        .bind(keep as i32)
        .execute(&self.pool)
        .await;
    }

    // ==============================
    // Traffic Stats
    // ==============================

    /// Save current traffic stats (upsert — single row with id=1)
    pub async fn save_stats(&self, stats: &GlobalTrafficStats) {
        let breakdown_json = serde_json::to_string(&stats.attack_breakdown).unwrap_or_default();
        let dist_json = serde_json::to_string(&stats.classifier_distribution).unwrap_or_default();

        let result = sqlx::query(
            r#"
            INSERT OR REPLACE INTO traffic_stats
                (id, total_requests, blocked, allowed, total_latency_ms, rule_triggers,
                 ml_detections, threat_intel_blocks, bytes_processed, total_inference_time_us,
                 ml_scanned_count, last_confidence_score, attack_breakdown,
                 classifier_predictions, classifier_detections, last_attack_type,
                 classifier_distribution, updated_at)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            "#,
        )
        .bind(stats.total_requests as i64)
        .bind(stats.blocked as i64)
        .bind(stats.allowed as i64)
        .bind(stats.total_latency_ms as i64)
        .bind(stats.rule_triggers as i64)
        .bind(stats.ml_detections as i64)
        .bind(stats.threat_intel_blocks as i64)
        .bind(stats.bytes_processed as i64)
        .bind(stats.total_inference_time_us as i64)
        .bind(stats.ml_scanned_count as i64)
        .bind(stats.last_confidence_score as f64)
        .bind(&breakdown_json)
        .bind(stats.classifier_predictions as i64)
        .bind(stats.classifier_detections as i64)
        .bind(&stats.last_attack_type)
        .bind(&dist_json)
        .execute(&self.pool)
        .await;

        if let Err(e) = result {
            warn!("Failed to save stats to SQLite: {}", e);
        }
    }

    /// Load traffic stats from DB
    pub async fn load_stats(&self) -> GlobalTrafficStats {
        let row = sqlx::query_as::<_, StatsRow>(
            "SELECT * FROM traffic_stats WHERE id = 1"
        )
        .fetch_optional(&self.pool)
        .await;

        match row {
            Ok(Some(r)) => {
                let attack_breakdown: HashMap<AttackCategory, u64> =
                    serde_json::from_str(&r.attack_breakdown).unwrap_or_default();
                let classifier_distribution: HashMap<String, u64> =
                    serde_json::from_str(&r.classifier_distribution).unwrap_or_default();

                // Merge with defaults (ensure all categories present)
                let mut breakdown = HashMap::new();
                for cat in AttackCategory::all() {
                    breakdown.insert(cat, *attack_breakdown.get(&cat).unwrap_or(&0));
                }

                let stats = GlobalTrafficStats {
                    total_requests: r.total_requests as u64,
                    blocked: r.blocked as u64,
                    allowed: r.allowed as u64,
                    total_latency_ms: r.total_latency_ms as u64,
                    rule_triggers: r.rule_triggers as u64,
                    ml_detections: r.ml_detections as u64,
                    threat_intel_blocks: r.threat_intel_blocks as u64,
                    bytes_processed: r.bytes_processed as u64,
                    total_inference_time_us: r.total_inference_time_us as u64,
                    ml_scanned_count: r.ml_scanned_count as u64,
                    last_confidence_score: r.last_confidence_score as f32,
                    attack_breakdown: breakdown,
                    classifier_predictions: r.classifier_predictions as u64,
                    classifier_detections: r.classifier_detections as u64,
                    last_attack_type: r.last_attack_type,
                    classifier_distribution,
                };
                info!("💾 Loaded stats from SQLite (total_requests: {})", stats.total_requests);
                stats
            }
            _ => {
                info!("💾 No existing stats in SQLite, using defaults");
                GlobalTrafficStats::default()
            }
        }
    }

    // ==============================
    // Traffic History
    // ==============================

    /// Insert a traffic history data point
    pub async fn insert_history_point(&self, point: &TrafficTimeSeries) {
        let _ = sqlx::query(
            "INSERT INTO traffic_history (timestamp, total_requests, blocked_requests, bytes_processed, avg_latency) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(point.timestamp as i64)
        .bind(point.total_requests as i64)
        .bind(point.blocked_requests as i64)
        .bind(point.bytes_processed as i64)
        .bind(point.avg_latency)
        .execute(&self.pool)
        .await;
    }

    /// Load recent traffic history (last N points, default 3600 = 1 hour)
    pub async fn load_history(&self, limit: usize) -> VecDeque<TrafficTimeSeries> {
        let rows = sqlx::query_as::<_, HistoryRow>(
            "SELECT timestamp, total_requests, blocked_requests, bytes_processed, avg_latency FROM traffic_history ORDER BY timestamp DESC LIMIT ?"
        )
        .bind(limit as i32)
        .fetch_all(&self.pool)
        .await;

        match rows {
            Ok(rows) => {
                let mut history: VecDeque<TrafficTimeSeries> = rows.into_iter().rev().map(|r| {
                    TrafficTimeSeries {
                        timestamp: r.timestamp as u64,
                        total_requests: r.total_requests as u64,
                        blocked_requests: r.blocked_requests as u64,
                        bytes_processed: r.bytes_processed as u64,
                        avg_latency: r.avg_latency,
                    }
                }).collect();
                info!("💾 Loaded {} history points from SQLite", history.len());
                history
            }
            Err(e) => {
                warn!("Failed to load history from SQLite: {}", e);
                VecDeque::with_capacity(3600)
            }
        }
    }

    /// Keep only the most recent N history points
    pub async fn cleanup_old_history(&self, keep: usize) {
        let _ = sqlx::query(
            "DELETE FROM traffic_history WHERE id NOT IN (SELECT id FROM traffic_history ORDER BY timestamp DESC LIMIT ?)"
        )
        .bind(keep as i32)
        .execute(&self.pool)
        .await;
    }

    // ==============================
    // Shadow Events
    // ==============================

    /// Insert a shadow event
    pub async fn insert_shadow_event(&self, event: &ShadowEvent) {
        let _ = sqlx::query(
            "INSERT INTO shadow_events (rule_id, client_ip, path, timestamp, payload_sample) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(&event.rule_id)
        .bind(&event.client_ip)
        .bind(&event.path)
        .bind(event.timestamp as i64)
        .bind(&event.payload_sample)
        .execute(&self.pool)
        .await;
    }

    /// Load recent shadow events
    pub async fn load_shadow_events(&self, limit: usize) -> VecDeque<ShadowEvent> {
        let rows = sqlx::query_as::<_, ShadowRow>(
            "SELECT rule_id, client_ip, path, timestamp, payload_sample FROM shadow_events ORDER BY timestamp DESC LIMIT ?"
        )
        .bind(limit as i32)
        .fetch_all(&self.pool)
        .await;

        match rows {
            Ok(rows) => {
                rows.into_iter().map(|r| ShadowEvent {
                    rule_id: r.rule_id,
                    client_ip: r.client_ip,
                    path: r.path,
                    timestamp: r.timestamp as u64,
                    payload_sample: r.payload_sample,
                }).collect()
            }
            Err(_) => VecDeque::new(),
        }
    }

    /// Clear all shadow events
    pub async fn clear_shadow_events(&self) {
        let _ = sqlx::query("DELETE FROM shadow_events")
            .execute(&self.pool)
            .await;
    }

    /// Get total log count
    pub async fn log_count(&self) -> i64 {
        let row: Option<(i64,)> = sqlx::query_as("SELECT COUNT(*) FROM request_logs")
            .fetch_optional(&self.pool)
            .await
            .unwrap_or(None);
        row.map(|r| r.0).unwrap_or(0)
    }
}

// ==============================
// SQLx Row Types
// ==============================

#[derive(sqlx::FromRow)]
struct LogRow {
    id: String,
    timestamp: i64,
    client_ip: String,
    method: String,
    uri: String,
    status: i32,
    action: String,
    reason: String,
    country: String,
    ml_features: Option<String>,
    headers: Option<String>,
    body: Option<String>,
}

#[derive(sqlx::FromRow)]
struct StatsRow {
    total_requests: i64,
    blocked: i64,
    allowed: i64,
    total_latency_ms: i64,
    rule_triggers: i64,
    ml_detections: i64,
    threat_intel_blocks: i64,
    bytes_processed: i64,
    total_inference_time_us: i64,
    ml_scanned_count: i64,
    last_confidence_score: f64,
    attack_breakdown: String,
    classifier_predictions: i64,
    classifier_detections: i64,
    last_attack_type: String,
    classifier_distribution: String,
}

#[derive(sqlx::FromRow)]
struct HistoryRow {
    timestamp: i64,
    total_requests: i64,
    blocked_requests: i64,
    bytes_processed: i64,
    avg_latency: f64,
}

#[derive(sqlx::FromRow)]
struct ShadowRow {
    rule_id: String,
    client_ip: String,
    path: String,
    timestamp: i64,
    payload_sample: String,
}
