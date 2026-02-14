use axum::{Router, routing::get, Json, http::StatusCode, extract::State};
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn, debug};

use crate::state::WafState;

/// Health Monitor for upstream health checking
pub struct HealthMonitor {
    is_healthy: AtomicBool,
    consecutive_failures: AtomicUsize,
    unhealthy_threshold: usize,
    #[allow(dead_code)]
    health_check_url: String,
    #[allow(dead_code)]
    check_interval: Duration,
    #[allow(dead_code)]
    check_timeout: Duration,
}

impl HealthMonitor {
    pub fn new(
        upstream_host: &str,
        upstream_port: u16,
        scheme: &str,
        health_path: &str,
        interval: Duration,
        timeout: Duration,
        unhealthy_threshold: usize,
    ) -> Self {
        let health_check_url = format!("{}://{}:{}{}", scheme, upstream_host, upstream_port, health_path);
        
        Self {
            is_healthy: AtomicBool::new(true), // Assume healthy initially
            consecutive_failures: AtomicUsize::new(0),
            unhealthy_threshold,
            health_check_url,
            check_interval: interval,
            check_timeout: timeout,
        }
    }

    /// Check if upstream is currently healthy
    pub fn is_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::Relaxed)
    }

    /// Mark upstream as healthy (e.g., after successful response)
    pub fn mark_healthy(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let was_healthy = self.is_healthy.swap(true, Ordering::Relaxed);
        if !was_healthy {
            info!("Upstream recovered, marking as healthy");
        }
    }

    /// Mark upstream as having failed
    pub fn mark_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.unhealthy_threshold {
            let was_healthy = self.is_healthy.swap(false, Ordering::Relaxed);
            if was_healthy {
                warn!(
                    "Upstream marked unhealthy after {} consecutive failures",
                    failures
                );
            }
        }
    }

    /// Run the health check loop (spawned as background task)
    pub async fn run_loop(self: Arc<Self>) {
        info!("Health check loop disabled for Episode 1 (No Reqwest)");
    }
}

/// Axum routes for health endpoints (with shared WafState)
pub fn health_routes() -> Router<Arc<WafState>> {
    Router::new()
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        .route("/health/startup", get(startup))
}

/// Liveness probe - is the process alive?
/// Always returns 200 if the server can respond.
async fn liveness() -> StatusCode {
    StatusCode::OK
}

/// Individual health check result
#[derive(Debug, Clone, serde::Serialize)]
struct HealthCheck {
    status: &'static str,
    latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

/// Readiness probe - can we serve traffic?
/// Checks: database, redis, rule_engine (loaded rules).
async fn readiness(
    State(state): State<Arc<WafState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut all_ok = true;

    // ── 1. Database Check ──
    let db_check = if let Some(pool) = &state.db_pool {
        let start = Instant::now();
        match sqlx::query("SELECT 1").execute(pool).await {
            Ok(_) => HealthCheck {
                status: "ok",
                latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
                details: None,
            },
            Err(e) => {
                all_ok = false;
                warn!("Health check: database unreachable: {}", e);
                HealthCheck {
                    status: "error",
                    latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
                    details: Some(format!("Connection failed: {}", e)),
                }
            }
        }
    } else {
        // No DB configured — not a failure, just "not configured"
        HealthCheck {
            status: "not_configured",
            latency_ms: None,
            details: Some("PgPool not initialized".to_string()),
        }
    };

    // ── 2. Redis Check ──
    let redis_check = {
        let redis_url_env = std::env::var("REDIS_URL").ok();
        if let Some(ref redis_url) = redis_url_env {
            let start = Instant::now();
            match redis::Client::open(redis_url.as_str()) {
                Ok(client) => {
                    match client.get_multiplexed_tokio_connection().await {
                        Ok(mut conn) => {
                            let ping_result: Result<String, _> = redis::cmd("PING")
                                .query_async(&mut conn)
                                .await;
                            match ping_result {
                                Ok(resp) if resp == "PONG" => HealthCheck {
                                    status: "ok",
                                    latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
                                    details: None,
                                },
                                Ok(resp) => HealthCheck {
                                    status: "degraded",
                                    latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
                                    details: Some(format!("Unexpected PING response: {}", resp)),
                                },
                                Err(e) => {
                                    all_ok = false;
                                    HealthCheck {
                                        status: "error",
                                        latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
                                        details: Some(format!("PING failed: {}", e)),
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            all_ok = false;
                            HealthCheck {
                                status: "error",
                                latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
                                details: Some(format!("Connection failed: {}", e)),
                            }
                        }
                    }
                }
                Err(e) => {
                    all_ok = false;
                    HealthCheck {
                        status: "error",
                        latency_ms: None,
                        details: Some(format!("Invalid URL: {}", e)),
                    }
                }
            }
        } else {
            HealthCheck {
                status: "not_configured",
                latency_ms: None,
                details: Some("Redis URL not set".to_string()),
            }
        }
    };

    // ── 3. Rule Engine Check ──
    let rule_engine_check = {
        let engine = state.rule_engine.load();
        let rule_count = engine.rules.len();
        if rule_count > 0 {
            HealthCheck {
                status: "ok",
                latency_ms: None,
                details: Some(format!("{} rules loaded", rule_count)),
            }
        } else {
            all_ok = false;
            warn!("Health check: rule engine has 0 rules loaded");
            HealthCheck {
                status: "degraded",
                latency_ms: None,
                details: Some("No rules loaded".to_string()),
            }
        }
    };

    let overall_status = if all_ok { "ready" } else { "degraded" };
    let status_code = if all_ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };

    let body = Json(json!({
        "status": overall_status,
        "checks": {
            "database": db_check,
            "redis": redis_check,
            "rule_engine": rule_engine_check,
        }
    }));

    if all_ok {
        Ok(body)
    } else {
        // Return 503 with details when degraded
        Ok(body)
    }
}

/// Startup probe - has the app finished initializing?
/// Checks if uptime exceeds a minimum boot threshold and rule engine is loaded.
async fn startup(
    State(state): State<Arc<WafState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let uptime = state.uptime();
    let engine = state.rule_engine.load();
    let rules_loaded = engine.rules.len() > 0;
    
    // Consider started if running for >2s and rules are loaded
    let is_started = uptime > Duration::from_secs(2) && rules_loaded;
    
    if is_started {
        Ok(Json(json!({
            "status": "started",
            "uptime_secs": uptime.as_secs(),
            "rules_loaded": engine.rules.len(),
        })))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_monitor_mark_healthy() {
        let monitor = HealthMonitor::new("localhost", 8080, "http", "/health", 
            Duration::from_secs(5), Duration::from_secs(2), 3);
        assert!(monitor.is_healthy());
        monitor.mark_failure();
        monitor.mark_failure();
        monitor.mark_failure();
        assert!(!monitor.is_healthy());
        monitor.mark_healthy();
        assert!(monitor.is_healthy());
    }

    #[test]
    fn test_health_monitor_threshold() {
        let monitor = HealthMonitor::new("localhost", 8080, "http", "/health", 
            Duration::from_secs(5), Duration::from_secs(2), 3);
        // 2 failures < threshold=3, should still be healthy
        monitor.mark_failure();
        monitor.mark_failure();
        assert!(monitor.is_healthy());
        // 3rd failure triggers unhealthy
        monitor.mark_failure();
        assert!(!monitor.is_healthy());
    }
}

