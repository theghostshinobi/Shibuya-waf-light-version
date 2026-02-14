use axum::{Router, Json, extract::State, routing::{get, post}};
use serde::{Serialize, Deserialize};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use chrono::{DateTime, Utc, TimeZone};
use sqlx::PgPool;
use crate::shadow::replay::{ReplayEngine, ReplayReport};
use crate::rules::parser::parse_rule;
use crate::rules::engine::{RuleEngine, EngineConfig, EngineMode};
use crate::ml::inference::MLInferenceEngine;

#[derive(Clone, Serialize)]
pub struct DiscoveredEndpoint {
    pub method: String,
    pub path: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub hit_count: u64,
    pub avg_latency_ms: f64,
}

#[derive(Clone)]
pub struct EndpointDiscovery {
    endpoints: Arc<RwLock<HashMap<String, DiscoveredEndpoint>>>,
}

impl EndpointDiscovery {
    pub fn new() -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub fn record(&self, method: &str, path: &str, latency_ms: f64) {
        let key = format!("{} {}", method, path);
        let mut endpoints = self.endpoints.write().unwrap();
        
        endpoints.entry(key.clone())
            .and_modify(|e| {
                e.hit_count += 1;
                e.last_seen = Utc::now();
                e.avg_latency_ms = (e.avg_latency_ms * (e.hit_count - 1) as f64 + latency_ms) / e.hit_count as f64;
            })
            .or_insert(DiscoveredEndpoint {
                method: method.to_string(),
                path: path.to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                hit_count: 1,
                avg_latency_ms: latency_ms,
            });
    }
    
    pub fn get_all(&self) -> Vec<DiscoveredEndpoint> {
        let endpoints = self.endpoints.read().unwrap();
        endpoints.values().cloned().collect()
    }
}

#[derive(Clone)]
pub struct ShadowAppState {
    pub discovery: EndpointDiscovery,
    pub db: Option<PgPool>,
    pub ml_engine: Option<Arc<MLInferenceEngine>>,
}

#[derive(Deserialize)]
pub struct ReplayRequest {
    pub policy: String,
    pub from: Option<i64>, // Timestamp in ms or 0
    pub to: Option<i64>,
}

pub fn shadow_api_router(discovery: EndpointDiscovery, db: Option<PgPool>, ml_engine: Option<Arc<MLInferenceEngine>>) -> Router {
    let state = ShadowAppState {
        discovery,
        db,
        ml_engine,
    };

    Router::new()
        .route("/shadow-api/endpoints", get(list_discovered_endpoints))
        .route("/replay", post(replay_traffic))
        .with_state(state)
}

async fn list_discovered_endpoints(
    State(state): State<ShadowAppState>
) -> Json<Vec<DiscoveredEndpoint>> {
    Json(state.discovery.get_all())
}

async fn replay_traffic(
    State(state): State<ShadowAppState>,
    Json(payload): Json<ReplayRequest>,
) -> Result<Json<ReplayReport>, String> {
    // 1. Check if DB is available
    let db = state.db.ok_or_else(|| "Database not configured".to_string())?;

    // 2. Parse Policy
    // The policy string might contain multiple rules. 
    // Usually SecLang rules are one per line or multiline.
    // parse_rule parses a SINGLE rule.
    // We need to split lines and parse each.
    // Simplified: split by newline, ignore empty/comments, parse lines.
    
    let mut rules = Vec::new();
    for line in payload.policy.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Handle "SecRule ..."
        if trimmed.starts_with("SecRule") {
             match parse_rule(trimmed) {
                 Ok(rule) => rules.push(rule),
                 Err(e) => return Err(format!("Failed to parse rule '{}': {}", trimmed, e)),
             }
        }
    }
    
    if rules.is_empty() {
        return Err("No valid rules found in policy".to_string());
    }

    // 3. Create Rule Engine
    let engine_config = EngineConfig {
        paranoia_level: 1, // Default for replay
        inbound_threshold: 5,
        outbound_threshold: 4,
        enabled: true,
        mode: EngineMode::Detection, // Always detection for replay
    };
    
    let rule_engine = Arc::new(RuleEngine::new(rules, engine_config));
    
    // 4. Time Range
    let from_time = if let Some(ts) = payload.from {
        if ts > 0 {
             match Utc.timestamp_millis_opt(ts) {
                 chrono::LocalResult::Single(dt) => dt,
                 _ => Utc::now() - chrono::Duration::hours(1)
             }
        } else {
             Utc::now() - chrono::Duration::hours(1)
        }
    } else {
        Utc::now() - chrono::Duration::hours(1)
    };
    
    let to_time = if let Some(ts) = payload.to {
         if ts > 0 {
             match Utc.timestamp_millis_opt(ts) {
                 chrono::LocalResult::Single(dt) => dt,
                 _ => Utc::now()
             }
         } else {
             Utc::now()
         }
    } else {
        Utc::now()
    };

    // 5. Run Replay
    let replay_engine = ReplayEngine::new(db, state.ml_engine); // Scoring engine removed from struct
    
    match replay_engine.replay_with_policy(from_time, to_time, rule_engine).await {
        Ok(report) => Ok(Json(report)),
        Err(e) => Err(format!("Replay failed: {}", e)),
    }
}
