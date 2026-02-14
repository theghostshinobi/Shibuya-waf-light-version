use axum::{
    routing::{get, post},
    Router, Json, extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use waf_killer_core::rules::engine::RuleEngine;
use arc_swap::ArcSwap;
use sqlx::PgPool;
use axum::response::{IntoResponse, Response};

pub enum ApiError {
    NotFound(String),
    Forbidden(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

/// Minimal API State for build compatibility
pub struct ApiState {
    pub db_pool: PgPool,
    pub rule_engine: Arc<ArcSwap<RuleEngine>>,
}

#[derive(Deserialize)]
pub struct RequestFilters {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub action: Option<String>,
}

#[derive(Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub pages: u32,
}

#[derive(Serialize)]
pub struct Stats {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub ml_detections: u64,
    pub avg_latency_ms: f64,
    pub requests_per_sec: f64,
}

#[derive(Serialize, Clone)]
pub struct RequestSummary {
    pub id: String,
    pub timestamp: i64,
    pub method: String,
    pub url: String,
    pub client_ip: String,
    pub action: String,
    pub reason: String,
    pub crs_score: i32,
    pub ml_score: f64,
    pub latency_ms: u32,
}

pub fn create_router(state: Arc<ApiState>) -> Router {
    Router::new()
        // Stats
        .route("/api/stats", get(get_stats))
        // Rules
        .route("/api/rules", get(get_rules))
        .route("/api/rules/:id/enable", post(enable_rule))
        .route("/api/rules/:id/disable", post(disable_rule))
        // Health
        .route("/health", get(health_check))
        .with_state(state)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
}

// Stats Handler
async fn get_stats(State(_state): State<Arc<ApiState>>) -> Json<Stats> {
    Json(Stats {
        total_requests: 12500,
        blocked_requests: 450,
        ml_detections: 120,
        avg_latency_ms: 12.5,
        requests_per_sec: 45.2,
    })
}

#[derive(Serialize)]
pub struct RuleInfo {
    pub id: u32,
    pub msg: String,
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct RuleListResponse {
    pub rules: Vec<RuleInfo>,
}

// Rule Handlers
async fn get_rules(State(state): State<Arc<ApiState>>) -> Json<RuleListResponse> {
    let engine = state.rule_engine.load();
    let rules = engine.rules.iter().map(|r| RuleInfo {
        id: r.id,
        msg: "Matched CRS Rule".to_string(),
        enabled: true,
    }).collect();
    
    Json(RuleListResponse { rules })
}

async fn enable_rule(State(_state): State<Arc<ApiState>>, Path(id): Path<String>) -> StatusCode {
    tracing::info!("Enabling rule {}", id);
    StatusCode::OK
}

async fn disable_rule(State(_state): State<Arc<ApiState>>, Path(id): Path<String>) -> StatusCode {
    tracing::info!("Disabling rule {}", id);
    StatusCode::OK
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "healthy" }))
}
