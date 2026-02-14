use std::sync::Arc;
use tokio::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::api_protection::openapi::OpenApiSpec;

#[derive(Debug, Clone)]
pub struct ApiProtectionStats {
    pub total_validations: Arc<AtomicU64>,
    pub openapi_blocks: Arc<AtomicU64>,
    pub graphql_depth_blocks: Arc<AtomicU64>,
    pub graphql_complexity_blocks: Arc<AtomicU64>,
}

impl Default for ApiProtectionStats {
    fn default() -> Self {
        Self {
            total_validations: Arc::new(AtomicU64::new(0)),
            openapi_blocks: Arc::new(AtomicU64::new(0)),
            graphql_depth_blocks: Arc::new(AtomicU64::new(0)),
            graphql_complexity_blocks: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl ApiProtectionStats {
    pub fn increment_validation(&self) {
        self.total_validations.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn increment_openapi_block(&self) {
        self.openapi_blocks.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn increment_graphql_depth_block(&self) {
        self.graphql_depth_blocks.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn increment_graphql_complexity_block(&self) {
        self.graphql_complexity_blocks.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn get_snapshot(&self) -> ApiProtectionStatsSnapshot {
        ApiProtectionStatsSnapshot {
            total_validations: self.total_validations.load(Ordering::Relaxed),
            openapi_blocks: self.openapi_blocks.load(Ordering::Relaxed),
            graphql_depth_blocks: self.graphql_depth_blocks.load(Ordering::Relaxed),
            graphql_complexity_blocks: self.graphql_complexity_blocks.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiProtectionStatsSnapshot {
    pub total_validations: u64,
    pub openapi_blocks: u64,
    pub graphql_depth_blocks: u64,
    pub graphql_complexity_blocks: u64,
}

/// Holds the current OpenAPI spec in memory
pub struct ApiProtectionState {
    pub openapi_spec: Arc<RwLock<Option<OpenApiSpec>>>,
    pub stats: ApiProtectionStats,
}

impl Default for ApiProtectionState {
    fn default() -> Self {
        Self {
            openapi_spec: Arc::new(RwLock::new(None)),
            stats: ApiProtectionStats::default(),
        }
    }
}
