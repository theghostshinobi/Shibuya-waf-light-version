// core/src/shadow/capture.rs

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::parser::context::RequestContext;
use crate::rules::engine::{InspectionResult, InspectionAction};
use sqlx::PgPool;
use anyhow::Result;
use tracing::{info, warn};

pub struct TrafficCapture {
    db: PgPool,
    capture_config: CaptureConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub enabled: bool,
    pub sample_rate: f32,        // 0.0-1.0
    pub max_body_size: usize,    // Don't capture huge bodies
    pub retention_days: u32,     // Auto-delete old captures
}

impl TrafficCapture {
    pub fn new(db: PgPool, config: CaptureConfig) -> Self {
        Self { db, capture_config: config }
    }

    pub async fn capture_request(
        &self,
        ctx: &RequestContext,
        result: &InspectionResult,
    ) -> Result<()> {
        if !self.should_capture() {
            return Ok(());
        }
        
        // Serialize RequestContext for replay
        let snapshot = RequestSnapshot {
            request_id: ctx.request_id.clone(),
            timestamp: Utc::now(),
            
            // HTTP metadata
            method: ctx.method.clone(),
            uri: ctx.uri.clone(),
            headers: ctx.headers.clone(),
            query_params: ctx.query_params.clone(),
            
            // Body (truncated if too large)
            body: self.truncate_body(&ctx.body_raw),
            
            // Client info
            client_ip: ctx.client_ip.clone(),
            
            // Decision made
            action: result.action,
            crs_score: result.crs_score,
            ml_score: result.ml_anomaly_score,
        };
        
        // Store in database
        sqlx::query(
            "INSERT INTO traffic_snapshots 
             (request_id, snapshot_data, created_at)
             VALUES ($1, $2, $3)"
        )
        .bind(&snapshot.request_id)
        .bind(serde_json::to_value(&snapshot)?)
        .bind(snapshot.timestamp)
        .execute(&self.db)
        .await?;
        
        Ok(())
    }
    
    fn should_capture(&self) -> bool {
        if !self.capture_config.enabled {
            return false;
        }
        
        // Probabilistic sampling
        rand::random::<f32>() < self.capture_config.sample_rate
    }
    
    fn truncate_body(&self, body: &Option<Arc<Vec<u8>>>) -> Option<Vec<u8>> {
        body.as_ref().map(|b| {
            if b.len() > self.capture_config.max_body_size {
                b[..self.capture_config.max_body_size].to_vec()
            } else {
                b.to_vec()
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSnapshot {
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub uri: String,
    pub headers: HashMap<String, Vec<String>>,
    pub query_params: HashMap<String, Vec<String>>,
    pub body: Option<Vec<u8>>,
    pub client_ip: String,
    pub action: InspectionAction,
    pub crs_score: i32,
    pub ml_score: f32,
}
