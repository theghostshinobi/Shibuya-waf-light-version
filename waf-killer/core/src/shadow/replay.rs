// core/src/shadow/replay.rs

use crate::shadow::capture::RequestSnapshot;
use crate::rules::engine::{RuleEngine, InspectionResult, InspectionAction};
use crate::parser::context::{RequestContext, TransformedData, InspectionMetadata};
use crate::ml::inference::MLInferenceEngine;
// use crate::ml::scoring::ScoringEngine;
use sqlx::PgPool;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tracing::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub struct ReplayEngine {
    db: PgPool,
    ml_engine: Option<Arc<MLInferenceEngine>>,
    // scoring_engine: Option<Arc<ScoringEngine>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReplayReport {
    pub total_requests: usize,
    pub unchanged: usize,
    pub new_blocks: usize,
    pub new_allows: usize,
    pub new_blocks_examples: Vec<RequestSnapshot>,
    pub new_allows_examples: Vec<RequestSnapshot>,
}

impl ReplayEngine {
    pub fn new(
        db: PgPool, 
        ml_engine: Option<Arc<MLInferenceEngine>>,
        // scoring_engine: Option<Arc<ScoringEngine>>,
    ) -> Self {
        Self { db, ml_engine }
    }

    pub async fn replay_with_policy(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        new_engine: Arc<RuleEngine>,
    ) -> Result<ReplayReport> {
        // 1. Load captured traffic
        let snapshots = self.load_snapshots(from, to).await?;
        info!("Replaying {} requests...", snapshots.len());
        
        // 2. Replay each request
        let mut report = ReplayReport::default();
        
        for snapshot in snapshots {
            // Reconstruct RequestContext
            let ctx = self.reconstruct_context(&snapshot);
            
            // Run through new policy
            let new_result = new_engine.inspect_request(&ctx);
            
            // Compare with original decision
            let diff = self.compare_decisions(
                &snapshot.action,
                &new_result.action
            );
            
            report.add_result(snapshot, diff);
        }
        
        Ok(report)
    }
    
    async fn load_snapshots(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<RequestSnapshot>> {
        let rows = sqlx::query(
            "SELECT snapshot_data 
             FROM traffic_snapshots 
             WHERE created_at BETWEEN $1 AND $2
             ORDER BY created_at ASC
             LIMIT 10000"
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.db)
        .await?;
        
        let mut snapshots = Vec::new();
        for row in rows {
             let snapshot_data: serde_json::Value = sqlx::Row::get(&row, "snapshot_data");
             let snap: RequestSnapshot = serde_json::from_value(snapshot_data)
                .map_err(|e| anyhow!("Failed to parse snapshot: {}", e))?;
             snapshots.push(snap);
        }
        Ok(snapshots)
    }
    
    fn reconstruct_context(&self, snapshot: &RequestSnapshot) -> RequestContext {
        // Rebuild RequestContext from snapshot
        // Note: Some fields like transformed and inspection_metadata might be partially filled or empty
        // as they are typically generated during parsing. For replay, the RuleEngine will re-extract
        // what it needs from the raw fields if transformations are needed.
        
        let path = snapshot.uri.split('?').next().unwrap_or("").to_string();
        let query_string = snapshot.uri.split('?').nth(1).unwrap_or("").to_string();

        RequestContext {
            request_id: snapshot.request_id.clone(),
            timestamp: snapshot.timestamp,
            client_ip: snapshot.client_ip.clone(),
            server_name: String::new(),
            protocol: "HTTP/1.1".to_string(), // Default for replay
            method: snapshot.method.clone(),
            uri: snapshot.uri.clone(),
            path,
            query_string,
            headers: snapshot.headers.clone(),
            cookies: HashMap::new(), // Extract from headers if needed
            query_params: snapshot.query_params.clone(),
            body_raw: snapshot.body.as_ref().map(|b| Arc::new(b.clone())),
            body_size: snapshot.body.as_ref().map(|b| b.len()).unwrap_or(0),
            content_type: snapshot.headers.get("content-type").and_then(|h| h.first().cloned()),
            body_json: None,
            body_form: None,
            body_multipart: None,
            body_text: None,
            transformed: TransformedData::default(),
            inspection_metadata: InspectionMetadata::default(),
        }
    }
    
    fn compare_decisions(
        &self,
        original: &InspectionAction,
        new: &InspectionAction,
    ) -> DecisionComparison {
        DecisionComparison {
            changed: original != new,
            is_new_block: *original == InspectionAction::Allow && *new == InspectionAction::Block,
            is_new_allow: *original == InspectionAction::Block && *new == InspectionAction::Allow,
        }
    }
}

struct DecisionComparison {
    changed: bool,
    is_new_block: bool,
    is_new_allow: bool,
}

impl ReplayReport {
    fn add_result(&mut self, snapshot: RequestSnapshot, comp: DecisionComparison) {
        self.total_requests += 1;
        
        if !comp.changed {
            self.unchanged += 1;
        } else if comp.is_new_block {
            self.new_blocks += 1;
            if self.new_blocks_examples.len() < 10 {
                self.new_blocks_examples.push(snapshot);
            }
        } else if comp.is_new_allow {
            self.new_allows += 1;
            if self.new_allows_examples.len() < 10 {
                self.new_allows_examples.push(snapshot);
            }
        }
    }
}
