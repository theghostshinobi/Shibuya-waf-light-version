// core/src/shadow/executor.rs

use std::sync::Arc;
use std::time::Duration;
use crate::rules::engine::{RuleEngine, InspectionResult, InspectionAction, RuleMatch};
use crate::parser::context::RequestContext;
use crate::shadow::{ShadowConfig, ShadowResult, DecisionDiff, diff::DiffRecorder};
use crate::ml::inference::MLInferenceEngine;
// use crate::ml::scoring::ScoringEngine;
// use crate::ml::baseline::{TrafficStats, BaselineStats};
use tracing::{warn, debug};
use tokio::time::timeout;
use ahash::AHasher;
use std::hash::{Hash, Hasher};

pub struct ShadowExecutor {
    pub shadow_config: ShadowConfig,
    pub production_engine: Arc<RuleEngine>,
    pub shadow_engine: Arc<RuleEngine>,
    pub diff_recorder: Arc<DiffRecorder>,
    pub ml_engine: Option<Arc<MLInferenceEngine>>,
    // pub scoring_engine: Option<Arc<ScoringEngine>>,
}

impl ShadowExecutor {
    pub async fn execute_with_shadow(
        &self,
        ctx: &RequestContext,
        prod_result: &InspectionResult,
        // traffic_stats: Option<&TrafficStats>,
        // baseline: Option<&BaselineStats>,
    ) -> Option<ShadowResult> {
        // 1. Check if this request should be shadowed
        if !self.should_shadow_request(ctx) {
            return None;
        }
        
        // 2. Execute shadow policy (in parallel, doesn't affect response)
        let engine = self.shadow_engine.clone();
        let ml = self.ml_engine.clone();
        // let scorer = self.scoring_engine.clone();
        let ctx_clone = ctx.clone();
        
        // We use spawn to ensure it doesn't block the main thread if it takes too long
        let shadow_future = tokio::task::spawn_blocking(move || {
            engine.inspect_request(&ctx_clone)
        });
        
        // 3. Wait for shadow result (with timeout)
        match timeout(Duration::from_millis(100), shadow_future).await {
            Ok(Ok(result)) => {
                // 4. Compare results
                let diff = self.compare_results(ctx, prod_result, &result);
                
                // 5. Record diff for analysis
                if let Err(e) = self.diff_recorder.record(diff.clone()).await {
                    warn!("Failed to record shadow diff: {}", e);
                }
                
                Some(ShadowResult {
                    decision: result,
                    diff_from_prod: diff,
                })
            },
            Ok(Err(e)) => {
                warn!("Shadow execution task failed: {}", e);
                None
            },
            Err(_) => {
                warn!("Shadow execution timeout for request {}", ctx.request_id);
                None
            }
        }
    }
    
    fn should_shadow_request(&self, ctx: &RequestContext) -> bool {
        if !self.shadow_config.enabled {
            return false;
        }
        
        // Route filtering
        if let Some(routes) = &self.shadow_config.routes {
            if !routes.iter().any(|r| ctx.uri.contains(r)) {
                return false;
            }
        }
        
        // Sample by percentage (deterministic based on request_id)
        let mut hasher = AHasher::default();
        ctx.request_id.hash(&mut hasher);
        let hash = hasher.finish();
        let sample = (hash % 100) as u8;
        
        sample < self.shadow_config.percentage
    }
    
    fn compare_results(
        &self,
        ctx: &RequestContext,
        prod: &InspectionResult,
        shadow: &InspectionResult,
    ) -> DecisionDiff {
        let action_changed = prod.action != shadow.action;
        
        DecisionDiff {
            request_id: ctx.request_id.clone(),
            production_action: prod.action,
            shadow_action: shadow.action,
            action_changed,
            
            production_score: prod.combined_score,
            shadow_score: shadow.combined_score,
            score_delta: shadow.combined_score - prod.combined_score,
            
            production_rules: prod.rules_matched.clone(),
            shadow_rules: shadow.rules_matched.clone(),
            
            new_blocks: action_changed && 
                        prod.action == InspectionAction::Allow &&
                        shadow.action == InspectionAction::Block,
            new_allows: action_changed &&
                        prod.action == InspectionAction::Block &&
                        shadow.action == InspectionAction::Allow,
        }
    }
}
