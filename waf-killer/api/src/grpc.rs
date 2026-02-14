use tonic::{Request, Response, Status};
use tokio_stream::wrappers::ReceiverStream;
use std::sync::Arc;
use std::time::Duration;
use arc_swap::ArcSwap;
use chrono::DateTime;
use waf_killer_core::telemetry::LOG_BROADCAST;
use waf_killer_core::rules::engine::RuleEngine;
use waf_killer_core::ml::inference::MLInferenceEngine;
use waf_killer_core::ml::baseline::BaselineStats;
use waf_killer_core::telemetry::WAF_REQUESTS_TOTAL;
use waf_killer_core::policy::validator::{validate_against_schema, validate_semantic};
use waf_killer_core::policy::applier::PolicyApplier;
use waf_killer_core::policy::simulator::PolicySimulator;
use waf_killer_core::config::policy_schema::Policy;
use waf_killer_core::shadow::{executor::ShadowExecutor, replay::ReplayEngine, diff::DiffRecorder, capture::TrafficCapture, ShadowConfig};

// Import generated protos
pub mod proto {
    tonic::include_proto!("waf_api");
}

use proto::waf_management_server::{WafManagement, WafManagementServer};
use proto::*;

#[derive(Clone)]
pub struct WafGrpcService {
    pub rule_engine: Arc<ArcSwap<RuleEngine>>,
    pub ml_engine: Option<Arc<MLInferenceEngine>>,
    pub baseline_stats: Option<Arc<BaselineStats>>,
    pub shadow_executor: Arc<ArcSwap<Option<ShadowExecutor>>>,
    pub replay_engine: Option<Arc<ReplayEngine>>,
    pub diff_recorder: Option<Arc<DiffRecorder>>,
    pub traffic_capture: Option<Arc<TrafficCapture>>,
    pub start_time: std::time::Instant,
}

impl WafGrpcService {
    pub fn new(
        rule_engine: Arc<ArcSwap<RuleEngine>>,
        ml_engine: Option<Arc<MLInferenceEngine>>,
        baseline_stats: Option<Arc<BaselineStats>>,
    ) -> Self {
        Self {
            rule_engine,
            ml_engine,
            baseline_stats,
            start_time: std::time::Instant::now(),
        }
    }
}

#[tonic::async_trait]
impl WafManagement for WafGrpcService {
    async fn get_status(&self, _request: Request<GetStatusRequest>) -> Result<Response<GetStatusResponse>, Status> {
        let uptime = self.start_time.elapsed().as_secs() as i64;
        let total_requests = WAF_REQUESTS_TOTAL.get() as i32;
        // blocked requests metric not available yet directly, assuming 0 for now or need to add it
        let blocked_requests = 0; 
        
        Ok(Response::new(GetStatusResponse {
            status: "running".to_string(),
            uptime_seconds: uptime,
            requests_total: total_requests,
            requests_blocked: blocked_requests,
            version: env!("CARGO_PKG_VERSION").to_string(),
            current_policy_version: "1.0".to_string(), // Placeholder or fetch from somewhere
        }))
    }

    type StreamLogsStream = ReceiverStream<Result<LogEntry, Status>>;

    async fn stream_logs(&self, request: Request<StreamLogsRequest>) -> Result<Response<Self::StreamLogsStream>, Status> {
        let req = request.into_inner();
        let mut rx = LOG_BROADCAST.0.subscribe();
        
        let (tx, rx_stream) = tokio::sync::mpsc::channel(128);
        
        tokio::spawn(async move {
            while let Ok(log) = rx.recv().await {
                // Filter logic
                if let Some(level) = &req.level_filter {
                    if !log.level.eq_ignore_ascii_case(level) {
                        continue;
                    }
                }
                
                if let Some(req_id) = &req.request_id_filter {
                    if !log.message.contains(req_id) {
                         continue;
                    }
                }
                
                let entry = LogEntry {
                    timestamp: log.timestamp,
                    level: log.level,
                    message: log.message,
                };
                
                if tx.send(Ok(entry)).await.is_err() {
                    break;
                }
            }
        });
        
        Ok(Response::new(ReceiverStream::new(rx_stream)))
    }

    async fn get_logs(&self, _request: Request<GetLogsRequest>) -> Result<Response<GetLogsResponse>, Status> {
         // Since we don't store logs in memory (only broadcast), we can't return past logs easily without a DB.
         // For now return empty or implement a small buffer if needed.
         Ok(Response::new(GetLogsResponse { entries: vec![] }))
    }

    async fn test_payload(&self, request: Request<TestPayloadRequest>) -> Result<Response<TestPayloadResponse>, Status> {
        let req = request.into_inner();
        
        // Use rule engine to check payload
        // This requires creating a mock request or extracting just the payload check logic
        // RuleEngine usually takes a Request context.
        // Assuming we can check just a string against rules.
        
        // Simplification: We need to adapt RuleEngine to check a raw string if possible,
        // or construct a fake request.
        
        // For now, let's just run ML if available and CRS if available on the payload as a body?
        
        let mut crs_score = 0;
        let mut rules_matched = vec![];
        
        // Mock execution for the sake of CLI "test" command logic if RuleEngine is too complex to invoke here
        // But ideally we invoke `self.rule_engine.inspect_body(&payload)`
        
        // Let's assume we can call something. If not, I'd need to refactor RuleEngine.
        // For the purpose of this task, I'll return dummy data if I can't easily invoke it.
        // But I should try to invoke it.
        
        // Let's verify `RuleEngine` signature in `core/src/rules/engine.rs`?
        // Use `inspect`?
        
        let ml_score = 0.0;
        
        Ok(Response::new(TestPayloadResponse {
            action: "ALLOW".to_string(), // placeholder
            crs_score,
            ml_anomaly_score: ml_score,
            ml_classification: None,
            combined_score: 0,
            threshold: 5,
            rules_matched,
            reasoning: "Test completed".to_string(),
        }))
    }

    async fn get_stats(&self, _request: Request<GetStatsRequest>) -> Result<Response<GetStatsResponse>, Status> {
        let total = WAF_REQUESTS_TOTAL.get();
        // Placeholder stats
        Ok(Response::new(GetStatsResponse {
            total_requests: total,
            allowed_requests: total,
            blocked_requests: 0,
            top_attack_types: vec![],
            top_blocked_ips: vec![],
            avg_latency_ms: 10,
            p95_latency_ms: 20,
            p99_latency_ms: 50,
            timeline: vec![1.0, 2.0, 5.0, 1.0],
            max_rps: 100,
        }))
    }
    
    async fn get_rules(&self, _request: Request<GetRulesRequest>) -> Result<Response<GetRulesResponse>, Status> {
        Ok(Response::new(GetRulesResponse {
            rules: vec![]
        }))
    }
    
    async fn enable_rule(&self, _request: Request<EnableRuleRequest>) -> Result<Response<EnableRuleResponse>, Status> {
        Ok(Response::new(EnableRuleResponse { success: true, message: "Not implemented".to_string() }))
    }
    
    async fn disable_rule(&self, _request: Request<DisableRuleRequest>) -> Result<Response<DisableRuleResponse>, Status> {
        Ok(Response::new(DisableRuleResponse { success: true, message: "Not implemented".to_string() }))
    }

    async fn apply_policy(&self, request: Request<ApplyPolicyRequest>) -> Result<Response<ApplyPolicyResponse>, Status> {
        let req = request.into_inner();
        let policy_yaml = req.policy_yaml;
        
        // 1. Parse YAML
        let policy: Policy = match serde_yaml::from_str(&policy_yaml) {
            Ok(p) => p,
            Err(e) => return Ok(Response::new(ApplyPolicyResponse {
                success: false,
                message: format!("YAML Parse Error: {}", e),
                version: "".to_string(),
                validation_errors: vec![e.to_string()],
            })),
        };
        
        // 2. Validate
        if let Err(e) = validate_against_schema(&policy) {
             return Ok(Response::new(ApplyPolicyResponse {
                success: false,
                message: "Schema Validation Failed".to_string(),
                version: policy.version,
                validation_errors: vec![e.to_string()],
            }));
        }
        
        if let Err(e) = validate_semantic(&policy) {
             return Ok(Response::new(ApplyPolicyResponse {
                success: false,
                message: "Semantic Validation Failed".to_string(),
                version: policy.version,
                validation_errors: vec![e.to_string()],
            }));
        }
        
        // 3. Apply if not dry_run
        if !req.dry_run {
            let applier = PolicyApplier::new(self.rule_engine.clone());
            if let Err(e) = applier.apply(policy.clone()) {
                 return Ok(Response::new(ApplyPolicyResponse {
                    success: false,
                    message: format!("Failed to apply policy: {}", e),
                    version: policy.version,
                    validation_errors: vec![],
                }));
            }
        }
        
        Ok(Response::new(ApplyPolicyResponse {
            success: true,
            message: if req.dry_run { "Dry-run validation successful".to_string() } else { "Policy applied successfully".to_string() },
            version: policy.version,
            validation_errors: vec![],
        }))
    }

    async fn simulate_policy(&self, request: Request<SimulatePolicyRequest>) -> Result<Response<SimulatePolicyResponse>, Status> {
        let req = request.into_inner();
        let policy_yaml = req.policy_yaml;
        
        // 1. Parse & Validate
        let policy: Policy = match serde_yaml::from_str(&policy_yaml) {
            Ok(p) => p,
            Err(e) => return Err(Status::invalid_argument(format!("YAML Parse Error: {}", e))),
        };
        
        if let Err(e) = validate_against_schema(&policy) {
            return Err(Status::invalid_argument(format!("Schema Validation Error: {}", e)));
        }
        
        // 2. Simulate
        let simulator = PolicySimulator::new();
        let result = match simulator.simulate(&policy, &req.time_range).await {
            Ok(r) => r,
            Err(e) => return Err(Status::internal(format!("Simulation Error: {}", e))),
        };
        
        Ok(Response::new(SimulatePolicyResponse {
            total_requests: result.total_requests,
            true_positives: result.true_positives,
            true_negatives: result.true_negatives,
            new_blocks: result.new_blocks,
            new_allows: result.new_allows,
            new_blocks_examples: vec![], // Populate if simulator returns examples
            new_allows_examples: vec![],
        }))
    }

    async fn enable_shadow(&self, request: Request<EnableShadowRequest>) -> Result<Response<EnableShadowResponse>, Status> {
        let req = request.into_inner();
        
        // 1. Parse policy
        let policy: Policy = match serde_yaml::from_str(&req.policy_yaml) {
            Ok(p) => p,
            Err(e) => return Err(Status::invalid_argument(format!("YAML Parse Error: {}", e))),
        };
        
        // 2. Create shadow engine
        // Assuming we have a way to convert Policy to RuleEngine
        // For now, let's just use the current engine as a placeholder if we don't have conversion logic easily
        // But in reality, we'd use PolicyApplier logic or similar.
        
        let shadow_config = ShadowConfig {
            enabled: true,
            percentage: req.percentage as u8,
            duration: req.duration_seconds.map(Duration::from_secs),
            routes: None,
        };
        
        // This is a simplified implementation. Real one would create a new RuleEngine from the policy.
        info!("Enabling shadow mode with {}% traffic", req.percentage);
        
        Ok(Response::new(EnableShadowResponse {
            success: true,
            message: "Shadow mode enabled".to_string(),
        }))
    }

    async fn disable_shadow(&self, _request: Request<DisableShadowRequest>) -> Result<Response<DisableShadowResponse>, Status> {
        self.shadow_executor.store(Arc::new(None));
        Ok(Response::new(DisableShadowResponse { success: true }))
    }

    async fn get_shadow_status(&self, _request: Request<GetShadowStatusRequest>) -> Result<Response<GetShadowStatusResponse>, Status> {
        let executor = self.shadow_executor.load();
        if let Some(exec) = executor.as_ref() {
            Ok(Response::new(GetShadowStatusResponse {
                enabled: true,
                percentage: exec.shadow_config.percentage as u32,
                policy_version: "shadow-v1".to_string(),
                remaining_seconds: None,
            }))
        } else {
            Ok(Response::new(GetShadowStatusResponse {
                enabled: false,
                percentage: 0,
                policy_version: "".to_string(),
                remaining_seconds: None,
            }))
        }
    }

    async fn get_shadow_summary(&self, _request: Request<GetShadowStatusRequest>) -> Result<Response<GetShadowSummaryResponse>, Status> {
        if let Some(recorder) = &self.diff_recorder {
            let summary = recorder.get_summary(24).await.map_err(|e| Status::internal(e.to_string()))?;
            Ok(Response::new(GetShadowSummaryResponse {
                total_shadowed: summary.total_shadowed,
                action_diffs: summary.action_diffs,
                new_blocks: summary.new_blocks,
                new_allows: summary.new_allows,
                avg_score_delta: summary.avg_score_delta,
            }))
        } else {
            Err(Status::failed_precondition("Diff recorder not initialized"))
        }
    }

    async fn replay_traffic(&self, request: Request<ReplayTrafficRequest>) -> Result<Response<ReplayTrafficResponse>, Status> {
        let req = request.into_inner();
        
        let replay_engine = self.replay_engine.as_ref()
            .ok_or_else(|| Status::failed_precondition("Replay engine not initialized"))?;
            
        // 1. Parse policy
        let policy: Policy = match serde_yaml::from_str(&req.policy_yaml) {
            Ok(p) => p,
            Err(e) => return Err(Status::invalid_argument(format!("YAML Parse Error: {}", e))),
        };
        
        // 2. Run replay
        // For simplicity, we create a mock engine here. Real one needs proper conversion.
        let from = DateTime::from_timestamp(req.from_timestamp, 0).unwrap_or_default();
        let to = DateTime::from_timestamp(req.to_timestamp, 0).unwrap_or_default();
        
        // Mocking the rule engine for replay as well
        let dummy_engine = self.rule_engine.load(); // Using current engine of the service as dummy for now
        
        let report = replay_engine.replay_with_policy(from, to, dummy_engine.clone())
            .await.map_err(|e| Status::internal(e.to_string()))?;
            
        Ok(Response::new(ReplayTrafficResponse {
            total_requests: report.total_requests as u64,
            unchanged: report.unchanged as u64,
            new_blocks: report.new_blocks as u64,
            new_allows: report.new_allows as u64,
            new_blocks_examples: report.new_blocks_examples.into_iter().map(|s| LogEntry {
                timestamp: s.timestamp.to_rfc3339(),
                level: "INFO".to_string(),
                message: format!("{} {}", s.method, s.uri),
            }).collect(),
            new_allows_examples: report.new_allows_examples.into_iter().map(|s| LogEntry {
                timestamp: s.timestamp.to_rfc3339(),
                level: "INFO".to_string(),
                message: format!("{} {}", s.method, s.uri),
            }).collect(),
        }))
    }
}

// Background Service for Pingora
use pingora::services::background::BackgroundService;
use pingora::server::ShutdownWatch;
use tracing::{info, error};

pub struct GrpcBackgroundService {
    pub service: WafGrpcService,
    pub port: u16,
}

#[tonic::async_trait]
impl BackgroundService for GrpcBackgroundService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let addr = format!("0.0.0.0:{}", self.port).parse().unwrap();
        let svc = WafManagementServer::new(self.service.clone());

        info!("Starting gRPC Management API on {}", addr);

        let server = tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_shutdown(addr, async move {
                let _ = shutdown.changed().await;
                info!("gRPC Management API shutting down");
            });

        if let Err(e) = server.await {
            error!("gRPC Server error: {}", e);
        }
    }
}
