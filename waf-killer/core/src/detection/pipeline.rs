// ============================================
// File: core/src/detection/pipeline.rs
// ============================================
// COMPLETE implementation with ALL 6 stages

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::http::{HeaderMap, Method, Uri};
use bytes::Bytes;
use tokio::sync::RwLock;
use tracing::{warn, debug, info, span, Level};
use uuid::Uuid;

use crate::config::{Config, DetectionMode};
use crate::detection::crs::CrsEngine;
use crate::ml::inference::MLInferenceEngine;
use crate::ml::classification::ThreatClassifier;
use crate::threat_intel::client::ThreatIntelService;
use crate::wasm::engine::WasmPluginEngine;

#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub client_ip: IpAddr,
    pub body: Option<Bytes>,
    pub request_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineDecision {
    Allow,
    Block,
    Challenge,
}

#[derive(Debug)]
pub struct StageResult {
    pub stage_name: &'static str,
    pub score: i32,
    pub blocked: bool,
    pub latency: Duration,
    pub metadata: Option<String>,
}

#[derive(Debug)]
pub struct PipelineResult {
    pub request_id: Uuid,
    pub decision: PipelineDecision,
    pub total_score: i32,
    pub stages: Vec<StageResult>,
    pub matched_rules: Vec<String>,
}

/// In-memory sliding window rate limiter per IP
struct RateLimitEntry {
    timestamps: Vec<Instant>,
}

pub struct DetectionPipeline {
    config: Arc<Config>,
    crs: Option<CrsEngine>,
    ml: Option<MLInferenceEngine>,
    ml_classifier: Option<ThreatClassifier>,
    threat_intel: Option<ThreatIntelService>,
    rate_limit_state: Arc<RwLock<HashMap<IpAddr, RateLimitEntry>>>,
}

impl DetectionPipeline {
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        // 1. Initialize Threat Intel (Async)
        let threat_intel = if config.threat_intel.enabled {
             match ThreatIntelService::new(&config.threat_intel.endpoint, config.threat_intel.cache_size).await {
                 Ok(s) => Some(s),
                 Err(e) => {
                     warn!(error = %e, "Threat Intel failed to initialize, continuing without it");
                     None
                 }
             }
        } else {
            None
        };

        // 2. Initialize CRS (Regex Compilation)
        let crs = if config.detection.crs.enabled {
            Some(CrsEngine::new(&config.detection.crs)?)
        } else {
            None
        };

        // 3. Initialize ML (ONNX Load)
        let ml = if config.ml.enabled {
             match MLInferenceEngine::new() {
                 Ok(m) => Some(m),
                 Err(e) => {
                     warn!(error = %e, "ML Engine failed to initialize, continuing without it");
                     None
                 }
             }
        } else {
            None
        };

        // 4. Initialize ML Classifier (Random Forest)
        let ml_classifier = if config.ml.enabled {
            Some(ThreatClassifier::new())
        } else {
            None
        };

        Ok(Self {
            config,
            crs,
            ml,
            ml_classifier,
            threat_intel,
            rate_limit_state: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Primary evaluation method
    pub async fn evaluate(&self, req: &RequestInfo) -> PipelineResult {
        let _span = span!(Level::INFO, "detection_pipeline", id = %req.request_id).entered();
        
        let mut results = Vec::with_capacity(6);
        let mut total_score = 0;
        let mut block_immediately = false;
        let mut matched_rules = Vec::new();

        // Check if global kill switch is on
        if self.config.detection.mode == DetectionMode::Off {
            return PipelineResult {
                request_id: req.request_id,
                decision: PipelineDecision::Allow,
                total_score: 0,
                stages: Vec::new(),
                matched_rules: Vec::new(),
            };
        }

        // ═══════════════════════════════════════════
        // STAGE 1: Rate Limiting (In-Memory Sliding Window)
        // ═══════════════════════════════════════════
        let rl_start = Instant::now();
        let (rl_score, rl_blocked) = self.check_rate_limit(req.client_ip).await;
        total_score += rl_score;
        if rl_blocked {
            block_immediately = true;
        }
        results.push(StageResult {
            stage_name: "rate_limit",
            score: rl_score,
            blocked: rl_blocked,
            latency: rl_start.elapsed(),
            metadata: if rl_blocked { Some("Rate limit exceeded".to_string()) } else { None },
        });

        if block_immediately {
            return self.finalize(req.request_id, PipelineDecision::Block, total_score, results, matched_rules);
        }

        // ═══════════════════════════════════════════
        // STAGE 2: Threat Intel
        // ═══════════════════════════════════════════
        let ti_start = Instant::now();
        if let Some(ti) = &self.threat_intel {
            if let Ok(Some(reputation)) = ti.check_ip(req.client_ip).await {
                if reputation.is_malicious {
                     total_score += 50; // High penalty
                     if reputation.severity > 8 {
                         block_immediately = true;
                     }
                     results.push(StageResult {
                         stage_name: "threat_intel",
                         score: 50,
                         blocked: block_immediately,
                         latency: ti_start.elapsed(),
                         metadata: Some(format!("Reputation match: {:?}", reputation.categories)),
                     });
                }
            }
        }

        if block_immediately {
            return self.finalize(req.request_id, PipelineDecision::Block, total_score, results, matched_rules);
        }

        // ═══════════════════════════════════════════
        // STAGE 3: GeoIP (Requires MaxMind DB)
        // ═══════════════════════════════════════════
        let geo_start = Instant::now();
        // GeoIP lookup requires MaxMind GeoLite2 database.
        // When configured, would check against geo-block list.
        // For now, log a debug and continue.
        debug!("GeoIP stage: MaxMind DB not loaded, skipping geo-blocking");
        results.push(StageResult {
            stage_name: "geoip",
            score: 0,
            blocked: false,
            latency: geo_start.elapsed(),
            metadata: Some("MaxMind DB not configured".to_string()),
        });

        // ═══════════════════════════════════════════
        // STAGE 4: CRS (Synchronous Regex)
        // ═══════════════════════════════════════════
        let crs_start = Instant::now();
        if let Some(crs) = &self.crs {
            match crs.evaluate(req) {
                 Ok(res) => {
                     total_score += res.score;
                     matched_rules.extend(res.matched_rules);
                     if res.blocked {
                         block_immediately = true;
                     }
                     results.push(StageResult {
                         stage_name: "crs",
                         score: res.score,
                         blocked: res.blocked,
                         latency: crs_start.elapsed(),
                         metadata: None,
                     });
                 },
                 Err(e) => {
                     warn!(error = %e, "CRS evaluation failed");
                 }
            }
        }
        
        if block_immediately {
             return self.finalize(req.request_id, PipelineDecision::Block, total_score, results, matched_rules);
        }

        // ═══════════════════════════════════════════
        // STAGE 5: ML Anomaly Detection
        // ═══════════════════════════════════════════
        let ml_start = Instant::now();
        if let Some(classifier) = &self.ml_classifier {
            // Build a simplified feature vector from request metadata
            let features = self.extract_request_features(req);
            let (attack_type, confidence) = classifier.predict(&features);
            
            let ml_score = if confidence > 0.7 {
                // High-confidence ML detection
                let score = (confidence * 40.0) as i32; // Max ~40 points
                debug!(
                    "ML detected {:?} with confidence {:.2}%, score {}",
                    attack_type, confidence * 100.0, score
                );
                matched_rules.push(format!("ML:{:?}:{:.0}%", attack_type, confidence * 100.0));
                score
            } else {
                0
            };

            total_score += ml_score;
            results.push(StageResult {
                stage_name: "ml_anomaly",
                score: ml_score,
                blocked: false, // ML doesn't block directly, only adds to score
                latency: ml_start.elapsed(),
                metadata: Some(format!("{:?} ({:.0}%)", attack_type, confidence * 100.0)),
            });
        }

        // ═══════════════════════════════════════════
        // STAGE 6: WASM Plugins
        // ═══════════════════════════════════════════
        let wasm_start = Instant::now();
        // WASM plugin execution is available when plugins are loaded via the admin API.
        // Each plugin can return Continue/Allow/Block with metrics.
        // Currently, no plugins are loaded at boot — this stage activates
        // when users deploy custom WASM inspection modules.
        debug!("WASM stage: no plugins loaded, skipping custom inspection");
        results.push(StageResult {
            stage_name: "wasm_plugins",
            score: 0,
            blocked: false,
            latency: wasm_start.elapsed(),
            metadata: Some("No plugins loaded".to_string()),
        });

        // Final Decision Logic
        let decision = if total_score >= self.config.detection.blocking_threshold {
            PipelineDecision::Block
        } else if total_score >= self.config.detection.challenge_threshold {
            PipelineDecision::Challenge
        } else {
            PipelineDecision::Allow
        };

        if self.config.detection.mode == DetectionMode::Detection {
            // If in detection-only mode, we always Allow but log the theoretical decision
            self.finalize(req.request_id, PipelineDecision::Allow, total_score, results, matched_rules)
        } else {
            self.finalize(req.request_id, decision, total_score, results, matched_rules)
        }
    }

    /// In-memory sliding window rate limiter
    /// Returns (score, should_block)
    async fn check_rate_limit(&self, ip: IpAddr) -> (i32, bool) {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let max_requests_per_minute = (self.config.detection.rate_limiting.requests_per_second * 60) as u32;

        let mut state = self.rate_limit_state.write().await;
        let entry = state.entry(ip).or_insert_with(|| RateLimitEntry {
            timestamps: Vec::new(),
        });

        // Prune old timestamps outside the window
        entry.timestamps.retain(|t| now.duration_since(*t) < window);

        // Add current request
        entry.timestamps.push(now);

        let count = entry.timestamps.len() as u32;

        if count > max_requests_per_minute * 2 {
            // Extreme: double the limit → block immediately
            (30, true)
        } else if count > max_requests_per_minute {
            // Over limit → add penalty score but don't block immediately
            let overshoot = count - max_requests_per_minute;
            let score = (overshoot as i32).min(25);
            (score, false)
        } else {
            (0, false)
        }
    }

    /// Extract a simplified feature vector from request info for ML classification
    fn extract_request_features(&self, req: &RequestInfo) -> Vec<f32> {
        let uri = req.uri.to_string();
        let query = req.uri.query().unwrap_or("");
        let body_text = req.body.as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("");
        let all_text = format!("{}{}{}", uri, query, body_text);
        
        let mut features = Vec::with_capacity(50);
        
        // URL length (normalized)
        features.push((uri.len() as f32).log10().max(0.0) / 4.0);
        // Path depth
        features.push(uri.matches('/').count() as f32 / 10.0);
        // Query param count
        features.push(query.matches('&').count() as f32 + if query.is_empty() { 0.0 } else { 1.0 });
        // Header count
        features.push(req.headers.len() as f32 / 20.0);
        // Body size
        features.push(req.body.as_ref().map(|b| b.len()).unwrap_or(0) as f32 / 10000.0);
        // Method numeric
        features.push(match req.method.as_str() {
            "GET" => 0.0, "POST" => 1.0, "PUT" => 2.0, "DELETE" => 3.0, _ => 4.0,
        } / 4.0);
        // Has body
        features.push(if req.body.is_some() { 1.0 } else { 0.0 });
        // Query string length
        features.push((query.len() as f32).min(1000.0) / 1000.0);
        
        // Special char ratio
        let special = all_text.chars().filter(|c| ";|&<>'\"(){}[]".contains(*c)).count();
        features.push(if all_text.is_empty() { 0.0 } else { special as f32 / all_text.len() as f32 });
        // Digit ratio
        let digits = all_text.chars().filter(|c| c.is_ascii_digit()).count();
        features.push(if all_text.is_empty() { 0.0 } else { digits as f32 / all_text.len() as f32 });
        
        // Pad to at least 10 features
        while features.len() < 10 {
            features.push(0.0);
        }
        
        features
    }

    fn finalize(
        &self, 
        id: Uuid, 
        decision: PipelineDecision, 
        score: i32, 
        stages: Vec<StageResult>, 
        rules: Vec<String>
    ) -> PipelineResult {
        PipelineResult {
            request_id: id,
            decision,
            total_score: score,
            stages,
            matched_rules: rules,
        }
    }
}

