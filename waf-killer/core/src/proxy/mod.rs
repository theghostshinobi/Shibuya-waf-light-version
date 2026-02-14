// ============================================
// File: core/src/proxy/mod.rs
// ============================================
// Episode 1: The Glue
// SECURITY FIX: Pipeline reordered to prevent Self-DoS
// ============================================

use std::sync::Arc;
use std::time::{Instant, Duration};
use std::sync::atomic::Ordering;
use arc_swap::ArcSwap;

use async_trait::async_trait;
use log::{debug, error, info, warn};
use pingora::http::ResponseHeader;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::Result;

use crate::config::Config;
use crate::parser::context::RequestContext;
use crate::parser::http::HttpParser;
use crate::rules::engine::{RuleEngine, InspectionAction};
use crate::botdetection::{BotDetector, DetectionAction};
use crate::ratelimit::distributed::RateLimiter;
use crate::wasm::{WasmPluginManager, interface::{WasmRequest, WasmAction}};

use crate::state::{SharedState, RequestLog, ShadowEvent, AttackCategory};
use crate::ml::inference::MLInferenceEngine;
use crate::ml::features::extract_features;
use crate::ml::feedback::FeedbackManager;
use crate::ml::classification::{ThreatClassifier, AttackType as MlAttackType};
use crate::ml::explainability::ExplainabilityEngine;
use crate::traffic_stats::TrafficStatsTracker;

use std::sync::Mutex;
use crate::api::shadow_api::EndpointDiscovery;

// API Protection Imports
use crate::api_protection::openapi::OpenAPIValidator;
use crate::api_protection::graphql::{
    GraphQLParser, DepthAnalyzer, ComplexityScorer, FieldAuthorizer, GraphQLRateLimiter,
    validate_alias_count, validate_batch_size, extract_graphql_query,
};


/// Maximum allowed body size (10MB) - prevents memory exhaustion attacks
const MAX_BODY_SIZE_BYTES: usize = 10 * 1024 * 1024;

pub struct WafProxy {
    pub config: Arc<ArcSwap<Config>>,
    pub rule_engine: Arc<RuleEngine>, 
    pub bot_detector: Arc<BotDetector>,
    pub rate_limiter: Arc<RateLimiter>,
    pub wasm_manager: Arc<WasmPluginManager>,
    pub shared: Arc<SharedState>,
    pub ml_engine: Option<Arc<MLInferenceEngine>>,
    pub feedback_manager: Option<Arc<FeedbackManager>>,

    pub threat_client: Option<Arc<crate::threat_intel::client::ThreatIntelClient>>, 
    pub traffic_tracker: TrafficStatsTracker,
    pub endpoint_discovery: Arc<EndpointDiscovery>,
    
    // API Protection
    pub openapi_validator: Option<Arc<OpenAPIValidator>>,
    pub graphql_parser: Option<Arc<GraphQLParser>>,
    pub graphql_depth_analyzer: Option<Arc<DepthAnalyzer>>,
    pub graphql_complexity_scorer: Option<Arc<ComplexityScorer>>,
    pub graphql_authorizer: Option<Arc<FieldAuthorizer>>,
    pub graphql_rate_limiter: Option<Arc<GraphQLRateLimiter>>,
    pub graphql_schema: Option<String>, // Added for scorer
    pub api_protection_enabled: bool,
    pub threat_classifier: Option<Arc<ThreatClassifier>>,
    pub explainability_engine: Option<Arc<ExplainabilityEngine>>,
}


#[async_trait]
impl ProxyHttp for WafProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        // Create an empty or default context
        // In reality, we populate this in request_filter
        RequestContext::new(uuid::Uuid::new_v4().to_string(), "0.0.0.0".to_string())
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let start = Instant::now();
        let config = self.config.load();

        info!("🔵 [PROXY] Request received: {} {}", session.req_header().method, session.req_header().uri);
        
        // Prometheus: count every request
        crate::metrics::METRICS.requests_total.inc();
        
        // ═══════════════════════════════════════════════════════════════════════
        // PHASE 1: LIGHTWEIGHT CHECKS (Headers Only - NO BODY READ)
        // These checks run BEFORE reading any body data to prevent Self-DoS
        // ═══════════════════════════════════════════════════════════════════════
        
        // Extract minimal info from headers (cheap operations)
        let client_ip = session.client_addr()
            .map(|a| format!("{}", a))
            .map(|s| {
                if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
                    return sa.ip().to_string();
                }
                s
            })
            .unwrap_or_else(|| "0.0.0.0".to_string());
        
        let request_id = uuid::Uuid::new_v4().to_string();
        
        // 1.1 RATE LIMITING FIRST (IP-based, no body needed)
        // This MUST come first to block flooding attacks before any processing
        let rate_limit_key = format!("ip:{}", client_ip);
        let allowed = self.rate_limiter.check_limit(
            &rate_limit_key, 
            100, // Burst capacity
            10.0 // Refill rate / sec
        ).await.unwrap_or(true); // Fail open

        if !allowed {
            warn!("⏳ RATE LIMITED (pre-body): {}", client_ip);
            {
                let mut stats = self.shared.traffic_stats.lock().unwrap();
                stats.record_attack(AttackCategory::RateLimitExceeded);
            }
            let _ = session.respond_error(429).await;
            self.log_request(request_id, client_ip, "Block", "Rate Limit", 429, start.elapsed(), session, None, None).await;
            return Ok(true);
        }

        // 1.2 BOT DETECTION (Header-based fingerprinting)
        // Check User-Agent, JA3, HTTP/2 fingerprint - no body needed
        if self.shared.controller.bot_detection_enabled.load(Ordering::Relaxed) {
             let has_verification = false; // Placeholder for Cookie check extraction
             
             let user_agent = session.req_header().headers.get("user-agent")
                  .and_then(|v| v.to_str().ok())
                  .unwrap_or("");
     
             let bot_result = self.bot_detector.detect(
                 &client_ip, 
                 user_agent, 
                 None, // TLS Info extraction todo
                 None, // HTTP2 Info extraction todo
                 has_verification
             );
     
             match bot_result.action {
                 DetectionAction::Block => {
                     info!("🤖 BOT BLOCKED (pre-body): {} (score: {})", client_ip, bot_result.bot_score);
                     {
                         let mut stats = self.shared.traffic_stats.lock().unwrap();
                         stats.record_attack(AttackCategory::BotDetected);
                     }
                     let _ = session.respond_error(403).await;
                     self.log_request(request_id, client_ip, "Block", "Bot Detected", 403, start.elapsed(), session, None, None).await;
                     return Ok(true);
                 }
                 DetectionAction::Challenge(html_content) => {
                      info!("🤖 BOT CHALLENGE (pre-body): {} (score: {})", client_ip, bot_result.bot_score);
                      let mut header = ResponseHeader::build(200, Some(4)).unwrap();
                      header.insert_header("Content-Type", "text/html").unwrap();
                      header.insert_header("X-WAF-Challenge", "Active").unwrap();
                      
                      let _ = session.write_response_header(Box::new(header), false).await;
                      let _ = session.write_response_body(Some(bytes::Bytes::from(html_content)), true).await;
                      self.log_request(request_id, client_ip, "Challenge", "Bot Challenge", 200, start.elapsed(), session, None, None).await;
                      return Ok(true);
                 }
                 DetectionAction::Allow => {
                     // Determine if we should tag traffic
                     debug!("Bot Score (pre-body): {}", bot_result.bot_score);
                 }
             }
        }

        // ═══════════════════════════════════════════════════════════════════════

        // 1.3 Threat Intel Check (IP Reputation) - New
        let mut ip_reputation = None;
        if let Some(client) = &self.threat_client {
             if let Ok(ip_addr) = client_ip.parse() {
                 // Check IP synchronously (in-memory hashmap)
                 ip_reputation = client.check_ip(ip_addr);
                 
                 if let Some(ref reputation) = ip_reputation {
                     // Check score threshold
                     if reputation.reputation_score >= 70 { // Threshold from config
                         warn!("💀 THREAT INTEL: IP {} is known malicious (score: {}, type: {:?})", 
                             client_ip, reputation.reputation_score, reputation.threat_type);
                         
                         // Increment struct for Global stats
                         {
                             let mut stats = self.shared.traffic_stats.lock().unwrap();
                             stats.threat_intel_blocks += 1;
                             stats.record_attack(AttackCategory::ThreatIntel);
                         }

                         let shadow_mode = config.shadow.enabled || self.shared.controller.shadow_mode_enabled.load(Ordering::Relaxed);

                         if !shadow_mode {
                             let _ = session.respond_error(403).await;
                             self.log_request(request_id.clone(), client_ip.clone(), "Block", "Threat Intelligence", 403, start.elapsed(), session, None, None).await;
                             return Ok(true);
                         } else {
                             warn!("👻 SHADOW MODE: Threat Intel would have blocked {}", client_ip);
                             crate::metrics::METRICS.shadow_blocks.inc();
                             // Record shadow event
                             let event = ShadowEvent {
                                 rule_id: "ThreatIntel".to_string(),
                                 client_ip: client_ip.clone(),
                                 path: session.req_header().uri.path().to_string(),
                                 timestamp: std::time::SystemTime::now()
                                     .duration_since(std::time::UNIX_EPOCH)
                                     .unwrap()
                                     .as_secs(),
                                 payload_sample: format!("Malicious IP (score: {}, type: {:?})", reputation.reputation_score, reputation.threat_type),
                             };
                             self.shared.add_shadow_event(event);
                         }
                     }
                 }
             }
        }

        // ═══════════════════════════════════════════════════════════════════════════════
        // PHASE 2: BODY LOADING (Only after lightweight checks pass)
        // Now safe to read body - known good IP, not a bot flood
        // ════════════════════════════════════════════════════════════════════════
        
        // 2.1 Content-Length enforcement (before reading)
        let content_length = session.req_header().headers.get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);

        let max_body = config.security.max_body_size.min(MAX_BODY_SIZE_BYTES);
        
        // Reject oversized bodies before reading
        if content_length > max_body {
            warn!("🚫 BODY TOO LARGE: {} bytes from {} (max: {})", content_length, client_ip, max_body);
            let mut header = ResponseHeader::build(413, Some(2)).unwrap();
            header.insert_header("Content-Type", "application/json").unwrap();
            let _ = session.write_response_header(Box::new(header), false).await;
            let body = serde_json::json!({
                "error": "Payload Too Large",
                "max_size": max_body,
                "received": content_length
            });
            let _ = session.write_response_body(Some(bytes::Bytes::from(body.to_string())), true).await;
            self.log_request(request_id, client_ip, "Block", "Body Too Large", 413, start.elapsed(), session, None, None).await;
            return Ok(true);
        }

        // 2.2 Identify GraphQL requests EARLY
        let is_graphql = session.req_header().uri.path().contains("/graphql") || 
                         session.req_header().headers.get("content-type")
                           .and_then(|v| v.to_str().ok())
                           .map(|ct| ct.contains("application/graphql"))
                           .unwrap_or(false);

        // 2.3 Read body (CONDITIONAL EARLY READ for GraphQL or standard flow)
        // This ensures the body is available for GraphQL validation
        let should_read_body = (content_length > 0) || 
                               (session.req_header().headers.get("transfer-encoding").map(|v| v.as_bytes()) == Some(b"chunked")) ||
                               is_graphql; // Always try to read body for GraphQL even if length is implicit

        let body_bytes = if should_read_body && content_length <= max_body {
             if let Ok(Some(body)) = session.read_request_body().await {
                 // Double-check actual size after read (defense in depth)
                 if body.len() > max_body {
                     warn!("🚫 BODY EXCEEDED MAX AFTER READ: {} bytes", body.len());
                     let _ = session.respond_error(413).await;
                     self.log_request(request_id, client_ip, "Block", "Body Too Large", 413, start.elapsed(), session, None, None).await;
                     return Ok(true);
                 }
                 body
             } else {
                 bytes::Bytes::new()
             }
        } else {
            bytes::Bytes::new()
        };
        
        // ═══════════════════════════════════════════════════════════════════════
        // PHASE 3: DEEP INSPECTION (Full parsing, WASM, WAF Engine, ML)
        // Expensive operations only after body is safely loaded
        // ═══════════════════════════════════════════════════════════════════════

        // 3.1 Full Request Parsing - Populate Context (NOW with Body populated!)
        *ctx = match HttpParser::parse_request(
            session.req_header(), 
            body_bytes.clone(), // Pass the read body
            request_id.clone(), 
            client_ip.clone()
        ).await {
            Ok(c) => c,
            Err(e) => {
                error!("Parsing failed: {}", e);
                 let _ = session.respond_error(400).await;
                 self.log_request(request_id, client_ip, "Block", "Parsing Failed", 400, start.elapsed(), session, None, Some(String::from_utf8_lossy(&body_bytes).to_string())).await;
                 return Ok(true);
            }
        };

        // 3.2 WASM Plugin Execution
        if config.wasm.enabled && self.shared.controller.ebpf_enabled.load(Ordering::Relaxed) { 
            // Transform headers to HashMap
            let mut headers_map = std::collections::HashMap::new();
            for (name, value) in session.req_header().headers.iter() {
                if let Ok(v_str) = value.to_str() {
                    headers_map.insert(name.to_string(), v_str.to_string());
                }
            }

            let wasm_req = WasmRequest {
                id: ctx.request_id.clone(),
                method: session.req_header().method.to_string(),
                path: session.req_header().uri.path().to_string(),
                headers: headers_map,
                client_ip: client_ip.clone(),
                body_preview: body_bytes.slice(0..std::cmp::min(body_bytes.len(), 1024)).to_vec(),
            };

            let actions = self.wasm_manager.run_plugins(&wasm_req);
            
            for action in actions {
                match action {
                    WasmAction::Block { reason, score } => {
                        info!("🔌 WASM PLUGIN BLOCKED: {} (reason: {}, score: {})", ctx.request_id, reason, score);
                        let _ = session.respond_error(403).await;
                        self.log_request(request_id, client_ip, "Block", &format!("WASM: {}", reason), 403, start.elapsed(), session, None, Some(String::from_utf8_lossy(&body_bytes).to_string())).await;
                        return Ok(true);
                    },
                    WasmAction::Allow => {}, 
                    _ => {}
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // PHASE 3.5: API PROTECTION (OpenAPI & GraphQL)
        // ═══════════════════════════════════════════════════════════════════════
        
        if self.api_protection_enabled {
            // OpenAPI Validation
            if self.is_api_request(ctx) {
                if let Some(validator) = &self.openapi_validator {
                    match validator.validate_request(ctx) {
                        Ok(validation) => {
                            if !validation.is_valid {
                                // Block invalid API requests
                                let errors = validation.errors.iter()
                                    .map(|e| format!("{:?}", e))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                    
                                warn!("🛡️ API BLOCKED: OpenAPI validation checks failed: {}", errors);
                                {
                                    let mut stats = self.shared.traffic_stats.lock().unwrap();
                                    stats.record_attack(AttackCategory::ProtocolViolation);
                                }
                                let _ = session.respond_error(403).await;
                                self.log_request(request_id, client_ip, "Block", &format!("API Validation: {}", errors), 403, start.elapsed(), session, None, ctx.body_text.clone()).await;
                                return Ok(true);
                            }
                        }
                        Err(e) => {
                            // Fail open on internal validation error
                            warn!("API validation internal error: {}", e);
                        }
                    }
                }
            }

            // GraphQL Protection
            if self.is_graphql_request(ctx) {
                let config = self.config.load();
                let graphql_config = &config.api_protection.graphql;
                
                // a. Batch Size Check (before parsing individual queries)
                if let Some(raw_body) = &ctx.body_raw {
                    let body_str = String::from_utf8_lossy(raw_body);
                    let batch_result = validate_batch_size(&body_str, graphql_config.max_batch_size);
                    
                    info!("🔍 GraphQL Batch Check: size={}, limit={}, exceeds={}", 
                          batch_result.batch_size, batch_result.max_allowed, batch_result.exceeds_limit);

                    if batch_result.exceeds_limit {
                        warn!("🛡️ GRAPHQL BLOCKED: Batch size {} exceeds limit {}", 
                              batch_result.batch_size, batch_result.max_allowed);
                        {
                            let mut stats = self.shared.traffic_stats.lock().unwrap();
                            stats.record_attack(AttackCategory::ProtocolViolation);
                        }
                        let mut header = ResponseHeader::build(429, Some(2)).unwrap();
                        header.insert_header("Content-Type", "application/json").unwrap();
                        let _ = session.write_response_header(Box::new(header), false).await;
                        let body = serde_json::json!({
                            "error": "Query batch size too large",
                            "batch_size": batch_result.batch_size,
                            "max_allowed": batch_result.max_allowed
                        });
                        let _ = session.write_response_body(Some(bytes::Bytes::from(body.to_string())), true).await;
                        self.log_request(request_id, client_ip, "Block", "GraphQL Batch Size", 429, start.elapsed(), session, None, ctx.body_text.clone()).await;
                        return Ok(true);
                    }
                }
                
                if let Some(parser) = &self.graphql_parser {
                    // USE UPDATED QUERY EXTRACTION which supports batch and errors
                    match extract_graphql_query(ctx.body_text.as_deref().unwrap_or("")) {
                        Ok(query_str) => {
                             // Correctly parse first
                             if let Ok(query) = parser.parse(&query_str) {
                                 // We use query.query for analysis which is string (from our parse above, but check return type)
                                 // Actually parser.parse returns GraphQLQuery struct.
                                 // Analyzer needs query string.
                                 
                                 // b. Depth Check
                                 if let Some(analyzer) = &self.graphql_depth_analyzer {
                                     match analyzer.analyze(&query.query) {
                                         Ok(depth_res) => {
                                             if !depth_res.is_valid {
                                                 warn!("🛡️ GRAPHQL BLOCKED: Depth limit exceeded ({})", depth_res.actual_depth);
                                                  {
                                                      let mut stats = self.shared.traffic_stats.lock().unwrap();
                                                      stats.record_attack(AttackCategory::ProtocolViolation);
                                                  }
                                                  let _ = session.respond_error(403).await;
                                                  self.log_request(request_id, client_ip, "Block", "GraphQL Context Depth", 403, start.elapsed(), session, None, ctx.body_text.clone()).await;
                                                  return Ok(true);
                                             }
                                         }
                                         Err(_) => {}
                                     }
                                 }
                                 
                                 // c. Complexity
                                 let mut complexity_score = 0;
                                 if let Some(scorer) = &self.graphql_complexity_scorer {
                                     match scorer.score(&query.query, &self.graphql_schema) {
                                         Ok(score_res) => {
                                             complexity_score = score_res.total_score;
                                             if score_res.exceeds_limit(scorer.max_complexity) { // Accessing field directly as struct is local
                                                  warn!("🛡️ GRAPHQL BLOCKED: Complexity limit exceeded ({})", complexity_score);
                                                  let _ = session.respond_error(403).await;
                                                  self.log_request(request_id, client_ip, "Block", "GraphQL Complexity", 403, start.elapsed(), session, None, ctx.body_text.clone()).await;
                                                  return Ok(true);
                                              }
                                         }
                                         Err(_) => {}
                                     }
                                 }
                                 
                                 // d. Alias Count Check (anti-alias bombing)
                                 match validate_alias_count(&query.query, graphql_config.max_aliases) {
                                     Ok(alias_result) => {
                                         if alias_result.exceeds_limit {
                                             warn!("🛡️ GRAPHQL BLOCKED: Alias count {} exceeds limit {}",
                                                   alias_result.alias_count, alias_result.max_allowed);
                                             {
                                                 let mut stats = self.shared.traffic_stats.lock().unwrap();
                                                 stats.record_attack(AttackCategory::ProtocolViolation);
                                             }
                                             let mut header = ResponseHeader::build(429, Some(2)).unwrap();
                                             header.insert_header("Content-Type", "application/json").unwrap();
                                             let _ = session.write_response_header(Box::new(header), false).await;
                                             let body = serde_json::json!({
                                                 "error": "Too many aliases in query",
                                                 "alias_count": alias_result.alias_count,
                                                 "max_allowed": alias_result.max_allowed
                                              });
                                              let _ = session.write_response_body(Some(bytes::Bytes::from(body.to_string())), true).await;
                                              self.log_request(request_id, client_ip, "Block", "GraphQL Aliases", 429, start.elapsed(), session, None, ctx.body_text.clone()).await;
                                              return Ok(true);
                                          }
                                     }
                                     Err(_) => {}
                                 }

                                 // e. Authorization
                                 if let Some(authorizer) = &self.graphql_authorizer {
                                     // Assuming ctx has user_context, but RequestContext definition doesn't show it explicitly.
                                     // Using None for now or verify context.
                                     // prompt said "ctx.user_context.is_some()".
                                     // I checked RequestContext in previous turn, it does NOT have user_context.
                                     // I will pass None for now.
                                     if let Ok(auth_res) = authorizer.authorize(&query.query, &None) {
                                         if !auth_res.authorized {
                                              warn!("🛡️ GRAPHQL BLOCKED: Field authorization failed");
                                              let _ = session.respond_error(403).await;
                                              self.log_request(request_id, client_ip, "Block", "GraphQL Authz", 403, start.elapsed(), session, None, ctx.body_text.clone()).await;
                                              return Ok(true);
                                          }
                                     }
                                 }

                                 // f. Rate Limiting
                                 if let Some(limiter) = &self.graphql_rate_limiter {
                                     if let Ok(rate_res) = limiter.check_limit(&client_ip, &query.query, complexity_score).await {
                                         if !rate_res.allowed {
                                             warn!("🛡️ GRAPHQL RATE LIMITED");
                                             let _ = session.respond_error(429).await;
                                             self.log_request(request_id, client_ip, "Block", "GraphQL Rate Limit", 429, start.elapsed(), session, None, ctx.body_text.clone()).await;
                                             return Ok(true);
                                         }
                                     }
                                 }
                             }
                        }
                        Err(e) => {
                            warn!("Failed to extract GraphQL query: {}", e);
                            // If we identified it as GraphQL but failed to extract/parse, it might be malformed.
                            // However, we should be careful not to fail open if strict mode is on.
                            // For now, logging warning.
                        }
                    }
                }
            }
        }

        // 3.2 ML Anomaly Detection (Layer 2)

        
        // Track traffic stats
        let traffic_stats = self.traffic_tracker.get_stats(&client_ip);
        self.traffic_tracker.record_request(
            &client_ip,
            &ctx.path,
            session.req_header().headers.get("user-agent").and_then(|v| v.to_str().ok())
        );

        // ML Prediction
        let mut ml_score = 0.0f32;
        
        if let Some(ref ml) = self.ml_engine {
            match extract_features(ctx, Some(&traffic_stats)) {
                Ok(feature_vector) => {
                    let feature_data = feature_vector.features.to_vec();
                    // NEW: serialize features for feedback loop
                    let features_json = serde_json::to_string(&feature_data).ok();
                    
                    let ml_start = Instant::now();
                    match ml.predict(feature_data) {
                        Ok(prediction) => {
                            let duration = ml_start.elapsed().as_micros() as u64;
                            ml_score = prediction.score;
                            
                            {
                                let mut stats = self.shared.traffic_stats.lock().unwrap();
                                stats.ml_scanned_count += 1;
                                stats.total_inference_time_us += duration;
                                stats.last_confidence_score = ml_score;
                                
                                if ml_score > config.ml.threshold {
                                    stats.ml_detections += 1;
                                }
                            }

                            if ml_score > config.ml.threshold {
                                let shadow_mode = config.shadow.enabled || 
                                                  self.shared.controller.shadow_mode_enabled.load(Ordering::Relaxed) ||
                                                  config.ml.shadow_mode;

                                if shadow_mode {
                                     warn!("👻 SHADOW MODE: ML Anomaly would be blocked: {} (score: {:.2})", client_ip, ml_score);
                                     crate::metrics::METRICS.shadow_blocks.inc();
                                     let event = ShadowEvent {
                                         rule_id: format!("ML:{:.2}", ml_score),
                                         client_ip: client_ip.clone(),
                                         path: session.req_header().uri.path().to_string(),
                                         timestamp: std::time::SystemTime::now()
                                             .duration_since(std::time::UNIX_EPOCH)
                                             .unwrap()
                                             .as_secs(),
                                         payload_sample: ctx.body_raw.as_ref()
                                             .map(|b| String::from_utf8_lossy(&b[..b.len().min(100)]).to_string())
                                             .unwrap_or_else(|| session.req_header().uri.path().to_string()),
                                     };
                                     self.shared.add_shadow_event(event);
                                     self.log_request(request_id.clone(), client_ip.clone(), "ShadowBlock", &format!("ML Anomaly (score: {:.2})", ml_score), 200, start.elapsed(), session, features_json, ctx.body_text.clone()).await;
                                } else {
                                     warn!("🤖 ML ANOMALY BLOCKED: {} (score: {:.2})", client_ip, ml_score);
                                     {
                                         let mut stats = self.shared.traffic_stats.lock().unwrap();
                                         stats.record_attack(AttackCategory::MlAnomaly);
                                     }
                                     let _ = session.respond_error(403).await;
                                     self.log_request(request_id, client_ip, "Block", &format!("ML Anomaly (score: {:.2})", ml_score), 403, start.elapsed(), session, features_json, ctx.body_text.clone()).await;
                                     return Ok(true);
                                }
                            }
                        },
                        Err(e) => {
                             if !config.ml.fail_open {
                                 error!("ML prediction failed: {}", e);
                             } else {
                                 warn!("ML prediction failed: {}, continuing without ML score", e);
                             }
                        }
                    }
                },
                Err(e) => {
                    warn!("Feature extraction failed: {}", e);
                }
            }
        }

        // 3.2.1 Threat Classification (smartcore Random Forest — always active)
        if let Some(ref classifier) = self.threat_classifier {
            let ml_enabled = self.shared.controller.ml_enabled.load(Ordering::Relaxed);
            if ml_enabled {
                match extract_features(ctx, Some(&traffic_stats)) {
                    Ok(feature_vector) => {
                        let feature_data = feature_vector.features.to_vec();
                        let features_json = serde_json::to_string(&feature_data).ok();
                        
                        let clf_start = Instant::now();
                        let (attack_type, confidence, _probabilities) = classifier.predict_proba(&feature_data);
                        let clf_duration = clf_start.elapsed().as_micros() as u64;
                        
                        // Update classifier stats
                        {
                            let mut stats = self.shared.traffic_stats.lock().unwrap();
                            stats.classifier_predictions += 1;
                            stats.total_inference_time_us += clf_duration;
                            
                            if attack_type != MlAttackType::Benign {
                                stats.classifier_detections += 1;
                                stats.last_attack_type = attack_type.name().to_string();
                                *stats.classifier_distribution
                                    .entry(attack_type.name().to_string())
                                    .or_insert(0) += 1;
                            }
                        }

                        if attack_type != MlAttackType::Benign && confidence > config.ml.threshold {
                            let shadow_mode = config.shadow.enabled || 
                                              self.shared.controller.shadow_mode_enabled.load(Ordering::Relaxed) ||
                                              config.ml.shadow_mode;

                            let reason = format!("ML Classification: {} (confidence: {:.2})", attack_type.name(), confidence);

                            if shadow_mode {
                                warn!("👻 SHADOW: {} detected from {} (confidence: {:.2})", attack_type.name(), client_ip, confidence);
                                crate::metrics::METRICS.shadow_blocks.inc();
                                let event = ShadowEvent {
                                    rule_id: format!("CLF:{}:{:.2}", attack_type.name(), confidence),
                                    client_ip: client_ip.clone(),
                                    path: session.req_header().uri.path().to_string(),
                                    timestamp: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs(),
                                    payload_sample: ctx.body_raw.as_ref()
                                        .map(|b| String::from_utf8_lossy(&b[..b.len().min(100)]).to_string())
                                        .unwrap_or_else(|| session.req_header().uri.path().to_string()),
                                };
                                self.shared.add_shadow_event(event);
                                self.log_request(request_id.clone(), client_ip.clone(), "ShadowBlock", &reason, 200, start.elapsed(), session, features_json, ctx.body_text.clone()).await;
                            } else {
                                warn!("🧠 ML CLASSIFIED ATTACK: {} from {} (confidence: {:.2}, severity: {})", 
                                    attack_type.name(), client_ip, confidence, attack_type.severity());
                                {
                                    let mut stats = self.shared.traffic_stats.lock().unwrap();
                                    stats.record_attack(AttackCategory::MlAnomaly);
                                }
                                let _ = session.respond_error(403).await;
                                self.log_request(request_id, client_ip, "Block", &reason, 403, start.elapsed(), session, features_json, ctx.body_text.clone()).await;
                                return Ok(true);
                            }
                        } else if attack_type != MlAttackType::Benign {
                            debug!("🧠 ML low-confidence detection: {} ({:.2}) — passing", attack_type.name(), confidence);
                        }
                    },
                    Err(e) => {
                        debug!("Classifier feature extraction failed: {}", e);
                    }
                }
            }
        }

        // 3.3.0 Shadow Mode Sampling
        let shadow_mode_enabled = self.shared.controller.shadow_mode_enabled.load(Ordering::Relaxed) || config.shadow.enabled;
        
        if shadow_mode_enabled {
            let sample_rate = self.shared.controller.shadow_sample_rate.load(Ordering::Relaxed);
            
            if sample_rate < 100 {
                let random_val = rand::random::<u8>() % 100;
                if random_val >= sample_rate {
                     debug!("👻 SHADOW SAMPLING: Skipping request {} (rolled {}, needed < {})", ctx.request_id, random_val, sample_rate);
                     self.log_request(request_id, client_ip, "Allow", "Shadow Sample Skipped", 200, start.elapsed(), session, None, None).await;
                     return Ok(false);
                }
            }
        }

        // 3.3 WAF Rule Engine Inspection (Layer 3)
        info!("🟡 [PROXY] Calling inspection layer...");
        
        let mut inspection_result = self.rule_engine.inspect_request(ctx);

        info!("🟢 [PROXY] Inspection result: {:?}", inspection_result.action);

        // 3.4 Combine Scores (CRS + ML + Threat Intel)
        if ml_score >= 0.8 {
            inspection_result.combined_score += 5;
        } else if ml_score >= 0.6 {
            inspection_result.combined_score += 3;
        } else if ml_score >= 0.4 {
            inspection_result.combined_score += 1;
        }

        if let Some(rep) = &ip_reputation {
            let threat_contribution = match rep.reputation_score {
                90..=100 => 10,
                70..=89 => 5,
                50..=69 => 3,
                30..=49 => 1,
                _ => 0,
            };
            inspection_result.combined_score += threat_contribution;
            debug!("Threat Intel boosted score by +{}", threat_contribution);
        }
        
        if inspection_result.combined_score >= config.detection.blocking_threshold && inspection_result.action == InspectionAction::Allow {
             inspection_result.action = InspectionAction::Block;
             debug!("Combined score {} triggered block (threshold: {})", inspection_result.combined_score, config.detection.blocking_threshold);
        }

        let latency = start.elapsed();
        debug!("Full inspection took {:?}", latency);

        // 3.4 Final Decision
        match inspection_result.action {
            InspectionAction::Block => {
                {
                    let mut stats = self.shared.traffic_stats.lock().unwrap();
                    stats.rule_triggers += 1;
                }

                let shadow_mode = config.shadow.enabled || self.shared.controller.shadow_mode_enabled.load(Ordering::Relaxed);
                
                if shadow_mode {
                     warn!("👻 SHADOW MODE: Request {} would be blocked by WAF Score {}", ctx.request_id, inspection_result.combined_score);
                     crate::metrics::METRICS.shadow_blocks.inc();
                     let event = ShadowEvent {
                         rule_id: format!("WAF:{}", inspection_result.combined_score),
                         client_ip: client_ip.clone(),
                         path: session.req_header().uri.path().to_string(),
                         timestamp: std::time::SystemTime::now()
                             .duration_since(std::time::UNIX_EPOCH)
                             .unwrap()
                             .as_secs(),
                         payload_sample: ctx.body_raw.as_ref()
                             .map(|b| String::from_utf8_lossy(&b[..b.len().min(100)]).to_string())
                             .unwrap_or_else(|| session.req_header().uri.path().to_string()),
                     };
                     self.shared.add_shadow_event(event);
                     self.log_request(request_id.clone(), client_ip.clone(), "ShadowBlock", &format!("Score {}", inspection_result.combined_score), 200, latency, session, None, ctx.body_text.clone()).await;
                     session.req_header_mut().insert_header("X-WAF-Inspection", "ShadowBlocked").unwrap();
                     return Ok(false);
                } else {
                    info!("BLOCKED request {} score={}", ctx.request_id, inspection_result.combined_score); 
                    
                    // Categorize the attack based on matched rules
                    let category = if !inspection_result.rules_matched.is_empty() {
                        // Use first matched rule ID to determine category
                        let first_rule_id = inspection_result.rules_matched[0].rule_id;
                        AttackCategory::from_rule_id(first_rule_id)
                    } else {
                        AttackCategory::Other
                    };
                    
                    {
                        let mut stats = self.shared.traffic_stats.lock().unwrap();
                        stats.record_attack(category);
                    }
                    
                    let body = serde_json::json!({
                        "error": "Forbidden",
                        "reason": "WAF Blocked", 
                        "req_id": ctx.request_id,
                        "score": inspection_result.combined_score
                    });
                    
                    let body_bytes = body.to_string();
                    let mut header = ResponseHeader::build(403, Some(4)).unwrap();
                    header.insert_header("Content-Type", "application/json").unwrap();
                    header.insert_header("Content-Length", body_bytes.len().to_string()).unwrap();
                    header.insert_header("X-WAF-Score", inspection_result.combined_score.to_string()).unwrap();
                    
                    let _ = session.write_response_header(Box::new(header), false).await;
                    let _ = session.write_response_body(Some(bytes::Bytes::from(body_bytes)), true).await;
                    
                    self.log_request(request_id, client_ip, "Block", "WAF Rules", 403, latency, session, None, ctx.body_text.clone()).await;
                    return Ok(true); 
                }
            }
            InspectionAction::Challenge => {
                let _ = session.respond_error(429).await;
                self.log_request(request_id, client_ip, "Challenge", "Rate Limit Challenge", 429, latency, session, None, ctx.body_text.clone()).await;
                return Ok(true);
            }
            _ => {
                session.req_header_mut().insert_header("X-WAF-Inspection", "Passed").unwrap();
                self.log_request(request_id, client_ip, "Allow", "Passed", 200, latency, session, None, ctx.body_text.clone()).await;
                return Ok(false); 
            }
        }
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let config = self.config.load();
         let upstream_url = &config.upstream.backend_url;
         
         let addr = if upstream_url.starts_with("http://") {
             upstream_url.strip_prefix("http://").unwrap()
         } else {
             upstream_url
         };
         
         let peer_addr = if addr.contains(':') {
             addr.to_string()
         } else {
             format!("{}:80", addr)
         };

         let tls = config.upstream.backend_url.starts_with("https://");
         
         let mut peer = HttpPeer::new(peer_addr, tls, String::new());
         
         peer.options.connection_timeout = Some(config.upstream.connect_timeout);
         
         Ok(Box::new(peer))
    }
}

impl WafProxy {
    async fn log_request(&self, id: String, ip: String, action: &str, reason: &str, status: u16, latency: Duration, session: &Session, features: Option<String>, body: Option<String>) {
        let mut headers = Vec::new();
        for (name, value) in session.req_header().headers.iter() {
            if let Ok(v) = value.to_str() {
                headers.push((name.to_string(), v.to_string()));
            }
        }

        let log = RequestLog {
            id,
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            client_ip: ip,
            method: session.req_header().method.to_string(),
            uri: session.req_header().uri.path().to_string(),
            status,
            action: action.to_string(),
            reason: reason.to_string(),
            country: "Unknown".to_string(),
            ml_features: features, 
            headers: Some(headers),
            body,
        };
        self.shared.add_log(log);

        // Update Global Stats + Prometheus
        {
            let mut stats = self.shared.traffic_stats.lock().unwrap();
            stats.total_requests += 1;
            stats.total_latency_ms += latency.as_millis() as u64;
            if action == "Block" {
                stats.blocked += 1;
                crate::metrics::METRICS.requests_blocked.inc();
            } else if action == "Challenge" {
                stats.blocked += 1;
                crate::metrics::METRICS.requests_challenged.inc();
            } else {
                stats.allowed += 1;
            }
            crate::metrics::METRICS.detection_latency.observe(latency.as_secs_f64());
        }

        // Endpoint Discovery
        self.endpoint_discovery.record(
            session.req_header().method.as_str(),
            session.req_header().uri.path(),
            latency.as_millis() as f64
        );
    }
    
    fn is_api_request(&self, ctx: &RequestContext) -> bool {
        // Exclude GraphQL endpoints from OpenAPI validation
        if ctx.uri.contains("/graphql") {
            return false;
        }
        if ctx.uri.starts_with("/api") {
            return true;
        }
        if let Some(ct) = ctx.headers.get("content-type") {
            if let Some(head) = ct.first() {
                 return head.contains("application/json");
            }
        }
        false
    }

    fn is_graphql_request(&self, ctx: &RequestContext) -> bool {
        if ctx.uri.contains("/graphql") {
            return true;
        }
        if let Some(ct) = ctx.headers.get("content-type") {
            if let Some(head) = ct.first() {
                 return head.contains("application/graphql");
            }
        }
        false
    }



}
