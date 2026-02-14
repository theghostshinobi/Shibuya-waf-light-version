use super::actions::{Action, Severity};
use super::parser::Rule;
use super::scoring::TransactionContext;
use crate::parser::context::RequestContext; 
use crate::rules::variables::extract_variable;
use std::time::{Duration, Instant};
use crate::ml::features::extract_features;
use crate::ml::classification::{ThreatClassifier, AttackType};
use crate::ml::explainability::{ExplainabilityEngine, Explanation};
// use crate::ml::inference::{MLInferenceEngine, AttackClassification};
// use crate::ml::scoring::{ScoringEngine, CombinedScore};
// use crate::ml::baseline::{TrafficStats, BaselineStats}; // Assuming these exist or will stub
use log::debug;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub paranoia_level: u8,
    pub inbound_threshold: i32,
    pub outbound_threshold: i32,
    pub enabled: bool,
    pub mode: EngineMode,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EngineMode {
    Blocking,
    Detection,
    Off,
}

pub struct RuleEngine {
    pub rules: Vec<Rule>,
    pub config: EngineConfig,
    // ML Components
    // feature_extractor removed, using stateless
    classifier: ThreatClassifier,
    explainer: ExplainabilityEngine,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InspectionResult {
    pub action: InspectionAction,
    pub crs_score: i32,
    pub ml_anomaly_score: f32, // Stubs for now
    pub ml_classification: Option<AttackType>,
    pub ml_explanation: Option<Explanation>,
    pub combined_score: i32,
    pub rules_matched: Vec<RuleMatch>,
    pub execution_time: u64, // Changed from Duration to u64 (microseconds) for serialization
    pub reasoning: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub enum InspectionAction {
    Allow,
    Block,
    Log,
    Challenge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: u32,
    pub msg: String,
    pub severity: Severity,
}

struct CombinedScoreStub {
   score: i32,
   action: InspectionAction,
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>, config: EngineConfig) -> Self {
        Self { 
            rules, 
            config,
            // feature_extractor removed
            classifier: ThreatClassifier::new(),
            explainer: ExplainabilityEngine::new(),
        }
    }

    pub fn inspect_request(
        &self, 
        ctx: &RequestContext, 
    ) -> InspectionResult {
        let start = Instant::now();
        let mut tx_ctx = TransactionContext::new();
        let mut matches = Vec::new();
        let mut blocked = false;

        // 1. CRS / Rule Inspection
        if self.config.enabled && self.config.mode != EngineMode::Off {
            for rule in &self.rules {
                let mut rule_matched = false;
                
                // Check if rule is disabled
                if rule.actions.contains(&Action::Disabled) {
                    continue;
                }

                // Variable Extraction & Matching Logic
                for rule_var in &rule.variables {
                    let extracted_values = extract_variable(&rule_var.variable, ctx);
                    for val in extracted_values {
                        // DEBUG: Inspect Rule 9000001
                        if rule.id == 9000001 {
                            debug!("Rule 9000001 checking var {:?}: '{}'", rule_var.variable, val);
                        }

                        let mut current_val = val;
                        for t in &rule.transformations {
                            current_val = t.apply(&current_val);
                        }
                        let mut is_match = rule.operator.matches(&current_val);
                        if rule.operator_negation {
                            is_match = !is_match;
                        }

                        if is_match {
                             if !rule_var.negation { rule_matched = true; break; }
                        } else {
                            if rule_var.negation { rule_matched = true; break; }
                        }
                    }
                    if rule_matched { break; }
                }

                if rule_matched {
                    let mut msg = String::new();
                    let mut severity = Severity::Notice;
                    let mut score_delta = 0;
                    let mut has_setvar_score = false;
                    let mut has_block_action = false;

                    for action in &rule.actions {
                        match action {
                            Action::Block => {
                                has_block_action = true;
                            },
                            Action::Deny(_) => {
                                has_block_action = true;
                            },
                            Action::Msg(m) => msg = m.clone(),
                            Action::Severity(s) => severity = *s,
                            Action::SetVar(val) => {
                                 // Handle CRS scoring variables (pl1..4)
                                 // Only count SetVar scoring for seed rules (900001-900099)
                                 // CRS rules' SetVar scores on benign traffic accumulate too high
                                 if val.contains("anomaly_score") && (rule.id >= 900001 && rule.id <= 900099) {
                                     has_setvar_score = true;
                                     // Extract value part (after =+)
                                     if let Some(idx) = val.find("=+") {
                                         let val_part = &val[idx+2..];
                                         let delta = if val_part.contains("critical") { 5 }
                                            else if val_part.contains("error") { 4 }
                                            else if val_part.contains("warning") { 3 }
                                            else if val_part.contains("notice") { 2 }
                                            else { val_part.parse::<i32>().unwrap_or(0) };
                                         
                                         if delta > 0 {
                                            score_delta += delta;
                                            debug!("Rule {} increased score by {}", rule.id, delta);
                                         }
                                     }
                                 }
                            }
                            _ => {}
                        }
                    }

                    // If rule has Block/Deny action but no SetVar scoring,
                    // auto-increment score based on severity.
                    // Only for seed OWASP rules (900001-900099) — CRS rules use their own SetVar scoring.
                    if has_block_action && !has_setvar_score && (rule.id >= 900001 && rule.id <= 900099) {
                        let auto_score = match severity {
                            Severity::Emergency => 100,
                            Severity::Alert => 100,
                            Severity::Critical => 100,   // Instant block
                            Severity::Error => 50,       // High signal
                            Severity::Warning => 25,     // Medium signal
                            Severity::Notice => 10,      // Low signal
                            Severity::Info => 5,
                            Severity::Debug => 2,
                        };
                        score_delta += auto_score;
                        debug!("Rule {} auto-scored {} (severity={:?}, no SetVar)", rule.id, auto_score, severity);
                    }
                    
                    tx_ctx.increment_score("tx.anomaly_score", score_delta);

                    matches.push(RuleMatch {
                        rule_id: rule.id,
                        msg,
                        severity,
                    });
                }
            }
        }
        
        // 1.5 Multipart Security Inspection (Mega Fix)
        if let Some(multipart_fields) = &ctx.body_multipart {
             let mp_result = self.inspect_multipart_request(ctx, multipart_fields);
             if mp_result.crs_score > 0 {
                 tx_ctx.increment_score("multipart_risk", mp_result.crs_score);
                 matches.extend(mp_result.rules_matched);
             }
        }
        
        // 2. ML Classification (Episode 5)
        let mut ml_classification = None;
        let mut ml_explanation = None;
        
        // We run ML if anomaly score is low (to find hidden attacks) OR high (to classify them)
        // For efficiency, run always in this demo, but typically could be conditional
        if let Ok(feature_vector) = extract_features(ctx, None) {
            let features_vec = feature_vector.features.to_vec();
            let (attack_type, confidence) = self.classifier.predict(&features_vec);
            
            if attack_type != AttackType::Benign && confidence > 0.6 {
                ml_classification = Some(attack_type.clone());
                debug!("ML Detected: {:?} with confidence {:.2}", attack_type, confidence);
                
                // Explain
                let explanation = self.explainer.explain(&features_vec, attack_type.clone());
                ml_explanation = Some(explanation);
            }
        }

        // 3. Combined Scoring
        // NOTE: ML boosting disabled in rule engine — the proxy already runs
        // its own ThreatClassifier pass (with proper shadow mode, thresholds, etc.)
        // Having it here too caused ALL requests to get +50, blocking everything.
        // if ml_classification.is_some() {
        //     tx_ctx.increment_score("ml_boost", 50);
        // }

        log::warn!("🔍 [RULE_ENGINE] CRS score={}, matched_rules={}, ml_classification={:?}",
            tx_ctx.anomaly_score, matches.len(), ml_classification);

        let final_result = CombinedScoreStub {
             score: tx_ctx.anomaly_score,
             action: if tx_ctx.anomaly_score >= self.config.inbound_threshold { InspectionAction::Block } else { InspectionAction::Allow },
         };

        // Enforce blocking mode
        if final_result.action == InspectionAction::Block && self.config.mode == EngineMode::Blocking {
            blocked = true;
        }

        let reasoning_str = if let Some(exp) = &ml_explanation {
            format!("CRS Score: {}, ML: {} ({})", tx_ctx.anomaly_score, ml_classification.map(|c| c.name()).unwrap_or("None"), exp.reasoning)
        } else {
            format!("CRS Score: {}, ML: None", tx_ctx.anomaly_score)
        };

        InspectionResult {
            action: if blocked { InspectionAction::Block } else { final_result.action },
            crs_score: tx_ctx.anomaly_score,
            ml_anomaly_score: 0.0, // stub
            ml_classification,
            ml_explanation,
            combined_score: final_result.score,
            rules_matched: matches,
            execution_time: start.elapsed().as_micros() as u64,
            reasoning: reasoning_str,
        }
    }

    /// Inspect multipart request with file upload security
    pub fn inspect_multipart_request(
        &self,
        _ctx: &RequestContext,
        fields: &[crate::parser::context::MultipartField],
    ) -> InspectionResult {
        let mut total_risk = 0;
        let mut matched_rules = Vec::new();
        
        for field in fields {
            let field_risk = field.security_checks.risk_score as i32;
            total_risk += field_risk;
            
            // Generate alerts for high-risk uploads
            if field.security_checks.risk_score >= 40 {
                 matched_rules.push(RuleMatch {
                    rule_id: 900000,
                    msg: format!("HIGH RISK file upload: field='{}', filename='{}', risk={}", 
                        field.name, 
                        field.filename.as_deref().unwrap_or("unknown"), 
                        field.security_checks.risk_score
                    ),
                    severity: Severity::Critical,
                });
                
                // Add warnings
                for warning in &field.security_checks.warnings {
                     matched_rules.push(RuleMatch {
                        rule_id: 900000,
                        msg: format!("File warning: {}", warning),
                        severity: Severity::Error,
                    });
                }
            }
            
            // Check for specific attack types
            if field.security_checks.has_path_traversal {
                matched_rules.push(RuleMatch {
                    rule_id: 900001,
                    msg: "Path traversal in filename".to_string(),
                    severity: Severity::Critical,
                });
            }
            
            if field.security_checks.is_executable {
                matched_rules.push(RuleMatch {
                    rule_id: 900002,
                    msg: "Executable file upload".to_string(),
                    severity: Severity::Error,
                });
            }
            
            if field.security_checks.is_script {
                matched_rules.push(RuleMatch {
                    rule_id: 900003,
                    msg: "Script file upload (PHP/JSP/ASP)".to_string(),
                    severity: Severity::Critical,
                });
            }
            
            if field.security_checks.content_type_mismatch {
                matched_rules.push(RuleMatch {
                    rule_id: 900004,
                    msg: "Content-Type spoofing detected".to_string(),
                    severity: Severity::Error,
                });
            }
            
            if field.security_checks.is_potentially_malicious {
                matched_rules.push(RuleMatch {
                    rule_id: 900005,
                    msg: "Malicious content patterns detected".to_string(),
                    severity: Severity::Critical,
                });
            }
            
            // Also inspect text field content with normal rules - Stub for now
            // If we wanted to, we could extract text and run through rules, but let's stick to file security
        }
        
        let action = if total_risk >= 100 {
            InspectionAction::Block
        } else if total_risk >= 50 {
            InspectionAction::Log
        } else {
            InspectionAction::Allow
        };
        
        InspectionResult {
            action,
            crs_score: total_risk,
            ml_anomaly_score: 0.0,
            ml_classification: None,
            ml_explanation: None,
            combined_score: total_risk,
            rules_matched: matched_rules,
            execution_time: 0, // negligible or not measured here
            reasoning: "Multipart Security Scan".to_string(),
        }
    }
}
