use crate::parser::context::RequestContext;
use crate::rules::engine::{InspectionResult, InspectionAction};

// Stub for now. If needed we can expand.
// Assuming InspectionResult and RequestContext are available in crate::proxy or similar.
// If they are not, I will add simple stubs or depend on the grep result.

pub struct EarlyExitEngine {
    threshold: i32,
}

impl EarlyExitEngine {
    pub fn new(threshold: i32) -> Self {
        Self { threshold }
    }

    /// Returns Some(decision) if we can exit early, None if need full check
    pub fn check_early_exit(
        &self,
        _ctx: &RequestContext, // Unused for now but available for logic
        partial_score: i32,
        rules_checked_percentage: f32, // Added parameter to logic
    ) -> Option<InspectionResult> {
        // If score already exceeds threshold, no need to continue
        if partial_score >= self.threshold {
            return Some(InspectionResult {
                action: InspectionAction::Block,
                reasoning: "Score exceeded threshold during early check".to_string(),
                crs_score: partial_score,
                combined_score: partial_score,
                rules_matched: vec![],
                ml_anomaly_score: 0.0,
                ml_classification: None,
                latency_ms: 0,
            });
        }
        
        // If we're more than 50% through rules and score is 0, likely clean
        if partial_score == 0 && rules_checked_percentage > 0.5 {
            // Note: We would add to negative cache here if we had access to it easily
            
            return Some(InspectionResult {
                action: InspectionAction::Allow,
                reasoning: "Clean request (early exit)".to_string(),
                crs_score: 0,
                combined_score: 0,
                rules_matched: vec![],
                ml_anomaly_score: 0.0,
                ml_classification: None,
                latency_ms: 0,
            });
        }
        
        None
    }
}
