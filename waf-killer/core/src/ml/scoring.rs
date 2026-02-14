use super::inference::AttackClassification;
use std::sync::Arc;
use crate::rules::engine::InspectionAction;

#[derive(Clone)]
pub struct ScoringWeights {
    pub crs_weight: f32,        // 0.6
    pub ml_anomaly_weight: f32, // 0.3
    pub ml_class_weight: f32,   // 0.1
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            crs_weight: 0.6,
            ml_anomaly_weight: 0.3,
            ml_class_weight: 0.1,
        }
    }
}

pub struct ScoringEngine {
    weights: ScoringWeights,
}

impl ScoringEngine {
    pub fn new(weights: ScoringWeights) -> Self {
        Self { weights }
    }

    pub fn calculate_combined_score(
        &self,
        crs_score: i32,
        ml_anomaly_score: f32,
        ml_classification: Option<&AttackClassification>,
    ) -> CombinedScore {
        // Normalize CRS score (0-100) to 0-1
        // Assuming CRS score usually is roughly 5 per rule match. 
        // 20 points is already quite high (Blocking threshold).
        // Let's cap at 50 for normalization purposes to 1.0
        let normalized_crs = (crs_score as f32 / 50.0).min(1.0);
        
        // ML anomaly score already 0-1
        
        // ML classification confidence (0-1, or 0 if no classification)
        let normalized_class = ml_classification
            .map(|c| c.confidence)
            .unwrap_or(0.0);
        
        // Weighted average
        let combined = (normalized_crs * self.weights.crs_weight)
            + (ml_anomaly_score * self.weights.ml_anomaly_weight)
            + (normalized_class * self.weights.ml_class_weight);
        
        // Scale back to 0-100 for display/logging
        let final_score = (combined * 100.0) as i32;
        
        // Determine action based on score
        // Adjusted thresholds for combined score
        let action = match final_score {
            0..=39 => InspectionAction::Allow,
            40..=69 => InspectionAction::Log,
            // 70..=89 => InspectionAction::Challenge, // Challenge not yet impl?
            90..=100 => InspectionAction::Block,
            _ => InspectionAction::Block, // > 100
        };
        
        CombinedScore {
            score: final_score,
            action,
            breakdown: ScoreBreakdown {
                crs_contribution: (normalized_crs * self.weights.crs_weight * 100.0) as i32,
                ml_anomaly_contribution: (ml_anomaly_score * self.weights.ml_anomaly_weight * 100.0) as i32,
                ml_class_contribution: (normalized_class * self.weights.ml_class_weight * 100.0) as i32,
            },
        }
    }
}

#[derive(Debug)]
pub struct CombinedScore {
    pub score: i32,
    pub action: InspectionAction,
    pub breakdown: ScoreBreakdown,
}

#[derive(Debug)]
pub struct ScoreBreakdown {
    pub crs_contribution: i32,
    pub ml_anomaly_contribution: i32,
    pub ml_class_contribution: i32,
}
