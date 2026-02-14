use anyhow::Result;
use ort::{
    session::{Session, builder::GraphOptimizationLevel as OptimizationLevel},
    value::Tensor,
};
use std::sync::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::ml::scaler::ScalerMetadata;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackType {
    SQLInjection,
    XSS,
    PathTraversal,
    RCE,
    SSRF,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct AttackClassification {
    pub attack_type: AttackType,
    pub confidence: f32,
    pub probabilities: Vec<f32>,
}

#[derive(Debug, Clone)]
pub struct AnomalyPrediction {
    pub score: f32,
    pub is_anomaly: bool,
    pub confidence: f32,
    pub top_features: Vec<(String, f32)>,
}

impl Default for AnomalyPrediction {
    fn default() -> Self {
        Self {
            score: 0.0,
            is_anomaly: false,
            confidence: 0.0,
            top_features: Vec::new(),
        }
    }
}

fn calculate_confidence(score: f32) -> f32 {
    if score >= 0.9 {
        0.95
    } else if score >= 0.7 {
        0.85
    } else if score >= 0.5 {
        0.70
    } else {
        0.50
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MLError {
    #[error("Session error: {0}")]
    SessionError(String),
    
    #[error("Model load error: {0}")]
    ModelLoadError(String),
    
    #[error("Scaler load error: {0}")]
    ScalerLoadError(String),
    
    #[error("Feature scaling error: {0}")]
    FeatureScalingError(String),
    
    #[error("Tensor error: {0}")]
    TensorError(String),
    
    #[error("Inference error: {0}")]
    InferenceError(String),
    
    #[error("Output parse error: {0}")]
    OutputParseError(String),
}

pub struct MLInferenceEngine {
    session: Mutex<Session>,  // ✨ MUTEX for thread safety
    scaler: ScalerMetadata,
    threshold: RwLock<f32>, // ✨ RWLOCK for thread-safe updates
}

impl MLInferenceEngine {
    pub fn new(
        model_path: &str,
        scaler_path: &str,
        threshold: f32,
    ) -> Result<Self, MLError> {
        log::info!("Loading ONNX model from: {}", model_path);
        
        let session = Session::builder()
            .map_err(|e| MLError::SessionError(e.to_string()))?
            .with_optimization_level(OptimizationLevel::Level3)
            .map_err(|e| MLError::SessionError(e.to_string()))?
            .with_intra_threads(4)
            .map_err(|e| MLError::SessionError(e.to_string()))?
            .commit_from_file(model_path)
            .map_err(|e| MLError::ModelLoadError(format!("{}: {}", model_path, e)))?;
        
        log::info!("Loading scaler from: {}", scaler_path);
        let scaler = ScalerMetadata::from_file(scaler_path)
            .map_err(|e| MLError::ScalerLoadError(e.to_string()))?;
        
        log::info!(
            "ML Engine initialized: {} features, threshold={:.2}",
            scaler.feature_count,
            threshold
        );
        
        Ok(Self {
            session: Mutex::new(session),
            scaler,
            threshold: RwLock::new(threshold),
        })
    }
    
    pub fn predict(&self, features: Vec<f32>) -> Result<AnomalyPrediction, MLError> {
        // Step 1: Scale features
        let scaled = self.scaler.transform(&features)
            .map_err(|e| MLError::FeatureScalingError(e.to_string()))?;
        
        // Step 2: Lock session and run inference
        let mut session = self.session.lock()
            .map_err(|e| MLError::InferenceError(format!("Mutex lock failed: {}", e)))?;
        
        let input_shape = vec![1, self.scaler.feature_count];
        let input_tensor = Tensor::from_array((
            input_shape.as_slice(),
            scaled.into_boxed_slice()
        ))
        .map_err(|e| MLError::TensorError(e.to_string()))?;
        
        let outputs = session.run(ort::inputs![input_tensor])
            .map_err(|e| MLError::InferenceError(e.to_string()))?;
        
        // Step 3: Extract score
        // Access the first output tensor
        let output_value = &outputs[0]; 
        let (_, score_data) = output_value
            .try_extract_tensor::<f32>()
            .map_err(|e| MLError::OutputParseError(e.to_string()))?;
        
        // Assuming single output score
        let score = score_data.first().copied().unwrap_or(0.0).max(0.0).min(1.0);
        
        // Read threshold with lock
        let threshold = *self.threshold.read().unwrap_or_else(|p| p.into_inner());

        Ok(AnomalyPrediction {
            score,
            is_anomaly: score >= threshold,
            confidence: calculate_confidence(score),
            top_features: self.get_top_features(&features),
        })
    }
    
    pub fn update_threshold(&self, threshold: f32) { // Changed to &self
        let val = threshold.max(0.0).min(1.0);
        if let Ok(mut w) = self.threshold.write() {
             *w = val;
             log::info!("ML threshold updated to: {:.2}", val);
        }
    }
    
    pub fn get_threshold(&self) -> f32 {
        *self.threshold.read().unwrap_or_else(|p| p.into_inner())
    }
    
    fn get_top_features(&self, features: &[f32]) -> Vec<(String, f32)> {
        let mut feature_scores: Vec<(String, f32)> = features
            .iter()
            .enumerate()
            .map(|(i, &value)| {
                let name = self.scaler.get_feature_name(i)
                    .unwrap_or("unknown")
                    .to_string();
                (name, value)
            })
            .collect();
        
        feature_scores.sort_by(|a, b| {
            b.1.abs().partial_cmp(&a.1.abs()).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        feature_scores.into_iter().take(5).collect()
    }
}
