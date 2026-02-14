use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Scaler metadata from training pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalerMetadata {
    pub feature_count: usize,
    pub scaler_mean: Vec<f32>,
    pub scaler_scale: Vec<f32>,
    pub feature_names: Vec<String>,
    pub training_date: String,
    pub training_samples: usize,
    pub model_version: String,
}

impl ScalerMetadata {
    /// Load scaler from JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ScalerError> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Err(ScalerError::FileNotFound(path.display().to_string()));
        }
        
        let content = fs::read_to_string(path)
            .map_err(|e| ScalerError::ReadError(e.to_string()))?;
        
        let metadata: ScalerMetadata = serde_json::from_str(&content)
            .map_err(|e| ScalerError::ParseError(e.to_string()))?;
        
        // Validate metadata
        metadata.validate()?;
        
        log::info!(
            "Loaded scaler: {} features, trained on {} samples ({})",
            metadata.feature_count,
            metadata.training_samples,
            metadata.model_version
        );
        
        Ok(metadata)
    }
    
    /// Validate scaler metadata consistency
    fn validate(&self) -> Result<(), ScalerError> {
        // Check mean/scale length matches feature_count
        if self.scaler_mean.len() != self.feature_count {
            return Err(ScalerError::InvalidMetadata(format!(
                "scaler_mean length {} != feature_count {}",
                self.scaler_mean.len(),
                self.feature_count
            )));
        }
        
        if self.scaler_scale.len() != self.feature_count {
            return Err(ScalerError::InvalidMetadata(format!(
                "scaler_scale length {} != feature_count {}",
                self.scaler_scale.len(),
                self.feature_count
            )));
        }
        
        if self.feature_names.len() != self.feature_count {
            return Err(ScalerError::InvalidMetadata(format!(
                "feature_names length {} != feature_count {}",
                self.feature_names.len(),
                self.feature_count
            )));
        }
        
        // Check for NaN or Inf in scaler values
        for (i, &mean) in self.scaler_mean.iter().enumerate() {
            if !mean.is_finite() {
                return Err(ScalerError::InvalidMetadata(format!(
                    "scaler_mean[{}] is not finite: {}",
                    i, mean
                )));
            }
        }
        
        for (i, &scale) in self.scaler_scale.iter().enumerate() {
            if !scale.is_finite() || scale == 0.0 {
                return Err(ScalerError::InvalidMetadata(format!(
                    "scaler_scale[{}] is invalid: {}",
                    i, scale
                )));
            }
        }
        
        log::debug!("Scaler metadata validation passed");
        Ok(())
    }
    
    /// Apply standardization to feature vector
    pub fn transform(&self, features: &[f32]) -> Result<Vec<f32>, ScalerError> {
        if features.len() != self.feature_count {
            return Err(ScalerError::FeatureMismatch {
                expected: self.feature_count,
                got: features.len(),
            });
        }
        
        let scaled: Vec<f32> = features
            .iter()
            .zip(&self.scaler_mean)
            .zip(&self.scaler_scale)
            .map(|((&feature, &mean), &scale)| {
                // Standard scaling: (x - mean) / scale
                (feature - mean) / scale
            })
            .collect();
        
        Ok(scaled)
    }
    
    /// Get feature name by index
    pub fn get_feature_name(&self, index: usize) -> Option<&str> {
        self.feature_names.get(index).map(|s| s.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScalerError {
    #[error("Scaler file not found: {0}")]
    FileNotFound(String),
    
    #[error("Failed to read scaler file: {0}")]
    ReadError(String),
    
    #[error("Failed to parse scaler JSON: {0}")]
    ParseError(String),
    
    #[error("Invalid scaler metadata: {0}")]
    InvalidMetadata(String),
    
    #[error("Feature count mismatch: expected {expected}, got {got}")]
    FeatureMismatch { expected: usize, got: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scaler_loading() {
        // Create test scaler file
        let test_metadata = ScalerMetadata {
            feature_count: 3,
            scaler_mean: vec![1.0, 2.0, 3.0],
            scaler_scale: vec![0.5, 1.0, 2.0],
            feature_names: vec!["f1".to_string(), "f2".to_string(), "f3".to_string()],
            training_date: "2026-01-28".to_string(),
            training_samples: 1000,
            model_version: "v1.0".to_string(),
        };
        
        // Test transformation
        let features = vec![2.0, 4.0, 7.0];
        let scaled = test_metadata.transform(&features).unwrap();
        
        // Expected: [(2-1)/0.5, (4-2)/1.0, (7-3)/2.0] = [2.0, 2.0, 2.0]
        assert_eq!(scaled, vec![2.0, 2.0, 2.0]);
    }
    
    #[test]
    fn test_invalid_feature_count() {
        let metadata = ScalerMetadata {
            feature_count: 2,
            scaler_mean: vec![1.0, 2.0],
            scaler_scale: vec![1.0, 1.0],
            feature_names: vec!["f1".to_string(), "f2".to_string()],
            training_date: "2026-01-28".to_string(),
            training_samples: 1000,
            model_version: "v1.0".to_string(),
        };
        
        let features = vec![1.0, 2.0, 3.0]; // Wrong size
        let result = metadata.transform(&features);
        
        assert!(matches!(result, Err(ScalerError::FeatureMismatch { .. })));
    }
}
