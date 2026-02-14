use anyhow::{Result, Context};
use ort::session::{Session, builder::GraphOptimizationLevel};
use ort::value::Value;
use std::sync::Mutex;
use std::path::Path;
use std::fs::File;
use std::collections::HashMap;
use std::time::Instant;
use serde::{Deserialize, Serialize};
use super::features::FeatureVector;
use ndarray::Array;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackClass {
    Benign = 0,
    CommandInjection = 1,
    PathTraversal = 2,
    RCE = 3,
    SQLi = 4,
    XSS = 5,
    // Note: The index must match the alphabetical sort of LabelEncoder if that's what sklearn used.
    // In my Python output I saw: ['Benign' 'CommandInjection' 'PathTraversal' 'RCE' 'SQLi' 'XSS']
    // So:
    // 0: Benign
    // 1: CommandInjection
    // 2: PathTraversal
    // 3: RCE
    // 4: SQLi
    // 5: XSS
}

impl AttackClass {
    pub fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::Benign),
            1 => Some(Self::CommandInjection),
            2 => Some(Self::PathTraversal),
            3 => Some(Self::RCE),
            4 => Some(Self::SQLi),
            5 => Some(Self::XSS),
            _ => None,
        }
    }

    pub fn to_index(&self) -> usize {
        *self as usize
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Benign => "Benign",
            Self::CommandInjection => "CommandInjection",
            Self::PathTraversal => "PathTraversal",
            Self::RCE => "RCE",
            Self::SQLi => "SQLi",
            Self::XSS => "XSS",
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::Benign,
            Self::CommandInjection,
            Self::PathTraversal,
            Self::RCE,
            Self::SQLi,
            Self::XSS,
        ]
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::Benign => Severity::Info,
            Self::XSS => Severity::Warning,
            Self::SQLi | Self::RCE | Self::CommandInjection => Severity::Critical,
            Self::PathTraversal => Severity::Error,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Serialize)]
pub struct ClassificationResult {
    pub predicted_class: AttackClass,
    pub confidence: f32, // 0.0-1.0 for predicted class
    pub all_scores: HashMap<AttackClass, f32>,
    pub is_attack: bool,
    pub explanation: ClassificationExplanation,
}

#[derive(Debug, Serialize)]
pub struct ClassificationExplanation {
    pub top_features: Vec<FeatureImportance>,
    pub reasoning: String,
}

#[derive(Debug, Serialize)]
pub struct FeatureImportance {
    pub feature_name: String,
    pub value: f32,
    pub importance: f32,
    pub impact: String, // "StronglySupports", "Supports", "Neutral"
}

#[derive(Debug, Deserialize)]
pub struct ClassifierMetadata {
    pub version: String,
    pub training_date: String,
    pub accuracy: f32,
    pub classes: Vec<String>,
    pub scaler: ScalerParams,
    pub feature_names: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ScalerParams {
    pub mean: Vec<f32>,
    pub scale: Vec<f32>,
}

pub struct AttackClassifier {
    session: Mutex<Session>,
    scaler_mean: Vec<f32>,
    scaler_scale: Vec<f32>,
    metadata: ClassifierMetadata,
    feature_importance_map: HashMap<String, Vec<f32>>, // ClassName -> feature_importances
    feature_names: Vec<String>,
}

impl AttackClassifier {
    pub fn load(model_path: &Path) -> Result<Self> {
        let _ = ort::init().with_name("waf-classifier").commit();

        let session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .with_intra_threads(1)?
            .commit_from_file(model_path)
            .context("Failed to load ONNX classifier")?;

        // Load Metadata
        let metadata_path = model_path.parent()
            .context("Model path has no parent")?
            .join("classifier_metadata.json");
            
        let file = File::open(&metadata_path)
            .with_context(|| format!("Failed to open metadata: {:?}", metadata_path))?;
        let metadata: ClassifierMetadata = serde_json::from_reader(file)?;

        // Load Feature Importance
        let imp_path = model_path.parent()
            .unwrap()
            .join("feature_importance.json");
        let imp_file = File::open(&imp_path)
            .with_context(|| format!("Failed to open feature importance: {:?}", imp_path))?;
        let feature_importance_map: HashMap<String, Vec<f32>> = serde_json::from_reader(imp_file)?;

        Ok(Self {
            session: Mutex::new(session),
            scaler_mean: metadata.scaler.mean.clone(),
            scaler_scale: metadata.scaler.scale.clone(),
            feature_names: metadata.feature_names.clone(),
            metadata,
            feature_importance_map,
        })
    }

    pub fn predict(&self, features: &FeatureVector) -> Result<ClassificationResult> {
        // 1. Standardize
        let mut standardized = Vec::with_capacity(28);
        for i in 0..28 {
            let val = (features.features[i] - self.scaler_mean[i]) / self.scaler_scale[i];
            standardized.push(val);
        }

        // 2. Inference
        let input_array = Array::from_shape_vec((1, 28), standardized.clone())?;
        let input_value = Value::from_array(input_array)?;
        
        let mut session = self.session.lock().map_err(|_| anyhow::anyhow!("Failed to lock session"))?;
        let outputs = session.run(ort::inputs!["float_input" => input_value])?;
        
        // Output 0: label (int64) - handled by zipmap: false
        let label_tensor = outputs.get("label").ok_or_else(|| anyhow::anyhow!("No 'label' output"))?;
        // If it's single int
        let label_idx: i64 = label_tensor.try_extract_tensor::<i64>()?.1[0];
        
        // Output 1: probabilities (float32 tensor of shape [1, n_classes])
        let prob_tensor = outputs.get("probabilities").ok_or_else(|| anyhow::anyhow!("No 'probabilities' output"))?;
        let probs: &[f32] = prob_tensor.try_extract_tensor::<f32>()?.1;
        
        let predicted_class = AttackClass::from_index(label_idx as usize)
            .unwrap_or(AttackClass::Benign);
            
        let confidence = probs[label_idx as usize];

        let mut all_scores = HashMap::new();
        for (i, &p) in probs.iter().enumerate() {
            if let Some(c) = AttackClass::from_index(i) {
                all_scores.insert(c, p);
            }
        }

        // 3. Explainability
        let explanation = self.explain_prediction(&features, &standardized, predicted_class);

        Ok(ClassificationResult {
            predicted_class,
            confidence,
            all_scores,
            is_attack: predicted_class != AttackClass::Benign,
            explanation,
        })
    }

    fn explain_prediction(
        &self,
        features: &FeatureVector,
        _standardized: &[f32], 
        predicted_class: AttackClass,
    ) -> ClassificationExplanation {
        let class_name = predicted_class.name();
        // Default to empty if not found
        let empty_imp = vec![0.0; 28];
        let class_importances = self.feature_importance_map.get(class_name).unwrap_or(&empty_imp);

        let mut feature_importances = Vec::with_capacity(28);

        for (i, &imp) in class_importances.iter().enumerate() {
             // Basic impact logic: Feature Value * Global Importance for Class
             // Since SHAP values in feature_importance_map are already "impacts" (averaged), 
             // we can use them directly or scale by current feature value if they are coefficients (Linear).
             // But for RBF SVM/XGB, SHAP importances are "average impact magnitude".
             // A true local explanation needs TreeExplainer/KernelExplainer at runtime (too slow).
             // So we use: Global Importance * (Feature Value - Mean) -> roughly contribution relative to mean?
             // Or simpler: Just report features that have high global importance for this class AND are "active" (non-zero).
             
             // Simplification for speed:
             // If feature > 0 (it is present), we ascribe its importance.
             // If feature is 0 (not present), its contribution is likely neutral/negative depending on model.
             
             let feat_val = features.features[i];
             if feat_val == 0.0 { continue; } // Skip 0 features for explanation clarity

             let importance_val = imp; // This is avg(|SHAP|)
             
             if importance_val > 0.01 {
                 feature_importances.push(FeatureImportance {
                     feature_name: self.feature_names.get(i).unwrap_or(&format!("feat_{}", i)).clone(),
                     value: feat_val,
                     importance: importance_val,
                     impact: if importance_val > 0.1 { "StronglySupports".to_string() } else { "Supports".to_string() },
                 });
             }
        }

        // Sort by importance
        feature_importances.sort_by(|a, b| b.importance.partial_cmp(&a.importance).unwrap());
        
        let top_features: Vec<_> = feature_importances.into_iter().take(5).collect();

        let reasoning_parts: Vec<String> = top_features.iter()
            .map(|f| format!("{} ({:.1})", f.feature_name, f.value))
            .collect();

        let reasoning = format!(
            "Classified as {} due to: {}", 
            predicted_class.name(), 
            reasoning_parts.join(", ")
        );

        ClassificationExplanation {
            top_features,
            reasoning,
        }
    }
}
