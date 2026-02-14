use smartcore::ensemble::random_forest_classifier::{RandomForestClassifier, RandomForestClassifierParameters};
use smartcore::linalg::basic::matrix::DenseMatrix;
use std::sync::Mutex;
use std::path::Path;
use serde::{Deserialize, Serialize};
use log::{info, warn, error};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackType {
    Benign = 0,
    SQLi = 1,
    XSS = 2,
    RCE = 3,
    PathTraversal = 4,
    CommandInjection = 5,
    SSRF = 6,
    XXE = 7,
    SSTI = 8,
    NoSQLi = 9,
}

impl AttackType {
    pub fn from_index(idx: u32) -> Self {
        match idx {
            0 => Self::Benign,
            1 => Self::SQLi,
            2 => Self::XSS,
            3 => Self::RCE,
            4 => Self::PathTraversal,
            5 => Self::CommandInjection,
            6 => Self::SSRF,
            7 => Self::XXE,
            8 => Self::SSTI,
            9 => Self::NoSQLi,
            _ => Self::Benign,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Benign => "Benign",
            Self::SQLi => "SQLi",
            Self::XSS => "XSS",
            Self::RCE => "RCE",
            Self::PathTraversal => "Path Traversal",
            Self::CommandInjection => "Command Injection",
            Self::SSRF => "SSRF",
            Self::XXE => "XXE",
            Self::SSTI => "SSTI",
            Self::NoSQLi => "NoSQLi",
        }
    }
    
    pub fn severity(&self) -> &'static str {
        match self {
            Self::Benign => "none",
            Self::SQLi | Self::RCE | Self::CommandInjection => "critical",
            Self::XSS | Self::SSTI | Self::SSRF => "high",
            Self::PathTraversal | Self::XXE | Self::NoSQLi => "high",
        }
    }

    pub fn all_classes() -> &'static [AttackType] {
        &[
            Self::Benign, Self::SQLi, Self::XSS, Self::RCE,
            Self::PathTraversal, Self::CommandInjection, Self::SSRF,
            Self::XXE, Self::SSTI, Self::NoSQLi,
        ]
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Benign" => Some(Self::Benign),
            "SQLi" => Some(Self::SQLi),
            "XSS" => Some(Self::XSS),
            "RCE" => Some(Self::RCE),
            "Path Traversal" => Some(Self::PathTraversal),
            "Command Injection" => Some(Self::CommandInjection),
            "SSRF" => Some(Self::SSRF),
            "XXE" => Some(Self::XXE),
            "SSTI" => Some(Self::SSTI),
            "NoSQLi" => Some(Self::NoSQLi),
            _ => None,
        }
    }
}

/// Production threat classifier using smartcore Random Forest.
/// Trains on comprehensive synthetic data covering 10 attack classes.
pub struct ThreatClassifier {
    model: Mutex<Option<RandomForestClassifier<f32, u32, DenseMatrix<f32>, Vec<u32>>>>,
    /// Number of trees in the ensemble
    n_trees: usize,
}

impl ThreatClassifier {
    pub fn new() -> Self {
        let n_trees = 100;
        let model = Self::train_production_model(n_trees);
        Self {
            model: Mutex::new(Some(model)),
            n_trees,
        }
    }

    /// Load a pre-trained model from disk via bincode serialization.
    /// Falls back to training a new model if the file doesn't exist or is corrupted.
    pub fn load(path: &Path) -> Self {
        if path.exists() {
            match std::fs::read(path) {
                Ok(bytes) => {
                    match bincode::deserialize::<RandomForestClassifier<f32, u32, DenseMatrix<f32>, Vec<u32>>>(&bytes) {
                        Ok(model) => {
                            info!("✅ ML model loaded from {}", path.display());
                            return Self {
                                model: Mutex::new(Some(model)),
                                n_trees: 100,
                            };
                        }
                        Err(e) => {
                            warn!("⚠️ Failed to deserialize model from {}: {}. Retraining.", path.display(), e);
                        }
                    }
                }
                Err(e) => {
                    warn!("⚠️ Failed to read model file {}: {}. Retraining.", path.display(), e);
                }
            }
        } else {
            info!("📦 No saved model at {}. Training new model.", path.display());
        }

        let classifier = Self::new();
        if let Err(e) = classifier.save(path) {
            warn!("⚠️ Could not save trained model: {}", e);
        }
        classifier
    }

    /// Save the current model to disk via bincode serialization.
    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let guard = self.model.lock().map_err(|e| format!("Lock poisoned: {}", e))?;
        if let Some(ref model) = *guard {
            let bytes = bincode::serialize(model)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let byte_len = bytes.len();
            std::fs::write(path, bytes)?;
            info!("💾 Model saved to {} ({} bytes)", path.display(), byte_len);
            Ok(())
        } else {
            Err("No model to save".into())
        }
    }

    /// Train a production-grade Random Forest with comprehensive synthetic data
    /// covering all 10 attack classes with realistic feature distributions.
    fn train_production_model(n_trees: usize) -> RandomForestClassifier<f32, u32, DenseMatrix<f32>, Vec<u32>> {
        info!("🤖 Training Production Random Forest Model ({} trees, 10 classes)...", n_trees);

        let mut x_data = Vec::new();
        let mut y_data = Vec::new();
        let mut rng_state: u64 = 42;

        // Simple deterministic pseudo-random for reproducibility
        let mut next_f32 = |state: &mut u64| -> f32 {
            *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            ((*state >> 33) as f32) / (u32::MAX as f32) * 2.0
        };

        // ===== Class 0: Benign (200 samples) =====
        for _ in 0..200 {
            let mut row = vec![0.0f32; 50];
            row[0] = 15.0 + next_f32(&mut rng_state) * 20.0;   // URI len: 15-35
            row[1] = 5.0 + next_f32(&mut rng_state) * 10.0;    // Header count
            row[2] = next_f32(&mut rng_state).abs() * 0.1;      // Special char ratio: low
            row[3] = 0.0;                                        // No SQL chars
            row[4] = 0.0;                                        // No SQL keywords
            row[5] = 0.9 + next_f32(&mut rng_state).abs() * 0.1; // Entropy: high (normal)
            row[6] = 0.0;                                        // No XSS patterns
            row[7] = next_f32(&mut rng_state).abs() * 0.05;     // Low encoding ratio
            x_data.push(row);
            y_data.push(0u32);
        }

        // ===== Class 1: SQLi (80 samples) =====
        for _ in 0..80 {
            let mut row = vec![0.0f32; 50];
            row[0] = 30.0 + next_f32(&mut rng_state) * 50.0;
            row[2] = 0.15 + next_f32(&mut rng_state).abs() * 0.2;
            row[3] = 3.0 + next_f32(&mut rng_state).abs() * 5.0;
            row[4] = 2.0 + next_f32(&mut rng_state).abs() * 4.0;
            row[28] = 3.0 + next_f32(&mut rng_state).abs() * 4.0;
            row[34] = 2.0 + next_f32(&mut rng_state).abs() * 3.0;
            row[35] = 1.0;
            row[36] = next_f32(&mut rng_state).abs() * 2.0;
            x_data.push(row);
            y_data.push(1);
        }

        // ===== Class 2: XSS (80 samples) =====
        for _ in 0..80 {
            let mut row = vec![0.0f32; 50];
            row[0] = 25.0 + next_f32(&mut rng_state) * 40.0;
            row[2] = 0.2 + next_f32(&mut rng_state).abs() * 0.2;
            row[6] = 2.0 + next_f32(&mut rng_state).abs() * 3.0;
            row[29] = 2.0 + next_f32(&mut rng_state).abs() * 3.0;
            row[38] = 1.0 + next_f32(&mut rng_state).abs() * 4.0;
            row[39] = 1.0;
            row[40] = next_f32(&mut rng_state).abs() * 2.0;
            x_data.push(row);
            y_data.push(2);
        }

        // ===== Class 3: RCE (60 samples) =====
        for _ in 0..60 {
            let mut row = vec![0.0f32; 50];
            row[0] = 40.0 + next_f32(&mut rng_state) * 80.0;
            row[2] = 0.1 + next_f32(&mut rng_state).abs() * 0.15;
            row[41] = 2.0 + next_f32(&mut rng_state).abs() * 3.0;
            row[42] = 1.0 + next_f32(&mut rng_state).abs() * 2.0;
            row[43] = 1.0;
            row[44] = next_f32(&mut rng_state).abs() * 2.0;
            row[7] = 0.1 + next_f32(&mut rng_state).abs() * 0.2;
            x_data.push(row);
            y_data.push(3);
        }

        // ===== Class 4: Path Traversal (60 samples) =====
        for _ in 0..60 {
            let mut row = vec![0.0f32; 50];
            row[0] = 30.0 + next_f32(&mut rng_state) * 60.0;
            row[45] = 3.0 + next_f32(&mut rng_state).abs() * 5.0;
            row[46] = 1.0 + next_f32(&mut rng_state).abs() * 3.0;
            row[47] = 1.0;
            row[7] = 0.15 + next_f32(&mut rng_state).abs() * 0.3;
            row[2] = 0.1 + next_f32(&mut rng_state).abs() * 0.1;
            x_data.push(row);
            y_data.push(4);
        }

        // ===== Class 5: Command Injection (70 samples) =====
        for _ in 0..70 {
            let mut row = vec![0.0f32; 50];
            row[0] = 20.0 + next_f32(&mut rng_state) * 40.0;
            row[2] = 0.1 + next_f32(&mut rng_state).abs() * 0.15;
            row[41] = 1.0 + next_f32(&mut rng_state).abs() * 3.0;
            row[48] = 2.0 + next_f32(&mut rng_state).abs() * 3.0;
            row[49] = 1.0 + next_f32(&mut rng_state).abs() * 2.0;
            row[42] = next_f32(&mut rng_state).abs() * 2.0;
            x_data.push(row);
            y_data.push(5);
        }

        // ===== Class 6: SSRF (60 samples) =====
        // SSRF: long URIs, internal IP patterns, URL-like param values
        for _ in 0..60 {
            let mut row = vec![0.0f32; 50];
            row[0] = 50.0 + next_f32(&mut rng_state) * 80.0;   // Long URI
            row[1] = 6.0 + next_f32(&mut rng_state) * 4.0;     // Normal headers
            row[2] = 0.1 + next_f32(&mut rng_state).abs() * 0.15; // Moderate special chars
            row[5] = 0.6 + next_f32(&mut rng_state).abs() * 0.2; // Lower entropy (structured URLs)
            row[8] = 1.0;                                        // Has body (POST w/ URL params)
            row[9] = 50.0 + next_f32(&mut rng_state) * 100.0;   // Long query string
            row[10] = 4.0 + next_f32(&mut rng_state).abs() * 2.0; // High param count in body
            row[13] = 1.0;                                        // Has URL-like value in params
            row[15] = 1.0 + next_f32(&mut rng_state).abs() * 2.0; // Internal IP indicators  
            row[21] = 0.3 + next_f32(&mut rng_state).abs() * 0.3; // Digit ratio (IP addresses)
            x_data.push(row);
            y_data.push(6);
        }

        // ===== Class 7: XXE (50 samples) =====
        // XXE: XML content, entity declarations, DOCTYPE patterns
        for _ in 0..50 {
            let mut row = vec![0.0f32; 50];
            row[0] = 20.0 + next_f32(&mut rng_state) * 30.0;
            row[4] = 0.3 + next_f32(&mut rng_state).abs() * 0.4; // Body size indicator
            row[8] = 1.0;                                         // Has body
            row[2] = 0.15 + next_f32(&mut rng_state).abs() * 0.2; // Special chars (< > & ;)
            row[14] = 2.0 + next_f32(&mut rng_state).abs() * 3.0; // XML entity indicators
            row[16] = 1.0;                                         // Content-type anomaly
            row[19] = 1.0 + next_f32(&mut rng_state).abs() * 3.0; // Nested depth indicators
            row[20] = 0.1 + next_f32(&mut rng_state).abs() * 0.2; // Whitespace ratio (XML formatting)
            x_data.push(row);
            y_data.push(7);
        }

        // ===== Class 8: SSTI (50 samples) =====
        // SSTI: template syntax patterns ({{ }}, ${}, <% %>), eval-like constructs
        for _ in 0..50 {
            let mut row = vec![0.0f32; 50];
            row[0] = 25.0 + next_f32(&mut rng_state) * 50.0;
            row[2] = 0.2 + next_f32(&mut rng_state).abs() * 0.25; // High special chars ({, }, $, %)
            row[5] = 0.5 + next_f32(&mut rng_state).abs() * 0.3;  // Moderate entropy
            row[7] = 0.1 + next_f32(&mut rng_state).abs() * 0.15; // Encoding ratio
            row[11] = 1.0 + next_f32(&mut rng_state).abs() * 3.0; // Template syntax indicators
            row[12] = 0.15 + next_f32(&mut rng_state).abs() * 0.2; // Bracket density
            row[17] = 1.0 + next_f32(&mut rng_state).abs() * 2.0; // Eval-like keywords
            row[18] = next_f32(&mut rng_state).abs() * 2.0;       // Math expression indicators
            x_data.push(row);
            y_data.push(8);
        }

        // ===== Class 9: NoSQLi (60 samples) =====
        // NoSQLi: $gt, $ne, $regex patterns, JSON operators
        for _ in 0..60 {
            let mut row = vec![0.0f32; 50];
            row[0] = 25.0 + next_f32(&mut rng_state) * 40.0;
            row[2] = 0.15 + next_f32(&mut rng_state).abs() * 0.2;
            row[5] = 0.6 + next_f32(&mut rng_state).abs() * 0.2;  // Moderate entropy
            row[8] = 1.0;                                          // Has body (JSON)
            row[10] = 2.0 + next_f32(&mut rng_state).abs() * 3.0; // Deep param nesting
            row[22] = 2.0 + next_f32(&mut rng_state).abs() * 4.0; // $ operator count
            row[23] = 1.0 + next_f32(&mut rng_state).abs() * 2.0; // MongoDB operator keywords
            row[24] = 0.15 + next_f32(&mut rng_state).abs() * 0.2; // JSON structural anomaly
            row[25] = 1.0 + next_f32(&mut rng_state).abs() * 3.0; // Nested object depth
            x_data.push(row);
            y_data.push(9);
        }

        let total_samples = x_data.len();
        let x = DenseMatrix::from_2d_vec(&x_data);
        let y = y_data;

        let params = RandomForestClassifierParameters::default()
            .with_n_trees(n_trees as u16)
            .with_max_depth(12)
            .with_min_samples_leaf(2)
            .with_min_samples_split(4)
            .with_seed(42);

        match RandomForestClassifier::fit(&x, &y, params) {
            Ok(model) => {
                info!("✅ Production Model Trained: {} trees, {} samples, 10 classes", 
                      n_trees, total_samples);
                model
            },
            Err(e) => {
                error!("❌ Failed to train model: {}", e);
                panic!("Could not train production ML model: {}", e);
            }
        }
    }

    pub fn predict(&self, features: &Vec<f32>) -> (AttackType, f32) {
        let model_lock = self.model.lock().unwrap();
        if let Some(model) = model_lock.as_ref() {
            let x = DenseMatrix::from_2d_vec(&vec![features.clone()]);

            let prediction = model.predict(&x).unwrap_or(vec![0]);
            let predicted_idx = prediction[0];

            let confidence = self.calculate_ensemble_confidence(model, features, predicted_idx);

            (AttackType::from_index(predicted_idx), confidence)
        } else {
            (AttackType::Benign, 0.0)
        }
    }

    /// Predict with full probability distribution across all classes.
    pub fn predict_proba(&self, features: &Vec<f32>) -> (AttackType, f32, Vec<(AttackType, f32)>) {
        let model_lock = self.model.lock().unwrap();
        if let Some(model) = model_lock.as_ref() {
            let x = DenseMatrix::from_2d_vec(&vec![features.clone()]);

            let prediction = model.predict(&x).unwrap_or(vec![0]);
            let predicted_idx = prediction[0];
            let confidence = self.calculate_ensemble_confidence(model, features, predicted_idx);

            // Build probability distribution via perturbation voting
            let mut class_votes = [0u32; 10];
            let n_perturbations = 20;
            let mut rng_state: u64 = 99887;

            // Count the primary prediction
            class_votes[predicted_idx as usize] += 1;

            for _ in 0..n_perturbations {
                let perturbed: Vec<f32> = features.iter().map(|&f| {
                    rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let noise = ((rng_state >> 33) as f32 / u32::MAX as f32 - 0.5) * 0.15;
                    (f + f * noise).max(0.0)
                }).collect();

                let px = DenseMatrix::from_2d_vec(&vec![perturbed]);
                if let Ok(pred) = model.predict(&px) {
                    if (pred[0] as usize) < 10 {
                        class_votes[pred[0] as usize] += 1;
                    }
                }
            }

            let total_votes = (n_perturbations + 1) as f32;
            let probabilities: Vec<(AttackType, f32)> = class_votes.iter().enumerate()
                .map(|(i, &count)| (AttackType::from_index(i as u32), count as f32 / total_votes))
                .filter(|(_, prob)| *prob > 0.0)
                .collect();

            (AttackType::from_index(predicted_idx), confidence, probabilities)
        } else {
            (AttackType::Benign, 0.0, vec![(AttackType::Benign, 1.0)])
        }
    }

    /// Get the number of trees in the model.
    pub fn n_trees(&self) -> usize {
        self.n_trees
    }

    /// Calculate confidence based on ensemble stability.
    fn calculate_ensemble_confidence(
        &self,
        model: &RandomForestClassifier<f32, u32, DenseMatrix<f32>, Vec<u32>>,
        features: &[f32],
        primary_class: u32,
    ) -> f32 {
        let n_perturbations = 10;
        let mut agreements = 0u32;
        let mut rng_state: u64 = 12345;

        for _ in 0..n_perturbations {
            let perturbed: Vec<f32> = features.iter().map(|&f| {
                rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let noise = ((rng_state >> 33) as f32 / u32::MAX as f32 - 0.5) * 0.1;
                (f + f * noise).max(0.0)
            }).collect();

            let x = DenseMatrix::from_2d_vec(&vec![perturbed]);
            if let Ok(pred) = model.predict(&x) {
                if pred[0] == primary_class {
                    agreements += 1;
                }
            }
        }

        let vote_ratio = agreements as f32 / n_perturbations as f32;
        let confidence = 0.50 + (vote_ratio * 0.49);

        if primary_class != 0 && vote_ratio >= 0.8 {
            (confidence + 0.05).min(0.99)
        } else {
            confidence
        }
    }
}
