use super::classification::AttackType;
// use super::features::FeatureVector;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FeatureImportance {
    pub feature_name: String,
    pub importance: f32, // Simplified contribution score
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Explanation {
    pub top_features: Vec<FeatureImportance>,
    pub reasoning: String,
}

pub struct ExplainabilityEngine {
    // Feature names map (index -> name)
    feature_names: Vec<String>,
}

impl ExplainabilityEngine {
    pub fn new() -> Self {
        // Names corresponding to features.rs extraction logic
        // This is manually synced for Ep 5. ideally comes from config/metadata.
        let mut names = Vec::new();
        names.push("uri_len".to_string());         // 0
        names.push("body_size".to_string());       // 1
        names.push("entropy_uri".to_string());     // 2
        names.push("entropy_body".to_string());    // 3
        names.push("special_chars_sql".to_string()); // 4 (Actually 28 in features.rs loop? No, features.rs has specific pushes)
        // Let's look at features.rs structure:
        // 1. uri len
        // 2. body size
        // 3. entropy uri
        // 4. entropy body
        // 5. chars sql [''', '"', ';']
        // 6. chars html ['<', '>', '/']
        // 7. chars cmd ['|', '&', '$']
        // 8. sql keywords
        // 9. xss patterns
        // 10. path traversal ../
        // 11. path traversal ..\
        // 12-15. Method OneHot (GET, POST, PUT, OTHER)
        // 16. is_json
        // 17. is_multipart
        // 18. header count
        // 19-21. Rare headers
        // ... padded to 50.
        
        let predefined = vec![
            "URI Length", "Body Size", "URI Entropy", "Body Entropy",
            "SQL Special Chars", "HTML Special Chars", "Command Chars",
            "SQL Keywords Count", "XSS Patterns Count",
            "Path Traversal (Slash)", "Path Traversal (Backslash)",
            "Method: GET", "Method: POST", "Method: PUT", "Method: Other",
            "Is JSON", "Is Multipart", "Header Count",
            "Header: X-Forwarded-For", "Header: X-Real-IP", "Header: Cluster-IP"
        ];
        
        for p in predefined {
            names.push(p.to_string());
        }
        
        // Pad
        while names.len() < 50 {
            names.push(format!("Feature_{}", names.len()));
        }

        Self {
            feature_names: names
        }
    }

    /// Explain why a request was classified as a certain attack type
    /// Uses a Heuristic Global Importance * Local Value approach
    pub fn explain(&self, features: &Vec<f32>, attack_type: AttackType) -> Explanation {
        if attack_type == AttackType::Benign {
            return Explanation {
                top_features: vec![],
                reasoning: "Request is benign.".to_string(),
            };
        }

        // Global importance weights (heuristic knowledge base)
        let weights = self.get_heuristic_weights(attack_type);
        
        // Calculate local contribution: Feature Value * Weight
        // We assume features are somewhat normalized or count-based.
        // For counts (keywords), high count * high weight = high contribution.
        let mut contributions: Vec<(usize, f32)> = features.iter().enumerate()
            .map(|(i, &val)| {
                let w = weights.get(&i).unwrap_or(&0.0);
                // If feature is 0, no contribution usually
                (i, val * w)
            })
            .filter(|(_, score)| *score > 0.0)
            .collect();
            
        // Sort descending
        contributions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        // Take Top 3
        let top_features: Vec<FeatureImportance> = contributions.into_iter().take(3)
            .map(|(i, score)| FeatureImportance {
                feature_name: self.feature_names.get(i).unwrap_or(&format!("Unknown_{}", i)).clone(),
                importance: score
            })
            .collect();

        let reasoning = if top_features.is_empty() {
            format!("Detected {} based on model confidence, but specific feature contribution is low.", attack_type.name())
        } else {
            let top_names: Vec<String> = top_features.iter().map(|f| f.feature_name.clone()).collect();
            format!("Detected {} primarily due to: {}", attack_type.name(), top_names.join(", "))
        };

        Explanation {
            top_features,
            reasoning
        }
    }

    fn get_heuristic_weights(&self, attack_type: AttackType) -> HashMap<usize, f32> {
        let mut w = HashMap::new();
        // Indices based on Sync with features.rs logic above
        // 4: SQL Special Chars
        // 5: HTML Special Chars
        // 6: Command Chars
        // 7: SQL Keywords
        // 8: XSS Patterns
        // 9: Path Traversal (Slash)
        // 10: Path Traversal (Backslash)

        match attack_type {
            AttackType::SQLi => {
                w.insert(7, 10.0); // SQL Keywords
                w.insert(4, 5.0);  // SQL Chars
                w.insert(2, 2.0);  // Entropy
            },
            AttackType::XSS => {
                w.insert(8, 10.0); // XSS Patterns
                w.insert(5, 5.0);  // HTML Chars
            },
            AttackType::RCE | AttackType::CommandInjection => {
                w.insert(6, 10.0); // Command Chars
            },
            AttackType::PathTraversal => {
                w.insert(9, 10.0); // ../
                w.insert(10, 10.0); // ..\
            },
            AttackType::SSRF => {
                w.insert(0, 4.0);
                w.insert(13, 8.0);
                w.insert(15, 10.0);
            },
            AttackType::XXE => {
                w.insert(14, 10.0);
                w.insert(5, 5.0);
                w.insert(19, 6.0);
            },
            AttackType::SSTI => {
                w.insert(11, 10.0);
                w.insert(12, 6.0);
                w.insert(17, 8.0);
            },
            AttackType::NoSQLi => {
                w.insert(22, 10.0);
                w.insert(23, 8.0);
                w.insert(25, 5.0);
            },
            _ => {}
        }
        w
    }
}
