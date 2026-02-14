use super::features::FeatureVector;
use super::baseline::BaselineStats;

#[derive(Debug, Clone)]
pub struct AnomalyExplanation {
    pub top_features: Vec<FeatureContribution>,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct FeatureContribution {
    pub feature_name: String,
    pub value: f32,
    pub contribution: f32,     // Z-score magnitude
    pub is_anomalous: bool,
}

pub fn explain_anomaly(
    features: &FeatureVector,
    baseline: &BaselineStats,
) -> AnomalyExplanation {
    let mut contributions = Vec::new();
    
    for (i, &value) in features.features.iter().enumerate() {
        let feature_name = features.feature_names[i];
        let normal_mean = baseline.feature_means[i];
        let normal_std = baseline.feature_stds[i];
        
        // Avoid division by zero
        let z_score = if normal_std > 0.0001 {
            (value - normal_mean) / normal_std
        } else {
            // If std is 0, any deviation is infinite anomaly
            if (value - normal_mean).abs() > 0.0001 {
                100.0 
            } else {
                0.0
            }
        };
        
        let contribution = z_score.abs();
        let is_anomalous = contribution > 3.0; // > 3 sigma
        
        contributions.push(FeatureContribution {
            feature_name: feature_name.to_string(),
            value,
            contribution,
            is_anomalous,
        });
    }
    
    // Sort by contribution descending
    contributions.sort_by(|a, b| b.contribution.partial_cmp(&a.contribution).unwrap_or(std::cmp::Ordering::Equal));
    
    let top_features: Vec<_> = contributions.into_iter().take(3).collect();
    
    let summary = top_features.iter()
        .map(|f| format!("{} ({:.1}, score {:.1})", f.feature_name, f.value, f.contribution))
        .collect::<Vec<_>>()
        .join(", ");
        
    AnomalyExplanation {
        top_features,
        summary,
    }
}
