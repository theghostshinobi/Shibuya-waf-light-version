use waf_killer_core::ml::classification::{ThreatClassifier, AttackType};
use waf_killer_core::ml::features::{FeatureVector, FEATURE_NAMES};

// Model is trained in-memory; no file path needed

fn create_mock_features(is_sqli: bool) -> FeatureVector {
    let mut features = [0.0f32; 50];
    if is_sqli {
        // SQLi features: index 34 = SQL keywords, 28 = SQL chars
        features[34] = 2.0;
        features[28] = 3.0;
    } else {
        // Benign
        features[0] = 10.0; // url length
    }
    FeatureVector {
        features,
        feature_names: &FEATURE_NAMES,
    }
}

#[test]
fn test_classifier_loads() {
    let classifier = ThreatClassifier::new();
    // If we get here without panic, the mock model trained successfully
    let features = create_mock_features(false);
    let (attack_type, _confidence) = classifier.predict(&features.features.to_vec());
    assert_eq!(attack_type, AttackType::Benign);
}

#[test]
fn test_classify_sqli() {
    let classifier = ThreatClassifier::new();
    let features = create_mock_features(true);
    let (attack_type, confidence) = classifier.predict(&features.features.to_vec());
    
    println!("Prediction: {:?} Confidence: {}", attack_type, confidence);
    
    // With mock training data, SQLi features should trigger SQLi classification
    assert_ne!(attack_type, AttackType::Benign, "Expected attack, got Benign");
}

#[test]
fn test_classify_benign() {
    let classifier = ThreatClassifier::new();
    let features = create_mock_features(false);
    let (attack_type, _confidence) = classifier.predict(&features.features.to_vec());
    
    assert_eq!(attack_type, AttackType::Benign);
}
