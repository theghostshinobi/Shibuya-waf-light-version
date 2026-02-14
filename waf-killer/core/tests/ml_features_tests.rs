use waf_killer_core::ml::features::{self, extract_features, TrafficStats};
use waf_killer_core::parser::context::RequestContext;
use std::sync::Arc;
use std::collections::HashMap;

#[test]
fn test_feature_extraction_normal_request() {
    let ctx = create_normal_request();
    let stats = TrafficStats::default();
    let features = extract_features(&ctx, Some(&stats)).expect("Feature extraction failed");
    
    // Check dimensions
    assert_eq!(features.features.len(), 50);
    
    // Check that values are in valid range
    for (i, &val) in features.features.iter().enumerate() {
        assert!(
            val >= 0.0 && val <= 10.0, 
            "Feature {} out of range: {}",
            features.feature_names[i],
            val
        );
    }

    // Verify some expected values for a normal request
    // "GET" -> 0.0
    let method_idx = features.feature_names.iter().position(|&n| n == "method_numeric").unwrap();
    assert_eq!(features.features[method_idx], 0.0);

    // SQL pattern count should be 0
    let sql_idx = features.feature_names.iter().position(|&n| n == "sql_pattern_count").unwrap();
    assert_eq!(features.features[sql_idx], 0.0);
}

#[test]
fn test_feature_extraction_sqli_attack() {
    let mut ctx = create_normal_request();
    // Inject SQLi payload in query string
    ctx.query_string = "id=1' OR '1'='1".to_string();
    ctx.uri = format!("/product?{}", ctx.query_string);
    
    let features = extract_features(&ctx, None).unwrap();
    
    // SQL pattern count should be high
    let sql_idx = features.feature_names.iter().position(|&n| n == "sql_pattern_count").unwrap();
    assert!(features.features[sql_idx] > 0.0, "Expected SQL patterns to be detected");
    
    // Suspicious keywords should be detected (OR is not in keyword list, but 'select' is)
    // Let's add 'union select' to make it stronger
    ctx.query_string = "id=1 UNION SELECT * FROM users".to_string();
    ctx.uri = format!("/product?{}", ctx.query_string);
    let features = extract_features(&ctx, None).unwrap();
    
    assert!(features.features[sql_idx] > 0.0, "Expected SQL patterns for UNION SELECT");
    
    let keyword_idx = features.feature_names.iter().position(|&n| n == "suspicious_keywords").unwrap();
    assert!(features.features[keyword_idx] > 0.0, "Expected suspicious keywords");
}

#[test]
fn test_feature_extraction_xss_attack() {
    let mut ctx = create_normal_request();
    // Inject XSS in body
    let payload = "<script>alert(1)</script>";
    ctx.body_raw = Some(Arc::new(payload.as_bytes().to_vec()));
    ctx.body_size = payload.len();
    
    let features = extract_features(&ctx, None).unwrap();
    
    let xss_idx = features.feature_names.iter().position(|&n| n == "xss_pattern_count").unwrap();
    assert!(features.features[xss_idx] > 0.0, "Expected XSS patterns");
    
    let special_char_idx = features.feature_names.iter().position(|&n| n == "special_char_ratio").unwrap();
    assert!(features.features[special_char_idx] > 0.0, "Expected special chars");
}

#[test]
fn test_entropy_high_variance() {
    // Test that high entropy input yields higher feature value than low entropy
    
    // Low entropy
    let mut ctx1 = create_normal_request();
    ctx1.query_string = "aaaaaaaaaaaa".to_string();
    let f1 = extract_features(&ctx1, None).unwrap();
    let ent_idx = f1.feature_names.iter().position(|&n| n == "entropy_query").unwrap();
    
    // High entropy
    let mut ctx2 = create_normal_request();
    ctx2.query_string = "8x92mb5k2l1p".to_string(); // Random
    let f2 = extract_features(&ctx2, None).unwrap();
    
    assert!(
        f2.features[ent_idx] > f1.features[ent_idx],
        "Random string should have higher entropy than repeated string"
    );
}

#[test]
fn test_json_features() {
    let mut ctx = create_normal_request();
    ctx.content_type = Some("application/json".to_string());
    // Nested JSON
    let json = r#"{"users": [{"id": 1, "data": {"a": [1,2]}}, {"id": 2}]}"#;
    ctx.body_raw = Some(Arc::new(json.as_bytes().to_vec()));
    ctx.body_size = json.len();
    
    let features = extract_features(&ctx, None).unwrap();
    
    let depth_idx = features.feature_names.iter().position(|&n| n == "json_depth").unwrap();
    let keys_idx = features.feature_names.iter().position(|&n| n == "json_key_count").unwrap();
    let arrays_idx = features.feature_names.iter().position(|&n| n == "json_array_count").unwrap();
    
    assert!(features.features[depth_idx] > 0.0, "JSON depth not detected");
    assert!(features.features[keys_idx] > 0.0, "JSON keys not detected");
    assert!(features.features[arrays_idx] > 0.0, "JSON arrays not detected");
}

// Helpers
fn create_normal_request() -> RequestContext {
    let mut ctx = RequestContext::new("req-123".to_string(), "127.0.0.1".to_string());
    ctx.method = "GET".to_string();
    ctx.uri = "/home/index.html".to_string();
    ctx.path = "/home/index.html".to_string();
    ctx.protocol = "HTTP/1.1".to_string();
    ctx.headers.insert("user-agent".to_string(), vec!["Mozilla/5.0".to_string()]);
    ctx.headers.insert("accept".to_string(), vec!["text/html".to_string()]);
    ctx.query_string = "".to_string();
    ctx
}

#[test]
fn test_helper_functions_direct() {
    // Tests for individual helper functions exposed by module if public, 
    // but since they are private in mod, we stick to extract_features testing 
    // OR we test public helpers provided in features.rs
    
    assert!((features::calculate_entropy("aaaa") - 0.0).abs() < 0.1);
    assert!(features::calculate_entropy("random text") > 2.0); // Shannon entropy of random text > 0
    
    assert_eq!(features::count_suspicious_keywords("hello world"), 0.0);
    assert!(features::count_suspicious_keywords("SELECT * FROM users") >= 1.0);
    
    assert_eq!(features::detect_encoding_layers("hello"), 0.0);
    assert!(features::detect_encoding_layers("hello%20world") >= 1.0);
}

#[test]
fn test_feature_extraction_performance() {
    let ctx = create_normal_request();
    let stats = TrafficStats::default(); // Reuse stats
    
    // Warmup
    for _ in 0..100 {
        let _ = extract_features(&ctx, Some(&stats));
    }
    
    let start = std::time::Instant::now();
    let iterations = 1000;
    for _ in 0..iterations {
        let _ = extract_features(&ctx, Some(&stats)); 
        // Note: compiler might optimize this if result is unused, 
        // but 'extract_features' is complex enough and returns Result.
        // To be safe we could use std::hint::black_box but it's not stable on valid stable rust generally or requires feature.
    }
    let duration = start.elapsed();
    let avg_time = duration.as_secs_f64() * 1000.0 / iterations as f64;
    
    println!("Average feature extraction time: {:.4} ms", avg_time);
    
    // Requirement is < 1ms
    assert!(avg_time < 0.2, "Feature extraction too slow: {:.4} ms (target < 0.2ms)", avg_time); 
}

