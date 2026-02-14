use waf_killer_core::rules::engine::{RuleEngine, EngineConfig, EngineMode, InspectionAction};
use waf_killer_core::rules::parser::parse_rule;
use waf_killer_core::parser::context::RequestContext;

#[test]
fn test_block_sqli() {
    // 1. Setup Engine with scoring rules
    let rule_str = r#"SecRule ARGS:q "@rx (?i:union.*select)" "id:1000,phase:2,pass,msg:'SQLi',severity:'CRITICAL',setvar:'tx.anomaly_score=+5'""#;
    let rule = parse_rule(rule_str).expect("Failed to parse rule");
    
    let config = EngineConfig {
        paranoia_level: 1,
        inbound_threshold: 5, // Score threshold
        outbound_threshold: 4,
        enabled: true,
        mode: EngineMode::Blocking,
    };
    
    let engine = RuleEngine::new(vec![rule], config);

    // 2. Setup Malicious Request
    let mut ctx = RequestContext::new("123".to_string(), "1.2.3.4".to_string());
    ctx.query_params.insert("q".to_string(), vec!["1' UNION SELECT 1".to_string()]); 

    // 3. Inspect
    let result = engine.inspect_request(&ctx);

    // 4. Verify - rule should match and score should trigger block
    assert_eq!(result.rules_matched.len(), 1);
    assert_eq!(result.rules_matched[0].rule_id, 1000);
    assert_eq!(result.action, InspectionAction::Block);
}

#[test]
fn test_score_blocking() {
    // Test that scoring works and blocks when threshold exceeded
    let rule_str = r#"SecRule ARGS:q "@rx (?i:union.*select)" "id:1000,phase:2,pass,msg:'SQLi',setvar:'tx.anomaly_score=+5'""#;
    let rule = parse_rule(rule_str).expect("Failed to parse rule");
    
    let config = EngineConfig {
        paranoia_level: 1,
        inbound_threshold: 5, // Threshold 5
        outbound_threshold: 4,
        enabled: true,
        mode: EngineMode::Blocking,
    };
    
    let engine = RuleEngine::new(vec![rule], config);
    let mut ctx = RequestContext::new("123".to_string(), "1.2.3.4".to_string());
    ctx.query_params.insert("q".to_string(), vec!["UNION SELECT".to_string()]);

    let result = engine.inspect_request(&ctx);

    assert_eq!(result.crs_score, 5);
    assert_eq!(result.action, InspectionAction::Block);
}

