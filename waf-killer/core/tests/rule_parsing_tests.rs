use waf_killer_core::rules::parser::parse_rule;
use waf_killer_core::rules::actions::{Action, Severity};
use waf_killer_core::rules::operators::Operator;
use waf_killer_core::rules::variables::Variable;

#[test]
fn test_parse_sqli_rule() {
    let input = r#"SecRule ARGS|ARGS_NAMES "@rx (?i:union.*select)" "id:942100,phase:2,block,t:none,t:urlDecodeUni,t:lowercase,msg:'SQL Injection',logdata:'Matched Data: %{TX.0}',severity:'CRITICAL',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-sqli',setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'""#;
    
    let rule = parse_rule(input).expect("Failed to parse rule");
    
    assert_eq!(rule.id, 942100);
    assert_eq!(rule.phase, 2);
    
    // Check variables
    assert_eq!(rule.variables.len(), 2);
    // ARGS or ARGS_NAMES
    
    // Check operator
    match rule.operator {
        Operator::Rx(_) => {}, // OK
        _ => panic!("Expected Rx operator"),
    }
    
    // Check match message
    let has_msg = rule.actions.iter().any(|a| matches!(a, Action::Msg(s) if s == "SQL Injection"));
    assert!(has_msg);
    
    // Check severity
    let has_sev = rule.actions.iter().any(|a| matches!(a, Action::Severity(Severity::Critical)));
    assert!(has_sev);
    
    // Check transformations
    assert!(rule.transformations.len() >= 2); // urlDecodeUni, lowercase
}

#[test]
fn test_parse_variable_negation() {
    let input = r#"SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/ "@rx my_pattern" "id:100,phase:1,pass""#;
    
    let rule = parse_rule(input).expect("Failed to parse rule");
    
    assert_eq!(rule.variables.len(), 2);
    assert!(!rule.variables[0].negation);
    assert!(rule.variables[1].negation);
    
    if let Variable::RequestCookiesSpecific(s) = &rule.variables[1].variable {
        assert_eq!(s, "/__utm/");
    } else {
        panic!("Expected RequestCookiesSpecific");
    }
}
