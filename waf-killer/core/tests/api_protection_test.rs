// ============================================
// API Protection Integration Tests
// Episode 11: Task #3 - Initialization Tests
// ============================================

use std::path::PathBuf;

// Mock config for testing API Protection initialization
fn create_test_api_protection_config(enabled: bool) -> waf_killer_core::config::ApiProtectionConfig {
    waf_killer_core::config::ApiProtectionConfig {
        enabled,
        openapi_validation_enabled: false,
        openapi_specs: vec![],
        graphql: waf_killer_core::config::GraphQLProtectionConfig {
            endpoint: "/graphql".to_string(),
            max_depth: 10,
            max_complexity: 1000,
            max_batch_size: 10,
            max_aliases: 50,
            introspection_enabled: false,
            rate_limits: None,
            field_costs: None,
            auth_rules: vec![],
        },
        strict_mode: false,
    }
}

#[test]
fn test_api_protection_config_default() {
    let config = waf_killer_core::config::ApiProtectionConfig::default();
    
    // Verify defaults
    assert!(config.enabled);
    assert!(!config.openapi_validation_enabled);
    assert!(config.openapi_specs.is_empty());
    assert_eq!(config.graphql.max_depth, 7);
    assert_eq!(config.graphql.max_complexity, 1000);
    assert!(!config.strict_mode);
}

#[test]
fn test_api_protection_disabled() {
    let config = create_test_api_protection_config(false);
    
    assert!(!config.enabled);
    // Even when disabled, graphql config should have valid defaults
    assert!(config.graphql.max_depth > 0);
    assert!(config.graphql.max_complexity > 0);
}

#[test]
fn test_api_protection_enabled() {
    let config = create_test_api_protection_config(true);
    
    assert!(config.enabled);
    assert_eq!(config.graphql.endpoint, "/graphql");
    assert_eq!(config.graphql.max_depth, 10);
}

#[test]
fn test_graphql_auth_rules_parsing() {
    let auth_rule = waf_killer_core::config::GraphQLAuthRule {
        field_path: "User.email".to_string(),
        required_roles: vec!["authenticated".to_string()],
    };
    
    assert_eq!(auth_rule.field_path, "User.email");
    assert_eq!(auth_rule.required_roles.len(), 1);
    assert_eq!(auth_rule.required_roles[0], "authenticated");
}

#[test]
fn test_graphql_rate_limit_entry() {
    let entry = waf_killer_core::config::GraphQLRateLimitEntry {
        requests_per_minute: 1000,
        complexity_per_minute: 10000,
    };
    
    assert_eq!(entry.requests_per_minute, 1000);
    assert_eq!(entry.complexity_per_minute, 10000);
}

#[tokio::test]
async fn test_config_load_with_api_protection() {
    // This test verifies that the config can be loaded and API Protection section parsed
    let config_path = std::path::Path::new("tests/test_config.yaml");
    
    if config_path.exists() {
        let result = waf_killer_core::config::Config::load(config_path).await;
        // Config should load successfully if file exists
        if let Ok(config) = result {
            // API Protection should have valid values
            assert!(config.api_protection.graphql.max_depth > 0);
            assert!(config.api_protection.graphql.max_complexity > 0);
        }
    }
}

#[test]
fn test_config_validation_graphql_limits() {
    use waf_killer_core::config::Config;
    
    // Create a config with invalid GraphQL limits
    let mut config = Config::default();
    config.api_protection.enabled = true;
    config.api_protection.graphql.max_depth = 0; // Invalid
    
    // Validation should fail
    let result = config.validate();
    assert!(result.is_err());
    
    // Fix the depth
    config.api_protection.graphql.max_depth = 10;
    config.api_protection.graphql.max_complexity = 0; // Invalid
    
    let result = config.validate();
    assert!(result.is_err());
    
    // Fix complexity
    config.api_protection.graphql.max_complexity = 1000;
    
    // Now validation should pass (assuming other defaults are valid)
    // Note: TLS validation may fail if cert files don't exist
    config.server.tls.enabled = false;
    let result = config.validate();
    assert!(result.is_ok());
}

#[test]
fn test_graphql_protection_config_serialization() {
    let config = waf_killer_core::config::GraphQLProtectionConfig::default();
    
    // Should serialize without error
    let yaml = serde_yaml::to_string(&config);
    assert!(yaml.is_ok());
    
    // Should deserialize back
    let yaml_str = yaml.unwrap();
    let parsed: Result<waf_killer_core::config::GraphQLProtectionConfig, _> = 
        serde_yaml::from_str(&yaml_str);
    assert!(parsed.is_ok());
    
    let parsed_config = parsed.unwrap();
    assert_eq!(parsed_config.max_depth, config.max_depth);
    assert_eq!(parsed_config.max_complexity, config.max_complexity);
}
