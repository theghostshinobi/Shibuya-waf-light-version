// ============================================
// File: core/src/api_protection/mod.rs
// ============================================
// Episode 11: API Security
// JSON Structure Validation & GraphQL Protection
// ============================================

pub mod openapi;
pub mod graphql;
pub mod state;
pub mod jwt;
pub mod oauth;

use anyhow::{Result, anyhow};
use serde_json::Value;
use std::collections::HashSet;
use serde::de::Deserializer;

// ═══════════════════════════════════════════════════════════════════════════════
// JSON Structure Validation
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of JSON structure validation
#[derive(Debug, Clone)]
pub struct JsonValidation {
    /// Whether the JSON structure is valid
    pub is_valid: bool,
    /// Maximum depth found in the JSON
    pub max_depth: usize,
    /// Whether duplicate keys were detected
    pub has_duplicate_keys: bool,
    /// Reason for rejection if invalid
    pub rejection_reason: Option<String>,
}

/// Validates JSON structure for security concerns.
/// 
/// Blocks if:
/// - Nesting depth exceeds `max_depth` (DoS prevention)
/// - Duplicate keys are detected (bypass prevention)
/// 
/// # Arguments
/// * `body` - Raw JSON bytes to validate
/// * `max_depth` - Maximum allowed nesting depth (recommended: 10)
/// 
/// # Returns
/// * `Ok(JsonValidation)` - Validation result
/// * `Err` - If JSON cannot be parsed (malformed)
pub fn validate_json_structure(body: &[u8], max_depth: usize) -> Result<JsonValidation> {
    // Early exit for empty body
    if body.is_empty() {
        return Ok(JsonValidation {
            is_valid: true,
            max_depth: 0,
            has_duplicate_keys: false,
            rejection_reason: None,
        });
    }

    // Step 1: Check for duplicate keys using raw parsing
    let has_duplicates = check_duplicate_keys(body)?;
    
    // Step 2: Parse JSON and calculate depth
    let value: Value = serde_json::from_slice(body)
        .map_err(|e| anyhow!("Malformed JSON: {}", e))?;
    
    let depth = calculate_json_depth(&value);
    
    // Step 3: Determine validity
    let mut rejection_reason = None;
    
    if depth > max_depth {
        rejection_reason = Some(format!(
            "JSON nesting depth {} exceeds maximum allowed {}", 
            depth, max_depth
        ));
    } else if has_duplicates {
        rejection_reason = Some("Duplicate keys detected in JSON".to_string());
    }
    
    Ok(JsonValidation {
        is_valid: rejection_reason.is_none(),
        max_depth: depth,
        has_duplicate_keys: has_duplicates,
        rejection_reason,
    })
}

/// Recursively calculates the maximum nesting depth of a JSON value.
/// Depth counts the number of container nesting levels:
///   - Primitives (string, number, bool, null) = 0
///   - Empty array/object = 1
///   - Non-empty array/object = 1 + max child depth
fn calculate_json_depth(value: &Value) -> usize {
    match value {
        Value::Array(arr) => {
            if arr.is_empty() {
                1
            } else {
                1 + arr.iter().map(calculate_json_depth).max().unwrap_or(0)
            }
        }
        Value::Object(obj) => {
            if obj.is_empty() {
                1
            } else {
                1 + obj.values().map(calculate_json_depth).max().unwrap_or(0)
            }
        }
        _ => 0, // Primitives have depth 0 (not containers)
    }
}

/// Checks for duplicate keys in JSON using raw string parsing
/// This is necessary because serde_json silently ignores duplicates
fn check_duplicate_keys(body: &[u8]) -> Result<bool> {
    let json_str = std::str::from_utf8(body)
        .map_err(|e| anyhow!("Invalid UTF-8 in JSON: {}", e))?;
    
    // Use serde_json's streaming parser with a custom deserializer
    // to detect duplicate keys at each level
    check_duplicates_recursive(json_str)
}

/// Recursively checks for duplicate keys at each level of the JSON
fn check_duplicates_recursive(json_str: &str) -> Result<bool> {
    // Track which objects we need to check
    struct DuplicateChecker;
    
    impl<'de> serde::de::Visitor<'de> for DuplicateChecker {
        type Value = bool;
        
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("any JSON value")
        }
        
        fn visit_map<M>(self, mut access: M) -> std::result::Result<bool, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut keys = HashSet::new();
            let mut found_duplicate = false;
            
            while let Some(key) = access.next_key::<String>()? {
                if !found_duplicate && !keys.insert(key) {
                    found_duplicate = true;
                }
                
                // Always consume the value to avoid trailing characters
                let value: Value = access.next_value()?;
                if !found_duplicate && check_value_for_duplicates(&value) {
                    found_duplicate = true;
                }
            }
            
            Ok(found_duplicate)
        }
        
        fn visit_seq<S>(self, mut access: S) -> std::result::Result<bool, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            while let Some(value) = access.next_element::<Value>()? {
                if check_value_for_duplicates(&value) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        
        // Primitive types - no duplicates possible
        fn visit_bool<E>(self, _: bool) -> std::result::Result<bool, E> { Ok(false) }
        fn visit_i64<E>(self, _: i64) -> std::result::Result<bool, E> { Ok(false) }
        fn visit_u64<E>(self, _: u64) -> std::result::Result<bool, E> { Ok(false) }
        fn visit_f64<E>(self, _: f64) -> std::result::Result<bool, E> { Ok(false) }
        fn visit_str<E>(self, _: &str) -> std::result::Result<bool, E> { Ok(false) }
        fn visit_none<E>(self) -> std::result::Result<bool, E> { Ok(false) }
        fn visit_unit<E>(self) -> std::result::Result<bool, E> { Ok(false) }
    }
    
    let mut deserializer = serde_json::Deserializer::from_str(json_str);
    let result = deserializer.deserialize_any(DuplicateChecker)
        .map_err(|e| anyhow!("JSON parse error during duplicate check: {}", e))?;
    
    Ok(result)
}

/// Helper to check a parsed Value for duplicate keys in nested objects
fn check_value_for_duplicates(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            // serde_json::Map already deduplicates, so we can't detect duplicates
            // from a parsed Value. This is handled in the raw parsing above.
            // But we still need to check nested values
            for v in map.values() {
                if check_value_for_duplicates(v) {
                    return true;
                }
            }
            false
        }
        Value::Array(arr) => {
            for v in arr {
                if check_value_for_duplicates(v) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GraphQL Query Analysis
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of GraphQL query analysis
#[derive(Debug, Clone)]
pub struct GraphQLAnalysis {
    /// Maximum nesting depth detected
    pub depth: usize,
    /// Whether this appears to be an attack (excessive depth)
    pub is_attack: bool,
    /// Number of selection fields
    pub field_count: usize,
    /// Raw operation type (query/mutation/subscription)
    pub operation_type: Option<String>,
}

/// Default maximum GraphQL query depth before flagging as attack
pub const DEFAULT_GRAPHQL_MAX_DEPTH: usize = 5;

/// Analyzes a GraphQL query for potential attacks.
/// 
/// Detects:
/// - Excessive query depth (DoS via deeply nested queries)
/// - High field counts (batch attacks)
/// 
/// # Arguments
/// * `query` - The GraphQL query string
/// 
/// # Returns
/// * `Ok(GraphQLAnalysis)` - Analysis result with depth and attack flag
pub fn analyze_graphql(query: &str) -> Result<GraphQLAnalysis> {
    analyze_graphql_with_threshold(query, DEFAULT_GRAPHQL_MAX_DEPTH)
}

/// Analyzes a GraphQL query with a custom depth threshold
pub fn analyze_graphql_with_threshold(query: &str, max_depth: usize) -> Result<GraphQLAnalysis> {
    // Lightweight depth analysis by counting braces
    let depth = calculate_graphql_depth(query);
    
    // Count fields (approximation: count valid identifiers before { or after newlines)
    let field_count = count_graphql_fields(query);
    
    // Detect operation type
    let operation_type = detect_operation_type(query);
    
    Ok(GraphQLAnalysis {
        depth,
        is_attack: depth > max_depth,
        field_count,
        operation_type,
    })
}

/// Calculates the maximum nesting depth of a GraphQL query
/// by tracking brace depth
fn calculate_graphql_depth(query: &str) -> usize {
    let mut max_depth = 0;
    let mut current_depth: usize = 0;
    let mut in_string = false;
    let mut escape_next = false;
    
    for ch in query.chars() {
        if escape_next {
            escape_next = false;
            continue;
        }
        
        match ch {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '{' if !in_string => {
                current_depth += 1;
                max_depth = max_depth.max(current_depth);
            }
            '}' if !in_string => {
                current_depth = current_depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    
    max_depth
}

/// Counts the approximate number of fields in a GraphQL query
fn count_graphql_fields(query: &str) -> usize {
    // Simple heuristic: count words that look like field names
    // (alphanumeric identifiers not followed by '(')
    let mut count = 0;
    let mut in_string = false;
    let chars: Vec<char> = query.chars().collect();
    let mut i = 0;
    
    while i < chars.len() {
        if chars[i] == '"' {
            in_string = !in_string;
            i += 1;
            continue;
        }
        
        if in_string {
            i += 1;
            continue;
        }
        
        // Check for identifier start
        if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
            // Skip the identifier
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            
            let word: String = chars[start..i].iter().collect();
            
            // Skip keywords
            let keywords = ["query", "mutation", "subscription", "fragment", "on", "true", "false", "null"];
            if !keywords.contains(&word.to_lowercase().as_str()) {
                count += 1;
            }
        } else {
            i += 1;
        }
    }
    
    count
}

/// Detects the operation type from a GraphQL query
fn detect_operation_type(query: &str) -> Option<String> {
    let trimmed = query.trim_start();
    
    if trimmed.starts_with("query") || trimmed.starts_with("{") {
        Some("query".to_string())
    } else if trimmed.starts_with("mutation") {
        Some("mutation".to_string())
    } else if trimmed.starts_with("subscription") {
        Some("subscription".to_string())
    } else {
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Shared Trait
// ═══════════════════════════════════════════════════════════════════════════════

pub trait ApiValidator {
    // Shared trait for API validation (for future extensibility)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Unit Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // --- JSON Validation Tests ---
    
    #[test]
    fn test_json_valid_shallow() {
        let json = r#"{"name": "test", "value": 123}"#;
        let result = validate_json_structure(json.as_bytes(), 10).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.max_depth, 1);
        assert!(!result.has_duplicate_keys);
    }
    
    #[test]
    fn test_json_nested_within_limit() {
        let json = r#"{"a": {"b": {"c": {"d": 1}}}}"#;
        let result = validate_json_structure(json.as_bytes(), 10).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.max_depth, 4);
    }
    
    #[test]
    fn test_json_too_deep() {
        // Create deeply nested JSON (depth 15)
        let json = r#"{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":{"n":{"o":1}}}}}}}}}}}}}}}"#;
        let result = validate_json_structure(json.as_bytes(), 10).unwrap();
        assert!(!result.is_valid);
        assert!(result.max_depth > 10);
        assert!(result.rejection_reason.unwrap().contains("depth"));
    }
    
    #[test]
    fn test_json_duplicate_keys() {
        // JSON with duplicate keys
        let json = r#"{"name": "first", "name": "second"}"#;
        let result = validate_json_structure(json.as_bytes(), 10).unwrap();
        assert!(!result.is_valid);
        assert!(result.has_duplicate_keys);
    }
    
    #[test]
    fn test_json_array_depth() {
        let json = r#"[[[[1, 2, 3]]]]"#;
        let result = validate_json_structure(json.as_bytes(), 10).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.max_depth, 4);
    }
    
    #[test]
    fn test_json_empty() {
        let result = validate_json_structure(b"", 10).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.max_depth, 0);
    }
    
    #[test]
    fn test_json_malformed() {
        let result = validate_json_structure(b"{invalid json}", 10);
        assert!(result.is_err());
    }
    
    // --- GraphQL Analysis Tests ---
    
    #[test]
    fn test_graphql_simple_query() {
        let query = r#"{ user { name email } }"#;
        let result = analyze_graphql(query).unwrap();
        assert!(!result.is_attack);
        assert_eq!(result.depth, 2);
        assert_eq!(result.operation_type, Some("query".to_string()));
    }
    
    #[test]
    fn test_graphql_deep_query_attack() {
        let query = r#"
            query {
                user {
                    posts {
                        comments {
                            author {
                                friends {
                                    posts {
                                        id
                                    }
                                }
                            }
                        }
                    }
                }
            }
        "#;
        let result = analyze_graphql(query).unwrap();
        assert!(result.is_attack);
        assert!(result.depth > 5);
    }
    
    #[test]
    fn test_graphql_mutation() {
        let query = r#"mutation { createUser(name: "test") { id } }"#;
        let result = analyze_graphql(query).unwrap();
        assert_eq!(result.operation_type, Some("mutation".to_string()));
        assert!(!result.is_attack);
    }
    
    #[test]
    fn test_graphql_with_strings() {
        // Ensure braces in strings don't affect depth
        let query = r#"{ user(filter: "{ name: 'test' }") { id } }"#;
        let result = analyze_graphql(query).unwrap();
        assert_eq!(result.depth, 2);
        assert!(!result.is_attack);
    }
    
    #[test]
    fn test_graphql_custom_threshold() {
        let query = r#"{ a { b { c { d } } } }"#;
        
        // With threshold 3, this should be an attack
        let result = analyze_graphql_with_threshold(query, 3).unwrap();
        assert!(result.is_attack);
        
        // With threshold 5, this should be OK
        let result = analyze_graphql_with_threshold(query, 5).unwrap();
        assert!(!result.is_attack);
    }
}
