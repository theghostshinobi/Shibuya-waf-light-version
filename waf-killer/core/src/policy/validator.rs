use super::models::Policy;
use anyhow::{Result, Context};
use jsonschema::{Draft, JSONSchema};
use std::net::IpAddr;
use std::str::FromStr;

pub fn validate_against_schema(policy: &Policy) -> Result<()> {
    // Determine the absolute path to the schema file
    // In a real build, we might include_str! the schema or load it from a known location.
    // For now, let's assume we can include it or read it.
    // Since `include_str!` requires a literal path at compile time, and the schema is in `schemas/`,
    // we use a relative path from this file.
    // core/src/policy/validator.rs -> ../../../schemas/policy.schema.json
    
    // WARNING: include_str! path is relative to the current file.
    let schema_str = include_str!("../../../schemas/policy.schema.json");
    
    let schema_json: serde_json::Value = serde_json::from_str(schema_str)
        .context("Failed to parse policy schema definitions")?;

    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(&schema_json)
        .map_err(|e| anyhow::anyhow!("Failed to compile JSON schema: {}", e))?;

    let policy_json = serde_json::to_value(policy)
        .context("Failed to serialize policy to JSON for validation")?;

    if let Err(errors) = compiled.validate(&policy_json) {
        let error_messages: Vec<String> = errors
            .map(|e| format!("Path: {} - Error: {}", e.instance_path, e))
            .collect();
            
        return Err(anyhow::anyhow!(
            "Policy schema validation failed:\n{}",
            error_messages.join("\n")
        ));
    }

    Ok(())
}

pub fn validate_semantic(policy: &Policy) -> Result<()> {
    let mut errors = Vec::new();

    // 1. Check for route conflicts (naive check for duplicates)
    let mut paths = std::collections::HashSet::new();
    for route in &policy.routes {
        if !paths.insert(&route.path) {
            errors.push(format!("Duplicate route path found: {}", route.path));
        }
    }

    // 2. Check IP validity
    for ip in &policy.ip_lists.whitelist {
        if !is_valid_cidr_or_ip(ip) {
            errors.push(format!("Invalid IP/CIDR in whitelist: {}", ip));
        }
    }
    for ip in &policy.ip_lists.blacklist {
        if !is_valid_cidr_or_ip(ip) {
            errors.push(format!("Invalid IP/CIDR in blacklist: {}", ip));
        }
    }

    // 3. Check custom rule IDs uniqueness
    let mut rule_ids = std::collections::HashSet::new();
    for rule in &policy.custom_rules {
        if !rule_ids.insert(&rule.id) {
            errors.push(format!("Duplicate custom rule ID: {}", rule.id));
        }
        
        // Also validate per-route rules
    }
    
    for route in &policy.routes {
         for rule in &route.policy.custom_rules {
             // Route specific rules might share IDs with global rules? Usually bad practice.
             if rule_ids.contains(&rule.id) {
                  // Warn or error? Let's error for safety to prevent confusion.
                  errors.push(format!("Rule ID {} in route {} conflicts with global or other rule", rule.id, route.path));
             }
             if !rule_ids.insert(&rule.id) {
                  errors.push(format!("Duplicate custom rule ID {} in route {}", rule.id, route.path));
             }
         }
    }

    if !errors.is_empty() {
        return Err(anyhow::anyhow!(
            "Policy semantic validation failed:\n{}",
            errors.join("\n")
        ));
    }

    Ok(())
}

fn is_valid_cidr_or_ip(s: &str) -> bool {
    // Check if it's a plain IP
    if IpAddr::from_str(s).is_ok() {
        return true;
    }
    // Check if it's a CIDR (basic check)
    if let Some((ip, mask)) = s.split_once('/') {
        if IpAddr::from_str(ip).is_ok() {
             if let Ok(m) = mask.parse::<u8>() {
                 return m <= 128; // Covers IPv6 too
             }
        }
    }
    false
}
