use super::actions::Action;
use super::parser::{parse_rule, Rule};
use anyhow::Result;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn load_from_dir(path: &Path) -> Result<Self> {
        let mut rules = Vec::new();

        // 1. Load crs-setup.conf if exists
        let setup_path = path.join("crs-setup.conf");
        if setup_path.exists() {
            tracing::info!("Loading CRS setup: {:?}", setup_path);
            if let Ok(_content) = fs::read_to_string(&setup_path) {
                 // For MVP: Skip setup complicated logic
            }
        }

        // 2. Walk directory for .conf files
        let mut files = Vec::new();
        for entry in WalkDir::new(path).sort_by_file_name() {
             let entry = entry?;
             let path = entry.path();
             if path.extension().map_or(false, |ext| ext == "conf") {
                 if path.file_name().unwrap() != "crs-setup.conf" {
                     files.push(path.to_owned());
                 }
             }
        }

        for file_path in files {
            tracing::info!("Loading rules from: {:?}", file_path);
            let content = fs::read_to_string(&file_path)?;
            let parsed = parse_file_content(&content);
            tracing::info!("  -> Loaded {} rules", parsed.len());
            for rule in &parsed {
                let msg = rule.actions.iter().find_map(|a| match a {
                    Action::Msg(m) => Some(m.as_str()),
                    _ => None
                }).unwrap_or("No description");
                tracing::debug!("    Rule ID {}: {}", rule.id, msg);
            }
            // Filter out rules with ID 0 (invalid/unparsed ID)
            let initial_count = parsed.len();
            let valid_rules: Vec<Rule> = parsed.into_iter().filter(|r| r.id != 0).collect();
            tracing::info!("  -> Kept {} valid rules (dropped {} with ID 0)", valid_rules.len(), initial_count - valid_rules.len());
            rules.extend(valid_rules);
        }

        tracing::info!("Loaded {} rules total", rules.len());
        Ok(RuleSet { rules })
    }
}

// Helper to handle multiline rules and comments
fn parse_file_content(content: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut current_rule = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#") || trimmed.is_empty() {
             // If we have a pending rule that ended with \, continue?
             // No, usually \ is at end of line.
             // If trimmed is comment, ignore.
             continue;
        }

        if trimmed.ends_with('\\') {
            // Continuation
            current_rule.push_str(&trimmed[..trimmed.len() - 1]);
            current_rule.push(' ');
        } else {
            // End of line, or single line
            if !current_rule.is_empty() {
                // We had a continuation
                current_rule.push_str(trimmed);
                // Parse
                if let Ok(rule) = parse_rule(&current_rule) {
                    rules.push(rule);
                } else {
                    tracing::warn!("Failed to parse rule: {}", current_rule.lines().next().unwrap_or(""));
                    if let Err(e) = parse_rule(&current_rule) {
                        tracing::warn!("  Error: {}", e);
                    }
                }
                current_rule.clear();
            } else {
                // Fresh line
                if let Ok(rule) = parse_rule(trimmed) {
                    rules.push(rule);
                } else {
                    // Start of a rule? Or SecAction? 
                    // If it starts with SecRule, keep accumulating?
                    // No, invalid parse means likely complicated syntax or unsupported directive.
                    // For MVP, simple SecRule parsing support.
                    if trimmed.starts_with("SecRule") {
                         // Maybe it was multi-line but didn't end with \ on this line?
                         // Should just fail.
                    }
                }
            }
        }
    }
    
    // Check lingering
    if !current_rule.is_empty() {
         if let Ok(rule) = parse_rule(&current_rule) {
             rules.push(rule);
         }
    }

    rules
}
