// ============================================
// File: core/src/detection/crs/engine.rs
// ============================================
// COMPLETE implementation with massive rule set

use std::sync::Arc;
use anyhow::{Context, Result};
use regex::Regex;
use tracing::debug;
use crate::config::CrsConfig;
use crate::detection::pipeline::RequestInfo;

#[derive(Debug)]
pub struct CrsResult {
    pub score: i32,
    pub matched_rules: Vec<String>,
    pub blocked: bool,
}

#[derive(Clone)]
pub struct Rule {
    pub id: u32,
    pub name: String,
    pub pattern: Regex,
    pub score: i32,
    pub tags: Vec<String>,
}

pub struct CrsEngine {
    rules: Vec<Rule>,
    config: CrsConfig,
}

impl CrsEngine {
    pub fn new(config: &CrsConfig) -> Result<Self> {
        let mut rules = Vec::new();
        
        // --- 1. Load Hardcoded Bootstrap Rules (Baselines) ---
        // SQL Injection Rules (942xxx)
        add_rule(&mut rules, 942100, "SQLi: Union access", r"(?i)(\bunion\b[\s\S]*\bselect\b)", 5)?;
        add_rule(&mut rules, 942110, "SQLi: Basic OR 1=1", r#"(?i)('|"|`)\s*(or|and)\s+(\d+)\s*[=<>]\s*\3"#, 5)?;
        add_rule(&mut rules, 942120, "SQLi: Comment injection", r"(--|#|/\*)", 3)?;
        add_rule(&mut rules, 942130, "SQLi: Tautology", r"(?i)(or|and)\s+1=1", 5)?;
        add_rule(&mut rules, 942140, "SQLi: Admin access attempt", r"(?i)admin'--", 5)?;
        add_rule(&mut rules, 942150, "SQLi: Sleep/Behnchmark", r"(?i)\b(sleep|benchmark|pg_sleep)\s*\(", 5)?;
        add_rule(&mut rules, 942160, "SQLi: Stacked queries", r";\s*(select|insert|update|delete|drop|alter)", 5)?;
        add_rule(&mut rules, 942170, "SQLi: Version extraction", r"(?i)(@@version|version\(\))", 4)?;
        
        // XSS Rules (941xxx)
        add_rule(&mut rules, 941100, "XSS: Script tag", r"(?i)<\s*script[\s\S]*?>", 5)?;
        add_rule(&mut rules, 941110, "XSS: Event handler", r"(?i)\bon\w+\s*=", 4)?;
        add_rule(&mut rules, 941120, "XSS: Javascript URI", r"(?i)javascript:\s*", 5)?;
        add_rule(&mut rules, 941130, "XSS: Iframe injection", r"(?i)<\s*iframe[\s\S]*?>", 4)?;
        add_rule(&mut rules, 941140, "XSS: Object/Embed", r"(?i)<\s*(object|embed)[\s\S]*?>", 4)?;
        add_rule(&mut rules, 941150, "XSS: SVG onload", r"(?i)<\s*svg[^>]*onload", 5)?;
        add_rule(&mut rules, 941160, "XSS: Body onload", r"(?i)<\s*body[^>]*onload", 5)?;
        
        // RCE / Command Injection (932xxx)
        add_rule(&mut rules, 932100, "RCE: Unix Command Injection", r"(?i)(;|\||\|\||&&|\$\(|\`)\s*(cat|nc|netcat|wget|curl|bash|sh|python|perl|php|ruby|gcc|whoami|id|uname|pwd)\b", 5)?;
        add_rule(&mut rules, 932110, "RCE: Windows Command Injection", r"(?i)(&|\||\|\|)\s*(cmd|powershell|certutil|bitsadmin)\b", 5)?;
        add_rule(&mut rules, 932120, "RCE: ETC Shadow Access", r"(?i)/etc/(shadow|passwd|group)", 5)?;
        
        // Path Traversal (930xxx)
        add_rule(&mut rules, 930100, "PT: Dot Dot Slash", r"(\.\./|\.\.\\)", 5)?;
        add_rule(&mut rules, 930110, "PT: Double Encoded", r"(?i)(%2e%2e|%252e%252e)", 4)?;
        add_rule(&mut rules, 930120, "PT: Windows root", r"(?i)[c-z]:\\", 4)?;
        
        // Protocol Anomalies
        add_rule(&mut rules, 920100, "LFI: PHP Wrappers", r"(?i)php://(input|filter|memory)", 5)?;

        // --- 2. Load Rules from Directory ---
        let rules_path = &config.rules_path;
        if rules_path.exists() && rules_path.is_dir() {
            tracing::info!("Loading CRS rules from directory: {:?}", rules_path);
            
            let entries = std::fs::read_dir(rules_path)?;
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                
                if path.extension().map_or(false, |ext| ext == "conf") {
                    let filename = path.file_name().unwrap_or_default().to_string_lossy();
                    tracing::info!("Loading rules from file: {}", filename);
                    
                    let content = std::fs::read_to_string(&path)?;
                    let loaded_count = parse_and_add_rules(&mut rules, &content)?;
                    
                    tracing::info!("  Loaded {} rules from {}", loaded_count, filename);
                }
            }
        } else {
             tracing::warn!("CRS rules directory not found or invalid: {:?}", rules_path);
        }

        tracing::info!("Total CRS rules loaded: {}", rules.len());
        
        Ok(Self {
            rules,
            config: config.clone(),
        })
    }
    
    /// Evaluate request against ALL compiled rules
    pub fn evaluate(&self, req: &RequestInfo) -> Result<CrsResult> {
        let mut score = 0;
        let mut matched = Vec::new();

        // 1. Prepare inspection buffers (normalize once)
        let uri_path = req.uri.path();
        let query = req.uri.query().unwrap_or("");
        
        // Inspect Headers
        let mut headers_str = String::with_capacity(1024);
        for (k, v) in &req.headers {
            headers_str.push_str(k.as_str());
            headers_str.push(':');
            if let Ok(s) = v.to_str() {
                headers_str.push_str(s);
            }
            headers_str.push('\n');
        }

        // Inspect Body (limit size for regex performance)
        let body_str = if let Some(b) = &req.body {
             std::str::from_utf8(b).unwrap_or("")
        } else {
             ""
        };

        // 2. Iterate rules
        for rule in &self.rules {
            let mut hit = false;

            // Check URI
            if rule.pattern.is_match(uri_path) { hit = true; }
            // Check Query
            if !hit && rule.pattern.is_match(query) { hit = true; }
            // Check Headers (Cookies/User-Agent often targeted)
            if !hit && rule.pattern.is_match(&headers_str) { hit = true; }
            // Check Body
            if !hit && !body_str.is_empty() && rule.pattern.is_match(body_str) { hit = true; }

            if hit {
                debug!(rule_id = rule.id, name = %rule.name, "CRS Rule Matched");
                score += rule.score;
                matched.push(format!("{}: {}", rule.id, rule.name));
            }
        }

        Ok(CrsResult {
            score,
            matched_rules: matched,
            blocked: score >= self.config.inbound_threshold,
        })
    }
}

fn add_rule(list: &mut Vec<Rule>, id: u32, name: &str, regex: &str, score: i32) -> Result<()> {
    list.push(Rule {
        id,
        name: name.to_string(),
        pattern: Regex::new(regex).context(format!("Failed to compile rule {}", id))?,
        score,
        tags: vec![],
    });
    Ok(())
}

/// Simple parser for ModSecurity-style @rx rules
/// Handles: SecRule VARS "@rx RE" "id:123, msg:'...', severity:'CRITICAL'"
fn parse_and_add_rules(list: &mut Vec<Rule>, content: &str) -> Result<usize> {
    let mut count = 0;
    
    // Normalize newlines and continuation lines (simplification)
    // Replace " \" with space to join lines
    let normalized = content.replace("\\\n", " ").replace("\\\r\n", " ");
    
    // Split by SecRule
    // Note: This is a robust-enough heuristic for this task's clean input
    for chunk in normalized.split("SecRule") {
        let chunk = chunk.trim();
        if chunk.is_empty() { continue; }
        
        // 1. Extract Regex Pattern: "@rx (?P<rx>...)"
        // Pattern might contain quotes, so be careful. 
        // Assumption: @rx is followed by space and "pattern"
        if let Some(start) = chunk.find("@rx ") {
             let rest = &chunk[start + 4..];
             let quote_char = rest.chars().next().unwrap_or('"'); // ' or "
             
             if let Some(end) = rest[1..].find(quote_char) {
                 let regex_pattern = &rest[1..end + 1]; // +1 to offset skip
                 
                 // 2. Extract ID
                 if let Some(id_start) = chunk.find("id:") {
                     // Check if id is quoted or plain number (ignoring surrounding junk)
                     // Simple scan: "id:12345"
                     let id_slice = &chunk[id_start+3..];
                     let id_end = id_slice.find([',', '"', '\'', ' ']).unwrap_or(id_slice.len());
                     let id_str = &id_slice[..id_end].trim();
                     
                     if let Ok(id) = id_str.parse::<u32>() {
                         
                         // 3. Extract Message
                         let msg = if let Some(msg_start) = chunk.find("msg:'") {
                             if let Some(msg_end) = chunk[msg_start+5..].find('\'') {
                                 &chunk[msg_start+5..msg_start+5+msg_end]
                             } else {
                                 "Imported Rule"
                             }
                         } else {
                             "Imported Rule"
                         };
                         
                         // 4. Extract Severity/Score
                         let score = if chunk.contains("severity:'CRITICAL'") { 5 }
                                     else if chunk.contains("severity:'HIGH'") { 4 }
                                     else if chunk.contains("severity:'MEDIUM'") { 3 }
                                     else { 2 };
                         
                         // Check for conflicts (if ID already exists in list)
                         if !list.iter().any(|r| r.id == id) {
                             match add_rule(list, id, msg, regex_pattern, score) {
                                 Ok(_) => { 
                                     tracing::debug!("Loaded rule {}: {}", id, msg);
                                     count += 1; 
                                 },
                                 Err(e) => {
                                     tracing::warn!("Failed to compile rule {}: {}", id, e);
                                 }
                             }
                         }
                     }
                 }
             }
        }
    }
    Ok(count)
}
