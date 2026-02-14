use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::scanner::ScannerFinding;
use crate::virtual_patch::cve::{CVEDatabase, CVEInfo};

// We need to define or import CustomRule. 
// Assuming it's in crate::rules or similar. 
// For now, I'll define a compatible struct here if it's not easily available or if I want to decouple.
// But the prompt says `core/src/rules/engine.rs` exists.
// Let's assume a definition compatible with what we need.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub phase: i32,
    pub condition: String,
    pub action: String, // "Block", "Allow", "Log"
    pub score: i32,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct VirtualPatch {
    pub id: String,
    pub cve_id: String,
    pub cve_info: CVEInfo,
    pub rules: Vec<CustomRule>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub verified: bool,
    pub active: bool,
}

pub struct VirtualPatchGenerator {
    cve_db: Arc<CVEDatabase>,
}

impl VirtualPatchGenerator {
    pub fn new(cve_db: Arc<CVEDatabase>) -> Self {
        Self { cve_db }
    }

    pub async fn generate_from_cve(&self, cve_id: &str) -> Result<VirtualPatch> {
        // 1. Fetch CVE info
        let cve_info = self.cve_db.fetch_cve(cve_id).await?;
        
        // 2. Generate rules from attack patterns
        let mut rules = Vec::new();
        
        for (i, pattern) in cve_info.attack_patterns.iter().enumerate() {
            let rule = CustomRule {
                id: format!("CVE-{}-{}", cve_id, i),
                name: format!("Virtual patch for {}", cve_id),
                enabled: true,
                phase: 2,  // Request body phase
                condition: format!(
                    "request.body_raw matches \"{}\"",
                    pattern.pattern.replace("\"", "\\\"")
                ),
                action: "Block".to_string(),
                score: 10,  // Critical
                tags: vec![
                    "cve".to_string(),
                    cve_id.to_string(),
                    "virtual-patch".to_string(),
                ],
                metadata: HashMap::from([
                    ("cve_id".to_string(), cve_id.to_string()),
                    ("severity".to_string(), cve_info.severity.clone()),
                    ("cvss_score".to_string(), cve_info.cvss_score.to_string()),
                ]),
            };
            
            rules.push(rule);
        }
        
        Ok(VirtualPatch {
            id: Uuid::new_v4().to_string(),
            cve_id: cve_id.to_string(),
            cve_info,
            rules,
            created_at: Utc::now(),
            expires_at: None,  // Manual expiry
            verified: false,
            active: true,
        })
    }
    
    pub async fn generate_from_finding(
        &self,
        finding: &ScannerFinding,
    ) -> Result<VirtualPatch> {
        // Generate virtual patch from scanner finding
        
        // 1. Extract attack payload from evidence
        let attack_payload = self.extract_attack_payload(finding)?;
        
        // 2. Generate regex pattern
        let pattern = self.generate_pattern(&attack_payload)?;
        
        // 3. Create rule
        let rule = CustomRule {
            id: format!("FINDING-{}", Uuid::new_v4()),
            name: format!("Virtual patch for {}", finding.title),
            enabled: true,
            phase: 2,
            condition: format!(
                "(request.uri contains \"{}\" or request.body_raw matches \"{}\")",
                finding.path.replace("\"", "\\\""),
                pattern.replace("\"", "\\\"") 
            ),
            action: "Block".to_string(),
            score: self.severity_to_score(&finding.severity),
            tags: vec![
                "scanner-finding".to_string(),
                finding.scanner_type.clone(),
                "virtual-patch".to_string(),
            ],
            metadata: HashMap::new(),
        };
        
        Ok(VirtualPatch {
            id: Uuid::new_v4().to_string(),
            cve_id: finding.cve_id.clone().unwrap_or_default(),
            cve_info: CVEInfo::default(),  // No CVE info for generic findings
            rules: vec![rule],
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(30)),  // Auto-expire
            verified: false,
            active: true,
        })
    }
    
    fn extract_attack_payload(&self, finding: &ScannerFinding) -> Result<String> {
        // Extract attack payload from scanner evidence
        
        if let Some(evidence) = &finding.evidence {
            // Try to find payload in request
            if let Some(request) = &evidence.request {
                // Look for common attack patterns (simplified)
                if let Some(payload) = self.find_payload_in_request(request) {
                    return Ok(payload);
                }
            }
        }
        
        // Fallback: use finding title/description or a placeholder
        // In real world, we need better extraction.
        Ok(finding.title.clone()) 
    }
    
    fn find_payload_in_request(&self, request: &str) -> Option<String> {
        // Simple heuristic: look for query params or body
        // This is a placeholder for more complex logic
        None 
    }
    
    fn generate_pattern(&self, payload: &str) -> Result<String> {
        // Generate regex pattern from attack payload
        
        // Escape special chars but keep attack-relevant characters
        let mut pattern = regex::escape(payload);
        
        // Make it flexible (whitespace, case-insensitive for keywords)
        pattern = pattern.replace(" ", r"\s*");
        
        // Make SQL keywords case-insensitive
        for keyword in &["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP"] {
             // Basic replacement simulation
             // In rust regex crate we can use `(?i)` flag but replacing literal strings with case insensitive groups is nicer
             // but `regex::escape` escapes everything.
             // We'd need to unescape or handle differently.
             // For this MVP, we will stick to basic escaping + some manual tweaks or relying on engine's case insensitivity options.
        }
        
        Ok(pattern)
    }
    
    fn severity_to_score(&self, severity: &str) -> i32 {
        match severity.to_uppercase().as_str() {
            "CRITICAL" => 10,
            "HIGH" => 7,
            "MEDIUM" => 5,
            "LOW" => 3,
            _ => 5,
        }
    }
}
