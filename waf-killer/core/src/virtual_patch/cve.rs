use anyhow::{Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use crate::scanner::ScannerFinding;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CVEInfo {
    pub cve_id: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: f32,
    pub published_date: Option<DateTime<Utc>>,
    pub references: Vec<String>,
    pub vulnerable_products: Vec<VulnerableProduct>,
    pub attack_patterns: Vec<AttackPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnerableProduct {
    pub vendor: String,
    pub product: String,
    pub version_start: Option<String>,
    pub version_end: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub pattern_type: String,  // "regex", "signature", "behavior"
    pub pattern: String,
    pub confidence: f32,
}

pub struct CVEDatabase {
    client: Client,
    cache: Arc<RwLock<HashMap<String, CVEInfo>>>,
}

impl CVEDatabase {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn fetch_cve(&self, cve_id: &str) -> Result<CVEInfo> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(info) = cache.get(cve_id) {
                return Ok(info.clone());
            }
        }
        
        // Fetch from NVD API (e.g. cve.circl.lu is a convenient free mirror)
        let url = format!("https://cve.circl.lu/api/cve/{}", cve_id);
        
        // This is a free public API, rate limits might apply.
        let response = self.client.get(&url).send().await?;
        
        if !response.status().is_success() {
             return Err(anyhow!("Failed to fetch CVE info: {}", response.status()));
        }

        let cve_data: serde_json::Value = response.json().await?;
        
        // Check if CVE exists
        if cve_data.get("id").is_none() {
            return Err(anyhow!("CVE not found"));
        }

        // Parse CVE data
        let cve_info = self.parse_cve_data(&cve_data)?;
        
        // Cache it
        {
            let mut cache = self.cache.write().await;
            cache.insert(cve_id.to_string(), cve_info.clone());
        }
        
        Ok(cve_info)
    }
    
    pub async fn search_cves(&self, product: &str, version: &str) -> Result<Vec<CVEInfo>> {
        // Search for CVEs affecting specific product/version
        // Using cve.circl.lu/api/search/product/version which is supported
        let url = format!(
            "https://cve.circl.lu/api/search/{}/{}",
            urlencoding::encode(product),
            urlencoding::encode(version)
        );
        
        let response = self.client.get(&url).send().await?;
         if !response.status().is_success() {
             return Err(anyhow!("Failed to search CVEs: {}", response.status()));
        }
        
        let results: Vec<serde_json::Value> = response.json().await?;
        
        let mut infos = Vec::new();
        for data in results {
            if let Ok(info) = self.parse_cve_data(&data) {
                infos.push(info);
            }
        }
        Ok(infos)
    }
    
    fn parse_cve_data(&self, data: &serde_json::Value) -> Result<CVEInfo> {
        // Extract attack patterns from CVE description and references
        let description = data["summary"].as_str().unwrap_or("").to_string();
        let attack_patterns = self.extract_attack_patterns(&description);
        
        let severity = data["cvss"].as_str().unwrap_or("UNKNOWN").to_string();
        let cvss_score = data["cvss"].as_f64().unwrap_or(0.0) as f32; // This API sometimes returns string, sometimes number depending on version, handling loosely
        
        // Actually cve.circl.lu returns "cvss" as number usually if it exists.
        // Let's be safer.
        let cvss_score = if let Some(score) = data["cvss"].as_f64() {
             score as f32
        } else if let Some(score_str) = data["cvss"].as_str() {
             score_str.parse::<f32>().unwrap_or(0.0)
        } else {
             0.0
        };


        Ok(CVEInfo {
            cve_id: data["id"].as_str().unwrap_or("").to_string(),
            description: description.clone(),
            severity,
            cvss_score,
            published_date: Some(Utc::now()),  // TODO: parse "Published" if available
            references: vec![], // TODO: parse references
            vulnerable_products: vec![], // TODO: parse vulnerable_configuration
            attack_patterns,
        })
    }
    
    fn extract_attack_patterns(&self, description: &str) -> Vec<AttackPattern> {
        let mut patterns = Vec::new();
        let desc_lower = description.to_lowercase();
        
        // Look for common attack indicators in description
        if desc_lower.contains("sql injection") || desc_lower.contains("sqli") {
            patterns.push(AttackPattern {
                pattern_type: "signature".to_string(),
                pattern: r"(?i)(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)".to_string(),
                confidence: 0.8,
            });
        }
        
        if desc_lower.contains("xss") || desc_lower.contains("cross-site scripting") {
            patterns.push(AttackPattern {
                pattern_type: "signature".to_string(),
                pattern: r"(?i)(<script|javascript:|onerror=|onload=)".to_string(),
                confidence: 0.8,
            });
        }
        
        if desc_lower.contains("path traversal") || desc_lower.contains("directory traversal") {
            patterns.push(AttackPattern {
                pattern_type: "signature".to_string(),
                pattern: r"(\.\./|\.\.\\)".to_string(),
                confidence: 0.9,
            });
        }
        
        if desc_lower.contains("command injection") {
            patterns.push(AttackPattern {
                pattern_type: "signature".to_string(),
                pattern: r"(;|\||`|\$\(|\${)".to_string(),
                confidence: 0.7,
            });
        }
        
        patterns
    }
}
