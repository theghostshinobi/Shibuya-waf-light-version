use anyhow::{Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use crate::scanner::{ScanConfig, ScannerFinding, ScannerEvidence};
use chrono::Utc;

pub struct BurpSuiteClient {
    base_url: String,
    api_key: String,
    client: Client,
}

#[derive(Deserialize)]
pub struct BurpIssue {
    pub issue_type: String,
    pub name: String,
    pub severity: String,
    pub confidence: String,
    pub path: String,
    pub evidence: Vec<BurpEvidence>,
    pub remediation: String,
}

#[derive(Deserialize)]
pub struct BurpEvidence {
    pub request: String,
    pub response: String,
}

#[derive(Deserialize)]
struct SiteMapEntry {
    method: String,
    path: String,
    parameters: Vec<String>,
}

pub struct Endpoint {
    pub method: String,
    pub path: String,
    pub parameters: Vec<String>,
    pub discovered_at: chrono::DateTime<Utc>,
}

impl BurpSuiteClient {
    pub fn new(base_url: String, api_key: String) -> Self {
        Self {
            base_url,
            api_key,
            client: Client::new(),
        }
    }

    pub async fn get_findings(&self, scan_id: &str) -> Result<Vec<ScannerFinding>> {
        let url = format!("{}/v0.1/scan/{}/issues", self.base_url, scan_id);
        
        let response = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(anyhow!("Failed to fetch findings: {}", response.status()));
        }

        let issues: Vec<BurpIssue> = response.json().await?;
        
        let findings = issues.into_iter().enumerate().map(|(i, issue)| {
            let evidence = issue.evidence.first().map(|e| ScannerEvidence {
                request: Some(e.request.clone()),
                response: Some(e.response.clone()),
                other: None,
            });

            ScannerFinding {
                id: format!("BURP-{}-{}", scan_id, i),
                title: issue.name,
                severity: issue.severity,
                confidence: issue.confidence,
                scanner_type: "burp".to_string(),
                path: issue.path,
                method: None, // Burp issues often don't explicitly list method in top level, extracted from evidence usually
                evidence,
                description: Some(issue.issue_type), // Using issue type as description
                solution: Some(issue.remediation),
                cve_id: None,
                discovered_at: Utc::now(),
            }
        }).collect();

        Ok(findings)
    }
    
    pub async fn start_scan(
        &self,
        config: ScanConfig,
    ) -> Result<String> {
        let url = format!("{}/v0.1/scan", self.base_url);
        
        let response = self.client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(&serde_json::json!({
                "scope": {
                    "include": [{ "rule": config.target_url }]
                },
                "scan_configuration": {
                    // Map config to Burp specific structure if needed, simplified here
                },
            }))
            .send()
            .await?;
        
        if !response.status().is_success() {
             return Err(anyhow!("Failed to start scan: {}", response.status()));
        }

        let result: serde_json::Value = response.json().await?;
        let scan_id = result["scan_id"].as_str()
            .ok_or_else(|| anyhow!("No scan_id in response"))?;
        
        Ok(scan_id.to_string())
    }
    
    pub async fn export_site_map(&self) -> Result<Vec<Endpoint>> {
        // Get all discovered endpoints from Burp's site map
        let url = format!("{}/v0.1/sitemap", self.base_url);
        
        let response = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;
            
        if !response.status().is_success() {
             return Err(anyhow!("Failed to export site map: {}", response.status()));
        }
        
        let site_map: Vec<SiteMapEntry> = response.json().await?;
        
        // Convert to internal Endpoint format
        let endpoints = site_map.into_iter()
            .map(|entry| Endpoint {
                method: entry.method,
                path: entry.path,
                parameters: entry.parameters,
                discovered_at: Utc::now(),
            })
            .collect();
        
        Ok(endpoints)
    }
}
