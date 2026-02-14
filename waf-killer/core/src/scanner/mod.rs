use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use chrono::{DateTime, Utc};

pub mod burp;
pub mod zap;
pub mod nuclei;
pub mod sarif;
pub mod discovery;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerFinding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub scanner_type: String,
    pub path: String,
    pub method: Option<String>,
    pub evidence: Option<ScannerEvidence>,
    pub description: Option<String>,
    pub solution: Option<String>,
    pub cve_id: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerEvidence {
    pub request: Option<String>,
    pub response: Option<String>,
    pub other: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target_url: String,
    pub max_depth: Option<i32>,
    pub concurrent_requests: Option<i32>,
    pub excluded_paths: Vec<String>,
}

#[async_trait]
pub trait Scanner: Send + Sync {
    async fn start_scan(&self, config: ScanConfig) -> Result<String>; // Returns scan_id
    async fn get_status(&self, scan_id: &str) -> Result<String>;
    async fn get_findings(&self, scan_id: &str) -> Result<Vec<ScannerFinding>>;
    async fn stop_scan(&self, scan_id: &str) -> Result<()>;
}
