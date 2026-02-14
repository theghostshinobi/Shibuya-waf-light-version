use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::fs;
use std::path::Path;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::time::Duration;
use tracing::{info, warn, error};

/// File path for vulnerability persistence
const VULNS_FILE_PATH: &str = "data/vulns.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum VulnStatus {
    OPEN,
    FIXED,
    FALSE_POSITIVE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub status: VulnStatus,
    pub cve_id: Option<String>,
    pub description: String,
    pub affected_path: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct VulnerabilityManager {
    vulns: Arc<RwLock<Vec<Vulnerability>>>,
}

impl VulnerabilityManager {
    /// Create a new VulnerabilityManager, loading existing vulns from disk if available
    pub fn new() -> Self {
        let vulns = Self::load_from_disk();
        info!("📋 VulnerabilityManager initialized with {} vulnerabilities from disk", vulns.len());
        
        Self {
            vulns: Arc::new(RwLock::new(vulns)),
        }
    }

    /// Load vulnerabilities from the JSON file
    fn load_from_disk() -> Vec<Vulnerability> {
        let path = Path::new(VULNS_FILE_PATH);
        
        // Ensure data directory exists
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                if let Err(e) = fs::create_dir_all(parent) {
                    warn!("Failed to create data directory: {}", e);
                }
            }
        }
        
        if !path.exists() {
            info!("No existing vulns.json found, starting fresh");
            return Vec::new();
        }
        
        match fs::read_to_string(path) {
            Ok(content) => {
                match serde_json::from_str::<Vec<Vulnerability>>(&content) {
                    Ok(vulns) => {
                        info!("✅ Loaded {} vulnerabilities from {}", vulns.len(), VULNS_FILE_PATH);
                        vulns
                    }
                    Err(e) => {
                        error!("Failed to parse vulns.json: {}. Starting fresh.", e);
                        Vec::new()
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read vulns.json: {}. Starting fresh.", e);
                Vec::new()
            }
        }
    }

    /// Save current vulnerabilities to disk
    fn save_to_disk(&self) {
        let vulns = self.vulns.read().unwrap();
        
        match serde_json::to_string_pretty(&*vulns) {
            Ok(json) => {
                // Ensure data directory exists
                let path = Path::new(VULNS_FILE_PATH);
                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        let _ = fs::create_dir_all(parent);
                    }
                }
                
                if let Err(e) = fs::write(VULNS_FILE_PATH, json) {
                    error!("Failed to write vulns.json: {}", e);
                } else {
                    info!("💾 Saved {} vulnerabilities to {}", vulns.len(), VULNS_FILE_PATH);
                }
            }
            Err(e) => {
                error!("Failed to serialize vulnerabilities: {}", e);
            }
        }
    }

    pub fn list(&self) -> Vec<Vulnerability> {
        self.vulns.read().unwrap().clone()
    }

    pub fn add(&self, mut vuln: Vulnerability) -> Vulnerability {
        if vuln.id.is_empty() {
             vuln.id = Uuid::new_v4().to_string();
        }
        self.vulns.write().unwrap().push(vuln.clone());
        self.save_to_disk(); // Persist after add
        vuln
    }

    /// Update the status of a vulnerability by ID
    pub fn update_status(&self, id: &str, new_status: VulnStatus) -> bool {
        let mut store = self.vulns.write().unwrap();
        if let Some(vuln) = store.iter_mut().find(|v| v.id == id) {
            vuln.status = new_status;
            drop(store); // Release lock before saving
            self.save_to_disk();
            true
        } else {
            false
        }
    }

    /// Get a single vulnerability by ID
    pub fn get(&self, id: &str) -> Option<Vulnerability> {
        self.vulns.read().unwrap().iter().find(|v| v.id == id).cloned()
    }

    pub fn import(&self, entries: Vec<Vulnerability>) -> usize {
        let mut store = self.vulns.write().unwrap();
        let mut count = 0;
        for mut v in entries {
            // Simple upsert by title + path for demo purposes (deduplication)
            let exists = store.iter().any(|existing| 
                existing.title == v.title && existing.affected_path == v.affected_path
            );
            if !exists {
                if v.id.is_empty() {
                    v.id = Uuid::new_v4().to_string();
                }
                if v.discovered_at == DateTime::<Utc>::MIN_UTC {
                    v.discovered_at = Utc::now();
                }
                store.push(v);
                count += 1;
            }
        }
        drop(store); // Release lock before saving
        if count > 0 {
            self.save_to_disk(); // Persist after import
        }
        count
    }

    /// Start an async vulnerability scan
    pub async fn start_scan(&self) {
        let manager = self.clone();
        tokio::spawn(async move {
            // Simulate scan duration
            tokio::time::sleep(Duration::from_secs(3)).await;

            let new_vulns = vec![
                Vulnerability {
                    id: Uuid::new_v4().to_string(),
                    title: "Exposed .env file".to_string(),
                    severity: Severity::CRITICAL,
                    status: VulnStatus::OPEN,
                    cve_id: None,
                    description: "Sensitive configuration file accessible via public URL.".to_string(),
                    affected_path: Some("/.env".to_string()),
                    discovered_at: Utc::now(),
                },
                Vulnerability {
                    id: Uuid::new_v4().to_string(),
                    title: "SQL Injection in Login".to_string(),
                    severity: Severity::HIGH,
                    status: VulnStatus::OPEN,
                    cve_id: Some("CVE-2024-XXXX".to_string()),
                    description: "Login parameter 'user' is vulnerable to SQLi.".to_string(),
                    affected_path: Some("/api/login".to_string()),
                    discovered_at: Utc::now(),
                },
                 Vulnerability {
                    id: Uuid::new_v4().to_string(),
                    title: "Missing CSP Header".to_string(),
                    severity: Severity::LOW,
                    status: VulnStatus::OPEN,
                    cve_id: None,
                    description: "Content-Security-Policy header is missing.".to_string(),
                    affected_path: Some("/".to_string()),
                    discovered_at: Utc::now(),
                }
            ];
            
            let imported = manager.import(new_vulns);
            info!("🔍 Scan complete: {} new vulnerabilities discovered", imported);
        });
    }
}

