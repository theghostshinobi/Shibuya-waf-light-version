// ============================================
// File: core/src/config/audit.rs
// ============================================
//! Audit logging system for configuration changes.
//! 
//! Tracks:
//! - Who made the change (User/IP)
//! - When (Timestamp)
//! - What changed (Diff)
//! - Backup reference

use serde::{Serialize, Deserialize};
use std::path::PathBuf;
use chrono::Utc;
use anyhow::Result;
use std::fs::OpenOptions;
use std::io::Write;
use tracing::info;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub timestamp: String,
    pub user: String,
    pub source_ip: String,
    pub changes: Vec<ConfigChange>,
    pub backup_path: Option<String>,
    pub validation_passed: bool,
    pub applied: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigChange {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
    pub reason: Option<String>,
}

pub struct AuditLogger {
    log_path: PathBuf,
}

impl AuditLogger {
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            log_path: path.into(),
        }
    }

    pub fn log(&self, entry: &AuditEntry) -> Result<()> {
        // Serialize to JSON Line
        let json = serde_json::to_string(entry)?;
        
        // Open file in append mode
        if let Some(parent) = self.log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
            
        writeln!(file, "{}", json)?;
        
        // Check rotation (Objective 4: Rotate after 10MB or 90 days - simplified to size for now)
        if let Ok(metadata) = std::fs::metadata(&self.log_path) {
            if metadata.len() > 10 * 1024 * 1024 { // 10MB
                self.rotate_log()?;
            }
        }
        
        Ok(())
    }

    fn rotate_log(&self) -> Result<()> {
        info!("Rotating audit log > 10MB");
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let new_name = format!("{}.{}", self.log_path.display(), timestamp);
        std::fs::rename(&self.log_path, &new_name)?;
        Ok(())
    }
}
