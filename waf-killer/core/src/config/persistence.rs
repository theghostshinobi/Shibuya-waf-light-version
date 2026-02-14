// ============================================
// File: core/src/config/persistence.rs
// ============================================
//! Persistence layer for WAF configuration.
//! 
//! # Features
//! - Atomic Writes: Never corrupts config on crash
//! - Backups: Auto-backup before write
//! - Rotation: Keep last N backups
//! - Audit: Logs changes via AuditLogger

use super::Config;
use super::audit::{AuditLogger, AuditEntry, ConfigChange};
use super::validation::ValidationEngine;
use anyhow::{Result, Context, anyhow};
use std::path::{Path, PathBuf};
use std::fs;
use chrono::Utc;
use tracing::{info, warn, error};
use tempfile::NamedTempFile;
use std::io::Write;

pub struct ConfigPersister {
    config_path: PathBuf,
    backup_dir: PathBuf,
    audit_logger: AuditLogger,
    max_backups: usize,
}

impl ConfigPersister {
    pub fn new<P: Into<PathBuf>>(config_path: P) -> Self {
        let path = config_path.into();
        let parent = path.parent().unwrap_or(Path::new("."));
        let backup_dir = parent.join("backups");
        let audit_path = parent.join("config_changes.jsonl");

        Self {
            config_path: path,
            backup_dir,
            audit_logger: AuditLogger::new(audit_path),
            max_backups: 10,
        }
    }

    /// Save configuration safely with validation, backup, and audit logging
    pub fn save(
        &self, 
        new_config: &Config, 
        current_config: &Config,
        user: &str,
        source_ip: &str,
        _change_reason: Option<String>
    ) -> Result<()> {
        // 1. Validate
        ValidationEngine::validate_update(current_config, new_config)
            .context("Validation failed")?;

        // 2. Diff for audit
        let changes = self.diff(current_config, new_config);
        if changes.is_empty() {
            info!("No configuration changes detected so skipping save.");
            return Ok(());
        }

        // 3. Backup existing
        let backup_path = self.backup_current()?;

        // 4. Atomic Write
        self.atomic_write(new_config)?;

        // 5. Audit Log (non-blocking failure)
        let audit_entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            user: user.to_string(),
            source_ip: source_ip.to_string(),
            changes,
            backup_path: backup_path.map(|p| p.to_string_lossy().to_string()),
            validation_passed: true,
            applied: true,
        };
        
        if let Err(e) = self.audit_logger.log(&audit_entry) {
            error!("Failed to write audit log: {}", e);
            // We don't fail the request if audit fails, but we scream in logs
        }

        Ok(())
    }

    fn atomic_write(&self, config: &Config) -> Result<()> {
        let parent = self.config_path.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;

        // Create temp file in same directory (important for atomic rename)
        let mut temp_file = NamedTempFile::new_in(parent)?;
        
        let yaml = serde_yaml::to_string(config)?;
        temp_file.write_all(yaml.as_bytes())?;
        
        // Fsync to ensure disk flush
        temp_file.as_file().sync_all()?;
        
        // Atomic rename
        temp_file.persist(&self.config_path).map_err(|e| e.error)?;
        
        info!("Configuration persisted to {:?}", self.config_path);
        Ok(())
    }

    fn backup_current(&self) -> Result<Option<PathBuf>> {
        if !self.config_path.exists() {
            return Ok(None);
        }

        fs::create_dir_all(&self.backup_dir)?;
        
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S_%3f").to_string();
        let filename = self.config_path.file_name()
            .ok_or_else(|| anyhow!("Invalid config path"))?
            .to_string_lossy();
            
        let backup_name = format!("{}.{}.bak", filename, timestamp);
        let backup_path = self.backup_dir.join(backup_name);

        fs::copy(&self.config_path, &backup_path)?;
        info!("Backup created at {:?}", backup_path);

        // Rotate backups
        self.rotate_backups()?;

        Ok(Some(backup_path))
    }

    fn rotate_backups(&self) -> Result<()> {
        let entries = fs::read_dir(&self.backup_dir)?;
        let mut backups: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map_or(false, |ext| ext == "bak"))
            .collect();
        
        // Sort by name (which includes timestamp)
        backups.sort();
        
        // Remove oldest if we exceed max
        if backups.len() > self.max_backups {
            let to_remove = backups.len() - self.max_backups;
            for path in backups.iter().take(to_remove) {
                if let Err(e) = fs::remove_file(path) {
                    warn!("Failed to remove old backup {:?}: {}", path, e);
                } else {
                    info!("Rotated old backup: {:?}", path);
                }
            }
        }
        
        Ok(())
    }

    // A simple diff - in real life we might want a recursive deep diff
    // For now we just compare high level modules
    fn diff(&self, old: &Config, new: &Config) -> Vec<ConfigChange> {
        let mut changes = Vec::new();
        
        // Helper macro to compare fields
        macro_rules! check {
            ($field:ident, $name:expr) => {
                let s_old = format!("{:?}", old.$field);
                let s_new = format!("{:?}", new.$field);
                if s_old != s_new {
                    changes.push(ConfigChange {
                        field: $name.to_string(),
                        old_value: s_old,
                        new_value: s_new,
                        reason: None,
                    });
                }
            };
        }

        check!(server, "server");
        check!(upstream, "upstream");
        check!(detection, "detection");
        check!(ml, "ml");
        check!(wasm, "wasm");
        check!(threat_intel, "threat_intel");
        check!(shadow, "shadow");
        check!(ebpf, "ebpf");
        check!(telemetry, "telemetry");
        check!(security, "security");
        check!(api_protection, "api_protection");

        changes
    }
    
    /// List available backups
    pub fn list_backups(&self) -> Result<Vec<PathBuf>> {
        if !self.backup_dir.exists() {
            return Ok(Vec::new());
        }
        
        let mut backups: Vec<PathBuf> = fs::read_dir(&self.backup_dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map_or(false, |ext| ext == "bak"))
            .collect();
            
        backups.sort(); // Oldest first
        backups.reverse(); // Newest first
        Ok(backups)
    }
    
    /// Restore a specific backup
    pub fn restore(&self, backup_name: &str) -> Result<()> {
        let backup_path = self.backup_dir.join(backup_name);
        if !backup_path.exists() {
            return Err(anyhow!("Backup not found"));
        }
        
        // Verify we can read it and it parses as valid config
        let content = fs::read_to_string(&backup_path)?;
        let restored_config: Config = serde_yaml::from_str(&content)?;
        
        // Validate it
        ValidationEngine::validate(&restored_config)?;
        
        // Verify integrity passed, now restore
        // We do this by essentially "saving" the restored config as the new config
        // But without creating a backup of the corrupted state if possible? 
        // Or maybe we treat restore as just another save? 
        // Let's rely on atomic_write directly to avoid double backup of bad state?
        // Actually, safer to treat it as a new save so we have a paper trail.
        
        self.atomic_write(&restored_config)?;
        info!("Restored configuration from {:?}", backup_path);
        
        Ok(())
    }
}
