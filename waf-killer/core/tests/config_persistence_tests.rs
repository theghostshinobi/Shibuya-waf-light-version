use waf_killer_core::config::{Config, ConfigPersister};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_atomic_save_and_backup() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("waf.yaml");
    
    // 1. Create initial config
    let mut initial_config = Config::default();
    initial_config.server.http_port = 9000;
    
    // Write initial file manually
    let yaml = serde_yaml::to_string(&initial_config).unwrap();
    fs::write(&config_path, yaml).unwrap();
    
    // 2. Setup Persister
    let persister = ConfigPersister::new(config_path.clone());
    
    // 3. Save new config
    let mut new_config = initial_config.clone();
    new_config.server.http_port = 9001;
    
    persister.save(&new_config, &initial_config, "test_user", "127.0.0.1", None).unwrap();
    
    // 4. Verify file on disk updated
    let saved_content = fs::read_to_string(&config_path).unwrap();
    let saved_config: Config = serde_yaml::from_str(&saved_content).unwrap();
    assert_eq!(saved_config.server.http_port, 9001);
    
    // 5. Verify backup created
    let backups = persister.list_backups().unwrap();
    assert_eq!(backups.len(), 1);
    
    // Verify backup content is OLD config
    let backup_content = fs::read_to_string(&backups[0]).unwrap();
    let backup_config: Config = serde_yaml::from_str(&backup_content).unwrap();
    assert_eq!(backup_config.server.http_port, 9000);
}

#[test]
fn test_validation_rejection() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("waf.yaml");
    
    let initial_config = Config::default();
    
    // Write initial
    let yaml = serde_yaml::to_string(&initial_config).unwrap();
    fs::write(&config_path, yaml).unwrap();
    
    let persister = ConfigPersister::new(config_path.clone());
    
    // Create INVALID config (ML threshold > 1.0)
    let mut bad_config = initial_config.clone();
    bad_config.ml.enabled = true;
    bad_config.ml.threshold = 1.5; 
    
    // Save should fail
    let result = persister.save(&bad_config, &initial_config, "test", "127.0.0.1", None);
    assert!(result.is_err());
    
    // Verify file NOT changed
    let content = fs::read_to_string(&config_path).unwrap();
    let on_disk: Config = serde_yaml::from_str(&content).unwrap();
    assert_eq!(on_disk.ml.threshold, initial_config.ml.threshold);
}

#[test]
fn test_backup_rotation() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("waf.yaml");
    
    let mut config = Config::default();
    fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
    
    let persister = ConfigPersister::new(config_path.clone());
    
    // Create 11 backups (max is 10)
    for i in 0..12 {
        let mut new_config = config.clone();
        new_config.server.http_port = 8000 + i;
        persister.save(&new_config, &config, "test", "1.1.1.1", None).unwrap();
        config = new_config; // Update current
        std::thread::sleep(std::time::Duration::from_millis(10)); // Ensure unique timestamps if fast
    }
    
    let backups = persister.list_backups().unwrap();
    assert_eq!(backups.len(), 10, "Should only keep 10 backups");
}

#[test]
fn test_restore() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("waf.yaml");
    
    let mut config_v1 = Config::default();
    config_v1.server.http_port = 1000;
    fs::write(&config_path, serde_yaml::to_string(&config_v1).unwrap()).unwrap();
    
    let persister = ConfigPersister::new(config_path.clone());
    
    // Save V2
    let mut config_v2 = config_v1.clone();
    config_v2.server.http_port = 2000;
    persister.save(&config_v2, &config_v1, "test", "1.1.1.1", None).unwrap();
    
    // Get backup name
    let backups = persister.list_backups().unwrap();
    let backup_name = backups[0].file_name().unwrap().to_str().unwrap();
    
    // Save V3
    let mut config_v3 = config_v2.clone();
    config_v3.server.http_port = 3000;
    persister.save(&config_v3, &config_v2, "test", "1.1.1.1", None).unwrap();
    
    // Current is V3 (3000)
    let content = fs::read_to_string(&config_path).unwrap();
    let on_disk: Config = serde_yaml::from_str(&content).unwrap();
    assert_eq!(on_disk.server.http_port, 3000);
    
    // Restore V1 (1000) from backup
    persister.restore(backup_name).unwrap();
    
    // Verify restored
    let content = fs::read_to_string(&config_path).unwrap();
    let restored: Config = serde_yaml::from_str(&content).unwrap();
    assert_eq!(restored.server.http_port, 1000);
}
