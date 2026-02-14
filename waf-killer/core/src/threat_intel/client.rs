use crate::threat_intel::types::*;
use serde::Serialize;
use crate::threat_intel::abuseipdb::AbuseIPDBClient;
use crate::threat_intel::alienvault::AlienVaultClient;
use crate::config::ThreatIntelConfig;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
 // Keep std duration for sleep/interval if needed, but here mostly logic
use chrono::{DateTime, Utc, Duration};
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Threat intelligence client
pub struct ThreatIntelClient {
    /// In-memory IP reputation cache
    reputation_cache: Arc<RwLock<HashMap<IpAddr, IpReputation>>>,
    
    /// Manual blacklist (admin-added IPs)
    manual_blacklist: Arc<RwLock<HashMap<IpAddr, BlacklistEntry>>>,
    
    /// Configuration
    config: RwLock<ThreatIntelConfig>,
    
    /// Last update timestamp
    last_update: Arc<RwLock<DateTime<Utc>>>,
}

#[derive(Debug, Clone)]
pub struct BlacklistEntry {
    pub reason: String,
    pub added_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}


impl ThreatIntelClient {
    /// Create new threat intelligence client
    pub fn new(config: ThreatIntelConfig) -> Self {
        Self {
            reputation_cache: Arc::new(RwLock::new(HashMap::new())),
            manual_blacklist: Arc::new(RwLock::new(HashMap::new())),
            config: RwLock::new(config),
            last_update: Arc::new(RwLock::new(Utc::now())), // Init with now
        }
    }
    
    /// Check IP reputation
    /// Returns Some(reputation) if IP is known, None if clean/unknown
    pub fn check_ip(&self, ip: IpAddr) -> Option<IpReputation> {
        // Read config lock
        let config_guard = self.config.read().unwrap();
        if !config_guard.enabled {
            return None;
        }
        
        // 1. Check manual blacklist first (highest priority)
        {
            let mut blacklist = self.manual_blacklist.write().unwrap();
            if let Some(entry) = blacklist.get(&ip) {
                // Check if expired
                let mut expired = false;
                if let Some(expires) = entry.expires_at {
                    if Utc::now() > expires {
                        expired = true;
                    }
                }

                if expired {
                    // Expired, remove and continue
                    blacklist.remove(&ip);
                } else {
                     // Still valid, return high reputation score
                     let entry_clone = entry.clone();
                     drop(blacklist); // Release lock before returning
                     return Some(IpReputation {
                        ip,
                        reputation_score: 100,
                        threat_type: ThreatType::Suspicious,
                        source: "manual_blacklist".to_string(),
                        first_seen: entry_clone.added_at,
                        last_seen: Utc::now(),
                        confidence: 1.0,
                        metadata: IpMetadata::default(),
                    });
                }
            }
        }
        
        // 2. Check reputation cache
        let cache = self.reputation_cache.read().unwrap();
        if let Some(rep) = cache.get(&ip) {
            // Check if cache entry is still valid
            let age = Utc::now().signed_duration_since(rep.last_seen);
            
            if age < Duration::hours(config_guard.cache_ttl_hours as i64) {
                return Some(rep.clone());
            }
        }
        
        None
    }

    /// Check IP with real-time API lookups (if feed not cached)
    /// This allows failing over to API if local cache misses, for specific providers
    pub async fn check_ip_with_apis(&self, ip: IpAddr) -> Option<IpReputation> {
        // First check locally
        if let Some(cached) = self.check_ip(ip) {
            return Some(cached);
        }
        
        // If not in cache, query APIs
        let feeds = self.config.read().unwrap().feeds.clone();
        for feed in &feeds {
            if !feed.enabled {
                continue;
            }
            
            match &feed.source_type {
                FeedType::AbuseIPDB => {
                    if let Some(api_key) = &feed.api_key {
                        let client = AbuseIPDBClient::new(api_key.clone());
                        if let Ok(Some(rep)) = client.check_ip(ip).await {
                            // Cache result
                            self.reputation_cache.write().unwrap().insert(ip, rep.clone());
                            return Some(rep);
                        }
                    }
                }
                
                FeedType::AlienVault => {
                    if let Some(api_key) = &feed.api_key {
                        let client = AlienVaultClient::new(api_key.clone());
                        if let Ok(Some(rep)) = client.check_ip(ip).await {
                            // Cache result
                            self.reputation_cache.write().unwrap().insert(ip, rep.clone());
                            return Some(rep);
                        }
                    }
                }
                
                _ => {}
            }
        }
        
        None
    }
    
    /// Add IP to manual blacklist
    pub fn add_to_blacklist(
        &self,
        ip: IpAddr,
        reason: String,
        duration_hours: Option<u32>,
    ) {
        let expires_at = duration_hours.map(|hours| {
            Utc::now() + Duration::hours(hours as i64)
        });
        
        let entry = BlacklistEntry {
            reason: reason.clone(), // Clone reason for log
            added_at: Utc::now(),
            expires_at,
        };
        
        self.manual_blacklist.write().unwrap().insert(ip, entry);
        
        log::info!(
            "IP {} added to blacklist: {} (expires: {:?})",
            ip,
            reason,
            expires_at
        );
    }
    
    /// Remove IP from manual blacklist
    pub fn remove_from_blacklist(&self, ip: IpAddr) -> bool {
        self.manual_blacklist.write().unwrap().remove(&ip).is_some()
    }
    
    /// Load threat feeds (call on startup and periodically)
    pub async fn load_feeds(&self) -> Result<usize, ThreatIntelError> {
        let mut total_loaded = 0;
        
        // Read config and clone feeds to avoid holding lock across await
        let feeds = self.config.read().unwrap().feeds.clone();
        
        for feed in &feeds {
            if !feed.enabled {
                continue;
            }
            
            match &feed.source_type {
                FeedType::StaticFile => {
                    if let Some(path) = &feed.file_path {
                        match self.load_from_file(path, &feed.name) {
                            Ok(count) => {
                                total_loaded += count;
                                log::info!("Loaded {} IPs from feed: {}", count, feed.name);
                            },
                            Err(e) => log::error!("Failed to load feed {}: {}", feed.name, e),
                        }
                    }
                }
                FeedType::TorExitNodes => {
                    match self.load_tor_exit_nodes().await {
                        Ok(count) => {
                            total_loaded += count;
                            log::info!("Loaded {} Tor exit nodes", count);
                        },
                        Err(e) => log::error!("Failed to load Tor exit nodes: {}", e),
                    }
                }
                FeedType::AbuseIPDB => {
                    if let Some(api_key) = &feed.api_key {
                        let client = AbuseIPDBClient::new(api_key.clone());
                        // AbuseIPDB blacklist download needs subscription for efficiency, using modest confidence
                        match client.download_blacklist(75).await {
                            Ok(ips) => {
                                let mut cache = self.reputation_cache.write().unwrap();
                                let count = ips.len();
                                for rep in ips {
                                    cache.insert(rep.ip, rep);
                                }
                                total_loaded += count;
                                log::info!("Loaded {} IPs from AbuseIPDB", count);
                            }
                            Err(e) => {
                                log::warn!("Failed to load AbuseIPDB feed: {}", e);
                            }
                        }
                    } else {
                        log::warn!("AbuseIPDB feed enabled but no API key provided");
                    }
                }
                FeedType::AlienVault => {
                    // AlienVault OTX doesn't have bulk download like AbuseIPDB easily
                    log::info!("AlienVault OTX configured for real-time lookups");
                }
                _ => {
                    log::warn!("Feed type {:?} not implemented", feed.source_type);
                }
            }
        }
        
        *self.last_update.write().unwrap() = Utc::now();
        
        Ok(total_loaded)
    }
    
    /// Load IPs from a file (one IP per line)
    pub fn load_from_file(&self, path: &str, source: &str) -> Result<usize, ThreatIntelError> {
        let file = File::open(path)
            .map_err(|e| ThreatIntelError::FileError(format!("Failed to open {}: {}", path, e)))?;
        
        let reader = BufReader::new(file);
        let mut count = 0;
        let mut cache = self.reputation_cache.write().unwrap();
        
        for line in reader.lines() {
            let line = line.map_err(|e| ThreatIntelError::FileError(e.to_string()))?;
            let line = line.trim();
            
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Parse IP (handle optional metadata: "1.2.3.4,botnet,80")
            let parts: Vec<&str> = line.split(',').collect();
            if let Ok(ip) = parts[0].parse::<IpAddr>() {
                let threat_type = if parts.len() > 1 {
                    parse_threat_type(parts[1])
                } else {
                    ThreatType::Suspicious
                };
                
                let reputation_score = if parts.len() > 2 {
                    parts[2].parse().unwrap_or(70)
                } else {
                    70  // Default score for file-based feeds
                };
                
                cache.insert(ip, IpReputation {
                    ip,
                    reputation_score,
                    threat_type,
                    source: source.to_string(),
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    confidence: 0.8,
                    metadata: IpMetadata::default(),
                });
                
                count += 1;
            }
        }
        
        Ok(count)
    }
    
    /// Load Tor exit nodes from official list
    async fn load_tor_exit_nodes(&self) -> Result<usize, ThreatIntelError> {
        // Tor Project maintains a list at: https://check.torproject.org/exit-addresses
        let url = "https://check.torproject.org/exit-addresses";
        
        let response = reqwest::get(url)
            .await
            .map_err(|e| ThreatIntelError::NetworkError(e.to_string()))?
            .text()
            .await
            .map_err(|e| ThreatIntelError::NetworkError(e.to_string()))?;
        
        let mut count = 0;
        let mut cache = self.reputation_cache.write().unwrap();
        
        for line in response.lines() {
            // Format: "ExitAddress 1.2.3.4 2024-01-28 12:00:00"
            if line.starts_with("ExitAddress") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(ip) = parts[1].parse::<IpAddr>() {
                        cache.insert(ip, IpReputation {
                            ip,
                            reputation_score: 50,  // Moderate score for Tor
                            threat_type: ThreatType::TorExit,
                            source: "tor_project".to_string(),
                            first_seen: Utc::now(),
                            last_seen: Utc::now(),
                            confidence: 1.0,
                            metadata: IpMetadata {
                                is_tor: true,
                                ..Default::default()
                            },
                        });
                        count += 1;
                    }
                }
            }
        }
        
        Ok(count)
    }
    
    /// Get statistics about loaded threat intel
    pub fn get_stats(&self) -> ThreatIntelStats {
        let cache = self.reputation_cache.read().unwrap();
        let blacklist = self.manual_blacklist.read().unwrap();
        
        let mut by_type = HashMap::new();
        for rep in cache.values() {
            let type_str = format!("{:?}", rep.threat_type);
            *by_type.entry(type_str).or_insert(0) += 1;
        }
        
        ThreatIntelStats {
            total_ips: cache.len(),
            manual_blacklist_size: blacklist.len(),
            by_threat_type: by_type,
            last_update: *self.last_update.read().unwrap(),
        }
    }

    /// Update configuration and reload if necessary
    pub async fn update_config(&self, new_config: ThreatIntelConfig) -> Result<usize, ThreatIntelError> {
        {
            let mut w = self.config.write().unwrap();
            *w = new_config;
        }
        log::info!("Threat Intel configuration updated");
        self.load_feeds().await
    }
}

#[derive(Debug, Serialize)]
pub struct ThreatIntelStats {
    pub total_ips: usize,
    pub manual_blacklist_size: usize,
    pub by_threat_type: HashMap<String, usize>,
    pub last_update: DateTime<Utc>,
}

/// Parse threat type from string
fn parse_threat_type(s: &str) -> ThreatType {
    match s.to_lowercase().as_str() {
        "botnet" => ThreatType::Botnet,
        "scanner" => ThreatType::Scanner,
        "bruteforce" | "brute_force" => ThreatType::BruteForce,
        "spam" => ThreatType::Spam,
        "proxy" => ThreatType::Proxy,
        "tor" | "tor_exit" => ThreatType::TorExit,
        "malware" => ThreatType::Malware,
        "phishing" => ThreatType::Phishing,
        "ddos" => ThreatType::DDoS,
        "datacenter" => ThreatType::Datacenter,
        _ => ThreatType::Suspicious,
    }
}

