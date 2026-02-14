use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::ml::features::TrafficStats;

/// In-memory traffic statistics tracker
/// (For production, use Redis for distributed tracking)
#[derive(Clone)]
pub struct TrafficStatsTracker {
    stats: Arc<RwLock<HashMap<String, ClientStats>>>,
}

struct ClientStats {
    requests_1min: Vec<Instant>,
    requests_5min: Vec<Instant>,
    unique_paths_1min: HashMap<String, Instant>,
    errors_1min: Vec<Instant>,
    user_agent: Option<String>,
    user_agent_count: u32,
}

impl TrafficStatsTracker {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Record a request
    pub fn record_request(&self, ip: &str, path: &str, user_agent: Option<&str>) {
        let mut stats = self.stats.write().unwrap();
        let client = stats.entry(ip.to_string()).or_insert_with(|| ClientStats {
            requests_1min: Vec::new(),
            requests_5min: Vec::new(),
            unique_paths_1min: HashMap::new(),
            errors_1min: Vec::new(),
            user_agent: None,
            user_agent_count: 0,
        });
        
        let now = Instant::now();
        
        // Add to 1min and 5min buckets
        client.requests_1min.push(now);
        client.requests_5min.push(now);
        
        // Track unique paths in 1min window
        client.unique_paths_1min.insert(path.to_string(), now);
        
        // Track user agent
        if let Some(ua) = user_agent {
            if client.user_agent.as_deref() != Some(ua) {
                client.user_agent = Some(ua.to_string());
                client.user_agent_count += 1;
            }
        }
        
        // Cleanup old entries (older than 5 minutes)
        client.cleanup(now);
    }
    
    /// Record an error response
    pub fn record_error(&self, ip: &str) {
        let mut stats = self.stats.write().unwrap();
        if let Some(client) = stats.get_mut(ip) {
            client.errors_1min.push(Instant::now());
        }
    }
    
    /// Get current stats for an IP
    pub fn get_stats(&self, ip: &str) -> TrafficStats {
        let stats = self.stats.read().unwrap();
        
        if let Some(client) = stats.get(ip) {
            let now = Instant::now();
            
            TrafficStats {
                request_count_1min: client.requests_1min.iter()
                    .filter(|&&t| now.duration_since(t) < Duration::from_secs(60))
                    .count() as u32,
                request_count_5min: client.requests_5min.iter()
                    .filter(|&&t| now.duration_since(t) < Duration::from_secs(300))
                    .count() as u32,
                unique_paths_1min: client.unique_paths_1min.iter()
                    .filter(|(_, &t)| now.duration_since(t) < Duration::from_secs(60))
                    .count(),
                error_count_1min: client.errors_1min.iter()
                    .filter(|&&t| now.duration_since(t) < Duration::from_secs(60))
                    .count() as u32,
                user_agent_seen_count: client.user_agent_count,
            }
        } else {
            TrafficStats::default()
        }
    }
}

impl ClientStats {
    fn cleanup(&mut self, now: Instant) {
        let cutoff_1min = now - Duration::from_secs(60);
        let cutoff_5min = now - Duration::from_secs(300);
        
        self.requests_1min.retain(|&t| t > cutoff_1min);
        self.requests_5min.retain(|&t| t > cutoff_5min);
        self.unique_paths_1min.retain(|_, &mut t| t > cutoff_1min);
        self.errors_1min.retain(|&t| t > cutoff_1min);
    }
}

impl Default for TrafficStatsTracker {
    fn default() -> Self {
        Self::new()
    }
}
