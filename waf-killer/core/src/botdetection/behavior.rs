use dashmap::DashMap;
use std::time::{SystemTime, Duration};
use std::sync::Arc;

const MAX_REQUESTS_PER_WINDOW: usize = 20; // Max requests in 1 second
const VELOCITY_WINDOW: Duration = Duration::from_secs(1);
const HISTORY_RETENTION: Duration = Duration::from_secs(60);

/// Track request timestamps for an IP
#[derive(Debug)]
struct RequestHistory {
    timestamps: Vec<SystemTime>,
}

impl RequestHistory {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
        }
    }
    
    /// Add a new request timestamp
    fn record_request(&mut self, now: SystemTime) {
        self.timestamps.push(now);
        
        // Clean old timestamps (older than retention period)
        let cutoff = now.checked_sub(HISTORY_RETENTION).unwrap_or(now);
        self.timestamps.retain(|&ts| ts >= cutoff);
    }
    
    /// Calculate requests in the last window
    fn requests_in_window(&self, window: Duration) -> usize {
        let now = SystemTime::now();
        let cutoff = now.checked_sub(window).unwrap_or(now);
        
        self.timestamps.iter()
            .filter(|&&ts| ts >= cutoff)
            .count()
    }
    
    /// Calculate average time between requests
    fn average_interval(&self) -> Option<Duration> {
        if self.timestamps.len() < 2 {
            return None;
        }
        
        let mut intervals = Vec::new();
        for i in 1..self.timestamps.len() {
            if let Ok(interval) = self.timestamps[i].duration_since(self.timestamps[i-1]) {
                intervals.push(interval);
            }
        }
        
        if intervals.is_empty() {
            return None;
        }
        
        let total: Duration = intervals.iter().sum();
        Some(total / intervals.len() as u32)
    }
}

/// Behavioral tracker for bot detection
pub struct BehaviorTracker {
    // IP -> RequestHistory
    history: Arc<DashMap<String, RequestHistory>>,
}

impl BehaviorTracker {
    pub fn new() -> Self {
        Self {
            history: Arc::new(DashMap::new()),
        }
    }
    
    /// Track a new request from an IP
    pub fn track_request(&self, ip: &str) {
        let now = SystemTime::now();
        
        self.history
            .entry(ip.to_string())
            .or_insert_with(RequestHistory::new)
            .record_request(now);
    }
    
    /// Calculate velocity-based bot score
    /// Returns: 0.0 = normal, 1.0 = highly suspicious
    pub fn get_velocity_score(&self, ip: &str) -> f32 {
        let history = match self.history.get(ip) {
            Some(h) => h,
            None => return 0.0, // No history = neutral
        };
        
        let requests_per_sec = history.requests_in_window(VELOCITY_WINDOW);
        
        // Calculate score based on request rate
        let rate_score = if requests_per_sec > MAX_REQUESTS_PER_WINDOW {
            1.0 // Clearly bot-like
        } else if requests_per_sec > 10 {
            0.8 // Very suspicious
        } else if requests_per_sec > 5 {
            0.5 // Moderately suspicious
        } else {
            0.1 // Normal
        };
        
        // Check for too-regular intervals (bots often have consistent timing)
        let regularity_score = if let Some(avg_interval) = history.average_interval() {
            if avg_interval.as_millis() < 100 {
                0.9 // Sub-100ms intervals = likely bot
            } else if avg_interval.as_millis() < 500 {
                0.6
            } else {
                0.2
            }
        } else {
            0.0
        };
        
        // Weighted combination
        (rate_score * 0.7) + (regularity_score * 0.3)
    }
    
    /// Check if IP has any verification cookie
    /// (This would be checked from actual cookie header in production)
    pub fn has_verification(&self, _ip: &str, has_cookie: bool) -> bool {
        has_cookie
    }
    
    /// Calculate overall behavioral bot score
    pub fn calculate_behavior_score(&self, ip: &str, has_verification_cookie: bool) -> f32 {
        let velocity_score = self.get_velocity_score(ip);
        
        // If verified, reduce score significantly
        if has_verification_cookie {
            return velocity_score * 0.2; // Verified users get 80% reduction
        }
        
        velocity_score
    }
    
    /// Cleanup old entries periodically
    pub fn cleanup(&self) {
        let now = SystemTime::now();
        let cutoff = now.checked_sub(HISTORY_RETENTION).unwrap_or(now);
        
        self.history.retain(|_ip, history| {
            // Keep if has recent requests
            history.timestamps.last()
                .map(|&last| last >= cutoff)
                .unwrap_or(false)
        });
    }
}

impl Default for BehaviorTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
    #[test]
    fn test_velocity_scoring() {
        let tracker = BehaviorTracker::new();
        let ip = "192.168.1.1";
        
        // Simulate rapid requests
        for _ in 0..15 {
            tracker.track_request(ip);
        }
        
        let score = tracker.get_velocity_score(ip);
        assert!(score > 0.5); // Should be suspicious
    }
    
    #[test]
    fn test_verification_reduces_score() {
        let tracker = BehaviorTracker::new();
        let ip = "192.168.1.2";
        
        for _ in 0..15 {
            tracker.track_request(ip);
        }
        
        let score_without = tracker.calculate_behavior_score(ip, false);
        let score_with = tracker.calculate_behavior_score(ip, true);
        
        assert!(score_with < score_without);
    }
}
