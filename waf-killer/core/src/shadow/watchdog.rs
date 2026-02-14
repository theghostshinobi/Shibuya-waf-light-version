// core/src/shadow/watchdog.rs

use std::sync::Arc;
use crate::telemetry::{REGISTRY, SHADOW_NEW_BLOCKS_TOTAL, WAF_REQUESTS_TOTAL, WAF_REQUEST_DURATION_SECONDS};
use prometheus::{Encoder, TextEncoder};
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};

pub struct Watchdog {
    thresholds: WatchdogThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchdogThresholds {
    pub max_error_rate_increase: f64,  // e.g. 0.05 for 5%
    pub max_latency_increase: f64,     // e.g. 0.50 for 50%
    pub max_new_blocks_per_min: u32,   // Absolute count
}

impl Default for WatchdogThresholds {
    fn default() -> Self {
        Self {
            max_error_rate_increase: 0.05,
            max_latency_increase: 0.50,
            max_new_blocks_per_min: 100,
        }
    }
}

impl Watchdog {
    pub fn new(thresholds: WatchdogThresholds) -> Self {
        Self { thresholds }
    }

    pub async fn should_rollback(&self) -> bool {
        // 1. Check Error Rate (block-to-request ratio spike)
        let error_rate_spike = self.check_error_rate().await;
        if error_rate_spike {
            warn!("Watchdog: Error rate spike detected! Block ratio exceeds threshold.");
            return true;
        }
        
        // 2. Check Latency (average request duration spike)
        let latency_spike = self.check_latency().await;
        if latency_spike {
            warn!("Watchdog: Latency spike detected! Average request duration exceeds threshold.");
            return true;
        }
        
        // 3. Check New Blocks Rate (absolute count)
        let excessive_blocks = self.check_new_blocks_rate().await;
        if excessive_blocks {
            warn!("Watchdog: Excessive new blocks detected!");
            return true;
        }
        
        false
    }
    
    /// Check error rate by computing the ratio of shadow blocks to total requests.
    /// If over `max_error_rate_increase`, it indicates a possible bad rule deployment.
    async fn check_error_rate(&self) -> bool {
        let total_requests = WAF_REQUESTS_TOTAL.get() as f64;
        if total_requests < 10.0 {
            // Not enough data to determine error rate
            return false;
        }
        
        let blocked = SHADOW_NEW_BLOCKS_TOTAL.get() as f64;
        let block_ratio = blocked / total_requests;
        
        debug!("Watchdog error rate: {:.4} (threshold: {:.4})", 
               block_ratio, self.thresholds.max_error_rate_increase);
        
        block_ratio > self.thresholds.max_error_rate_increase
    }
    
    /// Check latency by reading the average from the Prometheus histogram.
    /// If the average latency has increased beyond `max_latency_increase` (as a ratio
    /// over a baseline of 100ms), trigger a rollback.
    async fn check_latency(&self) -> bool {
        let metric = WAF_REQUEST_DURATION_SECONDS.get_sample_count();
        if metric < 10 {
            // Not enough data
            return false;
        }
        
        let total_duration = WAF_REQUEST_DURATION_SECONDS.get_sample_sum();
        let avg_duration_secs = total_duration / metric as f64;
        let baseline_secs = 0.1; // 100ms baseline
        
        let increase_ratio = (avg_duration_secs - baseline_secs) / baseline_secs;
        
        debug!("Watchdog latency: avg={:.4}s, increase_ratio={:.4} (threshold: {:.4})", 
               avg_duration_secs, increase_ratio, self.thresholds.max_latency_increase);
        
        increase_ratio > self.thresholds.max_latency_increase
    }
    
    /// Check if shadow new blocks counter exceeds the absolute per-minute threshold.
    async fn check_new_blocks_rate(&self) -> bool {
        let current_blocks = SHADOW_NEW_BLOCKS_TOTAL.get();
        if current_blocks > self.thresholds.max_new_blocks_per_min as u64 {
            error!("Watchdog: Shadow new blocks ({}) exceeded threshold ({})", 
                   current_blocks, self.thresholds.max_new_blocks_per_min);
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_thresholds() {
        let thresholds = WatchdogThresholds::default();
        assert!((thresholds.max_error_rate_increase - 0.05).abs() < f64::EPSILON);
        assert!((thresholds.max_latency_increase - 0.50).abs() < f64::EPSILON);
        assert_eq!(thresholds.max_new_blocks_per_min, 100);
    }

    #[tokio::test]
    async fn test_watchdog_no_data_no_rollback() {
        // With no requests processed, watchdog should not trigger
        let watchdog = Watchdog::new(WatchdogThresholds::default());
        assert!(!watchdog.should_rollback().await);
    }
}

