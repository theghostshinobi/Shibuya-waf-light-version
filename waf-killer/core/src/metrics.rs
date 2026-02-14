// ============================================
// File: core/src/metrics.rs
// ============================================
//! Prometheus metrics for observability.
//!
//! 🏗️ ARCHITECTURE: Lazy static metrics with proper labeling.

use lazy_static::lazy_static;
use prometheus::{
    opts, register_histogram, register_int_counter, Histogram, IntCounter,
};

lazy_static! {
    pub static ref METRICS: Metrics = Metrics::new();
}

pub struct Metrics {
    // Request metrics
    pub requests_total: IntCounter,
    pub requests_blocked: IntCounter,
    pub requests_challenged: IntCounter,
    pub shadow_blocks: IntCounter, // <--- ADDED
    
    // Latency metrics
    pub detection_latency: Histogram,
    pub backend_latency: Histogram,
    
    // Health metrics
    pub health_checks: IntCounter,
    
    // Error metrics
    pub backend_errors: IntCounter,
    pub pipeline_errors: IntCounter,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests_total: register_int_counter!(
                opts!("waf_requests_total", "Total number of requests processed")
            ).unwrap_or_else(|_| IntCounter::new("waf_requests_total", "fallback").unwrap()),
            
            requests_blocked: register_int_counter!(
                opts!("waf_requests_blocked", "Number of requests blocked by WAF")
            ).unwrap_or_else(|_| IntCounter::new("waf_requests_blocked", "fallback").unwrap()),
            
            requests_challenged: register_int_counter!(
                opts!("waf_requests_challenged", "Number of requests requiring challenge")
            ).unwrap_or_else(|_| IntCounter::new("waf_requests_challenged", "fallback").unwrap()),

            shadow_blocks: register_int_counter!(
                opts!("waf_shadow_blocks_total", "Number of requests that would have been blocked (Shadow Mode)")
            ).unwrap_or_else(|_| IntCounter::new("waf_shadow_blocks_total", "fallback").unwrap()),
            
            detection_latency: register_histogram!(
                "waf_detection_latency_seconds",
                "Detection pipeline latency in seconds",
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]
            ).unwrap_or_else(|_| Histogram::with_opts(
                prometheus::HistogramOpts::new("waf_detection_latency_seconds", "fallback")
            ).unwrap()),
            
            backend_latency: register_histogram!(
                "waf_backend_latency_seconds",
                "Backend request latency in seconds",
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
            ).unwrap_or_else(|_| Histogram::with_opts(
                prometheus::HistogramOpts::new("waf_backend_latency_seconds", "fallback")
            ).unwrap()),
            
            health_checks: register_int_counter!(
                opts!("waf_health_checks_total", "Number of health check requests")
            ).unwrap_or_else(|_| IntCounter::new("waf_health_checks_total", "fallback").unwrap()),
            
            backend_errors: register_int_counter!(
                opts!("waf_backend_errors_total", "Number of backend connection errors")
            ).unwrap_or_else(|_| IntCounter::new("waf_backend_errors_total", "fallback").unwrap()),
            
            pipeline_errors: register_int_counter!(
                opts!("waf_pipeline_errors_total", "Number of detection pipeline errors")
            ).unwrap_or_else(|_| IntCounter::new("waf_pipeline_errors_total", "fallback").unwrap()),
        }
    }
}

impl Clone for Metrics {
    fn clone(&self) -> Self {
        // Metrics are singletons, just return new references
        Self::new()
    }
}
