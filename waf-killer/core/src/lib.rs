// ============================================
// File: core/src/lib.rs
// ============================================
//! WAF Killer Core Library
//!
//! High-performance Web Application Firewall with ML-enhanced detection,
//! WASM plugin support, and full observability.

// Core modules
pub mod config;
pub mod proxy;
pub mod proxy_optimized; // <--- ADDED
pub mod state; // <--- ADDED
pub mod api; // <--- ADDED
pub mod auth; // <--- ADDED
pub mod rbac;

// Infrastructure modules
pub mod health;
pub mod metrics;
pub mod persistence;
pub mod telemetry;
pub mod graceful_shutdown;
pub mod admin_api;

// Security engines
pub mod rules;
pub mod ml;
pub mod wasm;

pub mod threat_intel; // <--- ADDED
pub mod vulnerabilities; // <--- ADDED
pub mod tenancy;
pub mod api_protection; // <--- ADDED


// Supporting modules
pub mod pool;
pub mod parser;
pub mod cache;
pub mod simd;

// Re-exports for convenience
pub use config::Config;
pub use proxy::WafProxy;

// Rate Limiting (Ep 15)
pub mod ratelimit;

// Bot Detection (Ep 16)
// Bot Detection (Ep 16)
pub mod botdetection;

pub mod traffic_stats;
pub mod shadow;
pub mod session;
pub mod quick_setup;
