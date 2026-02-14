// api/src/routes/ebpf.rs

use axum::{
    extract::{State, Json},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tracing::{info, error};

// Assuming we can access the core crate's global manager
// If not, we might need to expose it specifically or rethink the architecture.
// Since `waf_killer_core` is a dependency, we can access its public items.
// We added `pub mod ebpf` in core/lib.rs and `EBPF_MANAGER` is public in core/ebpf/manager.rs.
// However, `core` crate name is `waf_killer_core` in Cargo.toml.

use waf_killer_core::ebpf::manager::EBPF_MANAGER;

#[derive(Serialize)]
pub struct EBPFStatus {
    pub enabled: bool,
    pub stats: Option<EBPFStats>,
}

#[derive(Serialize)]
pub struct EBPFStats {
    pub total_packets: u64,
    pub blocked_packets: u64,
    pub rate_limited_packets: u64,
    pub allowed_packets: u64,
}

#[derive(Deserialize)]
pub struct BlockIPRequest {
    pub ip: IpAddr,
}

#[derive(Serialize)]
pub struct BlockIPResponse {
    pub success: bool,
    pub message: String,
}

impl From<waf_killer_core::ebpf::maps::Stats> for EBPFStats {
    fn from(s: waf_killer_core::ebpf::maps::Stats) -> Self {
        Self {
            total_packets: s.total_packets,
            blocked_packets: s.blocked_packets,
            rate_limited_packets: s.rate_limited_packets,
            allowed_packets: s.allowed_packets,
        }
    }
}

pub async fn get_ebpf_status() -> impl IntoResponse {
    #[cfg(feature = "ebpf")]
    {
        // Access global manager from core
        let manager_lock = EBPF_MANAGER.lock().unwrap();
        
        if let Some(manager) = &*manager_lock {
            match manager.get_stats() {
                Ok(stats) => {
                    return Json(EBPFStatus {
                        enabled: true,
                        stats: Some(stats.into()),
                    });
                }
                Err(e) => {
                    error!("Failed to get eBPF stats: {}", e);
                    // Still return enabled=true but no stats
                    return Json(EBPFStatus {
                        enabled: true,
                        stats: None,
                    });
                }
            }
        }
    }

    Json(EBPFStatus {
        enabled: false,
        stats: None,
    })
}

pub async fn block_ip_kernel(
    Json(payload): Json<BlockIPRequest>,
) -> impl IntoResponse {
    #[cfg(feature = "ebpf")]
    {
        let mut manager_lock = EBPF_MANAGER.lock().unwrap();
        
        if let Some(manager) = &mut *manager_lock {
            match manager.block_ip(payload.ip) {
                Ok(_) => {
                    return Json(BlockIPResponse {
                        success: true,
                        message: format!("IP {} blocked in kernel", payload.ip),
                    });
                },
                Err(e) => {
                    return Json(BlockIPResponse {
                        success: false,
                        message: format!("Failed to block IP: {}", e),
                    });
                }
            }
        }
    }

    Json(BlockIPResponse {
        success: false,
        message: "eBPF not enabled".to_string(),
    })
}

pub async fn get_ebpf_stats() -> impl IntoResponse {
    #[cfg(feature = "ebpf")]
    {
       let manager_lock = EBPF_MANAGER.lock().unwrap();
        if let Some(manager) = &*manager_lock {
            match manager.get_stats() {
                Ok(stats) => return Json(stats.into()),
                Err(_) => {},
            }
        }
    }
    
    // Return empty stats if not enabled
    Json(EBPFStats {
        total_packets: 0,
        blocked_packets: 0,
        rate_limited_packets: 0,
        allowed_packets: 0,
    })
}
