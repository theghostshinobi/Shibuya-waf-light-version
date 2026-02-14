use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Data passed from Host (WAF) to Guest (Plugin)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmRequest {
    pub id: String,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub client_ip: String,
    // Body is expensive to copy, maybe passed on demand or truncated
    pub body_preview: Vec<u8>, 
}

/// Action returned by Guest to Host
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WasmAction {
    Allow,
    Block { reason: String, score: i32 },
    Log { msg: String },
    ModifyHeaders { headers: HashMap<String, String> },
}

// Simple ABI constants
pub const MAX_PLUGIN_MEMORY: u32 = 10 * 1024 * 1024; // 10MB
pub const MAX_EXECUTION_FUEL: u64 = 1_000_000; // Arbitrary units(~5ms depending on cpu)
