use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::slice;

// ============================================
// Shared Types (Copy from interface.rs)
// In real world, this would be a shared crate
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmRequest {
    pub id: String,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub client_ip: String,
    pub body_preview: Vec<u8>, 
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WasmAction {
    Allow,
    Block { reason: String, score: i32 },
    Log { msg: String },
    ModifyHeaders { headers: HashMap<String, String> },
}

// ============================================
// Guest Utilities / ABI
// ============================================

#[no_mangle]
pub extern "C" fn waf_alloc(len: i32) -> *mut u8 {
    let mut buf = Vec::with_capacity(len as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

// External logging function provided by Host
extern "C" {
    fn host_log(ptr: *const u8, len: i32);
}

fn log(msg: &str) {
    unsafe { host_log(msg.as_ptr(), msg.len() as i32) };
}

// ============================================
// Main Logic
// ============================================

#[no_mangle]
pub extern "C" fn waf_run(ptr: *mut u8, len: i32) -> *mut u8 {
    // 1. Deserialize Request
    let req_bytes = unsafe { slice::from_raw_parts(ptr, len as usize) };
    let req: WasmRequest = match rmp_serde::from_slice(req_bytes) {
        Ok(r) => r,
        Err(_) => {
            log("Error deserializing request in WASM");
            return prepare_response(&WasmAction::Allow);
        }
    };

    // 2. Custom Logic
    log(&format!("Checking request: {}", req.path));

    let action = if req.headers.contains_key("x-hacker") {
        WasmAction::Block { 
            reason: "Hacker header detected by WASM".to_string(), 
            score: 100 
        }
    } else if req.path.contains("/admin-wasm") {
        WasmAction::Block {
             reason: "WASM Admin protection".to_string(),
             score: 90
        }
    } else {
        WasmAction::Allow
    };

    // 3. Return Response
    prepare_response(&action)
}

fn prepare_response(action: &WasmAction) -> *mut u8 {
    let mut bytes = rmp_serde::to_vec(action).unwrap();
    let len = bytes.len() as u32;
    
    // Prefix with length (Little Endian)
    let mut final_buf = len.to_le_bytes().to_vec();
    final_buf.extend(bytes);
    
    let ptr = final_buf.as_mut_ptr();
    std::mem::forget(final_buf);
    ptr
}
