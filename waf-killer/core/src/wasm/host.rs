use wasmtime::*;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder};
use anyhow::{Result, anyhow};
use std::time::Duration;
use log::{debug, info, warn, error};

// Context data available to the running plugin
pub struct WasmPluginContext {
    pub wasi_ctx: WasiCtx,
    pub request_id: String,
    pub method: String,
    pub path: String,
    // Add other fields as needed, simplified for prototype
    pub limits: StoreLimits,
    pub start_time: std::time::Instant,
}

// Resource Limit helpers
pub struct StoreLimits {
    pub max_memory: usize,
    pub memory_used: usize,
}

impl StoreLimits {
    pub fn new(max_memory_bytes: usize) -> Self {
        Self {
            max_memory: max_memory_bytes,
            memory_used: 0,
        }
    }
}

// Manually implementing ResourceLimiter is needed if we want strict control
// For now, we rely on wasmtime's config limits and manual checks in host funcs
// or standard StoreLimits if using `wasmtime::ResourceLimiter`.

/// Register host functions
pub fn register_host_functions(linker: &mut Linker<WasmPluginContext>) -> Result<()> {
    // Logging: log(level: i32, ptr: i32, len: i32)
    linker.func_wrap(
        "env",
        "log",
        |mut caller: Caller<'_, WasmPluginContext>, level: i32, ptr: i32, len: i32| {
            let memory = caller.get_export("memory")
                .and_then(|e| e.into_memory())
                .ok_or_else(|| anyhow!("No memory export"))?;
            
            let data = memory.data(&caller);
            // Safety check
            if ptr as usize + len as usize > data.len() {
                return Err(anyhow!("Memory access out of bounds"));
            }
            
            let message = match std::str::from_utf8(&data[ptr as usize..(ptr + len) as usize]) {
                Ok(s) => s.to_string(), // Copy to avoid borrowing issues
                Err(_) => return Err(anyhow!("Invalid UTF-8 sequence")),
            };
            
            match level {
                0 => debug!("[WASM] {}", message),
                1 => info!("[WASM] {}", message),
                2 => warn!("[WASM] {}", message),
                3 => error!("[WASM] {}", message),
                _ => {}
            }
            
            Ok(())
        },
    )?;

    // request::get_method() -> i32 (ptr/len packed?) or we use simple ABI
    // For simplicity in this non-component prototypes, let's pretend a simpler ABI or ignore implementation
    // Detail: Real WIT support requires `bindgen!` macro which spawns traits.
    
    // We will assume the `Host` trait integration happens via Manager or a separate "Glue" file if using `wit-bindgen`.
    // For manual implementation:
    
    linker.func_wrap("env", "get_method", |mut caller: Caller<'_, WasmPluginContext>, out_ptr: i32, out_cap: i32| -> Result<i32> {
        let method = caller.data().method.clone();
        let memory = caller.get_export("memory")
                .and_then(|e| e.into_memory())
                .ok_or_else(|| anyhow!("No memory export"))?;
        
        let bytes = method.as_bytes();
        let len = bytes.len().min(out_cap as usize);
        
        let data = memory.data_mut(&mut caller);
        data[out_ptr as usize..out_ptr as usize + len].copy_from_slice(&bytes[..len]);
        
        Ok(len as i32)
    })?;

    Ok(())
}
