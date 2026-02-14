use wasmtime::*;
use wasmtime_wasi::WasiCtx;
use std::time::Duration;
use anyhow::{Result, anyhow};
use crate::wasm::host::WasmPluginContext;

pub struct WasmPluginEngine {
    engine: Engine,
    linker: Linker<WasmPluginContext>,
    // store_limits: StoreLimits, // Note: Handled per-store
}

// Resource limits (CRITICAL for safety)
#[derive(Debug, Clone, Copy)]
pub struct WasmResourceLimits {
    pub max_memory_bytes: usize,        // 10MB default
    pub max_table_elements: u32,        // 1000
    pub max_instances: usize,           // 10
    pub max_tables: usize,              // 1
    pub max_memories: usize,            // 1
    pub fuel_limit: u64,                // 1M instructions
    pub execution_timeout: Duration,    // 10ms
}

impl Default for WasmResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 10 * 1024 * 1024,  // 10MB
            max_table_elements: 1000,
            max_instances: 10,
            max_tables: 1,
            max_memories: 1,
            fuel_limit: 1_000_000,  // 1M instructions
            execution_timeout: Duration::from_millis(10),
        }
    }
}

pub struct WasmPlugin {
    pub module: Module,
    pub plugin_id: String,
}

#[derive(Debug, Clone)]
pub enum PluginDecision {
    Continue,  // 0
    Allow,     // 1
    Block,     // 2
}

pub struct PluginDecisionWithMetrics {
    pub decision: PluginDecision,
    pub fuel_consumed: u64,
    pub execution_time_us: u64,
}

impl WasmPluginEngine {
    pub fn new(limits: WasmResourceLimits) -> Result<Self> {
        // Configure Wasmtime with strict security settings
        let mut config = Config::new();
        
        // Enable fuel metering (instruction counting)
        config.consume_fuel(true);
        
        // Enable epoch-based interruption (for timeouts)
        config.epoch_interruption(true);
        
        // Disable features that could be dangerous
        config.wasm_simd(false);           // No SIMD
        config.wasm_bulk_memory(false);    // No bulk memory ops (depends on guest requirements, but safer without)
        config.wasm_reference_types(false); 
        config.wasm_multi_memory(false);   
        
        // Enable optimizations
        config.cranelift_opt_level(OptLevel::Speed);
        
        let engine = Engine::new(&config)?;
        
        // Create linker with host functions
        let mut linker = Linker::new(&engine);
        // We will register host functions in manager or specific initializer
        // For now, assume host functionality is wired elsewhere or added here
        
        Ok(Self {
            engine,
            linker,
        })
    }
    
    pub fn linker(&mut self) -> &mut Linker<WasmPluginContext> {
        &mut self.linker
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Load a plugin from compiled WASM bytecode
    pub fn load_plugin(&self, wasm_bytes: &[u8], plugin_id: &str) -> Result<WasmPlugin> {
        // 1. Validate WASM module
        Module::validate(&self.engine, wasm_bytes)
            .map_err(|e| anyhow!("Invalid WASM module: {}", e))?;
        
        // 2. Compile module
        let module = Module::new(&self.engine, wasm_bytes)?;
        
        // 3. Verify exports (Basic check)
        let exports: Vec<_> = module.exports().map(|e| e.name()).collect();
        // Since we use components/WIT, "inspect" might be inside an interface adapter, 
        // but for raw modules/adapters it's "inspect". 
        // We skip strict name check here to allow potential component model evolution.
        
        Ok(WasmPlugin {
            module,
            plugin_id: plugin_id.to_string(),
        })
    }
}
