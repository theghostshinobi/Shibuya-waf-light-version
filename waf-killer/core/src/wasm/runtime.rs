use anyhow::{Result, Context, anyhow};
use wasmtime::{Engine, Linker, Module, Store, Config, Caller};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder}; // WasiCtx is in root in 14.0?
use crate::wasm::interface::{WasmRequest, WasmAction, MAX_EXECUTION_FUEL};
use log::{info};

pub struct WasmRuntime {
    engine: Engine,
    linker: Linker<WasmContext>,
}

pub struct WasmContext {
    wasi: WasiCtx,
    // Provide a scratch buffer for data exchange if needed
}

impl WasmRuntime {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true); // Enable instruction counting for timeout
        config.epoch_interruption(true); // Alternative timeout mechanism
        config.cache_config_load_default()?;
        
        let engine = Engine::new(&config)?;
        let mut linker = Linker::new(&engine);
        
        // Add WASI support (14.0 Root)
        wasmtime_wasi::add_to_linker(&mut linker, |ctx: &mut WasmContext| &mut ctx.wasi)?;

        // Define Host Functions (Logging)
        linker.func_wrap("env", "host_log", |mut caller: Caller<'_, WasmContext>, ptr: i32, len: i32| {
            let mem = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(m)) => m,
                _ => return,
            };
            
            // Read string from memory (unsafe-ish but handled by wasmtime checks)
            let data = match mem.data(&caller).get(ptr as usize..(ptr + len) as usize) {
                Some(d) => d,
                None => return,
            };
            
            if let Ok(msg) = std::str::from_utf8(data) {
                info!("[WASM GUEST] {}", msg);
            }
        })?;

        Ok(Self {
            engine,
            linker,
        })
    }

    pub fn compile(&self, code: &[u8]) -> Result<Module> {
        Module::new(&self.engine, code)
    }

    /// Run a plugin against a request
    pub fn run_plugin(
        &self, 
        module: &Module, 
        request: &WasmRequest
    ) -> Result<WasmAction> {
        // 1. Setup Context (WASI sandbox)
        let wasi = WasiCtxBuilder::new()
            .inherit_stdout()
            .inherit_stderr()
            .build();
            
        let mut store = Store::new(&self.engine, WasmContext { wasi });
        store.add_fuel(MAX_EXECUTION_FUEL)?;

        // 2. Instantiate
        let instance = self.linker.instantiate(&mut store, module)
            .context("Failed to instantiate WASM plugin")?;

        // 3. Serialize Request
        let req_bytes = rmp_serde::to_vec(request)?;
        let req_len = req_bytes.len() as i32;

        // 4. Allocate memory in Guest for request
        // Guest must export `alloc(size) -> ptr`
        let alloc_func = instance.get_typed_func::<i32, i32>(&mut store, "waf_alloc")
            .context("Plugin missing 'waf_alloc' export")?;
            
        let req_ptr = alloc_func.call(&mut store, req_len)?;

        // 5. Write Request to Guest Memory
        let memory = instance.get_memory(&mut store, "memory")
            .context("Plugin missing 'memory' export")?;
            
        memory.write(&mut store, req_ptr as usize, &req_bytes)?;

        // 6. Call Entrypoint
        let run_func = instance.get_typed_func::<(i32, i32), i32>(&mut store, "waf_run")
             .context("Plugin missing 'waf_run' export")?;
             
        let res_ptr = run_func.call(&mut store, (req_ptr, req_len))?;
        
        // 7. Read Result Length
        // We assume the first 4 bytes at res_ptr are the length (LE)
        let mut len_bytes = [0u8; 4];
        memory.read(&mut store, res_ptr as usize, &mut len_bytes)?;
        let res_len = u32::from_le_bytes(len_bytes) as usize;

        if res_len > 1024 * 1024 {
             return Err(anyhow!("Plugin returned too large response"));
        }

        // 8. Read Result Body (skip 4 bytes length)
        let mut res_bytes = vec![0u8; res_len as usize];
        memory.read(&mut store, (res_ptr + 4) as usize, &mut res_bytes)?;
        
        // 9. Deserialize Action
        let action: WasmAction = rmp_serde::from_slice(&res_bytes)
            .context("Failed to deserialize WasmAction from plugin")?;

        Ok(action)
    }
}
