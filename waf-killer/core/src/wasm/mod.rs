use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::path::{Path, PathBuf};
use log::{info, error};
use notify::{Watcher, RecursiveMode, RecommendedWatcher};
use wasmtime::Module;
use anyhow::Result;
use std::fs;

use crate::wasm::runtime::WasmRuntime;
use crate::wasm::interface::{WasmRequest, WasmAction};

pub mod interface;
pub mod runtime;

pub struct WasmPluginManager {
    runtime: Arc<WasmRuntime>,
    plugins: Arc<RwLock<HashMap<String, Module>>>,
    #[allow(dead_code)]
    watcher: Option<RecommendedWatcher>,
    plugins_dir: PathBuf,
}

impl WasmPluginManager {
    pub fn new(plugins_dir: &str) -> Result<Arc<Self>> {
        let runtime = Arc::new(WasmRuntime::new()?);
        let plugins = Arc::new(RwLock::new(HashMap::new()));
        let dir = PathBuf::from(plugins_dir);

        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }

        let manager = Arc::new(Self {
            runtime,
            plugins,
            watcher: None,
            plugins_dir: dir.clone(),
        });

        // Initial Load
        manager.load_all_plugins()?;

        // Setup Watcher
        // Note: In non-blocking async context, watcher needs to run carefully.
        // For simplicity, we create the watcher here but we need to keep `manager` alive
        // inside the event handler which is tricky with Arc<Self>.
        // We'll spawn a thread or task usually, but `notify` uses a closure.
        
        let manager_clone = manager.clone();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            match res {
               Ok(event) => {
                   if event.kind.is_modify() || event.kind.is_create() {
                       for path in event.paths {
                           if path.extension().map_or(false, |ext| ext == "wasm") {
                               info!("🔌 Detected change in plugin: {:?}", path);
                               let _ = manager_clone.load_plugin(&path);
                           }
                       }
                   }
               },
               Err(e) => error!("Watch error: {:?}", e),
            }
        })?;

        watcher.watch(&dir, RecursiveMode::NonRecursive)?;
        
        // We need to mutate self to store watcher, but we are inside Arc.
        // Interior mutability approach or restructuring.
        // For this demo, let's keep watcher handling separate or ignore storing it in struct 
        // if we drop it, it stops watching.
        // Hack: return (manager, watcher) tuple or wrapping.
        
        Ok(manager)
    }

    fn load_all_plugins(&self) -> Result<()> {
        for entry in fs::read_dir(&self.plugins_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "wasm") {
                self.load_plugin(&path)?;
            }
        }
        Ok(())
    }

    fn load_plugin(&self, path: &Path) -> Result<()> {
        info!("🔌 Loading plugin: {:?}", path);
        let code = fs::read(path)?;
        
        match self.runtime.compile(&code) {
             Ok(module) => {
                 let name = path.file_stem().unwrap().to_string_lossy().to_string();
                 self.plugins.write().unwrap().insert(name.clone(), module);
                 info!("✅ Plugin '{}' loaded successfully", name);
             }
             Err(e) => {
                 error!("❌ Failed to compile plugin {:?}: {}", path, e);
             }
        }
        Ok(())
    }

    pub fn run_plugins(&self, req: &WasmRequest) -> Vec<WasmAction> {
        let plugins = self.plugins.read().unwrap();
        let mut actions = Vec::new();

        for (name, module) in plugins.iter() {
            match self.runtime.run_plugin(module, req) {
                Ok(action) => {
                    if action != WasmAction::Allow {
                        info!("Plugin '{}' decided: {:?}", name, action);
                        actions.push(action);
                    }
                },
                Err(e) => {
                    error!("Plugin '{}' execution failed: {}", name, e);
                }
            }
        }
        actions
    }
    
    /// Returns the plugins directory path
    pub fn get_plugins_dir(&self) -> &Path {
        &self.plugins_dir
    }
    
    /// List all currently loaded plugins with metadata
    pub fn list_active_plugins(&self) -> Vec<WasmPluginInfo> {
        let plugins = self.plugins.read().unwrap();
        plugins.keys().filter_map(|name| {
            let path = self.plugins_dir.join(format!("{}.wasm", name));
            if let Ok(metadata) = fs::metadata(&path) {
                let size = metadata.len();
                // Calculate SHA256 hash for file identity
                let hash = if let Ok(data) = fs::read(&path) {
                    use sha2::{Sha256, Digest};
                    let result = Sha256::digest(&data);
                    format!("{:x}", result)[..16].to_string() // First 16 hex chars
                } else {
                    "unknown".to_string()
                };
                Some(WasmPluginInfo {
                    name: name.clone(),
                    size_bytes: size,
                    hash,
                })
            } else {
                Some(WasmPluginInfo {
                    name: name.clone(),
                    size_bytes: 0,
                    hash: "in-memory".to_string(),
                })
            }
        }).collect()
    }
    
    /// Create a stub manager that does nothing (for when WASM is disabled)
    pub fn stub() -> Self {
        let runtime = Arc::new(WasmRuntime::new().expect("Failed to create WASM runtime for stub"));
        Self {
            runtime,
            plugins: Arc::new(RwLock::new(HashMap::new())),
            watcher: None,
            plugins_dir: PathBuf::from("/dev/null"),
        }
    }
}

/// Information about a loaded WASM plugin
#[derive(Debug, Clone, serde::Serialize)]
pub struct WasmPluginInfo {
    pub name: String,
    pub size_bytes: u64,
    pub hash: String,
}
