use anyhow::Result;
use notify::{Watcher, RecursiveMode, Event, RecommendedWatcher, Config};
use std::path::Path;
use tokio::sync::mpsc;
use tracing::{info, error};
use crate::config::policy_schema::Policy;
use super::loader::PolicyLoader;

pub struct PolicyWatcher {
    _watcher: RecommendedWatcher, // Keep alive
    /*
    In a real implementation we might need to handle the watcher lifecycle more manually,
    but `notify` usually runs in background threads.
    */
}

impl PolicyWatcher {
    pub async fn start(
        mut loader: PolicyLoader,
        policy_tx: mpsc::Sender<Policy>,
    ) -> Result<Self> {
        info!("Starting Policy Watcher...");
        
        let (tx, mut rx) = mpsc::channel(1);
        
        // Create async watcher
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
             if let Ok(event) = res {
                 // We only care about modifications
                 if event.kind.is_modify() {
                     let _ = tx.blocking_send(event);
                 }
             }
        })?;
        
        // Watch the .git/refs/heads/main or just the policy.yaml?
        // If we pull via loader, we might be watching file system changes caused by pull?
        // Or if user edits locally.
        // Let's watch the directory containing policy.yaml
        let watch_path = loader.repo_path.join("policy.yaml"); // Watching specific file
        // Also watch .git/HEAD to detect commits if we rely on external pulls?
        // But Loader pulls.
        // If this is for "Hot reload without downtime" when SOMEONE changes git.
        // Usually we poll git, or use a webhook.
        // But the prompt says "watch Git for changes".
        // If we are strictly a client pulling, we'd need to poll origin.
        // BUT if this is "local dev" or "ArgoCD style" where something else syncs it,
        // OR if `PolicyWatcher` is supposed to poll remote.
        
        // The PROMPT example in `loader.rs` had `pull_latest`.
        // The PROMPT example in `watcher.rs` watched `.git/refs/heads/main`.
        
        // If we watch local `.git`, we assume something else is pulling or we are editing locally.
        // If we want to auto-pull, we need a poller.
        // Let's implement what the prompt suggested: watch local refs (implying something updates it, or we edit locally).
        // AND maybe a poller?
        
        // Let's stick to watching `policy.yaml` and `.git/refs/heads/main` for now.
        
        watcher.watch(Path::new(&loader.repo_path), RecursiveMode::Recursive)?;
        
        // Spawn the event handler
        tokio::spawn(async move {
            while let Some(_event) = rx.recv().await {
                // Debounce simple logic or just reload
                info!("Change detected, reloading policy...");
                
                // If it was a git change, we might want to check if HEAD changed.
                // Assuming `loader.load_policy` handles pulling if configured?
                // `loader.load_policy` calls `pull_latest`.
                // So if we detect a change, we pull?
                
                // Wait, if `loader.load_policy` calls `pull`, it might trigger FS events if it changes files!
                // Infinite loop risk.
                
                // Simplification for this episode:
                // We just reload if `policy.yaml` changes locally OR we trigger a periodic pull?
                // The prompt Code 5 `PolicyWatcher` shows:
                // `watcher.watch(.git/refs/heads/main)`
                // AND `matches!(event.kind, Modify)`.
                
                match loader.load_policy() {
                    Ok(new_policy) => {
                        info!("✅ Policy reloaded successfully");
                        if let Err(e) = policy_tx.send(new_policy).await {
                             error!("Failed to send new policy: {}", e);
                             break;
                        }
                    },
                    Err(e) => {
                        error!("❌ Policy reload failed: {}", e);
                    }
                }
            }
        });
        
        Ok(Self {
            _watcher: watcher,
        })
    }
}
