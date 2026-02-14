// core/src/shadow/rollout.rs

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;
use crate::shadow::watchdog::Watchdog;
use tracing::{info, warn, error};
use ahash::AHasher;
use std::hash::{Hash, Hasher};

pub struct GradualRollout {
    current_percentage: Arc<AtomicU8>,
    target_percentage: u8,
    increment_interval: Duration,
    watchdog: Arc<Watchdog>,
}

impl GradualRollout {
    pub fn new(
        start_percentage: u8,
        target_percentage: u8,
        increment_interval: Duration,
        watchdog: Arc<Watchdog>,
    ) -> Self {
        Self {
            current_percentage: Arc::new(AtomicU8::new(start_percentage)),
            target_percentage,
            increment_interval,
            watchdog,
        }
    }
    
    pub async fn start_rollout(&self) -> anyhow::Result<()> {
        let current = self.current_percentage.clone();
        let target = self.target_percentage;
        let interval = self.increment_interval;
        let watchdog = self.watchdog.clone();
        
        tokio::spawn(async move {
            info!("Starting gradual rollout: target {}%", target);
            loop {
                tokio::time::sleep(interval).await;
                
                let current_val = current.load(Ordering::Relaxed);
                
                if current_val >= target {
                    info!("Rollout complete: {}%", current_val);
                    break;
                }
                
                // Check watchdog before incrementing
                if watchdog.should_rollback().await {
                    error!("Watchdog triggered! Rolling back rollout...");
                    current.store(0, Ordering::SeqCst);
                    break;
                }
                
                // Increment by 10% or remaining
                let new_val = (current_val + 10).min(target);
                current.store(new_val, Ordering::SeqCst);
                
                info!("Rollout progress: {}%", new_val);
            }
        });
        
        Ok(())
    }
    
    pub fn get_current_percentage(&self) -> u8 {
        self.current_percentage.load(Ordering::Relaxed)
    }
    
    pub fn should_use_new_policy(&self, request_id: &str) -> bool {
        let percentage = self.get_current_percentage();
        
        if percentage == 0 {
            return false;
        }
        if percentage >= 100 {
            return true;
        }
        
        // Deterministic selection based on request_id
        let mut hasher = AHasher::default();
        request_id.hash(&mut hasher);
        let hash = hasher.finish();
        ((hash % 100) as u8) < percentage
    }
}
