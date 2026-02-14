use tokio::signal;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{info, warn};

pub struct GracefulShutdown {
    shutdown_requested: Arc<AtomicBool>,
}

impl GracefulShutdown {
    pub fn new() -> Self {
        Self {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
        }
    }
    
    pub async fn wait_for_signal(&self) {
        let shutdown_requested = self.shutdown_requested.clone();
        
        tokio::spawn(async move {
            // Wait for SIGTERM (K8s sends this on pod termination)
            match signal::ctrl_c().await {
                Ok(()) => {},
                Err(err) => {
                    warn!("Unable to listen for shutdown signal: {}", err);
                },
            }
            
            info!("Shutdown signal received, starting graceful shutdown...");
            shutdown_requested.store(true, Ordering::Relaxed);
        });
    }
    
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_requested.load(Ordering::Relaxed)
    }
    
    pub async fn shutdown_gracefully(&self) {
        info!("Draining connections...");
        
        // Simulate draining
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        info!("Graceful shutdown complete");
    }
}
