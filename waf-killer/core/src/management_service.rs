use pingora::services::background::BackgroundService;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, error};
use crate::health::{HealthMonitor, health_routes};
use crate::telemetry::Telemetry;
use crate::graceful_shutdown::GracefulShutdown;
use axum::{Router, routing::get};
use std::net::SocketAddr;

pub struct ManagementService {
    pub health: Arc<HealthMonitor>,
    pub port: u16,
}

#[async_trait::async_trait]
#[async_trait::async_trait]
impl BackgroundService for ManagementService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        // Start health check
        let hm_bg = self.health.clone();
        tokio::spawn(async move {
            hm_bg.run_loop().await;
        });

        let app = Router::new()
            .merge(health_routes())
            .route("/metrics", get(|| async {
                let body = Telemetry::gather_metrics();
                body
            }));

        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        info!("Management server listening on {}", addr);

        let server = axum::Server::bind(&addr)
            .serve(app.into_make_service());

        // Handle graceful shutdown
        let graceful = server.with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
            info!("Management service shutting down");
        });

        if let Err(e) = graceful.await {
            error!("Management server error: {}", e);
        }
    }
}
