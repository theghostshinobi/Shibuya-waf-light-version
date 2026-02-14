use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::State,
    response::IntoResponse,
};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::broadcast;
use futures::{sink::SinkExt, stream::StreamExt};
use tracing::{info, error};

pub struct WebSocketState {
    pub tx: broadcast::Sender<Event>,
}

#[derive(Clone, Serialize, Debug)]
#[serde(tag = "type", content = "data")]
pub enum Event {
    NewRequest(RequestSummary),
    StatsUpdate(Stats),
    Alert(Alert),
    Activity(waf_killer_core::collaboration::activity::Activity),

}

#[derive(Clone, Serialize, Debug)]
pub struct RequestSummary {
    pub id: String,
    pub timestamp: i64,
    pub method: String,
    pub url: String,
    pub client_ip: String,
    pub action: String, // ALLOW, BLOCK
    pub reason: String,
    pub crs_score: u32,
    pub ml_score: f32,
    pub latency_ms: u64,
}

#[derive(Clone, Serialize, Debug)]
pub struct Stats {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub ml_detections: u64,
    pub avg_latency_ms: f64,
    pub requests_per_sec: f64,
}

#[derive(Clone, Serialize, Debug)]
pub struct Alert {
    pub level: String, // info, warning, error
    pub message: String,
    pub timestamp: i64,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WebSocketState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<WebSocketState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.tx.subscribe();
    
    info!("New WebSocket connection established");

    // Spawn task to forward events to client
    let mut send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            let json = match serde_json::to_string(&event) {
                Ok(j) => j,
                Err(e) => {
                    error!("Failed to serialize event: {}", e);
                    continue;
                }
            };
            
            if sender.send(Message::Text(json)).await.is_err() {
                break;
            }
        }
    });

    // Keep connection alive
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Close(_) => break,
                Message::Ping(_) => {}, // Acknowledge generic ping if needed, but axum handles it usually
                 _ => {},
            }
        }
    });
    
    // Select to wait for either to finish
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };
    
    info!("WebSocket connection closed");
}

pub fn broadcast_request(state: &WebSocketState, request: RequestSummary) {
    let _ = state.tx.send(Event::NewRequest(request));
}

pub fn broadcast_stats(state: &WebSocketState, stats: Stats) {
    let _ = state.tx.send(Event::StatsUpdate(stats));
}
