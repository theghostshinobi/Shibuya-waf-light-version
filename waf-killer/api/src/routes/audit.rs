use axum::{
    extract::{State, Query},
    Json,
    http::StatusCode,
    response::IntoResponse,
};
use sqlx::PgPool;
use anyhow::Result;
use core::audit::export::AuditExporter;
use core::rbac::permissions::Permission;
use crate::middleware::rbac::check_permission;
use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct AuditParams {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
}

pub async fn get_audit_log(
    State(db): State<PgPool>,
    Query(params): Query<AuditParams>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    check_permission(Permission::ViewAuditLog).await?;
    
    // Reusing export logic for simplicity, but usually we'd have a JSON endpoint too.
    // The prompt asked for "export", so let's return CSV.
    
    let csv = AuditExporter::export_csv(&db, params.from, params.to)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
    Ok(([
        ("Content-Type", "text/csv"),
        ("Content-Disposition", "attachment; filename=\"audit.csv\"")
    ], csv))
}
