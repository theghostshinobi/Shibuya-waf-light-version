use axum::{
    extract::{State, Path},
    Json,
    http::StatusCode,
};
use sqlx::PgPool;
use anyhow::{Result, anyhow};
use core::tenancy::{Tenant, TenantSettings};
use core::tenancy::context::TenantContext;
use core::rbac::permissions::Permission;
use crate::middleware::rbac::check_permission;

pub async fn get_current_tenant(
    State(db): State<PgPool>,
) -> Result<Json<Tenant>, (StatusCode, String)> {
    check_permission(Permission::ManageTenant).await?;
    
    let tenant_id = TenantContext::tenant_id().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let tenant = sqlx::query_as::<_, Tenant>("SELECT * FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_one(&db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(tenant))
}

pub async fn update_tenant_settings(
    State(db): State<PgPool>,
    Json(payload): Json<TenantSettings>,
) -> Result<Json<Tenant>, (StatusCode, String)> {
    check_permission(Permission::ManageTenant).await?;
    
    let tenant_id = TenantContext::tenant_id().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let tenant = sqlx::query_as::<_, Tenant>(
        "UPDATE tenants SET settings = $1 WHERE id = $2 RETURNING *"
    )
    .bind(sqlx::types::Json(payload))
    .bind(tenant_id)
    .fetch_one(&db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(tenant))
}

// Admin only: list all tenants (internal use or super admin)
// Not exposed in main router yet
