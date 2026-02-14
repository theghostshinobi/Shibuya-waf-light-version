// core/src/api/tenant.rs

use axum::{
    extract::{Path, State},
    Json,
};
use std::sync::Arc;
use uuid::Uuid;
use crate::http::ApiState;
use waf_killer_core::tenancy::Tenant;
use waf_killer_core::tenancy::context::TenantContext;
use anyhow::{Result, anyhow};

pub async fn get_current_tenant(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<Tenant>, crate::http::ApiError> {
    let tenant_id = TenantContext::tenant_id().map_err(|e| crate::http::ApiError::Internal(e.to_string()))?;
    
    let tenant = sqlx::query_as!(
        Tenant,
        "SELECT id, slug, name, plan as \"plan: _\", status as \"status: _\", settings, quotas, created_at, updated_at 
         FROM tenants WHERE id = $1",
        tenant_id
    )
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| crate::http::ApiError::NotFound(format!("Tenant not found: {}", e)))?;
    
    Ok(Json(tenant))
}

pub async fn update_tenant_settings(
    State(state): State<Arc<ApiState>>,
    Json(settings): Json<serde_json::Value>,
) -> Result<Json<Tenant>, crate::http::ApiError> {
    let tenant_id = TenantContext::tenant_id().map_err(|e| crate::http::ApiError::Internal(e.to_string()))?;
    
    let tenant = sqlx::query_as!(
        Tenant,
        "UPDATE tenants SET settings = $1, updated_at = NOW() WHERE id = $2 
         RETURNING id, slug, name, plan as \"plan: _\", status as \"status: _\", settings, quotas, created_at, updated_at",
        settings,
        tenant_id
    )
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| crate::http::ApiError::Internal(e.to_string()))?;
    
    Ok(Json(tenant))
}
