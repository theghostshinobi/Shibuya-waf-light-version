// core/src/api/team.rs

use axum::{
    extract::{Path, State},
    Json,
    http::StatusCode,
};
use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use crate::http::ApiState;
use waf_killer_core::tenancy::context::TenantContext;
use waf_killer_core::rbac::roles::Role;

#[derive(Serialize, Deserialize)]
pub struct TeamMember {
    pub id: Uuid,
    pub user_id: Uuid,
    pub role: Role,
    pub name: Option<String>,
    pub email: String,
}

pub async fn list_team_members(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<Vec<TeamMember>>, crate::http::ApiError> {
    let tenant_id = TenantContext::tenant_id().map_err(|e| crate::http::ApiError::Internal(e.to_string()))?;
    
    let members = sqlx::query_as!(
        TeamMember,
        "SELECT tm.id, tm.user_id, tm.role as \"role: _\", u.name, u.email 
         FROM team_members tm
         JOIN users u ON tm.user_id = u.id
         WHERE tm.tenant_id = $1",
        tenant_id
    )
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| crate::http::ApiError::Internal(e.to_string()))?;
    
    Ok(Json(members))
}

#[derive(Deserialize)]
pub struct InviteRequest {
    pub email: String,
    pub role: Role,
}

pub async fn invite_member(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<InviteRequest>,
) -> Result<Json<TeamMember>, crate::http::ApiError> {
    let tenant_id = TenantContext::tenant_id().map_err(|e| crate::http::ApiError::Internal(e.to_string()))?;
    
    // 1. Find or create user
    let user_id = sqlx::query_scalar!(
        "INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id",
        payload.email
    )
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| crate::http::ApiError::Internal(e.to_string()))?;
    
    // 2. Add to team
    let member = sqlx::query_as!(
        TeamMember,
        "INSERT INTO team_members (tenant_id, user_id, role) VALUES ($1, $2, $3)
         RETURNING id, user_id, role as \"role: _\", (SELECT name FROM users WHERE id = $2) as name, (SELECT email FROM users WHERE id = $2) as email",
        tenant_id,
        user_id,
        payload.role as Role
    )
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| crate::http::ApiError::Internal(e.to_string()))?;
    
    Ok(Json(member))
}

pub async fn remove_member(
    State(state): State<Arc<ApiState>>,
    Path(member_id): Path<Uuid>,
) -> Result<StatusCode, crate::http::ApiError> {
    let tenant_id = TenantContext::tenant_id().map_err(|e| crate::http::ApiError::Internal(e.to_string()))?;
    
    sqlx::query!(
        "DELETE FROM team_members WHERE id = $1 AND tenant_id = $2",
        member_id,
        tenant_id
    )
    .execute(&state.db_pool)
    .await
    .map_err(|e| crate::http::ApiError::Internal(e.to_string()))?;
    
    Ok(StatusCode::NO_CONTENT)
}
