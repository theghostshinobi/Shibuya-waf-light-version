use chrono::{DateTime, Utc};
use uuid::Uuid;
use sqlx::PgPool;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use crate::tenancy::context::TenantContext;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditEntry {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub changes: Option<sqlx::types::Json<serde_json::Value>>,  // Before/after
    pub ip_address: Option<String>, // INET type in db, mapped to string
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl AuditEntry {
    pub async fn log(
        db: &PgPool,
        action: &str,
        resource_type: &str,
        resource_id: &str,
        changes: Option<serde_json::Value>,
    ) -> Result<()> {
        let tenant_id = TenantContext::tenant_id().unwrap_or_default();
        let user_id = TenantContext::user_id().ok();
        
        let changes_json = changes.map(|v| sqlx::types::Json(v));

        sqlx::query(
            "INSERT INTO audit_log 
             (tenant_id, user_id, action, resource_type, resource_id, changes)
             VALUES ($1, $2, $3, $4, $5, $6)"
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(changes_json)
        .execute(db)
        .await?;
        
        Ok(())
    }
}
