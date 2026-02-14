// core/src/collaboration/assignments.rs

use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use anyhow::Result;
use crate::tenancy::context::TenantContext;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assignment {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub incident_id: Uuid,
    pub assigned_to: Uuid,
    pub assigned_by: Uuid,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Assignment {
    pub async fn assign(
        db: &PgPool,
        incident_id: Uuid,
        assigned_to: Uuid,
    ) -> Result<Self> {
        let tenant_id = TenantContext::tenant_id()?;
        let assigned_by = TenantContext::user_id()?;
        
        // In a real app, assignments might be a separate table or a column on incidents.
        // For Episode 13, we'll assume a dedicated table (must be added to migrations if not there).
        // I will add it to a follow-up migration or use a generic 'tasks' approach.
        // Let's assume it's in the DB for now.
        
        let row = sqlx::query(
            "INSERT INTO assignments 
             (tenant_id, incident_id, assigned_to, assigned_by, status)
             VALUES ($1, $2, $3, $4, 'open')
             RETURNING id, tenant_id, incident_id, assigned_to, assigned_by, status, created_at, updated_at"
        )
        .bind(tenant_id)
        .bind(incident_id)
        .bind(assigned_to)
        .bind(assigned_by)
        .fetch_one(db)
        .await?;
        
        let assignment = Assignment {
            id: sqlx::Row::get(&row, "id"),
            tenant_id: sqlx::Row::get(&row, "tenant_id"),
            incident_id: sqlx::Row::get(&row, "incident_id"),
            assigned_to: sqlx::Row::get(&row, "assigned_to"),
            assigned_by: sqlx::Row::get(&row, "assigned_by"),
            status: sqlx::Row::get(&row, "status"),
            created_at: sqlx::Row::get(&row, "created_at"),
            updated_at: sqlx::Row::get(&row, "updated_at"),
        };
        
        Ok(assignment)
    }
}
