use chrono::{DateTime, Utc};
use uuid::Uuid;
use sqlx::PgPool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use anyhow::Result;
use crate::tenancy::context::TenantContext;
use tokio::sync::broadcast;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref ACTIVITY_BROADCAST: broadcast::Sender<Activity> = {
        let (tx, _) = broadcast::channel(100);
        tx
    };
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Activity {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    // Joined field, might be null if just selecting form table without join
    #[sqlx(default)] 
    pub user_name: Option<String>,
    pub action: sqlx::types::Json<ActivityAction>,
    pub entity_type: Option<String>,
    pub entity_id: Option<String>,
    pub metadata: Option<sqlx::types::Json<serde_json::Value>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ActivityAction {
    RuleCreated { rule_name: String },
    RuleEnabled { rule_id: String },
    RuleDisabled { rule_id: String },
    PolicyDeployed { policy_version: String },
    PatchActivated { cve_id: String },
    PatchDeactivated { patch_id: String },
    MemberInvited { email: String },
    MemberRemoved { user_name: String },
    CommentAdded { on: String },
    IncidentAssigned { to: String },
}

impl Activity {
    pub async fn log(
        db: &PgPool,
        action: ActivityAction,
        entity_type: &str,
        entity_id: &str,
    ) -> Result<()> {
        let tenant_id = TenantContext::tenant_id().unwrap_or_default();
        let user_id = TenantContext::user_id().unwrap_or_default();
        
        // 1. Insert into DB
        let activity = sqlx::query_as::<_, Activity>(
            "INSERT INTO activities 
             (tenant_id, user_id, action, entity_type, entity_id, metadata)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING *"
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(serde_json::to_value(&action)?)
        .bind(entity_type)
        .bind(entity_id)
        .bind(serde_json::to_value(json!({}))?)
        .fetch_one(db)
        .await?;
        
        // 2. Broadcast to subscribers (WebSockets)
        // We ignore error if no subscribers
        let _ = ACTIVITY_BROADCAST.send(activity);
        
        Ok(())
    }
    
    pub async fn get_feed(
        db: &PgPool,
        limit: i64,
    ) -> Result<Vec<Activity>> {
        let tenant_id = TenantContext::tenant_id()?;
        
        let activities = sqlx::query_as::<_, Activity>(
            "SELECT a.*, u.name as user_name
             FROM activities a
             JOIN users u ON a.user_id = u.id
             WHERE a.tenant_id = $1
             ORDER BY a.created_at DESC
             LIMIT $2"
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(db)
        .await?;
        
        Ok(activities)
    }
}
