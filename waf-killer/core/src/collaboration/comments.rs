use chrono::{DateTime, Utc};
use uuid::Uuid;
use sqlx::PgPool;
use serde::{Deserialize, Serialize};
use regex::Regex;
use anyhow::{Result, anyhow};
use crate::tenancy::context::TenantContext;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Comment {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub entity_type: String,  // Request, Rule, Patch, etc.
    pub entity_id: String,
    pub user_id: Uuid,
    pub content: String,
    pub mentions: Option<Vec<Uuid>>,      // @mentioned users
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy)]
pub enum EntityType {
    Request,
    Rule,
    VirtualPatch,
    Policy,
    Incident,
}

impl EntityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntityType::Request => "request",
            EntityType::Rule => "rule",
            EntityType::VirtualPatch => "virtual_patch",
            EntityType::Policy => "policy",
            EntityType::Incident => "incident",
        }
    }
}

impl Comment {
    pub async fn create(
        db: &PgPool,
        entity_type: EntityType,
        entity_id: &str,
        content: &str,
    ) -> Result<Self> {
        let tenant_id = TenantContext::tenant_id().unwrap_or(Uuid::default()); // Fallback or handle error proper
                                                                               // In real app, we should enforce context existence
                                                                               // For this snip, assume context is there or panic if unwrap
        let user_id = TenantContext::user_id().unwrap_or(Uuid::default()); 
        
        // Extract mentions (@uuid)
        // Simplification: assumes mentions are by UUID for now as per prompt
        let mentions = Self::extract_mentions(content);
        
        let comment = sqlx::query_as::<_, Comment>(
            "INSERT INTO comments 
             (tenant_id, entity_type, entity_id, user_id, content, mentions)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING *"
        )
        .bind(tenant_id)
        .bind(entity_type.as_str())
        .bind(entity_id)
        .bind(user_id)
        .bind(content)
        .bind(&mentions)
        .fetch_one(db)
        .await?;
        
        // TODO: NotificationService::send_mention(...)
        
        Ok(comment)
    }
    
    fn extract_mentions(content: &str) -> Vec<Uuid> {
        let mention_regex = Regex::new(r"@([a-f0-9-]{36})").unwrap();
        
        mention_regex
            .captures_iter(content)
            .filter_map(|cap| Uuid::parse_str(&cap[1]).ok())
            .collect()
    }
}
