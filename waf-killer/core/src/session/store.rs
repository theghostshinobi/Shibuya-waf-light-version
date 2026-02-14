// core/src/session/store.rs

use anyhow::Result;
use redis::{AsyncCommands, Client};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::net::IpAddr;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: IpAddr,
    pub user_agent: String,
    pub fingerprint: String,           // Device fingerprint
    pub mfa_verified: bool,
    pub metadata: HashMap<String, String>,
}

pub struct SessionStore {
    redis: Client,
}

impl SessionStore {
    pub fn new(redis: Client) -> Self {
        Self { redis }
    }

    pub async fn save(&self, session: &Session) -> Result<()> {
        let mut conn = self.redis.get_multiplexed_tokio_connection().await?;
        let key = format!("session:{}", session.id);
        let value = serde_json::to_string(session)?;
        
        // Store with TTL
        let ttl = (session.expires_at - Utc::now()).num_seconds();
        if ttl > 0 {
            let _: () = conn.set_ex(&key, &value, ttl as u64).await?;
        }
        
        // Index by user_id for quick lookup
        let user_key = format!("user_sessions:{}", session.user_id);
        let _: () = conn.sadd(&user_key, &session.id).await?;
        
        Ok(())
    }
    
    pub async fn get(&self, session_id: &str) -> Result<Option<Session>> {
        let mut conn = self.redis.get_multiplexed_tokio_connection().await?;
        let key = format!("session:{}", session_id);
        
        let value: Option<String> = conn.get(&key).await?;
        
        match value {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }
    
    pub async fn delete(&self, session_id: &str) -> Result<()> {
        let mut conn = self.redis.get_multiplexed_tokio_connection().await?;
        
        // Get session first to find user_id for indexing cleanup
        if let Some(session) = self.get(session_id).await? {
            let key = format!("session:{}", session_id);
            let _: () = conn.del(&key).await?;
            
            let user_key = format!("user_sessions:{}", session.user_id);
            let _: () = conn.srem(&user_key, session_id).await?;
        }
        
        Ok(())
    }
    
    pub async fn get_by_user(&self, user_id: Uuid) -> Result<Vec<Session>> {
        let mut conn = self.redis.get_multiplexed_tokio_connection().await?;
        let user_key = format!("user_sessions:{}", user_id);
        
        let session_ids: Vec<String> = conn.smembers(&user_key).await?;
        
        let mut sessions = Vec::new();
        for session_id in session_ids {
            if let Some(session) = self.get(&session_id).await? {
                sessions.push(session);
            } else {
                // Cleanup orphaned index
                conn.srem::<_, _, ()>(&user_key, &session_id).await?;
            }
        }
        
        // Sort by created_at desc
        sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        
        Ok(sessions)
    }
}
