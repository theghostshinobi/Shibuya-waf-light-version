// core/src/session/manager.rs

use anyhow::{anyhow, Result};
use std::sync::Arc;
use uuid::Uuid;
use chrono::{Utc, Duration};
use std::net::IpAddr;
use std::collections::HashMap;
use tracing::{warn, info};
use rand::RngCore;

use crate::session::store::{SessionStore, Session};

#[derive(Clone)]
pub struct SessionConfig {
    pub idle_timeout: Duration,         // e.g., 30 minutes
    pub absolute_timeout: Duration,     // e.g., 8 hours
    pub max_concurrent: u32,            // e.g., 3 sessions per user
    pub enable_hijacking_detection: bool,
}

pub struct SessionManager {
    store: Arc<SessionStore>,
    config: SessionConfig,
}

pub struct SessionRequest {
    pub ip_address: IpAddr,
    pub user_agent: String,
    pub accept_language: String,
    pub accept_encoding: String,
}

impl SessionManager {
    pub fn new(store: Arc<SessionStore>, config: SessionConfig) -> Self {
        Self { store, config }
    }

    /// Create new session
    pub async fn create_session(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        request: &SessionRequest,
    ) -> Result<Session> {
        // Check concurrent session limit
        let active_sessions = self.store.get_by_user(user_id).await?;
        if active_sessions.len() >= self.config.max_concurrent as usize {
            // Terminate oldest session
            if let Some(oldest) = active_sessions.last() {
                self.terminate_session(&oldest.id).await?;
            }
        }
        
        let session = Session {
            id: generate_session_id(),
            user_id,
            tenant_id,
            created_at: Utc::now(),
            last_active_at: Utc::now(),
            expires_at: Utc::now() + self.config.absolute_timeout,
            ip_address: request.ip_address,
            user_agent: request.user_agent.clone(),
            fingerprint: self.generate_fingerprint(request),
            mfa_verified: false,
            metadata: HashMap::new(),
        };
        
        // Store session
        self.store.save(&session).await?;
        
        info!("Session created for user {}: {}", user_id, session.id);
        
        Ok(session)
    }
    
    /// Validate session
    pub async fn validate_session(
        &self,
        session_id: &str,
        request: &SessionRequest,
    ) -> Result<Session> {
        let mut session = self.store.get(session_id).await?
            .ok_or_else(|| anyhow!("Session not found"))?;
        
        // Check expiration
        if session.expires_at < Utc::now() {
            self.terminate_session(session_id).await?;
            return Err(anyhow!("Session expired"));
        }
        
        // Check idle timeout
        let idle_limit = chrono::Duration::from_std(self.config.idle_timeout.to_std()?)?;
        if session.last_active_at + idle_limit < Utc::now() {
            self.terminate_session(session_id).await?;
            return Err(anyhow!("Session idle timeout"));
        }
        
        // Hijacking detection
        if self.config.enable_hijacking_detection {
            self.detect_hijacking(&session, request).await?;
        }
        
        // Update last active
        session.last_active_at = Utc::now();
        self.store.save(&session).await?;
        
        Ok(session)
    }
    
    /// Detect session hijacking
    async fn detect_hijacking(
        &self,
        session: &Session,
        request: &SessionRequest,
    ) -> Result<()> {
        // Check IP change
        if session.ip_address != request.ip_address {
            warn!(
                "Session {} IP changed: {} -> {}",
                session.id, session.ip_address, request.ip_address
            );
            
            // Require re-authentication
            return Err(anyhow!("Session security check failed: IP changed"));
        }
        
        // Check fingerprint change
        let current_fingerprint = self.generate_fingerprint(request);
        if session.fingerprint != current_fingerprint {
            warn!("Session {} fingerprint changed", session.id);
            return Err(anyhow!("Session security check failed: Fingerprint changed"));
        }
        
        Ok(())
    }
    
    fn generate_fingerprint(&self, request: &SessionRequest) -> String {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&request.user_agent);
        hasher.update(&request.accept_language);
        hasher.update(&request.accept_encoding);
        
        hex::encode(hasher.finalize())
    }
    
    /// Terminate session
    pub async fn terminate_session(&self, session_id: &str) -> Result<()> {
        self.store.delete(session_id).await?;
        info!("Session terminated: {}", session_id);
        Ok(())
    }
}

fn generate_session_id() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
