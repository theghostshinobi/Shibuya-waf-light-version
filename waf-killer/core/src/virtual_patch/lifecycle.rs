use anyhow::Result;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::Utc;
use crate::virtual_patch::generator::VirtualPatch;

pub struct PatchLifecycleManager {
    db: PgPool,
    active_patches: Arc<RwLock<HashMap<String, VirtualPatch>>>,
    // We would need a reference to the RuleEngine to notify it
}

impl PatchLifecycleManager {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            active_patches: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn activate_patch(&self, patch: VirtualPatch) -> Result<()> {
        // 1. Store in database
        let id_uuid = uuid::Uuid::parse_str(&patch.id)?;
        let rules_json = serde_json::to_value(&patch.rules)?;
        
        sqlx::query(
            "INSERT INTO virtual_patches 
             (id, cve_id, rules, created_at, expires_at, verified, active)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (id) DO UPDATE 
             SET active = $7, verified = $6, expires_at = $5"
        )
        .bind(id_uuid)
        .bind(&patch.cve_id)
        .bind(&rules_json)
        .bind(patch.created_at.naive_utc())
        .bind(patch.expires_at.map(|d| d.naive_utc()))
        .bind(patch.verified)
        .bind(patch.active)
        .execute(&self.db)
        .await?;
        
        // 2. Add to active patches (hot-reload)
        {
            let mut patches = self.active_patches.write().await;
            patches.insert(patch.id.clone(), patch.clone());
        }
        
        // 3. Notify rule engine to reload (Placeholder)
        // self.notify_rule_engine_reload().await?;
        
        println!("Virtual patch activated: {} (CVE: {})", patch.id, patch.cve_id);
        
        Ok(())
    }
    
    pub async fn deactivate_patch(&self, patch_id: &str) -> Result<()> {
        let id_uuid = uuid::Uuid::parse_str(patch_id)?;

        // 1. Mark as inactive in database
        sqlx::query(
            "UPDATE virtual_patches SET active = false WHERE id = $1"
        )
        .bind(id_uuid)
        .execute(&self.db)
        .await?;
        
        // 2. Remove from active patches
        {
            let mut patches = self.active_patches.write().await;
            patches.remove(patch_id);
        }
        
        // 3. Notify rule engine (Placeholder)
        // self.notify_rule_engine_reload().await?;
        
        println!("Virtual patch deactivated: {}", patch_id);
        
        Ok(())
    }
    
    pub async fn check_expiry(&self) -> Result<()> {
        // Run periodically to auto-deactivate expired patches
        
        let rows = sqlx::query(
            "SELECT id, cve_id, rules, created_at, expires_at, verified, active FROM virtual_patches 
             WHERE active = true 
             AND expires_at IS NOT NULL 
             AND expires_at < NOW()"
        )
        .fetch_all(&self.db)
        .await?;
        
        for row in rows {
            let id: uuid::Uuid = sqlx::Row::get(&row, "id");
            let id_str = id.to_string();
            println!("Auto-deactivating expired patch: {}", id_str);
            self.deactivate_patch(&id_str).await?;
        }
        
        Ok(())
    }
    
    pub async fn get_active_patches(&self) -> Vec<VirtualPatch> {
        let patches = self.active_patches.read().await;
        patches.values().cloned().collect()
    }
}
