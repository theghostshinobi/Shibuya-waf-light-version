use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use uuid::Uuid;
use chrono::Utc;
use super::{Tenant, TenantPlan, TenantStatus, TenantSettings, TenantQuotas};

/// In-memory storage for tenants (production: use DB)
pub struct TenantStore {
    tenants: Arc<RwLock<HashMap<Uuid, Tenant>>>,
}

impl TenantStore {
    pub fn new() -> Self {
        let mut tenants = HashMap::new();
        
        let default_id = Uuid::nil(); // Using Nil UUID for default for simplicity or a fixed one
        
        // Seed con tenant di default per testing
        let default_tenant = Tenant {
            id: default_id,
            slug: "default".to_string(),
            name: "Default Organization".to_string(),
            plan: TenantPlan::Free,
            status: TenantStatus::Active,
            created_at: Utc::now(),
            settings: sqlx::types::Json(TenantSettings {
                logo_url: None,
                primary_color: "#4F46E5".to_string(),
                timezone: "UTC".to_string(),
                retention_days: 7,
                slack_webhook: None,
                pagerduty_key: None,
            }),
            quotas: sqlx::types::Json(TenantQuotas::for_plan(&TenantPlan::Free)),
        };
        
        tenants.insert(default_id, default_tenant);
        
        Self {
            tenants: Arc::new(RwLock::new(tenants)),
        }
    }
    
    /// Get all tenants
    pub async fn list_all(&self) -> Vec<Tenant> {
        let lock = self.tenants.read().await;
        lock.values().cloned().collect()
    }
    
    /// Get tenant by ID
    pub async fn get_by_id(&self, id: &Uuid) -> Option<Tenant> {
        let lock = self.tenants.read().await;
        lock.get(id).cloned()
    }
    
    /// Count total tenants
    pub async fn count(&self) -> usize {
        let lock = self.tenants.read().await;
        lock.len()
    }

    /// Create new tenant
    pub async fn create(&self, mut tenant: Tenant) -> anyhow::Result<Tenant> {
        let mut lock = self.tenants.write().await;
        
        if tenant.id.is_nil() {
            tenant.id = Uuid::new_v4();
        }
        
        // Check if ID already exists
        if lock.contains_key(&tenant.id) {
            return Err(anyhow::anyhow!("Tenant with ID {} already exists", tenant.id));
        }
        
        // Check if slug already exists
        for existing in lock.values() {
            if existing.slug == tenant.slug {
                return Err(anyhow::anyhow!("Slug {} is already registered", tenant.slug));
            }
        }
        
        // Validation
        if tenant.name.is_empty() {
            return Err(anyhow::anyhow!("Tenant name cannot be empty"));
        }
        if tenant.slug.is_empty() {
            return Err(anyhow::anyhow!("Tenant slug cannot be empty"));
        }
        
        tenant.created_at = Utc::now();
        
        lock.insert(tenant.id, tenant.clone());
        Ok(tenant)
    }

    /// Update existing tenant
    pub async fn update(&self, id: &Uuid, updates: crate::tenancy::TenantUpdate) -> anyhow::Result<Tenant> {
        let mut lock = self.tenants.write().await;
        
        // Check slug uniqueness BEFORE getting mutable reference to tenant
        if let Some(slug) = &updates.slug {
            if slug.is_empty() {
                return Err(anyhow::anyhow!("Tenant slug cannot be empty"));
            }
            for (other_id, other_tenant) in lock.iter() {
                if other_id != id && other_tenant.slug == *slug {
                    return Err(anyhow::anyhow!("Slug {} is already in use", slug));
                }
            }
        }

        let tenant = lock.get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("Tenant not found: {}", id))?;
        
        // Apply updates
        if let Some(name) = updates.name {
            if name.is_empty() {
                return Err(anyhow::anyhow!("Tenant name cannot be empty"));
            }
            tenant.name = name;
        }
        if let Some(slug) = updates.slug {
            tenant.slug = slug;
        }
        if let Some(plan) = updates.plan {
            tenant.plan = plan;
            // Update quotas based on new plan
            tenant.quotas = sqlx::types::Json(crate::tenancy::TenantQuotas::for_plan(&tenant.plan));
        }
        if let Some(status) = updates.status {
            tenant.status = status;
        }
        if let Some(settings) = updates.settings {
            tenant.settings = sqlx::types::Json(settings);
        }
        
        Ok(tenant.clone())
    }

    /// Delete tenant (soft delete)
    pub async fn delete(&self, id: &Uuid) -> anyhow::Result<()> {
        let mut lock = self.tenants.write().await;
        
        // Prevent deletion of default tenant
        if id.is_nil() {
            return Err(anyhow::anyhow!("Cannot delete default tenant"));
        }
        
        let tenant = lock.get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("Tenant not found: {}", id))?;
        
        // Soft delete: change status
        tenant.status = crate::tenancy::TenantStatus::Disabled;
        
        Ok(())
    }
}

impl Default for TenantStore {
    fn default() -> Self {
        Self::new()
    }
}
