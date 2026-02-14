use tokio::task_local;
use uuid::Uuid;
use anyhow::{anyhow, Result};
use std::future::Future;
use crate::rbac::roles::Role;
use crate::rbac::permissions::Permission;

// Thread-local tenant context
task_local! {
    pub static TENANT_CONTEXT: TenantContext;
}

#[derive(Clone, Debug)]
pub struct TenantContext {
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    pub user_id: Option<Uuid>,
    pub user_role: Option<Role>,
}

impl TenantContext {
    pub fn current() -> Result<Self> {
        TENANT_CONTEXT.try_with(|ctx| ctx.clone())
            .map_err(|_| anyhow!("No tenant context available. Are you running inside with_tenant_context?"))
    }
    
    pub fn tenant_id() -> Result<Uuid> {
        Ok(Self::current()?.tenant_id)
    }
    
    pub fn user_id() -> Result<Uuid> {
        Self::current()?
            .user_id
            .ok_or_else(|| anyhow!("No user in context"))
    }
    
    pub fn has_permission(&self, permission: Permission) -> bool {
        if let Some(role) = &self.user_role {
            Role::has_permission(role, permission)
        } else {
            false
        }
    }
}

// Middleware/Helper to set tenant context
pub async fn with_tenant_context<F, R>(
    tenant_id: Uuid,
    tenant_slug: String,
    user_id: Option<Uuid>,
    user_role: Option<Role>,
    f: F,
) -> R
where
    F: Future<Output = R>,
{
    let ctx = TenantContext {
        tenant_id,
        tenant_slug,
        user_id,
        user_role,
    };
    
    TENANT_CONTEXT.scope(ctx, f).await
}
