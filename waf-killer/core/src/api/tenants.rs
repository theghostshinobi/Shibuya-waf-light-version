use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::tenancy::{Tenant, TenantUpdate};

#[derive(serde::Serialize)]
pub struct TenantsListResponse {
    pub tenants: Vec<Tenant>,
    pub total: usize,
}

/// GET /api/tenants - List all tenants
pub async fn list_tenants_handler(
    State(state): State<Arc<crate::state::WafState>>,
) -> Result<Json<TenantsListResponse>, StatusCode> {
    let tenants: Vec<Tenant> = state.tenant_store.list_all().await;
    let total = tenants.len();
    
    Ok(Json(TenantsListResponse {
        tenants,
        total,
    }))
}

/// GET /api/tenants/:id - Get single tenant
pub async fn get_tenant_handler(
    State(state): State<Arc<crate::state::WafState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<Tenant>, StatusCode> {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };
    
    match state.tenant_store.get_by_id(&uuid).await {
        Some(tenant) => Ok(Json(tenant)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// POST /api/tenants - Create new tenant
pub async fn create_tenant_handler(
    State(state): State<Arc<crate::state::WafState>>,
    Json(tenant): Json<Tenant>,
) -> Result<(StatusCode, Json<Tenant>), (StatusCode, String)> {
    match state.tenant_store.create(tenant).await {
        Ok(created) => Ok((StatusCode::CREATED, Json(created))),
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

/// PUT /api/tenants/:id - Update tenant
pub async fn update_tenant_handler(
    State(state): State<Arc<crate::state::WafState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(updates): Json<TenantUpdate>,
) -> Result<Json<Tenant>, (StatusCode, String)> {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return Err((StatusCode::BAD_REQUEST, "Invalid UUID".to_string())),
    };

    match state.tenant_store.update(&uuid, updates).await {
        Ok(updated) => Ok(Json(updated)),
        Err(e) => {
            if e.to_string().contains("not found") {
                Err((StatusCode::NOT_FOUND, e.to_string()))
            } else {
                Err((StatusCode::BAD_REQUEST, e.to_string()))
            }
        }
    }
}

/// DELETE /api/tenants/:id - Delete tenant
pub async fn delete_tenant_handler(
    State(state): State<Arc<crate::state::WafState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return Err((StatusCode::BAD_REQUEST, "Invalid UUID".to_string())),
    };

    match state.tenant_store.delete(&uuid).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            if e.to_string().contains("not found") {
                Err((StatusCode::NOT_FOUND, e.to_string()))
            } else if e.to_string().contains("Cannot delete") {
                Err((StatusCode::FORBIDDEN, e.to_string()))
            } else {
                Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
            }
        }
    }
}

pub fn routes() -> axum::Router<Arc<crate::state::WafState>> {
    use axum::routing::get;
    
    axum::Router::new()
        .route("/tenants", get(list_tenants_handler).post(create_tenant_handler))
        .route("/tenants/:id", get(get_tenant_handler).put(update_tenant_handler).delete(delete_tenant_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenancy::store::TenantStore;
    use crate::tenancy::{TenantPlan, TenantStatus, TenantSettings, TenantQuotas};
    use chrono::Utc;

    // We can't easily test the full Axum handler without more boilerplate,
    // but we can test the store logic which is the core part.
    
    #[tokio::test]
    async fn test_store_list_tenants() {
        let store = TenantStore::new();
        
        // Il default tenant deve esistere
        let tenants: Vec<crate::tenancy::Tenant> = store.list_all().await;
        assert!(!tenants.is_empty());
        assert_eq!(tenants[0].slug, "default");
    }
    
    #[tokio::test]
    async fn test_store_get_tenant_by_id() {
        let store = TenantStore::new();
        
        let tenant: Option<crate::tenancy::Tenant> = store.get_by_id(&Uuid::nil()).await;
        assert!(tenant.is_some());
        assert_eq!(tenant.unwrap().name, "Default Organization");
    }

    #[tokio::test]
    async fn test_store_create_tenant() {
        let store = TenantStore::new();
        
        let new_tenant = Tenant {
            id: Uuid::new_v4(),
            slug: "test-corp".to_string(),
            name: "Test Corp".to_string(),
            plan: TenantPlan::Startup,
            status: TenantStatus::Active,
            created_at: Utc::now(),
            settings: sqlx::types::Json(TenantSettings {
                logo_url: None,
                primary_color: "#000000".to_string(),
                timezone: "UTC".to_string(),
                retention_days: 30,
                slack_webhook: None,
                pagerduty_key: None,
            }),
            quotas: sqlx::types::Json(TenantQuotas::for_plan(&TenantPlan::Startup)),
        };
        
        let created = store.create(new_tenant).await.unwrap();
        assert_eq!(created.name, "Test Corp");
        assert_eq!(created.slug, "test-corp");
    }
    
    #[tokio::test]
    async fn test_store_update_tenant() {
        let store = TenantStore::new();
        
        let updates = TenantUpdate {
            name: Some("Updated Name".to_string()),
            slug: None,
            plan: Some(TenantPlan::Business),
            status: None,
            settings: None,
        };
        
        let updated = store.update(&Uuid::nil(), updates).await.unwrap();
        assert_eq!(updated.name, "Updated Name");
        assert_eq!(updated.plan, TenantPlan::Business);
    }
    
    #[tokio::test]
    async fn test_store_delete_tenant() {
        let store = TenantStore::new();
        
        // Create a tenant to delete
        let id = Uuid::new_v4();
        let tenant = Tenant {
            id,
            slug: "delete-me".to_string(),
            name: "To Delete".to_string(),
            plan: TenantPlan::Free,
            status: TenantStatus::Active,
            created_at: Utc::now(),
            settings: sqlx::types::Json(TenantSettings {
                logo_url: None,
                primary_color: "#000000".to_string(),
                timezone: "UTC".to_string(),
                retention_days: 7,
                slack_webhook: None,
                pagerduty_key: None,
            }),
            quotas: sqlx::types::Json(TenantQuotas::for_plan(&TenantPlan::Free)),
        };
        store.create(tenant).await.unwrap();
        
        // Delete it
        let result = store.delete(&id).await;
        assert!(result.is_ok());
        
        // Check status
        let deleted = store.get_by_id(&id).await.unwrap();
        assert_eq!(deleted.status, TenantStatus::Disabled);
    }
    
    #[tokio::test]
    async fn test_store_cannot_delete_default() {
        let store = TenantStore::new();
        
        let result = store.delete(&Uuid::nil()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cannot delete"));
    }
    
    #[tokio::test]
    async fn test_store_duplicate_slug_rejected() {
        let store = TenantStore::new();
        
        let tenant1 = Tenant {
            id: Uuid::new_v4(),
            slug: "duplicate".to_string(),
            name: "Tenant 1".to_string(),
            plan: TenantPlan::Free,
            status: TenantStatus::Active,
            created_at: Utc::now(),
            settings: sqlx::types::Json(TenantSettings {
                logo_url: None,
                primary_color: "#000000".to_string(),
                timezone: "UTC".to_string(),
                retention_days: 7,
                slack_webhook: None,
                pagerduty_key: None,
            }),
            quotas: sqlx::types::Json(TenantQuotas::for_plan(&TenantPlan::Free)),
        };
        store.create(tenant1).await.unwrap();
        
        // Try to create with same slug
        let tenant2 = Tenant {
            id: Uuid::new_v4(),
            slug: "duplicate".to_string(),
            name: "Tenant 2".to_string(),
            plan: TenantPlan::Free,
            status: TenantStatus::Active,
            created_at: Utc::now(),
            settings: sqlx::types::Json(TenantSettings {
                logo_url: None,
                primary_color: "#000000".to_string(),
                timezone: "UTC".to_string(),
                retention_days: 7,
                slack_webhook: None,
                pagerduty_key: None,
            }),
            quotas: sqlx::types::Json(TenantQuotas::for_plan(&TenantPlan::Free)),
        };
        
        let result = store.create(tenant2).await;
        assert!(result.is_err());
    }
}
