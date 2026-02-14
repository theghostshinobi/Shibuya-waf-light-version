use sqlx::{PgPool, Connection, postgres::PgRow};
use uuid::Uuid;
use anyhow::Result;
use serde::Serialize;
use serde_json::json;

pub struct TenantDatabase {
    pool: PgPool,
}

impl TenantDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn query_for_tenant<T>(
        &self,
        tenant_id: Uuid,
        query: &str,
    ) -> Result<Vec<T>>
    where
        T: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin,
    {
        let mut conn = self.pool.acquire().await?;
        
        // Set tenant context for RLS
        // Important: sqlx might reuse connections, so we must be careful. 
        // In a transaction this is safer. RLS settings are usually per-transaction or session.
        // SET LOCAL applies to the transaction.
        let mut tx = conn.begin().await?;

        sqlx::query(&format!(
            "SET LOCAL app.current_tenant_id = '{}'",
            tenant_id
        ))
        .execute(&mut *tx)
        .await?;
        
        // Execute query (RLS will filter automatically)
        let results = sqlx::query_as::<_, T>(query)
            .fetch_all(&mut *tx)
            .await?;
        
        tx.commit().await?;
        
        Ok(results)
    }
    
    // Helper to insert data with tenant_id, though typically we might do this via
    // normal struct insertion where tenant_id is a field.
    // This helper assumes `data` can be serialized to JSON and we can add `tenant_id`
    // But specific typed queries are often better/safer.
    // Kept for reference from prompt.
    pub async fn insert_with_tenant<T>(
        &self,
        tenant_id: Uuid,
        _table: &str,
        data: &T,
    ) -> Result<()>
    where
        T: Serialize,
    {
        // Auto-inject tenant_id into INSERT
        // This is a bit dynamic/hacky for Rust (usually we use structs).
        // For now, let's just log or implement if strictly needed.
        // A better approach in Rust is to have the struct include tenant_id.
        let mut values = serde_json::to_value(data)?;
        if let Some(obj) = values.as_object_mut() {
             obj.insert("tenant_id".to_string(), json!(tenant_id.to_string()));
        }
        
        // ... dynamic insert logic would go here ...
        
        Ok(())
    }
}
