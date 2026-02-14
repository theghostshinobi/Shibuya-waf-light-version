use sqlx::PgPool;
use chrono::{DateTime, Utc};
use anyhow::Result;
use crate::tenancy::context::TenantContext;
use crate::audit::logger::AuditEntry;

pub struct AuditExporter;

impl AuditExporter {
    pub async fn export_csv(
        db: &PgPool,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<String> {
        let tenant_id = TenantContext::tenant_id()?;
        
        let entries = sqlx::query_as::<_, AuditEntry>(
            "SELECT * FROM audit_log 
             WHERE tenant_id = $1 
             AND timestamp BETWEEN $2 AND $3
             ORDER BY timestamp ASC"
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .fetch_all(db)
        .await?;
        
        // Export as CSV (SOC2-ready format)
        let mut csv = String::from("Timestamp,User,Action,Resource,Details\n");
        
        for entry in entries {
            csv.push_str(&format!(
                "{},{},{},{},{}\n",
                entry.timestamp.to_rfc3339(),
                entry.user_id.map(|u| u.to_string()).unwrap_or_else(|| "system".to_string()),
                entry.action,
                format!("{}:{}", entry.resource_type, entry.resource_id),
                entry.changes.map(|c| c.0.to_string()).unwrap_or_default().replace(",", ";") // Simple escape
            ));
        }
        
        Ok(csv)
    }
}
