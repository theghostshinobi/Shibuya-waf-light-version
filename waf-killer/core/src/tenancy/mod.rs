use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Tenant {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub plan: TenantPlan,
    pub status: TenantStatus,
    pub created_at: DateTime<Utc>,
    pub settings: sqlx::types::Json<TenantSettings>,
    pub quotas: sqlx::types::Json<TenantQuotas>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TenantPlan {
    Free,
    Startup,      // $99/mo
    Business,     // $499/mo
    Enterprise,   // $2499/mo
    Custom,
}

// Implement SQLx Type for TenantPlan
impl sqlx::Type<sqlx::Postgres> for TenantPlan {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for TenantPlan {
    fn encode_by_ref(&self, buf: &mut sqlx::postgres::PgArgumentBuffer) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
        let s = serde_json::to_string(self).unwrap();
        // remove quotes
        let s = s.trim_matches('"');
        Ok(<String as sqlx::Encode<sqlx::Postgres>>::encode_by_ref(&s.to_string(), buf)?)
    }
}

impl sqlx::Decode<'_, sqlx::Postgres> for TenantPlan {
    fn decode(value: sqlx::postgres::PgValueRef<'_>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let s: String = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        // Adding quotes for serde_json
        let json_s = format!("\"{}\"", s);
        Ok(serde_json::from_str(&json_s)?)
    }
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TenantStatus {
    Active,
    Suspended,    // Non-payment
    Disabled,     // Violation
    Trial,        // 14-day trial
}

// Reuse logic for sqlx Type as above or just use simple String/derived usage if sqlx supports it directly or string map
impl sqlx::Type<sqlx::Postgres> for TenantStatus {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for TenantStatus {
    fn encode_by_ref(&self, buf: &mut sqlx::postgres::PgArgumentBuffer) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
        let s = serde_json::to_string(self).unwrap();
        let s = s.trim_matches('"');
        Ok(<String as sqlx::Encode<sqlx::Postgres>>::encode_by_ref(&s.to_string(), buf)?)
    }
}

impl sqlx::Decode<'_, sqlx::Postgres> for TenantStatus {
    fn decode(value: sqlx::postgres::PgValueRef<'_>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let s: String = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        let json_s = format!("\"{}\"", s);
        Ok(serde_json::from_str(&json_s)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSettings {
    pub logo_url: Option<String>,
    pub primary_color: String,
    pub timezone: String,
    pub retention_days: u32,
    pub slack_webhook: Option<String>,
    pub pagerduty_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantQuotas {
    pub max_requests_per_month: u64,
    pub max_rules: u32,
    pub max_team_members: u32,
    pub max_virtual_patches: u32,
    pub max_retention_days: u32,
}

impl TenantQuotas {
    pub fn for_plan(plan: &TenantPlan) -> Self {
        match plan {
            TenantPlan::Free => Self {
                max_requests_per_month: 100_000,
                max_rules: 10,
                max_team_members: 1,
                max_virtual_patches: 5,
                max_retention_days: 7,
            },
            TenantPlan::Startup => Self {
                max_requests_per_month: 10_000_000,
                max_rules: 100,
                max_team_members: 5,
                max_virtual_patches: 50,
                max_retention_days: 30,
            },
            TenantPlan::Business => Self {
                max_requests_per_month: 100_000_000,
                max_rules: 500,
                max_team_members: 20,
                max_virtual_patches: 200,
                max_retention_days: 90,
            },
            TenantPlan::Enterprise => Self {
                max_requests_per_month: u64::MAX,  // Unlimited
                max_rules: u32::MAX,
                max_team_members: u32::MAX,
                max_virtual_patches: u32::MAX,
                max_retention_days: 365,
            },
            TenantPlan::Custom => Self {
                max_requests_per_month: 1_000_000,
                max_rules: 50,
                max_team_members: 5,
                max_virtual_patches: 20,
                max_retention_days: 30,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantUpdate {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub plan: Option<TenantPlan>,
    pub status: Option<TenantStatus>,
    pub settings: Option<TenantSettings>,
}

pub mod context;
pub mod isolation;
pub mod quota;
pub mod billing;
pub mod store;
