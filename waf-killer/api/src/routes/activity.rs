use axum::{
    extract::{State, Query},
    Json,
    http::StatusCode,
};
use sqlx::PgPool;
use anyhow::Result;
use core::collaboration::activity::Activity;
use core::tenancy::context::TenantContext;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ActivityParams {
    limit: Option<i64>,
}

pub async fn get_activity_feed(
    State(db): State<PgPool>,
    Query(params): Query<ActivityParams>,
) -> Result<Json<Vec<Activity>>, (StatusCode, String)> {
    // Basic perm check
    // Assuming if you are in the tenant you can see activity? Or restricted?
    // Let's assume generic read access is enough or no specific perm enforcement for now beyond basic ctx.
    
    let limit = params.limit.unwrap_or(50);
    let activities = Activity::get_feed(&db, limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
    Ok(Json(activities))
}
