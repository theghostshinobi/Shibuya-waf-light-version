use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use uuid::Uuid;
use core::tenancy::context::with_tenant_context;
use core::rbac::roles::Role;
use sqlx::PgPool;

// Header keys
const HEADER_TENANT_ID: &str = "x-tenant-id";
const HEADER_USER_ID: &str = "x-user-id";
const HEADER_USER_ROLE: &str = "x-user-role";

#[derive(Clone)]
pub struct ApiState {
    pub db: PgPool,
}

pub async fn tenant_context_middleware(
    State(_state): State<PgPool>, // If we need to look up tenant by slug
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // 1. Extract tenant_id
    let tenant_id_str = req.headers()
        .get(HEADER_TENANT_ID)
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let tenant_id = Uuid::parse_str(tenant_id_str)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // 2. Extract user_id (optional, unauthenticated requests might not have it)
    let user_id = req.headers()
        .get(HEADER_USER_ID)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok());

    // 3. Extract role
    let user_role = req.headers()
        .get(HEADER_USER_ROLE)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<Role>().ok());

    // 4. Wrap the next handler in the tenant context
    // This uses the task_local logic we implemented in core
    Ok(with_tenant_context(
        tenant_id,
        String::new(), // slug could be fetched if needed
        user_id,
        user_role,
        async move {
            next.run(req).await
        }
    ).await)
}
