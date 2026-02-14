use axum::{
    Router, Json,
    extract::{State, Path},
    http::StatusCode,
    routing::{get, post, delete},
};
use serde::{Serialize, Deserialize};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub struct VirtualPatch {
    pub id: String,
    pub cve_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub rule: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub blocks_count: u64,
    pub affected_paths: Vec<String>,
}

#[derive(Clone)]
pub struct VirtualPatchStore {
    patches: Arc<RwLock<HashMap<String, VirtualPatch>>>,
}

impl VirtualPatchStore {
    pub fn new() -> Self {
        Self {
            patches: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

pub fn virtual_patches_router(store: VirtualPatchStore) -> Router {
    Router::new()
        .route("/virtual-patches", get(list_patches))
        .route("/virtual-patches", post(create_patch))
        .route("/virtual-patches/:id", delete(delete_patch))
        .route("/virtual-patches/generate", post(generate_from_cve))
        .with_state(store)
}

async fn list_patches(
    State(store): State<VirtualPatchStore>
) -> Json<Vec<VirtualPatch>> {
    let patches = store.patches.read().unwrap();
    Json(patches.values().cloned().collect())
}

#[derive(Deserialize)]
struct CreatePatchRequest {
    cve_id: String,
    title: String,
    description: String,
    severity: String,
    rule: String,
    affected_paths: Vec<String>,
}

async fn create_patch(
    State(store): State<VirtualPatchStore>,
    Json(req): Json<CreatePatchRequest>
) -> (StatusCode, Json<VirtualPatch>) {
    let patch = VirtualPatch {
        id: Uuid::new_v4().to_string(),
        cve_id: req.cve_id,
        title: req.title,
        description: req.description,
        severity: req.severity,
        rule: req.rule,
        status: "active".to_string(),
        created_at: Utc::now(),
        blocks_count: 0,
        affected_paths: req.affected_paths,
    };
    
    store.patches.write().unwrap().insert(patch.id.clone(), patch.clone());
    
    (StatusCode::CREATED, Json(patch))
}

async fn delete_patch(
    State(store): State<VirtualPatchStore>,
    Path(id): Path<String>
) -> StatusCode {
    match store.patches.write().unwrap().remove(&id) {
        Some(_) => StatusCode::NO_CONTENT,
        None => StatusCode::NOT_FOUND,
    }
}

#[derive(Deserialize)]
struct GenerateFromCVERequest {
    cve_id: String,
}

async fn generate_from_cve(
    State(store): State<VirtualPatchStore>,
    Json(req): Json<GenerateFromCVERequest>
) -> (StatusCode, Json<VirtualPatch>) {
    // Fetch CVE data from NVD API
    let nvd_url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
        req.cve_id
    );
    
    let patch = match reqwest::get(&nvd_url).await {
        Ok(response) => {
            let cve_data: serde_json::Value = response.json().await.unwrap_or_default();
            let description = cve_data["vulnerabilities"]["cve"]["descriptions"]["value"]
                .as_str()
                .unwrap_or("No description available")
                .to_string();
            
            // Generate SecLang rule based on CVE type
            let rule = generate_rule_from_description(&description, &req.cve_id);
            
            VirtualPatch {
                id: Uuid::new_v4().to_string(),
                cve_id: req.cve_id.clone(),
                title: format!("Auto-generated patch for {}", req.cve_id),
                description: description.chars().take(200).collect(),
                severity: "HIGH".to_string(),
                rule,
                status: "active".to_string(),
                created_at: Utc::now(),
                blocks_count: 0,
                affected_paths: vec!["/*".to_string()],
            }
        },
        Err(_) => {
            // Fallback if NVD API fails
            VirtualPatch {
                id: Uuid::new_v4().to_string(),
                cve_id: req.cve_id.clone(),
                title: format!("Patch for {}", req.cve_id),
                description: "Auto-generated patch (CVE data unavailable)".to_string(),
                severity: "MEDIUM".to_string(),
                rule: format!("SecRule REQUEST_URI \"@rx /vulnerable\" \"id:99{},phase:1,deny\"", 
                    rand::random::<u16>() % 1000),
                status: "testing".to_string(),
                created_at: Utc::now(),
                blocks_count: 0,
                affected_paths: vec!["/*".to_string()],
            }
        }
    };
    
    store.patches.write().unwrap().insert(patch.id.clone(), patch.clone());
    (StatusCode::CREATED, Json(patch))
}

fn generate_rule_from_description(desc: &str, cve_id: &str) -> String {
    let desc_lower = desc.to_lowercase();
    
    if desc_lower.contains("sql injection") || desc_lower.contains("sqli") {
        format!(
            "SecRule ARGS \"@rx (?i)(union.*select|insert.*into|delete.*from)\" \
             \"id:999{},phase:2,deny,status:403,msg:'Virtual Patch: {}'\"",
            rand::random::<u16>() % 1000, cve_id
        )
    } else if desc_lower.contains("xss") || desc_lower.contains("cross-site scripting") {
        format!(
            "SecRule ARGS \"@rx (?i)(<script|onerror=|onload=)\" \
             \"id:999{},phase:2,deny,status:403,msg:'Virtual Patch: {}'\"",
            rand::random::<u16>() % 1000, cve_id
        )
    } else if desc_lower.contains("path traversal") || desc_lower.contains("directory traversal") {
        format!(
            "SecRule ARGS \"@rx (?:\\.\\./|\\.\\\\)\" \
             \"id:999{},phase:2,deny,status:403,msg:'Virtual Patch: {}'\"",
            rand::random::<u16>() % 1000, cve_id
        )
    } else {
        format!(
            "SecRule REQUEST_URI \"@rx /api/vulnerable\" \
             \"id:999{},phase:1,deny,status:403,msg:'Virtual Patch: {}'\"",
            rand::random::<u16>() % 1000, cve_id
        )
    }
}
