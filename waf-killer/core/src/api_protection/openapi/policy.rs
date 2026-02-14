use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAPIPolicy {
    pub paths: Vec<String>,
    pub methods: Vec<String>,
    pub policy: EndpointPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointPolicy {
    pub rate_limit: Option<RateLimitConfig>,
    pub validation: ValidationConfig,
    pub authentication: AuthMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_minute: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    pub strict: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Required,
    Optional,
    Disabled,
}

pub struct PolicyEngine {
    policies: Vec<OpenAPIPolicy>,
}

impl PolicyEngine {
    pub fn new(policies: Vec<OpenAPIPolicy>) -> Self {
        Self { policies }
    }

    pub fn get_policy(&self, method: &str, path: &str) -> Option<&EndpointPolicy> {
        for p in &self.policies {
            if p.methods.contains(&method.to_string()) && p.paths.iter().any(|p_path| path.starts_with(p_path)) {
                return Some(&p.policy);
            }
        }
        None
    }
}
