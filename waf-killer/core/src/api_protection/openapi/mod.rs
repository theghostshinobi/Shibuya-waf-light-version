pub mod validator;
pub mod path_matcher;
pub mod validator_wrapper;

pub use validator_wrapper::OpenAPIValidator;
pub use validator::ValidationResult; // Ensure this is exported as requested

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use anyhow::{Result, Context};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OpenApiSpec {
    pub openapi: String,           // "3.0.0"
    pub info: ApiInfo,
    pub paths: HashMap<String, PathItem>,
    #[serde(default)]
    pub components: Option<Components>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Components {
    #[serde(default)]
    pub schemas: HashMap<String, JsonSchema>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiInfo {
    pub title: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PathItem {
    pub get: Option<Operation>,
    pub post: Option<Operation>,
    pub put: Option<Operation>,
    pub delete: Option<Operation>,
    pub patch: Option<Operation>,
    pub options: Option<Operation>,
    pub head: Option<Operation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Operation {
    pub summary: Option<String>,
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
    pub parameters: Option<Vec<Parameter>>,
    #[serde(rename = "requestBody")]
    pub request_body: Option<RequestBody>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestBody {
    pub required: Option<bool>,
    pub content: HashMap<String, MediaType>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MediaType {
    pub schema: Option<JsonSchema>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonSchema {
    pub r#type: String,  // "object", "array", "string", etc.
    pub properties: Option<HashMap<String, JsonSchema>>,
    pub required: Option<Vec<String>>,
    pub items: Option<Box<JsonSchema>>,  // Per array
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Parameter {
    pub name: String,
    pub r#in: String,              // "path", "query", "header"
    pub required: Option<bool>,
    pub schema: Option<ParameterSchema>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ParameterSchema {
    pub r#type: String,            // "string", "integer", "boolean"
}

impl OpenApiSpec {
    /// Carica uno spec OpenAPI da file YAML
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .context(format!("Failed to read OpenAPI spec from {}", path))?;
        
        let spec: OpenApiSpec = serde_yaml::from_str(&content)
            .context("Failed to parse OpenAPI YAML")?;
        
        Ok(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_openapi_spec() {
        // Create examples directory if it doesn't exist (handled by write_to_file but relative paths are tricky in tests)
        // For the test, we'll assume the file exists at the expected path relative to the crate root
        let spec = OpenApiSpec::load_from_file("examples/openapi-simple.yaml");
        if spec.is_err() {
            println!("Error: {:?}", spec.err());
            panic!("Failed to load OpenAPI spec from examples/openapi-simple.yaml");
        }
        
        let spec = spec.unwrap();
        assert_eq!(spec.info.title, "Test API");
        assert!(spec.paths.contains_key("/users/{id}"));
    }
}
