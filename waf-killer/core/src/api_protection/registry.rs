use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};

use super::openapi::{OpenApiSpec, PathItem};
use super::openapi::path_matcher::PathMatcher;
use super::graphql::GraphQLConfig;

/// A compiled OpenAPI spec ready for fast validation
#[derive(Debug, Clone)]
pub struct CompiledSpec {
    /// Original spec
    pub spec: OpenApiSpec,
    /// Pre-built path matcher for O(n) lookups
    pub path_matcher: PathMatcher,
    /// When this spec was loaded
    pub loaded_at: DateTime<Utc>,
    /// Spec version/hash for change detection
    pub version: String,
}

/// GraphQL configuration per tenant
#[derive(Debug, Clone)]
pub struct TenantGraphQLConfig {
    pub config: GraphQLConfig,
    /// Optional schema for field-level auth
    pub schema: Option<String>,
    pub loaded_at: DateTime<Utc>,
}

/// Multi-tenant registry for API specs
/// 
/// Thread-safe storage for OpenAPI and GraphQL configurations per tenant.
/// Uses Arc<RwLock> for concurrent access with rare writes.
pub struct SpecRegistry {
    /// OpenAPI specs indexed by tenant ID
    openapi_specs: Arc<RwLock<HashMap<Uuid, CompiledSpec>>>,
    /// GraphQL configs indexed by tenant ID
    graphql_configs: Arc<RwLock<HashMap<Uuid, TenantGraphQLConfig>>>,
    /// Default spec for requests without tenant context
    default_openapi: Arc<RwLock<Option<CompiledSpec>>>,
    /// Default GraphQL config
    default_graphql: Arc<RwLock<GraphQLConfig>>,
}

impl SpecRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            openapi_specs: Arc::new(RwLock::new(HashMap::new())),
            graphql_configs: Arc::new(RwLock::new(HashMap::new())),
            default_openapi: Arc::new(RwLock::new(None)),
            default_graphql: Arc::new(RwLock::new(GraphQLConfig::default())),
        }
    }

    /// Load an OpenAPI spec for a tenant
    /// 
    /// Performs atomic swap - old spec is replaced without blocking readers
    pub async fn load_openapi(&self, tenant_id: Uuid, spec: OpenApiSpec) -> Result<()> {
        let path_matcher = PathMatcher::from_spec(&spec)?;
        
        let compiled = CompiledSpec {
            spec,
            path_matcher,
            loaded_at: Utc::now(),
            version: Uuid::new_v4().to_string(), // Simple version generation
        };

        let mut specs = self.openapi_specs.write().await;
        specs.insert(tenant_id, compiled);
        
        Ok(())
    }

    /// Load an OpenAPI spec from YAML string for a tenant
    pub async fn load_openapi_yaml(&self, tenant_id: Uuid, yaml: &str) -> Result<()> {
        let spec: OpenApiSpec = serde_yaml::from_str(yaml)
            .map_err(|e| anyhow!("Failed to parse OpenAPI YAML: {}", e))?;
        
        self.load_openapi(tenant_id, spec).await
    }

    /// Load an OpenAPI spec from JSON string for a tenant
    pub async fn load_openapi_json(&self, tenant_id: Uuid, json: &str) -> Result<()> {
        let spec: OpenApiSpec = serde_json::from_str(json)
            .map_err(|e| anyhow!("Failed to parse OpenAPI JSON: {}", e))?;
        
        self.load_openapi(tenant_id, spec).await
    }

    /// Get the compiled OpenAPI spec for a tenant
    pub async fn get_openapi(&self, tenant_id: &Uuid) -> Option<CompiledSpec> {
        let specs = self.openapi_specs.read().await;
        specs.get(tenant_id).cloned()
    }

    /// Get OpenAPI spec, falling back to default if tenant not found
    pub async fn get_openapi_or_default(&self, tenant_id: &Uuid) -> Option<CompiledSpec> {
        if let Some(spec) = self.get_openapi(tenant_id).await {
            return Some(spec);
        }
        
        let default = self.default_openapi.read().await;
        default.clone()
    }

    /// Set the default OpenAPI spec (for requests without tenant context)
    pub async fn set_default_openapi(&self, spec: OpenApiSpec) -> Result<()> {
        let path_matcher = PathMatcher::from_spec(&spec)?;
        
        let compiled = CompiledSpec {
            spec,
            path_matcher,
            loaded_at: Utc::now(),
            version: Uuid::new_v4().to_string(),
        };

        let mut default = self.default_openapi.write().await;
        *default = Some(compiled);
        
        Ok(())
    }

    /// Remove OpenAPI spec for a tenant
    pub async fn remove_openapi(&self, tenant_id: &Uuid) -> bool {
        let mut specs = self.openapi_specs.write().await;
        specs.remove(tenant_id).is_some()
    }

    /// Check if a tenant has an OpenAPI spec loaded
    pub async fn has_openapi(&self, tenant_id: &Uuid) -> bool {
        let specs = self.openapi_specs.read().await;
        specs.contains_key(tenant_id)
    }

    // ===== GraphQL Methods =====

    /// Set GraphQL config for a tenant
    pub async fn set_graphql_config(&self, tenant_id: Uuid, config: GraphQLConfig) {
        let tenant_config = TenantGraphQLConfig {
            config,
            schema: None,
            loaded_at: Utc::now(),
        };

        let mut configs = self.graphql_configs.write().await;
        configs.insert(tenant_id, tenant_config);
    }

    /// Set GraphQL config with schema for field-level auth
    pub async fn set_graphql_with_schema(&self, tenant_id: Uuid, config: GraphQLConfig, schema: String) {
        let tenant_config = TenantGraphQLConfig {
            config,
            schema: Some(schema),
            loaded_at: Utc::now(),
        };

        let mut configs = self.graphql_configs.write().await;
        configs.insert(tenant_id, tenant_config);
    }

    /// Get GraphQL config for a tenant
    pub async fn get_graphql_config(&self, tenant_id: &Uuid) -> Option<TenantGraphQLConfig> {
        let configs = self.graphql_configs.read().await;
        configs.get(tenant_id).cloned()
    }

    /// Get GraphQL config, falling back to default
    pub async fn get_graphql_or_default(&self, tenant_id: &Uuid) -> GraphQLConfig {
        if let Some(config) = self.get_graphql_config(tenant_id).await {
            return config.config;
        }
        
        let default = self.default_graphql.read().await;
        default.clone()
    }

    /// Set default GraphQL config
    pub async fn set_default_graphql(&self, config: GraphQLConfig) {
        let mut default = self.default_graphql.write().await;
        *default = config;
    }

    // ===== Statistics =====

    /// Get count of loaded specs
    pub async fn stats(&self) -> RegistryStats {
        let openapi_count = self.openapi_specs.read().await.len();
        let graphql_count = self.graphql_configs.read().await.len();
        let has_default_openapi = self.default_openapi.read().await.is_some();

        RegistryStats {
            openapi_specs_count: openapi_count,
            graphql_configs_count: graphql_count,
            has_default_openapi,
        }
    }

    /// List all tenant IDs with OpenAPI specs
    pub async fn list_openapi_tenants(&self) -> Vec<Uuid> {
        let specs = self.openapi_specs.read().await;
        specs.keys().cloned().collect()
    }

    /// List all tenant IDs with GraphQL configs
    pub async fn list_graphql_tenants(&self) -> Vec<Uuid> {
        let configs = self.graphql_configs.read().await;
        configs.keys().cloned().collect()
    }
}

impl Default for SpecRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the registry
#[derive(Debug, Clone)]
pub struct RegistryStats {
    pub openapi_specs_count: usize,
    pub graphql_configs_count: usize,
    pub has_default_openapi: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_protection::openapi::ApiInfo;

    fn make_test_spec() -> OpenApiSpec {
        let mut paths = HashMap::new();
        paths.insert("/users".to_string(), PathItem {
            get: Some(crate::api_protection::openapi::Operation {
                summary: Some("List users".to_string()),
                parameters: None,
                request_body: None,
            }),
            post: None,
            put: None,
            delete: None,
        });

        OpenApiSpec {
            openapi: "3.0.0".to_string(),
            info: ApiInfo {
                title: "Test API".to_string(),
                version: "1.0".to_string(),
            },
            paths,
        }
    }

    #[tokio::test]
    async fn test_load_and_get_openapi() {
        let registry = SpecRegistry::new();
        let tenant_id = Uuid::new_v4();
        
        registry.load_openapi(tenant_id, make_test_spec()).await.unwrap();
        
        let spec = registry.get_openapi(&tenant_id).await;
        assert!(spec.is_some());
        assert_eq!(spec.unwrap().spec.info.title, "Test API");
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let registry = SpecRegistry::new();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        
        let mut spec_a = make_test_spec();
        spec_a.info.title = "Tenant A API".to_string();
        
        let mut spec_b = make_test_spec();
        spec_b.info.title = "Tenant B API".to_string();
        
        registry.load_openapi(tenant_a, spec_a).await.unwrap();
        registry.load_openapi(tenant_b, spec_b).await.unwrap();
        
        let got_a = registry.get_openapi(&tenant_a).await.unwrap();
        let got_b = registry.get_openapi(&tenant_b).await.unwrap();
        
        assert_eq!(got_a.spec.info.title, "Tenant A API");
        assert_eq!(got_b.spec.info.title, "Tenant B API");
    }

    #[tokio::test]
    async fn test_default_fallback() {
        let registry = SpecRegistry::new();
        let tenant_id = Uuid::new_v4();
        
        // No spec loaded for tenant
        assert!(registry.get_openapi(&tenant_id).await.is_none());
        
        // Set default
        registry.set_default_openapi(make_test_spec()).await.unwrap();
        
        // Now should fall back to default
        let spec = registry.get_openapi_or_default(&tenant_id).await;
        assert!(spec.is_some());
    }

    #[tokio::test]
    async fn test_remove_spec() {
        let registry = SpecRegistry::new();
        let tenant_id = Uuid::new_v4();
        
        registry.load_openapi(tenant_id, make_test_spec()).await.unwrap();
        assert!(registry.has_openapi(&tenant_id).await);
        
        registry.remove_openapi(&tenant_id).await;
        assert!(!registry.has_openapi(&tenant_id).await);
    }

    #[tokio::test]
    async fn test_stats() {
        let registry = SpecRegistry::new();
        
        let stats = registry.stats().await;
        assert_eq!(stats.openapi_specs_count, 0);
        assert!(!stats.has_default_openapi);
        
        registry.load_openapi(Uuid::new_v4(), make_test_spec()).await.unwrap();
        registry.load_openapi(Uuid::new_v4(), make_test_spec()).await.unwrap();
        
        let stats = registry.stats().await;
        assert_eq!(stats.openapi_specs_count, 2);
    }
}
