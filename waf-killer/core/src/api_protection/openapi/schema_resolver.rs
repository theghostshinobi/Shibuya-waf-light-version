use std::collections::{HashMap, HashSet};
use super::parser::{Schema, SchemaType};
use anyhow::{Result, anyhow};
use serde_json::Value;

/// Resolves $ref references in OpenAPI schemas with caching and cycle detection
#[derive(Debug, Clone)]
pub struct SchemaResolver {
    /// Cache of resolved schemas, keyed by $ref string
    cache: HashMap<String, Schema>,
    /// All component schemas from the spec
    components: HashMap<String, Schema>,
}

impl SchemaResolver {
    /// Create a new resolver with component schemas from an OpenAPI spec
    pub fn new(components: HashMap<String, Schema>) -> Self {
        Self {
            cache: HashMap::new(),
            components,
        }
    }

    /// Create an empty resolver (for specs without components)
    pub fn empty() -> Self {
        Self {
            cache: HashMap::new(),
            components: HashMap::new(),
        }
    }

    /// Resolve a $ref string to a Schema
    /// 
    /// Supports local refs only: "#/components/schemas/User"
    /// Returns cached result if available
    pub fn resolve(&mut self, reference: &str) -> Result<Schema> {
        // Check cache first
        if let Some(cached) = self.cache.get(reference) {
            return Ok(cached.clone());
        }

        // Resolve with cycle detection
        let mut visited = HashSet::new();
        let resolved = self.resolve_with_cycle_detection(reference, &mut visited)?;
        
        // Cache the result
        self.cache.insert(reference.to_string(), resolved.clone());
        
        Ok(resolved)
    }

    /// Resolve a $ref with cycle detection
    fn resolve_with_cycle_detection(
        &self,
        reference: &str,
        visited: &mut HashSet<String>,
    ) -> Result<Schema> {
        // Cycle detection
        if visited.contains(reference) {
            return Err(anyhow!("Circular reference detected: {}", reference));
        }
        visited.insert(reference.to_string());

        // Parse the reference path
        // Expected format: "#/components/schemas/SchemaName"
        let parts: Vec<&str> = reference.split('/').collect();
        
        if parts.len() != 4 || parts[0] != "#" || parts[1] != "components" || parts[2] != "schemas" {
            return Err(anyhow!(
                "Unsupported $ref format: {}. Only local refs (#/components/schemas/Name) are supported.",
                reference
            ));
        }

        let schema_name = parts[3];
        
        // Look up in components
        let base_schema = self.components.get(schema_name)
            .ok_or_else(|| anyhow!("Schema not found: {}", schema_name))?
            .clone();

        // Recursively resolve nested refs in properties
        let resolved = self.resolve_nested_refs(base_schema, visited)?;

        visited.remove(reference);
        Ok(resolved)
    }

    /// Resolve any nested $refs within a Schema
    fn resolve_nested_refs(&self, schema: Schema, visited: &mut HashSet<String>) -> Result<Schema> {
        let mut resolved = schema.clone();

        // Resolve properties
        if let Some(ref mut properties) = resolved.properties {
            let mut new_properties = HashMap::new();
            
            for (name, prop_schema) in properties.iter() {
                let resolved_prop = if let Some(ref ref_str) = prop_schema.reference {
                    // This property is a $ref, resolve it
                    self.resolve_with_cycle_detection(ref_str, visited)?
                } else {
                    // Recursively check for nested refs
                    self.resolve_nested_refs(prop_schema.clone(), visited)?
                };
                
                new_properties.insert(name.clone(), resolved_prop);
            }
            
            resolved.properties = Some(new_properties);
        }

        // Resolve items (for array types)
        if let Some(ref items) = resolved.items {
            if let Some(ref ref_str) = items.reference {
                let resolved_items = self.resolve_with_cycle_detection(ref_str, visited)?;
                resolved.items = Some(Box::new(resolved_items));
            } else {
                let resolved_items = self.resolve_nested_refs((**items).clone(), visited)?;
                resolved.items = Some(Box::new(resolved_items));
            }
        }

        Ok(resolved)
    }

    /// Check if a reference exists in components
    pub fn has_component(&self, name: &str) -> bool {
        self.components.contains_key(name)
    }

    /// Get all component schema names
    pub fn component_names(&self) -> Vec<&String> {
        self.components.keys().collect()
    }

    /// Clear the resolution cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        (self.cache.len(), self.components.len())
    }
}

/// Extension trait to add reference support to Schema
pub trait SchemaExt {
    /// Check if this schema is a reference
    fn is_ref(&self) -> bool;
    
    /// Get the reference string if this is a $ref
    fn get_ref(&self) -> Option<&String>;
}

impl SchemaExt for Schema {
    fn is_ref(&self) -> bool {
        self.reference.is_some()
    }

    fn get_ref(&self) -> Option<&String> {
        self.reference.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_object_schema(properties: Vec<(&str, Schema)>) -> Schema {
        Schema {
            schema_type: Some(SchemaType::Object),
            properties: Some(properties.into_iter().map(|(k, v)| (k.to_string(), v)).collect()),
            required: None,
            items: None,
            format: None,
            minimum: None,
            maximum: None,
            min_length: None,
            max_length: None,
            pattern: None,
            nullable: None,
            reference: None,
        }
    }

    fn make_string_schema() -> Schema {
        Schema {
            schema_type: Some(SchemaType::String),
            properties: None,
            required: None,
            items: None,
            format: None,
            minimum: None,
            maximum: None,
            min_length: None,
            max_length: None,
            pattern: None,
            nullable: None,
            reference: None,
        }
    }

    fn make_ref_schema(reference: &str) -> Schema {
        Schema {
            schema_type: None,
            properties: None,
            required: None,
            items: None,
            format: None,
            minimum: None,
            maximum: None,
            min_length: None,
            max_length: None,
            pattern: None,
            nullable: None,
            reference: Some(reference.to_string()),
        }
    }

    #[test]
    fn test_simple_ref_resolution() {
        let mut components = HashMap::new();
        components.insert(
            "User".to_string(),
            make_object_schema(vec![
                ("name", make_string_schema()),
                ("email", make_string_schema()),
            ]),
        );

        let mut resolver = SchemaResolver::new(components);
        let resolved = resolver.resolve("#/components/schemas/User").unwrap();

        assert!(matches!(resolved.schema_type, Some(SchemaType::Object)));
        assert!(resolved.properties.is_some());
        assert!(resolved.properties.as_ref().unwrap().contains_key("name"));
    }

    #[test]
    fn test_nested_ref_resolution() {
        let mut components = HashMap::new();
        
        // Address schema
        components.insert(
            "Address".to_string(),
            make_object_schema(vec![
                ("street", make_string_schema()),
                ("city", make_string_schema()),
            ]),
        );
        
        // User schema with $ref to Address
        components.insert(
            "User".to_string(),
            make_object_schema(vec![
                ("name", make_string_schema()),
                ("address", make_ref_schema("#/components/schemas/Address")),
            ]),
        );

        let mut resolver = SchemaResolver::new(components);
        let resolved = resolver.resolve("#/components/schemas/User").unwrap();

        // The address property should be resolved
        let props = resolved.properties.as_ref().unwrap();
        let address = props.get("address").unwrap();
        
        assert!(matches!(address.schema_type, Some(SchemaType::Object)));
        assert!(address.properties.as_ref().unwrap().contains_key("street"));
    }

    #[test]
    fn test_circular_reference_detection() {
        let mut components = HashMap::new();
        
        // Circular: A -> B -> A
        components.insert(
            "A".to_string(),
            make_object_schema(vec![
                ("b", make_ref_schema("#/components/schemas/B")),
            ]),
        );
        
        components.insert(
            "B".to_string(),
            make_object_schema(vec![
                ("a", make_ref_schema("#/components/schemas/A")),
            ]),
        );

        let mut resolver = SchemaResolver::new(components);
        let result = resolver.resolve("#/components/schemas/A");
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Circular reference"));
    }

    #[test]
    fn test_cache_hit() {
        let mut components = HashMap::new();
        components.insert("User".to_string(), make_string_schema());

        let mut resolver = SchemaResolver::new(components);
        
        // First resolve
        resolver.resolve("#/components/schemas/User").unwrap();
        assert_eq!(resolver.cache_stats().0, 1);
        
        // Second resolve should hit cache
        resolver.resolve("#/components/schemas/User").unwrap();
        assert_eq!(resolver.cache_stats().0, 1); // Cache size unchanged
    }

    #[test]
    fn test_invalid_ref_format() {
        let resolver = SchemaResolver::empty();
        
        // Wrong format
        let result = SchemaResolver::new(HashMap::new())
            .resolve("User");
        assert!(result.is_err());
        
        let result = SchemaResolver::new(HashMap::new())
            .resolve("./other-file.yaml#/schemas/User");
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_schema() {
        let mut resolver = SchemaResolver::empty();
        let result = resolver.resolve("#/components/schemas/NotExists");
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }
}
