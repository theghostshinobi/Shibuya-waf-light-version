use std::collections::HashMap;
use super::{OpenApiSpec, Operation};
use anyhow::Result;

/// A node in the path matching Trie
#[derive(Debug, Clone, Default)]
pub struct TrieNode {
    /// Literal path segment children (e.g., "users" -> node)
    literal_children: HashMap<String, TrieNode>,
    /// Parameter child (e.g., "{id}" -> (param_name, node))
    param_child: Option<(String, Box<TrieNode>)>,
    /// Operations at this endpoint, keyed by HTTP method
    operations: HashMap<String, Operation>,
    /// The original path template for this endpoint
    path_template: Option<String>,
}

/// Trie-based path matcher for O(n) path matching where n = number of segments
#[derive(Debug, Clone, Default)]
pub struct PathMatcher {
    root: TrieNode,
}

/// Result of a successful path match
#[derive(Debug, Clone)]
pub struct PathMatch<'a> {
    /// The matched operation
    pub operation: &'a Operation,
    /// Extracted path parameters
    pub params: HashMap<String, String>,
    /// The original path template
    pub template: &'a str,
}

impl PathMatcher {
    /// Create a new empty PathMatcher
    pub fn new() -> Self {
        Self {
            root: TrieNode::default(),
        }
    }

    /// Build a PathMatcher from an OpenAPI spec
    pub fn from_spec(spec: &OpenApiSpec) -> Result<Self> {
        let mut matcher = Self::new();
        
        for (path, path_item) in &spec.paths {
            // Add each method's operation to the trie
            if let Some(ref op) = path_item.get {
                matcher.insert(path, "GET", op.clone())?;
            }
            if let Some(ref op) = path_item.post {
                matcher.insert(path, "POST", op.clone())?;
            }
            if let Some(ref op) = path_item.put {
                matcher.insert(path, "PUT", op.clone())?;
            }
            if let Some(ref op) = path_item.delete {
                matcher.insert(path, "DELETE", op.clone())?;
            }
            if let Some(ref op) = path_item.patch {
                matcher.insert(path, "PATCH", op.clone())?;
            }
            if let Some(ref op) = path_item.options {
                matcher.insert(path, "OPTIONS", op.clone())?;
            }
            if let Some(ref op) = path_item.head {
                matcher.insert(path, "HEAD", op.clone())?;
            }
        }
        
        Ok(matcher)
    }

    /// Insert a path template with its operation into the trie
    pub fn insert(&mut self, path: &str, method: &str, operation: Operation) -> Result<()> {
        let segments = Self::parse_segments(path);
        let mut current = &mut self.root;
        
        for segment in &segments {
            if segment.starts_with('{') && segment.ends_with('}') {
                // Parameter segment
                let param_name = segment[1..segment.len()-1].to_string();
                
                if current.param_child.is_none() {
                    current.param_child = Some((param_name.clone(), Box::new(TrieNode::default())));
                }
                
                let (_, child) = current.param_child.as_mut().unwrap();
                current = child.as_mut();
            } else {
                // Literal segment
                if !current.literal_children.contains_key(segment) {
                    current.literal_children.insert(segment.clone(), TrieNode::default());
                }
                current = current.literal_children.get_mut(segment).unwrap();
            }
        }
        
        // Store operation at the terminal node
        current.operations.insert(method.to_uppercase(), operation);
        current.path_template = Some(path.to_string());
        
        Ok(())
    }

    /// Match a request path and method against the trie
    /// Returns the matched operation and extracted path parameters
    pub fn match_path<'a>(&'a self, path: &str, method: &str) -> Option<PathMatch<'a>> {
        let segments = Self::parse_segments(path);
        let mut params = HashMap::new();
        
        let node = self.find_node(&segments, &mut params)?;
        
        let operation = node.operations.get(&method.to_uppercase())?;
        let template = node.path_template.as_ref()?;
        
        Some(PathMatch {
            operation,
            params,
            template,
        })
    }

    /// Check if a path exists in the trie (any method)
    pub fn path_exists(&self, path: &str) -> bool {
        let segments = Self::parse_segments(path);
        let mut params = HashMap::new();
        
        if let Some(node) = self.find_node(&segments, &mut params) {
            !node.operations.is_empty()
        } else {
            false
        }
    }

    /// Find the terminal node for a path, extracting parameters along the way
    fn find_node<'a>(&'a self, segments: &[String], params: &mut HashMap<String, String>) -> Option<&'a TrieNode> {
        let mut current = &self.root;
        
        for segment in segments {
            // Try literal match first (higher priority)
            if let Some(child) = current.literal_children.get(segment) {
                current = child;
            }
            // Then try parameter match
            else if let Some((param_name, child)) = &current.param_child {
                params.insert(param_name.clone(), segment.clone());
                current = child.as_ref();
            }
            // No match
            else {
                return None;
            }
        }
        
        Some(current)
    }

    /// Parse a path into segments, handling edge cases
    fn parse_segments(path: &str) -> Vec<String> {
        path.trim_start_matches('/')
            .trim_end_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    /// Get all registered paths (for debugging/introspection)
    pub fn registered_paths(&self) -> Vec<(String, Vec<String>)> {
        let mut paths = Vec::new();
        self.collect_paths(&self.root, String::new(), &mut paths);
        paths
    }

    fn collect_paths(&self, node: &TrieNode, current_path: String, paths: &mut Vec<(String, Vec<String>)>) {
        if !node.operations.is_empty() {
            let methods: Vec<String> = node.operations.keys().cloned().collect();
            paths.push((current_path.clone(), methods));
        }
        
        for (segment, child) in &node.literal_children {
            let new_path = format!("{}/{}", current_path, segment);
            self.collect_paths(child, new_path, paths);
        }
        
        if let Some((param_name, child)) = &node.param_child {
            let new_path = format!("{}/{{{}}}", current_path, param_name);
            self.collect_paths(child.as_ref(), new_path, paths);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // use crate::api_protection::openapi::parser::{Parameter, ParameterLocation, Schema, SchemaType};

    fn make_operation(id: &str) -> Operation {
        Operation {
            operation_id: Some(id.to_string()),
            parameters: Some(vec![]),
            request_body: None,
            summary: None,
        }
    }

    #[test]
    fn test_literal_path_matching() {
        let mut matcher = PathMatcher::new();
        matcher.insert("/users", "GET", make_operation("list_users")).unwrap();
        matcher.insert("/users", "POST", make_operation("create_user")).unwrap();
        
        let match_result = matcher.match_path("/users", "GET");
        assert!(match_result.is_some());
        let m = match_result.unwrap();
        assert_eq!(m.operation.operation_id, Some("list_users".to_string()));
        assert!(m.params.is_empty());
        
        let match_result = matcher.match_path("/users", "POST");
        assert!(match_result.is_some());
        assert_eq!(match_result.unwrap().operation.operation_id, Some("create_user".to_string()));
        
        // Wrong method
        let match_result = matcher.match_path("/users", "DELETE");
        assert!(match_result.is_none());
        
        // Wrong path
        let match_result = matcher.match_path("/posts", "GET");
        assert!(match_result.is_none());
    }

    #[test]
    fn test_parameter_extraction() {
        let mut matcher = PathMatcher::new();
        matcher.insert("/users/{id}", "GET", make_operation("get_user")).unwrap();
        matcher.insert("/users/{id}/posts/{postId}", "GET", make_operation("get_user_post")).unwrap();
        
        // Single parameter
        let match_result = matcher.match_path("/users/123", "GET").unwrap();
        assert_eq!(match_result.operation.operation_id, Some("get_user".to_string()));
        assert_eq!(match_result.params.get("id"), Some(&"123".to_string()));
        
        // Multiple parameters
        let match_result = matcher.match_path("/users/123/posts/456", "GET").unwrap();
        assert_eq!(match_result.operation.operation_id, Some("get_user_post".to_string()));
        assert_eq!(match_result.params.get("id"), Some(&"123".to_string()));
        assert_eq!(match_result.params.get("postId"), Some(&"456".to_string()));
    }

    #[test]
    fn test_literal_priority_over_param() {
        let mut matcher = PathMatcher::new();
        matcher.insert("/users/{id}", "GET", make_operation("get_user")).unwrap();
        matcher.insert("/users/me", "GET", make_operation("get_current_user")).unwrap();
        
        // "me" should match literal, not parameter
        let match_result = matcher.match_path("/users/me", "GET").unwrap();
        assert_eq!(match_result.operation.operation_id, Some("get_current_user".to_string()));
        assert!(match_result.params.is_empty());
        
        // Other values should match parameter
        let match_result = matcher.match_path("/users/123", "GET").unwrap();
        assert_eq!(match_result.operation.operation_id, Some("get_user".to_string()));
        assert_eq!(match_result.params.get("id"), Some(&"123".to_string()));
    }

    #[test]
    fn test_path_normalization() {
        let mut matcher = PathMatcher::new();
        matcher.insert("/users/", "GET", make_operation("list_users")).unwrap();
        
        // All these should match
        assert!(matcher.match_path("/users", "GET").is_some());
        assert!(matcher.match_path("/users/", "GET").is_some());
        assert!(matcher.match_path("users", "GET").is_some());
    }

    #[test]
    fn test_registered_paths() {
        let mut matcher = PathMatcher::new();
        matcher.insert("/users", "GET", make_operation("list")).unwrap();
        matcher.insert("/users/{id}", "GET", make_operation("get")).unwrap();
        matcher.insert("/users/{id}", "DELETE", make_operation("delete")).unwrap();
        
        let paths = matcher.registered_paths();
        assert_eq!(paths.len(), 2); // Two unique paths
    }

    #[test]
    fn test_path_exists() {
        let mut matcher = PathMatcher::new();
        matcher.insert("/users/{id}", "GET", make_operation("get")).unwrap();
        
        assert!(matcher.path_exists("/users/123"));
        assert!(!matcher.path_exists("/posts/123"));
    }
}
