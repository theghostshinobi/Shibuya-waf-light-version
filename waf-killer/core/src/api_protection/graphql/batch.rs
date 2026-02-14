
/// Extract GraphQL query from JSON body (supports single and batch)
pub fn extract_graphql_query(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    
    // Try to parse as JSON
    let json: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return None,
    };
    
    // Handle single query: {"query": "..."}
    if let Some(query) = json.get("query").and_then(|v| v.as_str()) {
        return Some(query.to_string());
    }
    
    // Handle batch queries: [{"query": "..."}, {"query": "..."}]
    if let Some(arr) = json.as_array() {
        let queries: Vec<String> = arr.iter()
            .filter_map(|item| item.get("query").and_then(|v| v.as_str()))
            .map(String::from)
            .collect();
        
        if !queries.is_empty() {
            // Join queries with newlines for combined complexity analysis
            return Some(queries.join("\n"));
        }
    }
    
    None
}
