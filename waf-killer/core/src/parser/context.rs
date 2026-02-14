use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    // Metadata
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub client_ip: String, // String to accommodate various formats/proxies easily, or IpAddr if strict
    pub server_name: String,
    
    // HTTP basics
    pub protocol: String,
    pub method: String,
    pub uri: String,
    pub path: String,
    pub query_string: String,
    
    // Headers
    pub headers: HashMap<String, Vec<String>>,
    pub cookies: HashMap<String, String>,
    
    // Query parameters (parsed)
    pub query_params: HashMap<String, Vec<String>>,
    
    // Body (raw + parsed)
    // Note: We avoid holding the raw body in memory if possible, but for WAF it's often needed.
    // Use Arc<Vec<u8>> if shared, or Option if discarded.
    // For now assuming we might store it for inspection/logging.
    #[serde(skip)]
    pub body_raw: Option<Arc<Vec<u8>>>,
    pub body_size: usize,
    pub content_type: Option<String>,
    
    // Parsed body variants
    pub body_json: Option<serde_json::Value>,
    pub body_form: Option<HashMap<String, Vec<String>>>,
    pub body_multipart: Option<Vec<MultipartField>>,
    pub body_text: Option<String>, // For plain text/xml/html
    
    // Transformed data (for rule matching)
    pub transformed: TransformedData,
    
    // Metadata for inspection
    pub inspection_metadata: InspectionMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransformedData {
    // Each field stores the result after applying ALL transformations
    pub uri_decoded: String,
    
    // For maps, we transform keys and values
    pub query_params_decoded: HashMap<String, Vec<String>>,
    
    pub body_decoded: Option<String>,
    
    // Headers are special, we might transform specific ones or all
    pub headers_normalized: HashMap<String, Vec<String>>,
    
    // Aggregated view for pattern matching
    // These are crucial for fast rule matching - "does ANY parameter contain X?"
    pub all_args: Vec<String>,        // All keys from query + body + cookie names
    pub all_values: Vec<String>,      // All values from query + body + cookie values
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InspectionMetadata {
    pub entropy: f32,                
    pub special_char_count: u32,      
    pub suspicious_patterns: Vec<String>, 
}

use crate::parser::multipart_security::FileSecurityChecks;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartField {
    pub name: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    // Avoid storing large file content in memory if possible, 
    // but for WAF inspection we often need the start of the file or the whole thing if small.
    #[serde(skip)]
    pub content: Arc<Vec<u8>>, 
    pub size: usize,
    pub security_checks: FileSecurityChecks,
}

impl RequestContext {
    pub fn new(request_id: String, client_ip: String) -> Self {
        Self {
            request_id,
            timestamp: Utc::now(),
            client_ip,
            server_name: String::new(),
            protocol: String::new(),
            method: String::new(),
            uri: String::new(),
            path: String::new(),
            query_string: String::new(),
            headers: HashMap::new(),
            cookies: HashMap::new(),
            query_params: HashMap::new(),
            body_raw: None,
            body_size: 0,
            content_type: None,
            body_json: None,
            body_form: None,
            body_multipart: None,
            body_text: None,
            transformed: TransformedData::default(),
            inspection_metadata: InspectionMetadata::default(),
        }
    }
}
