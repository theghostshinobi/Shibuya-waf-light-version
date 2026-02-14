use crate::parser::context::RequestContext;
use std::collections::HashMap;
use regex::Regex;
use lazy_static::lazy_static;
use crate::parser::transforms::html_entity_decode; // Use existing transform logic

// Traffic statistics structure (from Redis or in-memory cache)
pub struct TrafficStats {
    pub request_count_1min: u32,
    pub request_count_5min: u32,
    pub unique_paths_1min: usize,
    pub error_count_1min: u32,
    pub user_agent_seen_count: u32,
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self {
            request_count_1min: 0,
            request_count_5min: 0,
            unique_paths_1min: 0,
            error_count_1min: 0,
            user_agent_seen_count: 0,
        }
    }
}

/// Main feature vector structure
#[derive(Debug, Clone)]
pub struct FeatureVector {
    pub features: [f32; 50],
    pub feature_names: &'static [&'static str; 50],
}

/// Feature names for explainability
pub const FEATURE_NAMES: [&str; 50] = [
    "url_length",
    "path_depth",
    "param_count",
    "header_count",
    "body_size",
    "method_numeric",
    "has_body",
    "query_string_length",
    "entropy_url",
    "entropy_query",
    "entropy_body",
    "entropy_headers",
    "special_char_ratio",
    "digit_ratio",
    "uppercase_ratio",
    "whitespace_ratio",
    "alphanum_ratio",
    "suspicious_keywords",
    "encoding_layers",
    "sql_pattern_count",
    "xss_pattern_count",
    "path_traversal_count",
    "command_injection_count",
    "protocol_version",
    "is_tls",
    "content_type_anomaly",
    "accept_header_length",
    "cookie_count",
    "user_agent_length",
    "referer_present",
    "request_rate_1min",
    "request_rate_5min",
    "unique_paths_1min",
    "error_rate_1min",
    "ua_is_bot",
    "ua_is_rare",
    "geo_distance",
    "is_tor",
    "is_proxy",
    "is_datacenter",
    "json_depth",
    "json_key_count",
    "json_array_count",
    "multipart_parts",
    "multipart_has_file",
    "xml_depth",
    "xml_entity_count",
    "has_base64",
    "has_hex_encoding",
    "has_unicode_escape",
];

lazy_static! {
    static ref SQL_PATTERN: Regex = Regex::new(
        r"(?i)(union.*select|select.*from|insert.*into|delete.*from|' or '|1=1)"
    ).unwrap();
    
    static ref XSS_PATTERN: Regex = Regex::new(
        r"(?i)(<script|javascript:|onerror=|onload=|<iframe)"
    ).unwrap();
    
    static ref PATH_TRAVERSAL_PATTERN: Regex = Regex::new(
        r"(\.\./|\.\.\\|%2e%2e%2f)"
    ).unwrap();
    
    static ref COMMAND_INJECTION_PATTERN: Regex = Regex::new(
        r"(;|\||&|\$\(|\`)"
    ).unwrap();
}

/// Extract all 50 features from RequestContext
pub fn extract_features(
    ctx: &RequestContext,
    traffic_stats: Option<&TrafficStats>,
) -> Result<FeatureVector, String> {
    let mut features = [0.0f32; 50];
    let mut idx = 0;
    
    // Concatenate all inspectable text
    let url_text = ctx.uri.clone();
    let query_text = ctx.query_string.clone();
    // Assuming body_raw contains bytes that might be UTF-8. 
    // In strict production, might want to be careful with huge bodies.
    let body_text = ctx.body_raw.as_ref()
        .and_then(|b| String::from_utf8(b.to_vec()).ok())
        .unwrap_or_default();
    let headers_text = format!("{:?}", ctx.headers); // Simple concat
    
    // === Category A: Request Metadata (8) ===
    features[idx] = normalize_length(url_text.len());
    idx += 1;
    
    features[idx] = ctx.path.matches('/').count() as f32;
    idx += 1;
    
    features[idx] = (ctx.query_params.len() + get_body_param_count(ctx)) as f32;
    idx += 1;
    
    features[idx] = ctx.headers.len() as f32;
    idx += 1;
    
    features[idx] = normalize_length(ctx.body_size);
    idx += 1;
    
    features[idx] = method_to_numeric(&ctx.method);
    idx += 1;
    
    features[idx] = if ctx.body_raw.is_some() { 1.0 } else { 0.0 };
    idx += 1;
    
    features[idx] = normalize_length(query_text.len());
    idx += 1;
    
    // === Category B: Payload Characteristics (15) ===
    features[idx] = calculate_entropy(&url_text) / 8.0; // Normalize to 0-1
    idx += 1;
    
    features[idx] = calculate_entropy(&query_text) / 8.0;
    idx += 1;
    
    features[idx] = calculate_entropy(&body_text) / 8.0;
    idx += 1;
    
    features[idx] = calculate_entropy(&headers_text) / 8.0;
    idx += 1;
    
    let all_text = format!("{}{}{}", url_text, query_text, body_text);
    features[idx] = special_char_ratio(&all_text);
    idx += 1;
    
    features[idx] = digit_ratio(&all_text);
    idx += 1;
    
    features[idx] = uppercase_ratio(&all_text);
    idx += 1;
    
    features[idx] = whitespace_ratio(&all_text);
    idx += 1;
    
    features[idx] = alphanum_ratio(&all_text);
    idx += 1;
    
    features[idx] = count_suspicious_keywords(&all_text) / 20.0; // Normalize
    idx += 1;
    
    features[idx] = detect_encoding_layers(&all_text) / 5.0;
    idx += 1;
    
    features[idx] = count_sql_patterns(&all_text) / 10.0;
    idx += 1;
    
    features[idx] = count_xss_patterns(&all_text) / 10.0;
    idx += 1;
    
    features[idx] = count_path_traversal_patterns(&all_text) / 10.0;
    idx += 1;
    
    features[idx] = count_command_injection_patterns(&all_text) / 10.0;
    idx += 1;
    
    // === Category C: HTTP Protocol Features (7) ===
    features[idx] = protocol_version_to_numeric(&ctx.protocol);
    idx += 1;
    
    // Simple heuristic for TLS if scheme is not directly available as parsed URI
    features[idx] = if url_text.starts_with("https://") || ctx.server_name.ends_with(":443") { 1.0 } else { 0.0 };
    idx += 1;
    
    features[idx] = content_type_anomaly_score(ctx.content_type.as_deref());
    idx += 1;
    
    features[idx] = normalize_length(
        ctx.headers.get("accept").map(|v| v.iter().map(|s| s.len()).sum()).unwrap_or(0)
    );
    idx += 1;
    
    features[idx] = ctx.cookies.len() as f32 / 50.0; // Normalize
    idx += 1;
    
    features[idx] = normalize_length(
        ctx.headers.get("user-agent").map(|v| v.iter().map(|s| s.len()).sum()).unwrap_or(0)
    );
    idx += 1;
    
    features[idx] = if ctx.headers.contains_key("referer") { 1.0 } else { 0.0 };
    idx += 1;
    
    // === Category D: Behavioral Features (10) ===
    if let Some(stats) = traffic_stats {
        features[idx] = (stats.request_count_1min as f32 / 1000.0).min(1.0);
        idx += 1;
        
        features[idx] = (stats.request_count_5min as f32 / 5000.0).min(1.0);
        idx += 1;
        
        features[idx] = (stats.unique_paths_1min as f32 / 100.0).min(1.0);
        idx += 1;
        
        features[idx] = (stats.error_count_1min as f32 / stats.request_count_1min.max(1) as f32).min(1.0);
        idx += 1;
        
        features[idx] = if stats.user_agent_seen_count < 10 { 1.0 } else { 0.0 };
        idx += 1;
    } else {
        // No stats available, use defaults
        for _ in 0..5 {
            features[idx] = 0.0;
            idx += 1;
        }
    }
    
    let ua = ctx.headers.get("user-agent")
        .and_then(|v| v.first())
        .map(|s| s.as_str())
        .unwrap_or("");
    
    features[idx] = is_bot_user_agent(ua);
    idx += 1;
    
    // Remaining behavioral features (geo, tor, proxy, datacenter)
    // Set to 0.0 for now (implement in future with IP database)
    for _ in 0..4 {
        features[idx] = 0.0;
        idx += 1;
    }
    
    // === Category E: Content-Type Specific (10) ===
    if let Some(content_type) = &ctx.content_type {
        if content_type.contains("application/json") {
            let (depth, keys, arrays) = extract_json_features(&body_text);
            features[idx] = depth / 20.0;
            idx += 1;
            features[idx] = keys / 500.0;
            idx += 1;
            features[idx] = arrays / 100.0;
            idx += 1;
        } else {
            // Not JSON
            for _ in 0..3 {
                features[idx] = 0.0;
                idx += 1;
            }
        }
        
        if content_type.contains("multipart/form-data") {
            features[idx] = ctx.body_multipart.as_ref().map(|v| v.len()).unwrap_or(0) as f32 / 100.0;
            idx += 1;
            features[idx] = if ctx.body_multipart.as_ref().map(|v| v.iter().any(|f| f.filename.is_some())).unwrap_or(false) { 1.0 } else { 0.0 };
            idx += 1;
        } else {
            features[idx] = 0.0;
            idx += 1;
            features[idx] = 0.0;
            idx += 1;
        }
    } else {
        // No content-type, fill 5 zeros
        for _ in 0..5 {
            features[idx] = 0.0;
            idx += 1;
        }
    }
    
    // Remaining content features (XML, encodings)
    // Just simple check for base64 like string or encoded chars in body/url
    // Fill remaining spots to reach 50
    // We have filled idx up to 47 (approx)
    // Let's check where we are exactly. 
    // Category A: 8. idx=8
    // Category B: 15. idx=23
    // Category C: 7. idx=30
    // Category D: 10. idx=40
    // Category E: 5 so far. idx=45.
    
    // Generic content features (3 features: has_base64, has_hex, has_unicode)
    // The prompt says "pad remaining to 50" but also lists 50 features.
    
    features[idx] = if all_text.contains("base64") || (all_text.len() > 20 && base64_decode_check(&all_text)) { 1.0 } else { 0.0 };
    idx += 1;
    
    features[idx] = if all_text.contains('%') { 1.0 } else { 0.0 }; // Hex encoding rough check
    idx += 1;
    
    features[idx] = if all_text.contains("\\u") { 1.0 } else { 0.0 }; // Unicode escape check
    idx += 1;
    
    // Pad remaining to 50
    while idx < 50 {
        features[idx] = 0.0;
        idx += 1;
    }
    
    Ok(FeatureVector {
        features,
        feature_names: &FEATURE_NAMES,
    })
}

// === Helper Functions ===

fn method_to_numeric(method: &str) -> f32 {
    match method {
        "GET" => 0.0,
        "POST" => 1.0,
        "PUT" => 2.0,
        "DELETE" => 3.0,
        "PATCH" => 4.0,
        "HEAD" => 5.0,
        "OPTIONS" => 6.0,
        _ => 7.0,
    }
}

fn protocol_version_to_numeric(protocol: &str) -> f32 {
    match protocol {
        "HTTP/1.0" => 0.0,
        "HTTP/1.1" => 1.0,
        "HTTP/2" => 2.0,
        "HTTP/3" => 3.0,
        _ => 1.0,
    }
}

pub fn normalize_length(length: usize) -> f32 {
    if length == 0 {
        return 0.0;
    }
    let log_length = (length as f32).log10();
    let log_max = (10000.0f32).log10();
    (log_length / log_max).min(1.0)
}

fn content_type_anomaly_score(content_type: Option<&str>) -> f32 {
    const COMMON_TYPES: &[&str] = &[
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/html",
        "text/plain",
    ];
    if let Some(ct) = content_type {
        for common in COMMON_TYPES {
            if ct.contains(common) {
                return 0.0; 
            }
        }
        return 1.0; 
    }
    0.0 
}

fn get_body_param_count(ctx: &RequestContext) -> usize {
    ctx.body_form.as_ref().map(|f| f.len()).unwrap_or(0)
}

pub fn calculate_entropy(data: &str) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq_map: HashMap<char, usize> = HashMap::new();
    for c in data.chars() {
        *freq_map.entry(c).or_insert(0) += 1;
    }
    let len = data.len() as f32;
    let mut entropy = 0.0;
    for &count in freq_map.values() {
        let p = count as f32 / len;
        entropy -= p * p.log2();
    }
    entropy
}

pub fn special_char_ratio(text: &str) -> f32 {
    if text.is_empty() { return 0.0; }
    let special_count = extract_special_chars(text).len();
    special_count as f32 / text.len() as f32
}

pub fn extract_special_chars(text: &str) -> Vec<char> {
    text.chars()
        .filter(|c| ";|&<>\'\"(){}[]".contains(*c))
        .collect()
}

pub fn digit_ratio(text: &str) -> f32 {
    if text.is_empty() { return 0.0; }
    let digit_count = text.chars().filter(|c| c.is_ascii_digit()).count();
    digit_count as f32 / text.len() as f32
}

pub fn uppercase_ratio(text: &str) -> f32 {
    if text.is_empty() { return 0.0; }
    let letter_count = text.chars().filter(|c| c.is_alphabetic()).count();
    if letter_count == 0 { return 0.0; }
    let upper_count = text.chars().filter(|c| c.is_uppercase()).count();
    upper_count as f32 / letter_count as f32
}

pub fn whitespace_ratio(text: &str) -> f32 {
    if text.is_empty() { return 0.0; }
    let ws_count = text.chars().filter(|c| c.is_whitespace()).count();
    ws_count as f32 / text.len() as f32
}

fn alphanum_ratio(text: &str) -> f32 {
    if text.is_empty() { return 0.0; }
    let alphanum_count = text.chars().filter(|c| c.is_alphanumeric()).count();
    alphanum_count as f32 / text.len() as f32
}

pub fn count_suspicious_keywords(text: &str) -> f32 {
    const SQL_KEYWORDS: &[&str] = &[
        "union", "select", "insert", "update", "delete", "drop",
        "exec", "execute", "xp_", "sp_", "varchar", "cast",
    ];
    const XSS_KEYWORDS: &[&str] = &[
        "script", "javascript", "onerror", "onload", "onclick",
        "eval", "alert", "prompt", "confirm",
    ];
    const RCE_KEYWORDS: &[&str] = &[
        "system", "shell", "cmd", "powershell", "bash",
        "wget", "curl", "nc", "netcat", "exec",
    ];
    const PATH_KEYWORDS: &[&str] = &[
        "../", "..\\", "etc/passwd", "boot.ini", "/proc/",
    ];
    
    let text_lower = text.to_lowercase();
    let mut count = 0.0;
    
    for keyword in SQL_KEYWORDS.iter()
        .chain(XSS_KEYWORDS.iter())
        .chain(RCE_KEYWORDS.iter())
        .chain(PATH_KEYWORDS.iter())
    {
        count += text_lower.matches(keyword).count() as f32;
    }
    count
}

pub fn detect_encoding_layers(text: &str) -> f32 {
    let mut depth = 0.0;
    let mut current = text.to_string();
    
    for _ in 0..5 {
        let decoded = try_decode_all(&current);
        if decoded != current {
            depth += 1.0;
            current = decoded;
        } else {
            break;
        }
    }
    depth
}

use base64::{Engine as _, engine::general_purpose};

fn try_decode_all(input: &str) -> String {
    // Try URL decode
    if let Ok(decoded) = percent_encoding::percent_decode_str(input).decode_utf8() {
        if decoded.as_ref() != input {
            return decoded.to_string();
        }
    }
    
    // Try HTML entity decode
    let html_decoded = html_entity_decode(input);
    if html_decoded != input {
        return html_decoded;
    }
    
    // Try base64 decode
    if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(input) {
        if let Ok(decoded) = String::from_utf8(decoded_bytes) {
            return decoded;
        }
    }
    
    input.to_string()
}

// Simple legacy wrapper if needed, but we use base64 crate directly above
fn base64_decode_check(input: &str) -> bool {
    general_purpose::STANDARD.decode(input).is_ok()
}

pub fn count_sql_patterns(text: &str) -> f32 {
    SQL_PATTERN.find_iter(text).count() as f32
}

pub fn count_xss_patterns(text: &str) -> f32 {
    XSS_PATTERN.find_iter(text).count() as f32
}

pub fn count_path_traversal_patterns(text: &str) -> f32 {
    PATH_TRAVERSAL_PATTERN.find_iter(text).count() as f32
}

pub fn count_command_injection_patterns(text: &str) -> f32 {
    COMMAND_INJECTION_PATTERN.find_iter(text).count() as f32
}

pub fn is_bot_user_agent(ua: &str) -> f32 {
    const BOT_SIGNATURES: &[&str] = &[
        "bot", "crawler", "spider", "scraper", "curl", "wget",
        "python-requests", "Go-http-client", "Apache-HttpClient",
        "nikto", "nmap", "sqlmap", "burp", "zap",
    ];
    let ua_lower = ua.to_lowercase();
    for sig in BOT_SIGNATURES {
        if ua_lower.contains(sig) {
            return 1.0;
        }
    }
    0.0
}

pub fn extract_json_features(json_body: &str) -> (f32, f32, f32) {
    use serde_json::Value;
    if let Ok(parsed) = serde_json::from_str::<Value>(json_body) {
        let depth = calculate_json_depth(&parsed, 0);
        let key_count = count_json_keys(&parsed);
        let array_count = count_json_arrays(&parsed);
        (depth as f32, key_count as f32, array_count as f32)
    } else {
        (0.0, 0.0, 0.0)
    }
}

fn calculate_json_depth(value: &serde_json::Value, current_depth: usize) -> usize {
    match value {
        serde_json::Value::Object(map) => {
            map.values()
                .map(|v| calculate_json_depth(v, current_depth + 1))
                .max()
                .unwrap_or(current_depth)
        }
        serde_json::Value::Array(arr) => {
            arr.iter()
                .map(|v| calculate_json_depth(v, current_depth + 1))
                .max()
                .unwrap_or(current_depth)
        }
        _ => current_depth,
    }
}

fn count_json_keys(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => {
            let child_keys: usize = map.values()
                .map(|v| count_json_keys(v))
                .sum();
            map.len() + child_keys
        }
        serde_json::Value::Array(arr) => {
            arr.iter().map(|v| count_json_keys(v)).sum()
        }
        _ => 0,
    }
}

fn count_json_arrays(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => {
            map.values().map(|v| count_json_arrays(v)).sum()
        }
        serde_json::Value::Array(arr) => {
            1 + arr.iter().map(|v| count_json_arrays(v)).sum::<usize>()
        }
        _ => 0,
    }
}
