use regex::Regex;
use lazy_static::lazy_static;
use std::borrow::Cow;
use unicode_normalization::UnicodeNormalization;
use html_escape::decode_html_entities;

lazy_static! {
    static ref BASE64_REGEX: Regex = Regex::new(r"^[A-Za-z0-9+/=]+$").unwrap();
    static ref URL_SAFE_BASE64_REGEX: Regex = Regex::new(r"^[A-Za-z0-9\-_]+$").unwrap();
    static ref SQL_COMMENT_REGEX: Regex = Regex::new(r"(?s)/\*.*?\*/|--.*$|#.*$").unwrap();
    // Path traversal specific regexes
    static ref WIN_PATH_SEPARATOR: Regex = Regex::new(r"\\+").unwrap();
    static ref MULTIPLE_SLASHES: Regex = Regex::new(r"/{2,}").unwrap();
    // Matches 2 or more dots which is a common bypass for .. filters (e.g. ... or ....)
    static ref DOT_SEGMENT: Regex = Regex::new(r"^\.+$").unwrap(); 
}

pub struct TransformPipeline;

impl TransformPipeline {
    /// Applies the standard pipeline of transformations to a string.
    /// Returns the fully normalized string.
    pub fn apply(input: &str) -> String {
        let mut result = Cow::Borrowed(input);
        
        // 1. URL Decode (Recursive)
        result = Cow::Owned(url_decode_recursive(&result, 5));
        
        // 2. HTML Entity Decode
        result = Cow::Owned(html_entity_decode(&result));
        
        // 3. Base64 Decode (if strictly base64)
        if result.len() > 8 && (BASE64_REGEX.is_match(&result) || URL_SAFE_BASE64_REGEX.is_match(&result)) {
             result = Cow::Owned(base64_decode_if_encoded(&result));
        }

        // 4. Unicode Normalization
        result = Cow::Owned(unicode_normalize(&result));
        
        // 5. Remove Null Bytes
        result = Cow::Owned(remove_null_bytes(&result));

        // 6. Lowercase
        result = Cow::Owned(lowercase(&result));
        
        // 7. Path Normalization is usually context specific, but we can do a pass here
        // if we suspect it is a path. For generic input, we might skip full path normalization
        // to avoid altering non-path data destructively. 
        // However, the prompt implies these transforms are available for the WAF engine.
        // We will expose normalize_path as a standalone tool for the rule engine.

        result.into_owned()
    }
}

pub fn url_decode(input: &str) -> String {
    match urlencoding::decode(input) {
        Ok(decoded) => decoded.into_owned(),
        Err(_) => input.to_string(), // Fallback
    }
}

pub fn url_decode_recursive(input: &str, max_depth: u8) -> String {
    let mut current = input.to_string();
    for _ in 0..max_depth {
        let decoded = url_decode(&current);
        if decoded == current {
            break;
        }
        current = decoded;
    }
    current
}

/// Decodes HTML entities with recursive support and bypass prevention.
/// Handles:
/// - Named entities (&lt; -> <)
/// - Numeric decimal (&#60; -> <)
/// - Numeric hex (&#x3C; -> <)
/// - Recursive decoding (up to 3 levels)
/// - Lenient parsing (missing semicolons)
pub fn html_entity_decode(input: &str) -> String {
    // 1. First pass with standard decoder
    // html-escape crate handles named, decimal, and hex entities efficiently.
    let mut current = decode_html_entities(input).into_owned();
    
    // 2. Recursive decoding (Max 3 levels to prevent DoS)
    // Attackers often double/triple encode: &amp;lt; -> &lt; -> <
    let max_depth = 3;
    for _ in 0..max_depth {
        let next = decode_html_entities(&current).into_owned();
        if next == current {
            break;
        }
        current = next;
    }
    
    // 3. Handle lenient bypasses that standard libraries might strictly reject
    // Many browsers are extremely lenient. We must be too.
    // Replace &lt, &gt, &quot, &apos, &amp followed by non-semicolon
    if current.contains('&') {
       current = current.replace("&lt", "<")
                        .replace("&gt", ">")
                        .replace("&quot", "\"")
                        .replace("&apos", "'")
                        .replace("&amp", "&");
    }

    current
}

use base64::{Engine as _, engine::general_purpose};

pub fn base64_decode_if_encoded(input: &str) -> String {
    // Try standard
    if let Ok(decoded) = general_purpose::STANDARD.decode(input) {
         if let Ok(utf8) = String::from_utf8(decoded) {
             return utf8;
         }
    }
    // Try URL safe
    if let Ok(decoded) = general_purpose::URL_SAFE.decode(input) {
         if let Ok(utf8) = String::from_utf8(decoded) {
             return utf8;
         }
    }
    input.to_string()
}

pub fn unicode_normalize(input: &str) -> String {
    input.nfc().collect()
}

pub fn lowercase(input: &str) -> String {
    input.to_lowercase()
}

pub fn remove_whitespace(input: &str) -> String {
    input.split_whitespace().collect()
}

pub fn collapse_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn remove_null_bytes(input: &str) -> String {
    input.replace('\0', "")
}

/// Normalizes a path string to prevent traversal attacks.
/// Steps:
/// 1. URL Decode
/// 2. Windows Backslash normalization
/// 3. Null byte removal
/// 4. Deduplicate slashes
/// 5. Path resolution (stack based)
pub fn normalize_path(input: &str) -> String {
    // 1. URL Decode first (recursive)
    let mut path = url_decode_recursive(input, 3);

    // 2. Normalize Backslashes to Slashes (Windows style)
    path = path.replace('\\', "/");
    
    // 3. Remove Null Bytes (Truncate)
    if let Some(idx) = path.find('\0') {
        path.truncate(idx);
    }
    
    // 4. Collapse Multiple Slashes
    while path.contains("//") {
        path = path.replace("//", "/");
    }
    
    // 5. Resolve Path Segments (handle ., .., and crazy variants like ....)
    let segments = path.split('/');
    let mut stack = Vec::new();
    let is_absolute = path.starts_with('/');
    
    for segment in segments {
        if segment.is_empty() || segment == "." {
            continue;
        }
        
        let clean_segment = segment.trim_end_matches(|c| c == ';' || c == ' '); // Handle ..; and ..(space)
        let is_traversal = clean_segment == ".." || DOT_SEGMENT.is_match(clean_segment);

        if is_traversal {
            if !stack.is_empty() {
                stack.pop();
            }
        } else {
            stack.push(clean_segment);
        }
    }
     
    let mut normalized = stack.join("/");
    if is_absolute {
        normalized.insert(0, '/');
    }
    
    if normalized.is_empty() && is_absolute {
        return "/".to_string();
    }
    
    normalized
}

pub fn remove_sql_comments(input: &str) -> String {
    SQL_COMMENT_REGEX.replace_all(input, "").into_owned()
}

pub fn count_special_chars(input: &str) -> u32 {
    input.chars()
        .filter(|c| ";|&<>'\"()".contains(*c))
        .count() as u32
}

pub fn calculate_entropy(input: &str) -> f32 {
    let mut counts = std::collections::HashMap::new();
    let len = input.len() as f32;
    if len == 0.0 { return 0.0; }
    
    for c in input.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    
    counts.values().fold(0.0, |acc, &count| {
        let p = count as f32 / len;
        acc - p * p.log2()
    })
}
