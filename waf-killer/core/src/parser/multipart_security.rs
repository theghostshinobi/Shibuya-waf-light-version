use std::collections::HashMap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

/// Comprehensive file upload security validation
pub fn validate_file_upload(
    _field_name: &str,
    filename: Option<&str>,
    content_type: Option<&str>,
    data: &[u8],
) -> Result<FileSecurityChecks, BodyParseError> {
    let mut checks = FileSecurityChecks::default();
    checks.declared_file_type = content_type.map(|s| s.to_string());
    
    // VALIDATION 1: Filename Security
    if let Some(fname) = filename {
        validate_filename(fname, &mut checks);
    }
    
    // VALIDATION 2: Magic Bytes Detection
    let detected_type = detect_file_type_from_magic(data);
    checks.detected_file_type = detected_type.clone();
    
    // VALIDATION 3: Content-Type Spoofing Detection
    if let (Some(declared), Some(detected)) = (content_type, &detected_type) {
        if !content_types_match(declared, detected) {
            checks.content_type_mismatch = true;
            checks.risk_score += 35;
            checks.warnings.push(format!(
                "Content-Type mismatch: declared '{}' but detected '{}'",
                declared, detected
            ));
        }
    }
    
    // VALIDATION 4: Malicious Content Scanning
    scan_for_malicious_content(data, &mut checks);
    
    // VALIDATION 5: File Size Anomalies
    check_size_anomalies(data.len(), &mut checks);
    
    // VALIDATION 6: Polyglot Detection
    detect_polyglot(data, &mut checks);
    
    // VALIDATION 7: Archive Bomb Detection (zip, tar, gz)
    if is_archive_type(&checks.detected_file_type) {
        check_archive_safety(data, &mut checks);
    }
    
    Ok(checks)
}

/// Validate filename for security issues
fn validate_filename(filename: &str, checks: &mut FileSecurityChecks) {
    // 1. Path traversal attempts
    if filename.contains("..") || filename.contains("/") || filename.contains("\\") {
        checks.has_path_traversal = true;
        checks.risk_score += 40;
        checks.warnings.push(format!("Path traversal attempt in filename: {}", filename));
    }
    
    // 2. Null byte injection (truncation attack)
    if filename.contains('\0') {
        checks.is_suspicious_filename = true;
        checks.risk_score += 50;
        checks.warnings.push("Null byte in filename".to_string());
    }
    
    // 3. Control characters
    if filename.chars().any(|c| c.is_control()) {
        checks.is_suspicious_filename = true;
        checks.risk_score += 25;
    }
    
    // 4. Suspicious double extensions (file.jpg.php)
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() > 2 {
        let last_two = &parts[parts.len()-2..];
        if is_executable_extension(last_two[1]) || is_script_extension(last_two[1]) {
             // Check if the second to last part is executable/script.
             // Actually logic in prompt was: if is_executable_extension(last_two) || is_executable_extension(last_two) which was a typo in prompt?
             // Prompt code:
             // if is_executable_extension(last_two) || is_executable_extension(last_two) {
             //    checks.is_suspicious_filename = true;
             //    checks.risk_score += 30;
             // }
             // Wait, `last_two` is a slice of &str. `is_executable_extension` takes explicit filename.
             // I'll implement a safer check here.
             // If we have "file.jpg.php", parts are ["file", "jpg", "php"]. last_two is ["jpg", "php"].
             // We want to check if "file.jpg" (part[0..len-1]) + ".php" is suspicious?
             // The common attack is "image.jpg.php" or "image.php.jpg".
             // Apache sometime executes "image.php.jpg" as PHP if configured with AddHandler.
             // Let's check if ANY part (except maybe the first) looks like an executable extension.
             for part in &parts[1..] {
                 let dummy_filename = format!("test.{}", part);
                 if is_executable_extension(&dummy_filename) || is_script_extension(&dummy_filename) {
                     // If it's the LAST part, it's caught by extension check below.
                     // If it's NOT the last part, it's a double extension attack.
                     if part != parts.last().unwrap() {
                         checks.is_suspicious_filename = true;
                         checks.risk_score += 30;
                         checks.warnings.push(format!("Double extension detected: inner extension .{} is suspicious", part));
                     }
                 }
             }
        }
    }
    
    // 5. Executable extensions
    if is_executable_extension(filename) {
        checks.is_executable = true;
        checks.risk_score += 30;
        checks.warnings.push(format!("Executable extension: {}", filename));
    }
    
    // 6. Script extensions
    if is_script_extension(filename) {
        checks.is_script = true;
        checks.risk_score += 35;
        checks.warnings.push(format!("Script file extension: {}", filename));
    }
    
    // 7. Very long filename (DoS / buffer overflow attempts)
    if filename.len() > 255 {
        checks.is_suspicious_filename = true;
        checks.risk_score += 20;
        checks.warnings.push("Filename exceeds 255 characters".to_string());
    }
    
    // 8. Unicode tricks (homograph attacks)
    if filename.chars().any(|c| c as u32 > 0x7F) {
        checks.risk_score += 10;
        checks.warnings.push("Non-ASCII characters in filename".to_string());
    }
}

/// Detect file type from magic bytes
fn detect_file_type_from_magic(data: &[u8]) -> Option<String> {
    if data.len() < 4 { // Relaxed validation for short files, but magic usually needs some bytes
        return None;
    }
    
    // Use `infer` crate if available, as per Cargo.toml addition, or manual checks.
    // The prompt implemented manual checks. I'll stick to manual to match prompt but enhance if needed.
    // Actually, I added `infer` crate. Let's use it for better detection, but keep the manual fallbacks for critical security types (like PHP hacks)
    
    // Manual critical checks first
    match &data[..] {
         // Executables (DANGER)
        [0x4D, 0x5A, ..] => return Some("application/x-msdownload".to_string()), // .exe, .dll
        [0x7F, 0x45, 0x4C, 0x46, ..] => return Some("application/x-elf".to_string()), // Linux binary
        [0xCE, 0xFA, 0xED, 0xFE, ..] |
        [0xCF, 0xFA, 0xED, 0xFE, ..] => return Some("application/x-mach-binary".to_string()), // macOS binary
        _ => {}
    }

    if let Some(kind) = infer::get(data) {
        return Some(kind.mime_type().to_string());
    }
    
    // Check magic bytes signatures manually if infer fails or for text types
    match &data[..] {
        _ => {
            // Check for text-based formats
            if let Ok(text) = std::str::from_utf8(&data[..data.len().min(512)]) {
                let text_lower = text.to_lowercase();
                
                // CRITICAL: Check for dangerous script types
                if text.starts_with("<?php") || text_lower.contains("<?php") {
                    return Some("application/x-httpd-php".to_string()); // 🚨 DANGER
                }
                if text.starts_with("#!/") {
                    return Some("application/x-sh".to_string()); // 🚨 DANGER
                }
                if text.starts_with("<%@") || text_lower.contains("<%@") {
                    return Some("application/x-jsp".to_string()); // 🚨 DANGER
                }
                if text_lower.starts_with("<?xml") {
                    return Some("application/xml".to_string());
                }
                if text_lower.starts_with("<!doctype html") || text_lower.starts_with("<html") {
                    return Some("text/html".to_string());
                }
                
                // Default to text/plain for valid UTF-8
                Some("text/plain".to_string())
            } else {
                // Binary data with no known signature
                Some("application/octet-stream".to_string())
            }
        }
    }
}

/// Check if Content-Types match (accounting for variations)
fn content_types_match(declared: &str, detected: &str) -> bool {
    // Normalize
    let declared = declared.split(';').next().unwrap_or(declared).trim().to_lowercase();
    let detected = detected.to_lowercase();
    
    // Exact match
    if declared == detected {
        return true;
    }
    
    // Generic matches
    if (declared == "application/octet-stream" || declared == "binary/octet-stream") && detected != "text/plain" {
        return true; // Generic binary type is acceptable
    }
    
    // Specific allowances
    let allowances = HashMap::from([
        ("image/jpg", "image/jpeg"),
        ("image/x-png", "image/png"),
    ]);
    
    if let Some(&expected) = allowances.get(declared.as_str()) {
        if detected == expected {
            return true;
        }
    }
    
    false
}

/// Scan file content for malicious patterns
fn scan_for_malicious_content(data: &[u8], checks: &mut FileSecurityChecks) {
    // Try to interpret as text
    let text = if let Ok(t) = std::str::from_utf8(data) {
        t.to_lowercase()
    } else {
        // For binary files, search in raw bytes
        return scan_binary_for_malware(data, checks);
    };
    
    lazy_static! {
        static ref MALICIOUS_PATTERNS: Vec<(&'static str, u8, &'static str)> = vec![
            // (pattern, risk_points, description)
            ("<?php", 40, "PHP code detected"),
            ("<%@", 40, "JSP code detected"),
            ("<script", 30, "JavaScript detected"),
            ("eval(", 35, "eval() function"),
            ("base64_decode", 30, "base64_decode()"),
            ("exec(", 40, "exec() function"),
            ("system(", 40, "system() call"),
            ("shell_exec", 40, "shell_exec()"),
            ("passthru", 35, "passthru()"),
            ("<!entity", 35, "XML entity (XXE risk)"),
            ("<!doctype", 15, "DOCTYPE declaration"),
            ("javascript:", 30, "javascript: protocol"),
            ("vbscript:", 35, "vbscript: protocol"),
            ("on error", 25, "VBScript error handler"),
            ("<iframe", 25, "iframe tag"),
            ("document.cookie", 20, "Cookie access"),
            ("window.location", 20, "Location manipulation"),
        ];
    }
    
    for (pattern, points, description) in MALICIOUS_PATTERNS.iter() {
        if text.contains(pattern) {
            checks.is_potentially_malicious = true;
            checks.risk_score += points;
            checks.warnings.push(format!("Malicious pattern: {}", description));
        }
    }
}

/// Scan binary data for embedded malware signatures
fn scan_binary_for_malware(data: &[u8], checks: &mut FileSecurityChecks) {
    // Search for suspicious byte sequences
    let suspicious_sequences: Vec<&[u8]> = vec![
        b"<?php",
        b"#!/bin/sh",
        b"#!/bin/bash",
        b"MZ", // PE header
    ];
    
    for seq in suspicious_sequences {
        if data.windows(seq.len()).any(|window| window == seq) {
            checks.is_potentially_malicious = true;
            checks.risk_score += 30;
            checks.warnings.push("Suspicious byte sequence in binary".to_string());
        }
    }
}

/// Detect polyglot files (valid in multiple formats)
fn detect_polyglot(data: &[u8], checks: &mut FileSecurityChecks) {
    let mut format_count = 0;
    
    // Check for multiple valid formats in same file
    if data.starts_with(b"\xFF\xD8\xFF") {
        format_count += 1; // JPEG
    }
    if data.starts_with(b"\x89PNG") {
        format_count += 1; // PNG
    }
    if data.windows(5).any(|w| w == b"<?php") {
        format_count += 1; // PHP
    }
    if data.windows(7).any(|w| w == b"<script") {
        format_count += 1; // HTML/JS
    }
    
    if format_count >= 2 {
        checks.risk_score += 40;
        checks.warnings.push("Polyglot file detected (valid in multiple formats)".to_string());
    }
}

/// Check for archive bombs (zip/gzip with extreme compression ratios)
fn check_archive_safety(data: &[u8], checks: &mut FileSecurityChecks) {
    let compressed_size = data.len();
    if compressed_size == 0 { return; }

    // For ZIP files, check compression ratio without extracting
    if data.starts_with(b"PK\x03\x04") {
        if let Ok(uncompressed_hint) = estimate_zip_uncompressed_size(data) {
            let ratio = uncompressed_hint as f64 / compressed_size as f64;
            
            if ratio > 100.0 {
                checks.risk_score += 50;
                checks.warnings.push(format!("Suspicious compression ratio: {:.0}x (possible zip bomb)", ratio));
            }
        }
    }
}

fn estimate_zip_uncompressed_size(data: &[u8]) -> Result<usize, ()> {
    // Parse ZIP central directory to get uncompressed sizes
    // This is a simplified check - full implementation would use zip crate
    if data.len() < 30 {
        return Err(());
    }
    
    // Read uncompressed size from local file header (bytes 22-25) - very rough check, looking at first file
    if data.len() >= 26 {
        // Zip local file header:
        // [0-4] Signature
        // ...
        // [22-26] Uncompressed size
        let size_bytes = &data[22..26];
        let size = u32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]]) as usize;
        Ok(size)
    } else {
        Err(())
    }
}

/// Check for size anomalies
fn check_size_anomalies(size: usize, checks: &mut FileSecurityChecks) {
    // Extremely small "images" (likely not real)
    if size < 100 && checks.detected_file_type.as_ref().map(|t| t.starts_with("image/")).unwrap_or(false) {
        checks.risk_score += 15;
        checks.warnings.push("Suspiciously small image file".to_string());
    }
    
    // Empty files
    if size == 0 {
        checks.risk_score += 20;
        checks.warnings.push("Empty file upload".to_string());
    }
}

fn is_archive_type(file_type: &Option<String>) -> bool {
    file_type.as_ref().map(|t| {
        t.contains("zip") || t.contains("gzip") || t.contains("tar") || t.contains("rar")
    }).unwrap_or(false)
}

/// Check if extension is executable
fn is_executable_extension(filename: &str) -> bool {
    const EXECUTABLE_EXTS: &[&str] = &[
        ".exe", ".dll", ".so", ".dylib", ".sys",
        ".com", ".bat", ".cmd", ".msi", ".scr",
        ".jar", ".war", ".ear",
        ".app", ".deb", ".rpm",
    ];
    
    let fname_lower = filename.to_lowercase();
    EXECUTABLE_EXTS.iter().any(|ext| fname_lower.ends_with(ext))
}

/// Check if extension is script
fn is_script_extension(filename: &str) -> bool {
    const SCRIPT_EXTS: &[&str] = &[
        ".php", ".php3", ".php4", ".php5", ".phtml",
        ".jsp", ".jspx",
        ".asp", ".aspx", ".asa", ".asax",
        ".sh", ".bash", ".zsh",
        ".py", ".pyc", ".pyo",
        ".rb", ".pl", ".cgi",
        ".ps1", ".psm1",
        ".vbs", ".vbe",
        ".js", ".jsx",
    ];
    
    let fname_lower = filename.to_lowercase();
    SCRIPT_EXTS.iter().any(|ext| fname_lower.ends_with(ext))
}

/// Validate regular form field
pub fn validate_form_field(name: &str, data: &[u8]) -> FileSecurityChecks {
    let mut checks = FileSecurityChecks::default();
    
    // Check for injection attempts in form data
    if let Ok(text) = std::str::from_utf8(data) {
        if text.len() > 10_000 {
            checks.risk_score += 10;
            checks.warnings.push("Unusually large form field".to_string());
        }
        
        // Basic XSS check
         if text.contains("<script") || text.contains("javascript:") {
             checks.risk_score += 20;
             checks.warnings.push(format!("Suspicious content in form field '{}'", name));
         }
    }
    
    checks
}

/// Error types
#[derive(Debug, thiserror::Error)]
pub enum BodyParseError {
    #[error("Invalid multipart: {0}")]
    InvalidMultipart(String),
    
    #[error("Multipart parse error: {0}")]
    MultipartParse(String),
    
    #[error("Too many multipart parts: limit={limit}, attempted={attempted}")]
    TooManyParts { limit: usize, attempted: usize },
    
    #[error("Field '{name}' too large: {size} bytes (limit: {limit})")]
    FieldTooLarge { name: String, size: usize, limit: usize },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileSecurityChecks {
    pub is_suspicious_filename: bool,
    pub has_path_traversal: bool,
    pub is_executable: bool,
    pub is_script: bool,
    pub content_type_mismatch: bool,
    pub is_potentially_malicious: bool,
    pub detected_file_type: Option<String>,
    pub declared_file_type: Option<String>,
    pub risk_score: u8,  // 0-100
    pub warnings: Vec<String>,
}
