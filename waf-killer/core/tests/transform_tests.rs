use waf_killer_core::parser::transforms::{html_entity_decode, normalize_path};

#[test]
fn test_html_entity_decode_named() {
    assert_eq!(html_entity_decode("&lt;script&gt;"), "<script>");
    assert_eq!(html_entity_decode("&amp;&lt;"), "&<");
}

#[test]
fn test_html_entity_decode_numeric_decimal() {
    assert_eq!(html_entity_decode("&#60;script&#62;"), "<script>");
    assert_eq!(html_entity_decode("&#39;OR&#39;1&#39;=&#39;1"), "'OR'1'='1");
}

#[test]
fn test_html_entity_decode_numeric_hex() {
    assert_eq!(html_entity_decode("&#x3C;script&#x3E;"), "<script>");
    assert_eq!(html_entity_decode("&#x27;OR&#x27;"), "'OR'");
}

#[test]
fn test_html_entity_decode_recursive() {
    assert_eq!(html_entity_decode("&amp;lt;"), "<");
    assert_eq!(html_entity_decode("&amp;amp;lt;"), "<");
}

#[test]
fn test_html_entity_decode_missing_semicolon() {
    assert_eq!(html_entity_decode("&ltscript&gt"), "<script>");
}

#[test]
fn test_html_entity_decode_invalid() {
    // Current behavior: invalid entities remain as strings or are partially decoded if they contain valid prefixes?
    // &invalid; -> &invalid;
    assert_eq!(html_entity_decode("&invalid;"), "&invalid;");
    
    // Out of range: &#999999; 
    // html_escape behavior on out of range? It usually uses the replacement char or leaves it. 
    // Let's assert what we expect. safest is to leave it or replace.
    // Let's verify what `html_escape` does. If it replaces with REPLACEMENT CHARACTER, that's fine.
    // If it leaves it, that's fine too. 
    let result = html_entity_decode("&#99999999;");
    // Assert it contains original or replacement check. 
    // Ideally we just want to ensure it doesn't panic.
    assert!(result.contains("&#") || result.contains("\u{FFFD}"));
}

#[test]
fn test_html_entity_decode_xss_bypass_attempts() {
    // Real-world bypass attempts from bug bounty reports
    assert_eq!(html_entity_decode("&#x3C;img src=x onerror=alert(1)&#x3E;"), "<img src=x onerror=alert(1)>");
    assert_eq!(html_entity_decode("&lt;svg/onload=alert(1)&gt;"), "<svg/onload=alert(1)>");
    assert_eq!(html_entity_decode("&#60;iframe src=javascript:alert(1)&#62;"), "<iframe src=javascript:alert(1)>");
}

// Path Normalization Tests

#[test]
fn test_normalize_path_basic_traversal() {
    assert_eq!(normalize_path("../../etc/passwd"), "etc/passwd");
    assert_eq!(normalize_path("../../../etc/passwd"), "etc/passwd");
    assert_eq!(normalize_path("./config/./app.conf"), "config/app.conf");
}

#[test]
fn test_normalize_path_double_dot_variants() {
    assert_eq!(normalize_path("....//....//etc/passwd"), "etc/passwd");
    assert_eq!(normalize_path("..;/..;/etc/passwd"), "etc/passwd");
}

#[test]
fn test_normalize_path_backslashes() {
    assert_eq!(normalize_path("..\\..\\etc\\passwd"), "etc/passwd");
    assert_eq!(normalize_path("..\\\\..\\\\etc"), "etc");
}

#[test]
fn test_normalize_path_multiple_slashes() {
    assert_eq!(normalize_path("/api///v1////users"), "/api/v1/users");
    assert_eq!(normalize_path("//////////etc/passwd"), "/etc/passwd");
}

#[test]
fn test_normalize_path_null_byte() {
    assert_eq!(normalize_path("../../etc/passwd\0.jpg"), "etc/passwd");
}

#[test]
fn test_normalize_path_real_world_bypasses() {
    // Actual bypass techniques from CTFs and bug bounties
    assert_eq!(normalize_path("....//....//....//etc/passwd"), "etc/passwd");
    assert_eq!(normalize_path("/var/www/../../etc/passwd"), "/etc/passwd");
    assert_eq!(normalize_path("/app/./../../etc/passwd"), "/etc/passwd");
}

#[test]
fn test_normalize_path_legitimate_paths() {
    // Don't break valid paths
    assert_eq!(normalize_path("/api/v1/users/123"), "/api/v1/users/123");
    assert_eq!(normalize_path("/static/images/logo.png"), "/static/images/logo.png");
}

#[test]
fn test_normalize_path_encoded() {
    // URL encoded
    assert_eq!(normalize_path("%2e%2e%2fetc%2fpasswd"), "etc/passwd");
    assert_eq!(normalize_path("..%252Fetc%252Fpasswd"), "etc/passwd"); // double encoded /
}
