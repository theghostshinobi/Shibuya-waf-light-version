use waf_killer_core::parser::transforms::*;

#[test]
fn test_url_decode() {
    assert_eq!(url_decode("%27"), "'");
    assert_eq!(url_decode("hello%20world"), "hello world");
    assert_eq!(url_decode("%2527"), "%27"); // Single decode
}

#[test]
fn test_url_decode_recursive() {
    assert_eq!(url_decode_recursive("%2527", 3), "'");
    assert_eq!(url_decode_recursive("%252527", 3), "'");
}

#[test]
fn test_html_entity_decode() {
    assert_eq!(html_entity_decode("&lt;script&gt;"), "<script>");
    assert_eq!(html_entity_decode("&#60;"), "<");
}

#[test]
fn test_base64_decode() {
    // ' OR '1'='1
    let encoded = "JyBPUiAnMSc9JzE=";
    assert_eq!(base64_decode_if_encoded(encoded), "' OR '1'='1");
    // Not base64
    assert_eq!(base64_decode_if_encoded("Hello world!"), "Hello world!");
}

#[test]
fn test_unicode_normalize() {
    // \u0027 -> '
    // Note: Rust strings are UTF-8, so we construct unicode char
    let input = "\u{0041}\u{030A}"; // A with ring
    let normalized = unicode_normalize(input);
    // NFC should compose it
    assert_eq!(normalized.chars().count(), 1); 
}

#[test]
fn test_remove_sql_comments() {
    assert_eq!(remove_sql_comments("SELECT * FROM users -- comment"), "SELECT * FROM users ");
    assert_eq!(remove_sql_comments("SELECT /* comment */ 1"), "SELECT  1");
}

#[test]
fn test_remove_null_bytes() {
    assert_eq!(remove_null_bytes("union%00select"), "union%00select"); // Logic: decoded first
    assert_eq!(remove_null_bytes("union\0select"), "unionselect");
}

#[test]
fn test_normalize_path() {
    assert_eq!(normalize_path("/etc//passwd"), "/etc/passwd");
    assert_eq!(normalize_path("..\\windows"), "../windows");
}

#[test]
fn test_pipeline() {
    let input = "%2527%20OR%201=1"; // Double encoded ' OR 1=1
    let output = TransformPipeline::apply(input);
    assert!(output.contains("' or 1=1"));
}
