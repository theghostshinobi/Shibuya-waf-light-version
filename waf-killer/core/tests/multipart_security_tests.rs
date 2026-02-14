use bytes::Bytes;
use waf_killer_core::parser::body::parse_body;
use waf_killer_core::parser::context::RequestContext;

#[tokio::test]
async fn test_basic_multipart_parsing() {
    let boundary = "----test";
    let body = create_test_multipart(boundary, &[
        ("name", "", None, Some(b"John Doe".to_vec())),
        ("avatar", "profile.jpg", Some("image/jpeg"), Some(fake_jpeg_data())),
    ]);
    
    let mut ctx = RequestContext::new("req1".to_string(), "127.0.0.1".to_string());
    let ct = format!("multipart/form-data; boundary={}", boundary);
    
    let result = parse_body(&mut ctx, Some(&ct), body).await;
    assert!(result.is_ok(), "Parse failed: {:?}", result.err());
    
    let fields = ctx.body_multipart.as_ref().unwrap();
    assert_eq!(fields.len(), 2);
    
    let avatar = fields.iter().find(|f| f.name == "avatar").unwrap();
    assert_eq!(avatar.filename, Some("profile.jpg".to_string()));
    assert_eq!(avatar.content.len(), fake_jpeg_data().len());
}

#[tokio::test]
async fn test_path_traversal_detection() {
    let boundary = "----test";
    let body = create_test_multipart(boundary, &[
        ("file", "../../etc/passwd", Some("text/plain"), Some(b"root:x:0:0".to_vec())),
    ]);
    
    let mut ctx = RequestContext::new("req2".to_string(), "127.0.0.1".to_string());
    let ct = format!("multipart/form-data; boundary={}", boundary);
    
    parse_body(&mut ctx, Some(&ct), body).await.unwrap();
    let fields = ctx.body_multipart.as_ref().unwrap();
    let file_field = &fields[0];
    
    assert!(file_field.security_checks.has_path_traversal);
    assert!(file_field.security_checks.risk_score >= 40);
}

#[tokio::test]
async fn test_php_file_upload_blocked() {
    let php_content = b"<?php system($_GET['cmd']); ?>";
    let boundary = "----test";
    let body = create_test_multipart(boundary, &[
        ("upload", "shell.php", Some("application/x-php"), Some(php_content.to_vec())),
    ]);
    
    let mut ctx = RequestContext::new("req3".to_string(), "127.0.0.1".to_string());
    let ct = format!("multipart/form-data; boundary={}", boundary);
    
    parse_body(&mut ctx, Some(&ct), body).await.unwrap();
    let fields = ctx.body_multipart.as_ref().unwrap();
    let field = &fields[0];
    
    assert!(field.security_checks.is_script);
    assert!(field.security_checks.is_potentially_malicious);
    assert!(field.security_checks.risk_score >= 70);
}

#[tokio::test]
async fn test_content_type_spoofing() {
    // Upload PHP file but declare it as image
    let php_content = b"<?php system('whoami'); ?>";
    let boundary = "----test";
    let body = create_test_multipart(boundary, &[
        ("file", "innocent.png", Some("image/png"), Some(php_content.to_vec())),
    ]);
    
    let mut ctx = RequestContext::new("req4".to_string(), "127.0.0.1".to_string());
    let ct = format!("multipart/form-data; boundary={}", boundary);
    
    parse_body(&mut ctx, Some(&ct), body).await.unwrap();
    let fields = ctx.body_multipart.as_ref().unwrap();
    let field = &fields[0];
    
    assert!(field.security_checks.content_type_mismatch);
    assert_eq!(
        field.security_checks.detected_file_type,
        Some("application/x-httpd-php".to_string())
    );
}

#[tokio::test]
async fn test_executable_upload_detected() {
    // PE header (Windows executable)
    let exe_data = vec![0x4D, 0x5A, 0x90, 0x00];
    let boundary = "----test";
    let body = create_test_multipart(boundary, &[
        ("file", "malware.exe", Some("application/x-msdownload"), Some(exe_data)),
    ]);
    
    let mut ctx = RequestContext::new("req5".to_string(), "127.0.0.1".to_string());
    let ct = format!("multipart/form-data; boundary={}", boundary);
    
    parse_body(&mut ctx, Some(&ct), body).await.unwrap();
    let fields = ctx.body_multipart.as_ref().unwrap();
    let field = &fields[0];
    
    assert!(field.security_checks.is_executable);
}

// Helpers
fn create_test_multipart(boundary: &str, parts: &[(&str, &str, Option<&str>, Option<Vec<u8>>)]) -> Bytes {
    let mut data = Vec::new();
    for (name, filename, content_type, content) in parts {
        data.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        if filename.is_empty() {
            data.extend_from_slice(format!("Content-Disposition: form-data; name=\"{}\"\r\n", name).as_bytes());
        } else {
            data.extend_from_slice(format!("Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n", name, filename).as_bytes());
        }
        
        if let Some(ct) = content_type {
            data.extend_from_slice(format!("Content-Type: {}\r\n", ct).as_bytes());
        }
        data.extend_from_slice(b"\r\n");
        if let Some(c) = content {
            data.extend_from_slice(c);
        }
        data.extend_from_slice(b"\r\n");
    }
    data.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    Bytes::from(data)
}

fn fake_jpeg_data() -> Vec<u8> {
    vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]
}
