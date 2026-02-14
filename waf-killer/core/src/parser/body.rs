use crate::parser::context::{MultipartField, RequestContext};
use crate::parser::multipart_security::{
    validate_file_upload, validate_form_field,
};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use mime::Mime;
use multer::{Constraints, Multipart, SizeLimit};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};
use futures::stream::TryStreamExt;

/// Configuration constants
const MAX_MULTIPART_PARTS: usize = 100;
const MAX_FIELD_SIZE: u64 = 50 * 1024 * 1024; // 50MB per field
const MAX_TOTAL_SIZE: u64 = 100 * 1024 * 1024; // 100MB total

pub async fn parse_body(
    ctx: &mut RequestContext,
    content_type_header: Option<&str>,
    body_bytes: Bytes,
) -> Result<()> {
    if body_bytes.is_empty() {
        return Ok(());
    }

    ctx.body_size = body_bytes.len();
    ctx.body_raw = Some(Arc::new(body_bytes.to_vec()));

    let ct_str = match content_type_header {
        Some(ct) => ct,
        None => return Ok(()),
    };

    ctx.content_type = Some(ct_str.to_string());

    let mime: Mime = ct_str
        .parse()
        .map_err(|_| anyhow!("Invalid Content-Type"))?;

    match (mime.type_().as_str(), mime.subtype().as_str()) {
        ("application", "json") => parse_json(ctx, &body_bytes),
        ("application", "x-www-form-urlencoded") => parse_form(ctx, &body_bytes),
        ("multipart", "form-data") => parse_multipart(ctx, ct_str, body_bytes).await,
        ("text", _) | ("application", "xml") => {
            if let Ok(text) = String::from_utf8(body_bytes.to_vec()) {
                ctx.body_text = Some(text);
            }
            Ok(())
        }
        _ => {
            debug!("Skipping parsing for content type: {}", ct_str);
            Ok(())
        }
    }
}

fn parse_json(ctx: &mut RequestContext, body: &[u8]) -> Result<()> {
    // Always store body_text so REQUEST_BODY variable works for rule matching
    if let Ok(text) = String::from_utf8(body.to_vec()) {
        ctx.body_text = Some(text);
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => {
            ctx.body_json = Some(v);
            Ok(())
        }
        Err(e) => {
            warn!("Failed to parse JSON body: {}", e);
            Ok(())
        }
    }
}

fn parse_form(ctx: &mut RequestContext, body: &[u8]) -> Result<()> {
    // Always store body_text so REQUEST_BODY variable works for rule matching
    if let Ok(text) = String::from_utf8(body.to_vec()) {
        ctx.body_text = Some(text);
    }
    match serde_urlencoded::from_bytes::<HashMap<String, String>>(body) {
        Ok(map) => {
            let mut new_map = HashMap::new();
            for (k, v) in map {
                new_map.insert(k, vec![v]);
            }
            ctx.body_form = Some(new_map);
            Ok(())
        }
        Err(e) => {
             warn!("Failed to parse form body: {}", e);
             Ok(())
        }
    }
}

async fn parse_multipart(ctx: &mut RequestContext, content_type: &str, body: Bytes) -> Result<()> {
    // Extract boundary from Content-Type header
    let boundary = extract_boundary(content_type)
        .ok_or_else(|| anyhow!("Missing boundary parameter"))?;
    
    // Create multipart parser with size constraints
    // Note: Wrapping Bytes into a stream for multer
    let stream = futures::stream::once(async move { Ok::<Bytes, anyhow::Error>(body) });
    
    let constraints = Constraints::new()
        .size_limit(
            SizeLimit::new()
                .per_field(MAX_FIELD_SIZE)
                .whole_stream(MAX_TOTAL_SIZE)
        );
        
    let mut multipart = Multipart::with_constraints(stream, boundary, constraints);
    let mut fields = Vec::new();
    let mut total_size = 0usize;
    
    // Parse each field
    while let Some(field) = multipart.next_field().await
        .map_err(|e| anyhow!("Multipart parse error: {}", e))?
    {
        // Security: Limit number of parts (DoS prevention)
        if fields.len() >= MAX_MULTIPART_PARTS {
            warn!("Too many multipart parts, stopping parse");
            break;
        }
        
        let parsed_field = parse_multipart_field(field).await?;
        total_size += parsed_field.size;
        fields.push(parsed_field);
        
        // Log suspicious fields
        if fields.last().unwrap().security_checks.risk_score >= 50 {
            warn!(
                "High-risk file upload detected: {} (risk: {})",
                fields.last().unwrap().filename.as_deref().unwrap_or("unknown"),
                fields.last().unwrap().security_checks.risk_score
            );
        }
    }
    
    debug!(
        "Parsed {} multipart fields, total size: {} bytes",
        fields.len(),
        total_size
    );
    
    ctx.body_multipart = Some(fields);
    Ok(())
}

/// Parse individual multipart field with security checks
async fn parse_multipart_field(
    mut field: multer::Field<'static>,
) -> Result<MultipartField> {
    // Extract field metadata
    let name = field.name()
        .ok_or_else(|| anyhow!("Field missing name"))?
        .to_string();
    
    let filename = field.file_name().map(|s| s.to_string());
    let content_type = field.content_type()
        .map(|mime| mime.to_string());
    
    // Read field data into memory
    let mut data = Vec::new();
    
    while let Some(chunk) = field.chunk().await
        .map_err(|e| anyhow!("Multipart chunk error: {}", e))?
    {
        data.extend_from_slice(&chunk);
        
        // Additional safety check
        if data.len() as u64 > MAX_FIELD_SIZE {
             return Err(anyhow!("Field '{}' too large", name));
        }
    }
    
    let size = data.len();
    
    // ✨ SECURITY VALIDATIONS ✨
    let security_checks = if filename.is_some() {
        // This is a file upload - run comprehensive security checks
        validate_file_upload(&name, filename.as_deref(), content_type.as_deref(), &data)
            .map_err(|e| anyhow!("Security check failed: {}", e))?
    } else {
        // Regular form field - basic checks
        validate_form_field(&name, &data)
    };
    
    Ok(MultipartField {
        name,
        filename,
        content_type,
        content: Arc::new(data),
        size,
        security_checks,
    })
}

/// Extract boundary from Content-Type header
fn extract_boundary(content_type: &str) -> Option<String> {
    // Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
    content_type
        .split(';')
        .find_map(|part| {
            let part = part.trim();
            if part.starts_with("boundary=") {
                Some(part[9..].trim_matches('"').to_string())
            } else {
                None
            }
        })
}
