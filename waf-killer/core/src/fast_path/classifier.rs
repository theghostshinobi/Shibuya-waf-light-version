use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use lru::LruCache;
use parking_lot::Mutex;
use xxhash_rust::xxh3::xxh3_64;

// Simplify RequestContext for this episode's context if not strictly defined elsewhere, 
// or assume it effectively has these fields.
// For now, I'll define a minimal struct or rely on usage to imply it.
// To avoid compilation errors if RequestContext isn't imported, I'll assume we pass the necessary fields or a generic context object.
// We will look for RequestContext definition later or assume it's in crate::proxy.

use crate::parser::context::RequestContext;

pub struct FastPathClassifier {
    whitelist_cache: Arc<DashMap<IpAddr, Instant>>,
    negative_cache: Arc<Mutex<LruCache<u64, ()>>>,
}

impl FastPathClassifier {
    pub fn new() -> Self {
        Self {
            whitelist_cache: Arc::new(DashMap::new()),
            negative_cache: Arc::new(Mutex::new(LruCache::new(std::num::NonZeroUsize::new(100_000).unwrap()))),
        }
    }

    /// Returns true if request can bypass heavy checks
    #[inline(always)]
    pub fn can_fast_path(&self, ctx: &RequestContext) -> bool {
        // 1. IP whitelist check (O(1))
        if self.is_whitelisted_ip(&ctx.client_ip) {
            return true;
        }
        
        // 2. Static content (images, CSS, JS) - always safe
        if self.is_static_content(&ctx.uri) {
            return true;
        }
        
        // 3. Request hash in negative cache (seen before, was clean)
        let hash = self.hash_request(ctx);
        if self.negative_cache.lock().contains(&hash) {
            return true;
        }
        
        // 4. Simple heuristics (no suspicious patterns)
        if !self.has_suspicious_patterns(ctx) {
            return true;
        }
        
        false
    }
    
    #[inline(always)]
    fn is_whitelisted_ip(&self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.whitelist_cache.get(ip) {
            // Check if whitelist entry is still valid (5 min TTL)
            entry.elapsed() < Duration::from_secs(300)
        } else {
            false
        }
    }
    
    #[inline(always)]
    fn is_static_content(&self, uri: &str) -> bool {
        // SIMD-accelerated suffix matching (conceptually, relying on compiler mainly here for simple slice check)
        static STATIC_EXTENSIONS: &[&str] = &[
            ".jpg", ".jpeg", ".png", ".gif", ".webp",
            ".css", ".js", ".woff", ".woff2", ".ttf",
            ".ico", ".svg", ".mp4", ".webm",
        ];
        
        // Check last 10 chars only (fast)
        let suffix = &uri[uri.len().saturating_sub(10)..];
        
        STATIC_EXTENSIONS.iter().any(|ext| suffix.ends_with(ext))
    }
    
    #[inline(always)]
    fn hash_request(&self, ctx: &RequestContext) -> u64 {
        let mut hasher = xxh3_64::new();
        hasher.update(ctx.method.as_bytes());
        hasher.update(ctx.uri.as_bytes());
        // Simple body check if available
        // hasher.update(&ctx.body_raw.as_ref().map(|b| &b[..100]).unwrap_or(&[])); 
        // For now safely handling potentially empty or non-existent body field if generic
        hasher.finish()
    }
    
    #[inline(always)]
    fn has_suspicious_patterns(&self, ctx: &RequestContext) -> bool {
        // Quick scan for obvious attack patterns
        
        let uri_lower = ctx.uri.to_lowercase();
        
        // SQL injection keywords
        if uri_lower.contains("union") || 
           uri_lower.contains("select") ||
           uri_lower.contains("' or '") {
            return true;
        }
        
        // XSS patterns
        if uri_lower.contains("<script") || 
           uri_lower.contains("javascript:") ||
           uri_lower.contains("onerror=") {
            return true;
        }
        
        // Path traversal
        if uri_lower.contains("../") || uri_lower.contains("..\\") {
            return true;
        }
        
        false
    }
}
