use sha2::{Sha256, Digest};
use regex::Regex;
use lazy_static::lazy_static;

/// Calculate JA3 fingerprint from TLS ClientHello
/// JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
/// For now, this is a simplified version since true JA3 requires TLS packet parsing
pub fn calculate_ja3_hash(tls_info: &TlsInfo) -> String {
    // In production, you'd parse actual TLS ClientHello bytes
    // For this implementation, we'll generate a hash from available TLS metadata
    let ja3_string = format!(
        "{},{},{},{},{}",
        tls_info.version,
        tls_info.ciphers.join("-"),
        tls_info.extensions.join("-"),
        tls_info.curves.join("-"),
        tls_info.point_formats.join("-")
    );
    
    let mut hasher = Sha256::new();
    hasher.update(ja3_string.as_bytes());
    hex::encode(hasher.finalize())
}

/// TLS information extracted from connection
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub version: String,
    pub ciphers: Vec<String>,
    pub extensions: Vec<String>,
    pub curves: Vec<String>,
    pub point_formats: Vec<String>,
}

impl Default for TlsInfo {
    fn default() -> Self {
        Self {
            version: "unknown".to_string(),
            ciphers: vec![],
            extensions: vec![],
            curves: vec![],
            point_formats: vec![],
        }
    }
}

lazy_static! {
    /// Known bot User-Agent patterns
    static ref BOT_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)bot").unwrap(),
        Regex::new(r"(?i)crawler").unwrap(),
        Regex::new(r"(?i)spider").unwrap(),
        Regex::new(r"(?i)scraper").unwrap(),
        Regex::new(r"(?i)curl").unwrap(),
        Regex::new(r"(?i)wget").unwrap(),
        Regex::new(r"(?i)python-requests").unwrap(),
        Regex::new(r"(?i)go-http-client").unwrap(),
        Regex::new(r"(?i)httpclient").unwrap(),
        Regex::new(r"(?i)java").unwrap(),
        Regex::new(r"(?i)headless").unwrap(),
        Regex::new(r"(?i)phantom").unwrap(),
        Regex::new(r"(?i)selenium").unwrap(),
        Regex::new(r"(?i)puppeteer").unwrap(),
    ];
    
    /// Legitimate browser patterns
    static ref BROWSER_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"Mozilla/5\.0.*Chrome").unwrap(),
        Regex::new(r"Mozilla/5\.0.*Firefox").unwrap(),
        Regex::new(r"Mozilla/5\.0.*Safari").unwrap(),
        Regex::new(r"Mozilla/5\.0.*Edge").unwrap(),
    ];
}

/// Analyze User-Agent string and return bot score
/// Returns: 0.0 = clearly human, 1.0 = clearly bot
pub fn analyze_user_agent(user_agent: &str) -> f32 {
    if user_agent.is_empty() {
        return 0.9; // No UA = suspicious
    }
    
    // Check for known bot patterns
    for pattern in BOT_PATTERNS.iter() {
        if pattern.is_match(user_agent) {
            return 1.0; // Clear bot
        }
    }
    
    // Check for legitimate browser patterns
    for pattern in BROWSER_PATTERNS.iter() {
        if pattern.is_match(user_agent) {
            // Additional checks for fake browser UAs
            if user_agent.len() < 50 {
                return 0.6; // Too short to be real browser
            }
            return 0.1; // Likely legitimate
        }
    }
    
    // Unknown UA pattern
    0.5
}

/// HTTP/2 fingerprinting based on frame order and priority
#[derive(Debug, Default)]
pub struct Http2Fingerprint {
    pub settings_order: Vec<String>,
    pub window_update: u32,
    pub priority_frames: Vec<String>,
}

pub fn calculate_http2_score(h2_info: &Http2Fingerprint) -> f32 {
    // Simplified scoring: real browsers tend to have specific patterns
    // Bots/scripts often have different or missing HTTP/2 behaviors
    
    if h2_info.settings_order.is_empty() {
        return 0.7; // No HTTP/2 settings = suspicious
    }
    
    // Real browsers typically send 6+ SETTINGS
    if h2_info.settings_order.len() < 4 {
        return 0.6;
    }
    
    // Check for known browser patterns
    let settings_str = h2_info.settings_order.join(",");
    
    // Chrome/Chromium pattern example
    if settings_str.contains("HEADER_TABLE_SIZE") && 
       settings_str.contains("ENABLE_PUSH") {
        return 0.2; // Looks like real browser
    }
    
    0.4 // Neutral
}

/// Calculate overall bot score from multiple signals
pub fn calculate_bot_score(
    user_agent: &str,
    tls_info: Option<&TlsInfo>,
    http2_info: Option<&Http2Fingerprint>,
) -> f32 {
    let ua_score = analyze_user_agent(user_agent);
    
    let tls_score = if let Some(tls) = tls_info {
        // Check if TLS fingerprint matches known bots
        let _ja3 = calculate_ja3_hash(tls);
        
        // In production, you'd maintain a database of known bot JA3 hashes
        // For now, simple heuristics
        if tls.ciphers.is_empty() {
            0.8
        } else if tls.ciphers.len() < 5 {
            0.6 // Minimal cipher list = suspicious
        } else {
            0.3
        }
    } else {
        0.5 // No TLS info available
    };
    
    let http2_score = if let Some(h2) = http2_info {
        calculate_http2_score(h2)
    } else {
        0.5 // No HTTP/2 info
    };
    
    // Weighted average with emphasis on UA
    (ua_score * 0.5) + (tls_score * 0.3) + (http2_score * 0.2)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bot_user_agents() {
        assert!(analyze_user_agent("curl/7.68.0") > 0.9);
        assert!(analyze_user_agent("python-requests/2.25.1") > 0.9);
        assert!(analyze_user_agent("Googlebot/2.1") > 0.9);
    }
    
    #[test]
    fn test_browser_user_agents() {
        let chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
        assert!(analyze_user_agent(chrome_ua) < 0.3);
    }
}
