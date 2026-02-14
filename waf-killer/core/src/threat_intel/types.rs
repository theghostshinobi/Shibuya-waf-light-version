use std::net::IpAddr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// IP reputation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputation {
    pub ip: IpAddr,
    pub reputation_score: u8,      // 0-100 (0=clean, 100=malicious)
    pub threat_type: ThreatType,
    pub source: String,             // Which feed reported this
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub confidence: f32,            // 0.0-1.0
    pub metadata: IpMetadata,
}

/// Type of threat associated with IP
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatType {
    Clean,              // No known threats
    Suspicious,         // Low confidence threat
    Botnet,             // Known botnet member
    Scanner,            // Port scanner / vulnerability scanner
    BruteForce,         // Brute force attacker
    Spam,               // Spam source
    Proxy,              // Open proxy / VPN
    TorExit,            // Tor exit node
    Malware,            // Malware C2 server
    Phishing,           // Phishing site
    DDoS,               // DDoS participant
    Datacenter,         // Datacenter IP (not inherently bad but suspicious)
}

/// Additional metadata about IP
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpMetadata {
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub is_proxy: bool,
    pub is_tor: bool,
    pub is_datacenter: bool,
    pub abuse_confidence: Option<u8>,  // AbuseIPDB score
}

/// Threat feed source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    pub name: String,
    pub source_type: FeedType,
    pub url: Option<String>,
    pub file_path: Option<String>,
    pub api_key: Option<String>,
    pub update_interval_hours: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedType {
    StaticFile,         // Load from local file
    HttpApi,            // Fetch from HTTP API
    AbuseIPDB,          // AbuseIPDB API
    AlienVault,         // AlienVault OTX
    TorExitNodes,       // Tor project exit node list
}

#[derive(Debug, thiserror::Error)]
pub enum ThreatIntelError {
    #[error("File error: {0}")]
    FileError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Api error: {0}")]
    ApiError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Authentication failed")]
    AuthenticationFailed,
}
