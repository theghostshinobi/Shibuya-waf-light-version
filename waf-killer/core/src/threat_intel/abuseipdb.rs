use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use std::net::IpAddr;
use crate::threat_intel::types::{IpReputation, ThreatType, IpMetadata, ThreatIntelError};
use chrono::Utc;

pub struct AbuseIPDBClient {
    client: Client,
    api_key: String,
    base_url: String,
    // rate_limiter: RateLimiter, // Simplified for now, relying on external management or just simple implementation
}

#[derive(Debug, Deserialize)]
struct AbuseIPDBCheckResponse {
    data: AbuseIPDBData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct AbuseIPDBData {
    ip_address: String,
    is_public: bool,
    ip_version: u8,
    is_whitelisted: bool,
    abuse_confidence_score: u8,
    country_code: Option<String>,
    usage_type: Option<String>,
    isp: Option<String>,
    domain: Option<String>,
    hostnames: Vec<String>,
    is_tor: bool,
    total_reports: u32,
    num_distinct_users: u32,
    last_reported_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AbuseIPDBBlacklistResponse {
    meta: BlacklistMeta,
    data: Vec<BlacklistEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct BlacklistMeta {
    generated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlacklistEntry {
    ip_address: String,
    abuse_confidence_score: u8,
}

impl AbuseIPDBClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            api_key,
            base_url: "https://api.abuseipdb.com/api/v2".to_string(),
        }
    }
    
    /// Check single IP reputation
    pub async fn check_ip(&self, ip: IpAddr) -> Result<Option<IpReputation>, ThreatIntelError> {
        let url = format!("{}/check", self.base_url);
        
        // Note: Real implementation should handle rate limiting here or in caller
        
        let response = self.client
            .get(&url)
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .query(&[
                ("ipAddress", ip.to_string()),
                ("maxAgeInDays", "90".to_string()),
                // ("verbose", "".to_string()), 
            ])
            .send()
            .await
            .map_err(|e| ThreatIntelError::NetworkError(e.to_string()))?;
        
        if !response.status().is_success() {
            let status = response.status();
            // let body = response.text().await.unwrap_or_default();
            
            return match status.as_u16() {
                429 => Err(ThreatIntelError::RateLimitExceeded),
                401 | 403 => Err(ThreatIntelError::AuthenticationFailed),
                _ => Err(ThreatIntelError::ApiError(format!("Status {}", status))),
            };
        }
        
        let data: AbuseIPDBCheckResponse = response.json().await
            .map_err(|e| ThreatIntelError::ParseError(e.to_string()))?;
        
        // Only return reputation if score is significant
        if data.data.abuse_confidence_score >= 25 {
            Ok(Some(IpReputation {
                ip,
                reputation_score: data.data.abuse_confidence_score,
                threat_type: classify_abuseipdb_threat(&data.data),
                source: "abuseipdb".to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                confidence: data.data.abuse_confidence_score as f32 / 100.0,
                // metadata: IpMetadata {
                //    country: data.data.country_code,
                //    organization: data.data.isp,
                //    is_tor: data.data.is_tor,
                //    abuse_confidence: Some(data.data.abuse_confidence_score),
                //    ..Default::default()
                // },
                metadata: IpMetadata::default(), // Using default for now to match types.rs unless we update types.rs
            }))
        } else {
            Ok(None) // Low score, not worth caching or flagging
        }
    }
    
    /// Download blacklist (requires paid subscription mostly for full list, but free has limits)
    pub async fn download_blacklist(
        &self,
        confidence_min: u8,
    ) -> Result<Vec<IpReputation>, ThreatIntelError> {
        let url = format!("{}/blacklist", self.base_url);
        
        let response = self.client
            .get(&url)
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .query(&[
                ("confidenceMinimum", confidence_min.to_string()),
                ("limit", "10000".to_string()),
            ])
            .send()
            .await
            .map_err(|e| ThreatIntelError::NetworkError(e.to_string()))?;
        
        if !response.status().is_success() {
            return Err(ThreatIntelError::ApiError(format!(
                "Blacklist download failed: {}",
                response.status()
            )));
        }
        
        let blacklist: AbuseIPDBBlacklistResponse = response.json().await
            .map_err(|e| ThreatIntelError::ParseError(e.to_string()))?;
        
        let mut reputations = Vec::new();
        
        for entry in blacklist.data {
            if let Ok(ip) = entry.ip_address.parse::<IpAddr>() {
                reputations.push(IpReputation {
                    ip,
                    reputation_score: entry.abuse_confidence_score,
                    threat_type: ThreatType::Suspicious,
                    source: "abuseipdb_blacklist".to_string(),
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    confidence: 0.9,
                    metadata: IpMetadata::default(),
                });
            }
        }
        
        Ok(reputations)
    }
}

fn classify_abuseipdb_threat(data: &AbuseIPDBData) -> ThreatType {
    if data.is_tor {
        return ThreatType::TorExit;
    }
    
    if let Some(usage) = &data.usage_type {
        let usage_lower = usage.to_lowercase();
        if usage_lower.contains("data center") || usage_lower.contains("hosting") {
            return ThreatType::Datacenter;
        }
    }
    
    // Classify by confidence score
    match data.abuse_confidence_score {
        90..=100 => ThreatType::Botnet,
        70..=89 => ThreatType::Scanner,
        50..=69 => ThreatType::Suspicious,
        _ => ThreatType::Suspicious,
    }
}
