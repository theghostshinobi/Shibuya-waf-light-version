use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use std::net::IpAddr;
use crate::threat_intel::types::{IpReputation, ThreatType, IpMetadata, ThreatIntelError};
use chrono::Utc;

pub struct AlienVaultClient {
    client: Client,
    api_key: String,
    base_url: String,
}

#[derive(Debug, Deserialize)]
struct OTXGeneralResponse {
    pulse_info: PulseInfo,
    base_indicator: BaseIndicator,
}

#[derive(Debug, Deserialize)]
struct PulseInfo {
    count: usize,
    pulses: Vec<Pulse>,
}

#[derive(Debug, Deserialize)]
struct Pulse {
    // id: String, // unused
    // name: String, // unused
    tags: Vec<String>,
    // malware_families: Vec<String>, // unused directly in logic below but useful to map
}

#[derive(Debug, Deserialize)]
struct BaseIndicator {
    // indicator: String, // unused
    #[serde(rename = "type")]
    // indicator_type: String, // unused
    reputation: Option<i32>,
}

impl AlienVaultClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap(),
            api_key,
            base_url: "https://otx.alienvault.com/api/v1".to_string(),
        }
    }
    
    /// Check IP reputation in OTX
    pub async fn check_ip(&self, ip: IpAddr) -> Result<Option<IpReputation>, ThreatIntelError> {
        let url = format!("{}/indicators/IPv4/{}/general", self.base_url, ip);
        
        let response = self.client
            .get(&url)
            .header("X-OTX-API-KEY", &self.api_key)
            .send()
            .await
            .map_err(|e| ThreatIntelError::NetworkError(e.to_string()))?;
        
        if !response.status().is_success() {
            if response.status() == 404 {
                // IP not in OTX database
                return Ok(None);
            }
            return Err(ThreatIntelError::ApiError(format!(
                "OTX API error: {}",
                response.status()
            )));
        }
        
        let data: OTXGeneralResponse = response.json().await
            .map_err(|e| ThreatIntelError::ParseError(e.to_string()))?;
        
        // If IP appears in any pulses (threat intel reports), it's suspicious
        if data.pulse_info.count > 0 {
            let threat_type = classify_otx_threat(&data.pulse_info);
            let reputation_score = calculate_otx_score(&data);
            
            Ok(Some(IpReputation {
                ip,
                reputation_score,
                threat_type,
                source: "alienvault_otx".to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                confidence: 0.75, // OTX is usually reliable if pulses exist
                metadata: IpMetadata::default(),
            }))
        } else {
            Ok(None)
        }
    }
}

fn classify_otx_threat(pulse_info: &PulseInfo) -> ThreatType {
    // Analyze tags and malware families
    for pulse in &pulse_info.pulses {
        let tags_lower: Vec<String> = pulse.tags.iter()
            .map(|t| t.to_lowercase())
            .collect();
        
        if tags_lower.iter().any(|t| t.contains("botnet")) {
            return ThreatType::Botnet;
        }
        if tags_lower.iter().any(|t| t.contains("scanner") || t.contains("scan")) {
            return ThreatType::Scanner;
        }
        if tags_lower.iter().any(|t| t.contains("malware") || t.contains("trojan")) {
            return ThreatType::Malware;
        }
        if tags_lower.iter().any(|t| t.contains("phish")) {
            return ThreatType::Phishing;
        }
    }
    
    ThreatType::Suspicious
}

fn calculate_otx_score(data: &OTXGeneralResponse) -> u8 {
    let pulse_count = data.pulse_info.count;
    
    // More pulses = higher confidence it's malicious
    let score: u8 = match pulse_count {
        0 => 0,
        1..=2 => 40,
        3..=5 => 60,
        6..=10 => 75,
        _ => 85,
    };
    
    // Adjust by reputation if available
    // Note: OTX reputation is complex, sometimes negative is bad? Unclear from snippet, assuming simplistic view
    if let Some(rep) = data.base_indicator.reputation {
        // Assuming implementation from prompt:
        if rep < 0 {
            return score.saturating_add(15).min(100);
        }
    }
    
    score
}
