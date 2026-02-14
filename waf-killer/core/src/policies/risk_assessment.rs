// core/src/policies/risk_assessment.rs

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{Utc, Timelike};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub struct RiskAssessment {
    pub level: RiskLevel,
    pub score: u32,
    pub indicators: Vec<String>,
}

impl RiskAssessment {
    pub async fn assess(
        _user_id: Uuid,
        ip: &IpAddr,
        fingerprint: &str,
        // In a real app, we'd pass a DB pool or cache to check history
    ) -> Self {
        let mut score = 0;
        let mut indicators = Vec::new();
        
        // 1. Time of day (login at 3am is suspicious-ish)
        let hour = Utc::now().hour();
        if hour < 6 || hour > 22 {
            score += 1;
            indicators.push("Unusual login time".to_string());
        }
        
        // 2. IP / Location (Simplified check)
        if ip.is_loopback() || ip.is_unspecified() {
            score += 2;
            indicators.push("Local or unspecified IP".to_string());
        }

        // 3. Device (Simplified)
        if fingerprint.is_empty() {
            score += 3;
            indicators.push("Missing device fingerprint".to_string());
        }

        let level = match score {
            0..=2 => RiskLevel::Low,
            3..=5 => RiskLevel::Medium,
            6..=8 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        Self {
            level,
            score,
            indicators,
        }
    }
}
