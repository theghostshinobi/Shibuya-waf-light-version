// core/src/policies/conditional_access.rs

use anyhow::Result;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::net::IpAddr;
use crate::policies::risk_assessment::{RiskLevel, RiskAssessment};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalAccessPolicy {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub priority: u32,
    pub conditions: AccessConditions,
    pub actions: AccessActions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessConditions {
    pub users: Option<Vec<Uuid>>,
    pub locations: Option<LocationCondition>,
    pub min_risk_level: Option<RiskLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LocationCondition {
    AllowedCountries(Vec<String>),
    BlockedCountries(Vec<String>),
    TrustedIPs(Vec<IpAddr>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessActions {
    pub grant_access: bool,
    pub require_mfa: bool,
    pub require_compliant_device: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessDecision {
    Allow,
    Deny(String),
    RequireMFA,
}

impl ConditionalAccessPolicy {
    pub async fn evaluate(
        &self,
        user_id: Uuid,
        ip: &IpAddr,
        risk: &RiskAssessment,
    ) -> Result<AccessDecision> {
        if !self.enabled {
            return Ok(AccessDecision::Allow);
        }

        // Check user scope
        if let Some(users) = &self.conditions.users {
            if !users.contains(&user_id) {
                return Ok(AccessDecision::Allow); // Policy doesn't apply
            }
        }

        // Check location/IP
        if let Some(location) = &self.conditions.locations {
            match location {
                LocationCondition::TrustedIPs(ips) => {
                    if !ips.contains(ip) {
                        return Ok(self.apply_actions("IP not trusted"));
                    }
                }
                // Country logic would require GeoIP integration
                _ => {}
            }
        }

        // Check risk level
        if let Some(min_risk) = &self.conditions.min_risk_level {
            if risk.level >= *min_risk {
                return Ok(self.apply_actions(&format!("Risk level too high: {:?}", risk.level)));
            }
        }

        Ok(AccessDecision::Allow)
    }

    fn apply_actions(&self, reason: &str) -> AccessDecision {
        if !self.actions.grant_access {
            return AccessDecision::Deny(reason.to_string());
        }
        if self.actions.require_mfa {
            return AccessDecision::RequireMFA;
        }
        AccessDecision::Allow
    }
}
