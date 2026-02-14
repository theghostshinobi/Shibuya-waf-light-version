use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: String,
    pub metadata: PolicyMetadata,
    pub global: GlobalSettings,
    #[serde(default)]
    pub ip_lists: IpLists,
    #[serde(default)]
    pub geo: GeoSettings,
    #[serde(default)]
    pub routes: Vec<RoutePolicy>,
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,
    // crs, response, logging, alerts, shadow can be added later as needed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub name: String,
    pub description: Option<String>,
    pub environment: String,
    pub owner: Option<String>,
    pub last_updated: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSettings {
    pub mode: PolicyMode, // blocking, detection, off
    pub paranoia_level: u8,
    pub anomaly_threshold: i32,
    #[serde(default = "default_action")]
    pub default_action: ActionType,
    #[serde(default)]
    pub rate_limit: GlobalRateLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Blocking,
    Detection,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalRateLimit {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst: u32,
}

impl Default for GlobalRateLimit {
    fn default() -> Self {
        Self { enabled: false, requests_per_minute: 1000, burst: 100 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpLists {
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default)]
    pub blacklist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoSettings {
    pub mode: GeoMode,
    #[serde(default)]
    pub allowed_countries: Vec<String>,
    #[serde(default)]
    pub blocked_countries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum GeoMode {
    Whitelist,
    Blacklist,
    Off,
}

impl Default for GeoMode {
    fn default() -> Self { Self::Off }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutePolicy {
    pub path: String,
    #[serde(default)]
    pub methods: Vec<String>,
    pub policy: RouteSpecificPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSpecificPolicy {
    pub anomaly_threshold: Option<i32>,
    pub require_auth: Option<bool>,
    // rate_limit per route, etc.
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub id: String, // Can be int or string in YAML, let's use String for flexibility
    pub name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_phase")]
    pub phase: u8,
    pub condition: String,
    pub action: ActionType,
    #[serde(default)]
    pub score: i32,
    pub message: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ActionType {
    Allow,
    Block,
    Deny,
    Drop,
    Challenge,
}

fn default_action() -> ActionType { ActionType::Allow }
fn default_true() -> bool { true }
fn default_phase() -> u8 { 2 }
