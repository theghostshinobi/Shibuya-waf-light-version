use serde::Serialize;
use anyhow::Result;
use std::collections::{HashSet, HashMap};
use chrono::{DateTime, Utc};
use crate::scanner::burp::Endpoint;

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredEndpoint {
    pub path: String,
    pub method: String,
    pub source: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub parameters: Vec<String>,
}

pub struct DiscoveryEngine {
    endpoints: HashMap<String, DiscoveredEndpoint>,
}

impl DiscoveryEngine {
    pub fn new() -> Self {
        Self {
            endpoints: HashMap::new(),
        }
    }

    pub fn add_endpoint(&mut self, endpoint: Endpoint, source: String) {
        let key = format!("{}:{}", endpoint.method, endpoint.path);
        
        if let Some(existing) = self.endpoints.get_mut(&key) {
            existing.last_seen = Utc::now();
            // Merge parameters
            let mut params: HashSet<String> = existing.parameters.iter().cloned().collect();
            for param in endpoint.parameters {
                params.insert(param);
            }
            existing.parameters = params.into_iter().collect();
        } else {
            self.endpoints.insert(key, DiscoveredEndpoint {
                path: endpoint.path,
                method: endpoint.method,
                source,
                first_seen: endpoint.discovered_at,
                last_seen: Utc::now(),
                parameters: endpoint.parameters,
            });
        }
    }

    pub fn get_endpoints(&self) -> Vec<DiscoveredEndpoint> {
        self.endpoints.values().cloned().collect()
    }
}
