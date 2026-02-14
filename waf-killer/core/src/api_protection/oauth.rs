use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use reqwest::Client;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub introspection_endpoint: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub exp: Option<i64>,
}

pub struct OAuthIntrospector {
    client: Client,
    config: OAuthConfig,
}

impl OAuthIntrospector {
    pub fn new(config: OAuthConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
            
        Self { client, config }
    }

    pub async fn introspect(&self, token: &str) -> Result<IntrospectionResponse> {
        let params = [
            ("token", token),
            ("token_type_hint", "access_token"),
        ];

        let response = self.client.post(&self.config.introspection_endpoint)
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .form(&params)
            .send()
            .await
            .map_err(|e| anyhow!("OAuth Introspection request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("OAuth Introspection returned error: {}", response.status()));
        }

        let introspection: IntrospectionResponse = response.json().await
            .map_err(|e| anyhow!("Failed to parse introspection response: {}", e))?;

        Ok(introspection)
    }
}
