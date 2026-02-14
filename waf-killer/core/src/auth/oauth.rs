// core/src/auth/oauth.rs

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope,
    PkceCodeVerifier,
};
use openidconnect::reqwest::async_http_client;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use std::sync::Arc;
use redis::AsyncCommands;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OIDCConfig {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

pub struct OAuthProvider {
    clients: DashMap<String, CoreClient>,
    redis: redis::Client, // Using redis to store OAuth state (CSRF, PKCE, Nonce)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub sub: String,
    pub email: String,
    pub name: String,
    pub picture: Option<String>,
}

impl OAuthProvider {
    pub fn new(redis: redis::Client) -> Self {
        Self {
            clients: DashMap::new(),
            redis,
        }
    }

    pub async fn create_client(
        &self,
        provider_name: &str,
        config: &OIDCConfig,
    ) -> Result<()> {
        let issuer = IssuerUrl::new(config.issuer.clone())?;
        
        // Discover provider metadata
        let metadata = CoreProviderMetadata::discover_async(issuer, async_http_client).await?;
        
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_uri.clone())?);
        
        self.clients.insert(provider_name.to_string(), client);
        
        Ok(())
    }
    
    /// Generate authorization URL
    pub async fn authorize_url(
        &self,
        provider_name: &str,
    ) -> Result<(String, CsrfToken, Nonce)> {
        let client = self.clients.get(provider_name)
            .ok_or_else(|| anyhow!("Provider not found: {}", provider_name))?;
        
        // Generate PKCE challenge
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        
        let mut auth_req = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            );
            
        auth_req = auth_req.add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge);
            
        let (auth_url, csrf_token, nonce) = auth_req.url();
        
        // Store PKCE verifier and nonce in Redis (keyed by CSRF token)
        self.store_oauth_state(&csrf_token, pkce_verifier, &nonce).await?;
        
        Ok((auth_url.to_string(), csrf_token, nonce))
    }
    
    /// Exchange authorization code for tokens
    pub async fn exchange_code(
        &self,
        provider_name: &str,
        code: &str,
        csrf_token: &str,
    ) -> Result<UserInfo> {
        let client = self.clients.get(provider_name)
            .ok_or_else(|| anyhow!("Provider not found: {}", provider_name))?;
        
        // Retrieve stored PKCE verifier and nonce
        let (pkce_verifier, nonce) = self.get_oauth_state(csrf_token).await?;
        
        // Exchange code for token
        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(pkce_verifier)
            .request_async(async_http_client)
            .await?;
        
        // Get ID token
        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow!("No ID token"))?;
        
        // Verify ID token
        let claims = id_token.claims(&client.id_token_verifier(), &nonce)?;
        
        // Extract user info
        Ok(UserInfo {
            sub: claims.subject().to_string(),
            email: claims.email()
                .map(|e| e.as_str().to_string())
                .unwrap_or_default(),
            name: claims.name()
                .and_then(|n| n.get(None))
                .map(|n| n.as_str().to_string())
                .unwrap_or_default(),
            picture: claims.picture()
                .and_then(|p| p.get(None))
                .map(|p| p.url().to_string()),
        })
    }

    async fn store_oauth_state(
        &self,
        csrf_token: &CsrfToken,
        pkce_verifier: PkceCodeVerifier,
        nonce: &Nonce,
    ) -> Result<()> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;
        let key = format!("oauth_state:{}", csrf_token.secret());
        let value = serde_json::to_string(&(pkce_verifier.secret(), nonce.secret()))?;
        
        // Store for 10 minutes
        let _: () = conn.set_ex(key, value, 600).await?;
        Ok(())
    }

    async fn get_oauth_state(
        &self,
        csrf_token: &str,
    ) -> Result<(PkceCodeVerifier, Nonce)> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;
        let key = format!("oauth_state:{}", csrf_token);
        
        let value: String = conn.get(key).await.map_err(|_| anyhow!("Invalid or expired OAuth state"))?;
        let (pkce_secret, nonce_secret): (String, String) = serde_json::from_str(&value)?;
        
        Ok((PkceCodeVerifier::new(pkce_secret), Nonce::new(nonce_secret)))
    }
}
