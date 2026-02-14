use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm, TokenData};
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use std::collections::HashSet;

/// JWT Claims structure (standard fields)
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: Option<usize>,
    pub iss: Option<String>,
    pub aud: Option<String>,
    #[serde(flatten)]
    pub custom: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub algorithm: Algorithm,
    pub required_claims: HashSet<String>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
}

pub struct JwtValidator {
    config: JwtConfig,
    decoding_key: DecodingKey,
}

impl JwtValidator {
    pub fn new(config: JwtConfig) -> Self {
        let decoding_key = DecodingKey::from_secret(config.secret.as_bytes());
        Self {
            config,
            decoding_key,
        }
    }

    pub fn validate(&self, token: &str) -> Result<TokenData<Claims>> {
        let mut validation = Validation::new(self.config.algorithm);
        
        if let Some(ref iss) = self.config.issuer {
            validation.set_issuer(&[iss]);
        }
        
        if let Some(ref aud) = self.config.audience {
            validation.set_audience(&[aud]);
        }

        let token_data = decode::<Claims>(
            token,
            &self.decoding_key,
            &validation,
        ).map_err(|e| anyhow!("JWT Validation failed: {}", e))?;

        // Check required custom claims
        for claim in &self.config.required_claims {
            if !token_data.claims.custom.contains_key(claim) {
                return Err(anyhow!("Missing required claim: {}", claim));
            }
        }

        Ok(token_data)
    }
}
