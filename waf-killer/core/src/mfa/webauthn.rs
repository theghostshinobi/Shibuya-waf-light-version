// core/src/mfa/webauthn.rs
// WebAuthn/Passkeys Manager - STUB IMPLEMENTATION
//
// NOTE: Full WebAuthn implementation requires the 'webauthn-rs' crate.
// This is a stub that allows the codebase to compile without native dependencies.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Stub types that mirror webauthn-rs types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreationChallengeResponse {
    pub challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRegistration {
    pub user_id: uuid::Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestChallengeResponse {
    pub challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyAuthentication {
    pub user_id: uuid::Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey {
    pub credential_id: Vec<u8>,
    pub cred_public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPublicKeyCredential {
    pub response: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredential {
    pub response: Vec<u8>,
}

#[derive(Debug)]
pub struct AuthenticationContext {
    pub user_verified: bool,
}

pub struct WebAuthnManager {
    rp_id: String,
    rp_origin: String,
}

impl WebAuthnManager {
    pub fn new(rp_id: &str, rp_origin: &str) -> Result<Self> {
        tracing::warn!("WebAuthn manager is a stub - enable webauthn-rs for full support");
        Ok(Self { 
            rp_id: rp_id.to_string(),
            rp_origin: rp_origin.to_string(),
        })
    }
    
    /// Start credential registration (enrollment) - STUB
    pub fn start_registration(
        &self,
        user_id: &uuid::Uuid,
        _email: &str,
        _name: &str,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration)> {
        Ok((
            CreationChallengeResponse {
                challenge: uuid::Uuid::new_v4().to_string(),
            },
            PasskeyRegistration {
                user_id: *user_id,
            },
        ))
    }
    
    /// Finish credential registration - STUB
    pub fn finish_registration(
        &self,
        _reg: &RegisterPublicKeyCredential,
        _reg_state: &PasskeyRegistration,
    ) -> Result<Passkey> {
        Err(anyhow!("WebAuthn is not available - enable webauthn-rs crate"))
    }
    
    /// Start authentication - STUB
    pub fn start_authentication(
        &self,
        _passkeys: &[Passkey],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication)> {
        Err(anyhow!("WebAuthn is not available - enable webauthn-rs crate"))
    }
    
    /// Finish authentication - STUB
    pub fn finish_authentication(
        &self,
        _auth: &PublicKeyCredential,
        _auth_state: &PasskeyAuthentication,
    ) -> Result<AuthenticationContext> {
        Err(anyhow!("WebAuthn is not available - enable webauthn-rs crate"))
    }
}
