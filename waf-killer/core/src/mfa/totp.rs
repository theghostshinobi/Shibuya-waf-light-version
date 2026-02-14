// core/src/mfa/totp.rs

use anyhow::Result;
use totp_lite::{totp, Sha1};
use qrcode::QrCode;
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::Serialize;
use uuid::Uuid;

pub struct TOTPManager {
    issuer: String,
}

#[derive(Debug, Serialize)]
pub struct TOTPSecret {
    pub user_id: Uuid,
    pub secret: String,
    pub uri: String,
    pub backup_codes: Vec<String>,
}

impl TOTPManager {
    pub fn new(issuer: String) -> Self {
        Self { issuer }
    }

    /// Generate TOTP secret for user
    pub fn generate_secret(&self, user_id: Uuid, email: &str) -> TOTPSecret {
        // Generate 160-bit random secret
        let mut secret = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut secret);
        
        let secret_base32 = base32::encode(
            base32::Alphabet::RFC4648 { padding: false },
            &secret,
        );
        
        TOTPSecret {
            user_id,
            secret: secret_base32.clone(),
            uri: self.generate_uri(email, &secret_base32),
            backup_codes: self.generate_backup_codes(),
        }
    }
    
    fn generate_uri(&self, email: &str, secret: &str) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}",
            urlencoding::encode(&self.issuer),
            urlencoding::encode(email),
            secret,
            urlencoding::encode(&self.issuer)
        )
    }
    
    /// Generate QR code for authenticator app enrollment
    pub fn generate_qr_code(&self, uri: &str) -> Result<String> {
        let qr = QrCode::new(uri)?;
        let svg = qr.render::<svg::Color>()
            .min_dimensions(200, 200)
            .build();
        
        Ok(svg)
    }
    
    /// Verify TOTP code
    pub fn verify_code(&self, secret: &str, code: &str) -> bool {
        let secret_bytes = match base32::decode(
            base32::Alphabet::RFC4648 { padding: false },
            secret,
        ) {
            Some(bytes) => bytes,
            None => return false,
        };
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Check current time + 1 step before/after (30s window)
        // time_step is i64 to avoid overflow when multiplying by 30
        for time_step in &[-1i64, 0i64, 1i64] {
            let timestamp = (now as i64 + time_step * 30) as u64;
            let expected = totp::<Sha1>(&secret_bytes, timestamp / 30);
            
            if expected == code {
                return true;
            }
        }
        
        false
    }
    
    fn generate_backup_codes(&self) -> Vec<String> {
        (0..10)
            .map(|_| {
                let mut code = [0u8; 4];
                rand::thread_rng().fill_bytes(&mut code);
                hex::encode(code).to_uppercase()
            })
            .collect()
    }
}
