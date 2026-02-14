// core/src/mfa/mod.rs

pub mod totp;
pub mod webauthn;

pub use totp::TOTPManager;
pub use webauthn::WebAuthnManager;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum MFAMethod {
    TOTP,
    WebAuthn,
    SMS,
    Email,
}
