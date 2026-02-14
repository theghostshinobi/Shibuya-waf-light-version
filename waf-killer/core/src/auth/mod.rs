// core/src/auth/mod.rs

pub mod saml;
// pub mod oauth;
pub mod ldap;
pub mod local;
pub mod providers;

pub use saml::SAMLProvider;
// pub use oauth::OAuthProvider;

pub mod admin;
