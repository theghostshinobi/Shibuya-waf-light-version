// core/src/auth/providers/mod.rs
// Authentication Provider Registry — Trait-based dispatch

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{info, warn, debug};

/// Unified authentication result returned by any provider.
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub provider: String,
}

/// Authentication provider types supported by the registry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProviderType {
    Local,
    Ldap,
    Saml,
    OAuth,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderType::Local => write!(f, "local"),
            ProviderType::Ldap => write!(f, "ldap"),
            ProviderType::Saml => write!(f, "saml"),
            ProviderType::OAuth => write!(f, "oauth"),
        }
    }
}

/// Trait for authentication providers.
/// Each provider must implement credential verification.
pub trait AuthProvider: Send + Sync {
    /// The provider type identifier.
    fn provider_type(&self) -> ProviderType;

    /// Authenticate with username/password credentials.
    /// Returns an AuthResult on success, error on failure.
    fn authenticate(&self, username: &str, password: &str) -> Result<AuthResult>;

    /// Whether this provider is currently available and configured.
    fn is_available(&self) -> bool;
}

/// Local provider adapter — wraps the existing LocalProvider.
pub struct LocalAuthAdapter {
    inner: crate::auth::local::LocalProvider,
}

impl LocalAuthAdapter {
    pub fn new() -> Self {
        Self {
            inner: crate::auth::local::LocalProvider::new(),
        }
    }
}

impl AuthProvider for LocalAuthAdapter {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }

    fn authenticate(&self, username: &str, password: &str) -> Result<AuthResult> {
        let user = self.inner.authenticate(username, password)?;
        Ok(AuthResult {
            user_id: user.email.clone(),
            email: user.email,
            name: username.to_string(),
            role: user.role,
            provider: "local".to_string(),
        })
    }

    fn is_available(&self) -> bool {
        true // Local is always available
    }
}

/// LDAP provider adapter — wraps the existing LdapProvider.
pub struct LdapAuthAdapter {
    inner: crate::auth::ldap::LdapProvider,
}

impl LdapAuthAdapter {
    pub fn new() -> Self {
        Self {
            inner: crate::auth::ldap::LdapProvider::new(),
        }
    }

    pub fn with_config(config: crate::auth::ldap::LdapConfig) -> Self {
        Self {
            inner: crate::auth::ldap::LdapProvider::with_config(config),
        }
    }
}

impl AuthProvider for LdapAuthAdapter {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Ldap
    }

    fn authenticate(&self, username: &str, password: &str) -> Result<AuthResult> {
        let user = self.inner.authenticate(username, password)?;
        Ok(AuthResult {
            user_id: user.dn.clone(),
            email: user.email,
            name: user.name,
            role: user.role,
            provider: "ldap".to_string(),
        })
    }

    fn is_available(&self) -> bool {
        self.inner.validate_config().is_ok()
    }
}

/// Registry that manages multiple authentication providers.
/// Supports fallback chains: try providers in priority order.
pub struct ProviderRegistry {
    /// Providers keyed by type, in priority order
    providers: RwLock<Vec<Arc<dyn AuthProvider>>>,
}

impl ProviderRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            providers: RwLock::new(Vec::new()),
        }
    }

    /// Create a registry with default providers (Local first).
    pub fn with_defaults() -> Self {
        let registry = Self::new();
        registry.register(Arc::new(LocalAuthAdapter::new()));
        info!("🔐 ProviderRegistry initialized with Local provider");
        registry
    }

    /// Register a new authentication provider.
    /// Providers are tried in registration order during authentication.
    pub fn register(&self, provider: Arc<dyn AuthProvider>) {
        if let Ok(mut providers) = self.providers.write() {
            info!("📋 Registered auth provider: {}", provider.provider_type());
            providers.push(provider);
        }
    }

    /// List all registered provider types.
    pub fn list_providers(&self) -> Vec<(String, bool)> {
        if let Ok(providers) = self.providers.read() {
            providers.iter()
                .map(|p| (p.provider_type().to_string(), p.is_available()))
                .collect()
        } else {
            vec![]
        }
    }

    /// Authenticate using the chain of registered providers.
    /// Tries each provider in order; returns the first successful result.
    pub fn authenticate(&self, username: &str, password: &str) -> Result<AuthResult> {
        let providers = self.providers.read()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;
        
        if providers.is_empty() {
            return Err(anyhow!("No authentication providers registered"));
        }

        let mut last_error = anyhow!("No providers available");

        for provider in providers.iter() {
            if !provider.is_available() {
                debug!("Skipping unavailable provider: {}", provider.provider_type());
                continue;
            }

            match provider.authenticate(username, password) {
                Ok(result) => {
                    info!("✅ Authenticated {} via {}", username, result.provider);
                    return Ok(result);
                }
                Err(e) => {
                    debug!("Provider {} failed for {}: {}", provider.provider_type(), username, e);
                    last_error = e;
                }
            }
        }

        warn!("⛔ All providers failed for user: {}", username);
        Err(last_error)
    }

    /// Authenticate against a specific provider type.
    pub fn authenticate_with(&self, provider_type: ProviderType, username: &str, password: &str) -> Result<AuthResult> {
        let providers = self.providers.read()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;
        
        for provider in providers.iter() {
            if provider.provider_type() == provider_type {
                return provider.authenticate(username, password);
            }
        }

        Err(anyhow!("Provider {:?} not registered", provider_type))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_with_defaults() {
        let registry = ProviderRegistry::with_defaults();
        let providers = registry.list_providers();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].0, "local");
        assert!(providers[0].1); // available
    }

    #[test]
    fn test_registry_authenticate_local() {
        let registry = ProviderRegistry::with_defaults();
        // Default admin seeded by LocalProvider
        let result = registry.authenticate("admin@shibuya.local", "ShibuyaAdmin2026!");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().provider, "local");
    }

    #[test]
    fn test_registry_authenticate_failure() {
        let registry = ProviderRegistry::with_defaults();
        let result = registry.authenticate("admin@shibuya.local", "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_registry_authenticate_with_type() {
        let registry = ProviderRegistry::with_defaults();
        let result = registry.authenticate_with(
            ProviderType::Local,
            "admin@shibuya.local",
            "ShibuyaAdmin2026!",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_registry_empty() {
        let registry = ProviderRegistry::new();
        let result = registry.authenticate("test", "test");
        assert!(result.is_err());
    }
}
