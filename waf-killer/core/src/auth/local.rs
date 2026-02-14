// core/src/auth/local.rs
// Local Database Authentication Provider — Real Implementation

use anyhow::{anyhow, Result};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{info, warn};

/// User record stored in the local auth provider.
#[derive(Debug, Clone)]
pub struct LocalUser {
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub active: bool,
}

/// Local database authentication provider.
/// Uses SHA-256 password hashing with a per-user salt.
/// In production, consider migrating to argon2 for stronger resistance.
pub struct LocalProvider {
    /// In-memory user store (email → user record)
    users: RwLock<HashMap<String, LocalUser>>,
    /// Global salt prefix (should be loaded from config in production)
    salt_prefix: String,
}

impl LocalProvider {
    pub fn new() -> Self {
        let provider = Self {
            users: RwLock::new(HashMap::new()),
            salt_prefix: "waf_shibuya_2026".to_string(),
        };
        
        // Seed a default admin if no users exist
        if let Err(e) = provider.register_user("admin@shibuya.local", "ShibuyaAdmin2026!", "admin") {
            warn!("Could not seed default admin: {}", e);
        }
        info!("🔐 LocalProvider initialized with default admin account");
        
        provider
    }

    /// Hash a password using SHA-256 with salt.
    fn hash_password(&self, email: &str, password: &str) -> String {
        let salted = format!("{}:{}:{}", self.salt_prefix, email, password);
        let mut hasher = Sha256::new();
        hasher.update(salted.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Register a new user.
    pub fn register_user(&self, email: &str, password: &str, role: &str) -> Result<()> {
        let mut users = self.users.write()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;
        
        if users.contains_key(email) {
            return Err(anyhow!("User {} already exists", email));
        }

        let hash = self.hash_password(email, password);
        users.insert(email.to_string(), LocalUser {
            email: email.to_string(),
            password_hash: hash,
            role: role.to_string(),
            active: true,
        });

        info!("✅ User registered: {} (role: {})", email, role);
        Ok(())
    }

    /// Authenticate a user with email and password.
    /// Returns the user record on success, error on failure.
    pub fn authenticate(&self, email: &str, password: &str) -> Result<LocalUser> {
        let users = self.users.read()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;
        
        let user = users.get(email)
            .ok_or_else(|| anyhow!("User not found"))?;
        
        if !user.active {
            return Err(anyhow!("User account is disabled"));
        }

        let provided_hash = self.hash_password(email, password);
        
        // Constant-time comparison to prevent timing attacks
        if constant_time_eq(&provided_hash, &user.password_hash) {
            info!("✅ Authentication successful for {}", email);
            Ok(user.clone())
        } else {
            warn!("⛔ Authentication failed for {}", email);
            Err(anyhow!("Invalid password"))
        }
    }

    /// Change password for an existing user.
    pub fn change_password(&self, email: &str, old_password: &str, new_password: &str) -> Result<()> {
        // First verify old password
        let _ = self.authenticate(email, old_password)?;

        let mut users = self.users.write()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;
        
        if let Some(user) = users.get_mut(email) {
            user.password_hash = self.hash_password(email, new_password);
            info!("🔑 Password changed for {}", email);
            Ok(())
        } else {
            Err(anyhow!("User not found"))
        }
    }

    /// List all registered users (without password hashes).
    pub fn list_users(&self) -> Result<Vec<(String, String, bool)>> {
        let users = self.users.read()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;
        
        Ok(users.values()
            .map(|u| (u.email.clone(), u.role.clone(), u.active))
            .collect())
    }

    /// Disable a user account.
    pub fn disable_user(&self, email: &str) -> Result<()> {
        let mut users = self.users.write()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;
        
        if let Some(user) = users.get_mut(email) {
            user.active = false;
            info!("🚫 User disabled: {}", email);
            Ok(())
        } else {
            Err(anyhow!("User not found"))
        }
    }
}

/// Constant-time string comparison to prevent timing attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_authenticate() {
        let provider = LocalProvider::new();
        provider.register_user("test@test.com", "password123", "viewer").unwrap();
        
        let user = provider.authenticate("test@test.com", "password123").unwrap();
        assert_eq!(user.email, "test@test.com");
        assert_eq!(user.role, "viewer");
    }

    #[test]
    fn test_wrong_password() {
        let provider = LocalProvider::new();
        provider.register_user("test@test.com", "password123", "viewer").unwrap();
        
        assert!(provider.authenticate("test@test.com", "wrong").is_err());
    }

    #[test]
    fn test_default_admin() {
        let provider = LocalProvider::new();
        let result = provider.authenticate("admin@shibuya.local", "ShibuyaAdmin2026!");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().role, "admin");
    }

    #[test]
    fn test_disable_user() {
        let provider = LocalProvider::new();
        provider.register_user("test@test.com", "pass", "viewer").unwrap();
        provider.disable_user("test@test.com").unwrap();
        
        assert!(provider.authenticate("test@test.com", "pass").is_err());
    }

    #[test]
    fn test_change_password() {
        let provider = LocalProvider::new();
        provider.register_user("test@test.com", "old_pass", "viewer").unwrap();
        provider.change_password("test@test.com", "old_pass", "new_pass").unwrap();
        
        assert!(provider.authenticate("test@test.com", "old_pass").is_err());
        assert!(provider.authenticate("test@test.com", "new_pass").is_ok());
    }
}
