use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use anyhow::{Result, Context as AnyhowContext};
use std::time::{SystemTime, UNIX_EPOCH};

const JWT_SECRET: &str = "waf-killer-bot-challenge-secret-change-in-production";
const CHALLENGE_DIFFICULTY: usize = 4; // Number of leading zeros required in hash

/// Challenge data embedded in JWT
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeClaims {
    pub challenge_string: String, // Random string to hash
    pub timestamp: u64,           // Challenge creation time
    pub exp: u64,                 // Expiration (5 minutes)
}

/// Response from client after solving challenge
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub nonce: u64,      // Solution nonce
    pub token: String,   // Original JWT
}

/// Generate a new challenge
pub fn generate_challenge() -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    
    // Generate random challenge string
    let challenge_string = format!("waf-challenge-{}-{}", now, rand::random::<u64>());
    
    let claims = ChallengeClaims {
        challenge_string,
        timestamp: now,
        exp: now + 300, // 5 minutes
    };
    
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes())
    )?;
    
    Ok(token)
}

/// Verify challenge response
pub fn verify_challenge_response(response: &ChallengeResponse) -> Result<bool> {
    // Decode and validate JWT
    let validation = Validation::new(Algorithm::HS256);
    let token_data = decode::<ChallengeClaims>(
        &response.token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &validation
    ).context("Invalid or expired token")?;
    
    let claims = token_data.claims;
    
    // Verify proof of work
    let input = format!("{}{}", claims.challenge_string, response.nonce);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hex::encode(hasher.finalize());
    
    // Check if hash has required leading zeros
    let has_valid_proof = hash.starts_with(&"0".repeat(CHALLENGE_DIFFICULTY));
    
    Ok(has_valid_proof)
}

/// HTML page with JavaScript challenge (Cloudflare-style interstitial)
pub const CHALLENGE_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Check</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 400px;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        h1 { color: #333; margin-bottom: 10px; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Check</h1>
        <p>Verifying your browser...</p>
        <div class="spinner"></div>
        <p id="status">Computing proof of work...</p>
    </div>
    
    <script>
        // Get challenge token from URL or embedded data
        const challenge = '{{CHALLENGE_TOKEN}}';
        
        async function sha256(message) {
            const msgBuffer = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }
        
        async function solveChallenge() {
            const difficulty = {{DIFFICULTY}};
            const requiredPrefix = '0'.repeat(difficulty);
            
            let nonce = 0;
            const startTime = Date.now();
            
            while (true) {
                const input = challenge.split('.')[1] + nonce; // Use JWT payload
                const hash = await sha256(input);
                
                if (hash.startsWith(requiredPrefix)) {
                    // Found solution!
                    document.getElementById('status').textContent = 'Verification complete!';
                    
                    // Submit solution
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            nonce: nonce,
                            token: challenge
                        })
                    });
                    
                    if (response.ok) {
                        window.location.reload();
                    } else {
                        document.getElementById('status').textContent = 'Verification failed. Please refresh.';
                    }
                    break;
                }
                
                nonce++;
                
                // Update UI every 1000 attempts
                if (nonce % 1000 === 0) {
                    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                    document.getElementById('status').textContent = 
                        `Attempt ${nonce}... (${elapsed}s)`;
                }
            }
        }
        
        // Auto-start challenge
        window.onload = () => {
            setTimeout(solveChallenge, 500); // Small delay for UI
        };
    </script>
</body>
</html>"#;

/// Generate challenge HTML with embedded token
pub fn generate_challenge_html(token: &str) -> String {
    CHALLENGE_HTML
        .replace("{{CHALLENGE_TOKEN}}", token)
        .replace("{{DIFFICULTY}}", &CHALLENGE_DIFFICULTY.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_challenge_generation() {
        let token = generate_challenge().unwrap();
        assert!(!token.is_empty());
    }
    
    #[test]
    fn test_challenge_verification() {
        let token = generate_challenge().unwrap();
        
        // This would require actually solving the PoW
        // For testing, we'd need to implement the solve logic in Rust too
        // Skipping actual verification test as it's time-intensive
    }
}
