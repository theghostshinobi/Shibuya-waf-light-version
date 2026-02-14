use redis::aio::ConnectionManager;
use redis::Script;
use anyhow::Result;
use log::{error, warn};
use std::time::Duration;

/// Distributed Rate Limiter using Redis Token Bucket
#[derive(Clone)]
pub struct RateLimiter {
    redis_pool: Option<ConnectionManager>, // Optional to support fail-open if initialization fails
    enabled: bool,
}

const TOKEN_BUCKET_SCRIPT: &str = r#"
-- Keys: 
-- 1: bucket_key (stores {tokens, timestamp})

-- Args:
-- 1: burst_capacity (max tokens)
-- 2: refill_rate (tokens per second)
-- 3: current_timestamp (seconds)
-- 4: cost (tokens required, usually 1)

local key = KEYS[1]
local burst = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

-- Get current state
local state = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(state[1])
local last_refill = tonumber(state[2])

if not tokens then
    -- Initial state: full bucket
    tokens = burst
    last_refill = now
end

-- Refill tokens based on elapsed time
local delta = math.max(0, now - last_refill)
local refill = delta * rate
tokens = math.min(burst, tokens + refill)

-- Check if enough tokens
local allowed = 0
if tokens >= cost then
    tokens = tokens - cost
    allowed = 1
end

-- Save new state (expire in 60s or enough to refill full)
redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
redis.call('EXPIRE', key, math.ceil(burst / rate) + 60)

return {allowed, tokens}
"#;

impl RateLimiter {
    pub async fn new(redis_url: Option<String>) -> Self {
        if let Some(url) = redis_url {
            match redis::Client::open(url.clone()) {
                Ok(client) => {
                     match client.get_tokio_connection_manager().await {
                         Ok(pool) => {
                             return Self {
                                 redis_pool: Some(pool),
                                 enabled: true,
                             };
                         }
                         Err(e) => {
                             error!("Failed to connect to Redis for RateLimiting: {}. Failing OPEN.", e);
                         }
                     }
                }
                Err(e) => {
                    error!("Invalid Redis URL '{}': {}. Failing OPEN.", url, e);
                }
            }
        } else {
            warn!("Redis URL not configured. Distributed Rate Limiting DISABLED.");
        }
        
        Self {
            redis_pool: None,
            enabled: false,
        }
    }

    /// Check if a request is allowed.
    /// Returns: 
    /// - Ok(true): Allowed
    /// - Ok(false): Rate Limited
    /// - Ok(true): Error occurred (Fail Open)
    pub async fn check_limit(&self, key: &str, capacity: u32, refill_rate_per_sec: f64) -> Result<bool> {
        if !self.enabled || self.redis_pool.is_none() {
            // Fail Open
            return Ok(true);
        }

        let mut conn = self.redis_pool.as_ref().unwrap().clone();
        
        let script = Script::new(TOKEN_BUCKET_SCRIPT);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs_f64();

        // Key namespacing
        let redis_key = format!("ratelimit:{}", key);

        // Redis Script Execution
        // We use a short timeout wrapper or rely on connection manager timeout? 
        // ConnectionManager handles reconnections, but individual op timeouts depend on how we invoke it.
        // For strict low latency, we might wrap in tokio::time::timeout
        
        let result: redis::RedisResult<(i32, f64)> = script
            .key(&redis_key)
            .arg(capacity)
            .arg(refill_rate_per_sec)
            .arg(now)
            .arg(1) // cost
            .invoke_async(&mut conn).await;

        match result {
            Ok((allowed_int, _remaining)) => {
                Ok(allowed_int == 1)
            }
            Err(e) => {
                error!("Redis error during rate limit check: {}. Failing OPEN.", e);
                // Fail Open logic
                Ok(true)
            }
        }
    }
}
