use super::parser::GraphQLQuery;
use async_graphql_parser::types::OperationType;
use anyhow::Result;
use std::collections::HashMap;

pub struct GraphQLRateLimiter {
    limits: HashMap<OperationType, RateLimit>,
}

pub struct RateLimit {
    pub requests_per_minute: u32,
    pub complexity_per_minute: u32,
}

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub reason: String,
}

impl GraphQLRateLimiter {
    pub fn new(limits: HashMap<OperationType, RateLimit>) -> Self {
        Self { limits }
    }

    pub async fn check_limit(
        &self,
        _client_id: &str,
        query: &GraphQLQuery,
        complexity: u32,
    ) -> Result<RateLimitResult> {
        for operation in &query.operations {
            let op_type = operation.ty;
            if let Some(limit) = self.limits.get(&op_type) {
                // In a real implementation, this would check against Redis
                // For now, we simulate success or simplified check
                if complexity > limit.complexity_per_minute {
                     return Ok(RateLimitResult {
                        allowed: false,
                        reason: format!("Complexity limit exceeded for {:?}", op_type),
                    });
                }
                
                // Simplified: we just return allowed for now as we don't have Redis integrated here directly
            }
        }
        
        Ok(RateLimitResult {
            allowed: true,
            reason: String::new(),
        })
    }
}
