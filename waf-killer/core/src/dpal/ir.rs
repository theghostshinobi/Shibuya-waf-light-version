use std::net::IpAddr;
use serde::{Deserialize, Serialize};

/// The Abstract Action intended by a policy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Action {
    Allow,
    Drop,
    /// Send to slow path (User Space) for deep inspection
    TrapToUserSpace,
    RateLimit {
        limit: u64,
        window_secs: u64,
    },
    Redirect {
        target: IpAddr,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MatchCondition {
    SourceIp(IpAddr),
    SourceCidr(String), // e.g. "192.168.1.0/24"
    DestinationPort(u16),
    TcpFlag(String), // e.g. "SYN"
    HttpHeader {
        key: String,
        value_regex: String,
    },
}

/// A hardware-agnostic representation of a security rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractPolicy {
    pub id: String,
    pub priority: u32,
    pub conditions: Vec<MatchCondition>,
    pub action: Action,
}
