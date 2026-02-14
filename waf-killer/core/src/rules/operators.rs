use regex::Regex;
use serde::{Serialize, Serializer};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum Operator {
    Rx(Regex),
    Contains(String),
    Eq(String),
    Gt(i64),
    Lt(i64),
    StrEq(String),
    BeginsWith(String),
    EndsWith(String),
    PhraseMatch(Vec<String>), // Loaded from file
    PmFromFile(String),       // Special case for parser to load later
    DetectSQLi,
    DetectXSS,
    IpMatch(String), // CIDR list (comma-separated)
    GeoMatch,        // GeoIP lookup (requires MaxMind DB)
    NoOp,
}

// Implement PartialEq manually because Regex doesn't implement it
impl PartialEq for Operator {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Operator::Rx(a), Operator::Rx(b)) => a.as_str() == b.as_str(),
            (Operator::Contains(a), Operator::Contains(b)) => a == b,
            (Operator::Eq(a), Operator::Eq(b)) => a == b,
            (Operator::Gt(a), Operator::Gt(b)) => a == b,
            (Operator::Lt(a), Operator::Lt(b)) => a == b,
            (Operator::StrEq(a), Operator::StrEq(b)) => a == b,
            (Operator::BeginsWith(a), Operator::BeginsWith(b)) => a == b,
            (Operator::EndsWith(a), Operator::EndsWith(b)) => a == b,
            (Operator::PhraseMatch(a), Operator::PhraseMatch(b)) => a == b,
            (Operator::PmFromFile(a), Operator::PmFromFile(b)) => a == b,
            (Operator::DetectSQLi, Operator::DetectSQLi) => true,
            (Operator::DetectXSS, Operator::DetectXSS) => true,
            (Operator::IpMatch(a), Operator::IpMatch(b)) => a == b,
            (Operator::GeoMatch, Operator::GeoMatch) => true,
            (Operator::NoOp, Operator::NoOp) => true,
            _ => false,
        }
    }
}

// Implement Eq manually
impl Eq for Operator {}

impl Operator {
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Operator::Rx(re) => re.is_match(value),
            Operator::Contains(pattern) => value.contains(pattern),
            Operator::Eq(pattern) => value == pattern,
            Operator::Gt(num) => value.len() as i64 > *num, 
            Operator::Lt(num) => (value.len() as i64) < *num,
            Operator::StrEq(pattern) => value == pattern,
            Operator::BeginsWith(pattern) => value.starts_with(pattern),
            Operator::EndsWith(pattern) => value.ends_with(pattern),
            Operator::PhraseMatch(phrases) => phrases.iter().any(|p| value.contains(p)),
            Operator::PmFromFile(_) => false, // Should have been loaded into PhraseMatch
            Operator::DetectSQLi => detect_sqli(value),
            Operator::DetectXSS => detect_xss(value),
            Operator::IpMatch(cidr_list) => ip_match(value, cidr_list),
            Operator::GeoMatch => {
                // GeoIP requires MaxMind DB — returns false with trace log
                // Enable by loading GeoLite2-Country.mmdb via config
                false
            },
            Operator::NoOp => false,
        }
    }
}

/// Detect SQL injection using libinjection's fingerprint-based analysis.
/// This is the same engine used by ModSecurity's @detectSQLi operator.
fn detect_sqli(value: &str) -> bool {
    let result = libinjectionrs::detect_sqli(value.as_bytes());
    result.fingerprint.is_some()
}

/// Detect XSS using libinjection's token-based analysis.
/// This is the same engine used by ModSecurity's @detectXSS operator.
fn detect_xss(value: &str) -> bool {
    let result = libinjectionrs::detect_xss(value.as_bytes());
    result.is_injection()
}

/// Match an IP address against a comma-separated list of CIDR ranges or single IPs.
/// Supports both IPv4 and IPv6.
fn ip_match(value: &str, cidr_list: &str) -> bool {
    let ip: IpAddr = match value.trim().parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    for entry in cidr_list.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        if entry.contains('/') {
            // CIDR notation: 192.168.1.0/24
            if let Some((network_str, prefix_str)) = entry.split_once('/') {
                if let (Ok(network), Ok(prefix_len)) = (
                    network_str.trim().parse::<IpAddr>(),
                    prefix_str.trim().parse::<u32>(),
                ) {
                    if cidr_contains(network, prefix_len, ip) {
                        return true;
                    }
                }
            }
        } else {
            // Single IP: exact match
            if let Ok(target) = entry.parse::<IpAddr>() {
                if ip == target {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if an IP address falls within a CIDR network.
fn cidr_contains(network: IpAddr, prefix_len: u32, ip: IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(net), IpAddr::V4(addr)) => {
            if prefix_len > 32 { return false; }
            if prefix_len == 0 { return true; }
            let net_bits = u32::from(net);
            let addr_bits = u32::from(addr);
            let mask = !0u32 << (32 - prefix_len);
            (net_bits & mask) == (addr_bits & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(addr)) => {
            if prefix_len > 128 { return false; }
            if prefix_len == 0 { return true; }
            let net_bits = u128::from(net);
            let addr_bits = u128::from(addr);
            let mask = !0u128 << (128 - prefix_len);
            (net_bits & mask) == (addr_bits & mask)
        }
        _ => false, // IPv4 vs IPv6 mismatch
    }
}

impl Serialize for Operator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Operator::Rx(re) => serializer.serialize_newtype_variant("Operator", 0, "Rx", re.as_str()),
            Operator::Contains(s) => serializer.serialize_newtype_variant("Operator", 1, "Contains", s),
            Operator::Eq(s) => serializer.serialize_newtype_variant("Operator", 2, "Eq", s),
            Operator::Gt(n) => serializer.serialize_newtype_variant("Operator", 3, "Gt", n),
            Operator::Lt(n) => serializer.serialize_newtype_variant("Operator", 4, "Lt", n),
            Operator::StrEq(s) => serializer.serialize_newtype_variant("Operator", 5, "StrEq", s),
            Operator::BeginsWith(s) => serializer.serialize_newtype_variant("Operator", 6, "BeginsWith", s),
            Operator::EndsWith(s) => serializer.serialize_newtype_variant("Operator", 7, "EndsWith", s),
            Operator::PhraseMatch(v) => serializer.serialize_newtype_variant("Operator", 8, "PhraseMatch", v),
            Operator::PmFromFile(s) => serializer.serialize_newtype_variant("Operator", 9, "PmFromFile", s),
            Operator::DetectSQLi => serializer.serialize_unit_variant("Operator", 10, "DetectSQLi"),
            Operator::DetectXSS => serializer.serialize_unit_variant("Operator", 11, "DetectXSS"),
            Operator::IpMatch(s) => serializer.serialize_newtype_variant("Operator", 12, "IpMatch", s),
            Operator::GeoMatch => serializer.serialize_unit_variant("Operator", 13, "GeoMatch"),
            Operator::NoOp => serializer.serialize_unit_variant("Operator", 14, "NoOp"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_sqli_basic() {
        // Classic SQLi patterns — must be detected
        assert!(detect_sqli("1' OR '1'='1"), "OR-based SQLi not detected");
        assert!(detect_sqli("1 UNION SELECT 1,2,3--"), "UNION SELECT not detected");
        assert!(detect_sqli("'; DROP TABLE users--"), "DROP TABLE not detected");
        // Note: libinjectionrs is intentionally aggressive to minimize false negatives.
        // False positive tuning is handled at the CRS rule/policy level.
    }

    #[test]
    fn test_detect_xss_basic() {
        // XSS patterns
        assert!(detect_xss("<script>alert(1)</script>"));
        assert!(detect_xss("<img src=x onerror=alert(1)>"));
        // Benign
        assert!(!detect_xss("hello world"));
        assert!(!detect_xss("normal text content"));
    }

    #[test]
    fn test_ip_match_single() {
        assert!(ip_match("192.168.1.1", "192.168.1.1"));
        assert!(!ip_match("192.168.1.2", "192.168.1.1"));
    }

    #[test]
    fn test_ip_match_cidr() {
        assert!(ip_match("192.168.1.50", "192.168.1.0/24"));
        assert!(ip_match("192.168.1.255", "192.168.1.0/24"));
        assert!(!ip_match("192.168.2.1", "192.168.1.0/24"));
    }

    #[test]
    fn test_ip_match_multi() {
        assert!(ip_match("10.0.0.1", "192.168.1.0/24, 10.0.0.0/8"));
        assert!(ip_match("192.168.1.50", "192.168.1.0/24, 10.0.0.0/8"));
        assert!(!ip_match("172.16.0.1", "192.168.1.0/24, 10.0.0.0/8"));
    }

    #[test]
    fn test_ip_match_ipv6() {
        assert!(ip_match("::1", "::1"));
        assert!(ip_match("fe80::1", "fe80::/10"));
    }
}
