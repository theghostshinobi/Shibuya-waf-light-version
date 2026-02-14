//! OWASP Core Rule Seeding Module
//!
//! Generates pre-configured security rules based on OWASP guidelines.
//! Called at startup if no rules are loaded.

use super::actions::{Action, Severity};
use super::operators::Operator;
use super::parser::{Rule, RuleVariable};
use super::transformations::Transformation;
use super::variables::Variable;
use regex::Regex;
use tracing::info;

/// Generates a comprehensive set of OWASP-based security rules.
/// Called at startup if the rules database is empty.
pub fn generate_owasp_rules() -> Vec<Rule> {
    info!("🛡️  Generating OWASP Core Rules...");
    
    let mut rules = Vec::new();
    
    // ========================================
    // SQL Injection Detection (ID: 900001)
    // ========================================
    if let Ok(regex) = Regex::new(r"(?i)(union\s+(all\s+)?select|information_schema|waitfor\s+delay|sleep\s*\(|benchmark\s*\(|load_file\s*\(|into\s+outfile|into\s+dumpfile)") {
        rules.push(Rule {
            id: 900001,
            phase: 2,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::Args, count: false, negation: false },
                RuleVariable { variable: Variable::QueryString, count: false, negation: false },
                RuleVariable { variable: Variable::RequestBody, count: false, negation: false },
                RuleVariable { variable: Variable::RequestUri, count: false, negation: false },
                RuleVariable { variable: Variable::RequestFilename, count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("SQL Injection Attack Detected".to_string()),
                Action::Severity(Severity::Critical),
                Action::Tag("OWASP_CRS".to_string()),
                Action::Tag("attack-sqli".to_string()),
            ],
            transformations: vec![
                Transformation::UrlDecode,
                Transformation::Lowercase,
                Transformation::ReplaceComments,
                Transformation::RemoveWhitespace,
            ],
        });
    }
    
    // ========================================  
    // SQL Injection - Classic Patterns (ID: 900002)
    // ========================================
    if let Ok(regex) = Regex::new(r"(?i)(\bor\b\s+\d+\s*=\s*\d+|\band\b\s+\d+\s*=\s*\d+|'\s*or\s*'|'\s*and\s*'|--\s*$|#\s*$|;\s*drop\s+|;\s*delete\s+|;\s*insert\s+|;\s*update\s+)") {
        rules.push(Rule {
            id: 900002,
            phase: 2,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::Args, count: false, negation: false },
                RuleVariable { variable: Variable::QueryString, count: false, negation: false },
                RuleVariable { variable: Variable::RequestUri, count: false, negation: false },
                RuleVariable { variable: Variable::RequestFilename, count: false, negation: false },
                RuleVariable { variable: Variable::RequestBody, count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("SQL Injection - Classic Pattern".to_string()),
                Action::Severity(Severity::Critical),
                Action::Tag("attack-sqli".to_string()),
            ],
            transformations: vec![Transformation::UrlDecode, Transformation::Lowercase, Transformation::ReplaceComments],
        });
    }

    // ========================================
    // XSS - Cross Site Scripting (ID: 900003)
    // ========================================
    if let Ok(regex) = Regex::new(r"(?i)(<script[^>]*>|javascript\s*:|on(load|error|click|mouse|focus|blur|change|submit|reset|select|input)\s*=|<iframe|<object|<embed|<svg\s+on|<img\s+[^>]*onerror)") {
        rules.push(Rule {
            id: 900003,
            phase: 2,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::Args, count: false, negation: false },
                RuleVariable { variable: Variable::RequestBody, count: false, negation: false },
                RuleVariable { variable: Variable::QueryString, count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("XSS Attack Detected".to_string()),
                Action::Severity(Severity::Error),
                Action::Tag("OWASP_CRS".to_string()),
                Action::Tag("attack-xss".to_string()),
            ],
            transformations: vec![
                Transformation::UrlDecode,
                Transformation::HtmlEntityDecode,
                Transformation::Lowercase,
            ],
        });
    }

    // ========================================
    // XSS - Event Handlers (ID: 900004)
    // ========================================
    if let Ok(regex) = Regex::new(r#"(?i)(expression\s*\(|url\s*\(\s*javascript|<[^>]+style\s*=\s*[^>]*expression|vbscript\s*:|data\s*:\s*text/html)"#) {
        rules.push(Rule {
            id: 900004,
            phase: 2,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::Args, count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("XSS via Expression/Data URI".to_string()),
                Action::Severity(Severity::Error),
                Action::Tag("attack-xss".to_string()),
            ],
            transformations: vec![Transformation::UrlDecode, Transformation::Lowercase],
        });
    }

    // ========================================
    // LFI - Local File Inclusion (ID: 900005)
    // ========================================
    if let Ok(regex) = Regex::new(r"(\.\.(/|\\|%2f|%5c)|/etc/(passwd|shadow|hosts)|/proc/(self|version|cmdline)|/var/log/|c:\\windows\\|boot\.ini)") {
        rules.push(Rule {
            id: 900005,
            phase: 2,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::RequestUri, count: false, negation: false },
                RuleVariable { variable: Variable::Args, count: false, negation: false },
                RuleVariable { variable: Variable::QueryString, count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("Path Traversal / LFI Attack".to_string()),
                Action::Severity(Severity::Critical),
                Action::Tag("OWASP_CRS".to_string()),
                Action::Tag("attack-lfi".to_string()),
            ],
            transformations: vec![
                Transformation::UrlDecode,
                Transformation::NormalizePath,
                Transformation::Lowercase,
            ],
        });
    }

    // ========================================
    // RCE - Remote Code Execution (ID: 900006)
    // ========================================
    if let Ok(regex) = Regex::new(r"(?i)(cmd(\.exe)?|/bin/(sh|bash|zsh|ksh)|powershell|;\s*(ls|cat|wget|curl|nc|netcat|python|perl|ruby|php)\s+|\|\s*(bash|sh)|`[^`]+`|\$\([^)]+\))") {
        rules.push(Rule {
            id: 900006,
            phase: 2,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::Args, count: false, negation: false },
                RuleVariable { variable: Variable::RequestBody, count: false, negation: false },
                RuleVariable { variable: Variable::RequestHeaders, count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("Remote Code Execution Attempt".to_string()),
                Action::Severity(Severity::Critical),
                Action::Tag("OWASP_CRS".to_string()),
                Action::Tag("attack-rce".to_string()),
            ],
            transformations: vec![Transformation::UrlDecode, Transformation::Lowercase],
        });
    }

    // ========================================
    // SSRF - Server Side Request Forgery (ID: 900007)
    // ========================================
    if let Ok(regex) = Regex::new(r"(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|0x7f|2130706433|file://|gopher://|dict://)") {
        rules.push(Rule {
            id: 900007,
            phase: 2,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::Args, count: false, negation: false },
                RuleVariable { variable: Variable::RequestBody, count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("SSRF Attack Detected".to_string()),
                Action::Severity(Severity::Critical),
                Action::Tag("attack-ssrf".to_string()),
            ],
            transformations: vec![Transformation::UrlDecode, Transformation::Lowercase],
        });
    }

    // ========================================
    // NoSQL Injection (ID: 900008)
    // ========================================
    if let Ok(regex) = Regex::new(r#"(\$where|\$regex|\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin|\$or|\$and|\$not|\$exists|\$type|\$mod|\$all|\$elemMatch)"#) {
        rules.push(Rule {
            id: 900008,
            phase: 2,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::Args, count: false, negation: false },
                RuleVariable { variable: Variable::RequestBody, count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("NoSQL Injection Attack".to_string()),
                Action::Severity(Severity::Critical),
                Action::Tag("attack-nosqli".to_string()),
            ],
            transformations: vec![Transformation::UrlDecode],
        });
    }

    // ========================================
    // Log4Shell / JNDI Injection (ID: 900009)
    // ========================================
    if let Ok(regex) = Regex::new(r"(?i)(\$\{jndi:|%24%7bjndi|%24%7Bjndi|\$\{lower:|%24%7blower|\$\{upper:|%24%7bupper|\$\{env:|ldap://|rmi://|dns://)") {
        rules.push(Rule {
            id: 900009,
            phase: 2,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::Args, count: false, negation: false },
                RuleVariable { variable: Variable::RequestHeaders, count: false, negation: false },
                RuleVariable { variable: Variable::RequestBody, count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("Log4Shell / JNDI Injection Attempt".to_string()),
                Action::Severity(Severity::Critical),
                Action::Tag("attack-log4j".to_string()),
                Action::Tag("CVE-2021-44228".to_string()),
            ],
            transformations: vec![Transformation::UrlDecode, Transformation::Lowercase],
        });
    }

    // ========================================
    // XML External Entity (XXE) (ID: 900010)
    // ========================================
    if let Ok(regex) = Regex::new(r#"(?i)(<!ENTITY|<!DOCTYPE[^>]*\[|SYSTEM\s+["']file://|SYSTEM\s+["']http://|PUBLIC\s+["'][^"']+["']\s+["'])"#) {
        rules.push(Rule {
            id: 900010,
            phase: 2,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::RequestBody, count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("XML External Entity (XXE) Attack".to_string()),
                Action::Severity(Severity::Critical),
                Action::Tag("attack-xxe".to_string()),
            ],
            transformations: vec![],
        });
    }


    // ========================================
    // Scanner / Pen-Test Tool Detection (ID: 900011)
    // ========================================
    rules.push(Rule {
        id: 900011,
        phase: 1,
        chain: false,
        operator_negation: false,
        variables: vec![
            RuleVariable { variable: Variable::RequestHeadersSpecific("user-agent".to_string()), count: false, negation: false },
        ],
        operator: Operator::PhraseMatch(vec![
            "nikto".to_string(),
            "sqlmap".to_string(),
            "nmap".to_string(),
            "dirbuster".to_string(),
            "gobuster".to_string(),
            "wfuzz".to_string(),
            "nuclei".to_string(),
            "burpsuite".to_string(),
            "acunetix".to_string(),
            "nessus".to_string(),
            "masscan".to_string(),
            "whatweb".to_string(),
            "jbrofuzz".to_string(),
            "w3af".to_string(),
            "openvas".to_string(),
            "havij".to_string(),
            "appscan".to_string(),
            "zmeu".to_string(),
            "paros".to_string(),
            "nmap scripting engine".to_string(),
        ]),
        actions: vec![
            Action::Block,
            Action::Msg("Security Scanner Detected".to_string()),
            Action::Severity(Severity::Warning),
            Action::Tag("automation-security-scanner".to_string()),
        ],
        transformations: vec![Transformation::Lowercase],
    });

    // ========================================
    // CRLF Injection (ID: 900012)
    // ========================================
    if let Ok(regex) = Regex::new(r"(%0d%0a|%0d|%0a|\r\n|\n|\r)(set-cookie|location|content-type|x-forwarded|host)\s*:") {
        rules.push(Rule {
            id: 900012,
            phase: 1,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::RequestUri, count: false, negation: false },
                RuleVariable { variable: Variable::Args, count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("CRLF Injection / HTTP Response Splitting".to_string()),
                Action::Severity(Severity::Critical),
                Action::Tag("attack-crlf".to_string()),
            ],
            transformations: vec![Transformation::Lowercase],
        });
    }

    // ========================================
    // Host Header Injection (ID: 900013)
    // ========================================
    if let Ok(regex) = Regex::new(r"(?i)(^[a-z]+://|[^a-z0-9.-])") {
        rules.push(Rule {
            id: 900013,
            phase: 1,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::RequestHeadersSpecific("x-forwarded-host".to_string()), count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("Host Header Injection via X-Forwarded-Host".to_string()),
                Action::Severity(Severity::Error),
                Action::Tag("attack-header-injection".to_string()),
            ],
            transformations: vec![],
        });
    }

    // ========================================
    // SQLi via libinjection on user input (ID: 900014)
    // Note: Do NOT inspect raw RequestUri/RequestFilename — libinjection
    // false-positives on clean paths like "/health". Only inspect
    // user-controlled input: Args, QueryString, RequestBody.
    // ========================================
    rules.push(Rule {
        id: 900014,
        phase: 2,
        chain: false,
        operator_negation: false,
        variables: vec![
            RuleVariable { variable: Variable::Args, count: false, negation: false },
            RuleVariable { variable: Variable::QueryString, count: false, negation: false },
        ],
        operator: Operator::DetectSQLi,
        actions: vec![
            Action::Block,
            Action::Msg("SQL Injection detected (libinjection)".to_string()),
            Action::Severity(Severity::Critical),
            Action::Tag("attack-sqli".to_string()),
        ],
        transformations: vec![Transformation::UrlDecode, Transformation::RemoveNulls],
    });

    // ========================================
    // SSRF patterns in URI (ID: 900015)
    // ========================================
    if let Ok(regex) = Regex::new(r"(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|kubernetes\.default\.svc)") {
        rules.push(Rule {
            id: 900015,
            phase: 2,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::RequestUri, count: false, negation: false },
                RuleVariable { variable: Variable::QueryString, count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("SSRF - Cloud Metadata Endpoint in URI".to_string()),
                Action::Severity(Severity::Critical),
                Action::Tag("attack-ssrf".to_string()),
            ],
            transformations: vec![Transformation::UrlDecode, Transformation::Lowercase],
        });
    }

    // ========================================
    // Shellshock Detection (ID: 900016)
    // ========================================
    if let Ok(regex) = Regex::new(r"\(\)\s*\{[^}]*;\s*\}\s*;") {
        rules.push(Rule {
            id: 900016,
            phase: 1,
            chain: false,
            operator_negation: false,
            variables: vec![
                RuleVariable { variable: Variable::RequestHeaders, count: false, negation: false },
            ],
            operator: Operator::Rx(regex),
            actions: vec![
                Action::Block,
                Action::Msg("Shellshock Attack (CVE-2014-6271)".to_string()),
                Action::Severity(Severity::Critical),
                Action::Tag("attack-shellshock".to_string()),
                Action::Tag("CVE-2014-6271".to_string()),
            ],
            transformations: vec![],
        });
    }

    info!("✅ Generated {} OWASP rules", rules.len());
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owasp_rules_generation() {
        let rules = generate_owasp_rules();
        assert!(rules.len() >= 10, "Should generate at least 10 OWASP rules");
        
        // Verify IDs are unique
        let ids: Vec<u32> = rules.iter().map(|r| r.id).collect();
        let unique: std::collections::HashSet<u32> = ids.iter().cloned().collect();
        assert_eq!(ids.len(), unique.len(), "Rule IDs should be unique");
    }
}
