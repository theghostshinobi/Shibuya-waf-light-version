# Security Policy

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in Shibuya WAF, please report it responsibly:

### How to Report

**DO NOT** open a public GitHub issue.

Instead:
1. Email: security@shibuya-waf.io
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **24 hours**: Acknowledgment of report
- **7 days**: Initial assessment and triage
- **30 days**: Fix development and testing
- **Public disclosure**: After fix is released

### Scope

**In scope:**
- Remote code execution
- Authentication bypass
- SQL injection / XSS in admin panel
- WAF rule bypass leading to attacks on backend
- Denial of Service vulnerabilities

**Out of scope:**
- Social engineering
- Physical attacks
- Third-party dependencies (report to them)

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | ✅ Yes             |
| < 1.0   | ❌ No (beta)       |

## Security Features

Shibuya WAF includes:
- OWASP Top 10 protection
- ML-based anomaly detection
- Threat intelligence integration
- eBPF kernel-level filtering
- Rate limiting and DDoS mitigation

## Acknowledgments

We appreciate responsible disclosure. Security researchers will be credited in release notes (unless they prefer anonymity).
