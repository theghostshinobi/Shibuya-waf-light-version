# SHIBUYA WAF

**Version:** 1.0  
**Release Date:** February 14, 2026  
**Classification:** Product Documentation

## Table of Contents

- [Introduction](#introduction)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [User Interface Overview](#user-interface-overview)
- [Feature Guides](#feature-guides)
- [Configuration Guide](#configuration-guide)
- [Technical Glossary](#technical-glossary)
- [Support](#support)

***

## Introduction

### What is SHIBUYA WAF

SHIBUYA is a high-performance, open-source Web Application Firewall (WAF) written in Rust. It functions as a reverse proxy between the Internet and your backend server, analyzing every HTTP request in real-time to block cyber attacks before they reach your application.

### Purpose

SHIBUYA protects web applications from:

| Threat | Description |
|--------|-------------|
| SQL Injection | Attempts to manipulate database queries |
| Cross-Site Scripting (XSS) | Injection of malicious JavaScript code |
| Remote Code Execution (RCE) | Execution of commands on the server |
| Local File Inclusion (LFI) | Unauthorized access to system files |
| SSRF | Attacks exploiting the server to reach internal resources |
| Malicious Bots | Scraping, brute force, credential stuffing |
| Application-layer DDoS | Server overload with excessive requests |

### Architecture

```
Internet → SHIBUYA WAF (analysis + blocking) → Backend App
                    ↓
              Dashboard (monitoring)
```

SHIBUYA operates on 5 security layers:

1. **OWASP CRS Rules** — 614 pattern matching rules
2. **ML Anomaly Detection** — IsolationForest for unknown threats
3. **ML Classification** — SVM that categorizes attack types
4. **Threat Intelligence** — IP reputation from external feeds
5. **Bot Detection** — TLS fingerprinting and behavioral analysis

### Target Audience

- Developers who want to protect their applications
- DevOps/SRE teams managing web infrastructures
- Security teams requiring a configurable WAF
- Startups and SMEs seeking an open-source alternative to Cloudflare WAF

***

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| Operating System | macOS 12+, Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+) |
| CPU | 2 cores (x86_64 or ARM64) |
| RAM | 512 MB |
| Disk | 500 MB free (without build artifacts) |
| Node.js | v18.0 or higher |
| npm | v8.0 or higher |
| Rust | 1.75+ (to compile backend) |

### Recommended Requirements (Production)

| Component | Requirement |
|-----------|-------------|
| CPU | 4+ cores |
| RAM | 2 GB+ |
| Disk | 5 GB (with logs and ML models) |
| Network | 1 Gbps |
| OS | Linux (optimal performance) |

### Network Ports

| Port | Service | Configurable |
|------|---------|--------------|
| 8080 | WAF HTTP Proxy | Yes (server.http_port) |
| 8443 | WAF HTTPS Proxy | Yes (server.https_port) |
| 9090 | Admin API | Yes (telemetry.metrics_port) |
| 5173 | Dashboard dev server | Yes (--port flag) |

### Optional Software

| Software | Purpose |
|----------|---------|
| PostgreSQL 14+ | Log persistence, traffic replay |
| Python 3.10+ | ML training scripts |
| Docker | Containerized deployment |

***

## Installation

### Quick Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/shibuya-waf.git
cd shibuya-waf/waf-killer

# 2. Run setup script (installs all dependencies)
./setup

# 3. Start the application (opens in browser)
./start
```

**TIP:** The `./setup` script automatically checks prerequisites, installs npm dependencies, and compiles the Rust backend.

### Manual Installation

#### Dashboard (Frontend)

```bash
cd waf-killer/dashboard
npm install
npm run dev -- --port 5173
```

Dashboard will be available at http://localhost:5173.

#### Backend (WAF Engine)

```bash
cd waf-killer/core
cargo build --release
./target/release/waf-killer --config config/waf.yaml
```

WAF proxy will be active at http://localhost:8080.

#### Installation Verification

```bash
# Verify dashboard is responding
curl -s http://localhost:5173 | head -5

# Verify WAF proxy is responding (requires compiled backend)
curl -s http://localhost:8080/health

# Verify Admin API is responding
curl -s http://localhost:9090/api/health
```

### First Access

1. Open browser at http://localhost:5173
2. Login with default credentials:
   - **Username:** admin
   - **Password:** BrutalDevAccess2026!
3. You will be redirected to the main Dashboard

**CAUTION:** Change the default password immediately in production via the Settings section.

***

## User Interface Overview

### General Layout

The interface uses a professional dark theme with a two-column layout:

- **Left sidebar** — Navigation between sections
- **Main area** — Active page content
- **Top bar** — Current path, Simple/Advanced toggle, WAF status

### Interface Modes

SHIBUYA offers two viewing modes:

| Mode | Content | Target User |
|------|---------|-------------|
| Simple | Only essential pages (Dashboard, Quick Setup, Requests, Analytics, Rules, ML, Bot Detection) | Non-technical users |
| Advanced | All pages + Settings, Vulnerabilities, Shadow API, System | DevOps and Security teams |

The toggle is located in the top right of the top bar.

### Navigation Map

| Page | Function |
|------|----------|
| Dashboard | Real-time overview: metrics, component status |
| Quick Setup | Wizard to protect a site in 30 seconds |
| Requests | Log of all requests with details |
| Analytics | Attack trend charts, distribution by type |
| Rules | OWASP CRS rule management |
| ML Engine | ML model configuration and feedback |
| Bot Detection | Anti-bot statistics and configuration |
| Settings | Complete WAF configuration (Advanced) |
| Vulnerabilities | Vulnerability scanner (Advanced) |

***

## Feature Guides

### Quick Setup — Protection in 30 Seconds

Quick Setup is the fastest way to activate WAF protection. No manual configuration required.

#### How to Use

**Step 1 — Enter Backend URL**

Enter your application URL (e.g., http://localhost:3000). You can also click on one of the framework presets to auto-fill:

| Preset | Auto-filled URL | Suggested Level |
|--------|----------------|-----------------|
| Next.js | http://localhost:3000 | Moderate |
| Vite/React | http://localhost:5173 | Moderate |
| Django | http://localhost:8000 | Strict |
| Flask | http://localhost:5000 | Moderate |
| Express | http://localhost:3000 | Moderate |
| Laravel | http://localhost:8000 | Strict |
| Rails | http://localhost:3000 | Moderate |
| Go | http://localhost:8080 | Permissive |

A green checkmark confirms the URL is valid.

**Step 2 — Choose Security Level**

| Level | Anomaly Threshold | Paranoia | Description |
|-------|------------------|----------|-------------|
| Strict | T=3 | PL3 | Maximum protection. May block legitimate edge-cases. Ideal for banking and healthcare apps. |
| Moderate ⭐ | T=5 | PL1 | Balanced. Blocks real attacks with few false positives. Recommended for most cases. |
| Permissive | T=10 | PL1 | Minimal friction. Blocks only obvious attacks. Ideal for high-traffic public APIs. |

**Step 3 — Click "Activate Protection"**

The system:
- Validates the URL (checks format and blocks SSRF)
- Tests connectivity to backend (5s timeout)
- Updates WAF configuration in real-time (hot-reload, zero restart)
- Shows success screen with WAF URL and curl test commands

**TIP:** After activation, all traffic to http://localhost:8080 will be proxied and automatically protected.

### Dashboard — Overview

The dashboard shows the WAF's real-time status.

#### Main Metrics

| Metric | Meaning |
|--------|---------|
| Total Requests | Total number of processed requests |
| Blocked | Requests blocked by WAF (attacks) |
| Allowed | Legitimate requests let through |
| Uptime | Time since last WAF startup |

#### Component Status

| Component | Green | Red |
|-----------|-------|-----|
| Proxy | Proxy active and functioning | Proxy unreachable |
| Rule Engine | CRS rules loaded | Error loading rules |
| eBPF | Kernel filter active | Not supported or disabled |
| WASM Plugins | Plugins loaded | No plugins or error |

### Requests — Request Log

This section shows detailed logs of every request processed by the WAF.

#### Information per Request

| Field | Description |
|-------|-------------|
| Timestamp | Request date and time |
| Method | GET, POST, PUT, DELETE, etc. |
| Path | Requested URL |
| Status | HTTP response code |
| Client IP | Requester's IP address |
| Action | ALLOW, BLOCK, CHALLENGE |
| Score | Cumulative anomaly score of triggered rules |
| Rules Matched | List of matched CRS rules |

#### Available Filters

- Filter by action (Blocked / Allowed / All)
- Filter by HTTP method
- Filter by source IP
- Search by URL path

### Analytics — Trends and Statistics

Page with charts and traffic analysis over time.

#### Available Charts

| Chart | What it Shows |
|-------|---------------|
| Request Volume | Total requests over time (line) |
| Block Rate | Percentage of blocked requests |
| Attack Types | Distribution by type: SQLi, XSS, RCE, LFI, etc. |
| Top IPs | IP addresses with most blocked requests |
| Top Paths | Most attacked URLs |
| Response Codes | HTTP code distribution (200, 403, 500, etc.) |

### Rules — Rule Management

Interface to view, enable, and disable OWASP CRS rules.

#### Rule Categories

| ID Range | Category | What it Protects |
|----------|----------|------------------|
| 920xxx | Protocol Enforcement | HTTP format validation |
| 921xxx | Protocol Attack | HTTP smuggling, splitting |
| 930xxx | LFI | Path traversal, file inclusion |
| 932xxx | RCE | Command injection, OS command |
| 941xxx | XSS | Cross-Site Scripting |
| 942xxx | SQLi | SQL Injection |
| 943xxx | Session Fixation | Session hijacking |
| 944xxx | Java Attack | Java deserialization |

#### Available Actions

- **Toggle ON/OFF** — Enable or disable individual rules
- **View Rule** — Display the rule's regex pattern
- **Search** — Search rules by ID or description
- **Filter by Category** — Filter by attack type

**WARNING:** Disabling rules reduces protection. Only do this if a rule causes confirmed false positives.

### ML Engine — Machine Learning

Configuration and monitoring of artificial intelligence models.

#### Active Models

| Model | Type | Purpose |
|-------|------|---------|
| IsolationForest | Anomaly detection | Detects never-before-seen behaviors (zero-day) |
| SVM Classifier | Classification | Categorizes: SQLi, XSS, RCE, benign |

#### Configurable Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Threshold | 0.7 | Score above which ML flags as suspicious (0.0–1.0) |
| ML Weight | 0.3 | Weight of ML verdict in total score |
| Shadow Mode | Off | If active, ML logs decisions without blocking |
| Fail Open | On | If ML has an error, allow the request through |

#### Feedback Loop

In the Pending Reviews section you can:
- View requests flagged by ML
- Mark as True Positive (confirmed attack) or False Positive (error)
- The model automatically recalibrates based on feedback

### Bot Detection

Detection and blocking of automated bots.

#### Detection Techniques

| Technique | Description |
|-----------|-------------|
| JA3 Fingerprint | Identifies client from TLS handshake |
| Behavior Analysis | Analyzes patterns: click speed, page sequence |
| Rate Patterns | Too-regular requests = bot |
| User-Agent Analysis | Comparison with database of known bots |

#### Displayed Statistics

- **Human vs Bot ratio** — Percentage of human vs automated traffic
- **Top Bot IPs** — IPs with most bot activity
- **Bot Types** — Crawler, scraper, brute force, etc.
- **Block Rate** — Percentage of bots blocked vs total

### Vulnerabilities Scanner

Integrated scanner to identify vulnerabilities in the protected application.

#### How to Start a Scan

1. Go to Vulnerabilities page (Advanced mode)
2. Click Start Scan
3. Wait for completion (status: automatic polling)
4. View results divided by severity: Critical, High, Medium, Low

#### Results

Each vulnerability reports:
- **CVE/ID** — Vulnerability identifier
- **Severity** — Critical / High / Medium / Low
- **Description** — Problem description
- **Affected Component** — Path or component involved
- **Remediation** — Correction suggestion

### Settings — UI Configuration

Complete configuration page accessible in Advanced mode.

#### Available Tabs

| Tab | Content |
|-----|---------|
| General | HTTP/HTTPS port, timeout, max connections, TLS |
| Upstream | Backend URL, pool size, connection timeout, health check |
| Detection | Mode (blocking/shadow), threshold, paranoia level |
| ML | ML threshold, shadow mode, fail open |
| API Protection | OpenAPI validation, GraphQL limits |
| Security | Admin token, max body/header size, allowed methods |

**IMPORTANT:** Changes made via Settings are applied in real-time (hot-reload). No need to restart the WAF.

***

## Configuration Guide

### Configuration File

The main file is `config/waf.yaml`. It is read at startup and can be modified via UI (Settings) or directly with a text editor.

### server Section — Server Configuration

```yaml
server:
  listen_addr: 0.0.0.0        # Listen address (0.0.0.0 = all interfaces)
  http_port: 8080              # WAF proxy HTTP port
  https_port: 8443             # WAF proxy HTTPS port
  shutdown_timeout: 30s        # Wait time for graceful shutdown
  request_timeout: 1m          # Maximum timeout per request
  max_connections: 10000       # Maximum simultaneous TCP connections
  tls:
    enabled: false             # Enable HTTPS
    cert_path: certs/server.crt
    key_path: certs/server.key
    min_version: TLS1.3        # Minimum accepted TLS version
    cipher_suites:             # Allowed cipher suites
      - TLS_AES_256_GCM_SHA384
      - TLS_AES_128_GCM_SHA256
      - TLS_CHACHA20_POLY1305_SHA256
```

### upstream Section — Backend

```yaml
upstream:
  backend_url: http://localhost:3000   # Application URL to protect
  pool_size: 100                       # Connections in pool to backend
  connect_timeout: 5s                  # Timeout to open connection
  request_timeout: 30s                 # Timeout to receive response
  idle_timeout: 1m 30s                 # Timeout for idle connections
  health_check:
    enabled: true                      # Enable periodic health check
    path: /health                      # Path to query
    interval: 10s                      # Check frequency
    timeout: 5s                        # Single check timeout
    unhealthy_threshold: 3             # Failed checks before marking "unhealthy"
    healthy_threshold: 2               # Successful checks before marking "healthy"
```

### detection Section — Detection Engine

```yaml
detection:
  enabled: true                # Enable detection engine
  mode: blocking               # blocking | shadow (log only) | disabled
  crs:
    enabled: true              # Enable OWASP CRS rules
    rules_path: rules/crs      # Rules file path
    paranoia_level: 1          # 1=conservative, 2=medium, 3=aggressive, 4=paranoid
    inbound_threshold: 5       # Cumulative score to block (lower = more sensitive)
    outbound_threshold: 4      # Score for outbound responses
  rate_limiting:
    enabled: true              # Enable rate limiting
    requests_per_second: 100   # Requests/s per IP
    burst_size: 200            # Maximum allowed burst
    ban_duration_secs: 60      # Ban duration after exceeding
  blocking_threshold: 25       # Overall anomaly score for blocking
  challenge_threshold: 15      # Score to show challenge (CAPTCHA) instead of block
```

**NOTE:** Paranoia Level: PL1 is suitable for most sites. Increase to PL2-PL3 only for high-sensitivity applications (banking, healthcare). PL4 generates many false positives and requires rule-by-rule tuning.

### ml Section — Machine Learning

```yaml
ml:
  enabled: true                                    # Enable ML inference
  model_path: ml/models/isolation_forest.onnx      # Anomaly detection model
  classifier_model_path: ml/models/attack_classifier.onnx  # Classification model
  scaler_path: ml/models/scaler.json               # Feature normalizer
  threshold: 0.7               # ML score to flag (0.0-1.0, lower = more sensitive)
  inference_threads: 4         # Threads dedicated to inference
  cache_features: true         # Cache features for similar requests
  ml_weight: 0.3               # ML weight in total score (0.0-1.0)
  shadow_mode: false           # If true, ML logs but doesn't block
  fail_open: true              # If ML has error, allow (true) or block (false)
```

### security Section — Security Limits

```yaml
security:
  admin_token: "your-secret-token"   # Token for Admin API authentication
  max_body_size: 10485760            # Max body size in bytes (10 MB)
  max_header_size: 8192              # Max header size (8 KB)
  max_uri_length: 2048               # Max URI length (2 KB)
  allowed_methods:                   # Allowed HTTP methods
    - GET
    - POST
    - PUT
    - PATCH
    - DELETE
    - HEAD
    - OPTIONS
  blocked_user_agents: []            # Blocked user-agent list (regex)
```

### api_protection Section — API Protection

```yaml
api_protection:
  enabled: true
  openapi_validation_enabled: false  # Validate requests against OpenAPI spec
  openapi_specs: []                  # OpenAPI 3.x file paths
  graphql:
    endpoint: /graphql               # GraphQL endpoint to protect
    max_depth: 7                     # Maximum query depth
    max_complexity: 1000             # Maximum query complexity
    max_batch_size: 10               # Maximum batch queries
    max_aliases: 50                  # Maximum aliases
    introspection_enabled: false     # Block introspection queries
  strict_mode: false                 # Block requests not conforming to spec
```

### telemetry Section — Logging and Metrics

```yaml
telemetry:
  log_level: debug              # Log level: trace | debug | info | warn | error
  log_format: json              # Format: json | text
  metrics_enabled: true         # Expose Prometheus metrics
  metrics_port: 9090            # /metrics endpoint port
  tracing_enabled: true         # Enable distributed tracing
  tracing_sample_rate: 0.1      # Percentage of traced requests (0.0-1.0)
```

### shadow Section — Shadow Mode

```yaml
shadow:
  enabled: false          # Enable global shadow mode
  percentage: 10          # Captured traffic percentage (1-100)
  duration: null          # Shadow duration (null = indefinite, or "24h")
  routes: null            # Specific routes (null = all)
```

**TIP:** Use Shadow Mode when introducing new rules: activate them in shadow for 24-72h, check logs for false positives, then promote to blocking.

### Environment Variables

Some configurations can be overridden with environment variables:

| Variable | Overrides | Example |
|----------|-----------|---------|
| WAF_HTTP_PORT | server.http_port | WAF_HTTP_PORT=9080 |
| WAF_BACKEND_URL | upstream.backend_url | WAF_BACKEND_URL=http://app:3000 |
| WAF_LOG_LEVEL | telemetry.log_level | WAF_LOG_LEVEL=info |
| WAF_ADMIN_TOKEN | security.admin_token | WAF_ADMIN_TOKEN=mysecret123 |
| WAF_PARANOIA_LEVEL | detection.crs.paranoia_level | WAF_PARANOIA_LEVEL=2 |

***

## Technical Glossary

| Term | Definition |
|------|------------|
| WAF | Web Application Firewall — firewall specialized for web applications |
| Reverse Proxy | Intermediate server that receives requests on behalf of backend |
| OWASP | Open Web Application Security Project — organization for web security |
| CRS | Core Rule Set — OWASP rule set for WAF |
| SQLi | SQL Injection — attack that manipulates database queries |
| XSS | Cross-Site Scripting — malicious JavaScript code injection |
| RCE | Remote Code Execution — remote command execution on server |
| LFI | Local File Inclusion — unauthorized access to server files |
| SSRF | Server-Side Request Forgery — attacker uses server to make internal requests |
| DDoS | Distributed Denial of Service — distributed service overload |
| Anomaly Score | Cumulative score of rules matching a request |
| Paranoia Level | CRS rule aggressiveness level (1-4) |
| Threshold | Threshold beyond which a request is blocked |
| Hot-Reload | Configuration update without restarting service |
| ArcSwap | Rust mechanism for atomic update of shared data |
| Shadow Mode | Mode that logs decisions without blocking traffic |
| False Positive (FP) | Legitimate request erroneously blocked |
| False Negative (FN) | Undetected attack that passes through |
| TPR | True Positive Rate — percentage of correctly blocked attacks |
| FPR | False Positive Rate — percentage of legitimate requests erroneously blocked |
| IsolationForest | ML algorithm for anomaly detection (detects outliers) |
| SVM | Support Vector Machine — ML algorithm for classification |
| ONNX | Open Neural Network Exchange — standard format for ML models |
| JA3 | TLS fingerprint based on client handshake |
| Rate Limiting | Limitation of number of requests per time unit |
| Token Bucket | Rate limiting algorithm with allowed burst |
| Connection Pool | Set of reused connections to backend |
| Health Check | Periodic check of backend health status |
| TLS | Transport Layer Security — encryption protocol for HTTPS |
| mTLS | Mutual TLS — mutual client/server authentication |
| GraphQL | Query language for APIs with typed schema |
| OpenAPI | Specification for describing REST APIs (formerly Swagger) |
| Prometheus | Open-source monitoring and alerting system |
| CVE | Common Vulnerabilities and Exposures — vulnerability identifier |

***

## Support

### Community Support (Free)

| Channel | Link | Response Time |
|---------|------|---------------|
| GitHub Issues | github.com/your-org/shibuya-waf/issues | 24-48h |
| Discord Server | discord.gg/shibuya-waf | Business hours |


### Bug Reporting

To report a bug:
1. Go to GitHub Issues
2. Use the "Bug Report" template
3. Include: WAF version, OS, relevant logs, steps to reproduce

### Vulnerability Disclosure

**CAUTION:** DO NOT report security vulnerabilities on public GitHub Issues.

We offer a bug bounty program with rewards up to $5,000 for critical WAF bypasses.

***

**Document generated February 14, 2026 — SHIBUYA WAF v1.0**

# WAF Security Test Report






## 📊 Test Summary

| Metric | Value |
|--------|-------|
| **Total Tests** | 51 (50 attacks + 1 safe baseline) |
| **Passed** | 51 / 51 |
| **Failed** | 0 |
| **Detection Rate** | 100.0% |
| **WAF Block Rate** | 96.1% (49 blocked, 2 allowed) |

***

## 🛡️ Full OWASP Top 10 (2021) Coverage

| Category | Tests | Attacks | Result |
|----------|-------|---------|--------|
| **A01: Broken Access Control** | 1–4 | Path traversal, forced browsing, dotfile | ✅ 4/4 |
| **A02: Cryptographic Failures** | 5–7 | Password, API key, token in URL | ✅ 3/3 |
| **A03: Injection (SQLi)** | 8–13 | OR 1=1, UNION, blind, stacked, login bypass, NoSQL $ne | ✅ 6/6 |
| **A03: Injection (XSS)** | 14–18 | script, img onerror, onmouseover, javascript:, SVG onload | ✅ 5/5 |
| **A03: Injection (CMDi)** | 19–21 | ping, exec, PowerShell | ✅ 3/3 |
| **A04: Insecure Design** | 22–24 | `__proto__` pollution, mass assignment, negative qty | ✅ 3/3 |
| **A05: Security Misconfiguration** | 25–28 | Nikto, sqlmap, debug, server-status | ✅ 4/4 |
| **A06: Vulnerable Components** | 29–32 | Log4Shell, Shellshock, Spring4Shell, WP plugin | ✅ 4/4 |
| **A07: Authentication Failures** | 33–38 | Open redirect ×2, brute force burst (4 attempts) | ✅ 6/6 |
| **A08: Software & Data Integrity** | 39–41 | PHP deser, proto pollution, Java deser (rO0ABX) | ✅ 3/3 |
| **A09: Logging & Monitoring Failures** | 42–44 | CRLF, log injection, HTTP response splitting | ✅ 3/3 |
| **A10: Server-Side Request Forgery** | 45–47 | AWS metadata, internal net, file:// protocol | ✅ 3/3 |

***

## 🎯 MITRE ATT&CK Techniques

| Technique | Test | Attack | Result |
|-----------|------|--------|--------|
| **T1190: Exploit Public-Facing Application** | 48 | Shellshock via User-Agent | ✅ BLOCK |
| **T1595: Active Reconnaissance** | 49 | WP xmlrpc.php fingerprinting | ✅ BLOCK |
| **T1059: Command & Scripting Interpreter** | 50 | Base64-encoded bash injection | ✅ BLOCK |

***

## 🔒 WAF Rules (16 total)

| Rule ID | Category | OWASP | Severity |
|---------|----------|-------|----------|
| `CRS-942100` | SQL Injection + NoSQL | A03 | 🔴 CRITICAL |
| `CRS-941100` | XSS | A03 | 🟠 HIGH |
| `CRS-932100` | Command Injection | A03 | 🔴 CRITICAL |
| `CRS-930100` | Path Traversal | A01 | 🟠 HIGH |
| `CRS-930110` | Broken Access Control | A01 | 🟡 MEDIUM |
| `CRS-934100` | SSRF | A10 | 🔴 CRITICAL |
| `CRS-934110` | Open Redirect | A07 | 🟡 MEDIUM |
| `CRS-921100` | CRLF/Header Injection | A09 | 🟠 HIGH |
| `CRS-920100` | Sensitive Data Exposure | A02 | 🟡 MEDIUM |
| `CRS-944100` | Deserialization | A08 | 🔴 CRITICAL |
| `RATE-001` | Rate Limiting | A04 | 🟡 MEDIUM |
| `CRS-920200` | Security Misconfiguration | A05 | 🟡 MEDIUM |
| `CRS-944200` | Vulnerable Components | A06 | 🔴 CRITICAL |
| `CRS-920300` | Brute Force | A07 | 🟠 HIGH |
| `MITRE-T1190` | Exploit Public-Facing App | MITRE | 🔴 CRITICAL |
| `MITRE-T1595` | Active Reconnaissance | MITRE | 🟡 MEDIUM |

***

## 🚀 Features

- ✅ **100% detection rate** across all OWASP Top 10 categories
- 🛡️ **96.1% block rate** with intelligent allow-listing
- 🎯 **MITRE ATT&CK** technique coverage
- 📈 **Real-time monitoring** and logging
- 🔧 **Customizable rules** engine
- ⚡ **Low latency** performance

***

## 📝 License

[Your License Here]

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

***

**Made with ❤️ for secure web applications**
