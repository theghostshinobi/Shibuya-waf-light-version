#!/usr/bin/env python3
"""
Post-Fix Targeted Verification Tests
=====================================
Tests specifically designed to verify the 4 critical fixes:
1. GraphQL alias/batch detection
2. Deserialization detection
3. SQLi obfuscation detection
4. Reconnaissance path blocking
"""

import asyncio
import aiohttp
import json
import time
from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime

# Configuration
TARGET_URL = "http://localhost:8095"

@dataclass
class TestResults:
    category: str
    total: int = 0
    blocked: int = 0
    passed: int = 0
    errors: int = 0
    details: List[Dict] = field(default_factory=list)
    
    @property
    def block_rate(self):
        return (self.blocked / self.total * 100) if self.total > 0 else 0

async def send_request(session, method, url, **kwargs):
    """Send request and return (status, blocked, latency)"""
    start = time.time()
    try:
        async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=10), **kwargs) as resp:
            latency = (time.time() - start) * 1000
            blocked = resp.status in [403, 406, 429]
            return resp.status, blocked, latency, None
    except Exception as e:
        return None, False, 0, str(e)

# =============================================================================
# GRAPHQL TESTS
# =============================================================================

async def test_graphql_aliases(session, results: TestResults):
    """Test alias bombing detection"""
    print("  Testing alias bombing...")
    
    test_cases = [
        (10, False, "Under limit"),
        (50, False, "At limit"),
        (51, True, "Just over limit"),
        (100, True, "Double limit"),
        (200, True, "4x limit"),
    ]
    
    for alias_count, should_block, desc in test_cases:
        aliases = " ".join([f"a{i}: user {{ name }}" for i in range(alias_count)])
        query = f"{{ {aliases} }}"
        payload = {"query": query}
        
        for _ in range(5):  # 5 requests per test case
            status, blocked, latency, err = await send_request(
                session, "POST", f"{TARGET_URL}/graphql",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1
            else:
                results.passed += 1
            
            results.details.append({
                "test": f"alias_{alias_count}",
                "expected_block": should_block,
                "actual_block": blocked,
                "status": status,
                "correct": blocked == should_block
            })

async def test_graphql_batching(session, results: TestResults):
    """Test batch query detection"""
    print("  Testing batch queries...")
    
    test_cases = [
        (1, False, "Single query"),
        (5, False, "Under limit"),
        (10, False, "At limit"),
        (11, True, "Just over limit"),
        (20, True, "Double limit"),
    ]
    
    for batch_size, should_block, desc in test_cases:
        batch = [{"query": "{ user { name } }"} for _ in range(batch_size)]
        
        for _ in range(5):
            status, blocked, latency, err = await send_request(
                session, "POST", f"{TARGET_URL}/graphql",
                json=batch,
                headers={"Content-Type": "application/json"}
            )
            
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1
            else:
                results.passed += 1
            
            results.details.append({
                "test": f"batch_{batch_size}",
                "expected_block": should_block,
                "actual_block": blocked,
                "status": status,
                "correct": blocked == should_block
            })

# =============================================================================
# DESERIALIZATION TESTS
# =============================================================================

PICKLE_PAYLOADS = [
    # Base64 pickle magic bytes
    "gASVIQAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwHb3MucG9wZW6UhZRSlC4=",
    "gAJjb3MKc3lzdGVtCnEAVQQvYmluU2g=",
    "gANjb3MKc3lzdGVtCnEAWAQAAAAvYmluU2g=",
    # Python dangerous imports
    "Y19fYnVpbHRpbnNfXwo=",
    "b3MucG9wZW4=",
    "c3VicHJvY2Vzcy5Qb3Blbg==",
]

JAVA_PAYLOADS = [
    # Java serialization magic
    "aced0005",
    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
    "rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7",
    # Dangerous classes
    "org.apache.commons.collections.functors.InvokerTransformer",
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
]

PHP_PAYLOADS = [
    'O:8:"stdClass":1:{s:4:"test";s:4:"data";}',
    'a:2:{i:0;s:4:"test";i:1;s:4:"data";}',
    'O:14:"GuzzleHttp\\Psr7":0:{}',
    'O:7:"Monolog":0:{}',
]

NODE_PAYLOADS = [
    '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}"}',
    '_$$ND_FUNC$$_function(){return 1}()',
]

async def test_deserialization(session, results: TestResults):
    """Test deserialization attack detection"""
    print("  Testing Python pickle...")
    for payload in PICKLE_PAYLOADS:
        for _ in range(3):
            status, blocked, latency, err = await send_request(
                session, "POST", f"{TARGET_URL}/api/data",
                json={"data": payload},
                headers={"Content-Type": "application/json"}
            )
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1
            else:
                results.passed += 1
    
    print("  Testing Java serialization...")
    for payload in JAVA_PAYLOADS:
        for _ in range(3):
            status, blocked, latency, err = await send_request(
                session, "POST", f"{TARGET_URL}/api/data",
                json={"data": payload},
                headers={"Content-Type": "application/json"}
            )
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1
            else:
                results.passed += 1
    
    print("  Testing PHP/Node.js serialization...")
    for payload in PHP_PAYLOADS + NODE_PAYLOADS:
        for _ in range(3):
            status, blocked, latency, err = await send_request(
                session, "POST", f"{TARGET_URL}/api/data",
                data=payload,
                headers={"Content-Type": "text/plain"}
            )
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1
            else:
                results.passed += 1

# =============================================================================
# SQLI OBFUSCATION TESTS
# =============================================================================

SQLI_COMMENT_PAYLOADS = [
    "' /**/OR/**/ '1'='1",
    "admin'/**/--",
    "' /**/UNION/**/SELECT/**/ 1,2,3--",
    "SELECT/*comment*/FROM/**/users",
    "1' /*/*/OR/*/*/ '1'='1",
]

SQLI_MYSQL_CONDITIONAL = [
    "/*!50000OR*/ '1'='1",
    "/*!50000UNION*/ SELECT 1,2,3",
    "' /*!12345SELECT*/ * FROM users--",
    "admin'/*!50000--*/",
]

SQLI_URL_ENCODED = [
    "%27%20OR%201%3D1--",
    "%27%20UNION%20SELECT%201%2C2%2C3--",
    "%2527%2520OR%25201%253D1--",  # double encoded
    "%27+OR+1%3D1--",
]

async def test_sqli_obfuscation(session, results: TestResults):
    """Test obfuscated SQLi detection"""
    print("  Testing comment obfuscation...")
    for payload in SQLI_COMMENT_PAYLOADS:
        for _ in range(10):
            status, blocked, latency, err = await send_request(
                session, "GET", f"{TARGET_URL}/api/search",
                params={"q": payload}
            )
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1
            else:
                results.passed += 1
    
    print("  Testing MySQL conditional comments...")
    for payload in SQLI_MYSQL_CONDITIONAL:
        for _ in range(10):
            status, blocked, latency, err = await send_request(
                session, "GET", f"{TARGET_URL}/api/search",
                params={"q": payload}
            )
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1
            else:
                results.passed += 1
    
    print("  Testing URL-encoded SQLi...")
    for payload in SQLI_URL_ENCODED:
        for _ in range(10):
            status, blocked, latency, err = await send_request(
                session, "GET", f"{TARGET_URL}/api/search?q={payload}"
            )
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1
            else:
                results.passed += 1

# =============================================================================
# RECONNAISSANCE TESTS
# =============================================================================

RECON_API_DOCS = [
    "/swagger.json", "/swagger.yaml", "/swagger-ui", "/swagger",
    "/api/docs", "/api-docs", "/openapi.json", "/redoc",
]

RECON_CONFIG_FILES = [
    "/.env", "/.git/config", "/.aws/credentials", "/.ssh/id_rsa",
    "/config.yaml", "/config.json", "/settings.py", "/.htaccess",
    "/web.config", "/application.properties",
]

RECON_BACKUP_FILES = [
    "/backup.sql", "/database.sql", "/dump.sql", "/db.sql",
    "/backup.tar.gz", "/backup.zip", "/site.bak", "/data.bak",
]

RECON_ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/wp-admin",
    "/phpmyadmin", "/cpanel", "/manager/html",
]

async def test_reconnaissance(session, results: TestResults):
    """Test reconnaissance path blocking"""
    print("  Testing API documentation paths...")
    for path in RECON_API_DOCS:
        for _ in range(5):
            status, blocked, latency, err = await send_request(
                session, "GET", f"{TARGET_URL}{path}"
            )
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1
            else:
                results.passed += 1
    
    print("  Testing config file paths...")
    for path in RECON_CONFIG_FILES:
        for _ in range(5):
            status, blocked, latency, err = await send_request(
                session, "GET", f"{TARGET_URL}{path}"
            )
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1
            else:
                results.passed += 1
    
    print("  Testing backup file paths...")
    for path in RECON_BACKUP_FILES:
        for _ in range(5):
            status, blocked, latency, err = await send_request(
                session, "GET", f"{TARGET_URL}{path}"
            )
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1
            else:
                results.passed += 1
    
    print("  Testing admin paths...")
    for path in RECON_ADMIN_PATHS:
        for _ in range(5):
            status, blocked, latency, err = await send_request(
                session, "GET", f"{TARGET_URL}{path}"
            )
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1
            else:
                results.passed += 1

# =============================================================================
# FALSE POSITIVE TESTS
# =============================================================================

LEGIT_API_CALLS = [
    ("GET", "/api/products", {"category": "electronics"}),
    ("GET", "/api/users", {"page": "1", "limit": "10"}),
    ("GET", "/api/search", {"q": "laptop reviews"}),
    ("POST", "/api/orders", {"product_id": 123, "quantity": 2}),
]

LEGIT_GRAPHQL = [
    "{ user { id name email } }",
    "{ products { id name price } }",
    "{ user { orders { id total } } }",
    "query GetUser { user(id: 1) { name } }",
]

async def test_false_positives(session, results: TestResults):
    """Test that legitimate traffic is not blocked"""
    print("  Testing legitimate API calls...")
    for method, path, params in LEGIT_API_CALLS:
        for _ in range(10):
            if method == "GET":
                status, blocked, latency, err = await send_request(
                    session, "GET", f"{TARGET_URL}{path}", params=params
                )
            else:
                status, blocked, latency, err = await send_request(
                    session, "POST", f"{TARGET_URL}{path}",
                    json=params, headers={"Content-Type": "application/json"}
                )
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1  # This is a FALSE POSITIVE
            else:
                results.passed += 1
    
    print("  Testing legitimate GraphQL queries...")
    for query in LEGIT_GRAPHQL:
        for _ in range(10):
            status, blocked, latency, err = await send_request(
                session, "POST", f"{TARGET_URL}/graphql",
                json={"query": query},
                headers={"Content-Type": "application/json"}
            )
            results.total += 1
            if err:
                results.errors += 1
            elif blocked:
                results.blocked += 1  # FALSE POSITIVE
            else:
                results.passed += 1

# =============================================================================
# MAIN
# =============================================================================

async def run_verification():
    """Run all verification tests"""
    print("\n" + "="*60)
    print("🧪 WAF POST-FIX VERIFICATION TESTS")
    print("="*60)
    print(f"Target: {TARGET_URL}")
    print(f"Time: {datetime.now().isoformat()}")
    print("="*60 + "\n")
    
    results = {
        "graphql": TestResults(category="GraphQL"),
        "deserialization": TestResults(category="Deserialization"),
        "sqli": TestResults(category="SQLi Obfuscation"),
        "recon": TestResults(category="Reconnaissance"),
        "false_positives": TestResults(category="False Positives"),
    }
    
    connector = aiohttp.TCPConnector(limit=50)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Test connectivity
        print("Checking WAF connectivity...")
        try:
            async with session.get(f"{TARGET_URL}/health", timeout=5) as resp:
                if resp.status != 200:
                    print(f"⚠️ Health check returned {resp.status}")
                else:
                    print("✅ WAF is responding\n")
        except Exception as e:
            print(f"❌ Cannot connect to WAF: {e}")
            print("Please start the WAF first: cargo run --release")
            return
        
        # Run tests
        print("\n📊 Test 1: GraphQL Protection")
        await test_graphql_aliases(session, results["graphql"])
        await test_graphql_batching(session, results["graphql"])
        
        print("\n📊 Test 2: Deserialization Detection")
        await test_deserialization(session, results["deserialization"])
        
        print("\n📊 Test 3: SQLi Obfuscation Detection")
        await test_sqli_obfuscation(session, results["sqli"])
        
        print("\n📊 Test 4: Reconnaissance Detection")
        await test_reconnaissance(session, results["recon"])
        
        print("\n📊 Test 5: False Positive Check")
        await test_false_positives(session, results["false_positives"])
    
    # Print summary
    print("\n" + "="*60)
    print("📊 VERIFICATION RESULTS SUMMARY")
    print("="*60)
    
    targets = {
        "graphql": 99.0,
        "deserialization": 99.0,
        "sqli": 95.0,
        "recon": 90.0,
    }
    
    all_passed = True
    
    for key, res in results.items():
        if key == "false_positives":
            # For FP, lower is better
            fp_rate = (res.blocked / res.total * 100) if res.total > 0 else 0
            status = "✅" if fp_rate < 1 else "❌"
            print(f"{status} {res.category}: {res.blocked}/{res.total} blocked ({fp_rate:.1f}% FP rate) - Target: <1%")
            if fp_rate >= 1:
                all_passed = False
        else:
            target = targets.get(key, 99.0)
            status = "✅" if res.block_rate >= target else "❌"
            print(f"{status} {res.category}: {res.blocked}/{res.total} blocked ({res.block_rate:.1f}%) - Target: {target}%+")
            if res.block_rate < target:
                all_passed = False
        
        if res.errors > 0:
            print(f"   ⚠️ {res.errors} errors (WAF may not be running)")
    
    print("\n" + "="*60)
    if all_passed:
        print("🎯 ALL TARGETS MET - VERIFICATION PASSED!")
    else:
        print("⚠️ SOME TARGETS NOT MET - SEE DETAILS ABOVE")
    print("="*60 + "\n")
    
    # Debug: Print details for suspicious passes (e.g. if we expect block but got pass)
    print("🔍 DEBUG: Inspecting 'Passed' requests (Status Codes):")
    for cat, res in results.items():
        if res.passed > 0:
            print(f"-- {cat} (First 3 passed):")
            count = 0
            for d in res.details:
                if not d['actual_block']:
                    print(f"   [{d['status']}] {d.get('test', 'unknown')}")
                    count += 1
                    if count >= 3: break
    
    print("\n" + "="*60)
    
    print("🔍 DEBUG: Inspecting 'Blocked' False Positives (Status Codes):")
    res = results['false_positives']
    if res.blocked > 0:
        print(f"-- False Positives (First 5 blocked):")
        count = 0
        for d in res.details:
            if d['actual_block']:
                print(f"   [{d['status']}] {d.get('test', 'unknown')}")
                count += 1
                if count >= 5: break
                
    print("\n" + "="*60)
    
    # Save detailed results
    report = {
        "timestamp": datetime.now().isoformat(),
        "target": TARGET_URL,
        "results": {k: {
            "category": v.category,
            "total": v.total,
            "blocked": v.blocked,
            "passed": v.passed,
            "errors": v.errors,
            "block_rate": v.block_rate,
        } for k, v in results.items()}
    }
    
    with open("verification_results.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"✅ Results saved to: verification_results.json")
    
    return results

if __name__ == "__main__":
    asyncio.run(run_verification())
