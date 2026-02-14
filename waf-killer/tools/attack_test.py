
import urllib.request
import urllib.error
import time
import sys

TARGET_URL = "http://localhost:8080/"

# Color codes for output
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

ATTACK_VECTORS = [
    {
        "name": "SQL Injection (Basic)",
        "payload": "?q=' OR 1=1 --",
        "expected": 403
    },
    {
        "name": "SQL Injection (UNION)",
        "payload": "?q=UNION SELECT username, password FROM users",
        "expected": 403
    },
    {
        "name": "Cross-Site Scripting (Script Tag)",
        "payload": "?q=<script>alert('XSS')</script>",
        "expected": 403
    },
    {
        "name": "Cross-Site Scripting (Event Handler)",
        "payload": "?q=<img src=x onerror=alert(1)>",
        "expected": 403
    },
    {
        "name": "Path Traversal",
        "payload": "?file=../../../../etc/passwd",
        "expected": 403
    },
    {
        "name": "Command Injection",
        "payload": "?cmd=; cat /etc/passwd",
        "expected": 403
    },
    {
        "name": "Legitimate Traffic (Control)",
        "payload": "?q=hello world",
        "expected": 200
    }
]

def run_attack_test():
    print(f"⚔️  Starting Security Tests against {TARGET_URL}")
    print("-" * 60)
    print(f"{'TEST NAME':<35} | {'STATUS':<8} | {'RESULT'}")
    print("-" * 60)

    passed = 0
    failed = 0

    import urllib.parse
    for attack in ATTACK_VECTORS:
        # Properly encode payload to avoid Invalid URI errors (400)
        # We manually split query params to keep ? and = unencoded for simplicity in this specific test structure
        safe_payload = attack["payload"].replace(" ", "%20").replace("<", "%3C").replace(">", "%3E").replace("'", "%27").replace('"', "%22")
        url = TARGET_URL + safe_payload
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
            with urllib.request.urlopen(req, timeout=2) as response:
                status = response.getcode()
                response_headers = response.info()
        except urllib.error.HTTPError as e:
            status = e.code
        except Exception as e:
            print(f"Error connecting: {e}")
            status = 0
            response_headers = None

        # Verification
        if status == attack["expected"]:
            result = f"{GREEN}PASS{RESET}"
            passed += 1
        else:
            result = f"{RED}FAIL (Got {status}, Expected {attack['expected']}){RESET}"
            failed += 1
        
        print(f"{attack['name']:<35} | {status:<8} | {result}")

    print("-" * 60)
    print(f"Summary: {passed} Passed, {failed} Failed")
    
    if failed == 0:
        print(f"\n🚀 {GREEN}WAF is blocking attacks correctly!{RESET}")
    else:
        print(f"\n⚠️ {RED}Some attacks bypassed the WAF! Check rules.{RESET}")

if __name__ == "__main__":
    run_attack_test()
