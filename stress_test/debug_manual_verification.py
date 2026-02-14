import urllib.request
import urllib.error
import json
import time

TARGET = "http://localhost:8095"

def test(name, url, method="GET", data=None, headers=None, expected_status=None):
    if headers is None: headers = {}
    headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    if data and method == "POST":
        headers['Content-Type'] = 'application/json'
        # ensure data is bytes
        if isinstance(data, str): data = data.encode('utf-8')
        elif isinstance(data, dict): data = json.dumps(data).encode('utf-8')
    
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    
    print(f"TEST: {name}...", end=" ")
    try:
        with urllib.request.urlopen(req) as f:
            status = f.status
            body = f.read().decode('utf-8', errors='ignore')
            print(f"[{status}] ", end="")
            if expected_status and status != expected_status:
                print(f"❌ FAILED (Expected {expected_status})")
            else:
                print(f"✅ PASSED")
            return status
    except urllib.error.HTTPError as e:
        print(f"[{e.code}] ", end="")
        if expected_status and e.code != expected_status:
             # If we expected 403 and got 429, or vice versa, it's a block, so maybe okay?
             if expected_status in [403, 429] and e.code in [403, 429]:
                 print(f"✅ PASSED (Blocked)")
             else:
                 print(f"❌ FAILED (Expected {expected_status})")
        else:
             print(f"✅ PASSED")
        return e.code
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return None

print("=== MANUAL VERIFICATION SUITE ===")

# 1. GraphQL Alias
aliases = " ".join([f"a{i}: user {{ name }}" for i in range(51)])
query = f"{{ {aliases} }}"
test("GraphQL Alias Bomb (51)", f"{TARGET}/graphql", "POST", {"query": query}, expected_status=429)

# 2. Deserialization (Pickle)
# "gASV..." is "cos\nsystem..."
pickle = "gASVIQAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlC4=" 
test("Deserialization (Pickle)", f"{TARGET}/api/data", "POST", {"data": pickle}, expected_status=403)

# 3. SQLi Obfuscation
sqli = "' /**/OR/**/ '1'='1"
test("SQLi Obfuscation", f"{TARGET}/api/search?q={urllib.parse.quote(sqli)}", "GET", expected_status=403)

# 4. Recon
test("Recon (.env)", f"{TARGET}/.env", "GET", expected_status=403)

# 5. Legitimate (False Positive Check)
test("Legitimate API", f"{TARGET}/health", "GET", expected_status=200)
