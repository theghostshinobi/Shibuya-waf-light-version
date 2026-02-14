
import urllib.request
import urllib.error
import json
import time

BASE_URL = "http://localhost:8095"

def test(name, url, method="GET", data=None, headers=None, expected_status=None):
    if headers is None: headers = {}
    
    # Use Chrome UA to bypass Bot Detection (Layer 1) and hit CRS (Layer 3)
    headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    
    if data and method == "POST":
        headers['Content-Type'] = 'application/json'
        # ensure data is bytes
        if isinstance(data, dict) or isinstance(data, list):
            data = json.dumps(data).encode('utf-8')
        elif isinstance(data, str):
            data = data.encode('utf-8')
    
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    
    print(f"TEST: {name}...", end=" ", flush=True)
    try:
        with urllib.request.urlopen(req) as response:
            status = response.getcode()
            print(f"[{status}]", end=" ")
            if expected_status and status != expected_status:
                 print(f"❌ FAILED (Expected {expected_status})")
            else:
                 print(f"✅ PASSED")
            return status
    except urllib.error.HTTPError as e:
        print(f"[{e.code}]", end=" ")
        if expected_status and e.code != expected_status:
             print(f"❌ FAILED (Expected {expected_status})")
        else:
             print(f"✅ PASSED")
        return e.code
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return 0

print("=== INTEGRATION GAP VERIFICATION SUITE ===")

# 1. GraphQL Integration Tests
graphql_url = f"{BASE_URL}/graphql"

# 1.1 Alias Bombing (should now work with early body read)
alias_query = "{ " + " ".join([f"a{i}: user {{ name }}" for i in range(60)]) + " }"
test("GraphQL Alias Bomb (60)", graphql_url, "POST", {"query": alias_query}, expected_status=429)

# 1.2 Batch Attack (should now be detected via extract_graphql_query)
batch_payload = [{"query": "{ user { name } }"} for _ in range(15)]
test("GraphQL Batch Attack (15)", graphql_url, "POST", batch_payload, expected_status=429)

# 2. Deserialization Tests (should verify rules loaded)
api_url = f"{BASE_URL}/users"

# 2.1 Python Pickle
pickle_payload = {"name": "Test User", "email": "test@example.com", "age": 25, "data": "gASVIQAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlC4="}
test("Deserialization (Pickle)", api_url, "POST", pickle_payload, expected_status=403)

# 2.2 Java Serialization
java_payload = {"name": "Test User", "email": "java@example.com", "age": 30, "data": "rO0ABXNyAA1qYXZhLnV0aWwuSGFzaA=="}
test("Deserialization (Java)", api_url, "POST", java_payload, expected_status=403)

