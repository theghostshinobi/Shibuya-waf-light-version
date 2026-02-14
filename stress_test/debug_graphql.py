import urllib.request
import json
import time

url = "http://localhost:8095/graphql"
# 51 aliases
aliases = " ".join([f"a{i}: user {{ name }}" for i in range(51)])
query = f"{{ {aliases} }}"
payload = {"query": query}
data = json.dumps(payload).encode('utf-8')

req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})

print(f"Sending {len(data)} bytes...")
try:
    with urllib.request.urlopen(req) as f:
        print(f"Status: {f.status}")
        print(f"Body: {f.read().decode('utf-8')[:100]}")
except urllib.error.HTTPError as e:
    print(f"Status: {e.code}")
    print(f"Body: {e.read().decode('utf-8')[:100]}")
except Exception as e:
    print(f"Error: {e}")
