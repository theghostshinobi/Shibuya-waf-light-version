#!/bin/bash

# Configuration
API_URL="http://localhost:9090"
PROXY_URL="http://localhost:8080" # Assuming 8080 is proxy port

echo "Testing Traffic Replay Integration..."

# 1. Generate some traffic to capture
echo "1. Generating traffic..."
curl -s -o /dev/null "$PROXY_URL/test?foo=bar"
curl -s -o /dev/null -X POST -d "user=admin" "$PROXY_URL/login"

# Wait for capture to be processed (async)
sleep 2

# 2. Define a Shadow Policy
POLICY='SecRule ARGS:foo "@streq bar" "id:1001,phase:1,deny,status:403,msg:Test Rule"'

# 3. Call Replay API
echo "2. Calling Replay API..."
RESPONSE=$(curl -s -X POST "$API_URL/replay" \
  -H "Content-Type: application/json" \
  -d "{
    \"policy\": \"$(echo $POLICY | sed 's/"/\\"/g')\",
    \"from\": 0,
    \"to\": 0
  }")

# 4. Analyze Result
echo "Response: $Response"

if echo "$RESPONSE" | grep -q "total_requests"; then
    echo "✅ Replay API returned valid response."
    TOTAL=$(echo "$RESPONSE" | jq '.total_requests')
    echo "   Total Requests Replayed: $TOTAL"
    if [ "$TOTAL" -gt 0 ]; then
        echo "   ✅ Traffic was found and replayed."
    else
        echo "   ⚠️  No traffic found in time range (expected if DB empty)."
    fi
else
    echo "❌ Replay API failed or returned unexpected response."
    echo "$RESPONSE"
    exit 1
fi
