#!/bin/bash
# validate_analytics.sh

echo "🔍 Validating Analytics API Wiring..."

# URL of Admin API
API_URL="http://localhost:9090/analytics/timeseries"
PROXY_URL="http://localhost:8080"

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "jq could not be found, please install it to run this script"
    exit 1
fi

# Function to get last request count
get_last_req() {
    curl -s $API_URL | jq '.[-1].total_requests // 0'
}

# 1. Baseline
echo "----------------------------------------"
echo "1. Fetching baseline history..."
count1=$(get_last_req)
echo "Baseline Total Requests: $count1"

# 2. Generate Traffic
echo "----------------------------------------"
echo "2. Generating 10 requests to WAF..."
for i in {1..10}; do
    # Use max-time 1s to avoid hanging on Keep-Alive without Content-Length
    curl -s -m 0.5 -o /dev/null "$PROXY_URL/" || true 
done
echo "Requests sent."

# Wait for 2 snapshots (2 seconds) to ensure capture
echo "Waiting for backend snapshot (3s)..."
sleep 3

# 3. Verify
echo "----------------------------------------"
echo "3. Fetching updated history..."
count2=$(get_last_req)
echo "New Total Requests: $count2"

diff=$((count2 - count1))

echo "----------------------------------------"
if [ "$diff" -ge 10 ]; then
    echo "✅ SUCCESS: WAF captured $diff new requests in TimeSeries!"
else
    echo "❌ FAILURE: Expected at least 10 new requests, got $diff."
    echo "Note: Ensure WAF is running!"
fi
echo "----------------------------------------"
