#!/bin/bash
# Verify WAF Wiring

BASE_URL="http://localhost:9090"

echo "🔍 Verifying WAF API Wiring..."

# 1. Check Timeseries
echo "1️⃣  Checking /analytics/timeseries..."
response=$(curl -s "$BASE_URL/analytics/timeseries")
if [[ $response == "[]" ]]; then
    echo "⚠️  Timeseries empty (Expected if just started, but endpoint works)"
elif [[ $response == *"timestamp"* ]]; then
    echo "✅ Timeseries returns data structure"
else
    echo "❌ Timeseries FAILED: $response"
fi

# 2. Check Rules PUT
echo "2️⃣  Checking Rules PUT..."
# We try to update rule 942100 (SQLi) - just toggling enabled
curl -X PUT "$BASE_URL/rules/942100" -H "Content-Type: application/json" -d '{"enabled": true}' -s > /dev/null
status=$?
if [ $status -eq 0 ]; then
   echo "✅ Rules PUT request sent (Check logs for 200 OK)"
else
   echo "❌ Rules PUT FAILED"
fi

# 3. Check Threat Intel Local
echo "3️⃣  Checking Threat Intel Lookup..."
lookup=$(curl -s "$BASE_URL/threat/lookup?ip=1.1.1.1")
echo "   Output: $lookup"
