#!/bin/bash
# Validate Vulnerability Manager Flow

echo "🔍 1. checking Initial Vulnerabilities (Should be empty)"
curl -s http://localhost:9090/api/vulnerabilities | python3 -m json.tool

echo -e "\n📡 2. Starting Scan..."
curl -X POST -s http://localhost:9090/api/vulnerabilities/scan | python3 -m json.tool

echo "⏳ Sleeping 4 seconds to allow scan to complete..."
sleep 4

echo "🔍 3. Checking Vulnerabilities (Should have items)"
RESULT=$(curl -s http://localhost:9090/api/vulnerabilities)
echo $RESULT | python3 -m json.tool

COUNT=$(echo $RESULT | grep -o "\"id\":" | wc -l)
echo "Found $COUNT vulnerabilities."

if [ "$COUNT" -gt 0 ]; then
    echo "✅ Success: Vulnerabilities detected and stored."
else
    echo "❌ Failure: No vulnerabilities found after scan."
    exit 1
fi
