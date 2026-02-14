#!/bin/bash
# test_phase2.sh - False Positive Testing

BASE_URL="http://localhost:8080"
echo "Starting Phase 2 Tests..."

echo "2.1a: Search with SQL Keywords"
curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/search?q=SELECT+laptop" | grep 200 && echo "✅ PASS (SELECT laptop)" || echo "❌ FAIL (SELECT laptop blocked)"
curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/search?q=database+OR+application" | grep 200 && echo "✅ PASS (database OR application)" || echo "❌ FAIL (database OR application blocked)"
curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/search?q=UNION+dataset" | grep 200 && echo "✅ PASS (UNION dataset)" || echo "❌ FAIL (UNION dataset blocked)"

echo "2.1b: Form Submissions with Special Characters"
curl -s -o /dev/null -w "%{http_code}" -X POST $BASE_URL/api/data \
  -H "Content-Type: application/json" \
  -d '{ "name": "John Doe", "email": "john.script@example.com", "message": "I need help with my account" }' | grep 200 && echo "✅ PASS (email with script)" || echo "❌ FAIL (email with script blocked)"

curl -s -o /dev/null -w "%{http_code}" -X POST $BASE_URL/api/data \
  -H "Content-Type: application/json" \
  -d '{ "name": "Jane Smith", "email": "jane@example.com", "message": "The price is <$100, can you help?" }' | grep 200 && echo "✅ PASS (message with <)" || echo "❌ FAIL (message with < blocked)"

echo "Phase 2 Complete."
