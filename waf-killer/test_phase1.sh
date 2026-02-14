#!/bin/bash
# test_phase1.sh - Attack Vector Testing

BASE_URL="http://localhost:8080"
echo "Starting Phase 1 Tests against $BASE_URL..."

# 1.1 GraphQL Protection
echo "--- Task 1.1: GraphQL Protection ---"
echo "1.1a: Normal GraphQL Query (Should PASS)"
curl -s -o /dev/null -w "%{http_code}" -X POST $BASE_URL/api/graphql \
  -H "Content-Type: application/json" \
  -d '{ "query": "{ user(id: 1) { id name email } }" }' | grep 200 && echo "✅ PASS" || echo "❌ FAIL"

echo "1.1b: Alias Bombing Attack (Should BLOCK)"
# 60 aliases
ALIAS_QUERY="{ a1:user{name} a2:user{name} a3:user{name} a4:user{name} a5:user{name} a6:user{name} a7:user{name} a8:user{name} a9:user{name} a10:user{name} a11:user{name} a12:user{name} a13:user{name} a14:user{name} a15:user{name} a16:user{name} a17:user{name} a18:user{name} a19:user{name} a20:user{name} a21:user{name} a22:user{name} a23:user{name} a24:user{name} a25:user{name} a26:user{name} a27:user{name} a28:user{name} a29:user{name} a30:user{name} a31:user{name} a32:user{name} a33:user{name} a34:user{name} a35:user{name} a36:user{name} a37:user{name} a38:user{name} a39:user{name} a40:user{name} a41:user{name} a42:user{name} a43:user{name} a44:user{name} a45:user{name} a46:user{name} a47:user{name} a48:user{name} a49:user{name} a50:user{name} a51:user{name} a52:user{name} a53:user{name} a54:user{name} a55:user{name} a56:user{name} a57:user{name} a58:user{name} a59:user{name} a60:user{name} }"
curl -s -o /dev/null -w "%{http_code}" -X POST $BASE_URL/api/graphql \
  -H "Content-Type: application/json" \
  -d "{\"query\": \"$ALIAS_QUERY\"}" | grep 429 && echo "✅ PASS" || echo "❌ FAIL"

echo "1.1c: Batch Query Attack (Should BLOCK)"
BATCH_QUERY='[{"query":"{user{name}}"},{"query":"{user{name}}"},{"query":"{user{name}}"},{"query":"{user{name}}"},{"query":"{user{name}}"},{"query":"{user{name}}"},{"query":"{user{name}}"},{"query":"{user{name}}"},{"query":"{user{name}}"},{"query":"{user{name}}"},{"query":"{user{name}}"},{"query":"{user{name}}"},{"query":"{user{name}}"},{"query":"{user{name}}"},{"query":"{user{name}}"}]'
curl -s -o /dev/null -w "%{http_code}" -X POST $BASE_URL/api/graphql \
  -H "Content-Type: application/json" \
  -d "$BATCH_QUERY" | grep 429 && echo "✅ PASS" || echo "❌ FAIL"

echo "1.1d: Deep Nesting Attack (Should BLOCK)"
NESTED_QUERY='{ "query": "{ user { friends { friends { friends { friends { friends { friends { friends { friends { friends { friends { friends { name } } } } } } } } } } } }" }'
curl -s -o /dev/null -w "%{http_code}" -X POST $BASE_URL/api/graphql \
  -H "Content-Type: application/json" \
  -d "$NESTED_QUERY" | grep 429 && echo "✅ PASS" || echo "❌ FAIL"


# 1.2 Deserialization Protection
echo "--- Task 1.2: Deserialization Protection ---"
echo "1.2a: Normal JSON Data (Should PASS)"
curl -s -o /dev/null -w "%{http_code}" -X POST $BASE_URL/api/data \
  -H "Content-Type: application/json" \
  -d '{ "data": "Hello world" }' | grep 200 && echo "✅ PASS" || echo "❌ FAIL"

echo "1.2b: Python Pickle Attack (Should BLOCK)"
curl -s -o /dev/null -w "%{http_code}" -X POST $BASE_URL/api/data \
  -H "Content-Type: application/json" \
  -d '{ "data": "gASVIQAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwHb3MucG9wZW6UhZRSlC4=" }' | grep 403 && echo "✅ PASS" || echo "❌ FAIL"

echo "1.2c: Java Serialization Attack (Should BLOCK)"
curl -s -o /dev/null -w "%{http_code}" -X POST $BASE_URL/api/data \
  -H "Content-Type: application/json" \
  -d '{ "data": "rO0ABXNyAA1qYXZhLnV0aWwuSGFzaE1hcAU=" }' | grep 403 && echo "✅ PASS" || echo "❌ FAIL"

echo "1.2d: PHP Serialization Attack (Should BLOCK)"
curl -s -o /dev/null -w "%{http_code}" -X POST $BASE_URL/api/data \
  -H "Content-Type: application/json" \
  -d '{ "data": "O:8:\"stdClass\":1:{s:4:\"test\";s:5:\"value\";}" }' | grep 403 && echo "✅ PASS" || echo "❌ FAIL"


# 1.3 SQLi Protection
echo "--- Task 1.3: SQLi Protection ---"
echo "1.3a: Normal Search Query (Should PASS)"
curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/search?q=laptop" | grep 200 && echo "✅ PASS" || echo "❌ FAIL"

echo "1.3b: Comment-Based SQLi (Should BLOCK)"
curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/search?q=1'/**/OR/**/1=1--" | grep 403 && echo "✅ PASS" || echo "❌ FAIL"

echo "1.3c: MySQL Conditional Comment SQLi (Should BLOCK)"
curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/search?q=1'/*!50000OR*/1=1--" | grep 403 && echo "✅ PASS" || echo "❌ FAIL"

echo "1.3d: URL-Encoded SQLi (Should BLOCK)"
curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/search?q=%27%20OR%201%3D1--" | grep 403 && echo "✅ PASS" || echo "❌ FAIL"


# 1.4 Recon Protection
echo "--- Task 1.4: Recon Protection ---"
echo "1.4a: Normal API Call (Should PASS)"
curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/users" | grep 200 && echo "✅ PASS" || echo "❌ FAIL"

echo "1.4b: API Documentation Access (Should BLOCK)"
curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/swagger.json" | grep 403 && echo "✅ PASS" || echo "❌ FAIL"

echo "1.4c: Environment File Access (Should BLOCK)"
curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/.env" | grep 403 && echo "✅ PASS" || echo "❌ FAIL"

echo "1.4d: Git Config Access (Should BLOCK)"
curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/.git/config" | grep 403 && echo "✅ PASS" || echo "❌ FAIL"

echo "Phase 1 Complete."
