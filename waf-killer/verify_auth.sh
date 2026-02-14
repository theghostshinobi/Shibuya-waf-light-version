#!/bin/bash

BASE_URL="http://127.0.0.1:8080"
TOKEN="secret123"

echo "🧪 Starting Admin API Auth Verification"

# 1. Test without token (Should Fail)
echo "1️⃣  Testing without token..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/stats")
if [ "$HTTP_CODE" == "401" ]; then
    echo "✅ Success: Got 401 as expected"
else
    echo "❌ Failed: Expected 401, got $HTTP_CODE"
fi

# 2. Test with invalid token (Should Fail)
echo "2️⃣  Testing with invalid token..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Admin-Token: wrong" "$BASE_URL/stats")
if [ "$HTTP_CODE" == "401" ]; then
    echo "✅ Success: Got 401 as expected"
else
    echo "❌ Failed: Expected 401, got $HTTP_CODE"
fi

# 3. Test with correct token (Should Succeed)
# Note: This requires the WAF to be running with WAF_ADMIN_TOKEN=secret123
echo "3️⃣  Testing with correct token..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Admin-Token: $TOKEN" "$BASE_URL/stats")
if [ "$HTTP_CODE" == "200" ]; then
    echo "✅ Success: Got 200 as expected"
else
    echo "❌ Failed: Expected 200, got $HTTP_CODE"
    # echo "   Ensure you ran the WAF with WAF_ADMIN_TOKEN=$TOKEN"
fi

echo "🏁 Verification Complete"
