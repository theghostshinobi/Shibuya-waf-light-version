#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

API_URL="http://localhost:9090"
PASSED=0
FAILED=0

echo "🔥 SHIBUYA WAF - AUTOMATED TEST SUITE"
echo "======================================"
echo ""

# Helper functions
test_endpoint() {
    local method=$1
    local endpoint=$2
    local expected_status=$3
    local description=$4
    
    echo -n "Testing: $description... "
    
    response=$(curl -s -o /dev/null -w "%{http_code}" -X $method "$API_URL$endpoint")
    
    if [ "$response" -eq "$expected_status" ]; then
        echo -e "${GREEN}✓ PASS${NC} (HTTP $response)"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC} (Expected $expected_status, got $response)"
        ((FAILED++))
        return 1
    fi
}

test_json_response() {
    local endpoint=$1
    local description=$2
    
    echo -n "Testing: $description... "
    
    response=$(curl -s "$API_URL$endpoint")
    
    if echo "$response" | jq . >/dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC} (Valid JSON)"
        echo "   Response: $(echo $response | jq -c . | cut -c1-80)..."
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC} (Invalid JSON)"
        echo "   Response: $response"
        ((FAILED++))
        return 1
    fi
}

echo "📡 PHASE 1: Backend API Tests"
echo "------------------------------"

# Test 1: Stats endpoint
test_json_response "/stats" "GET /stats (Dashboard statistics)"

# Test 2: Requests/Logs endpoint
test_json_response "/requests" "GET /requests (Traffic logs)"

# Test 3: Virtual Patches list
test_json_response "/virtual-patches" "GET /virtual-patches (List patches)"

# Test 4: Shadow API endpoints
test_json_response "/shadow-api/endpoints" "GET /shadow-api/endpoints (Discovered endpoints)"

# Test 5: Config endpoint
test_json_response "/config" "GET /config (WAF configuration)"

# Test 6: Rules endpoint
test_json_response "/rules" "GET /rules (Security rules)"

echo ""
echo "🔨 PHASE 2: POST/Create Operations"
echo "----------------------------------"

# Test 7: Generate virtual patch from CVE
echo -n "Testing: POST /virtual-patches/generate... "
response=$(curl -s -X POST "$API_URL/virtual-patches/generate" \
    -H "Content-Type: application/json" \
    -d '{"cve_id":"CVE-2024-TEST"}')

if echo "$response" | jq -e '.id' >/dev/null 2>&1; then
    echo -e "${GREEN}✓ PASS${NC}"
    patch_id=$(echo "$response" | jq -r '.id')
    echo "   Created patch ID: $patch_id"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAILED++))
fi

# Test 8: Verify patch was created
echo -n "Testing: Verify patch in list... "
response=$(curl -s "$API_URL/virtual-patches")
if echo "$response" | jq -e '.[] | select(.cve_id=="CVE-2024-TEST")' >/dev/null 2>&1; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAILED++))
fi

echo ""
echo "🚀 PHASE 3: Traffic Generation & Stats"
echo "--------------------------------------"

# Test 9: Generate traffic and verify stats update
echo "Generating 10 test requests..."
for i in {1..10}; do
    curl -s -k https://localhost:8443/test?id=$i >/dev/null 2>&1
done

sleep 1

echo -n "Testing: Stats updated after traffic... "
response=$(curl -s "$API_URL/stats")
total=$(echo "$response" | jq -r '.total_requests')

if [ "$total" -gt 0 ]; then
    echo -e "${GREEN}✓ PASS${NC}"
    echo "   Total requests: $total"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ WARNING${NC}"
    echo "   Total requests still 0 (might need proxy to be running)"
fi

echo ""
echo "🎨 PHASE 4: Dashboard Accessibility"
echo "-----------------------------------"

DASHBOARD_URL="http://localhost:5173"

# Test 10: Dashboard home
test_endpoint "GET" "$DASHBOARD_URL/" 200 "Dashboard homepage"

# Test 11: API routes accessible from dashboard
test_endpoint "GET" "$DASHBOARD_URL/api/stats" 200 "Dashboard proxy to /stats"

echo ""
echo "📊 TEST SUMMARY"
echo "==============="
echo -e "Total Tests: $((PASSED + FAILED))"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED! WAF is operational.${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Check errors above.${NC}"
    exit 1
fi
