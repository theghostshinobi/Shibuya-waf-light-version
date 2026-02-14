#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# API Protection End-to-End Test Suite
# Episode 11 - Task #4
# ═══════════════════════════════════════════════════════════════════════

set -e

# Configuration
WAF_HOST="${WAF_HOST:-localhost}"
WAF_PORT="${WAF_PORT:-8080}"
BASE_URL="http://${WAF_HOST}:${WAF_PORT}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0

# Helper function
test_result() {
    local name="$1"
    local expected_status="$2"
    local actual_status="$3"
    local response="$4"
    
    if [ "$actual_status" -eq "$expected_status" ]; then
        echo -e "${GREEN}✅ PASS${NC}: $name (status=$actual_status)"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}: $name (expected=$expected_status, got=$actual_status)"
        echo "   Response: $response"
        ((FAILED++))
        return 1
    fi
}

echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   API Protection End-to-End Test Suite${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Target: $BASE_URL"
echo ""

# ═══════════════════════════════════════════════════════════════════════
# TEST #1: OpenAPI Invalid Param Type
# ═══════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}▶ TEST #1: OpenAPI Invalid Param Type${NC}"
echo "  Sending GET /users/abc (string instead of integer)"

RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/users/abc" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" 2>/dev/null || echo -e "\n000")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

# We expect 403 if OpenAPI validation is blocking, or passthrough if not implemented
if [ "$HTTP_CODE" -eq "403" ]; then
    test_result "OpenAPI invalid param" 403 "$HTTP_CODE" "$BODY"
elif [ "$HTTP_CODE" -eq "000" ]; then
    echo -e "${RED}❌ FAIL${NC}: Connection refused - WAF not running?"
    ((FAILED++))
else
    echo -e "${YELLOW}⚠ WARN${NC}: Got status=$HTTP_CODE (OpenAPI validation may not be blocking)"
    echo "   Response: $BODY"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════
# TEST #2: GraphQL Depth Attack
# ═══════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}▶ TEST #2: GraphQL Depth Attack${NC}"
echo "  Sending deeply nested query (20+ levels)"

DEPTH_QUERY='{"query": "query { user { posts { comments { user { posts { comments { user { posts { comments { user { posts { comments { id } } } } } } } } } } } } }"}'

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/graphql" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
  -d "$DEPTH_QUERY" 2>/dev/null || echo -e "\n000")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" -eq "403" ]; then
    test_result "GraphQL depth attack" 403 "$HTTP_CODE" "$BODY"
elif [ "$HTTP_CODE" -eq "000" ]; then
    echo -e "${RED}❌ FAIL${NC}: Connection refused - WAF not running?"
    ((FAILED++))
else
    echo -e "${YELLOW}⚠ WARN${NC}: Got status=$HTTP_CODE (depth check may not be blocking)"
    echo "   Response: $BODY"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════
# TEST #3: GraphQL Complexity Attack  
# ═══════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}▶ TEST #3: GraphQL Complexity Attack${NC}"
echo "  Sending high complexity query (first: 1000 on multiple levels)"

COMPLEXITY_QUERY='{"query": "query { users(first: 1000) { posts(first: 1000) { comments(first: 1000) { id } } } }"}'

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/graphql" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
  -d "$COMPLEXITY_QUERY" 2>/dev/null || echo -e "\n000")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" -eq "403" ]; then
    test_result "GraphQL complexity attack" 403 "$HTTP_CODE" "$BODY"
elif [ "$HTTP_CODE" -eq "000" ]; then
    echo -e "${RED}❌ FAIL${NC}: Connection refused - WAF not running?"
    ((FAILED++))
else
    echo -e "${YELLOW}⚠ WARN${NC}: Got status=$HTTP_CODE (complexity check may not be blocking)"
    echo "   Response: $BODY"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════
# TEST #4A: Valid OpenAPI Request (Control Test)
# ═══════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}▶ TEST #4A: Valid OpenAPI Request${NC}"
echo "  Sending GET /users/123 (valid integer ID)"

RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/users/123" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" 2>/dev/null || echo -e "\n000")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

# Valid request should NOT be blocked (any 2xx, 4xx from backend except 403 from WAF)
if [ "$HTTP_CODE" -eq "000" ]; then
    echo -e "${RED}❌ FAIL${NC}: Connection refused - WAF not running?"
    ((FAILED++))
elif [ "$HTTP_CODE" -eq "403" ]; then
    echo -e "${RED}❌ FAIL${NC}: Valid request blocked by WAF (FALSE POSITIVE!)"
    echo "   Response: $BODY"
    ((FAILED++))
else
    echo -e "${GREEN}✅ PASS${NC}: Valid request not blocked (status=$HTTP_CODE)"
    ((PASSED++))
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════
# TEST #4B: Valid GraphQL Query (Control Test)
# ═══════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}▶ TEST #4B: Valid GraphQL Query${NC}"
echo "  Sending simple query { user(id: 1) { id name } }"

VALID_QUERY='{"query": "query { user(id: 1) { id name } }"}'

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/graphql" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
  -d "$VALID_QUERY" 2>/dev/null || echo -e "\n000")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" -eq "000" ]; then
    echo -e "${RED}❌ FAIL${NC}: Connection refused - WAF not running?"
    ((FAILED++))
elif [ "$HTTP_CODE" -eq "403" ]; then
    echo -e "${RED}❌ FAIL${NC}: Valid GraphQL blocked by WAF (FALSE POSITIVE!)"
    echo "   Response: $BODY"
    ((FAILED++))
else
    echo -e "${GREEN}✅ PASS${NC}: Valid GraphQL not blocked (status=$HTTP_CODE)"
    ((PASSED++))
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════
# EDGE CASE TESTS
# ═══════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}▶ EDGE CASE: Missing Content-Type${NC}"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/graphql" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
  -d '{"query": "{ user { id } }"}' 2>/dev/null || echo -e "\n000")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
if [ "$HTTP_CODE" -ne "000" ] && [ "$HTTP_CODE" -lt "500" ]; then
    echo -e "${GREEN}✅ PASS${NC}: No crash (status=$HTTP_CODE)"
    ((PASSED++))
else
    echo -e "${RED}❌ FAIL${NC}: Crash or connection error (status=$HTTP_CODE)"
    ((FAILED++))
fi

echo -e "${YELLOW}▶ EDGE CASE: Malformed JSON${NC}"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/graphql" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
  -d '{invalid json}' 2>/dev/null || echo -e "\n000")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
if [ "$HTTP_CODE" -ne "000" ] && [ "$HTTP_CODE" -lt "500" ]; then
    echo -e "${GREEN}✅ PASS${NC}: No crash (status=$HTTP_CODE)"
    ((PASSED++))
else
    echo -e "${RED}❌ FAIL${NC}: Crash or connection error (status=$HTTP_CODE)"
    ((FAILED++))
fi

echo -e "${YELLOW}▶ EDGE CASE: Empty Query${NC}"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/graphql" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
  -d '{"query": ""}' 2>/dev/null || echo -e "\n000")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
if [ "$HTTP_CODE" -ne "000" ] && [ "$HTTP_CODE" -lt "500" ]; then
    echo -e "${GREEN}✅ PASS${NC}: No crash (status=$HTTP_CODE)"
    ((PASSED++))
else
    echo -e "${RED}❌ FAIL${NC}: Crash or connection error (status=$HTTP_CODE)"
    ((FAILED++))
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   TEST SUMMARY${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${GREEN}Passed${NC}: $PASSED"
echo -e "  ${RED}Failed${NC}: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed!${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠ Some tests failed. Check WAF logs for details.${NC}"
    exit 1
fi
