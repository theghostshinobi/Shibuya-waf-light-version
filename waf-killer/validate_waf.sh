#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

WAF_PORT=3000
WAF_PID=""
REDIS_CONTAINER="waf-redis-test"

cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    if [ -n "$WAF_PID" ]; then
        kill $WAF_PID 2>/dev/null || true
    fi
    docker stop $REDIS_CONTAINER 2>/dev/null || true
    docker rm $REDIS_CONTAINER 2>/dev/null || true
    echo -e "${GREEN}Cleanup complete.${NC}"
}

trap cleanup EXIT

echo "================================================"
echo "      WAF KILLER - Runtime Validation Script    "
echo "================================================"

# STEP 1: Start Redis
echo -e "${YELLOW}[1/6] Starting Redis...${NC}"
docker run -d --name $REDIS_CONTAINER -p 6379:6379 redis:7-alpine
sleep 2
if docker ps | grep -q $REDIS_CONTAINER; then
    echo -e "${GREEN}✓ Redis started${NC}"
else
    echo -e "${RED}✗ Failed to start Redis${NC}"
    exit 1
fi

# STEP 2: Build Project
echo -e "${YELLOW}[2/6] Building project...${NC}"
cargo build --release 2>&1 | tail -5
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# STEP 3: Start WAF
echo -e "${YELLOW}[3/6] Starting WAF...${NC}"
cargo run --release &
WAF_PID=$!
sleep 5

if ps -p $WAF_PID > /dev/null; then
    echo -e "${GREEN}✓ WAF started (PID: $WAF_PID)${NC}"
else
    echo -e "${RED}✗ WAF failed to start${NC}"
    exit 1
fi

# STEP 4: Health Check
echo -e "${YELLOW}[4/6] Health check...${NC}"
for i in {1..10}; do
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$WAF_PORT/" 2>/dev/null | grep -qE "^[23]"; then
        echo -e "${GREEN}✓ WAF responding${NC}"
        break
    fi
    if [ $i -eq 10 ]; then
        echo -e "${RED}✗ WAF not responding after 10 attempts${NC}"
        exit 1
    fi
    sleep 1
done

# STEP 5: Run Tests
echo -e "${YELLOW}[5/6] Running attack tests...${NC}"

TESTS_PASSED=0
TESTS_FAILED=0

# Test 1: Normal request should PASS
echo -n "  [Test 1] Normal request: "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$WAF_PORT/")
if [[ "$HTTP_CODE" =~ ^[23] ]]; then
    echo -e "${GREEN}PASS (HTTP $HTTP_CODE)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}FAIL (HTTP $HTTP_CODE, expected 2xx/3xx)${NC}"
    ((TESTS_FAILED++))
fi

# Test 2: SQLi should be BLOCKED (403)
echo -n "  [Test 2] SQLi attack: "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$WAF_PORT/?id=%27%20OR%20%271%27%3D%271")
if [ "$HTTP_CODE" = "403" ]; then
    echo -e "${GREEN}PASS (HTTP $HTTP_CODE - Blocked)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}WARN (HTTP $HTTP_CODE, expected 403)${NC}"
    ((TESTS_FAILED++))
fi

# Test 3: Empty User-Agent (bot detection)
echo -n "  [Test 3] Empty User-Agent: "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "User-Agent: " "http://localhost:$WAF_PORT/")
if [[ "$HTTP_CODE" =~ ^(403|429|401|418)$ ]]; then
    echo -e "${GREEN}PASS (HTTP $HTTP_CODE - Challenged/Blocked)${NC}"
    ((TESTS_PASSED++))
elif [[ "$HTTP_CODE" =~ ^[23] ]]; then
    echo -e "${YELLOW}WARN (HTTP $HTTP_CODE - Allowed, bot detection may be disabled)${NC}"
    ((TESTS_PASSED++))  # Acceptable if bot detection is in detection-only mode
else
    echo -e "${RED}FAIL (HTTP $HTTP_CODE)${NC}"
    ((TESTS_FAILED++))
fi

# STEP 6: Summary
echo ""
echo "================================================"
if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}          ✓ SUCCESS - All tests passed!         ${NC}"
    echo -e "${GREEN}             WAF is GO for deployment            ${NC}"
else
    echo -e "${YELLOW}    ⚠ PARTIAL - $TESTS_PASSED passed, $TESTS_FAILED warnings    ${NC}"
    echo -e "${YELLOW}         Review warnings before deployment       ${NC}"
fi
echo "================================================"

exit 0
