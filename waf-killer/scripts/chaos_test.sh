#!/bin/bash
# Chaos Testing - Kill dependencies and verify WAF behavior

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}🌪️  Starting Chaos Tests${NC}"
echo ""

# Start all services
echo "Starting services..."
docker-compose -f docker/docker-compose.yml up -d
sleep 10

# Test 1: Kill Redis (should fail gracefully)
echo -e "${YELLOW}Test 1: Kill Redis${NC}"
docker-compose -f docker/docker-compose.yml stop redis
sleep 2

# WAF should still accept requests
if curl -k -s https://localhost:8443/health | grep -q "ok"; then
    echo -e "${GREEN}✅ WAF survives Redis failure${NC}"
else
    echo -e "${RED}❌ WAF fails without Redis${NC}"
    exit 1
fi

# Test 2: Restart Redis
echo -e "${YELLOW}Test 2: Redis Recovery${NC}"
docker-compose -f docker/docker-compose.yml start redis
sleep 5

if curl -k -s https://localhost:8443/health | grep -q "ok"; then
    echo -e "${GREEN}✅ WAF recovers from Redis restart${NC}"
else
    echo -e "${RED}❌ WAF doesn't recover${NC}"
    exit 1
fi

# Test 3: High load + Redis down
echo -e "${YELLOW}Test 3: Load Test Under Chaos${NC}"
docker-compose -f docker/docker-compose.yml stop redis

# Generate 100 requests
for i in {1..100}; do
    curl -k -s https://localhost:8443/ > /dev/null &
done
wait

if docker logs shibuya-waf 2>&1 | grep -q "PANIC\|FATAL"; then
    echo -e "${RED}❌ WAF panicked under load${NC}"
    exit 1
else
    echo -e "${GREEN}✅ WAF stable under chaos + load${NC}"
fi

# Cleanup
docker-compose -f docker/docker-compose.yml down

echo ""
echo -e "${GREEN}🎉 Chaos Tests Passed${NC}"
