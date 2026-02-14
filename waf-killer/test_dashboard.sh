#!/bin/bash

# Colors for output (added to fix missing definitions in prompt)
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "🎨 Dashboard Visual Tests"
echo "========================"

# Use curl to check if pages load
pages=("/" "/requests" "/analytics" "/rules" "/virtual-patches" "/shadow-api")

for page in "${pages[@]}"; do
    echo -n "Testing: $page... "
    status=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:5173$page")
    
    if [ "$status" -eq 200 ]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ (HTTP $status)${NC}"
    fi
done
