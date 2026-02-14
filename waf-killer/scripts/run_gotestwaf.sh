#!/bin/bash
# GoTestWAF - Automated WAF Testing for Shibuya

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
WAF_URL="${WAF_URL:-https://localhost:8443}"
REPORT_DIR="tests/gotestwaf/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_NAME="shibuya_${TIMESTAMP}"

# Detection thresholds
MIN_DETECTION_RATE=80
TARGET_DETECTION_RATE=90

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           GoTestWAF - Shibuya WAF Testing                ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Target WAF: ${WAF_URL}"
echo "Report: ${REPORT_DIR}/${REPORT_NAME}"
echo ""

# Check if WAF is running
echo -e "${YELLOW}🔍 Checking WAF availability...${NC}"
if ! curl -k -s -o /dev/null -w "%{http_code}" "${WAF_URL}/health" | grep -q "200\|404"; then
    echo -e "${RED}❌ WAF is not responding at ${WAF_URL}${NC}"
    echo "   Start WAF with: cargo run --release"
    exit 1
fi
echo -e "${GREEN}✅ WAF is running${NC}"
echo ""

# Create report directory
mkdir -p "${REPORT_DIR}"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker not found${NC}"
    echo "   Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Pull latest GoTestWAF image
echo -e "${YELLOW}📦 Pulling GoTestWAF image...${NC}"
docker pull wallarm/gotestwaf:latest

echo ""
echo -e "${GREEN}🚀 Starting GoTestWAF scan...${NC}"
echo ""

# Run GoTestWAF
docker run --rm \
    --network=host \
    -v "$(pwd)/${REPORT_DIR}:/app/reports" \
    wallarm/gotestwaf:latest \
    --url="${WAF_URL}" \
    --blockStatusCode=403 \
    --blockRegex="blocked|forbidden|denied" \
    --passStatusCode=200 \
    --reportPath="/app/reports" \
    --reportName="${REPORT_NAME}" \
    --reportFormat=json,html \
    --workers=10 \
    --followCookies \
    --maxRedirects=5 \
    --skipWAFIdentification \
    --testCase=owasp \
    --verbose

EXIT_CODE=$?

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Parse results
if [ -f "${REPORT_DIR}/${REPORT_NAME}.json" ]; then
    echo -e "${GREEN}📊 Test Results:${NC}"
    echo ""
    
    # Extract metrics using jq (if available)
    if command -v jq &> /dev/null; then
        DETECTION_RATE=$(jq -r '.summary.detection_rate // 0' "${REPORT_DIR}/${REPORT_NAME}.json")
        BLOCKED=$(jq -r '.summary.blocked // 0' "${REPORT_DIR}/${REPORT_NAME}.json")
        BYPASSED=$(jq -r '.summary.bypassed // 0' "${REPORT_DIR}/${REPORT_NAME}.json")
        UNRESOLVED=$(jq -r '.summary.unresolved // 0' "${REPORT_DIR}/${REPORT_NAME}.json")
        TOTAL=$(jq -r '.summary.total // 0' "${REPORT_DIR}/${REPORT_NAME}.json")
        
        echo "   Total Tests:     ${TOTAL}"
        echo "   Blocked:         ${BLOCKED}"
        echo "   Bypassed:        ${BYPASSED}"
        echo "   Unresolved:      ${UNRESOLVED}"
        echo ""
        
        # Detection rate with color and emoji
        if (( $(echo "${DETECTION_RATE} >= ${TARGET_DETECTION_RATE}" | bc -l) )); then
            echo -e "   Detection Rate:  ${GREEN}${DETECTION_RATE}%${NC} 🎉 EXCELLENT"
        elif (( $(echo "${DETECTION_RATE} >= ${MIN_DETECTION_RATE}" | bc -l) )); then
            echo -e "   Detection Rate:  ${GREEN}${DETECTION_RATE}%${NC} ✅ GOOD"
        elif (( $(echo "${DETECTION_RATE} >= 70" | bc -l) )); then
            echo -e "   Detection Rate:  ${YELLOW}${DETECTION_RATE}%${NC} ⚠️  ACCEPTABLE"
        else
            echo -e "   Detection Rate:  ${RED}${DETECTION_RATE}%${NC} ❌ NEEDS IMPROVEMENT"
        fi
        
        echo ""
        echo -e "${BLUE}📈 Detection by Category:${NC}"
        echo ""
        
        # Per-category results
        jq -r '.categories[] | "   \(.name | . + ":" | ljust(30)) \(.detection_rate)% (\(.blocked)/\(.total))"' \
            "${REPORT_DIR}/${REPORT_NAME}.json" 2>/dev/null || true
        
        echo ""
        echo -e "${BLUE}📄 Reports:${NC}"
        echo "   JSON:  ${REPORT_DIR}/${REPORT_NAME}.json"
        echo "   HTML:  ${REPORT_DIR}/${REPORT_NAME}.html"
        echo ""
        echo "   View report: open ${REPORT_DIR}/${REPORT_NAME}.html"
        
        # Save as latest
        cp "${REPORT_DIR}/${REPORT_NAME}.json" "${REPORT_DIR}/latest.json"
        
        # Exit code based on detection rate
        if (( $(echo "${DETECTION_RATE} < ${MIN_DETECTION_RATE}" | bc -l) )); then
            echo ""
            echo -e "${RED}⚠️  Detection rate ${DETECTION_RATE}% is below minimum ${MIN_DETECTION_RATE}%${NC}"
            exit 1
        fi
        
    else
        echo "   Install 'jq' for detailed metrics:"
        echo "   brew install jq  # macOS"
        echo "   apt-get install jq  # Ubuntu"
    fi
else
    echo -e "${RED}❌ Report file not found${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ GoTestWAF scan complete${NC}"
echo ""

exit 0
