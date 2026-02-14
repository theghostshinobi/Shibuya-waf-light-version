#!/usr/bin/env bash
# =====================================================================
#  Shibuya WAF Stress Test — Launcher
# =====================================================================
#  Starts the vulnerable app, then runs the 30-attack suite.
#  WAF and Dashboard should be started separately.
# =====================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       🏯  SHIBUYA WAF — STRESS TEST LAUNCHER  🏯           ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 1. Start vulnerable app
echo -e "${YELLOW}▸ Starting vulnerable target app on :3000...${NC}"
node "${SCRIPT_DIR}/vulnerable_app.js" &
VULN_PID=$!
sleep 1

# Check it started
if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health 2>/dev/null | grep -q "200"; then
    echo -e "${GREEN}✓ Vulnerable app running (PID: ${VULN_PID})${NC}"
else
    echo -e "${RED}✗ Vulnerable app failed to start${NC}"
    exit 1
fi

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Make sure these are running before pressing Enter:${NC}"
echo ""
echo -e "  ${YELLOW}1.${NC} WAF:        ${BOLD}cd ${PROJECT_DIR}/core && RUST_LOG=info WAF_GOD_MODE_KEY=god cargo run${NC}"
echo -e "  ${YELLOW}2.${NC} Dashboard:  ${BOLD}cd ${PROJECT_DIR}/dashboard && npm run dev${NC}"
echo -e ""
echo -e "  Open dashboard at: ${CYAN}http://localhost:5173${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
read -p "Press Enter when WAF is running to start the attack... "

echo ""
echo -e "${YELLOW}▸ Launching 30-attack suite...${NC}"
echo ""

bash "${SCRIPT_DIR}/attack_30.sh"

# Cleanup
echo -e "${YELLOW}▸ Cleaning up...${NC}"
kill $VULN_PID 2>/dev/null || true
echo -e "${GREEN}✓ Vulnerable app stopped${NC}"
echo ""
echo -e "${BOLD}Done! Check the dashboard for live results.${NC}"
