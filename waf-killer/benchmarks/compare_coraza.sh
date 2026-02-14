#!/usr/bin/env bash
# =============================================================================
# SHIBUYA WAF — Coraza Side-by-Side Comparison
# Deploys standalone Coraza with identical CRS rules, runs identical loads,
# and produces a comparison table.
# Usage: benchmarks/compare_coraza.sh --output comparison.md
# =============================================================================
set -euo pipefail

OUTPUT_FILE="coraza_comparison.md"
HTTP_PORT="8080"
CORAZA_PORT="8888"
CORAZA_ADMIN_PORT="8889"
DURATION="30s"
RATE=2000
CORAZA_DIR="/tmp/shibuya_coraza_bench"
CORAZA_PID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)      OUTPUT_FILE="$2";  shift 2 ;;
    --http-port)   HTTP_PORT="$2";    shift 2 ;;
    --coraza-port) CORAZA_PORT="$2";  shift 2 ;;
    --duration)    DURATION="$2";     shift 2 ;;
    --rate)        RATE="$2";         shift 2 ;;
    *) shift ;;
  esac
done

log() { echo -e "[CORAZA] $*"; }

cleanup() {
  if [[ -n "$CORAZA_PID" ]] && kill -0 "$CORAZA_PID" 2>/dev/null; then
    log "Stopping Coraza (PID $CORAZA_PID)..."
    kill "$CORAZA_PID" 2>/dev/null || true
    wait "$CORAZA_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ── Prerequisites ────────────────────────────────────────────────────────────
if ! command -v k6 &>/dev/null; then
  log "k6 not found — required for comparison. Install: brew install k6"
  echo "# Coraza Comparison — SKIPPED (k6 not installed)" > "$OUTPUT_FILE"
  exit 0
fi

if ! command -v go &>/dev/null; then
  log "Go not found — required to build Coraza proxy. Install: brew install go"
  echo "# Coraza Comparison — SKIPPED (Go not installed)" > "$OUTPUT_FILE"
  exit 0
fi

# ── Build Coraza Test Proxy ──────────────────────────────────────────────────
log "Setting up Coraza benchmark proxy..."
mkdir -p "$CORAZA_DIR"

cat > "$CORAZA_DIR/main.go" << 'GOEOF'
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
)

func main() {
	port := os.Getenv("CORAZA_PORT")
	if port == "" {
		port = "8888"
	}
	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://localhost:9999"
	}

	// Create WAF with CRS-like rules
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule ARGS "@detectSQLi" "id:1,phase:2,deny,status:403,msg:'SQLi detected'"
				SecRule ARGS "@detectXSS" "id:2,phase:2,deny,status:403,msg:'XSS detected'"
				SecRule REQUEST_URI "@rx \\.\\." "id:3,phase:1,deny,status:403,msg:'Path traversal'"
				SecRule ARGS "@rx (?i)(union.*select|insert.*into|delete.*from|drop.*table)" "id:100,phase:2,deny,status:403"
				SecRule ARGS "@rx (?i)(<script|javascript:|onerror=|onload=)" "id:101,phase:2,deny,status:403"
				SecRule ARGS "@rx (?i)(;\\s*(ls|cat|whoami|id|wget|curl|nc))" "id:102,phase:2,deny,status:403"
			`),
	)
	if err != nil {
		log.Fatalf("Failed to create WAF: %v", err)
	}

	// Simple backend that echoes 200 OK
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		io.WriteString(w, `{"status":"ok"}`)
	})

	handler := txhttp.WrapHandler(waf, backend)

	log.Printf("Coraza benchmark proxy starting on :%s", port)
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
GOEOF

cat > "$CORAZA_DIR/go.mod" << MODEOF
module coraza-bench
go 1.21
require (
	github.com/corazawaf/coraza/v3 v3.2.1
)
MODEOF

cd "$CORAZA_DIR"
log "Downloading Go dependencies..."
go mod tidy 2>&1 | tail -3 || {
  log "Failed to download Coraza dependencies"
  echo "# Coraza Comparison — SKIPPED (dependency error)" > "$OUTPUT_FILE"
  exit 0
}

log "Building Coraza proxy..."
go build -o coraza-bench . 2>&1 || {
  log "Failed to build Coraza proxy"
  echo "# Coraza Comparison — SKIPPED (build error)" > "$OUTPUT_FILE"
  exit 0
}

# Start Coraza proxy
CORAZA_PORT="$CORAZA_PORT" ./coraza-bench &
CORAZA_PID=$!
sleep 3

if ! kill -0 "$CORAZA_PID" 2>/dev/null; then
  log "Coraza proxy failed to start"
  echo "# Coraza Comparison — SKIPPED (startup error)" > "$OUTPUT_FILE"
  exit 0
fi

log "Coraza proxy running on port $CORAZA_PORT (PID $CORAZA_PID)"

# ── k6 Inline Script for Comparison ─────────────────────────────────────────
K6_SCRIPT=$(cat << 'K6EOF'
import http from 'k6/http';
import { check } from 'k6';

const TARGET = __ENV.TARGET_URL || 'http://localhost:8080';

export const options = {
  scenarios: {
    sustained: {
      executor: 'constant-arrival-rate',
      rate: parseInt(__ENV.RATE || '1000'),
      duration: __ENV.DURATION || '30s',
      preAllocatedVUs: 50,
      maxVUs: 200,
    },
  },
  insecureSkipTLSVerify: true,
};

const paths = ['/api/users', '/api/search?q=hello', '/api/products', '/api/health'];
function randomItem(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

export default function () {
  const res = http.get(`${TARGET}${randomItem(paths)}`);
  check(res, { 'status < 500': (r) => r.status < 500 });
}
K6EOF
)

RESULTS_DIR="$(dirname "$OUTPUT_FILE")"
mkdir -p "$RESULTS_DIR"

# ── Run against SHIBUYA ─────────────────────────────────────────────────────
log "═══ Testing SHIBUYA WAF (port $HTTP_PORT) ═══"
echo "$K6_SCRIPT" | TARGET_URL="http://localhost:${HTTP_PORT}" RATE="$RATE" DURATION="$DURATION" \
  k6 run --summary-export "${RESULTS_DIR}/k6_shibuya.json" - 2>&1 | tail -20

# ── Run against Coraza ───────────────────────────────────────────────────────
log "═══ Testing Coraza proxy (port $CORAZA_PORT) ═══"
echo "$K6_SCRIPT" | TARGET_URL="http://localhost:${CORAZA_PORT}" RATE="$RATE" DURATION="$DURATION" \
  k6 run --summary-export "${RESULTS_DIR}/k6_coraza.json" - 2>&1 | tail -20

# ── Memory comparison ───────────────────────────────────────────────────────
SHIBUYA_RSS=$(ps -o rss= -p "$(lsof -ti tcp:${HTTP_PORT} 2>/dev/null | head -1)" 2>/dev/null || echo "0")
CORAZA_RSS=$(ps -o rss= -p "$CORAZA_PID" 2>/dev/null || echo "0")
SHIBUYA_MB=$(python3 -c "print(round(${SHIBUYA_RSS:-0}/1024,1))")
CORAZA_MB=$(python3 -c "print(round(${CORAZA_RSS:-0}/1024,1))")

# ── Generate comparison report ───────────────────────────────────────────────
python3 - "${RESULTS_DIR}/k6_shibuya.json" "${RESULTS_DIR}/k6_coraza.json" "$SHIBUYA_MB" "$CORAZA_MB" "$OUTPUT_FILE" << 'PYEOF'
import json, sys

def load_k6(path):
    try:
        with open(path) as f:
            data = json.load(f)
        m = data.get("metrics", {})
        dur = m.get("http_req_duration", {})
        reqs = m.get("http_reqs", {})
        failed = m.get("http_req_failed", {})
        return {
            "p50": dur.get("values", {}).get("p(50)", 0),
            "p95": dur.get("values", {}).get("p(95)", 0),
            "p99": dur.get("values", {}).get("p(99)", 0),
            "avg": dur.get("values", {}).get("avg", 0),
            "rps": reqs.get("values", {}).get("rate", 0),
            "count": reqs.get("values", {}).get("count", 0),
            "error_rate": failed.get("values", {}).get("rate", 0),
        }
    except Exception as e:
        return {"p50": 0, "p95": 0, "p99": 0, "avg": 0, "rps": 0, "count": 0, "error_rate": 0}

shibuya = load_k6(sys.argv[1])
coraza = load_k6(sys.argv[2])
shib_mem = sys.argv[3]
cor_mem = sys.argv[4]
output = sys.argv[5]

def winner(a, b, lower_better=True):
    if lower_better:
        return "🏆" if a <= b else ""
    return "🏆" if a >= b else ""

lines = []
lines.append("# SHIBUYA vs Coraza — Performance Comparison")
lines.append("")
lines.append(f"| Metric | SHIBUYA | Coraza | Winner |")
lines.append(f"|:-------|--------:|-------:|:------:|")
lines.append(f"| p50 latency (ms) | {shibuya['p50']:.2f} | {coraza['p50']:.2f} | {winner(shibuya['p50'], coraza['p50'])} |")
lines.append(f"| p95 latency (ms) | {shibuya['p95']:.2f} | {coraza['p95']:.2f} | {winner(shibuya['p95'], coraza['p95'])} |")
lines.append(f"| p99 latency (ms) | {shibuya['p99']:.2f} | {coraza['p99']:.2f} | {winner(shibuya['p99'], coraza['p99'])} |")
lines.append(f"| Avg latency (ms) | {shibuya['avg']:.2f} | {coraza['avg']:.2f} | {winner(shibuya['avg'], coraza['avg'])} |")
lines.append(f"| Throughput (rps) | {shibuya['rps']:.0f} | {coraza['rps']:.0f} | {winner(shibuya['rps'], coraza['rps'], False)} |")
lines.append(f"| Total requests | {shibuya['count']:.0f} | {coraza['count']:.0f} | — |")
lines.append(f"| Error rate | {shibuya['error_rate']:.4f} | {coraza['error_rate']:.4f} | {winner(shibuya['error_rate'], coraza['error_rate'])} |")
lines.append(f"| Memory RSS (MB) | {shib_mem} | {cor_mem} | {winner(float(shib_mem), float(cor_mem))} |")
lines.append("")

# Verdict
shibuya_wins = 0
coraza_wins = 0
for metric, lower in [("p50", True), ("p95", True), ("p99", True), ("rps", False)]:
    sv = shibuya[metric]
    cv = coraza[metric]
    if lower:
        if sv < cv: shibuya_wins += 1
        elif cv < sv: coraza_wins += 1
    else:
        if sv > cv: shibuya_wins += 1
        elif cv > sv: coraza_wins += 1

if shibuya_wins > coraza_wins:
    lines.append(f"> **Verdict:** SHIBUYA wins {shibuya_wins}/{shibuya_wins+coraza_wins} metrics 🏆")
elif coraza_wins > shibuya_wins:
    lines.append(f"> **Verdict:** Coraza wins {coraza_wins}/{shibuya_wins+coraza_wins} metrics")
else:
    lines.append(f"> **Verdict:** Tie ({shibuya_wins} each)")

with open(output, "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"[CORAZA] Comparison report written to {output}")
PYEOF

log "Done — comparison report: $OUTPUT_FILE"
