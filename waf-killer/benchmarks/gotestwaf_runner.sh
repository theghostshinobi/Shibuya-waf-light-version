#!/usr/bin/env bash
# =============================================================================
# SHIBUYA WAF — GoTestWAF OWASP Runner
# Clones GoTestWAF, runs full OWASP test suite, parses results.
# Usage: benchmarks/gotestwaf_runner.sh --http-port 8080 --output-dir ./results/gotestwaf
# =============================================================================
set -euo pipefail

HTTP_PORT="8080"
OUTPUT_DIR="./gotestwaf_results"
GOTESTWAF_DIR="/tmp/gotestwaf_bench"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --http-port)  HTTP_PORT="$2";   shift 2 ;;
    --output-dir) OUTPUT_DIR="$2";  shift 2 ;;
    *) shift ;;
  esac
done

log() { echo -e "[GTWAF] $*"; }

mkdir -p "$OUTPUT_DIR"

# ── Prerequisites ────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  # Try Go-based install
  if ! command -v go &>/dev/null; then
    log "Neither Docker nor Go found. GoTestWAF requires one of them."
    echo "# GoTestWAF — SKIPPED (no Docker or Go)" > "$OUTPUT_DIR/gotestwaf_report.md"
    exit 0
  fi

  log "Docker not found, using Go to build GoTestWAF..."
  USE_DOCKER=false
else
  USE_DOCKER=true
fi

TARGET_URL="http://host.docker.internal:${HTTP_PORT}"
if ! $USE_DOCKER; then
  TARGET_URL="http://localhost:${HTTP_PORT}"
fi

# ── Setup GoTestWAF ──────────────────────────────────────────────────────────
if $USE_DOCKER; then
  log "Pulling GoTestWAF Docker image..."
  docker pull wallarm/gotestwaf:latest 2>&1 | tail -3

  log "Running GoTestWAF against SHIBUYA (port $HTTP_PORT)..."
  docker run --rm \
    --add-host=host.docker.internal:host-gateway \
    -v "$OUTPUT_DIR:/app/reports" \
    wallarm/gotestwaf:latest \
    --url "$TARGET_URL" \
    --workers 5 \
    --noEmailReport \
    --reportFormat markdown \
    --skipWAFIdentification \
    2>&1 | tee "$OUTPUT_DIR/gotestwaf_stdout.log"
else
  # Clone and build from source
  if [[ ! -d "$GOTESTWAF_DIR" ]]; then
    log "Cloning GoTestWAF..."
    git clone --depth 1 https://github.com/wallarm/gotestwaf.git "$GOTESTWAF_DIR" 2>&1 | tail -3
  fi

  cd "$GOTESTWAF_DIR"
  log "Building GoTestWAF..."
  go build -o gotestwaf ./cmd/gotestwaf 2>&1 | tail -3

  log "Running GoTestWAF against SHIBUYA (port $HTTP_PORT)..."
  ./gotestwaf \
    --url "$TARGET_URL" \
    --workers 5 \
    --noEmailReport \
    --reportFormat markdown \
    --reportPath "$OUTPUT_DIR" \
    --skipWAFIdentification \
    2>&1 | tee "$OUTPUT_DIR/gotestwaf_stdout.log"
fi

# ── Parse results ────────────────────────────────────────────────────────────
log "Parsing GoTestWAF results..."

# Find the generated report
REPORT_FILE=$(find "$OUTPUT_DIR" -name "*.md" -not -name "gotestwaf_report.md" -type f 2>/dev/null | head -1)

if [[ -z "$REPORT_FILE" ]]; then
  # Try to extract from stdout
  log "No markdown report file found, extracting from stdout..."
  REPORT_FILE=""
fi

# Generate summary from stdout log
python3 - "$OUTPUT_DIR/gotestwaf_stdout.log" "$OUTPUT_DIR" << 'PYEOF'
import sys, re, os

log_file = sys.argv[1]
output_dir = sys.argv[2]

try:
    with open(log_file) as f:
        content = f.read()
except FileNotFoundError:
    print("[GTWAF] No stdout log found")
    sys.exit(0)

lines = []
lines.append("# GoTestWAF OWASP Test Results")
lines.append("")

# Extract key metrics from output
blocked = re.findall(r'Blocked:\s*(\d+)', content)
bypassed = re.findall(r'Bypassed:\s*(\d+)', content)
total = re.findall(r'Total:\s*(\d+)', content)

if blocked and bypassed:
    b = int(blocked[-1])
    bp = int(bypassed[-1])
    t = int(total[-1]) if total else b + bp
    rate = round(b / t * 100, 1) if t > 0 else 0

    lines.append(f"| Metric | Value |")
    lines.append(f"|:-------|------:|")
    lines.append(f"| Total payloads | {t} |")
    lines.append(f"| Blocked | {b} |")
    lines.append(f"| Bypassed | {bp} |")
    lines.append(f"| **Detection rate** | **{rate}%** |")
    lines.append("")

    if rate >= 95:
        lines.append(f"> ✅ Detection rate {rate}% meets target (>95%)")
    elif rate >= 90:
        lines.append(f"> ⚠️ Detection rate {rate}% below target (>95%)")
    else:
        lines.append(f"> ❌ Detection rate {rate}% significantly below target (>95%)")
else:
    lines.append("_No structured results parsed from GoTestWAF output._")
    lines.append("")
    lines.append("Check raw log for details.")

# Extract per-category results if available
categories = re.findall(r'(\w[\w\s]+?)\s+(\d+)/(\d+)\s+\((\d+\.?\d*)%\)', content)
if categories:
    lines.append("")
    lines.append("## Per-Category Breakdown")
    lines.append("")
    lines.append("| Category | Detected/Total | Rate |")
    lines.append("|:---------|:--------------:|-----:|")
    for cat, det, tot, rate in categories:
        emoji = "✅" if float(rate) >= 95 else "⚠️" if float(rate) >= 80 else "❌"
        lines.append(f"| {cat.strip()} | {det}/{tot} | {emoji} {rate}% |")

with open(os.path.join(output_dir, "gotestwaf_report.md"), "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"[GTWAF] Summary written to {output_dir}/gotestwaf_report.md")
PYEOF

log "Done — results in $OUTPUT_DIR/"
