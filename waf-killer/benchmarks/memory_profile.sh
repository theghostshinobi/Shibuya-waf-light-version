#!/usr/bin/env bash
# =============================================================================
# SHIBUYA WAF — Memory Profiling Script
# Monitors WAF RSS memory during sustained load and detects leaks.
# Usage: benchmarks/memory_profile.sh --pid <WAF_PID> --duration 300 --output memory.csv
# =============================================================================
set -euo pipefail

PID=""
DURATION=300       # seconds
INTERVAL=5         # sample every N seconds
OUTPUT_FILE="memory.csv"
LOAD_RATE=500      # req/s during monitoring
HTTP_PORT="8080"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pid)       PID="$2";         shift 2 ;;
    --duration)  DURATION="$2";    shift 2 ;;
    --interval)  INTERVAL="$2";    shift 2 ;;
    --output)    OUTPUT_FILE="$2"; shift 2 ;;
    --load-rate) LOAD_RATE="$2";   shift 2 ;;
    --http-port) HTTP_PORT="$2";   shift 2 ;;
    *) shift ;;
  esac
done

if [[ -z "$PID" ]]; then
  echo "[ERROR] --pid is required"
  exit 1
fi

if ! kill -0 "$PID" 2>/dev/null; then
  echo "[ERROR] Process $PID not running"
  exit 1
fi

echo "[MEM] Profiling PID $PID for ${DURATION}s (sample every ${INTERVAL}s)"
echo "[MEM] Output: $OUTPUT_FILE"

# ── Start background load ───────────────────────────────────────────────────
LOAD_PID=""
BASE="http://localhost:${HTTP_PORT}"

# Use curl in a loop as lightweight load generator (no k6 dependency)
start_background_load() {
  echo "[MEM] Starting background load at ~${LOAD_RATE} req/s..."
  (
    local delay
    delay=$(python3 -c "print(1.0/${LOAD_RATE})" 2>/dev/null || echo "0.002")
    local paths=("/api/users" "/api/products?p=1" "/api/search?q=test" "/api/health" "/api/settings")
    local idx=0
    while true; do
      local path="${paths[$((idx % ${#paths[@]}))]}"
      curl -sf "${BASE}${path}" > /dev/null 2>&1 &
      idx=$((idx + 1))
      # Batch: send 10 concurrent curls, then sleep
      if (( idx % 10 == 0 )); then
        sleep "$(python3 -c "print(max(0.001, ${delay} * 10))")" 2>/dev/null || sleep 0.02
      fi
    done
  ) &
  LOAD_PID=$!
}

stop_background_load() {
  if [[ -n "$LOAD_PID" ]]; then
    kill "$LOAD_PID" 2>/dev/null || true
    # Kill any spawned curl children
    pkill -P "$LOAD_PID" 2>/dev/null || true
    wait "$LOAD_PID" 2>/dev/null || true
    echo "[MEM] Background load stopped"
  fi
}

trap stop_background_load EXIT

start_background_load

# ── Sample memory ────────────────────────────────────────────────────────────
echo "timestamp_s,elapsed_s,rss_kb,rss_mb,vsz_kb" > "$OUTPUT_FILE"

START_TIME=$(date +%s)
SAMPLES=0
FIRST_RSS=0
LAST_RSS=0
MAX_RSS=0

while (( SAMPLES * INTERVAL < DURATION )); do
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "[MEM] Process $PID exited during profiling"
    break
  fi

  NOW=$(date +%s)
  ELAPSED=$((NOW - START_TIME))

  # Get RSS and VSZ in KB (macOS ps syntax)
  MEM_LINE=$(ps -o rss=,vsz= -p "$PID" 2>/dev/null || echo "0 0")
  RSS_KB=$(echo "$MEM_LINE" | awk '{print $1}')
  VSZ_KB=$(echo "$MEM_LINE" | awk '{print $2}')
  RSS_MB=$(python3 -c "print(round(${RSS_KB}/1024, 1))" 2>/dev/null || echo "0")

  echo "${NOW},${ELAPSED},${RSS_KB},${RSS_MB},${VSZ_KB}" >> "$OUTPUT_FILE"

  if (( SAMPLES == 0 )); then FIRST_RSS=$RSS_KB; fi
  LAST_RSS=$RSS_KB
  if (( RSS_KB > MAX_RSS )); then MAX_RSS=$RSS_KB; fi

  # Progress indicator
  PCT=$((ELAPSED * 100 / DURATION))
  printf "\r[MEM] %3d%% | Elapsed: %ds/%ds | RSS: %s MB " "$PCT" "$ELAPSED" "$DURATION" "$RSS_MB"

  SAMPLES=$((SAMPLES + 1))
  sleep "$INTERVAL"
done

echo ""

# ── Analysis ─────────────────────────────────────────────────────────────────
stop_background_load
LOAD_PID=""

echo ""
echo "[MEM] ═══════════════════════════════════════════════"
echo "[MEM] Memory Profile Summary"
echo "[MEM] ═══════════════════════════════════════════════"

FIRST_MB=$(python3 -c "print(round(${FIRST_RSS}/1024, 1))")
LAST_MB=$(python3 -c "print(round(${LAST_RSS}/1024, 1))")
MAX_MB=$(python3 -c "print(round(${MAX_RSS}/1024, 1))")
GROWTH_KB=$((LAST_RSS - FIRST_RSS))
GROWTH_MB=$(python3 -c "print(round(${GROWTH_KB}/1024, 1))")

echo "[MEM]   Initial RSS:   ${FIRST_MB} MB"
echo "[MEM]   Final RSS:     ${LAST_MB} MB"
echo "[MEM]   Peak RSS:      ${MAX_MB} MB"
echo "[MEM]   Growth:        ${GROWTH_MB} MB"
echo "[MEM]   Samples:       ${SAMPLES}"
echo "[MEM]   Duration:      ${DURATION}s"

# Check for leaks: growth > 20% of initial is suspicious
GROWTH_PCT=$(python3 -c "
first = ${FIRST_RSS}
growth = ${GROWTH_KB}
if first > 0:
    print(round(growth / first * 100, 1))
else:
    print(0)
")

if (( $(echo "$GROWTH_PCT < 20" | bc -l 2>/dev/null || echo 1) )); then
  echo "[MEM]   Status:        ✅ STABLE (${GROWTH_PCT}% growth)"
else
  echo "[MEM]   Status:        ⚠️  POSSIBLE LEAK (${GROWTH_PCT}% growth)"
fi

echo "[MEM] ═══════════════════════════════════════════════"

# ── Generate ASCII chart ─────────────────────────────────────────────────────
echo "[MEM] Memory over time (ASCII):"
python3 - "$OUTPUT_FILE" << 'PYEOF'
import sys, csv
data = []
with open(sys.argv[1]) as f:
    reader = csv.DictReader(f)
    for row in reader:
        data.append((int(row['elapsed_s']), float(row['rss_mb'])))

if not data:
    print("  (no data)")
    sys.exit(0)

min_rss = min(d[1] for d in data)
max_rss = max(d[1] for d in data)
rng = max(max_rss - min_rss, 1)
width = 60
height = 15

# Simple ASCII chart
for row in range(height, -1, -1):
    threshold = min_rss + (rng * row / height)
    label = f"{threshold:6.0f}MB │"
    line = ""
    # Sample at most `width` points
    step = max(1, len(data) // width)
    for i in range(0, min(len(data), width * step), step):
        val = data[i][1]
        if val >= threshold:
            line += "█"
        else:
            line += " "
    print(f"  {label}{line}")

print(f"         └{'─' * width}")
elapsed_max = data[-1][0] if data else 0
left_label = "0s"
right_label = f"{elapsed_max}s"
padding = width - len(left_label) - len(right_label)
print(f"          {left_label}{' ' * max(0, padding)}{right_label}")
PYEOF
