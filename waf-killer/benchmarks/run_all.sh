#!/usr/bin/env bash
# =============================================================================
# SHIBUYA WAF — Master Benchmark Orchestrator
# Usage: ./benchmarks/run_all.sh [--skip-build] [--quick] [--no-coraza] [--no-gotestwaf]
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$SCRIPT_DIR/results"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="$RESULTS_DIR/$TIMESTAMP"

WAF_PID=""
WAF_ADMIN_PORT="${WAF_ADMIN_PORT:-9090}"
WAF_HTTP_PORT="${WAF_HTTP_PORT:-8080}"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${BLUE}[BENCH]${NC} $*"; }
ok()    { echo -e "${GREEN}[  OK ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[ WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL ]${NC} $*"; }

# ── Flags ──────────────────────────────────────────────────────────────────────
SKIP_BUILD=false; QUICK=false; NO_CORAZA=false; NO_GOTESTWAF=false
for arg in "$@"; do
  case "$arg" in
    --skip-build)  SKIP_BUILD=true ;;
    --quick)       QUICK=true ;;
    --no-coraza)   NO_CORAZA=true ;;
    --no-gotestwaf) NO_GOTESTWAF=true ;;
  esac
done

# ── Prerequisite check ─────────────────────────────────────────────────────────
check_prereqs() {
  log "Checking prerequisites..."
  local missing=()

  command -v cargo  &>/dev/null || missing+=("cargo (Rust)")
  command -v python3 &>/dev/null || missing+=("python3")
  command -v jq     &>/dev/null || missing+=("jq")
  command -v curl   &>/dev/null || missing+=("curl")

  # k6 is optional but highly recommended
  if ! command -v k6 &>/dev/null; then
    warn "k6 not found — load tests will be skipped (install: brew install k6)"
  fi

  if (( ${#missing[@]} > 0 )); then
    fail "Missing required tools: ${missing[*]}"
    echo "  Install them and re-run."
    exit 1
  fi

  # Python deps
  python3 -c "import json, csv, os, sys, datetime, statistics" 2>/dev/null || {
    fail "Python standard library check failed"; exit 1;
  }
  # matplotlib is optional, report_generator handles its absence gracefully
  python3 -c "import matplotlib" 2>/dev/null || warn "matplotlib not found — graphs will be ASCII only"

  ok "Prerequisites satisfied"
}

# ── Build WAF ──────────────────────────────────────────────────────────────────
build_waf() {
  if $SKIP_BUILD; then
    warn "Skipping build (--skip-build)"
    return
  fi
  log "Building WAF in release mode..."
  cd "$PROJECT_ROOT/core"
  cargo build --release 2>&1 | tail -5
  ok "Build complete"
  cd "$PROJECT_ROOT"
}

# ── Start / Stop WAF ──────────────────────────────────────────────────────────
start_waf() {
  log "Starting SHIBUYA WAF (Admin: $WAF_ADMIN_PORT, Proxy: $WAF_HTTP_PORT)..."
  cd "$PROJECT_ROOT/core"

  RUST_LOG=info cargo run --release -- \
    --config "$PROJECT_ROOT/config/waf.yaml" \
    --admin-port "$WAF_ADMIN_PORT" \
    > "$RUN_DIR/waf_stdout.log" 2>&1 &
  WAF_PID=$!
  cd "$PROJECT_ROOT"

  # Wait for health endpoint
  local retries=30
  while (( retries > 0 )); do
    if curl -sf "http://localhost:${WAF_ADMIN_PORT}/health" > /dev/null 2>&1; then
      ok "WAF is healthy (PID $WAF_PID)"
      return
    fi
    retries=$((retries - 1))
    sleep 2
  done
  fail "WAF failed to start within 60 seconds. Check $RUN_DIR/waf_stdout.log"
  exit 1
}

stop_waf() {
  if [[ -n "$WAF_PID" ]] && kill -0 "$WAF_PID" 2>/dev/null; then
    log "Stopping WAF (PID $WAF_PID)..."
    kill "$WAF_PID" 2>/dev/null || true
    wait "$WAF_PID" 2>/dev/null || true
    ok "WAF stopped"
  fi
}
trap stop_waf EXIT

# ── Benchmark runners ──────────────────────────────────────────────────────────
run_detection_test() {
  log "━━━ Detection Accuracy Test ━━━"
  bash "$SCRIPT_DIR/detection_test.sh" \
    --admin-port "$WAF_ADMIN_PORT" \
    --http-port "$WAF_HTTP_PORT" \
    --output "$RUN_DIR/detection_results.csv" \
    2>&1 | tee "$RUN_DIR/detection.log"
  ok "Detection test complete → $RUN_DIR/detection_results.csv"
}

run_load_test() {
  if ! command -v k6 &>/dev/null; then
    warn "Skipping load test (k6 not installed)"
    return
  fi
  log "━━━ k6 Load Test ━━━"
  local scenario="default"
  if $QUICK; then scenario="quick"; fi

  K6_WAF_HTTP_PORT="$WAF_HTTP_PORT" K6_WAF_ADMIN_PORT="$WAF_ADMIN_PORT" \
    k6 run \
    --out json="$RUN_DIR/k6_raw.json" \
    --summary-export "$RUN_DIR/k6_summary.json" \
    -e SCENARIO="$scenario" \
    "$SCRIPT_DIR/load_test.js" \
    2>&1 | tee "$RUN_DIR/k6.log"
  ok "Load test complete → $RUN_DIR/k6_summary.json"
}

run_memory_profile() {
  log "━━━ Memory Profile ━━━"
  local duration=300  # 5 min default
  if $QUICK; then duration=60; fi

  bash "$SCRIPT_DIR/memory_profile.sh" \
    --pid "$WAF_PID" \
    --duration "$duration" \
    --output "$RUN_DIR/memory.csv" \
    2>&1 | tee "$RUN_DIR/memory.log"
  ok "Memory profile complete → $RUN_DIR/memory.csv"
}

run_rust_microbench() {
  log "━━━ Rust Micro-Benchmarks (Criterion) ━━━"
  cd "$PROJECT_ROOT/core"
  # Run criterion benchmarks and capture output
  cargo bench --bench shibuya_bench -- --output-format bencher \
    2>&1 | tee "$RUN_DIR/criterion.log" || {
    warn "Criterion benchmarks had errors (non-fatal)"
  }
  # Copy criterion results if they exist
  if [[ -d "$PROJECT_ROOT/core/target/criterion" ]]; then
    cp -r "$PROJECT_ROOT/core/target/criterion" "$RUN_DIR/criterion_reports" 2>/dev/null || true
  fi
  cd "$PROJECT_ROOT"
  ok "Micro-benchmarks complete"
}

run_coraza_compare() {
  if $NO_CORAZA; then
    warn "Skipping Coraza comparison (--no-coraza)"
    return
  fi
  log "━━━ Coraza Comparison ━━━"
  bash "$SCRIPT_DIR/compare_coraza.sh" \
    --output "$RUN_DIR/coraza_comparison.md" \
    2>&1 | tee "$RUN_DIR/coraza.log"
  ok "Coraza comparison complete"
}

run_gotestwaf() {
  if $NO_GOTESTWAF; then
    warn "Skipping GoTestWAF (--no-gotestwaf)"
    return
  fi
  log "━━━ GoTestWAF OWASP Suite ━━━"
  bash "$SCRIPT_DIR/gotestwaf_runner.sh" \
    --http-port "$WAF_HTTP_PORT" \
    --output-dir "$RUN_DIR/gotestwaf" \
    2>&1 | tee "$RUN_DIR/gotestwaf.log"
  ok "GoTestWAF complete"
}

generate_report() {
  log "━━━ Generating Final Report ━━━"
  python3 "$SCRIPT_DIR/report_generator.py" \
    --results-dir "$RUN_DIR" \
    --output "$RUN_DIR/BENCHMARK_REPORT.md"
  ok "Report generated → $RUN_DIR/BENCHMARK_REPORT.md"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  🛡️  SHIBUYA WAF — Performance Benchmark Suite              ${NC}"
  echo -e "${BOLD}  $(date '+%Y-%m-%d %H:%M:%S')                                ${NC}"
  echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
  echo ""

  mkdir -p "$RUN_DIR"
  log "Results directory: $RUN_DIR"

  # Phase 1: Prepare
  check_prereqs
  build_waf

  # Phase 2: Rust micro-benchmarks (no WAF server needed)
  run_rust_microbench

  # Phase 3: Start WAF and run integration benchmarks
  start_waf

  run_detection_test
  run_load_test
  run_memory_profile
  run_coraza_compare
  run_gotestwaf

  # Phase 4: Report
  stop_waf
  WAF_PID=""  # Prevent double-stop in trap
  generate_report

  echo ""
  echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
  echo -e "${GREEN}  ✅  All benchmarks complete!${NC}"
  echo -e "  📄  Report: ${BOLD}$RUN_DIR/BENCHMARK_REPORT.md${NC}"
  echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"

  # Open report if on macOS
  if command -v open &>/dev/null; then
    open "$RUN_DIR/BENCHMARK_REPORT.md" 2>/dev/null || true
  fi
}

main
