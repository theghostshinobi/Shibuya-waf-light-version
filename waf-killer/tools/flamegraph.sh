#!/bin/bash
# tools/flamegraph.sh

echo "🔥 Generating CPU flamegraph..."

# Check requirements
if ! command -v perf &> /dev/null; then
    echo "perf not found (Linux only). Creating dummy flamegraph action for Mac..."
    echo "On Mac, consider using 'cargo flamegraph'."
    exit 0
fi

# Start WAF with profiling
cargo build --release
perf record -F 99 -g --call-graph dwarf -- \
    ./target/release/waf-killer-core &

WAF_PID=$!

# Run load test
echo "Running load test..."
# Check for wrk
if command -v wrk &> /dev/null; then
    wrk -t12 -c1000 -d30s http://localhost:8443
else
    sleep 30
fi

# Stop profiling
kill -SIGINT $WAF_PID
wait $WAF_PID

# Check for FlameGraph tools
if [ -d "FlameGraph" ]; then
    perf script | ./FlameGraph/stackcollapse-perf.pl | ./FlameGraph/flamegraph.pl > flamegraph.svg
    echo "✅ Flamegraph saved to flamegraph.svg"
else
    echo "FlameGraph tools not found in current directory. Please clone https://github.com/brendangregg/FlameGraph"
fi
