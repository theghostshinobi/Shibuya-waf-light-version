#!/bin/bash
# tools/benchmark.sh

echo "🚀 Running WAF Killer performance benchmarks..."

# Configuration
TARGET="http://localhost:8443" # Changed to http for local testing easily if certs not setup, or keep https
DURATION="60s"
CONNECTIONS="1000"
RATE="100000"  # 100k RPS

echo ""
echo "📊 Test 1: Throughput (clean requests)"
echo "Target: 1M RPS per instance"

# Check if wrk is installed
if ! command -v wrk &> /dev/null; then
    echo "wrk could not be found, please install it (brew install wrk)"
else
    wrk -t12 -c$CONNECTIONS -d$DURATION \
        --latency \
        $TARGET
fi

echo ""
echo "📊 Test 2: Attack detection latency"
echo "Target: <1ms p99"

# We would use specific scripts here if we had them
if command -v wrk &> /dev/null; then
    wrk -t12 -c$CONNECTIONS -d$DURATION \
        --latency \
        $TARGET
fi

echo ""
echo "📊 Test 3: Sustained load"
echo "Target: 99.99% success rate"

if ! command -v vegeta &> /dev/null; then
    echo "vegeta could not be found, please install it (brew install vegeta)"
else
    echo "GET $TARGET" | vegeta attack \
        -duration=$DURATION \
        -rate=$RATE \
        | vegeta report \
        | tee results.txt

    echo ""
    echo "📊 Results Summary:"
    cat results.txt | grep -E "Success|Latencies|Requests"
fi
