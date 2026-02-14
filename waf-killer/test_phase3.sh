#!/bin/bash
# test_phase3.sh - Performance Testing

BASE_URL="http://localhost:8080"
BACKEND_URL="http://localhost:3000"

echo "3.1 Measuring Latency..."
echo "Baseline (Direct to Backend):"
time for i in {1..100}; do curl -s $BACKEND_URL/health > /dev/null; done

echo "With WAF:"
time for i in {1..100}; do curl -s $BASE_URL/health > /dev/null; done

echo "3.2 Measuring Throughput..."
if command -v ab &> /dev/null; then
  echo "Running Apache Bench..."
  ab -n 1000 -c 10 $BASE_URL/health
else
  echo "Apache Bench (ab) not found. Skipping throughput test."
fi
