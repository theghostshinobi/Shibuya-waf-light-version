#!/bin/bash
# Test config persistence manually

# Ensure we are running against localhost
API="http://localhost:9090"
CONFIG_FILE="config/waf.yaml"

echo "==== 🔧 Starting Persistence Test ===="

# 1. Check health
echo "1. Checking health..."
curl -s "$API/health" | jq .
if [ $? -ne 0 ]; then
    echo "❌ Failed to connect to WAF"
    exit 1
fi

echo "2. Getting current config info..."
# We can check stats or config if exposed. For now we use ML threshold test.
# Note: we don't have a direct GET /config endpoint for everything, but we can verify effects.

# 3. Update ML threshold to 0.85 (Valid)
echo "3. Updating ML threshold to 0.85..."
RESPONSE=$(curl -s -X POST "$API/config/update" -H "Content-Type: application/json" -d '{"ml_threshold": 0.85}')
echo "$RESPONSE" | jq .

# Verify file content
echo "4. Verifying file on disk..."
if grep -q "threshold: 0.85" "$CONFIG_FILE"; then
    echo "✅ File updated successfully"
else
    echo "❌ File check failed!"
    grep "threshold" "$CONFIG_FILE"
    exit 1
fi

# 4. Try Invalid Update (ML > 1.0)
echo "5. Attempting INVALID update (threshold 1.5)..."
FAIL_RESP=$(curl -s -X POST "$API/config/update" -H "Content-Type: application/json" -d '{"ml_threshold": 1.5}')
echo "$FAIL_RESP"

if echo "$FAIL_RESP" | grep -q "success.*false"; then
    echo "✅ Invalid update correctly rejected"
else
    echo "❌ Failed to reject invalid update"
    exit 1
fi

# 5. Check Backups
echo "6. Checking backups..."
BACKUPS=$(curl -s "$API/config/backups")
echo "Backups: $BACKUPS"
COUNT=$(echo "$BACKUPS" | jq '. | length')
if [ "$COUNT" -gt 0 ]; then
    echo "✅ Backups exist"
else
    echo "❌ No backups found (expected at least 1)"
    exit 1
fi

# 6. Audit Log
echo "7. Checking audit log..."
if [ -f "config/config_changes.jsonl" ]; then
    echo "✅ Audit log exists"
    tail -n 1 config/config_changes.jsonl | jq .
else
    echo "❌ Audit log missing"
    exit 1
fi

# 7. Rollback
echo "8. Testing Rollback..."
# Get latest backup
LATEST_BACKUP=$(echo "$BACKUPS" | jq -r '.[0]')
echo "Rolling back to $LATEST_BACKUP..."

ROLL_RESP=$(curl -s -X POST "$API/config/rollback" -H "Content-Type: application/json" -d "{\"backup_timestamp\": \"$LATEST_BACKUP\"}")
echo "$ROLL_RESP" | jq .

if echo "$ROLL_RESP" | grep -q "success.*true"; then
    echo "✅ Rollback successful"
else
    echo "❌ Rollback details failed"
    exit 1
fi

echo "==== ✅ All Persistence Tests Passed ===="
