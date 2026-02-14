#!/bin/bash
# validate_rules.sh

ADMIN_URL="http://localhost:9090"

echo "🔍 Validating Rules API..."

# 1. Fetch Rules
echo "1. Fetching rules..."
curl -s "$ADMIN_URL/rules" > rules_dump.json
rules_count=$(jq length rules_dump.json)
echo "Found $rules_count rules."

# Check for SQLi rule
sqli_id=$(jq -r '.[] | select(.description | contains("SQL Injection")) | .id' rules_dump.json | head -n 1)
echo "Found SQLi Rule ID: $sqli_id"

if [ -z "$sqli_id" ]; then
    echo "❌ No SQLi rule found! Did seed rules load?"
    exit 1
fi

# 2. Disable Rule
echo "----------------------------------------"
echo "2. Disabling Rule $sqli_id..."
curl -s -X PUT "$ADMIN_URL/rules/$sqli_id" \
     -H "Content-Type: application/json" \
     -d '{"enabled": false}' | jq .

# 3. Verify
echo "----------------------------------------"
echo "3. Verifying status..."
curl -s "$ADMIN_URL/rules" > rules_dump_2.json
is_enabled=$(jq -r ".[] | select(.id == \"$sqli_id\") | .enabled" rules_dump_2.json)
echo "Rule Enabled Status: $is_enabled"

if [ "$is_enabled" == "false" ]; then
    echo "✅ SUCCESS: Rule disabled via API!"
else
    echo "❌ FAILURE: Rule is still enabled."
    exit 1
fi

# 4. Re-enable (Cleanup)
echo "----------------------------------------"
echo "4. Re-enabling Rule $sqli_id..."
curl -s -X PUT "$ADMIN_URL/rules/$sqli_id" \
     -H "Content-Type: application/json" \
     -d '{"enabled": true}' > /dev/null

echo "Done."
