import http.server
import socketserver
import threading
import time
import requests
import sys

# CONFIGURAZIONE
MOCK_SERVER_PORT = 3000   # La porta dove gira l'app "vittima"
WAF_URL = "http://localhost:8080" # La porta del tuo WAF
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

# 1. MOCK VULNERABLE SERVER
class VulnerableHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"VULNERABLE APP: I received this request!")
    
    def log_message(self, format, *args):
        return # Silenzia i log del server vittima

def start_mock_server():
    try:
        handler = VulnerableHandler
        with socketserver.TCPServer(("", MOCK_SERVER_PORT), handler) as httpd:
            print(f"[*] Mock Victim Server running on port {MOCK_SERVER_PORT}...")
            httpd.serve_forever()
    except OSError:
        print(f"[*] Port {MOCK_SERVER_PORT} busy, assuming server already running.")

# Avvia il server in un thread separato
server_thread = threading.Thread(target=start_mock_server, daemon=True)
server_thread.start()
time.sleep(1) # Aspetta che il server parta

# 2. ATTACK SUITE
payloads = [
    # TYPE, PAYLOAD, EXPECTED_STATUS
    ("SQL Injection", "/?q=' OR 1=1 --", 403),
    ("SQL Injection", "/login?u=admin'--", 403),
    ("XSS", "/?search=<script>alert(1)</script>", 403),
    ("XSS", "/?img=javascript:alert(1)", 403),
    ("Path Traversal", "/../../etc/passwd", 403),
    ("Path Traversal", "/config.json", 403), # Spesso protetto
    ("Command Injection", "/?cmd=| cat /etc/passwd", 403),
    ("Bad User-Agent", "/", 403, {"User-Agent": "sqlmap/1.4"}),
    ("Bad User-Agent", "/", 403, {"User-Agent": "Nikto"}),
    ("Legit Traffic", "/?page=home", 200),
    ("Legit Traffic", "/assets/logo.png", 200),
    ("Legit Traffic", "/api/v1/status", 200),
]

print(f"\n🚀 STARTING WAF STRESS TEST against {WAF_URL}\n")
print(f"{'TYPE':<20} | {'PAYLOAD':<30} | {'RESULT':<10} | {'LATENCY'}")
print("-" * 80)

blocked_count = 0
passed_count = 0
failed_test_count = 0

for item in payloads:
    attack_type = item[0]
    path = item[1]
    expected = item[2]
    headers = item[3] if len(item) > 3 else {}
    
    target = f"{WAF_URL}{path}"
    
    try:
        start = time.time()
        # Se non specificato header, usa uno normale
        if "User-Agent" not in headers:
            headers["User-Agent"] = "BrutalWAF-Tester/1.0"
            
        r = requests.get(target, headers=headers, timeout=2)
        latency = (time.time() - start) * 1000
        
        status = r.status_code
        
        # Logica del risultato
        is_blocked = status in [403, 406, 503]
        
        if is_blocked:
            res_str = f"{GREEN}BLOCKED ({status}){RESET}"
            blocked_count += 1
            if expected == 200: failed_test_count += 1 # False Positive
        else:
            res_str = f"{RED}PASSED ({status}){RESET}"
            passed_count += 1
            if expected == 403: failed_test_count += 1 # False Negative (Bypass)

        print(f"{attack_type:<20} | {path[:28]:<30} | {res_str:<20} | {latency:.1f}ms")
        
    except requests.exceptions.ConnectionError:
        print(f"{RED}CONNECTION ERROR{RESET}: Is WAF running on port 8080?")
        sys.exit(1)

print("-" * 80)
print(f"\n📊 REPORT:")
print(f"Total Requests: {len(payloads)}")
print(f"Blocked: {blocked_count}")
print(f"Passed:  {passed_count}")

if failed_test_count == 0:
    print(f"\n✅ SUCCESS: WAF behaved exactly as expected!")
else:
    print(f"\n⚠️ WARNING: {failed_test_count} tests failed (Bypasses or False Positives). Check logs.")

