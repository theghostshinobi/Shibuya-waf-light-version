import http.server
import socketserver
import threading
import time
import requests
import sys
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Configuration
MOCK_SERVER_PORT = 3001
WAF_URL = "http://localhost:8081"
Total_Attacks = 0
Blocked_Count = 0
Bypassed_Count = 0
Latencies = []

# 1. Mock Vulnerable Server
class VulnerableHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self._respond()
    
    def do_POST(self):
        self._respond()
        
    def do_PUT(self):
        self._respond()
        
    def do_DELETE(self):
        self._respond()
        
    def do_OPTIONS(self):
        self._respond()

    def _respond(self):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "vulnerable", "message": "I am waiting for attacks!"}')
    
    def log_message(self, format, *args):
        return # Silence server logs

def start_mock_server():
    with socketserver.TCPServer(("", MOCK_SERVER_PORT), VulnerableHandler) as httpd:
        print(f"{Fore.CYAN}[*] Mock Vulnerable Server started on port {MOCK_SERVER_PORT}")
        httpd.serve_forever()

# 2. Attack Suite
PAYLOADS = [
    # SQL Injection
    {"name": "SQL Injection (Basic)", "path": "/?id=1' OR '1'='1", "method": "GET"},
    {"name": "SQL Injection (Union)", "path": "/?q=UNION SELECT 1,2,3--", "method": "GET"},
    
    # XSS
    {"name": "XSS (Script Tag)", "path": "/?q=<script>alert(1)</script>", "method": "GET"},
    {"name": "XSS (Event Handler)", "path": "/", "method": "POST", "data": {"comment": "<img src=x onerror=alert(1)>"}},
    
    # Command Injection
    {"name": "Command Injection (Unix)", "path": "/?cmd=; cat /etc/passwd", "method": "GET"},
    {"name": "Command Injection (Windows)", "path": "/?cmd=| dir", "method": "GET"},
    
    # Path Traversal
    {"name": "Path Traversal (DotDot)", "path": "/../../etc/passwd", "method": "GET"},
    {"name": "Path Traversal (Encoded)", "path": "/..%2f..%2fetc%2fpasswd", "method": "GET"},
    
    # Bad User Agents
    {"name": "Bad Bot (SQLMap)", "path": "/", "method": "GET", "headers": {"User-Agent": "sqlmap/1.4"}},
    {"name": "Bad Bot (Nikto)", "path": "/", "method": "GET", "headers": {"User-Agent": "Nikto"}},
    
    # Shellshock
    {"name": "Shellshock", "path": "/", "method": "GET", "headers": {"User-Agent": "() { :;}; echo 'Vulnerable'"}},
    
    # Logic / Other
    {"name": "Admin Access (Unauthorized)", "path": "/admin/config", "method": "GET"},
    
    # 5 Clean Requests (False Positive Tests)
    {"name": "Clean Request (Home)", "path": "/", "method": "GET", "expect_block": False},
    {"name": "Clean Request (Login JSON)", "path": "/login", "method": "POST", "data": {"user": "alice", "pass": "secret"}, "expect_block": False},
    {"name": "Clean Request (Search)", "path": "/search?q=shoes", "method": "GET", "expect_block": False},
    {"name": "Clean Request (Static Image)", "path": "/images/logo.png", "method": "GET", "expect_block": False},
    {"name": "Clean Request (API Data)", "path": "/api/v1/items", "method": "GET", "expect_block": False},
]

def run_attacks():
    global Total_Attacks, Blocked_Count, Bypassed_Count, Latencies
    
    print(f"\n{Fore.YELLOW}[*] Waiting for WAF at {WAF_URL}...")
    
    # Simple check if WAF is up
    retries = 5
    while retries > 0:
        try:
            requests.get(WAF_URL, timeout=2)
            print(f"{Fore.GREEN}[+] WAF is UP! Launching attacks...")
            break
        except:
            time.sleep(1)
            retries -= 1
            if retries == 0:
                 print(f"{Fore.RED}[!] WAF is DOWN or not reachable at {WAF_URL}. Is it running?")
                 # Don't exit, maybe user starts it late, but warn.
    
    time.sleep(1)
    
    print(f"\n{Fore.WHITE}================ ATTACK LOG ================")
    
    session = requests.Session()
    
    for attack in PAYLOADS:
        Total_Attacks += 1
        name = attack["name"]
        method = attack["method"]
        path = attack["path"]
        url = f"{WAF_URL}{path}"
        headers = attack.get("headers", {})
        data = attack.get("data", None)
        expect_block = attack.get("expect_block", True)
        
        start_time = time.time()
        try:
            if method == "GET":
                response = session.get(url, headers=headers, timeout=5)
            elif method == "POST":
                response = session.post(url, json=data, headers=headers, timeout=5)
            else:
                response = session.request(method, url, headers=headers, timeout=5)
                
            latency = (time.time() - start_time) * 1000
            Latencies.append(latency)
            
            status = response.status_code
            
            # Analysis
            is_blocked = status in [403, 406, 429] # 429 for rate limit
            
            if expect_block:
                if is_blocked:
                    Blocked_Count += 1
                    print(f"{Fore.GREEN}🛡️  BLOCKED: {name:<30} | {status} | {latency:.2f}ms")
                else:
                    Bypassed_Count += 1
                    print(f"{Fore.RED}💀 BYPASSED: {name:<30} | {status} | {latency:.2f}ms")
            else:
                # Clean request
                if is_blocked:
                    # False Positive
                    print(f"{Fore.RED}⚠️  FALSE POS: {name:<30} | {status} | {latency:.2f}ms")
                else:
                    # True Negative
                    print(f"{Fore.BLUE}✅ PASSED:  {name:<30} | {status} | {latency:.2f}ms")
                    
        except Exception as e:
            print(f"{Fore.RED}[!] ERROR:   {name:<30} | {str(e)}")
            
    # Summary
    print(f"\n{Fore.WHITE}================ SUMMARY REPORT ================")
    avg_latency = sum(Latencies) / len(Latencies) if Latencies else 0
    
    print(f"Total Tests:  {Total_Attacks}")
    print(f"{Fore.GREEN}Blocked:      {Blocked_Count}")
    print(f"{Fore.RED}Bypassed:     {Bypassed_Count}")
    print(f"Avg Latency:  {avg_latency:.2f}ms")
    
    if Bypassed_Count == 0:
        print(f"\n{Fore.GREEN}🎉 WAF VERIFICATION SUCCESSFUL! No bypasses detected.")
    else:
        print(f"\n{Fore.RED}❌ WAF VERIFICATION FAILED! {Bypassed_Count} bypasses detected.")

if __name__ == "__main__":
    # Start Mock Server Thread
    server_thread = threading.Thread(target=start_mock_server)
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for server/user
    time.sleep(1)
    
    try:
        run_attacks()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
