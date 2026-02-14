import asyncio
import aiohttp
import time
import json
import random
import socket
import statistics
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Configuration
TARGET_URL = "http://localhost:9090"
DURATION = 60
CONCURRENCY = 100

# Statistics
stats = {
    "total_requests": 0,
    "blocked": 0,
    "passed": 0,
    "latencies": [],
    "payloads_bypassed": [],
    "start_time": None,
    "end_time": None,
    "errors": 0
}

# Payloads (Embedded for portability)
SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' UNION SELECT 1,2,3 --",
    "admin' --",
    "' OR '1'='1",
    "1; DROP TABLE users",
    "' OR SLEEP(5) --",
    "admin') #",
    "' OR 1=1%00",
    "unexisting_col UNION ALL SELECT 1,2,3,4,5--",
    "' or 1=1 limit 1 -- -+"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "\";alert('XSS');//",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<a href=\"javascript:alert(1)\">XSS</a>",
    "<input onfocus=alert(1) autofocus>",
    "<script>confirm(1)</script>"
]

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36"
]

async def send_request(session, method, url, params=None, data=None, json=None, headers=None, payload_type="normal"):
    start = time.time()
    try:
        if headers is None:
            headers = {}
        headers["User-Agent"] = random.choice(UAS)
        
        async with session.request(method, url, params=params, data=data, json=json, headers=headers, timeout=5) as response:
            latency = (time.time() - start) * 1000
            status = response.status
            content = await response.text()
            
            stats["total_requests"] += 1
            stats["latencies"].append(latency)
            
            if status in [403, 429, 406]:
                stats["blocked"] += 1
            elif status >= 200 and status < 400:
                stats["passed"] += 1
                if payload_type != "normal":
                    print(f"\033[91m⚠️ CRITICAL: {payload_type} payload bypassed! Status: {status} Payload: {params or data}\033[0m")
                    stats["payloads_bypassed"].append({"type": payload_type, "payload": params or data, "status": status})
            else:
                stats["errors"] += 1
                
    except Exception as e:
        stats["errors"] += 1
        # print(f"Request failed: {e}")

async def dos_flood():
    async with aiohttp.ClientSession() as session:
        end_time = time.time() + DURATION
        while time.time() < end_time:
            tasks = []
            for _ in range(50): # Batch of 50
                tasks.append(send_request(session, "GET", TARGET_URL))
                tasks.append(send_request(session, "POST", TARGET_URL, data={"data": "flood"}))
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.01)

async def sqli_storm():
    async with aiohttp.ClientSession() as session:
        end_time = time.time() + DURATION
        while time.time() < end_time:
            tasks = []
            for pay in SQLI_PAYLOADS:
                # Obfuscation variations could go here
                tasks.append(send_request(session, "GET", f"{TARGET_URL}/search", params={"q": pay}, payload_type="SQLi"))
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.1)

async def xss_bomb():
    async with aiohttp.ClientSession() as session:
        end_time = time.time() + DURATION
        while time.time() < end_time:
            tasks = []
            for pay in XSS_PAYLOADS:
                tasks.append(send_request(session, "POST", f"{TARGET_URL}/comment", data={"text": pay}, payload_type="XSS"))
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.1)
            
async def attack_chain():
    async with aiohttp.ClientSession() as session:
        end_time = time.time() + DURATION
        while time.time() < end_time:
            # 1. Recon
            await send_request(session, "GET", f"{TARGET_URL}/admin", payload_type="Recon")
            # 2. Brute Login
            for i in range(5):
                await send_request(session, "POST", f"{TARGET_URL}/login", json={"username": "admin", "password": f"pass{i}"}, payload_type="BruteForce")
            # 3. LFI Attempt
            await send_request(session, "GET", f"{TARGET_URL}/admin/logs", params={"file": "../../../../etc/passwd"}, payload_type="LFI")
            await asyncio.sleep(1)

def protocol_abuse():
    end_time = time.time() + DURATION
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("localhost", 9090))
            # Malformed Header
            req = b"GET / HTTP/1.1\r\nHost: localhost:9090\r\nX-Garbage: " + (b"A" * 10000) + b"\r\n\r\n"
            s.send(req)
            s.close()
            stats["total_requests"] += 1
        except:
            stats["errors"] += 1
        time.sleep(0.2)

async def monitor():
    print(f"[*] Monitoring started. Target: {TARGET_URL}")
    end_time = time.time() + DURATION
    async with aiohttp.ClientSession() as session:
        while time.time() < end_time:
            try:
                start = time.time()
                async with session.get(f"{TARGET_URL}/health", timeout=2) as resp:
                    print(f"[*] Health Check: {resp.status} - Latency: {(time.time()-start)*1000:.2f}ms - Blocked/Total: {stats['blocked']}/{stats['total_requests']}")
            except Exception as e:
                print(f"\033[91m⚠️ CRITICAL: WAF Health Check Failed! {e}\033[0m")
            await asyncio.sleep(5)

async def main():
    print(f"\033[92m[+] Starting BRUTAL Stress Test on {TARGET_URL}\033[0m")
    print(f"Duration: {DURATION}s")
    
    stats["start_time"] = datetime.now().isoformat()
    
    # Run Protocol abuse in thread
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor() as pool:
        # Start protocol abuse in background
        loop.run_in_executor(pool, protocol_abuse)
        
        # Async tasks
        await asyncio.gather(
            dos_flood(),
            sqli_storm(),
            xss_bomb(),
            attack_chain(),
            monitor()
        )
    
    stats["end_time"] = datetime.now().isoformat()
    
    # Calculate stats
    total = len(stats["latencies"])
    if total > 0:
        latencies = sorted(stats["latencies"])
        stats["p50"] = latencies[int(total * 0.5)] if latencies else 0
        stats["p95"] = latencies[int(total * 0.95)] if latencies else 0
        stats["p99"] = latencies[int(total * 0.99)] if latencies else 0
    
    # Write Report
    with open("stress_test_report.json", "w") as f:
        json.dump(stats, f, indent=2)
     
    print("\n\033[92m[+] Test Completed. Report saved to stress_test_report.json\033[0m")
    print(f"Total Requests: {stats['total_requests']}")
    print(f"Blocked: {stats['blocked']}")
    print(f"Passed (Should be 0 for attacks): {stats['passed']}")
    if stats['payloads_bypassed']:
        print(f"\033[91m[!] CRITICAL: {len(stats['payloads_bypassed'])} Payloads bypassed!\033[0m")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:9090")
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()
    
    TARGET_URL = args.target
    DURATION = args.duration
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopping...")
