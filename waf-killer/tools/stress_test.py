
import urllib.request
import urllib.error
import time
import concurrent.futures
import sys
import random

TARGET_URL = "http://localhost:8080/"
CONCURRENT_REQUESTS = 10
TOTAL_REQUESTS = 200

# Random User Agents to simulate real traffic
USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
]

def send_request(i):
    try:
        start_time = time.time()
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "X-Request-ID": f"stress-test-{i}"
        }
        
        url = TARGET_URL
        # Mix of normal and potentially blocked requests (SQLi simulation)
        if i % 10 == 0:
            # Simulate attack
            url += "?q=SELECT%20*%20FROM%20users"
        
        req = urllib.request.Request(url, headers=headers)
        
        with urllib.request.urlopen(req, timeout=2) as response:
            status = response.getcode()
            
        latency = (time.time() - start_time) * 1000
        return status, latency
    except urllib.error.HTTPError as e:
        latency = (time.time() - start_time) * 1000
        return e.code, latency
    except Exception as e:
        return None, 0

def run_stress_test():
    print(f"🚀 Starting Stress Test against {TARGET_URL}")
    print(f"Requests: {TOTAL_REQUESTS}, Concurrency: {CONCURRENT_REQUESTS}")
    print("-" * 40)

    results = []
    start_total = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_REQUESTS) as executor:
        futures = [executor.submit(send_request, i) for i in range(TOTAL_REQUESTS)]
        
        for future in concurrent.futures.as_completed(futures):
            status, latency = future.result()
            if status:
                results.append((status, latency))
            # Optional: Progress bar
            if len(results) % 50 == 0:
                print(f"Completed {len(results)}/{TOTAL_REQUESTS} requests...")

    duration = time.time() - start_total
    
    # Analysis
    if not results:
        print("❌ No successful requests.")
        return

    success_codes = [c for c, _ in results if 200 <= c < 300]
    blocked_codes = [c for c, _ in results if c == 403]
    errors = [c for c, _ in results if c >= 500]
    latencies = [l for _, l in results]
    avg_latency = sum(latencies) / len(latencies)
    max_latency = max(latencies)
    rps = len(results) / duration

    print("-" * 40)
    print(f"✅ Test Complete in {duration:.2f}s")
    print(f"throughput: {rps:.2f} req/s")
    print(f"Default 200 OK: {len(success_codes)}")
    print(f"Blocked 403:   {len(blocked_codes)}")
    print(f"Errors 5xx:    {len(errors)}")
    print(f"Avg Latency:   {avg_latency:.2f}ms")
    print(f"Max Latency:   {max_latency:.2f}ms")

if __name__ == "__main__":
    run_stress_test()
