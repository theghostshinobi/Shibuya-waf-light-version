import json
import random
import sys

def generate_normal_request():
    """Generate realistic normal request"""
    paths = ["/", "/api/users", "/api/products", "/about", "/contact", "/login", "/static/style.css"]
    methods = ["GET", "GET", "GET", "POST"] # More GETs
    
    path = random.choice(paths)
    method = random.choice(methods)
    
    # Simulate realistic query params
    query_params = {}
    if "api" in path or method == "GET":
        if random.random() < 0.5:
            query_params["page"] = [str(random.randint(1, 10))]
        if random.random() < 0.3:
            query_params["sort"] = [random.choice(["asc", "desc"])]
    
    # Simulate body for POST
    body_text = ""
    body_size = 0
    if method == "POST":
        body_text = json.dumps({"username": "user123", "data": "some content"})
        body_size = len(body_text)

    # Simplified RequestContext representation
    return {
        "uri": path + ("?" + "&".join([f"{k}={v[0]}" for k,v in query_params.items()]) if query_params else ""),
        "path": path,
        "query_params": query_params,
        "query_string": "&".join([f"{k}={v[0]}" for k,v in query_params.items()]) if query_params else "",
        "headers": {
            "user-agent": ["Mozilla/5.0..."],
            "accept": ["text/html,application/json"],
            "host": ["example.com"]
        },
        "cookies": {"session_id": "abc123456"} if random.random() > 0.2 else {},
        "method": method,
        "protocol": "HTTP/1.1",
        "body_size": body_size,
        "body_text": body_text if body_text else None,
        "server_name": "example.com",
        # Simulated Traffic Stats (Normal)
        "traffic_stats": {
             "request_count_1min": random.randint(1, 20),
             "request_count_5min": random.randint(5, 100),
             "unique_paths_1min": random.randint(1, 5),
             "error_count_1min": 0
        }
    }

def generate_attack_request():
    """Generate attack patterns"""
    attacks = [
        # SQLi
        {
            "path": "/api/search",
            "query_params": {"q": ["' OR '1'='1"]},
            "body_text": None,
            "method": "GET"
        },
        # XSS
        {
            "path": "/api/comments",
            "query_params": {},
            "body_text": "<script>alert(1)</script>",
            "method": "POST"
        },
        # Path Traversal
        {
            "path": "/api/files/../../etc/passwd",
            "query_params": {},
            "body_text": None,
            "method": "GET"
        },
        # CMD Injection
        {
            "path": "/api/admin",
            "query_params": {"cmd": ["cat /etc/shadow"]},
            "body_text": None,
            "method": "POST"
        }
    ]
    
    attack = random.choice(attacks)
    
    return {
        "uri": attack["path"], # Simplification
        "path": attack["path"],
        "query_params": attack["query_params"],
        "query_string": "", # TODO: build proper string
        "headers": {
            "user-agent": ["sqlmap/1.0"] if random.random() < 0.3 else ["Mozilla/5.0..."],
            "accept": ["*/*"],
            "host": ["example.com"]
        },
        "cookies": {},
        "method": attack["method"],
        "protocol": "HTTP/1.1",
        "body_size": len(attack["body_text"]) if attack["body_text"] else 0,
        "body_text": attack["body_text"],
        "server_name": "example.com",
        "traffic_stats": {
             "request_count_1min": random.randint(50, 200), # High rate
             "request_count_5min": random.randint(100, 500),
             "unique_paths_1min": random.randint(10, 50), # Scanning
             "error_count_1min": random.randint(5, 20)
        }
    }

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "attacks":
        for _ in range(1000):
            print(json.dumps(generate_attack_request()))
    else:
        for _ in range(10000):
            print(json.dumps(generate_normal_request()))
