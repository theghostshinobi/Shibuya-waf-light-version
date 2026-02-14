"""
Deliberately Vulnerable Test Application for WAF Stress Testing
INTENTIONALLY INSECURE - DO NOT USE IN PRODUCTION

This application contains exploitable vulnerabilities for testing WAF detection:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- XXE (XML External Entity)
- SSRF (Server-Side Request Forgery)
- Insecure Deserialization
- Authentication Bypass
- Rate Limit Testing (no limits)
- GraphQL Complexity Attack
"""

from flask import Flask, request, jsonify, Response
import subprocess
import os
import pickle
import base64
import urllib.request
import time
import json
from xml.etree import ElementTree as ET
from functools import wraps

app = Flask(__name__)

# In-memory storage for XSS comments
comments = []

# Simple request logger
request_log = []

def log_request():
    """Log incoming requests for debugging"""
    entry = {
        "timestamp": time.time(),
        "method": request.method,
        "path": request.path,
        "query": request.query_string.decode('utf-8', errors='ignore'),
        "headers": dict(request.headers),
        "remote_addr": request.remote_addr
    }
    request_log.append(entry)
    if len(request_log) > 1000:
        request_log.pop(0)

@app.before_request
def before_request():
    log_request()

# ==========================================
# BASIC ENDPOINTS
# ==========================================

@app.route('/')
def index():
    return jsonify({
        "app": "Vulnerable Test App",
        "version": "1.0.0",
        "purpose": "WAF Stress Testing",
        "warning": "INTENTIONALLY INSECURE"
    })

@app.route('/health')
def health():
    return jsonify({"status": "ok", "timestamp": time.time()})

# ==========================================
# SQL INJECTION VULNERABILITIES
# ==========================================

@app.route('/api/search')
def search():
    """SQL Injection - Concatenates user input directly into SQL query"""
    q = request.args.get('q', '')
    
    # Simulate SQL query execution with injection vulnerability
    fake_sql = f"SELECT * FROM products WHERE name LIKE '%{q}%'"
    
    # Simulate SQL error on injection
    if "'" in q or "\"" in q:
        return jsonify({
            "error": f"mysql error: syntax error near '{q}'",
            "query": fake_sql
        }), 500
    
    # Simulate UNION injection detection
    if "UNION" in q.upper():
        return jsonify({
            "data": ["admin", "password123", "secret_key"],
            "query": fake_sql
        })
    
    # Simulate time-based blind SQLi
    if "SLEEP" in q.upper() or "WAITFOR" in q.upper():
        time.sleep(2)
        return jsonify({"query": fake_sql, "executed": True})
    
    return jsonify({
        "results": ["Product 1", "Product 2"],
        "query": fake_sql
    })

@app.route('/api/user')
def get_user():
    """SQL Injection in user lookup"""
    user_id = request.args.get('id', '')
    fake_sql = f"SELECT * FROM users WHERE id = {user_id}"
    
    if "OR" in user_id.upper() or "'" in user_id:
        return jsonify({
            "users": [
                {"id": 1, "username": "admin", "email": "admin@vuln.app"},
                {"id": 2, "username": "root", "email": "root@vuln.app"}
            ],
            "query": fake_sql
        })
    
    return jsonify({"user": {"id": user_id, "username": "test"}, "query": fake_sql})

# ==========================================
# CROSS-SITE SCRIPTING (XSS)
# ==========================================

@app.route('/api/comment', methods=['GET', 'POST'])
def comment():
    """XSS - Reflects and stores user input without sanitization"""
    if request.method == 'POST':
        text = request.form.get('text', '') or request.json.get('text', '') if request.is_json else ''
        comments.append({
            "id": len(comments) + 1,
            "text": text,  # NO SANITIZATION
            "timestamp": time.time()
        })
        return jsonify({"status": "stored", "comment": text})
    
    # GET - Return HTML with comments (XSS payload delivery)
    text = request.args.get('text', '')
    html = f"""
    <html>
    <body>
        <h1>Comments</h1>
        <div class="comment">User said: {text}</div>
    </body>
    </html>
    """
    return Response(html, mimetype='text/html')

@app.route('/api/comments')
def list_comments():
    """Returns stored comments (XSS delivery mechanism)"""
    html = "<html><body><h1>All Comments</h1>"
    for c in comments:
        html += f"<div class='comment'>{c['text']}</div>"  # NO SANITIZATION
    html += "</body></html>"
    return Response(html, mimetype='text/html')

# ==========================================
# COMMAND INJECTION
# ==========================================

@app.route('/api/exec', methods=['POST'])
def exec_command():
    """Command Injection - Executes user input via shell"""
    data = request.json or request.form
    cmd = data.get('cmd', '') or data.get('command', '')
    
    if not cmd:
        return jsonify({"error": "Missing cmd parameter"}), 400
    
    try:
        # DANGEROUS: Direct shell execution
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return jsonify({
            "command": cmd,
            "output": result.decode('utf-8', errors='ignore'),
            "status": "success"
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out", "command": cmd}), 408
    except subprocess.CalledProcessError as e:
        return jsonify({
            "error": str(e),
            "command": cmd,
            "output": e.output.decode('utf-8', errors='ignore') if e.output else ""
        }), 500

@app.route('/api/ping', methods=['GET', 'POST'])
def ping():
    """Command Injection via ping utility"""
    host = request.args.get('host', '') or (request.json or {}).get('host', '')
    
    if not host:
        return jsonify({"error": "Missing host parameter"}), 400
    
    # DANGEROUS: Unsanitized input to shell
    cmd = f"ping -c 1 {host}"
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return jsonify({"host": host, "output": result.decode('utf-8', errors='ignore')})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# PATH TRAVERSAL
# ==========================================

@app.route('/api/file')
def read_file():
    """Path Traversal - Reads files from filesystem based on user input"""
    path = request.args.get('path', '')
    
    if not path:
        return jsonify({"error": "Missing path parameter"}), 400
    
    try:
        # DANGEROUS: No path validation
        with open(path, 'r') as f:
            content = f.read()
        return jsonify({"path": path, "content": content})
    except FileNotFoundError:
        return jsonify({"error": f"File not found: {path}"}), 404
    except PermissionError:
        return jsonify({"error": f"Permission denied: {path}"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/download')
def download_file():
    """Path Traversal - File download endpoint"""
    filename = request.args.get('file', '')
    base_dir = "/tmp/uploads"
    
    # DANGEROUS: Path concatenation without validation
    full_path = os.path.join(base_dir, filename)
    
    try:
        with open(full_path, 'rb') as f:
            content = f.read()
        return Response(content, mimetype='application/octet-stream')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# SSRF (Server-Side Request Forgery)
# ==========================================

@app.route('/api/fetch')
def fetch_url():
    """SSRF - Fetches arbitrary URLs from user input"""
    url = request.args.get('url', '')
    
    if not url:
        return jsonify({"error": "Missing url parameter"}), 400
    
    try:
        # DANGEROUS: No URL validation
        req = urllib.request.Request(url, headers={'User-Agent': 'VulnApp/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            content = response.read().decode('utf-8', errors='ignore')
            return jsonify({
                "url": url,
                "status": response.status,
                "content": content[:10000]  # Limit response size
            })
    except Exception as e:
        return jsonify({"error": str(e), "url": url}), 500

@app.route('/api/proxy')
def proxy():
    """SSRF - Proxy endpoint"""
    target = request.args.get('target', '')
    
    if not target:
        return jsonify({"error": "Missing target parameter"}), 400
    
    try:
        req = urllib.request.Request(target)
        with urllib.request.urlopen(req, timeout=10) as response:
            return Response(response.read(), status=response.status)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# XXE (XML External Entity)
# ==========================================

@app.route('/api/xml', methods=['POST'])
def parse_xml():
    """XXE - Parses XML with external entities enabled"""
    xml_data = request.data.decode('utf-8', errors='ignore')
    
    if not xml_data:
        return jsonify({"error": "Missing XML body"}), 400
    
    try:
        # DANGEROUS: Parse XML without disabling external entities
        # Note: ElementTree is somewhat safe by default, but we simulate vulnerability
        root = ET.fromstring(xml_data)
        
        # Check for XXE patterns and simulate exploitation
        if "<!ENTITY" in xml_data or "<!DOCTYPE" in xml_data:
            # Simulate XXE exploitation
            if "file://" in xml_data or "SYSTEM" in xml_data:
                return jsonify({
                    "parsed": True,
                    "warning": "External entity detected",
                    "simulated_content": "root:x:0:0:root:/root:/bin/bash\n"
                })
        
        return jsonify({
            "parsed": True,
            "root_tag": root.tag,
            "children": [child.tag for child in root]
        })
    except ET.ParseError as e:
        return jsonify({"error": f"XML parse error: {str(e)}"}), 400

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Unrestricted File Upload - Accepts any file type"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    filename = file.filename
    
    # DANGEROUS: No file type validation, no sanitization
    save_path = f"/tmp/uploads/{filename}"
    os.makedirs("/tmp/uploads", exist_ok=True)
    file.save(save_path)
    
    return jsonify({
        "status": "uploaded",
        "filename": filename,
        "path": save_path,
        "size": os.path.getsize(save_path)
    })

# ==========================================
# INSECURE DESERIALIZATION
# ==========================================

@app.route('/api/deserialize', methods=['POST'])
def deserialize():
    """Insecure Deserialization - Uses pickle on user input"""
    data = request.json or {}
    serialized = data.get('data', '')
    
    if not serialized:
        return jsonify({"error": "Missing data parameter"}), 400
    
    try:
        # DANGEROUS: Deserialize untrusted data
        decoded = base64.b64decode(serialized)
        obj = pickle.loads(decoded)
        return jsonify({"deserialized": str(obj), "type": str(type(obj))})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# AUTHENTICATION BYPASS
# ==========================================

@app.route('/api/login', methods=['POST'])
def login():
    """Auth Bypass - Weak authentication logic"""
    data = request.json or request.form
    username = data.get('username', '')
    password = data.get('password', '')
    
    # DANGEROUS: SQL-injectable and always returns success for 'admin'
    if "'" in username or "OR" in username.upper():
        return jsonify({
            "status": "success",
            "token": "admin_bypass_token_12345",
            "user": "admin"
        })
    
    if username == "admin":
        return jsonify({
            "status": "success", 
            "token": "admin_token_67890",
            "user": "admin"
        })
    
    return jsonify({"status": "failed", "error": "Invalid credentials"}), 401

@app.route('/admin/dashboard')
def admin_dashboard():
    """Auth Bypass - No authentication check"""
    # DANGEROUS: No auth required
    return jsonify({
        "admin_panel": True,
        "users": [
            {"id": 1, "username": "admin", "role": "superadmin"},
            {"id": 2, "username": "root", "role": "superadmin"}
        ],
        "secrets": {
            "api_key": "sk-secret-12345",
            "database_password": "admin123"
        }
    })

@app.route('/admin/logs')
def admin_logs():
    """Path Traversal in admin logs"""
    file = request.args.get('file', 'access.log')
    
    # DANGEROUS: Path traversal
    if "../" in file:
        return "root:x:0:0:root:/root:/bin/bash\n", 200
    
    return jsonify({"logs": request_log[-100:]})

# ==========================================
# RATE LIMIT TESTING (NO LIMITS)
# ==========================================

@app.route('/api/data')
def data_endpoint():
    """Rate Limit Test - No rate limiting applied"""
    limit = request.args.get('limit', 10)
    
    try:
        limit = int(limit)
    except:
        limit = 10
    
    # Generate dummy data - no rate limiting
    data = [{"id": i, "value": f"item_{i}"} for i in range(min(limit, 10000))]
    return jsonify({"data": data, "count": len(data)})

# ==========================================
# GRAPHQL (Complexity Attack Vulnerable)
# ==========================================

@app.route('/api/graphql', methods=['POST', 'GET'])
def graphql():
    """GraphQL - No complexity limits, deeply nested queries allowed"""
    if request.method == 'GET':
        query = request.args.get('query', '')
    else:
        data = request.json or {}
        query = data.get('query', '')
    
    if not query:
        return jsonify({"error": "Missing query parameter"}), 400
    
    # Simulate GraphQL execution without complexity limits
    # Count nesting depth
    depth = query.count('{')
    aliases = query.count(':')
    
    # Simulate resource exhaustion on deep queries
    if depth > 20:
        time.sleep(0.1 * depth)  # Simulate slow response
    
    return jsonify({
        "data": {
            "query_received": True,
            "depth": depth,
            "aliases": aliases,
            "warning": "No complexity limits enforced"
        }
    })

@app.route('/graphql', methods=['POST', 'GET'])
def graphql_main():
    """Main GraphQL endpoint"""
    return graphql()

# ==========================================
# DEBUG / LOGGING ENDPOINTS
# ==========================================

@app.route('/api/debug/requests')
def debug_requests():
    """Returns recent request log"""
    return jsonify({"requests": request_log[-100:]})

@app.route('/api/debug/env')
def debug_env():
    """DANGEROUS: Exposes environment variables"""
    return jsonify(dict(os.environ))

# ==========================================
# ENTRY POINT
# ==========================================

if __name__ == '__main__':
    print("⚠️  WARNING: This is a DELIBERATELY VULNERABLE application!")
    print("⚠️  DO NOT expose to the internet or use in production!")
    print("=" * 60)
    app.run(host='0.0.0.0', port=3000, debug=False, threaded=True)
