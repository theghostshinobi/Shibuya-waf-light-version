#!/usr/bin/env python3
"""
Intentionally Vulnerable Target Application for WAF Testing.
This app is DELIBERATELY vulnerable - never use in production!
Runs on port 3000 as the WAF upstream target.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse

class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        response = {
            "status": "ok",
            "path": self.path,
            "params": {k: v[0] if len(v) == 1 else v for k, v in params.items()},
            "message": "Vulnerable target responding"
        }
        self.wfile.write(json.dumps(response).encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='replace') if content_length > 0 else ''
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {
            "status": "ok",
            "path": self.path,
            "body_received": body[:500],
            "message": "Vulnerable target processed POST"
        }
        self.wfile.write(json.dumps(response).encode())

    def do_PUT(self):
        self.do_POST()

    def do_DELETE(self):
        self.do_GET()

    def do_PATCH(self):
        self.do_POST()

    def log_message(self, format, *args):
        pass  # Suppress request logs

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 3000), VulnerableHandler)
    print("🎯 Vulnerable target running on http://localhost:3000")
    server.serve_forever()
