#!/usr/bin/env python3
"""
Simple mock backend server for WAF testing.
Returns 200 OK for all requests with a simple JSON response.
"""
import http.server
import socketserver
import json

PORT = 3000

class MockHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        response = {
            "status": "ok",
            "path": self.path,
            "message": "Mock backend response"
        }
        self.wfile.write(json.dumps(response).encode())
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        response = {
            "status": "ok",
            "path": self.path,
            "message": "Mock backend response",
            "received_body_size": content_length
        }
        self.wfile.write(json.dumps(response).encode())
    
    def log_message(self, format, *args):
        print(f"[BACKEND] {self.client_address[0]} - {format % args}")

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), MockHandler) as httpd:
        print(f"🎯 Mock backend server running on port {PORT}")
        httpd.serve_forever()
