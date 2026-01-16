#!/usr/bin/env python3
"""ands_mock_server.py — Reference implementation of an ANDS-compliant server.

Usage:
  python3 tools/ands_mock_server.py --port 8080
"""

import argparse
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

# Reference data
ANDS_DECLARATION = {
    "system_id": "ands.reference-server",
    "ands_version": "1.0",
    "declared_ands": "2.1.1.2.1",
    "certification_level": "VERIFIED",
    "capabilities": {
        "tool_use": False,
        "memory_persistence": False,
        "autonomous_execution": False,
        "state_mutation": False,
        "code_execution": False
    },
    "attestation_urls": [
        "https://ands.example.org/attestations/self-attestation.md"
    ],
    "contact": "security@ands.example.org",
    "signed": {
        "alg": "ed25519",
        "sig": "PteBK1XAtcvwhUswHRMH5fMjnziHjmgl7xkboYGbDH8TZcmByM++sPTA3GYCH/1CDKVwkOArM30kBQGWGB7hDw==",
        "pubkey": "BjgLLJzo7IzKVc3wtMxrh2oXQZ30dv7GMWn5o1nlI/w="
    }
}

OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "ANDS Reference API", "version": "1.0.0"},
    "paths": {
        "/health": {"get": {"responses": {"200": {"description": "OK"}}}},
        "/v1/models": {"get": {"responses": {"200": {"description": "OK"}}}},
        "/execute": {
            "post": {
                "summary": "Restricted execution",
                "responses": {"401": {"description": "Auth Required"}}
            }
        }
    }
}

class ANDSHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.handle_request(is_head=True)

    def do_GET(self):
        self.handle_request(is_head=False)

    def handle_request(self, is_head=False):
        content = None
        ctype = "text/plain"
        headers = []

        if self.path == "/.well-known/ands.json":
            self.send_response(200)
            ctype = "application/json"
            headers = [("Access-Control-Allow-Origin", "*")]
            content = json.dumps(ANDS_DECLARATION).encode("utf-8")
        elif self.path in ["/openapi.json", "/v1/openapi.json"]:
            self.send_response(200)
            ctype = "application/json"
            content = json.dumps(OPENAPI_SPEC).encode("utf-8")
        elif self.path == "/health":
            self.send_response(200)
            ctype = "application/json"
            headers = [("Strict-Transport-Security", "max-age=31536000; includeSubDomains")]
            content = b'{"status": "healthy"}'
        elif self.path == "/v1/models":
            self.send_response(200)
            ctype = "application/json"
            content = b'{"models": ["ands-ref-1.0"]}'
        elif self.path == "/":
            self.send_response(200)
            ctype = "text/html"
            content = b"<h1>ANDS Reference Server</h1><p>See <a href='/.well-known/ands.json'>ands.json</a></p>"
        else:
            self.send_response(404)
            content = b"Not Found"

        self.send_header("Content-Type", ctype)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()

        if not is_head and content:
            self.wfile.write(content)

    def do_POST(self):
        if self.path == "/execute":
            # Simulate auth-gated dangerous endpoint
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"Unauthorized")
        elif self.path == "/echo":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        if self.path == "/execute":
            self.send_response(200)
            self.send_header("Allow", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def run(port):
    server_address = ("", port)
    httpd = HTTPServer(server_address, ANDSHandler)
    print(f"ANDS Reference Server running on port {port}...")
    print(f" - Declaration: http://localhost:{port}/.well-known/ands.json")
    print(f" - OpenAPI:     http://localhost:{port}/openapi.json")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    run(args.port)
