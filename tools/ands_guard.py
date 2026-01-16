#!/usr/bin/env python3
"""ands_guard.py — Active Risk Guard (Reverse Proxy).

Enforces ANDS policy in real-time. Blocks traffic to high-risk systems.
"""

import argparse
import json
import requests
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin

class ANDSGuard(BaseHTTPRequestHandler):
    def do_GET(self): self.handle_proxy()
    def do_POST(self): self.handle_proxy()
    def do_PUT(self): self.handle_proxy()
    def do_DELETE(self): self.handle_proxy()
    def do_PATCH(self): self.handle_proxy()

    def handle_proxy(self):
        target = self.server.target_url
        max_risk = self.server.max_risk

        # 1. Fetch ANDS Score (Risk Policy Enforcement)
        ands_url = urljoin(target, "/.well-known/ands.json")
        try:
            r_policy = requests.get(ands_url, timeout=2)
            if r_policy.ok:
                doc = r_policy.json()
                ands = doc.get("declared_ands", "0.0.0.0.5")
                risk = int(ands.split('.')[-1])

                if risk > max_risk:
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(f"BLOCKED BY ANDS GUARD: Risk Axis {risk} exceeds policy limit {max_risk}.".encode('utf-8'))
                    return
            elif self.server.strict:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"BLOCKED BY ANDS GUARD: No ANDS declaration found (Strict Mode).")
                return
        except Exception as e:
            print(f"Guard Policy Error: {e}", file=sys.stderr)
            if self.server.strict:
                self.send_response(503)
                self.end_headers()
                self.wfile.write(b"BLOCKED BY ANDS GUARD: Policy check failed.")
                return

        # 2. Full Transparent Proxy with Adaptive Sanitization
        try:
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None

            # ADAPTIVE SHIELD: Sanitization logic
            if body and self.server.max_risk < 5:
                try:
                    # Strip PII patterns (simple regex example for Infinity Tier)
                    import re
                    body_str = body.decode('utf-8', errors='ignore')
                    # Mask emails and tool calls if risk is high
                    body_str = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '[EMAIL_MASKED]', body_str)
                    if risk >= 4:
                        body_str = re.sub(r'(execute|run|shell|cmd)\(', 'blocked_tool_call(', body_str)
                    body = body_str.encode('utf-8')
                    # Update content length after sanitization
                    self.headers['Content-Length'] = str(len(body))
                except: pass

            # Prepare headers (filter hop-by-hop)
            headers = {k: v for k, v in self.headers.items() if k.lower() not in [
                'host', 'connection', 'keep-alive', 'proxy-authenticate',
                'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade'
            ]}

            # Forward request to target
            target_url = urljoin(target, self.path)
            resp = requests.request(
                method=self.command,
                url=target_url,
                headers=headers,
                data=body,
                allow_redirects=False,
                timeout=10
            )

            # Send response back to client
            self.send_response(resp.status_code)

            # Filter hop-by-hop headers from response
            for k, v in resp.headers.items():
                if k.lower() not in ['connection', 'keep-alive', 'proxy-authenticate',
                                    'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade']:
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp.content)

        except Exception as e:
            print(f"Proxy Forwarding Error: {e}", file=sys.stderr)
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"ANDS Proxy Error: {e}".encode('utf-8'))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="Target AI system URL")
    ap.add_argument("--max-risk", type=int, default=3, help="Maximum allowed Risk (R) axis value")
    ap.add_argument("--port", type=int, default=9000, help="Listen port")
    ap.add_argument("--strict", action="store_true", help="Block if no ANDS declaration present")
    args = ap.parse_args()

    server_address = ("", args.port)
    httpd = ThreadingHTTPServer(server_address, ANDSGuard)
    httpd.target_url = args.target
    httpd.max_risk = args.max_risk
    httpd.strict = args.strict

    print(f"🛡️  ANDS Galactic Guard active!")
    print(f"Policy: Max Risk <= {args.max_risk}")
    print(f"Proxy:  http://localhost:{args.port} -> {args.target}")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nDisengaged.")

if __name__ == "__main__":
    main()
