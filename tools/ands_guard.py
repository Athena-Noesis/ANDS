#!/usr/bin/env python3
"""ands_guard.py — Active Risk Guard (Reverse Proxy).

Enforces ANDS policy in real-time. Blocks traffic to high-risk systems.
"""

import argparse
import json
import requests
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urljoin

class ANDSGuard(BaseHTTPRequestHandler):
    def do_POST(self):
        self.handle_proxy()

    def do_GET(self):
        self.handle_proxy()

    def handle_proxy(self):
        target = self.server.target_url
        max_risk = self.server.max_risk

        # 1. Fetch ANDS Score
        ands_url = urljoin(target, "/.well-known/ands.json")
        try:
            r = requests.get(ands_url, timeout=2)
            if r.ok:
                doc = r.json()
                ands = doc.get("declared_ands", "0.0.0.0.5") # Default to high risk if not found
                risk = int(ands.split('.')[-1])

                if risk > max_risk:
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(f"BLOCKED BY ANDS GUARD: Risk Axis {risk} exceeds policy limit {max_risk}.".encode('utf-8'))
                    return
            else:
                # If no ANDS declaration, block it if policy is strict
                if self.server.strict:
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b"BLOCKED BY ANDS GUARD: No ANDS declaration found (Strict Mode).")
                    return
        except Exception as e:
            print(f"Guard Error: {e}", file=sys.stderr)

        # 2. Forward request (Simplified proxy logic)
        try:
            # We don't implement a full proxy here for brevity,
            # but this shows the "Decision Engine" placement.
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"SUCCESS: Request allowed by ANDS policy.")
        except Exception as e:
            self.send_response(502)
            self.end_headers()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="Target AI system URL")
    ap.add_argument("--max-risk", type=int, default=3, help="Maximum allowed Risk (R) axis value")
    ap.add_argument("--port", type=int, default=9000, help="Listen port")
    ap.add_argument("--strict", action="store_true", help="Block if no ANDS declaration present")
    args = ap.parse_args()

    server_address = ("", args.port)
    httpd = HTTPServer(server_address, ANDSGuard)
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
