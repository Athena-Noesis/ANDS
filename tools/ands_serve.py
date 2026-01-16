#!/usr/bin/env python3
"""ands_serve.py — Production-ready server for ANDS declarations.

Provides zero-code compliance for AI vendors.
"""

import argparse
import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class ANDSProvider(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/ands.json":
            self.serve_file(self.server.ands_path)
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>ANDS Declaration Provider</h1><p>Compliant 1.0</p>")
        else:
            self.send_response(404)
            self.end_headers()

    def serve_file(self, path):
        try:
            with open(path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode('utf-8'))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", help="Path to ands.json declaration")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File {args.file} not found.")
        sys.exit(1)

    server_address = (args.host, args.port)
    httpd = HTTPServer(server_address, ANDSProvider)
    httpd.ands_path = args.file

    print(f"🚀 ANDS Launchpad engaged!")
    print(f"Serving {args.file} at http://{args.host}:{args.port}/.well-known/ands.json")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutdown.")

if __name__ == "__main__":
    main()
