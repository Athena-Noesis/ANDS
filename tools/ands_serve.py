#!/usr/bin/env python3
"""ands_serve.py — Production-ready server for ANDS declarations.

Provides zero-code compliance for AI vendors.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler

class ANDSProvider(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/ands.json":
            self.serve_file(self.server.ands_path)
        elif self.path == "/ands-report":
            self.serve_report()
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>ANDS Launchpad</h1><p><a href='/ands-report'>Executive Scorecard</a> | <a href='/.well-known/ands.json'>JSON Declaration</a></p>")
        else:
            self.send_response(404)
            self.end_headers()

    def serve_report(self):
        # Dynamically generate scorecard based on local file
        try:
            # We "scan" ourselves locally
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
                report_path = tf.name

            # Simplified "self-scan" logic using current tools
            # Note: For production we would use a library call, but this ensures tool consistency
            cmd = [sys.executable, "tools/ands_scan.py", f"http://localhost:{self.server.server_port}", "--out", report_path]
            subprocess.run(cmd, capture_output=True)

            with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as hf:
                html_path = hf.name

            cmd_render = [sys.executable, "tools/report/render_report.py", report_path, "--template", "certificate", "--out", html_path]
            subprocess.run(cmd_render, capture_output=True)

            with open(html_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

            os.unlink(report_path)
            os.unlink(html_path)
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Error generating scorecard: {e}".encode('utf-8'))

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
