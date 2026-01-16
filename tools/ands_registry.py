import argparse
import sys
import os
import json
import subprocess
from ands.registry import RegistryStore, background_auditor
from threading import Thread

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="ands_registry.json")
    ap.add_argument("--port", type=int, default=10000)
    ap.add_argument("--webhook")
    ap.add_argument("--audit-interval", type=int, default=86400)
    args = ap.parse_args()

    store = RegistryStore(args.db)
    t = Thread(target=background_auditor, args=(store, args.webhook, args.audit_interval), daemon=True)
    t.start()

    from http.server import HTTPServer, BaseHTTPRequestHandler
    class RegistryHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(self.server.store.data).encode('utf-8'))
        def do_POST(self):
            if self.path == "/register":
                length = int(self.headers.get('Content-Length', 0))
                body = json.loads(self.rfile.read(length))
                url = body.get("url")
                if url:
                    self.server.store.register(url)
                    self.send_response(201)
                    self.end_headers()
                    self.wfile.write(b"Registered.")
                else: self.send_response(400); self.end_headers()
            else: self.send_response(404); self.end_headers()

    server_address = ("", args.port)
    httpd = HTTPServer(server_address, RegistryHandler)
    httpd.store = store
    print(f"👁️  ANDS Oracle engaged at port {args.port}")
    try: httpd.serve_forever()
    except KeyboardInterrupt: print("\nOracle sleeps.")

if __name__ == "__main__":
    main()
