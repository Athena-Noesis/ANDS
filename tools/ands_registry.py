#!/usr/bin/env python3
"""ands_registry.py — Galactic Registry for ANDS-compliant systems.

Maintains a directory of trusted AI systems and manages their lifecycle.
"""

import argparse
import json
import os
import sys
import subprocess
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from typing import Dict, Optional

import requests

class RegistryStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.data = self.load()

    def load(self):
        if os.path.exists(self.db_path):
            with open(self.db_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"systems": {}}

    def save(self):
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)

    def register(self, url: str):
        self.data["systems"][url] = {
            "registered_at": time.time(),
            "last_scan": None,
            "status": "PENDING"
        }
        self.save()

class RegistryHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(self.server.store.data).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

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
            else:
                self.send_response(400)
                self.end_headers()

def fire_webhook(url: str, payload: Dict):
    try:
        requests.post(url, json=payload, timeout=5)
    except:
        pass

def background_auditor(store: RegistryStore, webhook_url: Optional[str] = None, interval_secs: int = 86400):
    """Periodically re-scans registered systems with staggered delays."""
    print(f"[*] Oracle background auditor started (Interval: {interval_secs}s).")
    while True:
        systems = list(store.data["systems"].keys())
        if not systems:
            time.sleep(60)
            continue

        for url in systems:
            print(f"[*] Auditing {url}...")
            old_ands = (store.data["systems"][url].get("last_scan") or {}).get("inferred_ands")

            # Use subprocess to call the scanner for isolation
            try:
                res = subprocess.run([sys.executable, "tools/ands_scan.py", url], capture_output=True, text=True)
                if res.returncode == 0:
                    report = json.loads(res.stdout)
                    new_ands = report.get("inferred_ands")

                    # Check for drift/alerts
                    if old_ands and new_ands and old_ands != new_ands:
                        print(f"[!] ALERT: Capability drift detected for {url} ({old_ands} -> {new_ands})")
                        if webhook_url:
                            fire_webhook(webhook_url, {
                                "event": "ands_drift",
                                "target": url,
                                "old_ands": old_ands,
                                "new_ands": new_ands,
                                "report": report
                            })

                    store.data["systems"][url]["last_scan"] = report
                    store.data["systems"][url]["status"] = "ACTIVE"
                else:
                    store.data["systems"][url]["status"] = "UNREACHABLE"
            except Exception as e:
                print(f"Error auditing {url}: {e}")

            store.save()
            # Stagger individual scans to prevent resource spikes
            time.sleep(5)

        time.sleep(interval_secs)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="ands_registry.json")
    ap.add_argument("--port", type=int, default=10000)
    ap.add_argument("--webhook", help="Webhook URL for drift alerts")
    ap.add_argument("--audit-interval", type=int, default=86400, help="Interval between full audits (seconds, default 24h)")
    args = ap.parse_args()

    store = RegistryStore(args.db)

    # Start auditor thread
    t = Thread(target=background_auditor, args=(store, args.webhook, args.audit_interval), daemon=True)
    t.start()

    server_address = ("", args.port)
    httpd = HTTPServer(server_address, RegistryHandler)
    httpd.store = store

    print(f"👁️  ANDS Oracle engaged at port {args.port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nOracle sleeps.")

if __name__ == "__main__":
    main()
