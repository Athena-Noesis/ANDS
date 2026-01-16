import json
import os
import time
import subprocess
import sys
from threading import Thread
from typing import Dict, Optional
import requests

class RegistryStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.data = self.load()
    def load(self):
        if os.path.exists(self.db_path):
            with open(self.db_path, "r", encoding="utf-8") as f: return json.load(f)
        return {"systems": {}}
    def save(self):
        with open(self.db_path, "w", encoding="utf-8") as f: json.dump(self.data, f, indent=2)
    def register(self, url: str):
        self.data["systems"][url] = {"registered_at": time.time(), "last_scan": None, "status": "PENDING"}
        self.save()

def fire_webhook(url: str, payload: Dict):
    try: requests.post(url, json=payload, timeout=5)
    except: pass

def background_auditor(store: RegistryStore, webhook_url: Optional[str] = None, interval_secs: int = 86400):
    print(f"[*] Oracle background auditor started (Interval: {interval_secs}s).")
    while True:
        systems = list(store.data["systems"].keys())
        if not systems:
            time.sleep(60)
            continue
        for url in systems:
            old_ands = (store.data["systems"][url].get("last_scan") or {}).get("inferred_ands")
            try:
                res = subprocess.run([sys.executable, "tools/ands_scan.py", url], capture_output=True, text=True)
                if res.returncode == 0:
                    report = json.loads(res.stdout)
                    new_ands = report.get("inferred_ands")
                    if old_ands and new_ands and old_ands != new_ands:
                        if webhook_url: fire_webhook(webhook_url, {"event": "ands_drift", "target": url, "old_ands": old_ands, "new_ands": new_ands, "report": report})
                    store.data["systems"][url]["last_scan"] = report
                    store.data["systems"][url]["status"] = "ACTIVE"
                else: store.data["systems"][url]["status"] = "UNREACHABLE"
            except: pass
            store.save()
            time.sleep(5)
        time.sleep(interval_secs)
