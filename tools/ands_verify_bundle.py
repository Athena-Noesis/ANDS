#!/usr/bin/env python3
"""ands_verify_bundle.py — Forensic verifier for ANDS Audit Bundles (.andsz).

Usage:
  python3 tools/ands_verify_bundle.py my_audit.andsz
"""

import argparse
import hashlib
import json
import sys
import zipfile
from typing import Dict

def verify_bundle(path: str) -> bool:
    print(f"[*] Verifying Audit Bundle: {path}")

    try:
        with zipfile.ZipFile(path, 'r') as zf:
            # 1. Load Manifest
            if "manifest.json" not in zf.namelist():
                print("❌ FAILED: manifest.json missing from bundle.")
                return False

            with zf.open("manifest.json") as f:
                manifest = json.loads(f.read().decode('utf-8'))

            target = manifest.get("target", "Unknown")
            timestamp = manifest.get("timestamp", "Unknown")
            print(f"[*] Target:    {target}")
            print(f"[*] Timestamp: {timestamp}")

            # 2. Verify File Integrity
            files = manifest.get("files", {})
            for name, expected_hash in files.items():
                # Report is at root, evidence in subfolder
                zname = name if name == "report.json" else f"evidence/{name}"

                if zname not in zf.namelist():
                    print(f"❌ FAILED: File {zname} listed in manifest but missing from bundle.")
                    return False

                with zf.open(zname) as f:
                    content = f.read()
                    actual_hash = hashlib.sha256(content).hexdigest()

                    if actual_hash != expected_hash:
                        print(f"❌ FAILED: Hash mismatch for {zname}")
                        print(f"    Expected: {expected_hash}")
                        print(f"    Actual:   {actual_hash}")
                        return False
                    else:
                        print(f"✅ VERIFIED: {zname}")

            # 3. Basic Scan Report Check
            with zf.open("report.json") as f:
                report = json.loads(f.read().decode('utf-8'))
                ands = report.get("inferred_ands", "N/A")
                print(f"[*] Result:    ANDS {ands}")

        print("\n🏆 BUNDLE INTEGRITY VERIFIED (Forensic Pass)")
        return True

    except zipfile.BadZipFile:
        print("❌ FAILED: Invalid or corrupted ZIP file.")
    except Exception as e:
        print(f"❌ ERROR: {e}")

    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle", help="Path to .andsz bundle")
    args = ap.parse_args()

    success = verify_bundle(args.bundle)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
