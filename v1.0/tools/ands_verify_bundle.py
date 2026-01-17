#!/usr/bin/env python3
"""ands_verify_bundle.py — Forensic verifier for ANDS Audit Bundles (.andsz).

Usage:
  python3 tools/ands_verify_bundle.py my_audit.andsz
"""

import argparse
import base64
import hashlib
import json
import sys
import zipfile
from typing import Dict

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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

            # 3. Verify Auditor Signature(s) (Optional)
            found_sigs = 0
            valid_sigs = 0

            sig_files = ["signature.json", "signatures.json"]
            all_sigs = []

            for sf in sig_files:
                if sf in zf.namelist():
                    with zf.open(sf) as f:
                        data = json.loads(f.read().decode('utf-8'))
                        if isinstance(data, list): all_sigs.extend(data)
                        else: all_sigs.append(data)

            if all_sigs:
                # Manifest bytes are needed exactly as they were signed
                with zf.open("manifest.json") as f:
                    manifest_bytes = f.read()

                for sig_data in all_sigs:
                    found_sigs += 1
                    try:
                        pub_bytes = base64.b64decode(sig_data["pubkey"])
                        sig_bytes = base64.b64decode(sig_data["sig"])
                        pk = Ed25519PublicKey.from_public_bytes(pub_bytes)
                        pk.verify(sig_bytes, manifest_bytes)
                        print(f"✅ AUDITOR SIGNATURE VERIFIED: {sig_data['pubkey'][:16]}...")
                        valid_sigs += 1
                    except Exception as e:
                        print(f"❌ FAILED: Auditor signature invalid: {e}")

                print(f"[*] Council Status: {valid_sigs}/{found_sigs} valid signatures.")
                if valid_sigs == 0: return False
            else:
                print("[!] Warning: Bundle is not signed by any auditor.")

            # 4. Basic Scan Report Check
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
