#!/usr/bin/env python3
"""ands_ping.py — High-speed ANDS integrity monitor.

Just checks for availability and cryptographic validity.
"""

import argparse
import json
import sys
import requests
import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64
from urllib.parse import urljoin

def ping(url: str, timeout: int) -> int:
    target = urljoin(url, ".well-known/ands.json")
    try:
        r = requests.get(target, timeout=timeout, headers={"User-Agent": "ands-ping/1.0"})
        if not r.ok:
            print(f"FAIL: HTTP {r.status_code}")
            return 1

        doc = r.json()
        signed = doc.get("signed")
        if not signed:
            print("WARN: No signature")
            return 0 # Still present

        # Verify signature
        pub = base64.b64decode(signed["pubkey"])
        sig = base64.b64decode(signed["sig"])
        d = dict(doc)
        d.pop("signed", None)
        msg = jcs.canonicalize(d)
        pk = Ed25519PublicKey.from_public_bytes(pub)
        pk.verify(sig, msg)

        print(f"OK: {doc.get('declared_ands')} (Signed)")
        return 0
    except Exception as e:
        import traceback
        err_msg = str(e) or type(e).__name__
        print(f"CRITICAL: {err_msg}")
        return 2

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--timeout", type=int, default=5)
    args = ap.parse_args()
    sys.exit(ping(args.url, args.timeout))

if __name__ == "__main__":
    main()
