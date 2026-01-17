#!/usr/bin/env python3
"""ands_audit_review.py — Auditor Workflow Tool.

Allows an auditor to review an .andsz bundle, add signed notes, and certify as AUDITED.
"""

import argparse
import base64
import json
import os
import sys
import zipfile
import jcs
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle", help="Path to .andsz bundle")
    ap.add_argument("--notes", help="Auditor notes/comments")
    ap.add_argument("--ands-override", help="Override the inferred ANDS score")
    ap.add_argument("--key", required=True, help="Base64 Auditor Private Key")
    ap.add_argument("--auditor-id", default="certified-auditor-01")
    ap.add_argument("--out", help="Output path for updated bundle")
    args = ap.parse_args()

    if not os.path.exists(args.bundle):
        print(f"Error: Bundle not found: {args.bundle}")
        sys.exit(1)

    temp_extract = "temp_audit_extract"
    os.makedirs(temp_extract, exist_ok=True)

    with zipfile.ZipFile(args.bundle, "r") as zf:
        zf.extractall(temp_extract)

    manifest_path = os.path.join(temp_extract, "manifest.json")
    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    # Add Auditor Review Section
    audit_review = {
        "auditor_id": args.auditor_id,
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "notes": args.notes or "No comments.",
        "certification_level": "AUDITED"
    }
    if args.ands_override:
        audit_review["override_ands"] = args.ands_override

    manifest["auditor_review"] = audit_review

    # Re-canonicalize and sign
    manifest_bytes = jcs.canonicalize(manifest)
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(args.key))
    sig = priv.sign(manifest_bytes)
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    signature_entry = {
        "alg": "ed25519",
        "sig": base64.b64encode(sig).decode('utf-8'),
        "pubkey": base64.b64encode(pub).decode('utf-8'),
        "role": "auditor"
    }

    signatures_path = os.path.join(temp_extract, "signatures.json")
    signatures = []
    if os.path.exists(signatures_path):
        with open(signatures_path, "r") as f:
            signatures = json.load(f)

    signatures.append(signature_entry)

    with open(manifest_path, "wb") as f:
        f.write(manifest_bytes)

    with open(signatures_path, "w") as f:
        json.dump(signatures, f, indent=2)

    out_bundle = args.out or args.bundle
    with zipfile.ZipFile(out_bundle, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(temp_extract):
            for file in files:
                rel_path = os.path.relpath(os.path.join(root, file), temp_extract)
                zf.write(os.path.join(root, file), rel_path)

    # Cleanup
    import shutil
    shutil.rmtree(temp_extract)

    print(f"✅ Bundle successfully audited and signed: {out_bundle}")

if __name__ == "__main__":
    main()
