import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import jcs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ands.utils import logger, SchemaRegistry
from ands.validator import validate_schema

def main():
    parser = argparse.ArgumentParser(prog="ands sign", description="Sign or append signatures to an ANDS declaration")
    parser.add_argument("file", help="Path to ands.json declaration")
    parser.add_argument("--role", choices=["vendor", "auditor", "legal", "regulator"], default="vendor", help="Role of the signer")
    parser.add_argument("--name", help="Name of the signer/organization")
    parser.add_argument("--key", required=True, help="Base64 encoded Ed25519 private key")
    parser.add_argument("--out", help="Output path (default: overwrite input)")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing signature for this role")

    args = parser.parse_args(sys.argv[1:])

    input_path = Path(args.file)
    if not input_path.exists():
        print(f"Error: File {input_path} not found.")
        return 1

    try:
        with open(input_path, "r") as f:
            doc = json.load(f)
    except Exception as e:
        print(f"Error reading file: {e}")
        return 1

    # Ensure version is at least 1.2
    version = doc.get("ands_version", "1.0")
    if version < "1.2":
        print(f"Error: Multi-signature support requires ANDS 1.2+. Current version: {version}")
        print("Please run 'ands migrate' first.")
        return 1

    # Load private key
    try:
        priv_bytes = base64.b64decode(args.key)
        priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    except Exception as e:
        print(f"Error loading private key: {e}")
        return 1

    pub = priv.public_key()
    pub_b64 = base64.b64encode(pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode('utf-8')

    # Prepare data for signing (remove signatures for canonicalization)
    doc_to_sign = dict(doc)
    doc_to_sign.pop("signatures", None)
    doc_to_sign.pop("signed", None) # legacy

    msg = jcs.canonicalize(doc_to_sign)
    sig = priv.sign(msg)
    sig_b64 = base64.b64encode(sig).decode('utf-8')

    # Build signature object
    sig_obj = {
        "role": args.role,
        "signer": args.name or doc.get("system_id", "Unknown"),
        "sig": sig_b64,
        "alg": "ed25519",
        "pubkey": pub_b64,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    # Append or update signatures array
    if "signatures" not in doc:
        doc["signatures"] = []

    if args.overwrite:
        doc["signatures"] = [s for s in doc["signatures"] if s.get("role") != args.role]

    doc["signatures"].append(sig_obj)

    # Validate against schema before saving
    is_valid, msg = validate_schema(doc)
    if not is_valid:
        print(f"Warning: Signed declaration failed schema validation: {msg}")

    output_path = Path(args.out) if args.out else input_path
    try:
        with open(output_path, "w") as f:
            json.dump(doc, f, indent=2)
        print(f"✅ Successfully added signature for role: {args.role}")
        print(f"Total signatures: {len(doc['signatures'])}")
    except Exception as e:
        print(f"Error writing file: {e}")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
