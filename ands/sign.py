import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict

import jcs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def load_private_key(path: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a file."""
    with open(path, 'rb') as f:
        data = f.read().strip()

    # Try base64 first
    try:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(data))
    except Exception:
        pass

    # Try PEM
    try:
        return serialization.load_pem_private_key(data, password=None)
    except Exception:
        pass

    raise ValueError(f"Could not load Ed25519 private key from {path}. Ensure it is base64 encoded raw bytes or a PEM file.")

def main():
    parser = argparse.ArgumentParser(prog="ands sign", description="Sign an ANDS signing request locally.")
    parser.add_argument("request_file", help="Path to the .ands_signreq.json file")
    parser.add_argument("--key", required=True, help="Path to the Ed25519 private key file")
    parser.add_argument("--signer", required=True, help="Name of the signer (e.g., 'Athena Auditor')")
    parser.add_argument("--out", help="Path to save the signed request (default: request_file.signed.json)")

    args = parser.parse_args()

    if not os.path.exists(args.request_file):
        print(f"Error: Request file {args.request_file} not found.")
        return 1

    try:
        with open(args.request_file, 'r', encoding='utf-8') as f:
            req = json.load(f)

        priv = load_private_key(args.key)
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        # Canonicalize the request for signing
        msg = jcs.canonicalize(req)
        sig = priv.sign(msg)

        timestamp = datetime.now(timezone.utc).isoformat()

        signed_payload = {
            "request": req,
            "signature": {
                "role": req.get("role", "unknown"),
                "signer": args.signer,
                "signature": base64.b64encode(sig).decode('utf-8'),
                "timestamp": timestamp,
                "key_id": f"ed25519:{base64.b64encode(pub[:8]).decode('utf-8')}", # Simple key ID
                "alg": "ed25519",
                "pubkey": base64.b64encode(pub).decode('utf-8')
            }
        }

        out_path = args.out or (args.request_file + ".signed.json")
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(signed_payload, f, indent=2)

        print(f"SUCCESS: Signed request saved to {out_path}")
        return 0

    except Exception as e:
        print(f"Error signing request: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
