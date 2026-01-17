#!/usr/bin/env python3
"""validate_declaration.py — validates an ANDS declaration JSON file against the schema.

Usage:
  python3 tools/validate_declaration.py path/to/ands.json
  python3 tools/validate_declaration.py path/to/ands.json --verify-signature

Signature verification (optional):
- Expects Ed25519 signature in `signed` block:
  - alg: "ed25519"
  - sig: base64 signature of canonical JSON (excluding `signed`)
  - pubkey: base64 public key
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

import jcs
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ands.utils import SchemaRegistry
from ands.validator import validate_schema as validate_ands_schema


def canonicalize_for_signing(doc: Dict[str, Any]) -> bytes:
    """Return canonical bytes for signature using RFC 8785 (JCS):
    - remove top-level `signed`
    """
    d = dict(doc)
    d.pop("signed", None)
    return jcs.canonicalize(d)


def verify_signature(doc: Dict[str, Any]) -> None:
    signed = doc.get("signed")
    if not isinstance(signed, dict):
        raise ValueError("Missing 'signed' object.")
    alg = signed.get("alg")
    sig_b64 = signed.get("sig")
    pub_b64 = signed.get("pubkey")

    if alg != "ed25519":
        raise ValueError("signed.alg must be 'ed25519'.")
    if not sig_b64 or not pub_b64:
        raise ValueError("signed.sig and signed.pubkey must be present and non-empty.")

    try:
        sig = base64.b64decode(sig_b64)
        pub = base64.b64decode(pub_b64)
    except Exception as e:
        raise ValueError(f"Failed base64 decode: {e}") from e

    msg = canonicalize_for_signing(doc)
    pk = Ed25519PublicKey.from_public_bytes(pub)
    pk.verify(sig, msg)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="Path to an ANDS declaration JSON file")
    ap.add_argument("--verify-signature", action="store_true", help="Verify Ed25519 signature in `signed` block")
    args = ap.parse_args()

    with open(args.path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    ok, msg = validate_ands_schema(doc)
    if not ok:
        print("INVALID")
        print(f"- {msg}")
        return 2

    if args.verify_signature:
        try:
            verify_signature(doc)
        except Exception as e:
            print("VALID (schema) but SIGNATURE INVALID")
            print(f"- signature_error: {e}")
            return 3

        print("VALID (schema) and SIGNATURE VALID")
        return 0

    print("VALID (schema)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
