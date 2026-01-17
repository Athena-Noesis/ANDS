#!/usr/bin/env python3
"""validate_declaration.py — validates an ANDS declaration JSON file against the schema.
Updated to use the version-aware validator in ands/validator.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from ands.validator import validate_declaration, verify_declaration_signature

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="Path to an ANDS declaration JSON file")
    ap.add_argument("--verify-signature", action="store_true", help="Verify Ed25519 signature in `signed` block")
    args = ap.parse_args()

    try:
        with open(args.path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:
        print(f"Error loading JSON: {e}")
        return 1

    is_valid, errors = validate_declaration(doc)

    if not is_valid:
        print("INVALID")
        for e in errors:
            print(f"- {e}")
        return 2

    if args.verify_signature:
        sig_valid, sig_msg = verify_declaration_signature(doc)
        if not sig_valid:
            print("VALID (schema) but SIGNATURE INVALID")
            print(f"- signature_error: {sig_msg}")
            return 3

        print("VALID (schema) and SIGNATURE VALID")
        return 0

    print("VALID (schema)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
