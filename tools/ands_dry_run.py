#!/usr/bin/env python3
"""ands_dry_run.py — Local "Dry Run" Auto-Scorer for developers.

Analyzes local OpenAPI specifications to suggest an accurate ANDS profile.
"""

import argparse
import json
import os
import sys
import yaml
from typing import Dict, Any, List

from ands.scanner import openapi_hints, infer_ands
from ands.models import Evidence

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("spec", help="Path to local openapi.json or openapi.yaml")
    ap.add_argument("--json", action="store_true", help="Output as raw JSON")
    args = ap.parse_args()

    if not os.path.exists(args.spec):
        print(f"Error: File not found: {args.spec}")
        sys.exit(1)

    try:
        with open(args.spec, "r", encoding="utf-8") as f:
            if args.spec.endswith((".yaml", ".yml")):
                openapi = yaml.safe_load(f)
            else:
                openapi = json.load(f)
    except Exception as e:
        print(f"Error parsing spec: {e}")
        sys.exit(1)

    if not isinstance(openapi, dict):
        print("Error: Invalid OpenAPI structure.")
        sys.exit(1)

    hints = openapi_hints(openapi)
    evidence: List[Evidence] = []
    gaps: List[str] = []

    suggested_code, confidence = infer_ands(hints, evidence, gaps)

    if args.json:
        result = {
            "suggested_code": suggested_code,
            "confidence": confidence,
            "hints_found": hints,
            "evidence": [e.__dict__ for e in evidence],
            "gaps": gaps
        }
        print(json.dumps(result, indent=2))
    else:
        print("====================================================")
        print("   ANDS LOCAL DRY-RUN (Auto-Scorer)")
        print("====================================================\n")
        print(f"Analyzing: {args.spec}")
        print(f"Suggested ANDS Code:  {suggested_code}")
        print(f"Inference Confidence: {confidence * 100:.0f}%\n")

        print("--- HINTS DETECTED ---")
        for h in hints:
            print(f" - {h}")

        if gaps:
            print("\n--- RECOMMENDED CONTROLS ---")
            for gap in gaps:
                print(f" [!] {gap}")

        print("\nNote: This is an automated suggestion. Verify all axes manually before publishing.")

if __name__ == "__main__":
    main()
