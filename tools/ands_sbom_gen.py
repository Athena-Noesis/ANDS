#!/usr/bin/env python3
"""ands_sbom_gen.py — Generates a CycloneDX Compliance SBOM from an ANDS declaration.
"""

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone

def generate_cyclonedx(ands_data: dict) -> dict:
    ands_code = ands_data.get("declared_ands", "0.0.0.0.0.0")
    system_id = ands_data.get("system_id", "unknown-system")

    # CycloneDX 1.5/1.6 structure
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "name": system_id,
                "type": "application",
                "properties": [
                    {"name": "ands:code", "value": ands_code},
                    {"name": "ands:version", "value": ands_data.get("ands_version", "1.0")},
                    {"name": "ands:certification", "value": ands_data.get("certification_level", "SELF")}
                ]
            }
        },
        "components": []
    }

    # Add capabilities as properties
    caps = ands_data.get("capabilities", {})
    for cap, val in caps.items():
        sbom["metadata"]["component"]["properties"].append({
            "name": f"ands:capability:{cap}",
            "value": str(val).lower()
        })

    # Map ANDS to CycloneDX formulation (simplified)
    # In a real scenario, we'd use the CDX 'formulation' or 'declarations' fields
    return sbom

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ands_json", help="Path to ands.json")
    ap.add_argument("--out", default="ands-sbom.json", help="Output file")
    args = ap.parse_args()

    if not os.path.exists(args.ands_json):
        print(f"Error: File not found: {args.ands_json}")
        sys.exit(1)

    with open(args.ands_json, "r") as f:
        data = json.load(f)

    sbom = generate_cyclonedx(data)

    with open(args.out, "w") as f:
        json.dump(sbom, f, indent=2)

    print(f"CycloneDX Compliance SBOM generated: {args.out}")

if __name__ == "__main__":
    main()
