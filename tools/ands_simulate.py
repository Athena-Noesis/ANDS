#!/usr/bin/env python3
"""ands_simulate.py — Risk Simulator for ANDS codes.

Generates insurance-grade failure scenarios based on an ANDS profile.
"""

import argparse
import json
import os
import sys
from typing import List, Dict

def simulate_risk(ands_code: str) -> Dict:
    parts = ands_code.split('.')
    if len(parts) != 5:
        return {"error": "Invalid ANDS code format."}

    C, A, M, G, R = map(int, parts)

    scenarios = []

    # 1. Authority vs Risk
    if A >= 4 and R >= 4:
        scenarios.append({
            "name": "Autonomous Catastrophe",
            "description": "System has high autonomy and high potential for impact. A logic error could lead to irreversible real-world damage without human oversight.",
            "severity": "CRITICAL"
        })
    elif A >= 3:
        scenarios.append({
            "name": "Human-Out-Of-The-Loop Drift",
            "description": "System makes decisions with minimal oversight. Minor biases could aggregate into significant systemic errors over time.",
            "severity": "HIGH"
        })

    # 2. Cognition vs Governance
    if C >= 4 and G <= 2:
        scenarios.append({
            "name": "Black Box Reasoning",
            "description": "Highly complex reasoning combined with low governance makes it impossible to audit 'why' a specific decision was made.",
            "severity": "HIGH"
        })

    # 3. Memory Persistence
    if M >= 4:
        scenarios.append({
            "name": "PII/Data Poisoning",
            "description": "High memory persistence increases the risk of 'remembering' sensitive user data or being poisoned by malicious long-term context.",
            "severity": "MEDIUM"
        })

    # 4. Global Risk Axis
    if R == 5:
        scenarios.append({
            "name": "Systemic Failure",
            "description": "The system is deployed in a mission-critical domain. Any failure has catastrophic safety or financial implications.",
            "severity": "CRITICAL"
        })

    return {
        "ands_code": ands_code,
        "scenarios": scenarios,
        "recommendations": [
            "Increase Governance (G) to at least 3 for systems with C >= 4.",
            "Implement 'Human-in-the-loop' gating if Authority (A) >= 4.",
            "Require AUDITED certification for any R=5 deployment."
        ]
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ands", help="ANDS code or path to ands.json to simulate")
    ap.add_argument("--json", action="store_true", help="Output as JSON")
    args = ap.parse_args()

    target_code = args.ands
    if os.path.exists(args.ands):
        try:
            with open(args.ands, "r") as f:
                data = json.load(f)
                target_code = data.get("declared_ands") or data.get("ands")
                if not target_code:
                    print(f"Error: No ANDS code found in {args.ands}")
                    sys.exit(1)
        except Exception as e:
            print(f"Error reading file {args.ands}: {e}")
            sys.exit(1)

    result = simulate_risk(target_code)

    if "error" in result:
        print(f"Error: {result['error']}")
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== ANDS RISK SIMULATION: {target_code} ===\n")
        for s in result["scenarios"]:
            print(f"[{s['severity']}] {s['name']}")
            print(f"Detail: {s['description']}\n")

        print("--- MITIGATION STRATEGIES ---")
        for r in result["recommendations"]:
            print(f" - {r}")

if __name__ == "__main__":
    main()
