import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional
from dataclasses import asdict

from .models import ScanReport, ComplianceReport
from .policy_engine import PolicyEngine
from .scanner import main as scanner_main
from .utils import logger

def main():
    parser = argparse.ArgumentParser(prog="ands audit", description="Evaluate compliance against regulatory frameworks.")
    parser.add_argument("--file", help="Path to an ANDS declaration or scan report JSON file.")
    parser.add_argument("--scan", help="Target URL to perform a fresh scan before auditing.")
    parser.add_argument("--policy", default="eu_ai_act", help="Policy framework to use (default: eu_ai_act).")
    parser.add_argument("--out", help="Path to save the audit report.")
    parser.add_argument("--overrides", help="Path to a JSON file containing auditor overrides.")

    args, extra = parser.parse_known_args()

    report = None

    if args.scan:
        # Perform fresh scan
        # We need to capture the output of scanner_main or refactor it to return the report object
        # For now, let's assume we can run it and it writes to a temp file or we can call it.
        # Actually, it's better to refactor scanner.py's main to return the report.
        # But since I can't easily refactor it right now without risk, I'll use a temp file.
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        # Patch sys.argv to call scanner
        old_argv = sys.argv
        sys.argv = ["ands scan", args.scan, "--out", tmp_path] + extra
        try:
            scanner_main()
            with open(tmp_path, 'r') as f:
                data = json.load(f)
                # Ensure it's a ScanReport-like dict
                report = ScanReport(**{k: v for k, v in data.items() if k in ScanReport.__dataclass_fields__})
        finally:
            sys.argv = old_argv
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    elif args.file:
        with open(args.file, 'r') as f:
            data = json.load(f)
            # It could be a declaration or a scan report
            if "target" in data:
                # Likely a scan report
                report = ScanReport(**{k: v for k, v in data.items() if k in ScanReport.__dataclass_fields__})
            else:
                # Likely a declaration, wrap it in a minimal ScanReport
                report = ScanReport(
                    target="local-file",
                    reachable=True,
                    declared_ands=data.get("declared_ands"),
                    declared_certification_level=data.get("certification_level"),
                    inferred_ands=None,
                    confidence=1.0,
                    evidence=[],
                    gaps=[],
                    recommendations=[],
                    probes=[]
                )
    else:
        print("Error: Either --file or --scan must be provided.")
        parser.print_help()
        return 1

    # Load overrides if provided
    overrides = []
    if args.overrides and os.path.exists(args.overrides):
        with open(args.overrides, 'r') as f:
            overrides = json.load(f)

    engine = PolicyEngine()
    try:
        compliance = engine.evaluate(report, args.policy, overrides)
        report.compliance = compliance

        # Output results
        out_json = json.dumps(asdict(report), indent=2)
        if args.out:
            with open(args.out, 'w') as f:
                f.write(out_json)
        else:
            print(out_json)

        print_audit_summary(compliance)

    except Exception as e:
        print(f"Error during audit: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0

def print_audit_summary(compliance: ComplianceReport):
    print("\n" + "="*60)
    print(f" {compliance.framework} Compliance Report (v{compliance.version})")
    print("="*60)

    for art in compliance.articles:
        status_marker = "✅" if art.status == "compliant" else ("⚠" if art.status == "partial" else "❌")
        print(f" {art.id.ljust(3)} {art.title[:30].ljust(30)} .... {status_marker} {art.status.upper()}")

    print("-" * 60)
    print(f" Overall Compliance: {compliance.overall_score * 100:.1f}%")
    print("="*60 + "\n")

if __name__ == "__main__":
    sys.exit(main())
