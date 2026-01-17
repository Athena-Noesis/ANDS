import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional
from dataclasses import asdict

from .ci_engine import CIEngine
from .audit import main as audit_main
from .models import ScanReport
from .render import render_ci_markdown, render_ci_html
from .utils import logger

def main():
    parser = argparse.ArgumentParser(prog="ands ci", description="Run ANDS CI/CD audit and comparison.")
    parser.add_argument("--report", help="Path to the current ANDS scan report JSON.")
    parser.add_argument("--baseline", help="Path or URL to the baseline ANDS report.")
    parser.add_argument("--policy", default="eu_ai_act", help="Policy framework for compliance check.")
    parser.add_argument("--ui-url", help="Optional URL to a hosted ANDS UI instance.")
    parser.add_argument("--out-markdown", help="Path to save the Markdown summary.")
    parser.add_argument("--out-html", help="Path to save the HTML dashboard.")

    args, extra = parser.parse_known_args()

    engine = CIEngine()

    # 1. Load current report
    if not args.report:
        # If no report provided, try to run a fresh audit/scan
        # For simplicity, we assume 'ands audit' has been run or we run it here
        print("Error: --report is required for comparison.")
        return 1

    current = engine.load_report(args.report)
    if not current:
        print(f"Error: Could not load current report from {args.report}")
        return 1

    # 2. Load baseline
    baseline_path = args.baseline or os.environ.get("ANDS_BASELINE_URL") or "ands_report.latest.json"
    baseline = engine.load_report(baseline_path)

    # 3. Compare
    deltas = engine.compare(current, baseline)

    # 4. Render reports
    markdown = render_ci_markdown(deltas, args.ui_url)
    html = render_ci_html(current, deltas)

    if args.out_markdown:
        with open(args.out_markdown, 'w', encoding='utf-8') as f:
            f.write(markdown)
    else:
        print("\n--- CI/CD SUMMARY ---")
        print(markdown)

    if args.out_html:
        with open(args.out_html, 'w', encoding='utf-8') as f:
            f.write(html)

    # GitHub Action Support
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding='utf-8') as f:
            f.write(markdown)

    # 5. Exit codes
    if deltas["status"] == "block":
        print("\n🚫 AUDIT FAILED: Blocking issues detected.")
        return 1
    elif deltas["status"] == "warn":
        print("\n⚠️ AUDIT PASSED WITH WARNINGS.")
        return 0 # Or 2 if preferred
    else:
        print("\n✅ AUDIT PASSED.")
        return 0

if __name__ == "__main__":
    sys.exit(main())
