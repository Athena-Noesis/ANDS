#!/usr/bin/env python3
"""ands_summarize.py — Aggregate multiple scan reports into a summary table.

Usage:
  python3 tools/ands_summarize.py path/to/reports/ --format markdown
"""

import argparse
import json
import os
import sys
from typing import List, Dict, Any

def load_reports(directory: str) -> List[Dict[str, Any]]:
    reports = []
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a directory.")
        return []

    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            path = os.path.join(directory, filename)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Basic duck-typing check to ensure it's an ANDS report
                    if "target" in data and "inferred_ands" in data:
                        reports.append(data)
            except Exception as e:
                print(f"Warning: Failed to load {path}: {e}", file=sys.stderr)
    return reports

def generate_markdown(reports: List[Dict[str, Any]], baseline_reports: List[Dict[str, Any]] = None) -> str:
    if not reports:
        return "No valid reports found."

    baseline_map = {}
    if baseline_reports:
        for br in baseline_reports:
            target = br.get("target", "")
            if target:
                baseline_map[target] = br

    lines = [
        "# ANDS Portfolio Summary",
        "",
        "| Target | Declared | Inferred | Conf | Cert | Risk (R) | Drift |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |"
    ]

    for r in sorted(reports, key=lambda x: x.get("target", "")):
        target = r.get("target", "N/A")
        decl = r.get("declared_ands") or "N/A"
        inf = r.get("inferred_ands") or "N/A"
        conf = f"{int(r.get('confidence', 0) * 100)}%"
        cert = r.get("declared_certification_level") or "N/A"
        risk = inf.split('.')[-1] if inf != "N/A" else "N/A"

        drift = "N/A"
        if target in baseline_map:
            b_inf = baseline_map[target].get("inferred_ands", "N/A")
            if b_inf != inf:
                drift = f"**{b_inf} -> {inf}**"
            else:
                drift = "stable"

        lines.append(f"| {target} | {decl} | {inf} | {conf} | {cert} | {risk} | {drift} |")

    return "\n".join(lines)

def generate_csv(reports: List[Dict[str, Any]]) -> str:
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Target", "Declared ANDS", "Inferred ANDS", "Confidence", "Certification", "Risk (R)"])

    for r in sorted(reports, key=lambda x: x.get("target", "")):
        inf = r.get("inferred_ands") or "N/A"
        writer.writerow([
            r.get("target", "N/A"),
            r.get("declared_ands") or "N/A",
            inf,
            f"{int(r.get('confidence', 0) * 100)}%",
            r.get("declared_certification_level") or "N/A",
            inf.split('.')[-1] if inf != "N/A" else "N/A"
        ])
    return output.getvalue()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("directory", help="Directory containing ANDS report JSON files")
    ap.add_argument("--baseline", help="Directory containing baseline ANDS report JSON files for drift detection")
    ap.add_argument("--format", choices=["markdown", "csv"], default="markdown")
    ap.add_argument("--out", help="Write summary to file")
    args = ap.parse_args()

    reports = load_reports(args.directory)
    if not reports:
        print("No valid reports found in primary directory.")
        sys.exit(1)

    baseline_reports = None
    if args.baseline:
        baseline_reports = load_reports(args.baseline)

    if args.format == "markdown":
        output = generate_markdown(reports, baseline_reports)
    else:
        output = generate_csv(reports)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Summary written to {args.out}")
    else:
        print(output)

if __name__ == "__main__":
    main()
