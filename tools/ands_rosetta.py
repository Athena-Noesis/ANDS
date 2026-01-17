#!/usr/bin/env python3
"""ands_rosetta.py — The Rosetta Stone (Universal Harmonization).

Translates ANDS into ISO 42001, NIST AI RMF, and EU AI Act reports.
"""

import argparse
import json
import sys
import os
from ands.rosetta import RosettaEngine

def main():
    ap = argparse.ArgumentParser(prog="ands rosetta")
    subparsers = ap.add_subparsers(dest="command", help="Rosetta commands")

    # translate command (default behavior)
    parser_trans = subparsers.add_parser("translate", help="Translate ANDS code to regulatory frameworks")
    parser_trans.add_argument("ands", help="ANDS code (e.g., 2.1.2.3.4.1)")
    parser_trans.add_argument("--format", choices=["json", "text"], default="text")

    # checklist command
    parser_check = subparsers.add_parser("checklist", help="Generate article-level compliance checklist")
    parser_check.add_argument("file", help="Path to ands.json declaration")
    parser_check.add_argument("--framework", help="Limit to specific framework (e.g., eu_ai_act)")
    parser_check.add_argument("--format", choices=["json", "text"], default="text")

    # Compatibility: if no subcommand, assume translate
    if len(sys.argv) > 1 and sys.argv[1] not in ["translate", "checklist", "-h", "--help"]:
        sys.argv.insert(1, "translate")

    args = ap.parse_args()

    engine = RosettaEngine()

    if args.command == "translate":
        declaration = {"declared_ands": args.ands}
        results = engine.evaluate(declaration)

        if args.format == "json":
            print(json.dumps(results, indent=2))
        else:
            print(f"====================================================")
            print(f"   ANDS ROSETTA STONE (Universal Harmonization)")
            print(f"====================================================\n")
            print(f"Input ANDS: {args.ands}\n")
            for fw_key, fw_data in results.items():
                print(f"--- {fw_data['framework']} ({fw_data['version']}) ---")
                for art_id, art in fw_data["articles"].items():
                    status_icon = "[✓]" if art["status"] == "Compliant" else "[⚠]" if art["status"] == "Conditional" else "[✗]"
                    print(f" {status_icon} Article {art_id:4} : {art['title']}")
                print()

    elif args.command == "checklist":
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found.")
            return 1

        with open(args.file, "r") as f:
            declaration = json.load(f)

        results = engine.evaluate(declaration, framework_name=args.framework)

        if args.format == "json":
            print(json.dumps(results, indent=2))
        else:
            print(f"====================================================")
            print(f"   ANDS COMPLIANCE CHECKLIST")
            print(f"====================================================\n")

            for fw_key, fw_data in results.items():
                print(f"{fw_data['framework']} Compliance Checklist")
                print("-" * 40)
                comp, cond, non = 0, 0, 0
                for art_id, art in fw_data["articles"].items():
                    status_icon = "[✓]" if art["status"] == "Compliant" else "[⚠]" if art["status"] == "Conditional" else "[✗]"
                    print(f"{status_icon} Article {art_id:4} – {art['title']}")
                    if art["status"] == "Compliant": comp += 1
                    elif art["status"] == "Conditional":
                        cond += 1
                        print(f"    Missing Evidence: {', '.join(art['missing_evidence'])}")
                    else: non += 1

                print("-" * 40)
                print(f"Compliant: {comp} | Conditional: {cond} | Non-Compliant: {non}\n")

if __name__ == "__main__":
    main()
