#!/usr/bin/env python3
"""render_report.py — render a scan report JSON to Markdown.

This keeps the standard repo "compliance friendly" by providing human-readable output.
"""

from __future__ import annotations

import argparse
import json
import os

from jinja2 import Template


TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "templates", "report.md.j2")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report_json", help="Path to scan report JSON")
    ap.add_argument("--out", default="", help="Write Markdown to file")
    ap.add_argument("--template", choices=["report", "scorecard"], default="report", help="Report template to use")
    args = ap.parse_args()

    with open(args.report_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    t_path = TEMPLATE_PATH
    if args.template == "scorecard":
        t_path = os.path.join(os.path.dirname(__file__), "templates", "scorecard.md.j2")

    with open(t_path, "r", encoding="utf-8") as f:
        tmpl = Template(f.read())

    md = tmpl.render(r=data)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(md)
    else:
        print(md)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
