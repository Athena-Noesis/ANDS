import argparse
import os
import sys
from ands.render import render_markdown
from ands.models import ScanReport
import json
from dataclasses import asdict

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report_json")
    ap.add_argument("--out")
    ap.add_argument("--template", choices=["report", "scorecard", "certificate"], default="report")
    ap.add_argument("--format", choices=["markdown", "html"], default="markdown")
    ap.add_argument("--lang", choices=["en", "es", "fr", "de"], default="en")
    args = ap.parse_args()

    with open(args.report_json, "r") as f: data = json.load(f)

    # We use a dummy template path resolution for this script
    t_dir = os.path.join(os.path.dirname(__file__), "templates")
    t_name = "certificate.html.j2" if args.template == "certificate" else f"{args.template}.md.j2"
    t_path = os.path.join(t_dir, t_name)

    # In a real package we would use importlib.resources
    from ands.models import ScanReport
    report = ScanReport(**data)

    # render_markdown only handles md for now, but let's assume it handles both or we'll wrap it
    from jinja2 import Template
    from ands.render import TRANSLATIONS
    with open(t_path, "r") as f: tmpl = Template(f.read())
    output = tmpl.render(r=report, t=TRANSLATIONS[args.lang])

    if args.out:
        with open(args.out, "w") as f: f.write(output)
    else: print(output)

if __name__ == "__main__":
    main()
