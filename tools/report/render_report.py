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

TRANSLATIONS = {
    "en": {
        "title": "ANDS Scan Report", "risk": "Risk Level", "conf": "Confidence",
        "evidence": "Evidence", "gaps": "Gaps", "recs": "Recommendations",
        "target": "Target", "reachable": "Reachable", "decl_ands": "Declared ANDS",
        "decl_cert": "Declared Certification", "inf_ands": "Inferred ANDS"
    },
    "es": {
        "title": "Informe de Escaneo ANDS", "risk": "Nivel de Riesgo", "conf": "Confianza",
        "evidence": "Evidencia", "gaps": "Brechas", "recs": "Recomendaciones",
        "target": "Objetivo", "reachable": "Alcanzable", "decl_ands": "ANDS Declarado",
        "decl_cert": "Certificación Declarada", "inf_ands": "ANDS Inferido"
    },
    "fr": {
        "title": "Rapport de Scan ANDS", "risk": "Niveau de Risque", "conf": "Confiance",
        "evidence": "Preuves", "gaps": "Lacunes", "recs": "Recommandations",
        "target": "Cible", "reachable": "Joignable", "decl_ands": "ANDS Déclaré",
        "decl_cert": "Certification Déclarée", "inf_ands": "ANDS Inféré"
    },
    "de": {
        "title": "ANDS-Scan-Bericht", "risk": "Risikostufe", "conf": "Vertrauen",
        "evidence": "Beweise", "gaps": "Lücken", "recs": "Empfehlungen",
        "target": "Ziel", "reachable": "Erreichbar", "decl_ands": "Deklariertes ANDS",
        "decl_cert": "Deklarierte Zertifizierung", "inf_ands": "Abgeleitetes ANDS"
    }
}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report_json", help="Path to scan report JSON")
    ap.add_argument("--out", default="", help="Write output to file")
    ap.add_argument("--template", choices=["report", "scorecard", "certificate"], default="report", help="Report template to use")
    ap.add_argument("--format", choices=["markdown", "html"], default="markdown")
    ap.add_argument("--lang", choices=["en", "es", "fr", "de"], default="en", help="Output language")
    args = ap.parse_args()

    with open(args.report_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    t_name = f"{args.template}.md.j2"
    if args.template == "certificate":
        t_name = "certificate.html.j2"
    elif args.format == "html":
        # Fallback if someone wants a report in html (not implemented yet, but keeping structure)
        t_name = f"{args.template}.html.j2"

    t_path = os.path.join(os.path.dirname(__file__), "templates", t_name)

    with open(t_path, "r", encoding="utf-8") as f:
        tmpl = Template(f.read())

    # Add translations to template context
    md = tmpl.render(r=data, t=TRANSLATIONS[args.lang])

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(md)
    else:
        print(md)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
