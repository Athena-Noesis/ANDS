import os
from jinja2 import Template
from .models import ScanReport

TRANSLATIONS = {
    "en": {"title": "ANDS Scan Report", "risk": "Risk Level", "conf": "Confidence", "evidence": "Evidence", "gaps": "Gaps", "recs": "Recommendations", "target": "Target", "reachable": "Reachable", "decl_ands": "Declared ANDS", "decl_cert": "Declared Certification", "inf_ands": "Inferred ANDS"},
    "es": {"title": "Informe de Escaneo ANDS", "risk": "Nivel de Riesgo", "conf": "Confianza", "evidence": "Evidencia", "gaps": "Brechas", "recs": "Recomendaciones", "target": "Objetivo", "reachable": "Alcanzable", "decl_ands": "ANDS Declarado", "decl_cert": "Certificación Declarada", "inf_ands": "ANDS Inferido"},
    "fr": {"title": "Rapport de Scan ANDS", "risk": "Niveau de Risque", "conf": "Confiance", "evidence": "Preuves", "gaps": "Lacunes", "recs": "Recommandations", "target": "Cible", "reachable": "Joignable", "decl_ands": "ANDS Déclaré", "decl_cert": "Certification Déclarée", "inf_ands": "ANDS Inféré"},
    "de": {"title": "ANDS-Scan-Bericht", "risk": "Risikostufe", "conf": "Vertrauen", "evidence": "Beweise", "gaps": "Lücken", "recs": "Empfehlungen", "target": "Ziel", "reachable": "Erreichbar", "decl_ands": "Deklariertes ANDS", "decl_cert": "Deklarierte Zertifizierung", "inf_ands": "Abgeleitetes ANDS"}
}

def render_markdown(report: ScanReport, template_path: str, lang: str = "en") -> str:
    with open(template_path, "r", encoding="utf-8") as f:
        tmpl = Template(f.read())
    return tmpl.render(r=report, t=TRANSLATIONS.get(lang, TRANSLATIONS["en"]))
