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

def render_compliance_summary(report: ScanReport) -> str:
    """Generate a markdown summary of the compliance report."""
    if not report.compliance:
        return "No compliance data available."

    c = report.compliance
    md = f"# {c.framework} Compliance Summary (v{c.version})\n\n"
    md += f"**Overall Compliance: {c.overall_score * 100:.1f}%**\n\n"

    md += "| Article | Title | Status | Score |\n"
    md += "|---|---|---|---|\n"
    for art in c.articles:
        status_marker = "✅" if art.status == "compliant" else ("⚠️" if art.status == "partial" else "❌")
        md += f"| {art.id} | {art.title} | {status_marker} {art.status.upper()} | {art.score} |\n"

    md += "\n## Details\n\n"
    for art in c.articles:
        md += f"### Article {art.id}: {art.title}\n"
        md += f"{art.description}\n\n"
        md += f"- **Status:** {art.status.upper()}\n"
        md += f"- **Score:** {art.score}\n"
        md += f"- **Reasoning:** {art.reasoning}\n"
        if art.manual_override:
            md += "- **Note:** Verified by manual auditor override.\n"
        md += "\n"

    return md
