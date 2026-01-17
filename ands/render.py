import os
from typing import Any, Dict, List, Optional
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

def render_ci_markdown(deltas: Dict[str, Any], ui_url: Optional[str] = None) -> str:
    """Generate a Markdown summary for CI/CD PR comments."""
    status_emoji = {"pass": "✅", "warn": "⚠️", "block": "🚫"}[deltas["status"]]
    md = f"### {status_emoji} ANDS CI/CD Compliance Summary\n\n"

    md += "| Category | Baseline | Current | Δ |\n"
    md += "|---|---|---|---|\n"
    for name, data in deltas["axes"].items():
        delta_str = "—"
        if data["delta"] > 0: delta_str = f"📈 +{data['delta']}"
        elif data["delta"] < 0: delta_str = f"📉 {data['delta']}"
        md += f"| **{name}** | {data['baseline']} | {data['current']} | {delta_str} |\n"

    if deltas.get("compliance"):
        c = deltas["compliance"]
        md += f"\n**{c['framework']} Compliance:** {c['baseline_score']*100:.0f}% → {c['current_score']*100:.0f}% "
        if c['delta_score'] > 0: md += f"(📈 +{c['delta_score']*100:.0f}%)"
        elif c['delta_score'] < 0: md += f"(📉 {c['delta_score']*100:.0f}%)"
        md += "\n"

    if deltas["blocking_issues"]:
        md += "\n#### 🚫 Blocking Issues\n"
        for issue in deltas["blocking_issues"]:
            md += f"- {issue}\n"

    if deltas["warnings"]:
        md += "\n#### ⚠️ Warnings\n"
        for warn in deltas["warnings"]:
            md += f"- {warn}\n"

    if ui_url:
        md += f"\n🔍 [Open Detailed Audit in ANDS Portal]({ui_url})\n"

    md += f"\n**Overall Status:** {deltas['status'].upper()}\n"
    return md

def render_ci_html(current: ScanReport, deltas: Dict[str, Any]) -> str:
    """Generate a standalone HTML dashboard for the audit result."""
    # Simplified HTML generation for the dashboard artifact
    template = """
<!DOCTYPE html>
<html>
<head>
    <title>ANDS CI/CD Dashboard</title>
    <style>
        body { font-family: sans-serif; margin: 40px; background: #f4f7f6; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        h1 { color: #333; }
        .status-block { border-left: 5px solid #ff4d4d; }
        .status-pass { border-left: 5px solid #4CAF50; }
        .status-warn { border-left: 5px solid #ff9800; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        th { background: #f2f2f2; }
        .delta-pos { color: red; font-weight: bold; }
        .delta-neg { color: green; font-weight: bold; }
    </style>
</head>
<body>
    <h1>ANDS Audit Dashboard</h1>
    <div class="card status-{{ deltas.status }}">
        <h2>Overall Status: {{ deltas.status|upper }}</h2>
        <p>Target: {{ report.target }}</p>
        <p>ANDS: {{ report.inferred_ands or report.declared_ands }}</p>
    </div>

    <div class="card">
        <h3>ANDS Axis Deltas</h3>
        <table>
            <tr><th>Axis</th><th>Baseline</th><th>Current</th><th>Delta</th></tr>
            {% for name, data in deltas.axes.items() %}
            <tr>
                <td>{{ name }}</td>
                <td>{{ data.baseline }}</td>
                <td>{{ data.current }}</td>
                <td class="{{ 'delta-pos' if (name == 'R' and data.delta > 0) else '' }}">
                    {{ '+' if data.delta > 0 else '' }}{{ data.delta if data.delta != 0 else '—' }}
                </td>
            </tr>
            {% endfor %}
        </table>
    </div>

    {% if deltas.blocking_issues %}
    <div class="card">
        <h3 style="color: #ff4d4d;">🚫 Blocking Issues</h3>
        <ul>
            {% for issue in deltas.blocking_issues %}
            <li>{{ issue }}</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}

    {% if deltas.compliance %}
    <div class="card">
        <h3>{{ deltas.compliance.framework }} Compliance</h3>
        <p>Score: {{ (deltas.compliance.current_score * 100)|round|int }}% (Baseline: {{ (deltas.compliance.baseline_score * 100)|round|int }}%)</p>
        {% if deltas.compliance.article_changes %}
        <h4>Article Changes</h4>
        <ul>
            {% for chg in deltas.compliance.article_changes %}
            <li><strong>{{ chg.id }}: {{ chg.title }}</strong> - {{ chg.baseline_status }} &rarr; {{ chg.current_status }}</li>
            {% endfor %}
        </ul>
        {% endif %}
    </div>
    {% endif %}
</body>
</html>
    """
    from jinja2 import Template
    tmpl = Template(template)
    return tmpl.render(report=current, deltas=deltas)
