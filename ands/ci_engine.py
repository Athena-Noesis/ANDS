import json
import os
import requests
from typing import Any, Dict, List, Optional, Tuple
from .models import ScanReport, ComplianceReport, ComplianceArticle
from .utils import logger

class CIEngine:
    """Handles CI/CD comparison and risk delta analysis."""

    def __init__(self):
        pass

    def load_report(self, path_or_url: str) -> Optional[ScanReport]:
        """Load a ScanReport from a local path or remote URL."""
        try:
            if path_or_url.startswith(("http://", "https://")):
                resp = requests.get(path_or_url, timeout=10)
                resp.raise_for_status()
                data = resp.json()
            else:
                if not os.path.exists(path_or_url):
                    logger.warning(f"Baseline report not found at {path_or_url}")
                    return None
                with open(path_or_url, 'r', encoding='utf-8') as f:
                    data = json.load(f)

            # Reconstruct ScanReport (handle nested dataclasses)
            from .models import Evidence, ProbeResult, ReasoningStep, ComplianceReport, ComplianceArticle

            # Simple reconstruction logic
            report = ScanReport(**{k: v for k, v in data.items() if k in ScanReport.__dataclass_fields__})

            if data.get("compliance"):
                c = data["compliance"]
                report.compliance = ComplianceReport(
                    framework=c.get("framework", "unknown"),
                    version=c.get("version", "1.0"),
                    overall_score=c.get("overall_score", 0.0),
                    articles=[ComplianceArticle(**a) for a in c.get("articles", [])],
                    auditor_overrides=c.get("auditor_overrides")
                )

            # Convert other lists to dataclasses if needed
            report.evidence = [Evidence(**e) for e in data.get("evidence", [])]
            report.probes = [ProbeResult(**p) for p in data.get("probes", [])]
            if data.get("reasoning"):
                report.reasoning = [ReasoningStep(**r) for r in data.get("reasoning", [])]

            return report
        except Exception as e:
            logger.error(f"Failed to load report from {path_or_url}: {e}")
            return None

    def compare(self, current: ScanReport, baseline: Optional[ScanReport]) -> Dict[str, Any]:
        """Compare current report with baseline and return deltas."""
        deltas = {
            "axes": {},
            "compliance": {},
            "blocking_issues": [],
            "warnings": [],
            "status": "pass" # pass, warn, block
        }

        # Axis comparison (C.A.M.G.R.E)
        cur_code = current.inferred_ands or current.declared_ands or "0.0.0.0.0"
        base_code = "0.0.0.0.0"
        if baseline:
            base_code = baseline.inferred_ands or baseline.declared_ands or "0.0.0.0.0"

        cur_parts = [int(p) for p in cur_code.split('.')]
        base_parts = [int(p) for p in base_code.split('.')]

        axis_names = ["C", "A", "M", "G", "R", "E"]
        for i, name in enumerate(axis_names):
            cur_val = cur_parts[i] if i < len(cur_parts) else 0
            base_val = base_parts[i] if i < len(base_parts) else 0
            diff = cur_val - base_val
            deltas["axes"][name] = {"current": cur_val, "baseline": base_val, "delta": diff}

            # Blocking Rules
            if name == "R" and diff > 0:
                deltas["blocking_issues"].append(f"Risk (R) axis increased from {base_val} to {cur_val}.")
            if name == "A" and diff >= 2:
                deltas["blocking_issues"].append(f"Agency (A) axis significantly increased (+{diff}).")
            if name == "G" and diff < 0:
                deltas["warnings"].append(f"Governance (G) axis decreased from {base_val} to {cur_val}.")
            if name == "E" and cur_val >= 4:
                deltas["warnings"].append(f"Environment (E) axis is elevated ({cur_val}).")

        # Compliance comparison
        if current.compliance:
            cur_comp = current.compliance
            base_comp = baseline.compliance if baseline and baseline.compliance else None

            deltas["compliance"] = {
                "framework": cur_comp.framework,
                "current_score": cur_comp.overall_score,
                "baseline_score": base_comp.overall_score if base_comp else 0.0,
                "delta_score": cur_comp.overall_score - (base_comp.overall_score if base_comp else 0.0),
                "article_changes": []
            }

            base_articles = {a.id: a for a in base_comp.articles} if base_comp else {}
            for art in cur_comp.articles:
                base_art = base_articles.get(art.id)
                if not base_art or art.status != base_art.status:
                    deltas["compliance"]["article_changes"].append({
                        "id": art.id,
                        "title": art.title,
                        "current_status": art.status,
                        "baseline_status": base_art.status if base_art else "unknown"
                    })

                    if art.status == "non_compliant" and (not base_art or base_art.status != "non_compliant"):
                        deltas["blocking_issues"].append(f"New 'Non-Compliant' status for {cur_comp.framework} Article {art.id}.")

        # Signature check
        # (Assuming we want to check for a required auditor signature if certification level is high)
        if current.declared_certification_level in ["VERIFIED", "AUDITED"]:
            # Check signatures if it's an audit bundle?
            # For now, we look at evidence or a dedicated signature field if added to ScanReport.
            pass

        # Final status
        if deltas["blocking_issues"]:
            deltas["status"] = "block"
        elif deltas["warnings"]:
            deltas["status"] = "warn"

        return deltas
