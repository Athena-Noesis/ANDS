import os
import yaml
from typing import Any, Dict, List, Optional, Tuple
from .models import ScanReport, ComplianceReport, ComplianceArticle, Evidence
from .utils import logger

class PolicyEngine:
    """Evaluates ANDS reports against regulatory policies."""

    def __init__(self, policies_dir: Optional[str] = None):
        if policies_dir is None:
            # Look in the 'policies' directory relative to the current working directory
            # Or perhaps inside the package? ChatGPT suggested 'policies/' in the root.
            self.policies_dir = os.path.join(os.getcwd(), "policies")
        else:
            self.policies_dir = policies_dir

    def load_policy(self, framework_id: str) -> Dict[str, Any]:
        """Load a policy YAML file by its ID (e.g., 'eu_ai_act')."""
        path = os.path.join(self.policies_dir, f"{framework_id}.yaml")
        if not os.path.exists(path):
            # Try within the package if not found in current directory
            pkg_path = os.path.join(os.path.dirname(__file__), "policies", f"{framework_id}.yaml")
            if os.path.exists(pkg_path):
                path = pkg_path
            else:
                raise FileNotFoundError(f"Policy file {framework_id}.yaml not found.")

        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def evaluate(self, report: ScanReport, framework_id: str, overrides: List[Dict[str, Any]] = None) -> ComplianceReport:
        """Evaluate a scan report against a specific framework."""
        policy = self.load_policy(framework_id)
        articles_data = policy.get("articles", {})

        # Prepare the context for evaluation
        context = self._get_evaluation_context(report)

        compliance_articles = []
        for art_id, art_info in articles_data.items():
            article = self._evaluate_article(art_id, art_info, context, overrides)
            compliance_articles.append(article)

        # Handle dependencies (if an article fails, it might affect others)
        self._resolve_dependencies(compliance_articles, articles_data)

        overall_score = sum(a.score for a in compliance_articles) / len(compliance_articles) if compliance_articles else 0.0

        return ComplianceReport(
            framework=policy.get("framework", framework_id),
            version=policy.get("version", "1.0"),
            overall_score=round(overall_score, 2),
            articles=compliance_articles,
            auditor_overrides=overrides
        )

    def _get_evaluation_context(self, report: ScanReport) -> Dict[str, Any]:
        """Extract evaluation variables (C, A, M, G, R, E) and tags from the report."""
        ctx = {"C": 3, "A": 3, "M": 3, "G": 3, "R": 3, "E": 3}  # Defaults

        ands_code = report.inferred_ands or report.declared_ands or "3.3.3.3.3"
        parts = ands_code.split('.')
        for i, key in enumerate(["C", "A", "M", "G", "R", "E"]):
            if i < len(parts):
                try:
                    ctx[key] = int(parts[i])
                except ValueError:
                    pass

        # Extract tags from evidence
        tags = set()
        for e in report.evidence:
            # We assume findings might contain tags in the form of keywords
            finding = e.finding.lower()
            for tag in ["security_headers", "rbac_surface", "privacy_disclosures", "audit_indicators", "human_oversight_mechanism", "decision_review_log"]:
                if tag.replace("_", " ") in finding or tag in finding:
                    tags.add(tag)

        ctx["tags"] = tags
        return ctx

    def _evaluate_article(self, art_id: str, art_info: Dict[str, Any], context: Dict[str, Any], overrides: List[Dict[str, Any]] = None) -> ComplianceArticle:
        """Evaluate a single article against the context."""

        # Check for overrides
        if overrides:
            for ov in overrides:
                if str(ov.get("article")) == str(art_id):
                    status = ov.get("status", "non_compliant")
                    return ComplianceArticle(
                        id=art_id,
                        title=art_info.get("title", f"Article {art_id}"),
                        status=status,
                        score=1.0 if status == "compliant" else (0.5 if status == "partial" else 0.0),
                        description=art_info.get("description"),
                        reasoning=ov.get("comment", "Manual auditor override."),
                        manual_override=True
                    )

        thresholds = art_info.get("thresholds", {})

        # We'll use a simple evaluator for the logic strings
        def safe_eval(expr: str, ctx: Dict[str, Any]) -> bool:
            try:
                import re
                # Use word boundaries to avoid replacing letters inside 'and'/'or'
                e = expr
                for key in ["C", "A", "M", "G", "R", "E"]:
                    e = re.sub(rf"\b{key}\b", str(ctx.get(key, 3)), e)

                # Replace logical operators with python ones if needed (YAML might already use 'and'/'or')
                # But 'and'/'or' are valid in Python, so just ensure they are lowercase if not
                e = e.replace("AND", "and").replace("OR", "or")

                return eval(e, {"__builtins__": {}}, {})
            except Exception as e:
                logger.error(f"Error evaluating expression '{expr}': {e}")
                return False

        if safe_eval(thresholds.get("compliant", "False"), context):
            status = "compliant"
            score = 1.0
        elif safe_eval(thresholds.get("partial", "False"), context):
            status = "partial"
            score = 0.5
        else:
            status = "non_compliant"
            score = 0.0

        # Evidence bonus
        evidence_reqs = art_info.get("evidence_requirements", {})
        if status != "compliant" and evidence_reqs:
            req_tags = evidence_reqs.get("required_tags", [])
            if req_tags and all(t in context["tags"] for t in req_tags):
                # Upgrade status if all required tags are present
                if status == "non_compliant":
                    status = "partial"
                    score = 0.5
                elif status == "partial":
                    status = "compliant"
                    score = 1.0

        return ComplianceArticle(
            id=art_id,
            title=art_info.get("title", f"Article {art_id}"),
            status=status,
            score=score,
            description=art_info.get("description"),
            reasoning=f"Based on logic: {art_info.get('logic')}"
        )

    def _resolve_dependencies(self, compliance_articles: List[ComplianceArticle], articles_data: Dict[str, Any]):
        """Adjust scores based on cross-article dependencies."""
        art_map = {a.id: a for a in compliance_articles}

        # Example hardcoded rule: Article 9 non-compliance downgrades 15 and 16
        if "9" in art_map and art_map["9"].status == "non_compliant":
            for dep_id in ["15", "16"]:
                if dep_id in art_map and art_map[dep_id].status == "compliant":
                    art_map[dep_id].status = "partial"
                    art_map[dep_id].score = 0.5
                    art_map[dep_id].reasoning += " (Downgraded due to Article 9 failure)"

        # Generic dependency check from policy
        for art_id, art_info in articles_data.items():
            deps = art_info.get("dependencies", [])
            for dep_id in deps:
                if dep_id in art_map and art_map[dep_id].status == "non_compliant":
                    if art_id in art_map and art_map[art_id].status == "compliant":
                        art_map[art_id].status = "partial"
                        art_map[art_id].score = 0.5
                        art_map[art_id].reasoning += f" (Downgraded due to Article {dep_id} failure)"
