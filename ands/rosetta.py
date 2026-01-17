import os
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional
from .config import config

class RosettaEngine:
    """Regulatory Mapping Engine for evaluating ANDS declarations against frameworks."""

    def __init__(self, policies_dir: Optional[str] = None):
        if policies_dir:
            self.policies_dir = Path(policies_dir)
        else:
            # Fallback to internal policies directory
            self.policies_dir = Path(__file__).parent.parent / "policies"

        self.policies: Dict[str, Dict[str, Any]] = {}
        self._load_policies()

    def _load_policies(self):
        """Loads all YAML policies from the policies directory."""
        if not self.policies_dir.exists():
            return

        for path in self.policies_dir.glob("*.yaml"):
            try:
                with open(path, "r") as f:
                    policy = yaml.safe_load(f)
                    if policy and "framework" in policy:
                        self.policies[path.stem] = policy
            except Exception as e:
                print(f"Error loading policy {path}: {e}")

    def evaluate(self, declaration: Dict[str, Any], framework_name: Optional[str] = None) -> Dict[str, Any]:
        """Evaluates a declaration against one or all loaded frameworks."""
        results = {}

        ands_code = declaration.get("declared_ands", "")
        axes = self._parse_ands_code(ands_code)

        # Merge environment if present as a separate field
        if "environment" in declaration:
            axes["E"] = declaration["environment"]

        evidence_sources = self._get_evidence_sources(declaration)

        target_policies = {framework_name: self.policies[framework_name]} if framework_name in self.policies else self.policies

        for name, policy in target_policies.items():
            fw_results = {
                "framework": policy.get("framework"),
                "version": policy.get("version"),
                "articles": {}
            }

            for art_id, art_data in policy.get("articles", {}).items():
                status, missing_evidence = self._evaluate_article(art_data, axes, evidence_sources)
                fw_results["articles"][art_id] = {
                    "title": art_data.get("title"),
                    "status": status,
                    "description": art_data.get("description"),
                    "missing_evidence": missing_evidence
                }

            results[name] = fw_results

        return results

    def _parse_ands_code(self, code: str) -> Dict[str, int]:
        """Parses C.A.M.G.R or C.A.M.G.R.E string into a dictionary."""
        parts = code.split(".")
        axes = {"C": 0, "A": 0, "M": 0, "G": 0, "R": 0, "E": 0}
        labels = ["C", "A", "M", "G", "R", "E"]
        for i, val in enumerate(parts):
            if i < len(labels):
                try:
                    axes[labels[i]] = int(val)
                except ValueError:
                    pass
        return axes

    def _get_evidence_sources(self, declaration: Dict[str, Any]) -> List[str]:
        """Identifies types of evidence provided in the declaration."""
        sources = []
        if declaration.get("attestation_urls"):
            sources.append("attestation")
        if declaration.get("sbom_urls"):
            sources.append("sbom")
        if declaration.get("auditor_confirmation"):
            sources.append("audit")
        return sources

    def _evaluate_article(self, art_data: Dict[str, Any], axes: Dict[str, int], evidence_sources: List[str]) -> tuple[str, List[str]]:
        """Evaluates a single article's logic and evidence requirements."""
        logic = art_data.get("logic", "True")
        required_evidence = art_data.get("evidence_required", [])

        # Dynamic evaluation of ANDS axes
        compliant_logic = False
        try:
            # Safe evaluation context
            local_vars = axes.copy()
            compliant_logic = eval(logic, {"__builtins__": {}}, local_vars)
        except Exception as e:
            return "Error", []

        missing_evidence = [e for e in required_evidence if e not in evidence_sources]

        if not compliant_logic:
            return "Non-Compliant", []

        if missing_evidence:
            return "Conditional", missing_evidence

        return "Compliant", []
