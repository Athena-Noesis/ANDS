import json
import logging
import zipfile
import hashlib
import jcs
import os
import base64
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import asdict
from urllib.parse import urljoin

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import Evidence, ProbeResult, ScanReport, ReasoningStep
from .utils import safe_request, logger
from .rosetta import RosettaEngine

def openapi_hints(openapi: Dict[str, Any]) -> List[str]:
    txt = json.dumps(openapi).lower()
    hints: List[str] = []
    keys = ["tool", "function_call", "connector", "mcp", "snapshot", "provenance", "audit", "log", "upload", "attachment", "file", "blob", "s3", "execute", "sandbox", "run", "rbac", "roles", "permissions"]
    for k in keys:
        if k in txt: hints.append(f"{k}_surface")
    for p in (openapi.get("paths") or {}).keys():
        pl = str(p).lower()
        for k in ["mcp", "execute", "run", "snapshot", "audit", "provenance", "upload", "file", "attachment"]:
            if k in pl: hints.append(f"{k}_endpoints")
    return sorted(set(hints))

def pick_probe_paths(openapi: Optional[Dict[str, Any]]) -> Dict[str, List[str]]:
    common_safe = ["/health", "/status", "/metrics", "/robots.txt", "/.well-known/security.txt", "/.well-known/ai-plugin.json", "/v1/models", "/privacy", "/tos"]
    dangerous_defaults = ["/execute", "/run", "/tool", "/mcp", "/upload", "/files", "/.well-known/mcp", "/v1/sessions", "/v1/history"]
    if not openapi or not (openapi.get("paths")):
        return {"safe": common_safe, "dangerous": dangerous_defaults}
    paths = list((openapi.get("paths") or {}).keys())
    lower = [p.lower() for p in paths]
    safe_hits = [cand for cand in common_safe if cand.lower() in lower] or common_safe
    danger_hits = []
    for p in paths:
        pl = p.lower()
        if any(tok in pl for tok in ["execute", "run", "mcp", "tool", "upload", "file", "connector"]):
            danger_hits.append(p)
    return {"safe": safe_hits[:8], "dangerous": (danger_hits[:8] or dangerous_defaults)}

def infer_ands(hints: List[str], evidence_list: List[Evidence], gaps_list: List[str]) -> Tuple[str, float, List[ReasoningStep]]:
    C, A, M, G, R, S = 2, 1, 1, 1, 3, 0
    reasoning = []
    probe_txt = " ".join(e.finding for e in evidence_list if e.source == "probe").lower()

    # Baseline checks
    if "ai plugin" in probe_txt or "model listing" in probe_txt:
        if 3 > C:
            C = 3
            reasoning.append(ReasoningStep("C", "3", "AI plugin or model listing detected."))
    if "session/history" in probe_txt:
        if 2 > M:
            M = 2
            reasoning.append(ReasoningStep("M", "2", "Session or history endpoint detected."))
    if "policy/governance" in probe_txt:
        if 2 > G:
            G = 2
            reasoning.append(ReasoningStep("G", "2", "Governance markers detected."))

    # Sustainability Hints
    if any(k in probe_txt for k in ["local", "quantized", "ollama", "edge"]):
        S = 1
        reasoning.append(ReasoningStep("S", "1", "Local or optimized runtime detected."))

    def add_unique(source, finding, weight):
        if not any(e.source == source and e.finding == finding for e in evidence_list):
            evidence_list.append(Evidence(source, finding, weight))

    mapping = {
        "rbac_surface": (0, 0, 0, 2, 0, 0, "RBAC/permissions indicators found.", 1.5),
        "audit_or_snapshot_surface": (0, 0, 2, 2, 0, 0, "Audit/provenance/snapshot indicators found.", 1.5),
        "tool_or_connector_surface": (0, 0, 0, 0, 4, 0, "Tool/connector indicators found (higher risk surface).", 2.0),
        "file_handling_surface": (0, 0, 0, 0, 4, 0, "File/attachment handling indicators found.", 1.2),
        "code_execution_surface": (0, 0, 0, 0, 5, 0, "Code execution indicators found (highest risk surface).", 3.0),
    }
    for h in hints:
        if h in mapping:
            res = mapping[h]
            if res[0] > C: C = res[0]; reasoning.append(ReasoningStep("C", str(C), f"Hint: {h}"))
            if res[1] > A: A = res[1]; reasoning.append(ReasoningStep("A", str(A), f"Hint: {h}"))
            if res[2] > M: M = res[2]; reasoning.append(ReasoningStep("M", str(M), f"Hint: {h}"))
            if res[3] > G: G = res[3]; reasoning.append(ReasoningStep("G", str(G), f"Hint: {h}"))
            if res[4] > R: R = res[4]; reasoning.append(ReasoningStep("R", str(R), f"Hint: {h}"))
            if res[5] > S: S = res[5]; reasoning.append(ReasoningStep("S", str(S), f"Hint: {h}"))
            add_unique("openapi", res[6], res[7])

    if "code_execution_surface" in hints:
        msg = "Code execution surface detected; verify sandboxing and explicit human approval controls."
        if msg not in gaps_list: gaps_list.append(msg)

    pos_weight = sum(e.weight for e in evidence_list)
    gap_penalty = len(gaps_list) * 0.05
    conf = max(0.1, min(0.9, 0.2 + (pos_weight * 0.1) - gap_penalty))
    return f"{C}.{A}.{M}.{G}.{R}.{S}", conf, reasoning

def map_to_regulations(ands_code: str, custom_policy: Dict[str, Any] = None) -> Dict[str, str]:
    """Map ANDS score to major regulatory frameworks using RosettaEngine."""
    engine = RosettaEngine()
    declaration = {"declared_ands": ands_code}
    results = engine.evaluate(declaration)

    # Maintain backward compatibility for the simple Dict[str, str] mapping
    legacy_maps = {}
    for fw_key, fw_data in results.items():
        fw_name = fw_data["framework"]
        compliant_count = sum(1 for art in fw_data["articles"].values() if art["status"] == "Compliant")
        total_count = len(fw_data["articles"])

        if compliant_count == total_count:
            legacy_maps[fw_name] = "COMPLIANT"
        elif compliant_count == 0:
            legacy_maps[fw_name] = "NON-COMPLIANT"
        else:
            legacy_maps[fw_name] = f"PARTIAL ({compliant_count}/{total_count})"

    # Override with logic from scanner v1 for high-level classification if needed
    # (Optional: we can keep the nuanced v1 mapping as fallback/augmentation)
    parts = ands_code.split('.')
    if len(parts) >= 5:
        try:
            C, A, M, G, R = map(int, parts[:5])
            if R == 5: legacy_maps["EU AI Act"] = "PROHIBITED (Unacceptable Risk)"
        except: pass

    return legacy_maps

def analyze_probe_status(pr: ProbeResult, category: str, evidence: List[Evidence], gaps: List[str], recs: List[str]) -> None:
    if pr.status is None:
        gaps.append(f"Probe failed ({category}): {pr.url} ({pr.note})")
        return
    sec_headers = {"Strict-Transport-Security": "HSTS", "X-Content-Type-Options": "NoSniff", "X-Frame-Options": "Anti-Clickjacking", "Content-Security-Policy": "CSP"}
    found_sec = [label for h, label in sec_headers.items() if any(h.lower() == k.lower() for k in pr.headers.keys())]
    if found_sec: evidence.append(Evidence("probe", f"Security headers found on {pr.url}: {', '.join(found_sec)}", 0.5))

    path_hints = [
        ("ai-plugin.json", "AI Plugin manifest found.", 2.5),
        ("/v1/models", "Model listing endpoint reachable.", 1.5),
        ("/v1/sessions", "Session/History endpoint reachable (Memory marker).", 2.0),
        ("/privacy", "Policy documentation found.", 1.0),
        ("security.txt", "security.txt found.", 1.0),
        ("/.well-known/mcp", "MCP server capability detected.", 2.0),
        ("vllm", "vLLM Inference Engine fingerprint detected.", 1.5),
        ("ollama", "Ollama Local Runtime fingerprint detected.", 1.5)
    ]
    for p, f, w in path_hints:
        if pr.status == 200 and p in pr.url: evidence.append(Evidence("probe", f, w))

    if category == "dangerous":
        if pr.status == 200:
            evidence.append(Evidence("probe", f"DANGEROUS endpoint open (200): {pr.url}", 3.0))
            gaps.append(f"Dangerous endpoint accessible without auth: {pr.url}")
            recs.append("Require auth on tool/execution/upload endpoints.")
        elif pr.status in (401, 403): evidence.append(Evidence("probe", f"Dangerous endpoint protected ({pr.status}): {pr.url}", 1.5))
    elif pr.status == 200: evidence.append(Evidence("probe", f"Safe endpoint reachable: {pr.url}", 1.2))

def create_bundle(out_path: str, report: ScanReport, evidence_files: Dict[str, bytes], sign_keys: List[str] = None):
    """Create a multi-sig verifiable audit bundle."""
    bundle_path = out_path if out_path.endswith(".andsz") else out_path + ".andsz"
    manifest = {"timestamp": datetime.now(timezone.utc).isoformat(), "target": report.target, "files": {}}
    report_json = json.dumps(asdict(report), indent=2).encode("utf-8")
    manifest["files"]["report.json"] = hashlib.sha256(report_json).hexdigest()
    for name, content in evidence_files.items():
        manifest["files"][name] = hashlib.sha256(content).hexdigest()

    manifest_bytes = jcs.canonicalize(manifest)
    signatures = []

    if sign_keys:
        for k in sign_keys:
            try:
                priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(k))
                sig = priv.sign(manifest_bytes)
                pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                signatures.append({
                    "alg": "ed25519",
                    "sig": base64.b64encode(sig).decode('utf-8'),
                    "pubkey": base64.b64encode(pub).decode('utf-8')
                })
            except Exception as e: logger.error(f"Failed to sign bundle with key {k[:8]}: {e}")

    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.json", report_json)
        zf.writestr("manifest.json", manifest_bytes)
        if signatures:
            zf.writestr("signatures.json", json.dumps(signatures, indent=2).encode("utf-8"))
        for name, content in evidence_files.items():
            zf.writestr(f"evidence/{name}", content)
    logger.info(f"Audit bundle created: {bundle_path} ({len(signatures)} sigs)")
