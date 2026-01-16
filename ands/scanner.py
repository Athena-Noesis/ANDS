import json
import logging
import zipfile
import hashlib
import jcs
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import asdict
from urllib.parse import urljoin
import base64

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import Evidence, ProbeResult, ScanReport
from .utils import safe_request, logger

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

def infer_ands(hints: List[str], evidence_list: List[Evidence], gaps_list: List[str]) -> Tuple[str, float]:
    C, A, M, G, R = 2, 1, 1, 1, 3
    probe_txt = " ".join(e.finding for e in evidence_list if e.source == "probe").lower()
    if "ai plugin" in probe_txt or "model listing" in probe_txt: C = max(C, 3)
    if "session/history" in probe_txt: M = max(M, 2)
    if "policy/governance" in probe_txt: G = max(G, 2)

    def add_unique(source, finding, weight):
        if not any(e.source == source and e.finding == finding for e in evidence_list):
            evidence_list.append(Evidence(source, finding, weight))

    mapping = {
        "rbac_surface": (0, 0, 0, 2, 0, "RBAC/permissions indicators found.", 1.5),
        "audit_or_snapshot_surface": (0, 0, 2, 2, 0, "Audit/provenance/snapshot indicators found.", 1.5),
        "tool_or_connector_surface": (0, 0, 0, 0, 4, "Tool/connector indicators found (higher risk surface).", 2.0),
        "file_handling_surface": (0, 0, 0, 0, 4, "File/attachment handling indicators found.", 1.2),
        "code_execution_surface": (0, 0, 0, 0, 5, "Code execution indicators found (highest risk surface).", 3.0),
    }
    for h in hints:
        if h in mapping:
            res = mapping[h]
            C, A, M, G, R = max(C, res[0]), max(A, res[1]), max(M, res[2]), max(G, res[3]), max(R, res[4])
            add_unique("openapi", res[5], res[6])

    if "code_execution_surface" in hints:
        msg = "Code execution surface detected; verify sandboxing and explicit human approval controls."
        if msg not in gaps_list: gaps_list.append(msg)

    pos_weight = sum(e.weight for e in evidence_list)
    gap_penalty = len(gaps_list) * 0.05
    conf = max(0.1, min(0.9, 0.2 + (pos_weight * 0.1) - gap_penalty))
    return f"{C}.{A}.{M}.{G}.{R}", conf

def analyze_probe_status(pr: ProbeResult, category: str, evidence: List[Evidence], gaps: List[str], recs: List[str]) -> None:
    if pr.status is None:
        gaps.append(f"Probe failed ({category}): {pr.url} ({pr.note})")
        return
    sec_headers = {"Strict-Transport-Security": "HSTS", "X-Content-Type-Options": "NoSniff", "X-Frame-Options": "Anti-Clickjacking", "Content-Security-Policy": "CSP"}
    found_sec = [label for h, label in sec_headers.items() if any(h.lower() == k.lower() for k in pr.headers.keys())]
    if found_sec: evidence.append(Evidence("probe", f"Security headers found on {pr.url}: {', '.join(found_sec)}", 0.5))

    path_hints = [("ai-plugin.json", "AI Plugin manifest found.", 2.5), ("/v1/models", "Model listing endpoint reachable.", 1.5), ("/v1/sessions", "Session/History endpoint reachable (Memory marker).", 2.0), ("/privacy", "Policy documentation found.", 1.0), ("security.txt", "security.txt found.", 1.0)]
    for p, f, w in path_hints:
        if pr.status == 200 and p in pr.url: evidence.append(Evidence("probe", f, w))

    if category == "dangerous":
        if pr.status == 200:
            evidence.append(Evidence("probe", f"DANGEROUS endpoint open (200): {pr.url}", 3.0))
            gaps.append(f"Dangerous endpoint accessible without auth: {pr.url}")
            recs.append("Require auth on tool/execution/upload endpoints.")
        elif pr.status in (401, 403): evidence.append(Evidence("probe", f"Dangerous endpoint protected ({pr.status}): {pr.url}", 1.5))
    elif pr.status == 200: evidence.append(Evidence("probe", f"Safe endpoint reachable: {pr.url}", 1.2))

def create_bundle(out_path: str, report: ScanReport, evidence_files: Dict[str, bytes], sign_key: Optional[str] = None):
    bundle_path = out_path if out_path.endswith(".andsz") else out_path + ".andsz"
    manifest = {"timestamp": datetime.now(timezone.utc).isoformat(), "target": report.target, "files": {}}
    report_json = json.dumps(asdict(report), indent=2).encode("utf-8")
    manifest["files"]["report.json"] = hashlib.sha256(report_json).hexdigest()
    for name, content in evidence_files.items():
        manifest["files"][name] = hashlib.sha256(content).hexdigest()
    manifest_bytes = jcs.canonicalize(manifest)
    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.json", report_json)
        zf.writestr("manifest.json", manifest_bytes)
        if sign_key:
            try:
                priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(sign_key))
                sig = priv.sign(manifest_bytes)
                pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                signature = {"alg": "ed25519", "sig": base64.b64encode(sig).decode('utf-8'), "pubkey": base64.b64encode(pub).decode('utf-8')}
                zf.writestr("signature.json", json.dumps(signature, indent=2).encode("utf-8"))
            except Exception as e: logger.error(f"Failed to sign bundle: {e}")
        for name, content in evidence_files.items(): zf.writestr(f"evidence/{name}", content)
    logger.info(f"Audit bundle created: {bundle_path}")
