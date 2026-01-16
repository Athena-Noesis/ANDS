#!/usr/bin/env python3
"""ands_scan.py — Evidence-based ANDS scanner (DECLARED + OBSERVED + OPTIONAL PROBES)

What it does (safe, conservative):
1) Fetches `/.well-known/ands.json` (DECLARED track), if present
2) Fetches `openapi.json` (OBSERVED track) for capability hints, if present
3) Optional verification probes (non-invasive):
   - checks for auth gating on common health/status endpoints
   - checks whether dangerous-looking endpoints appear protected (401/403 expected)
   - records minimal HTTP status evidence (best-effort)

Outputs a JSON report with:
- declared ANDS, certification
- inferred ANDS, confidence
- evidence list, gaps, recommendations
- probe results (if verification mode enabled)

Important:
- External scanning cannot prove internal behavior.
- Probes are read-only and intentionally minimal.
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import re
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import jcs
import requests
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DEFAULT_TIMEOUT = 8
DEFAULT_USER_AGENT = "ands-scan/1.1"
ANDS_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+\.\d+$")


@dataclass
class Evidence:
    source: str
    finding: str
    weight: float = 1.0


@dataclass
class ProbeResult:
    url: str
    method: str
    status: Optional[int]
    headers: Dict[str, str]
    note: str


@dataclass
class ScanReport:
    target: str
    reachable: bool
    declared_ands: Optional[str]
    declared_certification_level: Optional[str]
    inferred_ands: Optional[str]
    confidence: float
    evidence: List[Evidence]
    gaps: List[str]
    recommendations: List[str]
    probes: List[ProbeResult]


def verify_declaration_signature(doc: Dict[str, Any]) -> Tuple[bool, str]:
    """Replicates verify_signature logic from validate_declaration.py."""
    signed = doc.get("signed")
    if not isinstance(signed, dict):
        return False, "Missing 'signed' block."

    alg = signed.get("alg")
    sig_b64 = signed.get("sig")
    pub_b64 = signed.get("pubkey")

    if alg != "ed25519":
        return False, f"Unsupported algorithm: {alg}"
    if not sig_b64 or not pub_b64:
        return False, "Missing sig or pubkey."

    try:
        sig = base64.b64decode(sig_b64)
        pub = base64.b64decode(pub_b64)

        # Canonicalize
        d = dict(doc)
        d.pop("signed", None)
        msg = jcs.canonicalize(d)

        pk = Ed25519PublicKey.from_public_bytes(pub)
        pk.verify(sig, msg)
        return True, "Signature VALID."
    except Exception as e:
        return False, f"Signature INVALID: {e}"


def normalize_base_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not url.endswith("/"):
        url += "/"
    return url


def safe_request(
    method: str,
    url: str,
    timeout: int,
    user_agent: str = DEFAULT_USER_AGENT,
    retries: int = 3,
    jitter: float = 0.0,
    headers: Optional[Dict[str, str]] = None
) -> Tuple[Optional[requests.Response], Optional[str]]:
    last_err = "UNKNOWN"
    merged_headers = {"User-Agent": user_agent}
    if headers:
        merged_headers.update(headers)

    for attempt in range(retries + 1):
        if attempt > 0:
            # Exponential backoff: 0.5s, 1s, 2s...
            backoff = (2 ** (attempt - 1)) * 0.5
            sleep_time = backoff + (random.uniform(0, jitter) if jitter > 0 else 0)
            time.sleep(sleep_time)

        try:
            r = requests.request(method, url, timeout=timeout, headers=merged_headers)
            return r, None
        except requests.exceptions.Timeout:
            last_err = "TIMEOUT"
        except requests.exceptions.RequestException as e:
            last_err = f"ERROR ({type(e).__name__})"
        except Exception as e:
            last_err = f"ERROR ({str(e)})"
            return None, last_err

    return None, last_err


def openapi_hints(openapi: Dict[str, Any]) -> List[str]:
    txt = json.dumps(openapi).lower()
    hints: List[str] = []

    if any(k in txt for k in ["tool", "function_call", "connector", "mcp"]):
        hints.append("tool_or_connector_surface")
    if any(k in txt for k in ["snapshot", "provenance", "audit", "log"]):
        hints.append("audit_or_snapshot_surface")
    if any(k in txt for k in ["upload", "attachment", "file", "blob", "s3"]):
        hints.append("file_handling_surface")
    if any(k in txt for k in ["execute", "sandbox", "run"]):
        hints.append("code_execution_surface")
    if any(k in txt for k in ["rbac", "roles", "permissions"]):
        hints.append("rbac_surface")

    # scan paths for stronger hints
    for p in (openapi.get("paths") or {}).keys():
        pl = str(p).lower()
        if "mcp" in pl:
            hints.append("mcp_endpoints")
        if "execute" in pl or "run" in pl:
            hints.append("execution_endpoints")
        if "snapshot" in pl:
            hints.append("snapshot_endpoints")
        if "audit" in pl or "provenance" in pl:
            hints.append("audit_endpoints")
        if "upload" in pl or "file" in pl or "attachment" in pl:
            hints.append("file_endpoints")

    return sorted(set(hints))


def pick_probe_paths(openapi: Optional[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Return small probe sets: safe vs dangerous."""
    common_safe = [
        "/health", "/status", "/metrics",
        "/robots.txt", "/.well-known/security.txt",
        "/.well-known/ai-plugin.json", "/v1/models",
        "/privacy", "/tos"
    ]
    dangerous_defaults = [
        "/execute", "/run", "/tool", "/mcp", "/upload", "/files",
        "/.well-known/mcp", "/v1/sessions", "/v1/history"
    ]

    if not openapi or not (openapi.get("paths")):
        return {"safe": common_safe, "dangerous": dangerous_defaults}

    paths = list((openapi.get("paths") or {}).keys())
    lower = [p.lower() for p in paths]

    safe_hits = [cand for cand in common_safe if cand.lower() in lower]
    if not safe_hits:
        safe_hits = common_safe

    danger_hits = []
    for p in paths:
        pl = p.lower()
        if any(tok in pl for tok in ["execute", "run", "mcp", "tool", "upload", "file", "connector"]):
            danger_hits.append(p)
    danger_hits = danger_hits[:6] if danger_hits else dangerous_defaults

    return {"safe": safe_hits[:5], "dangerous": danger_hits}


def infer_ands(hints: List[str], evidence: List[Evidence], gaps: List[str]) -> Tuple[str, float]:
    # Conservative baseline
    C, A, M, G, R = 2, 1, 1, 1, 3

    # Track findings to avoid duplicate weighting
    if "rbac_surface" in hints:
        G = max(G, 2)
        evidence.append(Evidence("openapi", "RBAC/permissions indicators found.", 1.5))

    if "audit_or_snapshot_surface" in hints or "audit_endpoints" in hints:
        M = max(M, 2)
        G = max(G, 2)
        evidence.append(Evidence("openapi", "Audit/provenance/snapshot indicators found.", 1.5))

    if "tool_or_connector_surface" in hints or "mcp_endpoints" in hints:
        R = max(R, 4)
        evidence.append(Evidence("openapi", "Tool/connector indicators found (higher risk surface).", 2.0))

    if "file_handling_surface" in hints or "file_endpoints" in hints:
        R = max(R, 4)
        evidence.append(Evidence("openapi", "File/attachment handling indicators found.", 1.2))

    if "code_execution_surface" in hints or "execution_endpoints" in hints:
        R = 5
        evidence.append(Evidence("openapi", "Code execution indicators found (highest risk surface).", 3.0))
        gaps.append("Code execution surface detected; verify sandboxing and explicit human approval controls.")

    # Weighted confidence calculation
    # Base confidence is 0.2
    # Each evidence weight adds to confidence, capped at 0.9
    pos_weight = sum(e.weight for e in evidence)
    # Penalize for gaps (each gap reduces confidence by 0.05)
    gap_penalty = len(gaps) * 0.05

    conf = 0.2 + (pos_weight * 0.1) - gap_penalty
    conf = max(0.1, min(0.9, conf))

    return f"{C}.{A}.{M}.{G}.{R}", conf


def analyze_probe_status(pr: ProbeResult, category: str, evidence: List[Evidence], gaps: List[str], recs: List[str]) -> None:
    """Interpret probe outcomes conservatively."""
    if pr.status is None:
        gaps.append(f"Probe failed ({category}): {pr.url} ({pr.note})")
        return

    # Check security headers
    sec_headers = {
        "Strict-Transport-Security": "HSTS",
        "X-Content-Type-Options": "NoSniff",
        "X-Frame-Options": "Anti-Clickjacking",
        "Content-Security-Policy": "CSP"
    }
    found_sec = []
    for h, label in sec_headers.items():
        if any(h.lower() == k.lower() for k in pr.headers.keys()):
            found_sec.append(label)

    if found_sec:
        evidence.append(Evidence("probe", f"Security headers found on {pr.url}: {', '.join(found_sec)}", 0.5))

    # Path-specific interpretations
    if pr.status == 200:
        if "ai-plugin.json" in pr.url:
            evidence.append(Evidence("probe", "AI Plugin manifest found.", 2.5))
        elif "/v1/models" in pr.url:
            evidence.append(Evidence("probe", "Model listing endpoint reachable.", 1.5))
        elif "/v1/sessions" in pr.url or "/v1/history" in pr.url:
            evidence.append(Evidence("probe", "Session/History endpoint reachable (Memory marker).", 2.0))
        elif "/privacy" in pr.url or "/tos" in pr.url:
            evidence.append(Evidence("probe", "Policy/Governance documentation found.", 1.0))
        elif "security.txt" in pr.url:
            evidence.append(Evidence("probe", "security.txt found.", 1.0))

    if category == "dangerous":
        if pr.status == 200:
            evidence.append(Evidence("probe", f"DANGEROUS endpoint appears open (200): {pr.url}", 3.0))
            gaps.append(f"Dangerous endpoint accessible without auth: {pr.url}")
            recs.append("Require auth on tool/execution/upload endpoints; treat as R>=4 until proven otherwise.")
        elif pr.status in (401, 403):
            evidence.append(Evidence("probe", f"Dangerous endpoint protected (expected {pr.status}): {pr.url}", 1.5))
        elif pr.status in (404, 405):
            evidence.append(Evidence("probe", f"Dangerous endpoint not found/allowed ({pr.status}): {pr.url}", 0.8))
        else:
            evidence.append(Evidence("probe", f"Dangerous endpoint returned {pr.status}: {pr.url}", 1.0))
    else:
        if pr.status == 200:
            evidence.append(Evidence("probe", f"Health/status endpoint reachable (200): {pr.url}", 1.2))
        elif pr.status in (401, 403):
            evidence.append(Evidence("probe", f"Health/status endpoint auth-gated ({pr.status}): {pr.url}", 1.0))
        else:
            evidence.append(Evidence("probe", f"Health/status endpoint returned {pr.status}: {pr.url}", 0.8))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="Base URL or hostname (e.g., https://example.com)")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--retries", type=int, default=3, help="Number of retries for network requests")
    ap.add_argument("--jitter", type=float, default=0.0, help="Max random jitter (seconds) to add between retries")
    ap.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent header for requests")
    ap.add_argument("-H", "--header", action="append", help="Custom headers (Key: Value)")
    ap.add_argument("--openapi-url", help="Direct URL to openapi.json (skips discovery)")
    ap.add_argument("--out", default="", help="Write JSON report to file")
    ap.add_argument("--verify", action="store_true", help="Enable non-invasive verification probes")
    ap.add_argument("--max-probes", type=int, default=10, help="Maximum number of probe requests (default 10)")
    args = ap.parse_args()

    custom_headers: Dict[str, str] = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()

    base = normalize_base_url(args.target)
    evidence: List[Evidence] = []
    gaps: List[str] = []
    recs: List[str] = []
    probes: List[ProbeResult] = []

    # Reachability probe (HEAD first, fallback GET)
    r0, err = safe_request("HEAD", base, args.timeout, args.user_agent, args.retries, args.jitter, custom_headers)
    if r0 is None:
        r0, err = safe_request("GET", base, args.timeout, args.user_agent, args.retries, args.jitter, custom_headers)

    if r0 is None:
        report = ScanReport(
            target=base,
            reachable=False,
            declared_ands=None,
            declared_certification_level=None,
            inferred_ands=None,
            confidence=0.0,
            evidence=[Evidence("probe", f"Unreachable: {err}", 3.0)],
            gaps=["Target not reachable."],
            recommendations=["Confirm URL/DNS/TLS, and network access."],
            probes=[],
        )
        out = json.dumps(asdict(report), indent=2)
        if args.out:
            Path(args.out).write_text(out + "\n", encoding="utf-8")
        else:
            print(out)
        return 2

    evidence.append(Evidence("probe", f"Reachable: HTTP {r0.status_code}", 1.0))

    # Declaration
    declared_ands: Optional[str] = None
    declared_cert: Optional[str] = None
    wk_url = urljoin(base, ".well-known/ands.json")
    rwk, _ = safe_request("GET", wk_url, args.timeout, args.user_agent, args.retries, args.jitter, custom_headers)
    if rwk is not None and rwk.ok:
        try:
            data = rwk.json()
            cand = data.get("declared_ands") or data.get("ands") or data.get("declared")
            declared_cert = data.get("certification_level") or data.get("cert_level")
            if isinstance(cand, str) and ANDS_RE.match(cand):
                declared_ands = cand
                evidence.append(Evidence("ands_well_known", f"Declared ANDS: {cand}", 3.0))
            else:
                gaps.append("ANDS declaration present but missing/invalid declared_ands format.")
            if declared_cert:
                evidence.append(Evidence("ands_well_known", f"Declared certification_level: {declared_cert}", 1.2))

            # Verify signature if present
            if "signed" in data:
                ok, msg = verify_declaration_signature(data)
                if ok:
                    evidence.append(Evidence("ands_well_known", msg, 2.0))
                else:
                    gaps.append(msg)
        except Exception:
            gaps.append("Failed to parse /.well-known/ands.json as JSON.")
    else:
        gaps.append("No /.well-known/ands.json found (or not accessible).")
        recs.append("Ask vendor to publish /.well-known/ands.json with declared_ands + certification_level.")

    # OpenAPI hints
    openapi: Optional[Dict[str, Any]] = None
    hints: List[str] = []
    if args.openapi_url:
        oa_urls = [args.openapi_url]
    else:
        oa_urls = [
            urljoin(base, "openapi.json"),
            urljoin(base, "openapi.yaml"),
            urljoin(base, "openapi.yml"),
            urljoin(base, "v1/openapi.json"),
            urljoin(base, "api/v1/openapi.json"),
            urljoin(base, "swagger.json"),
            urljoin(base, "swagger.yaml"),
            urljoin(base, "swagger.yml")
        ]

    for oa_url in oa_urls:
        roa, _ = safe_request("GET", oa_url, args.timeout, args.user_agent, args.retries, args.jitter, custom_headers)
        if roa is not None and roa.ok:
            try:
                if oa_url.endswith((".yaml", ".yml")):
                    openapi = yaml.safe_load(roa.text)
                else:
                    openapi = roa.json()

                if isinstance(openapi, dict):
                    hints = openapi_hints(openapi)
                    evidence.append(Evidence("openapi", f"OpenAPI hints from {oa_url}: {', '.join(hints) if hints else 'none'}", 1.2))
                    break
                else:
                    gaps.append(f"{oa_url} parsed but is not a dictionary.")
            except Exception:
                gaps.append(f"{oa_url} present but invalid format.")

    if not openapi:
        gaps.append("No openapi.json found (or not accessible).")

    # Optional verification probes
    if args.verify:
        targets = pick_probe_paths(openapi)
        budget = max(0, args.max_probes)

        def do_probe(path: str, category: str) -> None:
            nonlocal budget
            if budget <= 0:
                return
            budget -= 1
            full = urljoin(base, path.lstrip("/"))

            # Try GET
            resp, perr = safe_request("GET", full, args.timeout, args.user_agent, args.retries, args.jitter, custom_headers)
            pr = ProbeResult(
                url=full,
                method="GET",
                status=(resp.status_code if resp is not None else None),
                headers=(dict(resp.headers) if resp is not None else {}),
                note=(perr or "")
            )
            probes.append(pr)
            analyze_probe_status(pr, category, evidence, gaps, recs)

            # Try OPTIONS for dangerous endpoints
            if category == "dangerous" and budget > 0:
                budget -= 1
                oresp, operr = safe_request("OPTIONS", full, args.timeout, args.user_agent, args.retries, args.jitter, custom_headers)
                if oresp is not None:
                    opr = ProbeResult(
                        url=full,
                        method="OPTIONS",
                        status=oresp.status_code,
                        headers=dict(oresp.headers),
                        note=(operr or "")
                    )
                    probes.append(opr)
                    allow = oresp.headers.get("Allow")
                    if allow:
                        evidence.append(Evidence("probe", f"OPTIONS {full} allows: {allow}", 1.0))

        for p in targets["safe"]:
            do_probe(p, "safe")
        for p in targets["dangerous"]:
            do_probe(p, "dangerous")

        evidence.append(Evidence("probe", f"Verification probes executed: {len(probes)}", 0.8))

    inferred, conf = infer_ands(hints, evidence, gaps)

    # If probes found dangerous endpoints open, bump risk conservatively
    if any(p.status == 200 and any(tok in p.url.lower() for tok in ["execute", "run", "mcp", "tool", "upload", "file"]) for p in probes):
        parts = inferred.split(".")
        if len(parts) == 5:
            parts[-1] = "5"
            inferred = ".".join(parts)
            conf = min(0.90, conf + 0.10)
            evidence.append(Evidence("probe", "Inferred risk raised due to open dangerous endpoint(s).", 2.5))

    if declared_ands:
        # Boost confidence if we have a declaration
        conf = min(0.95, conf + 0.25)
        if declared_ands != inferred:
            gaps.append(f"Declared ANDS ({declared_ands}) differs from inferred ({inferred}). Verify accuracy.")
            recs.append("Require VERIFIED/AUDITED certification before high-risk deployment if discrepancy persists.")

    if not declared_cert:
        recs.append("Require certification_level (SELF/VERIFIED/AUDITED) for high-risk systems (R>=4).")

    report = ScanReport(
        target=base,
        reachable=True,
        declared_ands=declared_ands,
        declared_certification_level=declared_cert,
        inferred_ands=inferred,
        confidence=round(conf, 2),
        evidence=evidence,
        gaps=gaps,
        recommendations=sorted(set(recs)),
        probes=probes,
    )

    out = json.dumps(asdict(report), indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
