#!/usr/bin/env python3
"""ands_scan.py — Evidence-based ANDS scanner (DECLARED + OBSERVED + OPTIONAL PROBES)
"""

from __future__ import annotations
import argparse
import json
import logging
import sys
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urljoin

from ands import (
    ScanReport, Evidence, ProbeResult,
    normalize_base_url, get_session, safe_request, check_tls_integrity,
    openapi_hints, pick_probe_paths, analyze_probe_status, infer_ands, create_bundle,
    verify_declaration_signature, logger
)

DEFAULT_TIMEOUT = 8
SUPPORTED_ANDS_VERSIONS = ["1.0"]

def print_summary(report: ScanReport) -> None:
    out = sys.stderr
    width = 60
    line = lambda c="-": out.write(c * width + "\n")
    out.write("\n")
    line("=")
    out.write(f" ANDS SCAN SUMMARY: {report.target}\n")
    line("=")
    out.write(f" Reachable:      {'YES' if report.reachable else 'NO'}\n")
    out.write(f" Declared ANDS:  {report.declared_ands or 'N/A'}\n")
    out.write(f" Inferred ANDS:  {report.inferred_ands or 'N/A'}\n")
    out.write(f" Confidence:     {report.confidence * 100:.0f}%\n")
    if report.declared_certification_level: out.write(f" Certification:  {report.declared_certification_level}\n")
    line()
    out.write(f" Findings:       {len(report.evidence)} indicators\n")
    out.write(f" Gaps:           {len(report.gaps)} identified\n")
    if report.recommendations:
        line()
        out.write(" Top Recommendations:\n")
        for rec in report.recommendations[:3]: out.write(f" - {rec}\n")
    line("=")
    out.write("\n")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="Base URL or hostname")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--jitter", type=float, default=0.0)
    ap.add_argument("--user-agent", default="ands-scan/1.1")
    ap.add_argument("-H", "--header", action="append")
    ap.add_argument("--proxy")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--cacert")
    ap.add_argument("--openapi-url")
    ap.add_argument("--out", default="")
    ap.add_argument("--bundle")
    ap.add_argument("--sign-bundle")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--max-probes", type=int, default=15)
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args()

    lvl = logging.WARNING
    if args.verbose == 1: lvl = logging.INFO
    elif args.verbose >= 2: lvl = logging.DEBUG
    logging.basicConfig(level=lvl, format="%(levelname)s: %(message)s", stream=sys.stderr)

    session = get_session(args.retries, args.proxy, args.cert, args.key, args.cacert)
    custom_headers = {h.split(":", 1)[0].strip(): h.split(":", 1)[1].strip() for h in args.header if ":" in h} if args.header else {}
    base = normalize_base_url(args.target)
    evidence, gaps, recs, probes, snapshot_files = [], [], [], [], {}

    check_tls_integrity(base, evidence)
    r0, err = safe_request(session, "HEAD", base, args.timeout, args.user_agent, args.retries, args.jitter, custom_headers)
    if r0 is None: r0, err = safe_request(session, "GET", base, args.timeout, args.user_agent, args.retries, args.jitter, custom_headers)

    if r0 is None:
        report = ScanReport(base, False, None, None, None, 0.0, [Evidence("probe", f"Unreachable: {err}", 3.0)], ["Target not reachable."], ["Confirm URL/DNS/TLS."], [])
        out = json.dumps(asdict(report), indent=2)
        if args.out: Path(args.out).write_text(out + "\n")
        else: print(out)
        return 2

    evidence.append(Evidence("probe", f"Reachable: HTTP {r0.status_code}", 1.0))
    declared_ands, declared_cert = None, None
    wk_url = urljoin(base, ".well-known/ands.json")
    rwk, _ = safe_request(session, "GET", wk_url, args.timeout, args.user_agent, args.retries, args.jitter, custom_headers)
    if rwk and rwk.ok:
        snapshot_files["ands.json"] = rwk.content
        try:
            data = rwk.json()
            declared_ver = data.get("ands_version")
            if declared_ver and declared_ver not in SUPPORTED_ANDS_VERSIONS: gaps.append(f"Unsupported version: {declared_ver}")
            cand = data.get("declared_ands") or data.get("ands")
            declared_cert = data.get("certification_level")
            if isinstance(cand, str):
                declared_ands = cand
                evidence.append(Evidence("ands_well_known", f"Declared ANDS: {cand}", 3.0))
            if declared_cert: evidence.append(Evidence("ands_well_known", f"Declared certification: {declared_cert}", 1.2))

            # PRIME DIRECTIVE: Evidence Harvesting
            harvest_targets = {
                "attestation": data.get("attestation_urls", []),
                "sbom": data.get("sbom_urls", []),
                "policy": [data.get("contact")] if data.get("contact", "").startswith("http") else []
            }
            for category, urls in harvest_targets.items():
                for url in urls:
                    logger.info(f"Harvesting {category}: {url}")
                    hresp, herr = safe_request(session, "GET", url, args.timeout, args.user_agent, args.retries, args.jitter, custom_headers)
                    if hresp and hresp.ok:
                        snapshot_files[f"harvest_{category}_{Path(url).name}"] = hresp.content
                        evidence.append(Evidence("harvest", f"Harvested {category} artifact: {url}", 0.5))
                    else: gaps.append(f"Failed to harvest {category} from {url}: {herr}")

            if "signed" in data:
                ok, msg = verify_declaration_signature(data)
                evidence.append(Evidence("ands_well_known", msg, 2.0)) if ok else gaps.append(msg)
        except: gaps.append("Failed to parse ands.json")
    else:
        gaps.append("No ands.json found.")
        recs.append("Publish /.well-known/ands.json")

    oa_urls = [args.openapi_url] if args.openapi_url else [urljoin(base, p) for p in ["openapi.json", "openapi.yaml", "openapi.yml", "swagger.json"]]
    openapi, hints = None, []
    for oa_url in oa_urls:
        roa, _ = safe_request(session, "GET", oa_url, args.timeout, args.user_agent, args.retries, args.jitter, custom_headers)
        if roa and roa.ok:
            snapshot_files[Path(oa_url).name] = roa.content
            try:
                openapi = yaml.safe_load(roa.text) if oa_url.endswith((".yaml", ".yml")) else roa.json()
                if isinstance(openapi, dict):
                    hints = openapi_hints(openapi)
                    evidence.append(Evidence("openapi", f"Hints from {oa_url}: {', '.join(hints) or 'none'}", 1.2))
                    break
            except: pass
    if not openapi: gaps.append("No openapi spec found.")

    if args.verify:
        targets = pick_probe_paths(openapi)
        budget = max(0, args.max_probes)
        for cat in ["safe", "dangerous"]:
            for path in targets[cat]:
                if budget <= 0: break
                budget -= 1
                full = urljoin(base, path.lstrip("/"))
                resp, perr = safe_request(session, "GET", full, args.timeout, args.user_agent, args.retries, args.jitter, custom_headers)
                pr = ProbeResult(full, "GET", (resp.status_code if resp else None), (dict(resp.headers) if resp else {}), (perr or ""))
                probes.append(pr)
                analyze_probe_status(pr, cat, evidence, gaps, recs)
                if cat == "dangerous" and budget > 0:
                    budget -= 1
                    oresp, _ = safe_request(session, "OPTIONS", full, args.timeout, args.user_agent, args.retries, args.jitter, custom_headers)
                    if oresp:
                        probes.append(ProbeResult(full, "OPTIONS", oresp.status_code, dict(oresp.headers), ""))
                        if oresp.headers.get("Allow"): evidence.append(Evidence("probe", f"OPTIONS {full} allows: {oresp.headers.get('Allow')}", 1.0))
        evidence.append(Evidence("probe", f"Probes executed: {len(probes)}", 0.8))

    inferred, conf = infer_ands(hints, evidence, gaps)
    if any(p.status == 200 and any(t in p.url.lower() for t in ["execute", "run", "mcp", "tool", "upload", "file"]) for p in probes):
        parts = inferred.split(".")
        if len(parts) == 5:
            parts[-1] = "5"
            inferred = ".".join(parts)
            conf = min(0.90, conf + 0.10)
            evidence.append(Evidence("probe", "Risk raised due to open dangerous endpoints.", 2.5))

    if declared_ands:
        conf = min(0.95, conf + 0.25)
        if declared_ands != inferred: gaps.append(f"Discrepancy: Declared {declared_ands} vs Inferred {inferred}")
    if not declared_cert: recs.append("Require certification_level (R>=4)")

    report = ScanReport(base, True, declared_ands, declared_cert, inferred, round(conf, 2), evidence, gaps, sorted(set(recs)), probes)
    out_json = json.dumps(asdict(report), indent=2)
    if args.out: Path(args.out).write_text(out_json + "\n")
    else: print(out_json)
    if args.bundle: create_bundle(args.bundle, report, snapshot_files, args.sign_bundle)
    print_summary(report)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
