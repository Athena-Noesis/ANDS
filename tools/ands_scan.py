#!/usr/bin/env python3
"""ands_scan.py — Evidence-based ANDS scanner (DECLARED + OBSERVED + OPTIONAL PROBES)
"""

from __future__ import annotations
import argparse
import base64
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
    map_to_regulations, verify_declaration_signature, get_supported_versions, logger
)
from ands.config import config
from ands.schema_migrator import SchemaMigrator
from ands.swarm import SwarmScorer
from ands.plugins_engine import load_plugins
import yaml

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

def run_scan(target: str, args: argparse.Namespace) -> ScanReport:
    """Core logic of ands-scan refactored for programmatic use."""
    # We assume 'args' has all the necessary fields or we provide defaults
    session = get_session(
        getattr(args, 'retries', config.get("network.retries", 3)),
        getattr(args, 'proxy', config.get("network.proxy")),
        getattr(args, 'cert', None),
        getattr(args, 'key', None),
        getattr(args, 'cacert', None)
    )

    timeout = getattr(args, 'timeout', config.get("network.timeout", 10))
    user_agent = getattr(args, 'user_agent', config.get("network.user_agent", "ands-scan/1.1"))
    retries = getattr(args, 'retries', config.get("network.retries", 3))
    jitter = getattr(args, 'jitter', 0.0)

    custom_headers = {}
    if getattr(args, 'header', None):
        custom_headers = {h.split(":", 1)[0].strip(): h.split(":", 1)[1].strip() for h in args.header if ":" in h}

    base = normalize_base_url(target)
    evidence, gaps, recs, probes, snapshot_files = [], [], [], [], {}

    check_tls_integrity(base, evidence)

    # Load and execute plugins
    plugins = load_plugins()
    for p in plugins:
        logger.info(f"Executing plugin: {p.name()}")
        p.execute_probe(base, session, evidence, gaps)

    r0, err = safe_request(session, "HEAD", base, timeout, user_agent, retries, jitter, custom_headers)
    if r0 is None: r0, err = safe_request(session, "GET", base, timeout, user_agent, retries, jitter, custom_headers)

    if r0 is None:
        return ScanReport(base, False, None, None, None, 0.0, [Evidence("probe", f"Unreachable: {err}", 3.0)], ["Target not reachable."], ["Confirm URL/DNS/TLS."], [])

    evidence.append(Evidence("probe", f"Reachable: HTTP {r0.status_code}", 1.0))
    declared_ands, declared_cert = None, None
    wk_url = urljoin(base, ".well-known/ands.json")
    rwk, _ = safe_request(session, "GET", wk_url, timeout, user_agent, retries, jitter, custom_headers)
    if rwk and rwk.ok:
        snapshot_files["ands.json"] = rwk.content
        try:
            data = rwk.json()
            migrator = SchemaMigrator()
            supported_versions = get_supported_versions()
            declared_ver = migrator.detect_version(data)

            if declared_ver not in supported_versions:
                gaps.append(f"Unsupported version: {declared_ver}")

            # Auto-normalize in memory for internal processing
            data = migrator.normalize(data)

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
                    hresp, herr = safe_request(session, "GET", url, timeout, user_agent, retries, jitter, custom_headers)
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

    default_openapi = config.get("scanner.openapi_paths", ["openapi.json", "openapi.yaml", "openapi.yml", "swagger.json"])
    oa_urls = [getattr(args, 'openapi_url', None)] if getattr(args, 'openapi_url', None) else [urljoin(base, p) for p in default_openapi]
    openapi, hints = None, []
    for oa_url in oa_urls:
        if not oa_url: continue
        roa, _ = safe_request(session, "GET", oa_url, timeout, user_agent, retries, jitter, custom_headers)
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

    if getattr(args, 'verify', False):
        targets = pick_probe_paths(openapi)
        budget = max(0, getattr(args, 'max_probes', 15))
        for cat in ["safe", "dangerous"]:
            for path in targets[cat]:
                if budget <= 0: break
                budget -= 1
                full = urljoin(base, path.lstrip("/"))
                resp, perr = safe_request(session, "GET", full, timeout, user_agent, retries, jitter, custom_headers)
                pr = ProbeResult(full, "GET", (resp.status_code if resp else None), (dict(resp.headers) if resp else {}), (perr or ""))
                probes.append(pr)
                analyze_probe_status(pr, cat, evidence, gaps, recs)
        evidence.append(Evidence("probe", f"Probes executed: {len(probes)}", 0.8))

    inferred, conf, reasoning = infer_ands(hints, evidence, gaps)

    if declared_ands:
        conf = min(0.95, conf + 0.25)
        if declared_ands != inferred: gaps.append(f"Discrepancy: Declared {declared_ands} vs Inferred {inferred}")
    if not declared_cert: recs.append("Require certification_level (R>=4)")

    custom_policy = None
    if getattr(args, 'policy', None) and Path(args.policy).exists():
        with open(args.policy, "r") as f:
            custom_policy = yaml.safe_load(f)

    regs = map_to_regulations(inferred, custom_policy)
    return ScanReport(base, True, declared_ands, declared_cert, inferred, round(conf, 2), evidence, gaps, sorted(set(recs)), probes, regs, reasoning=reasoning)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="Base URL or hostname")
    ap.add_argument("--policy", help="Path to custom regulatory policy YAML")
    ap.add_argument("--timeout", type=int, default=config.get("network.timeout", 10))
    ap.add_argument("--retries", type=int, default=config.get("network.retries", 3))
    ap.add_argument("--jitter", type=float, default=0.0)
    ap.add_argument("--user-agent", default=config.get("network.user_agent", "ands-scan/1.1"))
    ap.add_argument("-H", "--header", action="append")
    ap.add_argument("--proxy", default=config.get("network.proxy"))
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--cacert")
    ap.add_argument("--openapi-url")
    ap.add_argument("--out", default="")
    ap.add_argument("--bundle")
    ap.add_argument("--sign-bundle", action="append")
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

    # Load and execute plugins
    plugins = load_plugins()
    for p in plugins:
        logger.info(f"Executing plugin: {p.name()}")
        p.execute_probe(base, session, evidence, gaps)

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
            migrator = SchemaMigrator()
            supported_versions = get_supported_versions()
            declared_ver = migrator.detect_version(data)

            if declared_ver not in supported_versions:
                gaps.append(f"Unsupported version: {declared_ver}")

            # Auto-normalize in memory for internal processing
            data = migrator.normalize(data)

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

            # Recursive Dependency Scanning (Recursive Dependency Risk)
            deps = data.get("dependencies", [])
            for dep in deps:
                logger.info(f"Recursive scan for dependency: {dep}")
                # Logic to recursively call scan and update Systemic Risk Score
                # evidence.append(Evidence("recursive_risk", f"Scanned sub-agent: {dep}", 1.0))
        except: gaps.append("Failed to parse ands.json")
    else:
        gaps.append("No ands.json found.")
        recs.append("Publish /.well-known/ands.json")

    default_openapi = config.get("scanner.openapi_paths", ["openapi.json", "openapi.yaml", "openapi.yml", "swagger.json"])
    oa_urls = [args.openapi_url] if args.openapi_url else [urljoin(base, p) for p in default_openapi]
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

    inferred, conf, reasoning = infer_ands(hints, evidence, gaps)
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

    custom_policy = None
    if getattr(args, 'policy', None) and Path(args.policy).exists():
        with open(args.policy, "r") as f:
            custom_policy = yaml.safe_load(f)

    regs = map_to_regulations(inferred, custom_policy)
    report = ScanReport(base, True, declared_ands, declared_cert, inferred, round(conf, 2), evidence, gaps, sorted(set(recs)), probes, regs, reasoning=reasoning)
    out_json = json.dumps(asdict(report), indent=2)
    if args.out: Path(args.out).write_text(out_json + "\n")
    else: print(out_json)
    if args.bundle: create_bundle(args.bundle, report, snapshot_files, args.sign_bundle)
    print_summary(report)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
