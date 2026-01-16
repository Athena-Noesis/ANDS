#!/usr/bin/env python3
"""ands_discover.py — Network discovery tool for AI systems.

Probes IP ranges to find active ANDS declarations.
"""

import argparse
import ipaddress
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple
from urllib.parse import urljoin

import requests

DEFAULT_PORTS = [80, 443, 8000, 8080, 5000]

def probe_target(target: str, timeout: int) -> Tuple[str, str]:
    """Check if a URL exposes a valid-looking ands.json."""
    url = urljoin(target, ".well-known/ands.json")
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "ands-discover/1.0"})
        if r.ok:
            data = r.json()
            if "declared_ands" in data or "system_id" in data:
                return target, data.get("declared_ands", "PRESENT")
    except:
        pass
    return target, None

def scan_worker(ip: str, ports: List[int], timeout: int):
    results = []
    for port in ports:
        scheme = "https" if port == 443 else "http"
        target = f"{scheme}://{ip}:{port}/"
        t, score = probe_target(target, timeout)
        if score:
            results.append((t, score))
    return results

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("network", help="CIDR range or IP address (e.g., 192.168.1.0/24)")
    ap.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)), help="Comma-separated list of ports")
    ap.add_argument("--threads", type=int, default=50, help="Parallel threads")
    ap.add_argument("--timeout", type=int, default=2, help="Timeout per probe")
    ap.add_argument("--out", help="Write findings to JSON file")
    args = ap.parse_args()

    try:
        net = ipaddress.ip_network(args.network, strict=False)
        ports = [int(p.strip()) for p in args.ports.split(",")]
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"--- ANDS NETWORK DISCOVERY ---")
    print(f"Network: {net}")
    print(f"Ports:   {ports}")
    print(f"Threads: {args.threads}")
    print(f"------------------------------\n")

    found = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_worker, str(ip), ports, args.timeout) for ip in net]
        for f in futures:
            res_list = f.result()
            for t, score in res_list:
                print(f"[+] FOUND: {t} (ANDS: {score})")
                found.append({"url": t, "ands": score})

    print(f"\nDiscovery finished. Found {len(found)} AI systems.")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(found, f, indent=2)
        print(f"Results saved to {args.out}")

if __name__ == "__main__":
    main()
