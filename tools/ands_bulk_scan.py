#!/usr/bin/env python3
"""ands_bulk_scan.py — Parallel ANDS scanner for large portfolios.

Usage:
  python3 tools/ands_bulk_scan.py urls.txt --threads 10 --out-dir ./reports
"""

import argparse
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import List

def scan_target(target: str, out_dir: str, args_list: List[str]):
    # Sanitize filename
    safe_name = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_").strip("_")
    out_path = os.path.join(out_dir, f"{safe_name}.json")

    cmd = [sys.executable, "tools/ands_scan.py", target, "--out", out_path] + args_list

    print(f"[*] Scanning {target}...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"[+] COMPLETED: {target} -> {out_path}")
    else:
        print(f"[!] FAILED: {target} (Code {result.returncode})")
        if result.stderr:
            print(f"    Error: {result.stderr.strip().splitlines()[-1]}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url_file", help="File containing list of URLs to scan (one per line)")
    ap.add_argument("--out-dir", default="bulk_reports", help="Directory to save scan reports")
    ap.add_argument("--threads", type=int, default=5, help="Number of parallel scan threads")
    ap.add_argument("--verify", action="store_true", help="Enable verification probes")
    ap.add_argument("--timeout", type=int, help="Override default timeout")
    args, unknown = ap.parse_known_args()

    if not os.path.exists(args.url_file):
        print(f"Error: {args.url_file} not found.")
        sys.exit(1)

    with open(args.url_file, "r") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not urls:
        print("No URLs found to scan.")
        sys.exit(0)

    os.makedirs(args.out_dir, exist_ok=True)

    # Prepare extra arguments for ands_scan.py
    extra_args = []
    if args.verify:
        extra_args.append("--verify")
    if args.timeout:
        extra_args.extend(["--timeout", str(args.timeout)])
    extra_args.extend(unknown)

    print(f"--- ANDS BULK SCANNER ---")
    print(f"Targets: {len(urls)}")
    print(f"Threads: {args.threads}")
    print(f"Out Dir: {args.out_dir}")
    print(f"--------------------------\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for url in urls:
            executor.submit(scan_target, url, args.out_dir, extra_args)

    print(f"\nBulk scan finished. Results in {args.out_dir}/")
    print(f"Run 'python3 tools/ands_summarize.py {args.out_dir}' to see the dashboard.")

if __name__ == "__main__":
    main()
