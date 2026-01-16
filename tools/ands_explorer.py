#!/usr/bin/env python3
"""ands_explorer.py — Portfolio Explorer (Standalone HTML Dashboard).

Usage:
  python3 tools/ands_explorer.py path/to/reports/ --out explorer.html
"""

import argparse
import json
import os
import sys
from typing import List, Dict, Any

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ANDS Intergalactic Explorer</title>
    <style>
        body { font-family: 'Inter', system-ui, sans-serif; background: #f9fafb; color: #111827; margin: 0; padding: 2rem; }
        .container { max-width: 1200px; margin: 0 auto; }
        header { margin-bottom: 2rem; }
        h1 { font-size: 2.25rem; font-weight: 800; color: #1e3a8a; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat-card { background: #fff; padding: 1.5rem; border-radius: 0.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .stat-val { font-size: 1.5rem; font-weight: bold; color: #1e3a8a; }
        .search { margin-bottom: 1rem; width: 100%; padding: 0.75rem; border: 1px solid #d1d5db; border-radius: 0.375rem; }
        table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 0.5rem; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        th { background: #f3f4f6; padding: 0.75rem; text-align: left; font-size: 0.875rem; text-transform: uppercase; color: #4b5563; }
        td { padding: 0.75rem; border-top: 1px solid #e5e7eb; }
        .badge { padding: 0.25rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
        .risk-5 { background: #fee2e2; color: #991b1b; }
        .risk-4 { background: #fef3c7; color: #92400e; }
        .risk-3 { background: #ecfdf5; color: #065f46; }
        .risk-1, .risk-2 { background: #f0fdf4; color: #166534; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>ANDS Intergalactic Explorer</h1>
            <p>Portfolio Risk Dashboard</p>
        </header>

        <div class="stats">
            <div class="stat-card"><div class="stat-name">Total Systems</div><div class="stat-val" id="total-count">0</div></div>
            <div class="stat-card"><div class="stat-name">Critical Risk (R5)</div><div class="stat-val" id="r5-count" style="color: #991b1b;">0</div></div>
            <div class="stat-card"><div class="stat-name">Avg Confidence</div><div class="stat-val" id="avg-conf">0%</div></div>
        </div>

        <input type="text" class="search" id="search" placeholder="Search targets or ANDS codes..." onkeyup="filterTable()">

        <table id="portfolio">
            <thead>
                <tr>
                    <th>Target</th>
                    <th>ANDS Code</th>
                    <th>Risk</th>
                    <th>Confidence</th>
                    <th>Cert</th>
                </tr>
            </thead>
            <tbody id="table-body">
                <!-- Data injected here -->
            </tbody>
        </table>
    </div>

    <script>
        const data = __DATA__;

        function render() {
            const body = document.getElementById('table-body');
            body.innerHTML = '';

            let r5 = 0;
            let sumConf = 0;

            data.forEach(r => {
                const tr = document.createElement('tr');
                const risk = r.inferred_ands.split('.').pop();
                if (risk === '5') r5++;
                sumConf += r.confidence;

                tr.innerHTML = `
                    <td>${r.target}</td>
                    <td><code>${r.inferred_ands}</code></td>
                    <td><span class="badge risk-${risk}">Risk ${risk}</span></td>
                    <td>${Math.round(r.confidence * 100)}%</td>
                    <td>${r.declared_certification_level || 'SELF'}</td>
                `;
                body.appendChild(tr);
            });

            document.getElementById('total-count').innerText = data.length;
            document.getElementById('r5-count').innerText = r5;
            document.getElementById('avg-conf').innerText = Math.round((sumConf / data.length) * 100) + '%';
        }

        function filterTable() {
            const q = document.getElementById('search').value.toLowerCase();
            const rows = document.querySelectorAll('#table-body tr');
            rows.forEach(row => {
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(q) ? '' : 'none';
            });
        }

        render();
    </script>
</body>
</html>
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("directory", help="Directory with ANDS JSON reports")
    ap.add_argument("--out", default="ands-explorer.html")
    args = ap.parse_args()

    reports = []
    for f in os.listdir(args.directory):
        if f.endswith(".json"):
            try:
                with open(os.path.join(args.directory, f), "r") as rfile:
                    d = json.load(rfile)
                    if "inferred_ands" in d:
                        reports.append(d)
            except: pass

    if not reports:
        print("No reports found.")
        sys.exit(1)

    html = HTML_TEMPLATE.replace("__DATA__", json.dumps(reports))
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Explorer dashboard created: {args.out}")

if __name__ == "__main__":
    main()
