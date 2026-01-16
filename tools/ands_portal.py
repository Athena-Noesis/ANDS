from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import json
import os
from ands.registry import RegistryStore
from ands.render import render_markdown, TRANSLATIONS

app = FastAPI(title="ANDS Galactic Command Center")
store = RegistryStore("ands_registry.json")

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    systems = store.data.get("systems", {})
    rows = ""
    for url, data in systems.items():
        status = data.get("status", "UNKNOWN")
        last_scan = data.get("last_scan") or {}
        ands = last_scan.get("inferred_ands", "N/A")

        # Temporal Trajectory
        history = data.get("history", [])
        trajectory = "Stable"
        if len(history) >= 2:
            prev = history[-2].get("ands")
            curr = history[-1].get("ands")
            if prev != curr: trajectory = f"Changed ({prev} ➔ {curr})"

        rows += f"<tr><td>{url}</td><td>{status}</td><td><code>{ands}</code></td><td>{trajectory}</td></tr>"

    return f"""
    <html>
    <head>
        <title>ANDS Galactic Command Center</title>
        <style>
            body {{ font-family: sans-serif; padding: 2rem; background: #f4f4f9; }}
            table {{ width: 100%; border-collapse: collapse; background: white; }}
            th, td {{ padding: 1rem; text-align: left; border-bottom: 1px solid #eee; }}
            th {{ background: #1e3a8a; color: white; }}
            tr:hover {{ background: #f9fafb; }}
        </style>
    </head>
    <body>
        <h1>ANDS Galactic Registry</h1>
        <p>Continuous AI Risk Monitoring</p>
        <table>
            <tr><th>Target URL</th><th>Status</th><th>Last ANDS</th><th>Temporal Trajectory</th></tr>
            {rows}
        </table>
    </body>
    </html>
    """

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=11000)
