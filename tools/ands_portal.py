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
        ands = (data.get("last_scan") or {}).get("inferred_ands", "N/A")
        rows += f"<tr><td>{url}</td><td>{status}</td><td>{ands}</td></tr>"

    return f"""
    <html>
    <head><title>ANDS Dashboard</title></head>
    <body>
        <h1>ANDS Galactic Registry</h1>
        <table border='1'>
            <tr><th>Target</th><th>Status</th><th>ANDS</th></tr>
            {rows}
        </table>
    </body>
    </html>
    """

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=11000)
