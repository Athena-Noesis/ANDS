#!/usr/bin/env python3
"""ands_mcp.py — MCP (Model Context Protocol) server for ANDS tools.

Exposes scan and validation capabilities to AI agents.
"""

import json
import sys
import subprocess
from typing import Any, Dict, List

def mcp_respond(result: Any):
    print(json.dumps(result))
    sys.stdout.flush()

def handle_scan(params: Dict[str, Any]) -> Dict[str, Any]:
    url = params.get("url")
    if not url:
        return {"error": "Missing url parameter"}

    cmd = [sys.executable, "tools/ands_scan.py", url]
    if params.get("verify"):
        cmd.append("--verify")

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        try:
            # ands_scan prints JSON to stdout
            # We need to filter out the ASCII summary which goes to stderr
            return {"report": json.loads(res.stdout)}
        except:
            return {"error": "Failed to parse scanner output", "raw": res.stdout}
    else:
        return {"error": f"Scanner failed with code {res.returncode}", "details": res.stderr}

def handle_validate(params: Dict[str, Any]) -> Dict[str, Any]:
    path = params.get("path")
    if not path:
        return {"error": "Missing path parameter"}

    cmd = [sys.executable, "tools/validate_declaration.py", path, "--verify-signature"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    return {"status": res.stdout.strip(), "error": res.stderr.strip(), "valid": res.returncode == 0}

def main():
    # Simple JSON-RPC-like interface for MCP
    for line in sys.stdin:
        try:
            req = json.loads(line)
            method = req.get("method")
            params = req.get("params", {})
            req_id = req.get("id")

            if method == "ands_scan":
                result = handle_scan(params)
            elif method == "ands_validate":
                result = handle_validate(params)
            elif method == "list_tools":
                result = {
                    "tools": [
                        {"name": "ands_scan", "description": "Scan an AI system URL for ANDS compliance", "parameters": {"url": "string", "verify": "boolean"}},
                        {"name": "ands_validate", "description": "Validate a local ands.json file", "parameters": {"path": "string"}}
                    ]
                }
            else:
                result = {"error": f"Unknown method: {method}"}

            mcp_respond({"jsonrpc": "2.0", "result": result, "id": req_id})
        except Exception as e:
            mcp_respond({"error": str(e)})

if __name__ == "__main__":
    main()
