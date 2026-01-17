import argparse
import os
import json
import uuid
import zipfile
import hashlib
import base64
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
import jcs

from .models import ScanReport, SigningRequest, SignatureBlock, ComplianceReport
from .utils import logger
from .validator import verify_declaration_signature

app = FastAPI(title="ANDS Notarization UI")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# In-memory session store for bundles
BUNDLES: Dict[str, Dict[str, Any]] = {}

def get_bundle_hash(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    bundles_list = []
    for bid, b in BUNDLES.items():
        bundles_list.append({
            "id": bid,
            "target": b["report"].target,
            "timestamp": b["timestamp"],
            "signatures_count": len(b["signatures"])
        })

    return templates.TemplateResponse("index.html", {
        "request": request,
        "bundles": bundles_list,
        "bundles_count": len(BUNDLES),
        "last_timestamp": datetime.now().strftime("%H:%M:%S")
    })

@app.post("/upload")
async def upload_bundle(request: Request, file: UploadFile = File(...)):
    if not file.filename.endswith(".andsz"):
        raise HTTPException(status_code=400, detail="Only .andsz files are supported")

    content = await file.read()
    bid = str(uuid.uuid4())[:8]

    # Extract bundle
    import io
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        report_data = json.loads(zf.read("report.json").decode('utf-8'))
        signatures = []
        if "signatures.json" in zf.namelist():
            signatures = json.loads(zf.read("signatures.json").decode('utf-8'))

        # Manifest
        manifest = json.loads(zf.read("manifest.json").decode('utf-8'))

    # Minimal validation of ScanReport fields
    # We might need to handle different versions here in the future
    report = ScanReport(**{k: v for k, v in report_data.items() if k in ScanReport.__dataclass_fields__})

    # Re-structure compliance if present
    if report_data.get("compliance"):
        c = report_data["compliance"]
        report.compliance = ComplianceReport(**{k: v for k, v in c.items() if k in ComplianceReport.__dataclass_fields__})
        # Articles need to be dataclasses too
        articles = []
        for a in c.get("articles", []):
            from .models import ComplianceArticle
            articles.append(ComplianceArticle(**a))
        report.compliance.articles = articles

    BUNDLES[bid] = {
        "id": bid,
        "report": report,
        "signatures": signatures,
        "raw_content": content,
        "manifest": manifest,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/bundle/{bid}", status_code=303)

@app.get("/bundle/{bid}", response_class=HTMLResponse)
async def bundle_detail(bid: str, request: Request):
    if bid not in BUNDLES:
        raise HTTPException(status_code=404, detail="Bundle not found")

    return templates.TemplateResponse("bundle.html", {
        "request": request,
        "b": BUNDLES[bid]
    })

@app.post("/bundle/{bid}/request")
async def generate_signing_request(bid: str, role: str = Form(...)):
    if bid not in BUNDLES:
        raise HTTPException(status_code=404, detail="Bundle not found")

    b = BUNDLES[bid]
    # We sign the manifest hash or the whole manifest
    # For now, let's follow the standard: sign the canonical manifest.json
    manifest_bytes = jcs.canonicalize(b["manifest"])
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()

    req = {
        "bundle_id": bid,
        "bundle_hash": manifest_hash,
        "role": role,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "ANDS_SIGNING_REQUEST_V1"
    }

    filename = f"signing_request_{bid}_{role}.ands_signreq.json"
    return JSONResponse(
        content=req,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.post("/bundle/{bid}/sign")
async def add_signature(bid: str, file: UploadFile = File(...)):
    if bid not in BUNDLES:
        raise HTTPException(status_code=404, detail="Bundle not found")

    content = await file.read()
    signed_data = json.loads(content.decode('utf-8'))

    # Validate the signature
    req = signed_data.get("request")
    sig_block = signed_data.get("signature")

    if not req or not sig_block:
        raise HTTPException(status_code=400, detail="Invalid signed request format")

    if req.get("bundle_id") != bid:
        raise HTTPException(status_code=400, detail="Signature does not match this bundle ID")

    # Verify the signature
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = base64.b64decode(sig_block["pubkey"])
        sig = base64.b64decode(sig_block["signature"])
        msg = jcs.canonicalize(req)

        pk = Ed25519PublicKey.from_public_bytes(pub)
        pk.verify(sig, msg)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Signature verification failed: {e}")

    # If valid, add to bundle signatures
    BUNDLES[bid]["signatures"].append(sig_block)

    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/bundle/{bid}", status_code=303)

@app.get("/bundle/{bid}/download")
async def download_bundle(bid: str):
    if bid not in BUNDLES:
        raise HTTPException(status_code=404, detail="Bundle not found")

    b = BUNDLES[bid]

    # Repackage the bundle with new signatures
    import io
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        # Copy existing files from original content
        with zipfile.ZipFile(io.BytesIO(b["raw_content"])) as old_zf:
            for item in old_zf.infolist():
                if item.filename not in ["signatures.json"]:
                    zf.writestr(item, old_zf.read(item.filename))

        # Add updated signatures
        zf.writestr("signatures.json", json.dumps(b["signatures"], indent=2).encode("utf-8"))

    output.seek(0)
    filename = f"notarized_{bid}.andsz"
    return HTMLResponse(
        content=output.getvalue(),
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "application/octet-stream"
        }
    )

def main():
    parser = argparse.ArgumentParser(prog="ands ui", description="Start the ANDS Notarization UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")

    args = parser.parse_args()

    print(f"Starting ANDS Notarization Portal at http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port)

if __name__ == "__main__":
    main()
