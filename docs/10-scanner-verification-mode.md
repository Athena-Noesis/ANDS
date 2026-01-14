# Scanner Verification Mode (Non-Invasive)

ANDS includes a reference scanner: `tools/ands_scan.py`.

## Purpose
Verification mode adds minimal, read-only probing to improve confidence.

It helps answer questions like:
- Are "dangerous" endpoints (execute/tool/upload) protected by auth?
- Does the system expose health/status endpoints, and are they gated?

## What it does
When run with `--verify`, the scanner:
- probes a few common health/status endpoints (GET)
- probes a few "dangerous-looking" endpoints discovered via OpenAPI (or common defaults)
- records only HTTP status codes and basic notes

## What it does NOT do
- No POST/PUT/PATCH/DELETE
- No credential guessing
- No exploitation attempts

## Usage
```bash
python3 tools/ands_scan.py https://example.com --verify --out report.json
```

## Interpretation
- For dangerous endpoints: 401/403 is expected; 200 without auth is a red flag.
- For safe endpoints: 200 is fine; 401/403 indicates auth-gating (also fine).

Verification is an aid - not a guarantee.
