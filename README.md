# ANDS — Athena Noesis Decimal System (Standard + Reference Tools)

ANDS is a conservative, auditable classification framework for AI systems across **five axes**:

**C**ognition • **A**uthority • **M**emory • **G**overnance • **R**isk

It is designed for procurement, compliance, insurance underwriting, and security review.

> ANDS is not a benchmark and not a safety guarantee.
> It is a structured disclosure + verification surface.

## Toolkit Installation

```bash
pip install .
ands config init  # Initialize default configuration
```

## Quick Start

### 0) Migrate an old declaration
```bash
ands migrate path/to/ands.json --to 1.1
```

### 1) Publish a declaration (vendors)
Host a JSON file at:
- `/.well-known/ands.json`

See: `spec/examples/ands-declaration-example.json`

### 2) Validate a declaration (offline)
```bash
python3 tools/validate_declaration.py spec/examples/ands-declaration-example.json
```

### 3) Scan a target (best-effort evidence report)
```bash
python3 tools/ands_scan.py https://example.com --out report.json
```

## What you get
The scanner outputs:
- declared ANDS (if present)
- inferred ANDS (best-effort)
- confidence score
- evidence list
- gaps + recommendations

## Standard Documents
- Overview: `docs/00-overview.md`
- Definition: `docs/01-ands-definition.md`
- Scoring rules: `docs/02-ands-scoring-rules.md`
- Certification levels: `docs/03-certification-levels.md`
- Enforcement guidance: `docs/04-enforcement-guidelines.md`
- Audit artifacts: `docs/05-audit-artifacts.md`
- Procurement clause templates: `docs/06-procurement-language.md`
- Threat model: `docs/07-threat-model.md`
- FAQ: `docs/08-faq.md`

## License
MIT (see `LICENSE`)

## Known Limitations
- External scanning cannot prove internal behavior. Vendors can lie or block scanners.
- OpenAPI and public endpoints may be absent or incomplete.
- Classification is not a security guarantee; combine ANDS with security review and operational controls.
- For high-risk deployments (R≥4), require VERIFIED or AUDITED certification and keep evidence on file.


## Signed declarations
See `docs/09-signed-declarations.md` for Ed25519 signing and verification.

## Verification mode (non-invasive)
The scanner supports an optional verification mode that performs a small number of read-only probes
(e.g., health/status endpoints and "dangerous-looking" endpoints) to see if they are protected.

```bash
python3 tools/ands_scan.py https://example.com --verify --out report.json
```

This does not prove internal behavior. It is an evidence-gathering enhancement.
