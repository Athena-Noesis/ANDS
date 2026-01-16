# ANDS Handbook: The Definitive Guide to AI Classification

Welcome to the **Athena Noesis Decimal System (ANDS)**. This handbook provides everything you need to know to classify, serve, and audit AI systems using the ANDS standard.

---

## 1. The Why: Why ANDS?

In a world of rapidly evolving AI, we need a standard way to communicate **capability** and **risk**. ANDS provides a 5-digit decimal code (e.g., `2.1.2.3.4`) that describes an AI across five critical axes:

- **C - Cognition**: Internal reasoning and task complexity.
- **A - Authority**: Decision-making autonomy and human-in-the-loop requirements.
- **M - Memory**: Persistence of data and state.
- **G - Governance**: Oversight, auditability, and control frameworks.
- **R - Risk**: Potential for negative impact and safety gating.

---

## 2. The Toolkit: How to use ANDS

The ANDS ecosystem provides a full lifecycle of tools:

### For Vendors (Initialization & Serving)
- **`ands_init.py`**: An interactive wizard to create your `ands.json` and sign it with Ed25519.
- **`ands_mock_server.py`**: A reference implementation showing how to serve your declaration.
- **Framework Integration**: See `docs/11-framework-integration.md` for FastAPI, Flask, and Express.js snippets.

### For Auditors (Scanning & Analysis)
- **`ands_scan.py`**: The "Gold Standard" scanner. Resilient, thorough, and produces verifiable audit bundles (`.andsz`).
- **`ands_verify_bundle.py`**: A forensic verifier for `.andsz` bundles to prove point-in-time compliance.
- **`ands_bulk_scan.py`**: Parallel scanner for processing entire portfolios of hundreds of AI systems.
- **`ands_explorer.py`**: Generates a standalone, interactive HTML dashboard for your entire AI portfolio.
- **`ands_summarize.py`**: A CLI tool to compare systems and detect "Capability Drift" over time.
- **`ands_badge.py`**: Generates SVG badges for social proof of your ANDS classification.

### For Infrastructure & Governance
- **`ands_guard.py`**: An active reverse-proxy that blocks traffic to AI systems that exceed your Risk (R) appetite.
- **`ands_registry.py`**: A "Galactic Oracle" server to maintain an index of all compliant AI in your network.
- **`ands_serve.py`**: A zero-code "Launchpad" that serves your JSON declaration and a live HTML scorecard at `/ands-report`.

### For Developers (Automation & AI)
- **`ands_ci.py`**: CI-optimized validator for GitHub Actions.
- **`ands_mcp.py`**: An MCP server that lets AI agents (like Claude) perform audits for you.
- **`ands_ping.py`**: Ultra-fast integrity monitor for SREs.

---

## 3. Deployment: Docker & mTLS

For sensitive government and enterprise use:
- **Docker**: The entire toolkit is containerized. `docker build -t ands-tools .`
- **Security**: The scanner supports mTLS (`--cert/--key`) and private CAs (`--cacert`) for restricted enclaves.

---

## 4. Certification Levels

- **SELF**: Vendor-declared scoring.
- **VERIFIED**: Cryptographically signed by the vendor.
- **AUDITED**: Third-party verified with an accompanying `.andsz` bundle.

---

## 5. Contact & Support

For more details, visit the project repository and check the `spec/` directory for technical schemas.
