# ANDS Master Roadmap

This document serves as the definitive development roadmap for the **Athena Noesis Decimal System (ANDS)**, structured across logical development tiers.

---

## 🧱 I. Foundation Tier — Core Professionalization (v1.0 → v1.5)
**Goal:** Make ANDS a robust, installable, production-ready Python toolkit.

- [x] **Formal Packaging**: Implemented `pyproject.toml` for `pip install .` support.
- [x] **Unified CLI**: Integrated all tools under a single `ands` command.
- [x] **Structured Logging**: Moved to standard `logging` framework with `setup_logging`.
- [x] **Expanded Unit Tests**: Core logic and schema validation covered by `pytest`.
- [x] **Configuration Management**: Central `ands.config.yaml` for global settings.
- [ ] **Schema Versioning Logic**: Formal migration paths between standard versions (Planned).

---

## 🏛️ II. Enterprise Tier — Governance, Risk & Auditing (v2.0 → v2.5)
**Goal:** Make ANDS enterprise-grade for insurers, governments, and regulated vendors.

- [x] **Cascading Risk Analysis**: Detected via recursive dependency scanning.
- [x] **Capability Drift Alerting**: Real-time Slack/Webhook notifications from The Oracle.
- [x] **Local LLM Probes**: Native support for Ollama/vLLM via plugin system.
- [x] **Standardized Schema Registry**: Reliable local and remote axis resolution.
- [ ] **Regulatory Mapping Engine v2**: Granular per-Article checklist mode (Planned).
- [ ] **Multi-Signature Notarization UI**: Web-based interface for collaborative signing (Planned).
- [ ] **CI/CD Dashboard**: Enhanced PR summaries for risk deltas (Planned).

---

## ⚙️ III. Strategic Tier — Advanced Risk Intelligence (v3.0 → v3.5)
**Goal:** Turn ANDS into an autonomous compliance and risk forecasting framework.

- [x] **Scanner Plugin Architecture**: Dynamic probe loading from `ands/plugins/`.
- [x] **"What-If" Regulatory Simulator**: Comparison against draft/custom legislation.
- [x] **Auditor Override Logic**: Support for human-in-the-loop axis adjustments.
- [x] **Reasoning Trace**: Logic explainability for inferred scores (Chain-of-Thought).
- [x] **Auditor Workflow Tool**: Forensic review and re-signing of audit bundles.
- [x] **Kubernetes Sidecar**: Pre-configured `ands_guard` for service meshes.
- [ ] **Federated Registries**: Multi-region Oracle syncing for sovereign networks (Planned).

---

## 🌐 IV. Frontier Tier — Hardware, Ecosystem, and Agentic Intelligence (v4.0 → v4.5)
**Goal:** Expand ANDS into the physical and economic layers of AI trust.

- [x] **Self-Correcting Guardians**: Adaptive risk negotiation at runtime.
- [x] **Emergent Swarm Risk Model**: Composite scoring for multi-agent organizations.
- [x] **Recursive Dependency Scoring**: Systemic risk computation across sub-agents.
- [ ] **Proof-of-Compute Integration**: Hardware-level Remote Attestation (Planned).
- [ ] **ANDS for Data ("D" Axis)**: Scoring for Training and RAG Datasets (Planned).
- [ ] **Economic Risk Engine**: Expected Loss (EL) modeling for insurance (Planned).
- [ ] **Red-Team Scanner**: Automated stress-testing for capability drift (Planned).

---

## 🧠 V. Experimental Tier — Behavioral Intelligence & Universal Harmonization (v5.0+)
**Goal:** Make ANDS the “Rosetta Stone” of AI safety and compliance.

- [x] **Semantic Alignment Probes**: Behavioral pressure testing for deception detection.
- [x] **Regulatory Rosetta Stone**: Universal translation to ISO, NIST, and EU standards.
- [x] **Sustainability Axis (S)**: Sixth dimension for environmental impact.
- [x] **Live Badge API**: Dynamic status indicators linked to Oracle registry.
- [x] **Auto-Scorer & Dry-Run**: Developer assistance for accurate scoring.
- [x] **ANDS-to-SBOM Integration**: CycloneDX-compliant metadata generation.
- [ ] **Transparency Ledger**: Immutable public log for declaration updates (Planned).

---
**Maintained by:** Athena Noesis Compliance & Standards Team
**Last Updated:** 2026-01-16
