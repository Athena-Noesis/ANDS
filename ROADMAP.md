# ANDS Strategic Roadmap

This document outlines the planned improvements and strategic vision for the Athena Noesis Decimal System (ANDS).

## 1. Core Framework Improvements
- **Standardized Packaging**: Add `pyproject.toml` and `setup.py` to allow `pip install -e .` for portability.
- **Unified CLI Entry Point**: Consolidate tools under a single `ands` command (e.g., `ands scan`, `ands init`).
- **Standardized Schema Registry**: Implement a robust, centralized schema registry with formal URN/URL systems for schema resolution.
- **Structured Logging**: Move from print statements to a structured logging framework (e.g., `logging` or `structlog`).
- **Schema Versioning Logic**: Implement explicit version-handling logic for backward compatibility (e.g., ANDS 1.0 to 2.0).
- **The "Sustainability" Axis**: Add a 6th axis for Environment (E) or Resource Intensity to the standard.

## 2. Tool & Capability Enhancements
- **Automated Dependency Auditing**: Deeply integrate recursive scanning of SBOMs for upstream ANDS declarations.
- **Enhanced Verification Probes**: Add AI-specific fingerprinting (vLLM, Ollama) and provider-specific health checks.
- **Input Robustness in Wizard**: Add CLI flags and YAML/JSON config support to `ands_init.py` for automated pipelines.
- **Continuous Monitoring (The Oracle)**: Support complex triggers and drift alerting (inferred vs. declared risk).
- **Signature Rotation and Lifecycle**: Implement key rotation and revocation support for long-lived deployments.
- **mTLS and Private PKI**: Streamline integration for enterprise private networks.

## 3. Integration & Interface
- **Advanced MCP (Model Context Protocol)**: Enable AI agents to perform high-assurance programmatic audits.
- **Evidence Persistence**: Enhance snapshotting and archiving of harvested evidence in `.andsz` bundles.
- **GUI / Web Interface**: Build an interactive, user-friendly interface for the Registry and Wizard in `ands_portal.py`.
- **Live Badge API**: A dynamic API linked to the Oracle registry for real-time compliance status display.
- **Local "Dry Run" Scanner**: A tool for developers to execute within their own network before they publish, suggesting the most accurate ANDS Cognition and Authority scores.
- **ANDS-to-SBOM Mapping**: Deeply integrate with SBOM standards (like CycloneDX). An ANDS declaration could be treated as a "Compliance SBOM" that sits alongside the "Software SBOM."

## 4. Community & Strategic Vision
- **Community-Driven Probe Library**: Open-source repository for non-invasive AI vulnerability probes.
- **Transparency Logs**: Integration with immutable logs for high-assurance (Risk 4+) system profiles.
- **Regulatory Translation Engine**: Deepen the mapping of ANDS codes to specific Article requirements in the EU AI Act and NIST AI RMF.

---
**Maintained by:** Athena Noesis Compliance & Standards Team
**Last Updated:** 2026-01-16
