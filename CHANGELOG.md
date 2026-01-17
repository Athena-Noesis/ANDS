# Changelog

## 1.5.0 (2026-01-20)
- [Added] Schema Versioning Logic with support for version-aware validation.
- [Added] `ands migrate` CLI command for upgrading declaration files.
- [Added] In-memory declaration normalization for backward compatibility in scanner.
- [Added] versioned schemas directory `ands/schemas/`.

## 1.1.0 (2026-01-17)
- [Added] Centralized configuration management via `ands.config.yaml`.
- [Added] `ands config init` and `ands config show` CLI commands.
- [Improved] Refactored `ands-scan` and `ands/utils.py` to respect global configuration.

## 1.0.0 (2026-01-13)
- Initial public release
- ANDS five-axis code definition
- `/.well-known/ands.json` declaration schema
- Chain-of-Work schema
- Reference scanner and validator tooling
