# Versioning

ANDS uses semantic versioning for the standard and schemas.

- **MAJOR**: breaking changes to meanings or required fields
- **MINOR**: backward-compatible additions (new optional fields, new reason codes with defaults)
- **PATCH**: clarifications, typos, examples, tooling bugfixes

The `.well-known` declaration includes `ands_version` so consumers can validate compatibility.
