# ANDS Schema Versioning

The Athena Noesis Decimal System (ANDS) toolkit supports multiple versions of the ANDS standard. This ensures backward compatibility while allowing the standard to evolve.

## Versioning Strategy

ANDS uses a hybrid Semantic Versioning (SemVer) strategy for both the standard and the JSON schemas.

- **Major (X.0)**: Structural changes, breaking validation rules, or redefinition of axes.
- **Minor (X.Y)**: Additive or non-breaking enhancements (e.g., adding optional fields like Environment).
- **Patch (X.Y.Z)**: Metadata fixes or documentation clarifications.

## Supported Versions

| Version | Status | Key Changes |
|---------|--------|-------------|
| **1.0** | Stable | Initial 5-axis model (C.A.M.G.R.) |
| **1.1** | **Current** | Added optional **Environment (E)** axis (C.A.M.G.R.E) |

## Schema Registry

The toolkit includes a centralized `SchemaRegistry` (in `ands/utils.py`) that resolves the correct schema based on the `ands_version` field in the declaration.

Schemas are stored in the `spec/` directory, organized by version:
- `spec/1.0/`
- `spec/1.1/`

## Migration: `ands migrate`

The `ands migrate` command allows you to upgrade declarations between versions.

### Example: Migrating 1.0 to 1.1
```bash
ands migrate declaration.json --to 1.1
```

**Note**: Migrating a declaration modifies the data, which **invalidates existing signatures**. You must re-sign the declaration after migration.

## Implementation Details

### Migration Engine
Migrations are implemented as modular transformation functions in `ands/migrations/`.

- `ands/migrations/m1_0_to_1_1.py`: Adds the `environment` field (defaulting to 3) and updates the version string.

### Validation
The validator automatically detects the version of a declaration and loads the corresponding schema for validation.

```python
from ands.validator import validate_schema

is_valid, message = validate_schema(my_declaration)
```
