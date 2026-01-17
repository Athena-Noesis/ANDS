# Regulatory Mapping Engine v2

The Regulatory Mapping Engine v2 (implemented as the `RosettaEngine`) provides granular, article-level compliance mapping between ANDS declarations and major global AI frameworks.

## Data-Driven Policies

Article mappings are defined in YAML files located in the `/policies/` directory. This allows for modular updates and region-specific overlays without changing the core codebase.

### Example: `policies/eu_ai_act.yaml`
```yaml
framework: "EU AI Act"
version: "1.1"
articles:
  "14":
    title: "Human Oversight"
    logic: "A <= 2 or G >= 3"
    evidence_required: ["attestation"]
    description: "AI systems shall be designed to be effectively overseen by natural persons."
```

## Compliance Evaluation Logic

Compliance is derived from ANDS axes using dynamic logic evaluation:

- **Compliant [✓]**: The ANDS axes satisfy the article's logic and all required evidence is present.
- **Conditional [⚠]**: The ANDS axes satisfy the logic, but required evidence (e.g., `attestation_urls` or `sbom_urls`) is missing from the declaration.
- **Non-Compliant [✗]**: The ANDS axes do not satisfy the article's logic.

## CLI Commands

### `ands rosetta translate`
Translates an ANDS code into high-level compliance statuses across frameworks.
```bash
ands rosetta translate 2.1.1.2.3.1
```

### `ands rosetta checklist`
Generates a detailed article-level compliance checklist for an `ands.json` file.
```bash
ands rosetta checklist examples/ands-declaration-example.json
```

## Integration with `ands-scan`

The `ands-scan` tool automatically includes a compliance summary in its report, leveraging the `RosettaEngine` to provide a consolidated view of potential regulatory standing.

```json
"compliance_summary": {
  "eu_ai_act": {
    "9": "Compliant",
    "10": "Conditional",
    "13": "Compliant",
    "14": "Compliant",
    "15": "Compliant",
    "16": "Compliant"
  }
}
```
