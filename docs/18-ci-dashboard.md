# ANDS CI/CD Dashboard

The ANDS toolkit includes a CI-optimized validator and reporting tool designed to provide rich feedback in automated pipelines (e.g., GitHub Actions).

## Features

- **Rich PR Summaries**: Generates a detailed Markdown dashboard for GitHub Step Summaries.
- **Risk Delta Analysis**: Compares the current `ands.json` against a baseline version to detect changes in risk scores across all axes (C.A.M.G.R.E).
- **Multi-Signature Verification**: Validates signatures against organization-defined trust policies (all, any, quorum).
- **Regulatory Overview**: Provides a per-article compliance checklist (EU AI Act, NIST AI RMF).
- **HTML Artifacts**: Generates a standalone, visual HTML report for detailed inspection.
- **Live Drift Detection (Optional)**: Can invoke `ands scan` to verify that the declared `ands.json` matches the actual system behavior.

## Usage in GitHub Actions

You can integrate the ANDS CI Dashboard into your workflows using the provided composite action.

### Example Workflow
```yaml
name: ANDS Compliance
on: [pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Required for delta comparison

      - name: Get Baseline
        run: git show origin/main:.well-known/ands.json > baseline.ands.json

      - name: ANDS Validation
        uses: ./.github/actions/ands-check # Path to your action
        with:
          path: '.well-known/ands.json'
          baseline-path: 'baseline.ands.json'
          live-scan: 'true'
```

## CLI Usage: `ands_ci.py`

You can also run the CI tool manually:

```bash
python3 tools/ands_ci.py path/to/ands.json \
    --baseline baseline.ands.json \
    --live \
    --html dashboard.html
```

## Report Contents

### Markdown Summary
The Markdown summary includes:
- **Signatures**: Status of all signers and trust policy verification.
- **Risk Profile**: Visual representation of scores with delta indicators (🔺/🔻).
- **Regulatory Checklist**: Articles 9-16 of the EU AI Act status.
- **Live Verify**: Results of any drift detection scans.

### HTML Dashboard
The generated HTML report provides a more detailed, color-coded view of the compliance status, suitable for archiving as a build artifact.
