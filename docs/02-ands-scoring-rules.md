# ANDS Scoring Rules (v1.0)

ANDS supports two forms of scoring:
1) **Declared**: vendor self-declaration via `/.well-known/ands.json`
2) **Observed**: evidence-based inference from public surfaces (OpenAPI, docs, behavior tests)

## Conservative defaults
If unknown, assign conservative values:
- A defaults to 1 (suggest-only) unless evidence shows state mutation or execution
- G defaults to 1 unless explicit audit artifacts exist
- R defaults to at least 3 if any external integrations exist

## Confidence
Observed classifications must include a confidence score in [0, 1] and an evidence list.

## Discrepancy policy
If declared differs from observed:
- record the discrepancy
- recommend VERIFIED or AUDITED certification before high-risk deployment
