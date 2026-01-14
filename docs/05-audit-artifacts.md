# Audit Artifacts

ANDS is designed to pair with structured artifacts for audit and incident reconstruction.

## Minimum recommended artifacts
- Intent acceptance/rejection records
- Tool/oracle invocation logs (inputs/outputs hashed)
- Safety verdicts (allow/block)
- Refusal artifacts (when the system halts)
- Chain-of-Work (event graph)

See `spec/chain-of-work.schema.json` and `spec/examples/chain-of-work-example.json`.
