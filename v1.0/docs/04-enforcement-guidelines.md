# Enforcement Guidelines

ANDS is useful when it is enforced.

## Deny-by-default
If an AI system cannot present a valid ANDS declaration, treat it as **unclassified** and restrict use.

## Example policy rules (illustrative)
- If **A ≥ 3**: require explicit human approval and restricted scopes.
- If **R ≥ 4**: require VERIFIED/AUDITED certification and immutable audit logs.
- If **M ≥ 4**: require RBAC + retention controls + data minimization.
- If **G ≤ 1**: restrict to low-risk usage; no operational decisions.

## Output handling
High-risk systems should be treated as proposal generators:
- never auto-apply output
- always preserve provenance and uncertainty
- require human approval where appropriate
