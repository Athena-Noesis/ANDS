# Procurement Language (Templates)

These clauses are intentionally conservative.

## Clause A — Mandatory ANDS Declaration
Vendor must publish and maintain a valid ANDS declaration at `/.well-known/ands.json`, including:
- system_id
- ands_version
- declared_ands
- certification_level
- scope and capability disclosures

## Clause B — Certification Requirement for High Risk
For any system deployed with **R ≥ 4**, Vendor must provide **VERIFIED** or **AUDITED** certification.

## Clause C — Change Notification
Vendor must notify Customer of any changes to:
- declared_ands
- capabilities (tool use, memory persistence, execution)
- certification status

## Clause D — Audit Right
Customer may request evidence supporting the ANDS declaration and may independently scan/validate.
