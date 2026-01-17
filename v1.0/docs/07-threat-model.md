# Threat Model

ANDS reduces risk by increasing visibility; it does not eliminate risk.

## Threats
- Vendors can lie about declarations
- Scanners can be blocked or deceived
- OpenAPI may be absent or incomplete
- Behavior can differ from documented surfaces

## Mitigations
- Require VERIFIED/AUDITED certification for high-risk use
- Prefer signed declarations
- Maintain independent scanning + sampling tests
- Log evidence and discrepancies

## Known limitations
- External scanning cannot prove internal behavior
- Classification must be combined with security review and operational controls
