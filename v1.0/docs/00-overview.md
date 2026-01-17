# ANDS Overview

ANDS is a five-axis decimal classification for AI systems:

- **C — Cognition**: how complex the system’s reasoning and generation capabilities are
- **A — Authority**: what the system is allowed to do (write, execute, mutate state, act)
- **M — Memory**: persistence scope and retention (none → long-lived, cross-user)
- **G — Governance**: observable controls, gates, audit artifacts, and human oversight
- **R — Risk**: aggregate deployment risk given the above + exposed surfaces

ANDS is intended to:
- make AI risk legible
- support procurement clauses
- enable insurer pricing models
- support audits and incident response

ANDS is not intended to:
- predict correctness
- certify truthfulness
- replace security review


## Known Limitations
- External tools can only infer from observable surfaces; they cannot prove internal behavior.
- Declarations can be false; certification levels exist to bound trust.
- ANDS is most effective when paired with enforcement policies and audit artifacts.
