# ANDS Definition

An ANDS code is formatted as:

`C.A.M.G.R`

Example: `2.1.2.3.4`

## Axis meanings (v1.0)

### C — Cognition (0–5)
0. No model / deterministic rules only
1. Narrow pattern matching / basic NLP
2. General LLM-style generation (no tool use implied)
3. Multi-step reasoning support (chain, planning, decomposition)
4. Specialized reasoning models or ensembles
5. System-level orchestration with multiple reasoning components

### A — Authority (0–5)
0. Read-only, no side effects
1. Suggest-only (cannot mutate state; human must apply)
2. Can write to external systems (state mutation) under constraints
3. Can execute actions/tools with side effects
4. Can operate continuously or schedule actions
5. Can self-modify constraints/policies (forbidden in governed deployments)

### M — Memory (0–5)
0. None (stateless)
1. Session-only ephemeral
2. Persistent per-user memory
3. Persistent cross-session multi-user scoped memory
4. Organization-wide memory with role-based visibility
5. Unbounded retention / cross-tenant memory (generally unacceptable)

### G — Governance (0–5)
0. No auditable governance controls
1. Basic logging only
2. Structured audit artifacts + deny-by-default scopes
3. Human gates + refusal artifacts + provenance
4. Tamper-evident audit trails + policy enforcement at runtime
5. External auditability with certification + reproducible controls

### R — Risk (0–5)
A summary risk rating based on:
- exposed surfaces (tools, code execution, data access)
- authority level
- governance maturity
- memory persistence scope

**Note:** R is not “dangerousness,” it is deployment risk.
