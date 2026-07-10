# crux-observe-api — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Shared wire types for the agent audit-chain data contract — the durable backend the
agent-observability navigator's Audit-trail surface reconstructs from. M0 froze the
`agent_trace_node` schema here so it is versioned with the code that consumes it: the
capture hooks, the reconstruction endpoint, the verify/export surface, and the navigator
UI all read these types (single source of truth for the wire shape, R6). Fields map to
EU-AI-Act articles (Art. 10/12/13/15) — see the module docs.

## Key symbols
- `TraceNode` — the frozen node schema; carries `contract_version`, passport `actor`, optional `receipt_id`, `private` (defaults `true` — inputs/reasoning may be PII).
- `CONTRACT_VERSION` — bumped only when old rows cannot satisfy the schema; readers branch on the row's version rather than orphaning history.
- `NodeKind` / `RiskClass` / `StepStatus` — the enums; wire values are `snake_case` and canonical (UI display variants like `run`/`err` never appear on the wire).
- `OutputKind::is_mutation` — `Write`/`Edit`/`Fact` mutate and MUST resolve to a CROWN receipt; `Bash` is deliberately not a mutation by kind.
- `ReasoningRef` — `fact:` or `blob:` scheme-prefixed pointer, **never raw chain-of-thought** (R1); any other scheme is rejected at deserialise time.
- `TraceNode::receipt_chain_ok` — the M6 gate: a mutating step carries a step `receipt_id` and every mutating output a `mutation_receipt_id`.

## Test & verify
- `cargo test -p crux-observe-api`
- `mod tests` in `lib.rs` pins wire compatibility: a mutation step missing its receipt
  fails `receipt_chain_ok`; `reasoning_ref_rejects_unknown_scheme` pins scheme rejection.

## Local rules
- This is a **compat-stability crate**: rows already written must keep deserialising.
  Evolve additively (`Option` + `#[serde(default)]`); a breaking shape change requires a
  `CONTRACT_VERSION` bump and read-side branching, never a silent field change.
- Stay dependency-light on purpose (serde only — no chrono, no ulid): timestamps are
  RFC-3339 strings, ids are opaque strings, so the crate compiles everywhere incl. WASM.
- Never widen `ReasoningRef` to carry inline reasoning text — the pointer-only design is
  what lets the contract assert it never holds live CoT.
