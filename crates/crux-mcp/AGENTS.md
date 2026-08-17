# crux-mcp — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Agent-facing MCP server: JSON-RPC 2.0 transport, tool dispatch, and an axum server
speaking MCP Streamable HTTP. Hosted inside `corecruxd` (port 14801). ~42 tool modules,
~33k LOC — index only. Agents authenticate through registered bearer tokens or
hosted-client OAuth introspection; `agent::mcp_authentication_configured` is the shared
fail-closed predicate used before dispatch, in discovery, and for bind validation.

## Where to start
- `src/tools/mod.rs` — `ToolDefinition` + `list_tools` / `list_tools_local_surface`:
  the tool catalogue and registration point; one module per tool family under `src/tools/`
- `src/dispatch.rs` — `dispatch`: JSON-RPC request → tool routing
- `src/crc_v1.rs` — CRC-v1 pointer-first output contract; `enabled()` returns true
  unless the caller opts out with `contract:"legacy"` (default ON)
- `src/budget.rs` — token-budget maths (`pointers_within_budget`,
  `fact_emit_within_budget`); enforcement sits in the tools (e.g. `src/tools/query.rs`)
- `src/server.rs` / `src/sse.rs` / `src/protocol.rs` — axum transport plumbing
- `src/agent.rs` / `src/agent_passport.rs` / `src/scope.rs` — auth, passports, scoping
- `src/ledger.rs` — durable agent action ledger: `tools/call` events appended to the
  observations stream, each getting a CROWN receipt (default OFF behind a feature flag)
- `src/t1_regression.rs` — the cross-tenant-leak merge bar (agent-passport T.1 suite)

## Key symbols
- `dispatch` (`src/dispatch.rs`) — the single tool-call entry point
- `list_tools` (`src/tools/mod.rs`) — full advertised catalogue
- `crc_v1::enabled` — output-contract negotiation (absent ⇒ CRC-v1)
- `tools::facts` — `store_fact` path; supersession via `mark_superseded`

## Invariants
- Checks I3: `src/tools/receipt_verify.rs` — `verified = signature_valid &&
  hash_matches && error_code == "OK"` (boolean-AND, fail-closed).
- Observes I4: recall filters `superseded_by.is_none()` by default
  (`src/tools/facts.rs`); `include_superseded=true` exposes the chain.
- Generic fact, memory-edit, consolidation, and forget tools cannot create,
  overwrite, or delete daemon-owned control namespaces; those records are
  reachable only through their typed daemon workflows.

## Test & verify
- `cargo test -p crux-mcp` (includes the `t1_regression` tenant-isolation suite)

## Local rules
- Every retrieval tool takes `token_budget` and must enforce it (see
  `tools::query`); a new retrieval tool without budget enforcement is a regression.
- CRC-v1 is the default output contract; the `legacy` escape exists for old consumers —
  never make legacy the default, and route new tool output through the CRC envelope.
- New tools register in `src/tools/mod.rs` AND get a tier entry in
  `vaultcrux-local::tool_surface::TOOL_SURFACE` (unknown names default to Local).
- Changes touching tenant scoping must keep `t1_regression` green — it is the merge bar.
- Namespace checks must use `corecrux_memory::fact_privacy`; do not grow a
  second MCP-only control-prefix list.
