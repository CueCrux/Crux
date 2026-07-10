# corecruxd — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

The Crux Daemon binary: HTTP API on **14800** (axum), gRPC on **4007** (tonic), embedded
MCP server on **14801**. Composes the corecrux-* substrate crates plus crux-{mcp, session,
router, observe, integrations, lens-features} into one long-running process. ~84k LOC —
this file is an index, not an inventory.

## Where to start
- `src/main.rs` — startup wiring order (bootstrap → passports → lens kinds → HTTP →
  gRPC → MCP → optional workspace scan); `#![deny(clippy::unwrap_used/expect_used/panic)]`
- `src/config.rs` — env-var-driven config (`config.example.env`); port defaults live here
- `src/http/mod.rs` — router assembly; one file per route family under `src/http/`
- `src/http/route_auth.rs` — test-only route authorization contract
  (`RouteAuthClass`: Public/Read/Write/AdminRead/AdminWrite/…) for every HTTP route
- `src/grpc.rs` — gRPC service + seal-receipt builders (see Invariants)
- `src/auth.rs` + `src/passports.rs` — token/passport auth plumbing
- `src/http/repos.rs` + `src/workspace_scan.rs` / `workspace_scan_ast.rs` /
  `workspace_scan_polyglot.rs` — repo registry and the AST scan behind
  `GET /v1/repos/{repo_id}/codemap` (`get_repo_codemap`)
- `src/work.rs` + `src/work_execplans.rs` — /v1/work kanban + ExecPlan projection
  (`derive_state`)

## Key symbols
- `sign_segment_seal_material` / `build_segment_seal_receipt` (`src/grpc.rs`) — private
  fns signing `corecrux_storage::SegmentSealMaterialV1`; NOT in a library crate
- `run_scan` / `run_scan_at` (`src/workspace_scan.rs`) — workspace symbol scan
- `get_repo_codemap` (`src/http/repos.rs`) — serves the AST-derived code map

## Invariants
- Establishes I2 (segment chain): `build_segment_seal_receipt` gates on both
  previous-link fields; `sign_segment_seal_material` signs the seal material.

## Test & verify
- `cargo test -p corecruxd` — HTTP handler tests live in `src/http/tests.rs`
  (spins up `AppState`, exercises every route family)

## Local rules
- Ports 14800 / 4007 / 14801 are fixed defaults — do not change them.
- New on-disk artifact type (companion file, projection, lens kind) ⇒ three-place
  wiring: storage allowlist, projection registry, load-at-startup. Missing one causes
  quarantine-on-restart bugs (see root CLAUDE.md pre-deploy gate).
- The daemon must never panic on untrusted input — the crate-level clippy denies are
  load-bearing; `#[allow]` only with a `// SAFETY:` justification.
- New HTTP routes must be classified in `src/http/route_auth.rs`.
