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
- `src/attention.rs` — counts-only attention roll-up behind
  `GET /v1/attention/summary`; port of the console's `deriveAttentionZone`
- `src/relay_device.rs` + `src/relay_client.rs` — relay device identity (derived
  from the passport seed) and the outbound handshake (contract v1 §§3,4,6,11)

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
- **The relay handshake context lives in ONE function** (`relay_client::relay_context`).
  The daemon signs over it and the relay rebuilds it independently; it is not a wire
  field, so a second copy that drifts shows up only as an unexplained proof failure
  in production. Its `data_egress_classes` is `["text"]` — do **not** copy sync's `&[]`.
- **Never log a relay token or possession proof** (contract §11). `AttachFrame`'s
  hand-written `Debug` redacts both; keep it that way if fields are added.
- `AttentionSummary` is counts-only on purpose — it exists so the hosted view can
  show attention without the plan names and local paths that disqualify
  `/v1/work` and `/v1/coord/active` from the frozen subset. Adding an item field
  reintroduces exactly the leak it was written to avoid.
