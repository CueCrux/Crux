# crux-lens-features — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

The Feature Registry lens — the first concrete lens on the `corecrux-memory` substrate
(entities + edges + kind_registry). It ports PlanCrux's Feature Registry onto the
substrate: registers two entity kinds (`capability`, `repo`) and provides the analytics
behind `/v1/features/*` HTTP routes and the MCP `feature_*` tools (wired in `corecruxd`).

## Key symbols
- `bootstrap_kinds` (`kinds.rs`) — registers `CAPABILITY_KIND` / `REPO_KIND` with the substrate's `KindRegistry`; corecruxd mounts it at startup.
- `compute_gaps` (`analytics.rs`) — gap analysis over capability entities → `GapsReport` / `Gap`.
- `compute_promise_coverage` — promised-vs-delivered analysis → `PromiseCoverage` / `PromiseEntry`.
- `compute_coverage_report` — the overall `CoverageReport`.

## Test & verify
- `cargo test -p crux-lens-features`

## Local rules
- **Two distinct "coverage" subsystems exist** (CODEMAP note): this crate computes
  feature-registry coverage/gaps (`compute_gaps` over capability entities), while
  `corecruxctl gaps` reports segment-indexed-vs-not coverage of the store. Don't conflate
  them, route one's output through the other, or reuse each other's terminology in APIs.
- Analytics functions take `&[Value]` capability payloads and stay pure — persistence and
  kind registration belong to the `corecrux-memory` substrate, not this crate. Store lens
  data as `(kind, id, payload)` entities + edges; don't grow a private store here.
- Capability/repo payload shape changes must stay compatible with both consumers
  (`corecruxd` HTTP `/v1/features/*` and the MCP `feature_*` tools) and the PlanCrux
  clients still hitting the proxy.
