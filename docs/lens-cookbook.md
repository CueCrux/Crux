# Lens Cookbook — Adding a Domain to the Crux Substrate

> Status: living document. Worked example uses the Features lens shipped in May 2026.

## What is a lens?

The Crux daemon's `corecrux-memory` crate ships a **substrate** — generic `entities` + `edges` + `kind_registry` with HTTP routes under `/v1/entities/*`, `/v1/edges/*`, `/v1/kinds/*` and matching MCP tools (`entity_*`, `edge_*`, `kind_*`, `entity_history`).

A **lens** is a Rust crate that:

1. **Registers one or more entity kinds** with the substrate's `KindRegistry` (JSON-Schema + allowed edges + description).
2. **Owns specialised HTTP routes** for queries that are awkward on the generic substrate — typically aggregations (gap analysis, coverage reports, dependency trees).
3. **Ships MCP tools** for agent ergonomics — domain-namespaced (`feature_*`, `task_*`, `goal_*`) instead of the generic `entity_*`.
4. **Optionally provides migration tools** to import legacy data (PlanCrux Postgres → Crux substrate, for example).

Trivial registries (Repo, Person, Promise) don't need a lens — they live as plain substrate entities and the generic `entity_*` routes are enough. Analytics-heavy domains earn a lens.

## Worked example: Features lens

Three files in `crates/crux-lens-features/`:

```text
src/
  lib.rs        — Re-exports + module wiring
  kinds.rs      — capability + repo KindRegistrations (JSON-Schema, edges, description)
  analytics.rs  — Pure functions over Vec<serde_json::Value>: compute_gaps,
                  compute_promise_coverage, compute_coverage_report
```

Cargo.toml is minimal — only `serde`, `serde_json`, `chrono`, and `corecrux-memory`.

## Step-by-step: adding a new lens

### 1. Create the workspace member

```bash
mkdir -p crates/crux-lens-<NAME>/src
```

`Cargo.toml`:
```toml
[package]
name = "crux-lens-<NAME>"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde = { version = "1.0.218", features = ["derive"] }
serde_json = "1.0.139"
corecrux-memory = { path = "../corecrux-memory" }

[lints]
workspace = true
```

Add the crate to the root `Cargo.toml` workspace members.

### 2. Define kinds (`src/kinds.rs`)

```rust
use corecrux_memory::{KindError, KindRegistration, KindRegistry};
use serde_json::json;

pub const MY_KIND: &str = "task";
pub const PARENT_EDGE: &str = "parent_of";

pub fn bootstrap_kinds(reg: &mut KindRegistry) -> Result<(), KindError> {
    if !reg.is_registered(MY_KIND) {
        reg.register(KindRegistration {
            kind: MY_KIND.into(),
            description: "PlanCrux Task (Crux lens).".into(),
            allowed_outgoing_edges: vec![PARENT_EDGE.into()],
            allowed_incoming_edges: vec![PARENT_EDGE.into()],
            json_schema: json!({
                "type": "object",
                "required": ["id", "title", "state"],
                "properties": {
                    "id":    {"type": "string"},
                    "title": {"type": "string"},
                    "state": {"type": "string", "enum": ["open","in_progress","blocked","done"]}
                }
            }),
        })?;
    }
    Ok(())
}
```

Rules of thumb for the schema:

- Keep `required` minimal — every required field is a write that can fail at the substrate boundary.
- Use `enum` for closed sets (states, severities, maturities). The substrate's shallow validator enforces them at write time.
- Optional fields can be any type; the substrate's validator tolerates `null` for typed optionals (M4 ergonomics fix).
- Edges are declared symmetrically: if `task` can have `parent_of` going out, you also declare it as `allowed_incoming_edges` (because the same edge kind is what another task receives).

### 3. Write the analytics (`src/analytics.rs`)

Pure functions over `&[serde_json::Value]`. Don't take an `EntityStore` parameter — the caller (HTTP or MCP layer) reads from the store and hands you the payloads. This keeps analytics unit-testable without spinning up a daemon.

```rust
pub fn compute_unblocked_count(tasks: &[Value]) -> usize {
    tasks.iter().filter(|t| t["state"] == "open" && unblocked(t)).count()
}
```

### 4. Wire kind bootstrap in `corecruxd/src/main.rs`

After `AppState` is constructed:

```rust
{
    let mut reg = state.kind_registry.write().await;
    if let Err(e) = crux_lens_<NAME>::bootstrap_kinds(&mut reg) {
        tracing::warn!(error=%e, "<NAME> lens bootstrap_kinds returned an error");
    }
}
```

Multiple lenses can bootstrap. Each calls `bootstrap_kinds` which short-circuits on already-registered kinds, so the order is irrelevant.

### 5. Add HTTP routes in `corecruxd/src/http/<NAME>.rs`

Pattern: read capabilities/tasks/whatever from `state.entity_store`, call into the pure analytics, return JSON.

```rust
pub(super) async fn analysis_unblocked(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let store = state.entity_store.read().await;
    let tasks: Vec<_> = store
        .list(&EntityQuery { kind: Some("task".into()), ..Default::default() })
        .into_iter()
        .map(|e| e.payload.clone())
        .collect();
    let count = crux_lens_<NAME>::compute_unblocked_count(&tasks);
    (StatusCode::OK, Json(json!({"unblocked": count}))).into_response()
}
```

Add `mod <NAME>;` and routes in `corecruxd/src/http/mod.rs`. Conventional path prefix: `/v1/<lens-name>/<resource>`.

### 6. Add MCP tools in `crux-mcp/src/tools/<NAME>.rs`

Same shape as the HTTP handler, but reads `ctx.entity_store` and returns the MCP `content` array. Add `pub mod <NAME>;` in `tools/mod.rs`, plus:

- One `ToolDefinition` per tool in `list_tools()` (don't forget `examples` in the input_schema — `all_schemas_have_examples` test enforces this).
- One dispatch arm per tool in `call_tool()`.
- One output-doc entry per tool in `tool_output_docs()` (`tool_output_docs_covers_all_tools` test enforces this).
- Bump `TOOL_COUNT` in `mod.rs` tests.

If `tool_output_docs()`'s `json!` macro hits the recursion limit, the file already has `#![recursion_limit = "256"]` from the M3 fix; bump higher if needed.

### 7. Migration / cutover

If the data lives outside Crux (a legacy Postgres, a YAML file, an external API), write a one-shot migration script. Pattern:

- Read source.
- For each record, `PUT /v1/entities/<kind>/<id>` with the validated payload.
- For each edge, `PUT /v1/edges`.

Then a parity script that compares Crux state to source, dedupes upstream id-collisions (last-write-wins), and exits non-zero on divergence. Cutover pattern: keep a dual-write bridge running until parity holds for one full poll cycle, then proxy reads to Crux, then retire the legacy path.

### 8. Tests

Three layers:

- **Lens unit tests** (`crates/crux-lens-<NAME>/src/`): exercise the pure analytics functions and the kind bootstrap.
- **MCP tool tests** (`crates/crux-mcp/src/tools/<NAME>.rs`): seed entities via `entity_upsert`, call your handler, assert the MCP `content` payload.
- **Live daemon integration test** (`crates/crux-integration-tests/tests/daemon.rs`): one end-to-end test that seeds via `/v1/entities/<kind>/<id>`, hits your `/v1/<lens>/<analysis>` endpoint, asserts the response.

The third is the strongest signal: it boots the real binary and exercises every wired path.

## Don't

- **Don't add a route that scans all entities for an aggregation that runs frequently.** Either keep aggregations bounded (`limit` query param) or register a secondary index. Substrate scans are fine for once-per-page analytics; they're not fine for hot paths.
- **Don't write directly to `entities.jsonl` from the lens.** Always go through `EntityStore::upsert` so the journal write and the in-memory state stay consistent. Even the lens's own audit hooks should call `entity_store.write().await.upsert(...)`.
- **Don't use the generic `entity_*` MCP tools as the public surface for your lens.** They're fine for plumbing, but namespace your domain operations (`task_*`, `goal_*`) so agents discover the right tool by domain.
- **Don't tightly couple the lens to a specific storage backend.** The lens reads from `EntityStore::list(...)`. If we later swap sled in (for example), the lens code is unaffected because the trait shape is stable.
- **Don't bypass the kind validator.** Even if your lens "knows" the payload shape, the substrate runs validation on every upsert. Trust it; don't replicate it in the lens.

## Compose with the substrate

The substrate gives you for free:

- **Receipts / audit trail** — `entity_history(kind, id)` returns the full version chain. The lens does not need a separate audit table; just call this.
- **Soft-delete** — `entity_delete` marks deleted; `entity_history` keeps the deleted version. The lens's "trash" view is a free-form `entity_list?include_deleted=true&kind=…`.
- **Cross-lens linking** — an edge between `(capability, X)` and `(task, Y)` is a `PUT /v1/edges` with `edge_kind="implements"`. Both lenses can read it. No coordination needed beyond agreeing on the edge kind name.

## When to extract aggregation into the lens vs. expose generic substrate

| Operation | Substrate is enough | Lens should own it |
|---|---|---|
| Get one entity | ✅ `entity_get` | — |
| List entities of a kind | ✅ `entity_list?kind=…` | — |
| Filter by payload field | Substrate (post-filter callers) | If the filter is hot, register a secondary index in the substrate. |
| Aggregation across many entities | — | Lens analytics function. |
| Dependency walking | — | Lens (see `get_dependency_tree` in features). |
| Domain-specific write (audit) | — | Lens — usually involves merging into existing payload + upserting. |
| Cross-domain join | — | Higher-level: a service that reads from multiple lenses. The substrate doesn't try to do joins. |

## Reference implementation

The Features lens is the canonical reference:

- Crate: [`crates/crux-lens-features/`](../crates/crux-lens-features/)
- HTTP routes: [`crates/corecruxd/src/http/features.rs`](../crates/corecruxd/src/http/features.rs)
- MCP tools: [`crates/crux-mcp/src/tools/features.rs`](../crates/crux-mcp/src/tools/features.rs)
- Integration test: search `features_lens_end_to_end` in [`crates/crux-integration-tests/tests/daemon.rs`](../crates/crux-integration-tests/tests/daemon.rs).

## Sibling pattern: agent config

For workflow guardrails (CLAUDE.md / AGENTS.md profile fragments) instead of domain data, see the [Agent Config Wizard](./agent-config-wizard.md). Same "substrate generic + per-domain opt-in" philosophy, different target: the wizard ships rules; lenses ship data.
