# B0 — Crux daemon surface for `crux-agent-passport-mcp-binding-2026-06-10`

> Read-only audit. Anchors below are file:line into `Crux/`. `session_bindings.rs`,
> `fact_privacy.rs`, `passports.rs`, the HTTP router and the MCP tool table were
> spot-verified directly during the audit; remaining anchors are verified as B1/B2 land.
> No code changed in B0.

Relevant crates: **`corecruxd`** (HTTP `:14800` — daemon-side passport/session/receipt
stores) and **`crux-mcp`** (MCP `:14801` — agent-facing tool surface). Neither
`resolve_principal` nor `ingest_mediation_receipt` exists today.

## A. Session-binding store — `crates/corecruxd/src/session_bindings.rs`
- `struct SessionBinding` (`:30-39`): `{session_id_hex, project_id, tenant_id, passport_id, passport_category, agent_work_gate, bound_at_unix_ms}`.
- `write_binding` (`:75-90`) → fact `__session_binding__::{session_id_hex}` key `record`; calls `fact_privacy::enforce_global` at `:87` but writes `private:false` (`:83`).
- `resolve(store, ResolveInput)` (`:49-73`) joins tenant→category→passport (`get_passport` / `default_for_category`); does **not** persist.
- `list_bindings` (`:92-111`) prefix-scans `__session_binding__::`, dedups latest. **No `get_binding(session_id_hex)` point lookup exists** → B1 adds a trivial one mirroring `:92-111`.
- Prod writer: `crates/corecruxd/src/http/session.rs:484-517` (`POST /session`); readers at `http/session.rs:224,278`.

## B. Passport stores (TWO, same prefix, different key) — split documented at `crux-mcp/src/tools/passport.rs:78-95`
1. **Daemon** `crates/corecruxd/src/passports.rs` — key `__passport__::{id}` key=`record`; `struct PassportRecord` (`:58-75`): `id, principal_id, public_key_hex, category, sponsor_id, reputation_tier, receipt_count, agent_work_gate, is_default_for_category, issued_at_unix_ms`. **Source of truth** for `category`/`agent_work_gate`. CRUD `:124-235`; `seed_defaults_if_missing` `:239-266`.
2. **MCP** `crates/crux-mcp/src/tools/passport.rs` — key `__passport__::{name}` key=`passport`; `struct PassportRecord` (`:30-48`): `principal_id, sponsor_id, reputation_tier, receipt_count, issued_at, passport_hash, tenant_group`. Hosts the reputation/tier ladder + sync gate (`require_passport_tier` `:153-191`); calling-agent reader `get_agent_passport` `:120-139`.
- Unifying read precedence already exists: `crux-mcp/src/category_enforce.rs:110-145` (`passport_category_for`) reads daemon `record.category` first, falls back to MCP `passport.tenant_group`. **B1 mirrors this precedence.**

## C. Tier ladder + capability source
- Tier ranking duplicated (B3 lever — not yet shared):
  - `corecruxd/src/passports.rs:35-93` — `TIER_*_RECEIPTS` + `resolve_tier(receipt_count) -> unverified|basic|established|trusted|elite`.
  - `crux-mcp/src/tools/passport.rs:23-76` — identical thresholds + **`tier_rank(tier) -> u8`** (`:68-76`), the only comparable-rank source. `identity.rs:52` hard-codes `OPERATOR_TIER="trusted"`.
- **No per-passport `capabilities[]` list exists.** Only vocab: session plan `capability_graph` (`http/session.rs:474`) and `passport_link_device.capabilities_subset` (default `["facts:read"]`, `identity.rs:686-689`). → `resolve_principal`'s `capabilities[]` is **net-new** (synthesize from tier→capability map; the canonical map is B3).

## D. Identity handlers (both hard-wired to the CALLING session)
- `handle_cuecrux_session` — `crux-mcp/src/tools/cuecrux_session.rs:57-159`. Auto-issues the calling agent's MCP passport (`:64`), then loopback `POST {daemon}/session` (`:107-122`) which triggers the §A write. Identity from `ctx.agent`; session_id is daemon-minted, **not** caller-supplied.
- `handle_get_agent_identity` — `crux-mcp/src/tools/mod.rs:2424-2436`. Returns only `ctx.agent.name`.
- Resolution order today: `ctx.agent` (bearer → `server.rs:52-73`) → `passport_key_name` (`passport.rs:108-116`) → `__passport__::{name}` key=`passport`. **No path accepts an external principal** → `resolve_principal` is a genuinely new read that takes `session_id|agent_token` as input.

## E. Receipts + timeline write path (MUST reuse — T.4)
- CROWN minting: `corecruxd/src/http/observations.rs:322-347` (`mint_receipt`) — BLAKE3 canonical body + Ed25519 sign with daemon-root passport key; returns `ReceiptEnvelopeV1{alg,signed_by,body_hash,signature}`. Canonical helper `canonical_body_bytes` `:314-320`.
- Mint+persist+stream pattern: `observations.rs:456-555` (`write_observation_record`) → `mint_receipt` `:523` → `append_observation` JSONL `:539` → dataplane stream `:545` (`STREAM_TYPE_RECEIPT`). Read back at `http/receipts.rs:10-44`.
- **Timeline is a read-projection, not a writer.** `/v1/projections/entity/timeline` reader `http/projections.rs:537-578`. Fed by `EntityFactV1` events (`corecrux-projections/src/events.rs:22,70`) applied at `corecrux-projections/src/state.rs:354-371` (`apply_entity_fact` → `entity_timelines`). The attribution-carrying writer is `entity_store.upsert(kind,id,payload,actor,registry)` — `http/entities.rs:76-97` (`put_entity`), `actor` from `actor_from_headers` `:85`.
- **⇒ `ingest_mediation_receipt` = `mint_receipt`-style sign + `entity_store.upsert(kind="mediation_receipt", actor=passport_id)`.** Never writes the timeline row directly (T.4).

## F. Insertion points
- **HTTP router**: `corecruxd/src/http/mod.rs:267` (`pub fn router`), flat `.route(...)` chain (passports `:825-829`, session `:484-486`, timeline `:349`). Add `GET /v1/principal/resolve` + `POST /v1/mediation/receipts` here.
- **MCP tools**: `crux-mcp/src/tools/mod.rs` — definition table `list_tools_local_surface` (`:133`, `ToolDefinition{name,description,input_schema}` `:68`) + dispatch `match name` in `call_tool` (`:2439-2495`). Collapsed-surface floor `surface.rs:56-66`. Add both tools in both places.
- MCP identity binding once at `crux-mcp/src/server.rs:52-95` (bearer → `agent_registry.lookup` → `with_agent`).

## G. Caller auth + tenant scoping (governs T.1/T.3)
- **HTTP** `corecruxd/src/auth.rs`: helpers `http_scope_context`/`passport_bound_context` (`:788-800`); guards `require_http_scopes` / `require_http_scopes_for_tenant` / `require_http_any_scope` (e.g. passports gate `admin:read` `http/passports.rs:60`; receipts gate `receipts:read`+tenant `http/receipts.rs:16`). Tenant from JWT/headers `["tenant_id","tenantId","tid"]` (`:296`), enforced by `require_tenant_allowed` (`:665-688`). Caller passport id from `x-corecrux-passport-id` via `bind_http_passport` (`:790`).
  - ⇒ new HTTP endpoints call `require_http_scopes_for_tenant` and reject if resolved binding's `tenant_id` ≠ caller tenant (T.1).
- **MCP** `crux-mcp/src/server.rs:52-73`: bearer → identity; 401 when registry non-empty (`:60-69`). Tenant not first-class in MCP — derived per-fact from entity prefix (`category_enforce.rs:82-87` `extract_tenant_prefix`).

## Can / can't today (standalone mediator)
- **Resolve an arbitrary principal? NO.** Every path reads `ctx.agent` (MCP) or caller's own `x-corecrux-passport-id` (HTTP). Join logic exists piecemeal (`session_bindings::resolve` + `passports::get_passport` + `tier_rank`) but is not exposed as one authenticated tenant-scoped read.
- **Ingest a receipt attributed to a passport? NO.** `mint_receipt` signs with the daemon-root key, is private to `observations`. No endpoint takes `{passport_id, tool_server, tool, args_sha, decision, outcome, ts}` and emits receipt+timeline.

## Minimal new surface
1. **`resolve_principal(session_id | agent_token)`** — wiring + one small reader. Compose new `session_bindings::get_binding(hex)` → `passports::get_passport` → `passports::resolve_tier`; for `agent_token` reuse `agent_registry.lookup` → name → `passport_key_name`. Net-new: `capabilities[]` (synthesize; canonical map = B3). Auth via `require_http_scopes_for_tenant` + cross-tenant reject (T.1).
2. **`ingest_mediation_receipt(...)`** — one new path from existing primitives. Guard: internally `resolve_principal(passport_id)` first; refuse if caller can't resolve / cross-tenant (T.1/T.3). Emit: `mint_receipt`-style sign + single `entity_store.upsert(kind="mediation_receipt", actor=passport_id)`. Never write timeline directly (T.4).

## Privacy enforcement (reserved prefixes)
- `__passport__::` — born private via `corecruxd/src/fact_privacy.rs:96` (`DEFAULT_PRIVATE_PREFIXES`), enforced in `passports::write_record:299` and `session_bindings::write_binding:87`. MCP side via `category_enforce.rs:14`.
- **GAP (close in B4):** `__session_binding__::` is **NOT** in `DEFAULT_PRIVATE_PREFIXES` (`fact_privacy.rs:75-102`) → binding facts are `private:false` (`session_bindings.rs:83`), only kept out of MCP recency via `crux-mcp/src/envelope.rs:72,78-84`. They are technically sync-eligible. **B4 adds `"__session_binding__::"` to `DEFAULT_PRIVATE_PREFIXES`.**

## Milestone implications
- **B1**: add `session_bindings::get_binding`; new resolver composing existing fns; synthesize `capabilities[]`; HTTP route + MCP tool; tenant-scope + cross-tenant deny.
- **B2**: reuse `mint_receipt` + `entity_store.upsert(actor=passport_id)`; guard via internal `resolve_principal`.
- **B3**: lift the duplicated tier ladder (`corecruxd/passports.rs:35-93` ≅ `crux-mcp/passport.rs:23-76`) toward a single source; define tier→capability map; expose read. Reconcile with gateway `policy.py:TIER_LADDER`.
- **B4**: add `__session_binding__::` to `DEFAULT_PRIVATE_PREFIXES`; T.1/T.3/T.4 negative suite.
- **B5**: human-gated `cargo-deploy` + smoke.
