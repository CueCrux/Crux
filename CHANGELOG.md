# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Cadence:** weekly rolling builds are cut from `main`; versioned releases
> ship every 4–8 weeks. Every versioned release gets human-readable notes
> here — if you tag a release, you write its entry.

## [Unreleased]

## [0.5.35] - 2026-07-03

### Added

- **Opt-in signed usage receipts (Phase T).** A local, signed, metadata-only
  `usage_ping` CROWN receipt (default-OFF), plus a consent-gated, verifiable
  opt-in submitter — the daemon's only sanctioned outbound signal, gated behind
  `CORECRUXD_USAGE_RECEIPTS_{SUBMIT,ENDPOINT,CONSENT_AT}`; inert under default
  config so `assert-no-phone-home` stays green (#315, #317, #318). See
  `docs/usage-receipts.md`.
- **Side-by-side demo** — `/console/receipts-vs-console`: the CROWN
  receipts-as-debugging timeline next to a vendor free-console mock (#316).
- OpenAPI: receipts routes covered in `/v1/openapi.json` plus a route-level
  contract test (#168).
- Upgrade-aware `501` responses on platform-only endpoints (HTTP + MCP) that
  signpost the hosted platform instead of a bare not-implemented (#169).
- Workspace wizard: live-session coordination protocol (`workspace-cuecrux` v2 → v3).

### Changed

- **Launch defaults ON** — coordination plane (`CORECRUXD_COORD`),
  passport-revocation enforcement (`CRUX_PASSPORT_REVOCATION`), agent-card
  discovery (`CRUX_AGENT_CARD`), and scoped-forget default to ON for fresh
  installs; typed action traces + activity signing remain documented opt-in (#314).
- Trust surface: `assert-no-phone-home.sh` + the CROWN receipt-tamper demo are
  now release-blocking gates in `release.yml` (#313).
- CI: `paths-ignore` replaced with a skip-but-report change-scope gate.

## [0.4.6] - 2026-06-11

### Added

- Console: Live board panel (`#/coord`) — coordination plane viewer (#166).

## [0.4.5] - 2026-06-11

### Fixed

- Coord board per-session recency gate (#165).

## [0.4.4] - 2026-06-11

### Fixed

- Coordination follow-up: announce overlap warnings, plus presence touch at
  bind/announce — board liveness fix (#164).

## [0.4.3] - 2026-06-11

### Added

- Coordination plane: live-session board for concurrent agent sessions —
  `/v1/coord`, `coord_status` / `coord_announce` MCP tools, boot digest (#163).
- Console: receipts view + CROWN verify panel with `#/receipts` deep link
  (#162).

## [0.4.2] - 2026-06-11

### Added

- Agent→passport resolution + mediation receipts for external mediators
  (B0–B4) (#161).

## [0.4.1] - 2026-06-10

### Added

- MCP tool-surface floor additions: `get_passport`, `receipt_verify`,
  `sync_status` (#160).

### Changed

- CRC-v1 default-on, with a legacy opt-out (#159).

## [0.4.0] - 2026-06-10

### Added

- Graph-driven dynamic MCP tool surface + capability-graph edges (#158).
- CRC-v1 pointer-first response contract: spec + daemon search tools (M0+M2)
  (#156).
- `corecrux.lane.*` registry with free→paid minting and usage-report ingest
  (#154).

### Changed

- Hardened daemon auth and agent helpers (#153).
- Dependency bumps (opentelemetry_sdk, wasmtime, rcgen, sha2, chrono, uuid,
  and others).

### Fixed

- Flaky gRPC replication-auth env-test race serialized (#157).

## [0.3.1] - 2026-06-05

### Fixed

- `corecruxd --version` and the boot banner now report the real short git sha in
  container builds instead of `(unknown)`. The Docker builder has no `.git`, so
  `build.rs` now honours a `CORECRUX_GIT_SHA` env (set from a `GIT_SHA` build-arg
  the Docker workflow passes as `github.sha`), falling back to `git` then
  `unknown`. Makes deploy audits able to confirm the running commit.

## [0.3.0] - 2026-06-05

### Fixed

- **New-tool probe fixes** (memory / freshness / coordination surface). A probe
  of the freshness/memory + orchestrator/punchcard/work tools surfaced 12 issues;
  all are fixed (ExecPlan `crux-new-tool-probe-fixes-2026-06-05`):
  - **Latest-version-wins recall.** `FactStore::store`/`try_store` now retire the
    prior `(entity, key)` version (`superseded_by`) so `query_facts` returns the
    current value instead of every historical version. Re-stores and `memory_edit`
    were leaking stale values into recall; `include_superseded` / `memory_view` /
    `memory_history` still expose the full chain.
  - **`memory_edit`** now stamps the editor's passport `actor` (was `null`),
    preserves the prior `horizon_class` (was reset to the entity default), and
    carries the user pin to the new version (was silently dropped — losing decay
    and scoped-forget protection).
  - **Scoped-forget honours pins.** Pinned facts survive `memory_forget` by
    default (documented #9 contract); `include_pinned: true` overrides for a
    GDPR Art.17 erasure. `__memory_pin::` added to the forget reserved prefixes.
  - **`update_work_state` 401.** The MCP `loopback_patch` helper was the only
    loopback verb not attaching the bearer token; it now does.
  - **Anonymous coordination writes.** MCP loopback writes forward
    `X-Corecrux-Passport-Id` from the session, and the punchcard
    acquire/release bodies accept `holder_passport` (preferred over the header
    actor), so orchestrator/punchcard/work writes are attributed to a real
    passport instead of `anonymous`.
  - **Orchestrator passport members.** `attach_to_orchestrator` accepts a
    `passport` member (validated against the passport store by id or
    principal_id) instead of returning an opaque 400; the error now names all
    accepted types.
  - **`memory_forget_dry_run`** returns `facts_that_would_be_affected` under
    `structuredContent` so MCP clients actually receive it.
  - **`create_work`** documents that `project_id` must be an existing project
    (no implicit `default`).
  - **Loopback error surfacing.** The MCP→daemon loopback helpers now disable
    `ureq`'s `http_status_as_error`, read the response body on 4xx/5xx, and
    surface the daemon's problem+json `detail` (e.g. `daemon returned 404:
    project not found` / `passport 'x' not found`) instead of a bare
    `status 404`. All four verbs (get/post/patch/delete) share one agent +
    status-error path; transport failures are reported distinctly.

### Changed

- **New `update_orchestrator` MCP tool** wraps `PATCH /v1/orchestrators/{id}`
  (name / assignee / state incl. `archived`) so an orchestrator can be closed
  out via MCP.
- **`store_fact`** advertises `horizon_class` + `freshness_horizon` in its
  schema (the handler already read them) so a freshness horizon is settable in
  one call.
- **Envelope `memories_used`** carries `age_hours` alongside `age_days` for
  unit consistency with the freshness/query rows.

### Added

- **GitHub shared memory** — selected GitHub repos become a searchable corpus
  any agent attached to the daemon can read:
  - PAT-based connection; the token is encrypted at rest with XChaCha20-
    Poly1305 using a key derived from the daemon-root passport via BLAKE3
    KDF (`LocalPassportKey::derive_subkey`). Endpoints:
    `GET /v1/integrations/github/status`,
    `POST /v1/integrations/github/connect` (verifies via api.github.com),
    `POST /v1/integrations/github/disconnect`.
  - Repo selection: `GET /v1/integrations/github/repos[/accessible]`,
    `POST/DELETE /v1/integrations/github/repos/{owner}/{repo}/select`.
  - Background sync worker pulls commits + PRs + issues + comments into
    facts under `github::owner/repo::{commit,pr,issue,comment}/{id}`.
    Polling cadence configurable via
    `CORECRUXD_GITHUB_SYNC_INTERVAL_SECS` (default 900s);
    `POST /v1/integrations/github/sync` triggers immediately.
  - Mention parser: `[work:<id>]` markers in PR/issue bodies link back to
    Plan A work items.
  - Five new MCP tools surface the indexed corpus to coding agents:
    `github_search`, `github_recent_commits`, `github_open_prs`,
    `github_open_issues`, `github_comments_since`.
  - Console UI: GitHub section in Settings with PAT connect form, repo
    picker, sync button, and per-repo selection. Project drawer surfaces
    open issues inline when `planning_target = github://owner/repo`.
- **Coordination** — multi-passport, projects, and a 6-state work kanban for
  cross-agent coordination on the same daemon:
  - `GET/POST/PATCH/DELETE /v1/passports` + `GET /v1/passports/{id}` — multi-
    passport store; auto-seeds `personal-default` / `work-default` /
    `public-default` on first boot. Per-passport `agent_work_gate` toggle
    queues agent state changes for human approval when set.
  - `POST /session` accepts new optional `project_id` / `tenant_id` /
    `passport_id` and returns the resolved binding via `X-CueCrux-*` response
    headers. `GET /v1/sessions/active` lists recent bindings.
  - `GET/POST/DELETE /v1/projects` + `GET /v1/projects/{id}` + member/tenant
    sub-routes. Auto-seeds a `default` project on first boot. `planning_target`
    supports `tenant://` or `github://` URLs (the latter activates once Plan B
    GitHub indexing ships).
  - `GET/POST /v1/work` + `GET/PATCH /v1/work/{id}` + comments + transitions +
    `POST /v1/work/gate/{id}/approve|reject`. Six work states: Planned ·
    In Progress · Blocked · Archive · Complete · Deployed. PATCH returns 200
    (applied) or 202 (queued behind a gate).
  - Six new MCP tools: `list_projects`, `get_project_context`, `list_work`,
    `create_work`, `update_work_state`, `comment_on_work`. Both Claude Code
    sessions and other agents can read/write the same kanban from inside
    their own session.
  - Console UI: new `Projects` and `Work` panels, rebuilt `Passport` panel
    with the six layers of agent self-knowledge (Identity + Rules filled;
    Operator/Directive/Playbook/Continuity as "Available in CueCrux Cloud"
    placeholders). Active-project picker in the rail.
- In-process relation graph wired into the open Crux Daemon: new
  `POST /v1/relations` (write edge — `facts:write` scope),
  `GET /v1/relations?tenant_id=&from_id=` (list outgoing — `admin:read`),
  `POST /v1/relations/expand` (multi-hop graph traversal — `admin:read`).
  Edges persist as JSONL at `data_dir/relations.jsonl` and are replayed into
  in-memory `ProjectionState` on startup. The `corecrux-projections::query::graph_expand`
  algorithm is now usable from the open daemon without a dataplane stub.
- Console settings page (cog icon, top-right of rail): persists chosen auth
  mode, embedding endpoint URL, and model; surfaces `restart_required` when
  changes need a daemon bounce. New endpoints: `GET/PUT /v1/console/settings`.
- Storage-breakdown chart relabelled to Text Search / Projections / Embedding /
  Graph, each with a hover tooltip explaining what populates it. Graph bar now
  reads real edge counts from the new relation surface.
- Overview hero condensed: daemon-posture and boundary-check facts are now
  inline chips with custom CSS tooltips inside the hero band, replacing the
  two stacked cards beneath.
- Embedded Crux Console redesigned for non-technical users: first-run
  onboarding flow with live healthz/readyz/version tiles and a 3-card auth
  picker (off / dev_scopes / jwt_hs256), nav reordered (Passport before
  Integrations), Add Fact form, fact search box, tenant Personal/Work/Public
  tabs, and a hand-rolled SVG storage-breakdown bar chart with Chunks/Bytes
  toggle. Aligned to the cuecrux palette. Single-file `playground/index.html`
  stays under 100 KB with no external dependencies.
- New console endpoints: `GET /v1/console/onboarding`,
  `POST /v1/console/onboarding/complete`, `POST /v1/console/onboarding/restart`,
  `GET /v1/console/storage-breakdown`, `POST /v1/console/facts/add`. Existing
  `GET /v1/console/facts` accepts `q=` and `top_k=`; `GET /v1/console/tenants`
  accepts `category=personal|work|public|all` and emits a `category` field per
  tenant (prefix-based; `personal` is the default).
- `CORECRUXD_CONSOLE_DEV_PATH` env: when set, the daemon serves the console
  HTML from disk instead of the embedded `include_str!` copy. Bind-mount via
  the new `docker-compose.dev.yml` overlay for instant browser-refresh
  iteration without rebuilding the image.
- Persistent console settings file at `data_dir/console/settings.json`
  (atomic tmp+rename writes, schema-versioned).
- JSONL persistence for fact store and session store — facts survive daemon restarts
- Paginated fact export endpoint (`GET /v1/facts/export`) with cursor pagination
- Bidirectional sync client — pull enriched facts from remote CoreCrux, push local facts back
- Background sync task with configurable interval (`CORECRUXD_SYNC_INTERVAL_SECS`)
- Privacy controls for sync: `private` flag on facts, 14 default entity-prefix blocklist, preview-before-push
- 3 new MCP tools: `sync_pull`, `sync_push`, `sync_status` (21 tools total)
- Architecture Decision Records (`docs/adr/`): append-only segments, CROWN receipts, CPU-only edition
- Benchmark documentation (`docs/benchmarks.md`)
- gRPC integration tests covering all data-plane RPCs
- Runnable Rust example (`examples/rust/append_and_query.rs`)

### Changed

- Split `corecrux-storage/src/lib.rs` (13k LOC) into 9 domain modules
- Split `corecruxd/src/http.rs` (10k LOC) into 10 handler sub-modules
- Migrated CI to self-hosted Hetzner runners
- Stripped all GPU/CUDA data-plane code (~10k LOC removed) — Crux Daemon is CPU-only
- Built-in MCP support is now part of the supported `corecruxd` runtime path, quickstarts/examples/docs, and CI smoke checks
- Standalone integration-test runs now have a dedicated helper script that builds `corecruxd`, exports `CORECRUXD_BINARY`, and runs the integration crate consistently

### Fixed

- Flaky `crux-observe` config test (env-var race condition)
- `SessionStore::put` TTL parameter across all callers
- `arduino/setup-protoc` GitHub API rate limit (added `repo-token`)
- Handoff import/export privacy and authenticity handling for MCP agent transfers
- MCP agent/session scoping across fact queries, entity listing, and session operations
- HTTP `private=true` fact writes are now rejected instead of implying unsupported caller scoping
- Runtime/docs/example drift around append compatibility, text-search request shapes, and local-daemon feature surfaces
- Integration harness startup and readiness behavior across HTTP, gRPC, and MCP listeners

### Security

- Fact sync privacy: sensitive entity prefixes (`finance:`, `health:`, `personal:`, etc.) are never pushed upstream
- Sync push requires explicit `confirm: true` via MCP tool — preview mode by default
- MCP bearer-token enforcement now returns `401` instead of silently accepting anonymous POSTs when agent tokens are configured

## [0.1.0] - 2026-04-03

### Added

- Append-only event store with sealed segments, BLAKE3 integrity, and crash recovery
- CPU BM25 retrieval via `.ccxi` companion indexes with PForDelta compression
- Graph signal fusion for relation-aware retrieval
- CROWN receipt generation with Ed25519 signatures and BLAKE3 chain
- Token-budgeted retrieval (fill results until token budget exhausted)
- Relevance floor (minimum BM25 score threshold with `below_floor` count)
- Progressive retrieval (scan/expand two-pass pattern)
- Coverage and gap reporting on every query response
- Fact store (receipted key-value entity memory with BM25 search)
- Session store (scoped state per session with token counting)
- CLI tools: `corecruxctl verify-store`, `replay`, `inspect-receipt`, `explain`, `gaps`
- Contribution manifest (`crux-contrib`) with BLAKE3 content-addressed envelopes
- Sync client (`crux-sync`) with outbox-based offline-first VaultCrux sync
- HTTP API on port 14800 (`/healthz`, `/readyz`, `/metrics`, `/v1/append`, `/v1/query/*`, `/v1/facts/*`, `/v1/sessions/*`)
- gRPC data plane (append, read, replay, export)
- Prometheus metrics endpoint (100+ operational metrics)
- Docker image (Debian bookworm-slim) with docker-compose.yml
- GitHub Actions CI (lint, test, 82%+ coverage, release binaries, Docker push)
- Strict linting (`unsafe_code` forbidden, pedantic clippy, 81% coverage floor)

### Security

- CueCrux Community Licence (CCL v1.0) with 3-year Apache 2.0 conversion
- No telemetry, no phone-home, no tracking in standalone mode
- `cargo-deny` supply chain and licence audit in CI
- `cargo-audit` CVE scanning in CI

[unreleased]: https://github.com/CueCrux/Crux/compare/v0.4.6...HEAD
[0.4.6]: https://github.com/CueCrux/Crux/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/CueCrux/Crux/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/CueCrux/Crux/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/CueCrux/Crux/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/CueCrux/Crux/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/CueCrux/Crux/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/CueCrux/Crux/compare/v0.3.1...v0.4.0
[0.1.0]: https://github.com/CueCrux/Crux/releases/tag/v0.1.0
