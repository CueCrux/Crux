# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Cadence:** weekly rolling builds are cut from `main`; versioned releases
> ship every 4–8 weeks. Every versioned release gets human-readable notes
> here — if you tag a release, you write its entry.

## [Unreleased]

### Changed

- **Relicensed to Apache-2.0 — Crux Daemon is now open source.** The CueCrux
  Community Licence (CCL v1.0), a source-available BSL-style licence, is
  replaced by the **Apache License, Version 2.0** across the repository. The CCL
  already named Apache 2.0 as its Change Licence, so this brings that conversion
  forward for every version instead of waiting out the per-release three-year
  clock. Redistribution in competing products and offering Crux as a hosted
  service to third parties — the two rights the CCL withheld — are now granted,
  along with Apache-2.0's express patent grant (section 3).
  - `LICENCE.md` → `LICENSE`, containing the unmodified upstream Apache-2.0
    text, so GitHub and SBOM scanners detect `Apache-2.0` instead of reporting
    an unrecognised custom licence.
  - New `NOTICE` file carrying the attribution required by section 4(d), plus
    the trademark and `content/` scope notes that must not be edited into the
    verbatim licence text.
  - Per-file headers on all 539 crate `.rs` files (and every script, workflow,
    proto, SDK source, and console asset) now read
    `SPDX-License-Identifier: Apache-2.0`. The contradictory
    "All rights reserved." line is dropped.
  - `license = "Apache-2.0"` in `[workspace.package]` and in the desktop shell,
    Python/TypeScript SDK, deb, Homebrew, and MCPB manifests;
    `LicenseRef-CCL-1.0` removed from the `cargo-deny` allowlist.
  - `scripts/check-licence-headers.sh` now enforces the Apache-2.0 header and
    SPDX line. Contribution terms in `CONTRIBUTING.md` are inbound=outbound
    under section 5 — no CLA. `docs/LICENCE-FAQ.md` rewritten;
    `docs/design/licence-recommendation.md` (the BUSL 1.1 proposal) marked
    superseded.
  - Curated content under `content/` keeps its separate licence
    (`content/LICENCE-CONTENT.md`) and is unaffected; that directory currently
    ships a placeholder manifest with no covered assets.
- **Licence file layout deduplicated to a single GitHub licence tab.**
  `LICENCE-CODE.md` (a three-line stub pointing at `LICENCE.md`) is removed, and
  the content licence moved from the root to `content/LICENCE-CONTENT.md` — the
  directory it governs. GitHub's licence detector scans only the repository
  root, so it now surfaces one top-level licence (`LICENCE.md`, the code
  licence) instead of two tabs. `LICENCE.md` links to the content licence, and
  release bundles ship it under `content/` alongside the assets it covers.

### Added

- **`CITATION.cff`.** Machine-readable citation metadata (GitHub "Cite this
  repository" button). Under Apache-2.0 citation is appreciated but not a
  licence condition.

### Fixed

- **A cold `cargo build` now completes on native Windows.** Three unrelated
  stops, none of which CI can see (every runner is Linux, and the release matrix
  is Linux + macOS — both unix):
  - `aws-lc-sys` assembles its x86_64 Windows routines with NASM, absent from a
    default Windows toolchain, so the build script aborted. The crate ships
    pre-assembled objects for this case; `AWS_LC_SYS_PREBUILT_NASM = "1"` now
    lives in `.cargo/config.toml`. Inert on Linux and macOS, where the prebuilt
    path is gated off by target.
  - `fsync_dir` (`corecrux-projections`) and `write_control_atomic`
    (`corecruxd`) bound a variable consumed only inside `#[cfg(unix)]`. Against
    the workspace-wide `unused_variables = "deny"`, that is a hard error off
    unix. Both bind the value under `#[cfg(not(unix))]` rather than renaming to
    `_path`/`_parent`, which would have suppressed the lint on unix where the
    variable is load-bearing.

- **`cargo clippy --workspace -- -D warnings` now passes on native Windows.**
  Seven `clippy::unnecessary_wraps` errors across `corecrux-receipts`,
  `corecrux-storage`, and `crux-claude-hooks`: each is a directory-fsync or
  file-permission routine whose body is unix-only, so off-unix it collapses to
  `Ok(())` and the `Result` looks redundant. The signature is shared with a
  genuinely fallible unix implementation, so these are suppressed at the site
  with a note, not "fixed" by dropping the return type.

  Native Windows remains post-v1 per `docs/getting-started.md`; WSL2 is still
  the supported path. This only stops the gap widening — there are ~49
  `#[cfg(unix)]` sites and no Windows job to catch the next one.

- **`config.example.env` no longer claims a `.env` file is read.** The daemon
  has no dotenv support, so copying the file and starting `corecruxd` failed
  with "CORECRUXD_AUTH_MODE must be set explicitly" — indistinguishable from a
  genuine config error. The header now shows how to export the values.

### Security

- **Invocation verification now names its actual trust level.**
  `POST /invocation/verify` replaces the misleading `verified` field with
  `structurally_consistent` and explicitly reports
  `authenticity_verified: false`, `replay_checked: false`, and
  `verification_scope: "local_structural_integrity"`. The Rust verdict helper
  is likewise renamed from `verified_overall()` to
  `structurally_consistent()`, and the Prometheus success label follows the
  new name. These are intentional breaking changes: the local public route
  checks hashes, parent linkage, capability, and channel, but does not verify a
  signature, execution evidence, freshness, or replay.
- **`.mcp.json` is gitignored.** MCP clients write the daemon's agent bearer
  token into that file at the repository root, where it was previously
  committable.

## [0.5.38] - 2026-07-10

### Added

- **AST-derived code-structure scanner.** Behind `CORECRUXD_AST_SCAN`, the
  workspace scanner produces the `WorkspaceScan` shape from a `syn` AST pass
  instead of the regex scanner (flag-off byte-identical). ~17× faster on the
  Crux tree (p95 ~0.9 s vs ~15 s) and more accurate: call-edges resolved
  module-qualified, dead-code by AST identifier-reachability rather than the
  O(n²) substring pass. Context-graph edges fold in as `Extracted` confidence.
- **Watched repositories.** `POST/GET/DELETE /v1/repos` register a repo the
  daemon should know about (tenant-scoped; `corecruxctl repo add|list|remove`;
  MCP `register_repo` / `list_repos`). Registering a local path runs a one-shot
  scan. An active file-watch loop (`CORECRUXD_REPO_WATCH`, default off) keeps a
  repo's graph current via incremental re-index — a single-file edit re-parses
  only that file — using `notify` with a WSL `/mnt` polling fallback.
- **Polyglot extraction.** TypeScript/TSX, Vue (`<script>` blocks) and Python
  via `tree-sitter`, alongside Rust via `syn`; a language-agnostic repo walk
  scans repositories that are not Cargo workspaces.
- **Typed code edges in the relation graph.** `RelationTypeV1` gains
  `Calls` / `Imports` / `Defines` / `DependsOn` (append-only); behind
  `CORECRUXD_CODEGRAPH_EDGES` a repo's code graph is emitted as tenant-scoped,
  temporal relation edges and traversable via `POST /v1/relations/expand`.
- **Code-graph retrieval boost (spike).** A code-graph adjacency closure for
  `fused_retrieve`'s graph lane, behind `CORECRUXD_CODEGRAPH_FUSION`
  (default off; no recall study yet — see the ExecPlan).
- **Console code-graph view.** `/console/codegraph` renders the typed code+claim
  graph with node/edge/confidence visual language, focus + inspector, and
  `file:line` deep-links.

  _ExecPlan: `ast-polyglot-code-graph-and-repo-watch-2026-07-08` (M0–M8);
  supersedes `workspace-scan-storyline-improvements-2026-05-03` and
  `crux-code-intelligence-2026-06-12`._

- **Code map serving.** `GET /v1/repos/{repoId}/codemap` (`format=summary|full`)
  serves the AST scan persisted at registration/re-index — the read side of
  `POST /v1/repos`. Tenant-scoped `admin:read`; distinct 404s for unregistered
  vs never-scanned repos. Downstream: the WikiCrux code-maps surface
  (wiki.cuecrux.com/code, `wiki_codemap` MCP tool) consumes this endpoint.
  _ExecPlan: `codemap-endpoint-and-agent-docs-hardening-2026-07-10`._
- **Credit Meter spend rail (default-off).** `CORECRUXD_CREDIT_METER=1` enables
  the comped-wallet `POST /v1/credits/spend` path: pinned quotes → signed
  `crux.credit_spend_receipt.v1`, idempotent on retry (no double-debit).
- **Vendor observations.** Handoff/vendor observation capture with provider
  breakdowns (`list_observations` / `get_observation` / `verify_observation`);
  MCP handoffs are observed.
- **Usage receipts (opt-in).** Signed, metadata-only `usage_ping` receipts with
  a consent-gated submitter; `/v1/version` gains update/version-notify state.
- **Agent-docs hardening.** Nested `AGENTS.md` in all 28 crates
  (symbol-anchored, ≤50 lines); `check-agent-docs.sh` v2 gates llms.txt link
  parity, nested-file presence, `llms-full.txt` freshness and (in CI) executes
  the cheap documented commands; deterministic `llms-full.txt` generator;
  CLAIMS 10–15 and INVARIANTS I5 (witness anchoring) / I6 (custody-proof
  export); README redesigned around the 60-second agent-first quickstart.

### Fixed

- **Merged scan routing.** A cargo workspace containing any non-Rust supported
  files no longer flattens to a single polyglot package with zero routes:
  `run_repo_scan_at` merges the native Rust workspace scan with a
  rust-excluded tree-sitter pass (self-scan: 29 packages / 319 routes /
  14,290 symbols), and the watch loop re-indexes through the same path.
- Stale agent docs: MCP tool `token_usage` → `session_token_usage`; CODEMAP's
  nonexistent `ShardStorage::append` → `append_batch`/`append_batch_with_stats`.
- **Passport key create race.** `write_new_passport_seed` losers of the
  `create_new` race could read the winner's key file before its bytes landed
  ("key file is empty"); the key is now written in one buffer and the
  AlreadyExists path retries briefly. Test temp dirs additionally salt
  nanos with pid + a counter (coarse VM clocks collided parallel tests into
  one dir — the CI flake behind this).

## [0.5.36] - 2026-07-03

### Added

- **Usage receipts self-populate.** The daemon now auto-emits one `usage_ping`
  (`event_class=daemon_start`, keyed to the root passport) on startup — but only
  when the operator has opted into submission (the three-way consent gate).
  Default installs still dial nothing (`assert-no-phone-home` stays green); once
  opted in, the adoption signal registers on every boot with no manual mint (#322).
- **Version-notify.** The usage-receipt collector's response advertises the
  latest Crux release; the daemon compares it to its own version and, when
  behind, logs a warning and surfaces `update.latest_release` / `update.behind`
  on `/v1/version` (#322).

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
