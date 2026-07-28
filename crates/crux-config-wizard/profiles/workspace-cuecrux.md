+++
name = "workspace-cuecrux"
version = 5
description = "CueCrux workspace specifics: ExecPlan paths, daemon endpoints, live-session coordination protocol, Chainguard rule, JobClaw/MirrorClaw, three-place wiring. v5 rewrites the Feature Registry section: the PlanCrux API (:3334) and its MCP server were retired 2026-07-24, so the daemon's Features lens is now the only surface, not the 'prefer for new clients' alternative. Also names FeatureCrux explicitly as an unrelated flag router, because the name collision sends agents to the wrong service. v4 corrected the daemon endpoints from loopback to the live Tailscale host (the rendered files had been hand-patched, so regenerating would have silently reverted them) and demoted the PlanCrux read and the coordination check to steps of the single boot sequence in memory-practices. CueCrux-internal — only enable inside the CueCrux planning monorepo."
targets = ["claude_md", "agents_md"]
order = 90
risk_class = "low"
+++

## CueCrux Workspace

> **Scope.** This profile encodes paths and tools (`PlanCrux/`, `AuditCrux/benchmarks/`) that exist inside the CueCrux planning monorepo. Operators outside the CueCrux workspace should not enable this profile — the cross-references will not resolve. Use the generic profiles (`memory-practices`, `execplan-discipline`, `eu-ai-act`, etc.) instead.

### ExecPlan location

- Preferred path: `PlanCrux/.agent/execplans/<slug>.md`.
- Format defined in `PlanCrux/.agent/PLANS.md` (Purpose, Non-goals, Context, Constraints, Proposed design, Milestones, Test plan, Rollout/rollback, Risks, Progress, Decision log).

### PlanCrux reference reading

Not part of the boot sequence — read `PlanCrux/README.md` and `PlanCrux/buildguide.md` when the task actually touches PlanCrux goals, definitions, or canonical flows, then retain them as working context. Re-read only when:

- The user explicitly asks to refresh.
- You detect a version change (`PlanCrux/README.version` or front-matter, or last-modified timestamp).
- You need an exact quote or precise detail that is missing from your cached context.

### Crux Daemon endpoints

- HTTP API: `http://100.70.12.73:14800` on the Tailscale host `crux`.
- MCP server: `http://100.70.12.73:14801/mcp`.
- gRPC: `100.70.12.73:4007`.
- Use `.crux/agent-profile.toml` / `~/.config/cuecrux/env` as the source of truth for runtime endpoints; do not assume loopback endpoints unless the operator explicitly asks for a local daemon.

### ExecPlan Work board

`GET /v1/work?source=all` (and the equivalent `mcp__crux__list_work(source="all")`) returns kanban work items **merged with** a read-time projection over `PlanCrux/.agent/execplans/*.md`. Aggregator is enabled when `CRUX_EXECPLANS_ROOT` is set in the daemon process env (typically `/srv/<workspace>/PlanCrux/.agent/execplans`).

- ExecPlan items carry id prefix `execplan:<slug>`, virtual `project_id = "execplans"`, and extension fields `plan_path`, `current_milestone`, `superseded_by`.
- State is derived from facts (`milestone:M<n>`, `gate:M<n>`) plus `Status:` / `Superseded by` lines in the markdown — see `Crux/crates/corecruxd/src/work_execplans.rs` `derive_state`.
- The console SPA exposes a `Source: All | Kanban | ExecPlans` chip group; selection persists in `localStorage`.
- Drift detector: `bash Crux/scripts/reconcile-execplan-sessions.sh` lists orphan sessions (registry entry, no `.md`) and unparseable plans. Prints, does not mutate.

### Live-session coordination (multi-session, same tree)

The daemon's coordination plane (`CORECRUXD_COORD=1`, live on host crux since v0.4.5) gives concurrent Claude sessions a shared board: who is live, what each is doing, and where they collide. Console view: [`/console#/coord`](https://crux.cuecrux.com/console#/coord). Liveness is automatic (session bind + announce touch presence); only the focus declaration is yours to make.

Protocol when other sessions may be active on the same repo:

1. **Check who is live** (boot step 5): the boot banner's `— LIVE SESSIONS —` section, or `coord_status`. It lists peers' focus, paths, leases, and ⚠ overlap rows.
2. **Announce on every ExecPlan or milestone switch**: `coord_announce(session_id, project_id, execplan_slug, milestone, paths, note?)`. Re-announce replaces; `ttl_seconds: 0` clears on the way out. The response carries `overlaps[]` — surface any to the operator before proceeding.
3. **Lease before multi-file mutation**: `punch_in` a `tree://<dir>` or `file://<path>` punchcard for paths you will modify. The PreToolUse hook checks leases on every Edit/Write.
4. **Exit cleanly**: prefer `create_handoff` (bundles facts + work ids) over letting intents/leases time out; clear your intent with a zero-TTL announce when finishing.

Semantics: everything is **advisory** — overlap warnings and intents never block; punchcards block only in `enforce` mode. A peer's intent or lease on your target path means coordinate (work-item comments, handoff), not stop. One write-agent per *claimed path-set* supersedes the older one-write-agent-per-tree rule when claims are in place.

### Container base images

When writing Dockerfiles, prefer Chainguard images over upstream distros (Alpine, Debian, Ubuntu). Chainguard images are rebuilt daily with zero known CVEs. Map:

| Instead of | Use |
|---|---|
| `node:<v>-alpine|slim|bookworm-slim` | `cgr.dev/chainguard/node:latest` |
| `postgres:16` | `cgr.dev/chainguard/postgres:latest` |
| `nginx:alpine` | `cgr.dev/chainguard/nginx:latest` |
| `alpine:<v>` / `debian:<v>-slim` | `cgr.dev/chainguard/wolfi-base:latest` |

If no Chainguard equivalent exists (`pgvector/pgvector`, `mcr.microsoft.com/playwright`), keep the current image and note why.

### Cross-session handoff tools

Two operator-in-the-loop tools live in `AuditCrux/benchmarks/`:

- **JobClaw** (`AuditCrux/benchmarks/jobclaw/`) — task-level handoff queue. Lifecycle: Opus enqueues → Sonnet claims → Sonnet completes → Opus picks up.
- **MirrorClaw** (`AuditCrux/benchmarks/mirrorclaw/`) — per-API-call handoff. Local Anthropic `/v1/messages` simulator that lets a flat-rate Claude Code session BE the LLM behind a benchmark harness. Port 9991 host → 9999 container.

**Security rule for both**: targets prepend a "Where to run" preamble that includes credential discovery. NEVER paste a secret value into a file you write — always use `jobclaw targets exec <name> -- <cmd>` or `eval "$(jobclaw targets env <name>)"`. If a flat-rate Claude session is the operator, it MUST NOT call the Anthropic API — that defeats the entire point.

### Feature Registry

The Crux daemon serves the Feature Registry at `http://<crux-host>:14800/v1/features/capabilities/*`. The PlanCrux API (`:3334`, `pnpm dev:api`) and the `plancrux` MCP server were **retired 2026-07-24** (`plancrux-retirement-master-2026-05-19`, complete at M2) — do not target them. `FeatureCrux/` is an unrelated per-tenant feature-flag router on :3335, not this registry.

Key endpoints: `GET /v1/features/capabilities` (list/filter), `GET /v1/features/capabilities/{id}`, `GET /v1/features/capabilities/{id}/tree`, `GET /v1/features/capabilities/analysis/gaps`, `.../analysis/promises`, `.../analysis/coverage`. Reads need scope `facts:read` or `admin:read`. The capability store is global — no tenant scoping.

After capability work, record an audit via `POST /v1/features/capabilities/{id}/audit` (needs `facts:write` or `admin:write`). Capability seed JSON still lives at `PlanCrux/tools/feature-registry/capabilities/*.json`; the PlanCrux repo remains the ExecPlan and docs home.
