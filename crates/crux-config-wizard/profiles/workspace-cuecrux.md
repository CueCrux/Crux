+++
name = "workspace-cuecrux"
version = 2
description = "CueCrux workspace specifics: ExecPlan paths, daemon ports, Chainguard rule, JobClaw/MirrorClaw, three-place wiring. CueCrux-internal — only enable inside the CueCrux planning monorepo."
targets = ["claude_md", "agents_md"]
order = 90
risk_class = "low"
+++

## CueCrux Workspace

> **Scope.** This profile encodes paths and tools (`PlanCrux/`, `AuditCrux/benchmarks/`) that exist inside the CueCrux planning monorepo. Operators outside the CueCrux workspace should not enable this profile — the cross-references will not resolve. Use the generic profiles (`memory-practices`, `execplan-discipline`, `eu-ai-act`, etc.) instead.

### ExecPlan location

- Preferred path: `PlanCrux/.agent/execplans/<slug>.md`.
- Format defined in `PlanCrux/.agent/PLANS.md` (Purpose, Non-goals, Context, Constraints, Proposed design, Milestones, Test plan, Rollout/rollback, Risks, Progress, Decision log).

### PlanCrux read-once boot

On the first interaction of a session, read `PlanCrux/README.md` and `PlanCrux/buildguide.md` once. Retain key goals, definitions, canonical flows, constraints, and Do/Don't lists as working context. Re-read only when:

- The user explicitly asks to refresh.
- You detect a version change (`PlanCrux/README.version` or front-matter, or last-modified timestamp).
- You need an exact quote or precise detail that is missing from your cached context.

### Crux Daemon endpoints

- HTTP API: `127.0.0.1:14800` (or configured).
- MCP server: `127.0.0.1:14801`.
- gRPC: `127.0.0.1:4007`.
- Do not change these defaults; see `Crux/CLAUDE.md` "Port 14800" rule.

### ExecPlan Work board

`GET /v1/work?source=all` (and the equivalent `mcp__crux__list_work(source="all")`) returns kanban work items **merged with** a read-time projection over `PlanCrux/.agent/execplans/*.md`. Aggregator is enabled when `CRUX_EXECPLANS_ROOT` is set in the daemon process env (typically `/srv/<workspace>/PlanCrux/.agent/execplans`).

- ExecPlan items carry id prefix `execplan:<slug>`, virtual `project_id = "execplans"`, and extension fields `plan_path`, `current_milestone`, `superseded_by`.
- State is derived from facts (`milestone:M<n>`, `gate:M<n>`) plus `Status:` / `Superseded by` lines in the markdown — see `Crux/crates/corecruxd/src/work_execplans.rs` `derive_state`.
- The console SPA exposes a `Source: All | Kanban | ExecPlans` chip group; selection persists in `localStorage`.
- Drift detector: `bash Crux/scripts/reconcile-execplan-sessions.sh` lists orphan sessions (registry entry, no `.md`) and unparseable plans. Prints, does not mutate.

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

The PlanCrux API serves a Feature Registry on port 3334 (`pnpm dev:api`). After the M5 cutover in `crux-domain-substrate-and-features-lens-2026-05-18`, the same surface is also available at `http://<crux-host>:14800/v1/features/capabilities/*`. Prefer Crux endpoints for new clients; legacy clients hit the proxy on PlanCrux side.

Key endpoints (PlanCrux): `GET /capabilities` (list/filter), `GET /capabilities/analysis/gaps` (gap analysis), `GET /capabilities/analysis/promises`, `GET /capabilities/analysis/coverage`.

After capability work, record an audit via `POST /capabilities/:id/audit` (PlanCrux) or `POST /v1/features/capabilities/:id/audit` (Crux post-cutover).
