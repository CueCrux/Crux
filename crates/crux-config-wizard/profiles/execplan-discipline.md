+++
name = "execplan-discipline"
version = 5
description = "Multi-milestone work goes through an ExecPlan first. Codifies the Insights-report `ExecPlan Workflow` snippet (M1..Mn pattern in 15+ sessions), plus the board-drift guard that keeps plan `Status:` lines aligned with derived state. v5 closes the propagation gap the gate routine never named: the board is a read-time projection over the daemon's replica, so a locally-committed plan is invisible until it is pushed and refreshed — and an *untracked* plan can be silently destroyed by a sibling session's checkout, which is how one closed plan was lost on 2026-07-31. Adds the push + `POST /v1/execplans/refresh` step and a commit-on-create rule. v4 corrects the Pre-flight step: it pointed at `get_gaps(query=...)`, which reads retrieval-coverage facts rather than the capability registry, and at a Feature Registry endpoint that moved into the Crux daemon when the PlanCrux API was retired 2026-07-24."
targets = ["claude_md", "agents_md"]
order = 30
risk_class = "low"
+++

## ExecPlan Workflow

### When to use one

If the task is more than a small, single-file change (multi-module edits, schema/API changes, refactors, new features, anything likely to take >30 minutes), switch to plan mode and create or update an ExecPlan before implementing.

Trivial fixes and one-shot edits don't need a plan.

### Where plans live

Default: `./.agent/execplans/<slug>.md` at the workspace root. Create the directory on first use.

Required sections in each plan: Purpose, Non-goals, Context, Constraints, Proposed design, Milestones, Test plan, Rollout/rollback, Risks, Progress, Decision log.

### Execution rules

- Proceed milestone-by-milestone. Don't stop to ask "what next" if the next milestone is clear from the plan.
- After every milestone:
  - Update the plan's `Progress` checklist inline.
  - Update the `Decision Log` with any non-trivial choice + commit_sha.
  - `store_fact(entity="execplan:<slug>", key="gate:M<n>", value={status, date, commit_sha, tests_passing, ...})`.
  - **Commit and push the plan file**, then `POST /v1/execplans/refresh`. The work board is a
    *read-time* projection over the daemon's replica of `*.md` — nothing is pushed to it, so a plan
    that is only committed locally is invisible to every other session. Refresh collapses the wait
    for the periodic pull; `409` means git backing is not configured, which is a different problem
    from a failed pull. Agents with no checkout author via `POST /v1/execplans` instead.
- Test + commit per milestone. Don't batch milestones into one commit.
- **Never leave a plan file untracked.** An untracked plan lives only in one working tree: a sibling
  session's `git checkout` takes it away, and the loss is silent because the board projects over the
  daemon's replica, not yours. Commit the file the moment you create it, not when the plan closes.
- When the plan's assumptions change mid-flight, record the reason in `Decision Log` first, then act.

### Risk class on every plan

Each ExecPlan declares a risk class (`low | medium | high`) in its Purpose section. High-risk plans (prod deploys, data deletion, multi-tenant changes) require human gate approval per the `eu-ai-act` profile.

### Pre-flight

Before writing the plan, pull capability gaps from the Crux daemon's Features lens and note any critical/high ones in the plan's `Risks` or `Decision log`:

```bash
source ~/.config/cuecrux/env   # CRUX_HTTP_URL + CRUX_AGENT_TOKEN
curl -s -H "Authorization: Bearer $CRUX_AGENT_TOKEN" "$CRUX_HTTP_URL/v1/features/capabilities/analysis/gaps"
```

Needs scope `facts:read` or `admin:read`; unauthenticated calls return 401. Local dev: run `corecruxd` with `CORECRUXD_AUTH_MODE=dev_scopes` and send `X-Corecrux-Scopes: facts:read`.

The MCP tool `get_gaps` is **not** this — it reads retrieval-coverage facts (`__ops__::coverage`), not capabilities. The MCP equivalent is `feature_suggest_next({limit})`, currently hidden from `tools/list` by RCX capability filtering, so prefer HTTP.

### Work table is true north

`list_work(source="all")` — step 4 of the single boot sequence, not a second boot — merges the kanban `work_items` table with the read-time projection over `*/.agent/execplans/*.md` (per ExecPlan `crux-work-panel-execplans-as-truenorth-2026-05-26`). Consult it before picking up a new task or proposing one.

- Treat unfinished entries (state in `{planned, in_progress, blocked}`) as the prioritized task set.
- If the user's request matches an in_progress plan's next milestone, resume it — do not start a parallel plan.
- A `blocked` entry with a `blocker_reason` is a question to surface to the operator, not a task to start.
- ExecPlan items (id prefix `execplan:`) have a `plan_path` field — open it before guessing what the plan is about.
- The `current_milestone` field on an ExecPlan item tells you where the previous session left off. Read the corresponding `gate:M<n-1>` fact for context.

Do not invent work that already exists in the table; do not let the table go stale by completing work without storing a `gate:M<n>` fact.

### Board-drift guard

If wired, a `store_fact` PostToolUse hook exits 2 and prompts you when you store a plan-terminal fact (`decision:close*`, or a `gate:*` marked plan-complete) while the plan's leading `Status:` token is still non-terminal — flip the line while you have the context. Only the **leading** token counts, so `Status: In progress (design complete)` is non-terminal. A SessionStart sweep names any plans whose derived state has outrun their `Status:` line. Both are advisory: they print, never mutate or block.

Install, wiring, and semantics: `bash scripts/setup-drift-guard.sh` (prints the config snippets; never edits your agent configs) and `docs/execplan-drift-guard.md`.
