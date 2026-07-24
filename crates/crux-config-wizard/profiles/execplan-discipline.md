+++
name = "execplan-discipline"
version = 2
description = "Multi-milestone work goes through an ExecPlan first. Codifies the Insights-report `ExecPlan Workflow` snippet (M1..Mn pattern in 15+ sessions), plus the board-drift guard that keeps plan `Status:` lines aligned with derived state."
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
- Test + commit per milestone. Don't batch milestones into one commit.
- When the plan's assumptions change mid-flight, record the reason in `Decision Log` first, then act.

### Risk class on every plan

Each ExecPlan declares a risk class (`low | medium | high`) in its Purpose section. High-risk plans (prod deploys, data deletion, multi-tenant changes) require human gate approval per the `eu-ai-act` profile.

### Pre-flight

Before writing the plan, call `get_gaps(query="<area>")` on the Feature Registry endpoint and note any critical/high gaps in the plan's `Risk` or `Decision Log`.

### Work table is true north

On session boot, before picking up a new task or proposing one, call `mcp__crux__list_work(source="all")`. The response merges the kanban `work_items` table with the read-time projection over `*/.agent/execplans/*.md` (per ExecPlan `crux-work-panel-execplans-as-truenorth-2026-05-26`).

- Treat unfinished entries (state in `{planned, in_progress, blocked}`) as the prioritized task set.
- If the user's request matches an in_progress plan's next milestone, resume it — do not start a parallel plan.
- A `blocked` entry with a `blocker_reason` is a question to surface to the operator, not a task to start.
- ExecPlan items (id prefix `execplan:`) have a `plan_path` field — open it before guessing what the plan is about.
- The `current_milestone` field on an ExecPlan item tells you where the previous session left off. Read the corresponding `gate:M<n-1>` fact for context.

Do not invent work that already exists in the table; do not let the table go stale by completing work without storing a `gate:M<n>` fact.

### Board-drift guard

Three layers keep a plan's `Status:` line from lagging its derived state (facts say "done", markdown still reads "In progress"). Install on a new machine with `bash scripts/setup-drift-guard.sh` in the Crux repo — it copies the scripts to `~/.local/share/crux/hooks/` and prints the config snippets below (it never edits your agent configs).

- **Write-time guard** — `execplan-status-guard.sh` runs as a `store_fact` **PostToolUse** hook. When you store a plan-terminal fact (`decision:close*`, or a `gate:*` marked plan-complete) but the plan's leading `Status:` token is still non-terminal, it exits 2 and nags you to flip the line while you have context. Only the *leading* token counts: `Status: In progress (design complete)` is non-terminal.
  - Claude Code `.claude/settings.json` → `hooks.PostToolUse` matcher `mcp__crux__store_fact`.
  - codex `.codex/hooks.json` → `hooks.PostToolUse` matcher `store_fact`.
- **Boot sweep** — run `reconcile-execplan-status.sh --quiet` on **SessionStart** (both agents). It GETs `/v1/work?source=all`, and for every `execplan:*` whose derived state is terminal but whose leading `Status:` token isn't, prints one compact line naming the plans to flip. Silent when clean; graceful skip (exit 0) if the daemon is down. Set `CRUX_EXECPLANS_ROOT` so it can resolve `<slug>.md`.

Both hook scripts are print-only / advisory — they never mutate a plan or block real work.
