+++
name = "execplan-discipline"
version = 1
description = "Multi-milestone work goes through an ExecPlan first. Codifies the Insights-report `ExecPlan Workflow` snippet (M1..Mn pattern in 15+ sessions)."
targets = ["claude_md", "agents_md"]
order = 30
risk_class = "low"
+++

## ExecPlan Workflow

### When to use one

If the task is more than a small, single-file change (multi-module edits, schema/API changes, refactors, new features, anything likely to take >30 minutes), switch to plan mode and create or update an ExecPlan before implementing.

Trivial fixes and one-shot edits don't need a plan.

### Where plans live

Default: `PlanCrux/.agent/execplans/<slug>.md`.

Plans must follow `PlanCrux/.agent/PLANS.md` (required sections: Purpose, Non-goals, Context, Constraints, Proposed design, Milestones, Test plan, Rollout/rollback, Risks, Progress, Decision log).

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
