+++
name = "memory-practices"
version = 1
description = "Crux daemon memory + retrieval discipline."
targets = ["claude_md", "agents_md"]
order = 10
risk_class = "low"
+++

## Crux Daemon Memory Practices

### Session boot (once per session)

Before any non-trivial work, in this order:

1. `sync_status()` — if mode is `local_only` or `degraded`, stay on the local store and skip cross-agent handoffs.
2. `update_status()` — if `behind`, pull `get_bootstrap(topic="docs", query="upgrade")` before touching deploys. If `ahead` or `diverged`, stop and escalate.
3. `get_bootstrap(topic="patterns")` on cold start to load current playbooks (token_budget=500).

Skip these only for trivial single-file edits.

### Two non-negotiable rules

- **`token_budget` is mandatory on every retrieval call.** Defaults: 500 for confirmations, 2000 for scans, 4000 for design pulls. The primary defence against output-token blowouts (Insights report friction #1, 9 sessions blocked).
- **Chat is for state transitions; durable content goes to `store_fact` or files.** Per-message chat output is limited to: (1) what changed, (2) gate result, (3) next milestone or escalation. ExecPlans, audit tables, benchmark results, and milestone summaries are written to files and referenced by path.

### Fact-storage conventions

When calling `store_fact`, use these entity prefixes and required keys — this keeps `query_facts` recall consistent across sessions.

- `entity="execplan:<slug>"` — keys: `decision:<topic>`, `milestone:M<n>`, `gate:M<n>`. Decision values must include `commit_sha`.
- `entity="bench:<id>"` — value object requires `{metric, value, corpus, lane_flags, commit_sha, run_id}`. `corpus` is mandatory.
- `entity="incident:<YYYY-MM-DD>"` — value requires `{symptom, cause, fix_sha, repro_steps}`.
- `entity="design:<slug>"` — for architectural notes; links to file path under `PlanCrux/.agent/execplans/<slug>.design.md`.

### Don'ts

- Do not call retrieval tools without `token_budget`.
- Do not put `store_fact` behind PostToolUse hooks — facts must be deliberate, not reflexive (volume dilutes recall).
- Do not migrate `MEMORY.md` content wholesale into Crux facts — they serve different audiences. Link via `store_fact(... value={memory_md_ref: "<slug>.md"})`.
- Do not skip `sync_status()` before remote integration work — operating on a `degraded` node and assuming sync produces silent contradictions.
