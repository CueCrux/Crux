+++
name = "memory-practices"
version = 2
description = "Crux daemon memory + retrieval discipline. v2 collapses the four competing session-boot rituals that were spread across this profile, execplan-discipline, and workspace-cuecrux into one ordered block, and drops the token_budget mandate and fact-storage entity conventions now that both are carried by the MCP tool schemas themselves (crux-mcp/src/tools/mod.rs), where the model reads them at call time instead of once at session start. Historical driver: the Insights report's friction #1, nine sessions blocked on output-token exhaustion."
targets = ["claude_md", "agents_md"]
order = 10
risk_class = "low"
+++

## Crux Daemon Memory Practices

### Session boot

This is the **only** boot sequence — run it once, in order, before non-trivial work; skip it for
trivial single-file edits. Later sections reference these steps; none of them start a second sequence.

1. `sync_status()` — on `local_only` or `degraded`, stay local and skip cross-agent handoffs.
2. `update_status()` — if `behind`, pull `get_bootstrap(topic="docs", query="upgrade")` before touching
   deploys; if `ahead` or `diverged`, stop and escalate.
3. `get_bootstrap(topic="patterns")` on a cold start.
4. `list_work(source="all")` — the work table is true north for what to pick up.
5. If sessions may be live in this tree, read the banner's live-sessions block or call `coord_status`
   before claiming paths.

### Chat is for state transitions

Durable content goes to `store_fact` or to files. Chat carries what changed, the gate result, and the
next milestone or escalation. ExecPlans, audit tables, and benchmark results are written and referenced
by path.

### Don'ts

- Do not put `store_fact` behind PostToolUse hooks — facts must be deliberate. Volume dilutes recall.
- Do not migrate `MEMORY.md` wholesale into facts; link via `value={memory_md_ref: "<slug>.md"}`.
- Do not skip `sync_status()` before remote integration work: assuming sync on a `degraded` node
  produces silent contradictions.

> Retrieval budgets and `store_fact` entity conventions live on the tools — read the `token_budget` and
> `entity` field descriptions in the MCP schema rather than restating them here.
