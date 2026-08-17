+++
name = "memory-practices"
version = 3
description = "Crux daemon memory + retrieval discipline. v3 adds the tool-routing block: three signals (the [tier:local] marker, sync_status local_only, and a stale 'unreachable' boot banner) were each being misread as 'the MCP tools cannot reach the daemon', causing agents to hand-roll curl against /v1/facts to reach a host the tools were already connected to. States what each signal actually means and the rule that one call settles it. v2 collapsed the four competing session-boot rituals that were spread across this profile, execplan-discipline, and workspace-cuecrux into one ordered block, and dropped the token_budget mandate and fact-storage entity conventions now that both are carried by the MCP tool schemas themselves (crux-mcp/src/tools/mod.rs), where the model reads them at call time instead of once at session start. Historical driver: the Insights report's friction #1, nine sessions blocked on output-token exhaustion."
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

### The MCP tools already reach the right daemon

Three signals get misread as "the daemon is unreachable, so write around it". They mean different things,
and none of them means the MCP tools are the wrong path:

| Signal | What it actually means |
|---|---|
| `[tier:local]` on a tool | **Entitlement tier** — callable on a free/local install. Not a claim about where data is stored. |
| `sync_status: local_only` | **Remote fact mirroring** is unconfigured. Unrelated to whether the client can reach a daemon. |
| Boot banner `unreachable` | **This session's MCP binding**, which can be stale. Probe `/readyz` before believing it. |

Every tool executes against whichever daemon the MCP client is configured to talk to, which is frequently
a remote host. So: **call the tool, and fall back to raw HTTP only on an actual failure.** Do not
hand-roll `curl` against `/v1/facts` because a marker or a banner implied the tool would not get there —
verifying costs one call, and inferring costs a rewrite.

### Don'ts

- Do not put `store_fact` behind PostToolUse hooks — facts must be deliberate. Volume dilutes recall.
- Do not migrate `MEMORY.md` wholesale into facts; link via `value={memory_md_ref: "<slug>.md"}`.
- Do not skip `sync_status()` before remote integration work: assuming sync on a `degraded` node
  produces silent contradictions.
- Do not conclude a tool is unavailable from its description or the banner. One call settles it.

> Retrieval budgets and `store_fact` entity conventions live on the tools — read the `token_budget` and
> `entity` field descriptions in the MCP schema rather than restating them here.
