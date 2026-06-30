+++
name = "scratchpad-survival"
version = 1
description = "Durable work product must not live in the ephemeral session scratchpad (GC'd on close). Archive it before a handoff with crux-scratchpad-persist; a SessionEnd hook backstops it."
targets = ["claude_md", "agents_md"]
order = 45
risk_class = "low"
+++

## Scratchpad Survival

The agent harness forces temp files into a session-scoped scratchpad
(`/tmp/claude-<uid>/<cwd>/<session_id>/scratchpad/`) that is garbage-collected
when the session closes. `create_handoff` carries facts, not files, and the Crux
daemon is often on another host — so anything written to scratchpad is unreachable
from the next session unless it is archived locally first.

### Rule 1 — durable work product never lives in scratchpad

Scratchpad is for genuinely throwaway temp files only. Anything that must survive
the session — benchmark/harness results, A/B reports, generated datasets, anything
a handoff or a future ExecPlan-pickup session needs — goes to a durable path (e.g.
an ExecPlan's `.agent/artifacts/<slug>/`) or to `store_fact`.

### Rule 2 — before a handoff or ExecPlan spinout, persist the scratchpad

```bash
crux-scratchpad-persist --execplan <slug> [<session_id>]
```

Copies `scratchpad/` + background `tasks/` outputs to
`~/.crux/scratchpad-archive/<YYYY-MM-DD>-<session_id>/` (with a `MANIFEST.txt`),
then records the pointer fact `execplan:<slug>/scratchpad_archive` so the next
session reaches it via `query_facts`. On a daemon whose token cannot write the
`execplan:` category, it prints the exact `store_fact` call to emit via MCP with
your agent passport instead. Omit `--execplan <slug>` to archive without a fact.

### Rule 3 — automatic backstop (already wired by `corecruxctl hooks install`)

A `SessionEnd` hook archives any non-empty scratchpad on session close and prunes
archives older than 30 days. It is best-effort and **fact-free** (facts stay
deliberate) — a no-op if the harness GC's the dir first — so it is a safety net,
not a substitute for Rule 2 on a real handoff.

Tunables (env): `CRUX_SCRATCH_ARCHIVE_ROOT`, `CRUX_SCRATCH_RETENTION_DAYS` (30),
`CRUX_SCRATCH_MAX_MB` (512). To recover a past session, read
`~/.crux/scratchpad-archive/<dir>/MANIFEST.txt`.
