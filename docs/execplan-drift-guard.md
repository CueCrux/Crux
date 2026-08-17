# ExecPlan board-drift guard

Keeps a plan's `Status:` line from lagging its derived state — the case where stored facts say a plan
is done but the markdown still reads `Status: In progress`, so the work board shows stale work.

Everything here is **advisory**. Both scripts print; neither mutates a plan nor blocks real work.

> Agent-facing summary lives in the `execplan-discipline` wizard profile (rendered into `CLAUDE.md` /
> `AGENTS.md`). This document is the operator reference: install, wiring, and semantics. Keep the
> profile short — it is loaded into every session; this file is read when someone is actually wiring
> the guard up.

## Install

```bash
bash scripts/setup-drift-guard.sh              # install + print config snippets
bash scripts/setup-drift-guard.sh --print-only # print snippets, install nothing
bash scripts/setup-drift-guard.sh --self-test
```

The installer copies both scripts into `${XDG_DATA_HOME:-$HOME/.local/share}/crux/hooks/` so agent
configs can point at a stable path that survives repo moves, then **prints** the JSON to merge into
your agent config. It deliberately never edits agent configs itself: merging into an existing `hooks`
map depends on what else is wired there, and a bad merge is worse than a copy-paste.

## The two layers

### 1. Write-time guard — `execplan-status-guard.sh`

Runs as a **PostToolUse** hook on `store_fact`. When you store a plan-terminal fact — `decision:close*`,
or a `gate:*` marked plan-complete — while the plan's leading `Status:` token is still non-terminal, it
exits 2 and prompts you to flip the line while you still have the context.

**Only the leading token counts.** `Status: In progress (design complete)` is non-terminal: the
parenthetical does not make it done.

| Agent | Config file | Hook | Matcher |
|---|---|---|---|
| Claude Code | `.claude/settings.json` | `hooks.PostToolUse` | `mcp__crux__store_fact` |
| codex | `.codex/hooks.json` | `hooks.PostToolUse` | `store_fact` |

### 2. Boot sweep — `reconcile-execplan-status.sh`

Run `reconcile-execplan-status.sh --quiet` on **SessionStart** in both agents. It `GET`s
`/v1/work?source=all` and, for every `execplan:*` whose derived state is terminal while its leading
`Status:` token is not, prints one compact line naming the plans to flip.

- Silent when clean.
- Exits 0 and skips gracefully when the daemon is unreachable, so it never blocks a session start.
- Set `CRUX_EXECPLANS_ROOT` so it can resolve `<slug>.md` from a work-item id.

## Related

`scripts/reconcile-execplan-sessions.sh` is a **separate** detector covering a different drift class:
orphan sessions (a registry entry with no `.md`) and unparseable plans. It also prints without
mutating. See the `workspace-cuecrux` profile.

## Keeping the daemon's replica current

The drift guard above compares a plan's `Status:` line against derived state. It
can only compare what the daemon can *see*, and what it sees is its own replica
of `*.md` — `/v1/work` walks `CRUX_EXECPLANS_ROOT` on every request and
re-projects. Nothing is pushed to it when you edit a plan.

So there are two distinct failure modes, and they look identical from the board:

| symptom | cause |
|---|---|
| plan's state is wrong | its `Status:` line drifted — the guard above catches this |
| plan is **absent** | the replica never received the file |

The second is the quiet one. A plan can be committed, pushed, and correct, and
still be invisible because the daemon's copy predates it — no error anywhere.

### If the deployment has git backing

Set `CRUX_EXECPLANS_GIT_REMOTE` (+ `_BRANCH`, `_INTERVAL_SECS`, `_CHECKOUT`) and
the replica maintains itself; `POST /v1/execplans/refresh` pulls on demand. Note
`_CHECKOUT` is **the repository**, while the projection root is normally
`<checkout>/.agent/execplans` — a mismatch is silent, and shows up only as an
empty board.

### If it does not

`POST /v1/execplans/refresh` returns **409** — "git backing is not configured",
which is deliberately distinct from a pull that ran and failed. The replica is
then whatever was last copied there, and it ages silently.

Use `scripts/sync-execplans-replica.sh` (`--dry-run` to preview). Run it after
merging plan changes; the board re-projects on the next read, no restart.

Measured on host `crux`: the replica went **four days stale and lost nine
plans**, one of them complete, before anyone noticed — and eighteen hours later
another ten files had changed. Treat a manual replica as a thing that stops
happening, and prefer git backing wherever a credential allows it.
