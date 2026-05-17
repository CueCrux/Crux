# crux-claude-hooks

Claude Code lifecycle hook binaries for the Crux Daemon.

Three subcommands under a single `crux-hook` binary, each fired by the Claude
Code harness at a specific lifecycle event. Best-effort and non-blocking: a
missing or unreachable daemon never blocks tool execution.

## Subcommands

| Subcommand | Hook event | Purpose |
|---|---|---|
| `context-monitor` | `PostToolUse` | Read-only loop / file-scope warnings. Surfaces inline via `additionalContext`. **Never writes facts** (CueCrux/CLAUDE.md §11.2). |
| `pre-compact` | `PreCompact` | Snapshots session state to the Crux daemon via MCP `save_session` before harness compaction. |
| `session-start` | `SessionStart` | Automates the §11.1 session-boot ritual: `sync_status` + `get_bootstrap("patterns")` with `token_budget=500`. Injects result as `additionalContext`. |

## Build

```bash
cd /home/myles/CueCrux/Crux
cargo build --release -p crux-claude-hooks
# Binary at: target/release/crux-hook
```

## Install (project-local)

Add to `.claude/settings.local.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/Crux/target/release/crux-hook context-monitor",
            "timeout": 5
          }
        ]
      }
    ],
    "PreCompact": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/Crux/target/release/crux-hook pre-compact",
            "timeout": 5
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/Crux/target/release/crux-hook session-start",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `CRUX_MCP_URL` | `http://127.0.0.1:14801/mcp` | Crux MCP endpoint. |
| `CRUX_HOOK_CONTEXT_MONITOR` | (unset) | Set to `off` to disable PostToolUse warnings. |
| `CRUX_HOOK_PRE_COMPACT` | (unset) | Set to `off` to disable PreCompact snapshots. |
| `CRUX_HOOK_SESSION_START` | (unset) | Set to `off` to disable SessionStart bootstrap. |

## Heuristics (context-monitor)

- **Loop detection**: warns when the last 3 `PostToolUse` events have the
  same `(tool_name, hash(tool_input))` signature. Critical-severity — bypasses
  debounce.
- **File scope**: warns once when more than 20 distinct files have been
  touched by `Edit` / `Write` / `NotebookEdit` in the session.
- **Debounce**: non-critical warnings fire at most once per 5 PostToolUse
  events.

Tunable constants live in [`src/state.rs`](src/state.rs):
`LOOP_DETECTION_THRESHOLD`, `FILE_SCOPE_WARN_THRESHOLD`, `WARNING_DEBOUNCE_CALLS`.

## State

Per-session debounce / history is persisted to
`${TMPDIR:-/tmp}/crux-hook-state-{sanitised_session_id}.json`. Session-id
sanitisation strips anything that is not `[A-Za-z0-9_-]` and caps at 64 chars
to prevent path traversal.

## Disable

To turn off in the current workspace, either:
1. Set the relevant `CRUX_HOOK_*=off` env var, or
2. Remove the `"hooks"` block from `.claude/settings.local.json`.

## Design rationale

See the ExecPlan: [`PlanCrux/.agent/execplans/crux-claude-hooks-2026-05-17.md`](../../../PlanCrux/.agent/execplans/crux-claude-hooks-2026-05-17.md).

## Attribution

Lifecycle-hook design patterns inspired by
[`affaan-m/everything-claude-code`](https://github.com/affaan-m/everything-claude-code)
(MIT). Specifically: the PostToolUse anomaly-detection pattern from
`scripts/hooks/ecc-context-monitor.js`, and the `PreCompact` / `SessionStart`
snapshot-and-bootstrap pattern from `hooks/memory-persistence/`.

The Crux integration is original Rust and explicitly diverges from ECC where
the memory models differ: hooks **never** call `store_fact` (CueCrux/CLAUDE.md
§11.2), and `$ cost` / `context %` metrics are intentionally out of scope
because the Claude Code harness does not expose them to hook stdin.

## Licence

CueCrux Community Licence (CCL v1.0). See `/home/myles/CueCrux/Crux/LICENCE.md`.
