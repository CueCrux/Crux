# Compaction-survival preset (Claude Code)

When Claude Code **compacts** a long conversation it replaces the transcript
with a summary. That summary routinely drops the things you care about most:
the open todo list, the set of files you were mid-edit in, and the last plan
you agreed on ("fix `auth.ts`, do **not** touch `billing.ts`"). The next turn
the agent no longer knows the guard-rail — and edits `billing.ts`.

This preset closes that gap with two hooks and no dependencies beyond `jq`:

| Hook | Claude Code event | What it does |
|---|---|---|
| `snapshot.sh` | **PreCompact** (`manual` + `auto`) | Parses the live transcript, writes open todos + files-in-play + latest notes to `~/.claude/compaction-snapshots/<session_id>.md`. |
| `restore.sh` | **SessionStart** (`source=compact`/`resume`) | Reads that snapshot back and returns it as `hookSpecificOutput.additionalContext`, so the model re-reads the working state compaction erased. |

Both hooks are fire-and-forget: every code path exits `0` and never emits
`{"decision":"block"}`, so a broken hook, a missing `jq`, or a foreign payload
can never block compaction.

## Verified hook contract (2026-07-17, <https://code.claude.com/docs/en/hooks>)

- **PreCompact** input (stdin JSON): `session_id`, `transcript_path`, `cwd`,
  `permission_mode`, `hook_event_name`, `trigger` (`"manual"`|`"auto"`),
  `custom_instructions` (string; empty on auto). Matcher matches the trigger.
  Exit 2 / `{"decision":"block"}` blocks compaction — we never do that.
- **SessionStart** input: `session_id`, `transcript_path`, `cwd`,
  `hook_event_name`, `source` ∈ `startup|resume|clear|compact`. Output:
  plain stdout is added to context, **or** JSON
  `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"…"}}`.
  `source=compact` is the event that fires immediately after compaction — this
  is our restore trigger.
- **PostCompact** exists but only shows stderr to the user; it *cannot* inject
  context, so restoration goes through `SessionStart(source=compact)` instead.

## Install

```bash
# 1. Put the scripts somewhere stable and make them executable.
install -D -m 0755 snapshot.sh /usr/local/share/crux/integrations/claude-code/compaction-survival/snapshot.sh
install -D -m 0755 restore.sh  /usr/local/share/crux/integrations/claude-code/compaction-survival/restore.sh

# 2. Merge settings.snippet.json into ~/.claude/settings.json (per-event if you
#    already have a hooks block), fixing the command paths to match step 1.

# 3. Restart Claude Code. Next compaction snapshots; next start after it restores.
```

## Prove it works

```bash
./proof.sh
```

Assert-based; runs the whole loss-without vs survival-with cycle against a
fixture transcript and exits non-zero if any step regresses.

## Tunables (env)

| Variable | Default | Purpose |
|---|---|---|
| `CRUX_COMPACTION_SNAPSHOT_DIR` | `~/.claude/compaction-snapshots` | Where snapshots + the event log live. |
| `CRUX_COMPACTION_LOG` | `$SNAP_DIR/compaction.log` | Tab-separated snapshot/restore log (feeds the kit's proof-report). |

## Licence

Part of the Crux repo — CueCrux Community Licence (CCL v1.0), source-available.
The same capability is also available as a standalone **MIT** proof-of-loss
mini-repo (the shareable demo) and, packaged with a one-command dual-agent
installer, as the **$9 Compaction Survival Kit** (see `../kit/`). The capability
itself is free here forever — the kit sells the packaging, not the capability.
