# Compaction-survival preset (Claude Code + Codex)

When an agent **compacts** a long conversation it replaces the transcript with a
summary. That summary routinely drops the things you care about most: the open
todo list, the set of files you were mid-edit in, and the last plan you agreed on
("fix `auth.ts`, do **not** touch `billing.ts`"). The next turn the agent no
longer knows the guard-rail — and edits `billing.ts`.

This preset closes that gap with two hooks and no dependencies beyond `jq`:

| Hook | Event | What it does |
|---|---|---|
| `snapshot.sh` | **PreCompact** (`manual` + `auto`) | Parses the live transcript, writes **active** todos + files-in-play + latest activity to `~/.claude/compaction-snapshots/<session_id>.md` (mode 0600). |
| `restore.sh` | **SessionStart** (`source=compact`/`resume`) | Reads that snapshot back (exact `session_id` match) and returns it as `hookSpecificOutput.additionalContext`, fenced as untrusted quoted data, so the model re-reads the working state compaction erased. |

Both hooks are fire-and-forget: every code path exits `0` and never emits a
block decision, so a broken hook, a missing `jq`, an unset `HOME`, or a foreign
payload can never block compaction.

## Verified hook contract (fetched 2026-07-17)

Claude Code: <https://code.claude.com/docs/en/hooks> · Codex: <https://learn.chatgpt.com/codex/hooks>

- **PreCompact** input (stdin JSON): `session_id`, `transcript_path`, `cwd`,
  `permission_mode`, `hook_event_name`, `trigger` (`"manual"`|`"auto"`),
  `custom_instructions` (string; empty on auto). Matcher matches the trigger.
  Exit 2 / a block decision blocks compaction — we never do that.
- **SessionStart** input: `…`, `source` ∈ `startup|resume|clear|compact`.
  Output: JSON
  `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"…"}}`.
  `source=compact` fires immediately after compaction — our restore trigger.
- **PostCompact** exists but only shows stderr; it *cannot* inject context, so
  restoration goes through `SessionStart(source=compact)`.
- **Codex** exposes the same PreCompact + SessionStart contract (PreCompact added
  in openai/codex PR #19905), so the same two hooks work there. Codex's transcript
  format is explicitly *not* a stable interface, so capture on Codex is
  best-effort (restore always works; the snapshotter never overwrites a good
  snapshot with an empty one).

## Security

- Snapshots may contain sensitive transcript excerpts. Written under `umask 077`
  (files 0600, dir 0700), via a same-dir temp + atomic rename.
- `session_id` is validated to `[A-Za-z0-9._-]` with no `..` — no path traversal.
- Restore is exact-`session_id` match only (no cross-session/newest-file
  fallback) and control-char-strips + fences the content as quoted historical
  data (prompt-injection hygiene).
- Snapshots auto-prune after `CRUX_COMPACTION_RETENTION_DAYS` (default 14);
  delete now with `rm -f ~/.claude/compaction-snapshots/*.md`.

## Install

```bash
# 1. Put the scripts somewhere stable and make them executable (portable — no GNU `install -D`).
DEST=/usr/local/share/crux/integrations/claude-code/compaction-survival
mkdir -p "$DEST"
install -m 0755 snapshot.sh restore.sh "$DEST"/

# 2. Merge settings.snippet.json into ~/.claude/settings.json — or ~/.codex/hooks.json
#    for Codex — (per-event if you already have a hooks block), fixing the command
#    paths to match step 1. Single-quote the path if it contains spaces.

# 3. Restart the agent. Next compaction snapshots; next start after it restores.
```

## Self-test

```bash
./selftest.sh
```

Assert-based fixture self-test (loss-without vs survival-with, plus the path-
traversal / empty-clobber / wrong-event guards). Not a signed proof — a local
check that the hooks behave. Exits non-zero if any step regresses.

## Tunables (env)

| Variable | Default | Purpose |
|---|---|---|
| `CRUX_COMPACTION_SNAPSHOT_DIR` | `~/.claude/compaction-snapshots` | Where snapshots + the event log live. |
| `CRUX_COMPACTION_LOG` | `$SNAP_DIR/compaction.log` | Tab-separated snapshot/restore log (feeds the kit's event report). |
| `CRUX_COMPACTION_CAP_LINES` | `4000` | Transcript-tail line cap per scan. |
| `CRUX_COMPACTION_RETENTION_DAYS` | `14` | Auto-prune snapshots older than this. |

## Licence

Part of the Crux repo — CueCrux Community Licence (CCL v1.0), source-available.
The same capability is also available as a standalone **MIT** proof-of-loss
mini-repo (the shareable demo) and, packaged with a one-command dual-agent
installer, as the **$9 Compaction Survival Kit** (see `../kit/`). The capability
itself is free here forever — the kit sells the packaging, not the capability.
