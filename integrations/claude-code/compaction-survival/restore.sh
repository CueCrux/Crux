#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# crux-compaction-restore — Claude Code SessionStart hook.
#
# After a compaction the session restarts with source="compact". This hook
# reads the snapshot that snapshot.sh wrote (keyed by session_id — preserved
# across compaction) and returns it as additionalContext, so the model recovers
# the open todos / files-in-play / plan that compaction summarized away.
#
# SessionStart output contract (verified 2026-07-17,
# https://code.claude.com/docs/en/hooks): stdout JSON of the form
#   {"hookSpecificOutput":{"hookEventName":"SessionStart",
#                          "additionalContext":"<string added to context>"}}
# source values: startup | resume | clear | compact. We restore only on
# compact/resume (nothing to recover on a fresh startup/clear).
#
# NEVER blocks: every path exits 0.
set -uo pipefail

SNAP_DIR="${CRUX_COMPACTION_SNAPSHOT_DIR:-$HOME/.claude/compaction-snapshots}"
LOG="${CRUX_COMPACTION_LOG:-$SNAP_DIR/compaction.log}"

command -v jq >/dev/null 2>&1 || exit 0

payload="$(cat 2>/dev/null || true)"
jqget() { printf '%s' "$payload" | jq -r "$1 // empty" 2>/dev/null; }
source_ev="$(jqget '.source')"
session_id="$(jqget '.session_id')"

case "$source_ev" in
  compact|resume) ;;                 # recover
  *) exit 0 ;;                       # startup/clear/unknown: nothing to restore
esac

snap="$SNAP_DIR/${session_id}.md"
# ponytail: session_id is stable across compaction so the exact match hits; the
# newest-snapshot fallback only matters if the id ever rotates. Guarded to
# compact|resume so it can't leak an unrelated snapshot into a fresh session.
if [ ! -f "$snap" ]; then
  snap="$(ls -t "$SNAP_DIR"/*.md 2>/dev/null | head -1)"
fi
[ -n "${snap:-}" ] && [ -f "$snap" ] || exit 0

jq -Rs --arg hdr "Recovered pre-compaction working state (compaction-survival preset). Compaction summarized the conversation; this is what was in flight beforehand:" \
  '{hookSpecificOutput:{hookEventName:"SessionStart",additionalContext:($hdr+"\n\n"+.)}}' \
  < "$snap" 2>/dev/null || true

printf '%s\trestore\t%s\tsource=%s snap=%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$session_id" "$source_ev" "$snap" >> "$LOG" 2>/dev/null || true
exit 0
