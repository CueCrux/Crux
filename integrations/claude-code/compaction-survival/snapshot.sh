#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# crux-compaction-snapshot — Claude Code PreCompact hook.
#
# Fires right before Claude Code compacts (summarizes) the conversation —
# manual /compact or automatic. Compaction is lossy: open todos, the set of
# files you were working in, and your latest plan get flattened into a summary
# and often silently dropped. This hook snapshots that working state to a
# durable file so the companion restore.sh (a SessionStart hook) can re-inject
# it after compaction as additionalContext.
#
# PreCompact input contract (verified 2026-07-17,
# https://code.claude.com/docs/en/hooks):
#   { session_id, transcript_path, cwd, hook_event_name:"PreCompact",
#     trigger:"manual"|"auto", custom_instructions:string }
#
# NEVER blocks compaction: every path exits 0 and no {"decision":"block"} is
# emitted. Foreign payloads (e.g. Codex, which has no PreCompact event) still
# produce a minimal, safe snapshot rather than erroring.
#
# Tunables (env):
#   CRUX_COMPACTION_SNAPSHOT_DIR  (default ~/.claude/compaction-snapshots)
#   CRUX_COMPACTION_LOG           (default $SNAP_DIR/compaction.log)
set -uo pipefail

SNAP_DIR="${CRUX_COMPACTION_SNAPSHOT_DIR:-$HOME/.claude/compaction-snapshots}"
LOG="${CRUX_COMPACTION_LOG:-$SNAP_DIR/compaction.log}"
mkdir -p "$SNAP_DIR" 2>/dev/null || true

command -v jq >/dev/null 2>&1 || exit 0   # jq absent: no-op, never block compaction

payload="$(cat 2>/dev/null || true)"
jqget() { printf '%s' "$payload" | jq -r "$1 // empty" 2>/dev/null; }

session_id="$(jqget '.session_id')"
transcript="$(jqget '.transcript_path')"
cwd="$(jqget '.cwd')"
trigger="$(jqget '.trigger')"
custom="$(jqget '.custom_instructions')"
transcript="${transcript/#\~/$HOME}"          # transcript_path may be ~-prefixed
[ -n "$session_id" ] || session_id="unknown-$(date +%s)"
snap="$SNAP_DIR/${session_id}.md"

# ---- extract the working state from the Claude Code transcript (JSONL) --------
# Absent path or foreign (non-CC) format => these stay empty; snapshot still writes.
# ponytail: jq scans the transcript line-by-line (JSONL default), no slurp — fine
# for multi-MB transcripts; switch to --stream only if they reach 100s of MB.
todos=""; files=""; notes=""
if [ -n "$transcript" ] && [ -f "$transcript" ]; then
  todos="$(jq -c 'try (.message.content[]? | select(.type=="tool_use" and .name=="TodoWrite") | .input.todos) // empty' "$transcript" 2>/dev/null | tail -1)"
  files="$(jq -r 'try (.message.content[]? | select(.type=="tool_use" and (.name=="Read" or .name=="Edit" or .name=="Write" or .name=="MultiEdit" or .name=="NotebookEdit")) | .input.file_path) // empty' "$transcript" 2>/dev/null | awk 'NF' | sort -u)"
  notes="$(jq -r 'try (select(.type=="assistant") | .message.content[]? | select(.type=="text") | .text) // empty' "$transcript" 2>/dev/null | awk 'NF' | tail -30)"
fi

# ---- render the snapshot ------------------------------------------------------
{
  echo "# Compaction snapshot"
  echo
  echo "- session: \`$session_id\`"
  echo "- cwd: \`${cwd:-?}\`"
  echo "- captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)  (trigger: ${trigger:-?})"
  [ -n "$custom" ] && echo "- /compact instructions: $custom"
  echo
  echo "## Open todos (at compaction)"
  if [ -n "$todos" ]; then
    printf '%s' "$todos" | jq -r '.[] | "- [\(.status // "?")] \(.content // .activeForm // "?")"' 2>/dev/null
  else
    echo "_none captured_"
  fi
  echo
  echo "## Files in play"
  if [ -n "$files" ]; then printf '%s\n' "$files" | sed 's/^/- /'; else echo "_none captured_"; fi
  echo
  echo "## Latest notes (verbatim tail of assistant reasoning)"
  echo
  if [ -n "$notes" ]; then printf '%s\n' "$notes"; else echo "_none captured_"; fi
} > "$snap" 2>/dev/null || true

# ---- append to the log the proof-report generator reads -----------------------
n_files="$(printf '%s' "$files" | grep -c . 2>/dev/null || echo 0)"
n_todos="$(printf '%s' "$todos" | jq 'length' 2>/dev/null || echo 0)"
printf '%s\tsnapshot\t%s\ttrigger=%s files=%s todos=%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$session_id" "${trigger:-?}" "$n_files" "$n_todos" \
  >> "$LOG" 2>/dev/null || true

exit 0
