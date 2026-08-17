#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# crux-compaction-snapshot — PreCompact hook for Claude Code AND OpenAI Codex.
#
# Both agents fire PreCompact right before they compact (summarize) the
# conversation. Compaction is lossy: open todos, the files you were working in,
# and your latest plan get flattened into a summary and often dropped. This hook
# snapshots that working state so the companion restore.sh (a SessionStart hook)
# can re-inject it after compaction.
#
# PreCompact input contract (verified 2026-07-17):
#   Claude Code https://code.claude.com/docs/en/hooks
#   Codex       https://learn.chatgpt.com/codex/hooks  (PreCompact added in
#               openai/codex PR #19905; transcript format is NOT a stable
#               interface, so capture is best-effort on Codex).
#   { session_id, transcript_path, cwd, hook_event_name:"PreCompact",
#     trigger:"manual"|"auto", custom_instructions:string }
#
# Security / safety:
#   - umask 077: snapshots may hold sensitive transcript excerpts -> 0600.
#   - session_id is validated to a bounded charset (no path traversal).
#   - NEVER blocks compaction: always exits 0, never emits a block decision.
#   - NEVER overwrites a non-empty snapshot with an empty capture.
#
# Tunables (env): CRUX_COMPACTION_SNAPSHOT_DIR (~/.claude/compaction-snapshots),
#   CRUX_COMPACTION_LOG, CRUX_COMPACTION_CAP_LINES (4000),
#   CRUX_COMPACTION_RETENTION_DAYS (14).
umask 077
set -uo pipefail

HOME_DIR="${HOME:-/tmp}"
SNAP_DIR="${CRUX_COMPACTION_SNAPSHOT_DIR:-$HOME_DIR/.claude/compaction-snapshots}"
LOG="${CRUX_COMPACTION_LOG:-$SNAP_DIR/compaction.log}"
CAP_LINES="${CRUX_COMPACTION_CAP_LINES:-4000}"
RET_DAYS="${CRUX_COMPACTION_RETENTION_DAYS:-14}"

main() {
  command -v jq >/dev/null 2>&1 || return 0
  local payload; payload="$(cat 2>/dev/null || true)"
  printf '%s' "$payload" | jq -e 'type=="object"' >/dev/null 2>&1 || return 0

  local ev sid transcript cwd trigger custom
  ev="$(printf '%s' "$payload" | jq -r '.hook_event_name // empty' 2>/dev/null)"
  [ "$ev" = "PreCompact" ] || return 0
  sid="$(printf '%s' "$payload" | jq -r '.session_id // empty' 2>/dev/null)"
  case "$sid" in ""|*[!A-Za-z0-9._-]*|*..*) return 0 ;; esac   # bounded id, no traversal
  transcript="$(printf '%s' "$payload" | jq -r '.transcript_path // empty' 2>/dev/null)"
  transcript="${transcript/#\~/$HOME_DIR}"
  cwd="$(printf '%s' "$payload" | jq -r '.cwd // empty' 2>/dev/null)"
  trigger="$(printf '%s' "$payload" | jq -r '.trigger // empty' 2>/dev/null)"
  custom="$(printf '%s' "$payload" | jq -r '.custom_instructions // empty' 2>/dev/null)"

  mkdir -p "$SNAP_DIR" 2>/dev/null || return 0
  local snap="$SNAP_DIR/${sid}.md"

  # --- ONE bounded scan of the transcript tail (current state lives at the end).
  # ponytail: tail -n caps the scan line-safely; older lines are irrelevant.
  local stream=""
  if [ -n "$transcript" ] && [ -f "$transcript" ]; then
    stream="$(tail -n "$CAP_LINES" "$transcript" 2>/dev/null | jq -r '
        . as $m | ($m.message.content // []) | .[]?
        | if   (.type=="tool_use" and .name=="TodoWrite") then "TODO\t"+(.input.todos|tojson)
          elif (.type=="tool_use" and (.name=="Read" or .name=="Edit" or .name=="Write" or .name=="MultiEdit")) then "FILE\t"+((.input.file_path)//"")
          elif (.type=="tool_use" and .name=="NotebookEdit") then "FILE\t"+((.input.notebook_path)//(.input.file_path)//"")
          elif ($m.type=="assistant" and .type=="text") then "NOTE\t"+(((.text)//"")|gsub("[\n\r\t]+";" "))
          else empty end
      ' 2>/dev/null | tr -d '\000-\010\013\014\016-\037')"
  fi
  local todos files notes
  todos="$(printf '%s\n' "$stream" | awk -F'\t' '$1=="TODO"{v=$2} END{if(v!="")print v}')"
  files="$(printf '%s\n' "$stream" | awk -F'\t' '$1=="FILE" && $2!=""{print $2}' | sort -u)"
  notes="$(printf '%s\n' "$stream" | awk -F'\t' '$1=="NOTE" && $2!=""{print $2}' | tail -8)"

  local todos_md=""
  [ -n "$todos" ] && todos_md="$(printf '%s' "$todos" | jq -r '.[]? | select(.status=="pending" or .status=="in_progress") | "- [\(.status)] \(.content // .activeForm // "?")"' 2>/dev/null)"

  # Never clobber a good snapshot with nothing (guards Codex's unstable format,
  # empty transcripts, and mid-turn re-fires).
  if [ -z "$todos_md$files$notes" ] && [ -s "$snap" ]; then return 0; fi

  local tmp; tmp="$(mktemp "$SNAP_DIR/.snap.XXXXXX" 2>/dev/null)" || return 0
  {
    echo "# Compaction snapshot"
    echo
    echo "- session: \`$sid\`"
    echo "- cwd: \`${cwd:-?}\`"
    echo "- captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)  (trigger: ${trigger:-?})"
    [ -n "$custom" ] && echo "- /compact instructions: $custom"
    echo
    echo "## Open todos (pending / in progress at compaction)"
    if [ -n "$todos_md" ]; then printf '%s\n' "$todos_md"; else echo "_none captured_"; fi
    echo
    echo "## Files in play (read or edited)"
    if [ -n "$files" ]; then printf '%s\n' "$files" | sed 's/^/- /'; else echo "_none captured_"; fi
    echo
    echo "## Latest activity (best-effort, untrusted transcript excerpt)"
    echo
    if [ -n "$notes" ]; then printf '%s\n' "$notes"; else echo "_none captured_"; fi
  } > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }
  mv -f "$tmp" "$snap" 2>/dev/null || { rm -f "$tmp"; return 0; }

  # Sensitive snapshots shouldn't accumulate forever.
  find "$SNAP_DIR" -maxdepth 1 -name '*.md' -mtime +"$RET_DAYS" -delete 2>/dev/null || true

  local n_files n_todos
  n_files="$(printf '%s' "$files"    | grep -c . 2>/dev/null || echo 0)"
  n_todos="$(printf '%s' "$todos_md" | grep -c . 2>/dev/null || echo 0)"
  printf '%s\tsnapshot\t%s\ttrigger=%s files=%s todos=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$sid" "${trigger:-?}" "$n_files" "$n_todos" >> "$LOG" 2>/dev/null || true
}
main || true
exit 0
