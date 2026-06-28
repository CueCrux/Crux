#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# crux-filemod.sh — B4 write-side file-modification ledger for Claude Code.
#
# The Crux-native form of "log what was modified, not just that a tree was
# claimed". Pairs two legs of one edit:
#   pre  (PreToolUse)  — stash the file's pre-edit content + content hash.
#   post (PostToolUse) — hash the post-edit file, diff against the stash for an
#                        exact line delta, and POST a `filemod` observation to
#                        the daemon's append-only (receipted) observation lane.
#
# Design notes:
#   * Self-contained: sources ~/.config/cuecrux/env for CRUX_HTTP_URL +
#     CRUX_AGENT_TOKEN exactly like crux-hook-env.sh, so it does NOT depend on
#     the corecruxctl-managed wrapper (a `hooks install` won't clobber it).
#   * Gated by CRUX_HOOK_FILEMOD=1 (opt-in, like the other observe legs).
#   * Fire-and-forget: a daemon outage or any error must never block a tool
#     call, so every path exits 0; failures go to the error log.
#   * Content address: sha256 (no blake3 CLI on this host). `hash_algo` is
#     recorded so a future blake3 alignment is unambiguous.
#
# Requires: jq, sha256sum, curl, diff (coreutils + diffutils).

set -u
MODE="${1:-}"

# Source hook env (token + urls). Never echo secrets.
set -a
# shellcheck disable=SC1090
. "$HOME/.config/cuecrux/env" 2>/dev/null || true
set +a

# Gate: opt-in only.
[ "${CRUX_HOOK_FILEMOD:-0}" = "1" ] || exit 0

command -v jq        >/dev/null 2>&1 || exit 0
command -v sha256sum >/dev/null 2>&1 || exit 0
command -v curl      >/dev/null 2>&1 || exit 0

URL="${CRUX_HTTP_URL:-http://127.0.0.1:14800}"
TOK="${CRUX_AGENT_TOKEN:-}"
TMO="${CRUX_FILEMOD_TIMEOUT:-0.8}"
MAX_BYTES="${CRUX_FILEMOD_MAX_BYTES:-2000000}"
STASH_ROOT="${TMPDIR:-/tmp}/crux-filemod"
LOG_DIR="$HOME/.claude/hooks"
ERR_LOG="$LOG_DIR/crux-filemod.errors.log"
mkdir -p "$LOG_DIR" 2>/dev/null || true

RAW="$(cat 2>/dev/null || true)"
[ -n "$RAW" ] || exit 0

SID="$(printf '%s' "$RAW" | jq -r '.session_id // .sessionId // "nosession"' 2>/dev/null)"
TOOL="$(printf '%s' "$RAW" | jq -r '.tool_name // .tool.name // ""' 2>/dev/null)"
case "$TOOL" in
  Edit|Write|MultiEdit|NotebookEdit) ;;
  *) exit 0 ;;
esac

FP="$(printf '%s' "$RAW" | jq -r '.tool_input.file_path // .tool_input.notebook_path // ""' 2>/dev/null)"
[ -n "$FP" ] || exit 0

KEY="$(printf '%s' "${SID}::${FP}" | sha256sum | cut -c1-40)"
DIR="$STASH_ROOT/$SID"
BEFORE="$DIR/$KEY.before"

hash_file() { [ -f "$1" ] && sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || printf ''; }
size_of()   { [ -f "$1" ] && wc -c < "$1" 2>/dev/null | tr -dc '0-9' || printf '0'; }

# ── pre leg: stash the before-image (content for diff; absent file = new) ─────
if [ "$MODE" = "pre" ]; then
  mkdir -p "$DIR" 2>/dev/null || true
  if [ -f "$FP" ] && [ "$(size_of "$FP")" -le "$MAX_BYTES" ]; then
    cp -f "$FP" "$BEFORE" 2>/dev/null || true
  else
    # too big (or new) → no content stash; record absence so post knows.
    rm -f "$BEFORE" 2>/dev/null || true
  fi
  exit 0
fi

# ── post leg: hash after, diff for delta, POST the filemod observation ────────
AFTER_HASH="$(hash_file "$FP")"
BEFORE_HASH=""
ADDED=0
REMOVED=0
if [ -f "$BEFORE" ]; then
  BEFORE_HASH="$(hash_file "$BEFORE")"
  D="$(diff "$BEFORE" "$FP" 2>/dev/null || true)"
  ADDED="$(printf '%s\n' "$D"  | grep -c '^> ' || true)"
  REMOVED="$(printf '%s\n' "$D" | grep -c '^< ' || true)"
elif [ -f "$FP" ]; then
  # new file (no before-image) → all current lines are additions.
  ADDED="$(wc -l < "$FP" 2>/dev/null | tr -dc '0-9' || printf '0')"
fi
ADDED="$(printf '%s' "${ADDED:-0}" | tr -dc '0-9')"; ADDED="${ADDED:-0}"
REMOVED="$(printf '%s' "${REMOVED:-0}" | tr -dc '0-9')"; REMOVED="${REMOVED:-0}"

PROJ_DIR="${CLAUDE_PROJECT_DIR:-$PWD}"
EXECPLAN="${CRUX_FILEMOD_EXECPLAN:-$(cat "$PROJ_DIR/.crux/active-execplan" 2>/dev/null || printf '')}"
MILESTONE="${CRUX_FILEMOD_MILESTONE:-}"
TS="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"

BODY="$(jq -nc \
  --arg fp "$FP" --arg bh "$BEFORE_HASH" --arg ah "$AFTER_HASH" \
  --argjson add "$ADDED" --argjson rem "$REMOVED" \
  --arg tool "$TOOL" --arg ep "$EXECPLAN" --arg ms "$MILESTONE" --arg ts "$TS" '
  {kind:"filemod", provider:"claude-code", client_ts:$ts,
   payload:{path:$fp, hash_algo:"sha256",
            content_sha256_before:(if $bh=="" then null else $bh end),
            content_sha256_after:(if $ah=="" then null else $ah end),
            lines_added:$add, lines_removed:$rem, tool:$tool,
            execplan_slug:(if $ep=="" then null else $ep end),
            milestone:(if $ms=="" then null else $ms end)}}' 2>>"$ERR_LOG")"

if [ -n "$BODY" ]; then
  AUTH=()
  [ -n "$TOK" ] && AUTH+=(-H "Authorization: Bearer $TOK")
  AUTH+=(-H "X-Corecrux-Scopes: sessions:write admin:read")
  CODE="$(curl -sS --max-time "$TMO" -o /dev/null -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' "${AUTH[@]}" \
    --data-binary "$BODY" \
    "$URL/v1/sessions/$SID/observations" 2>>"$ERR_LOG")"
  if [ "$CODE" != "201" ] && [ "$CODE" != "200" ]; then
    printf '%s [post] filemod POST HTTP %s for %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CODE" "$FP" >> "$ERR_LOG" 2>/dev/null || true
  fi
fi

rm -f "$BEFORE" 2>/dev/null || true
exit 0
