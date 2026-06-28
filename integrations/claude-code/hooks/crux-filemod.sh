#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# crux-filemod.sh — B4 write-side file-modification ledger for Claude Code.
#
# Pairs two legs of one edit:
#   pre  (PreToolUse)  — stash the file's pre-edit content + content hash.
#   post (PostToolUse) — hash the post-edit file, diff against the stash for an
#                        exact line delta, and POST a receipted `filemod`
#                        observation to the daemon's append-only observation lane.
#
# Content address: blake3 when available (b3sum, else python `blake3`), else
# sha256. `hash_algo` records which was used (blake3 aligns with the daemon's own
# content addressing; sha256 is the portable fallback). Self-contained: sources
# ~/.config/cuecrux/env for CRUX_HTTP_URL + CRUX_AGENT_TOKEN like crux-hook-env.sh.
# Gated by CRUX_HOOK_FILEMOD=1. Fire-and-forget: always exits 0.
#
# Requires: jq, curl, diff, and one of {b3sum | python3+blake3 | sha256sum}.

set -u
MODE="${1:-}"

set -a
# shellcheck disable=SC1090
. "$HOME/.config/cuecrux/env" 2>/dev/null || true
set +a

[ "${CRUX_HOOK_FILEMOD:-0}" = "1" ] || exit 0
# Hooks may run with a minimal PATH; make user-local tool dirs visible (b3sum etc.).
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
command -v jq   >/dev/null 2>&1 || exit 0
command -v curl >/dev/null 2>&1 || exit 0

# ── content hasher: blake3-preferred, sha256 fallback (chosen once) ───────────
if command -v b3sum >/dev/null 2>&1; then
  HASH_ALGO="blake3"; _hash() { b3sum "$1" 2>/dev/null | cut -d' ' -f1; }
elif python3 -c 'import blake3' >/dev/null 2>&1; then
  HASH_ALGO="blake3"; _hash() { python3 -c 'import blake3,sys;print(blake3.blake3(open(sys.argv[1],"rb").read()).hexdigest())' "$1" 2>/dev/null; }
elif command -v sha256sum >/dev/null 2>&1; then
  HASH_ALGO="sha256"; _hash() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
else
  exit 0
fi
hash_file() { [ -f "$1" ] && _hash "$1" || printf ''; }
size_of()   { [ -f "$1" ] && wc -c < "$1" 2>/dev/null | tr -dc '0-9' || printf '0'; }

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

# ── pre leg: stash the before-image (content for diff; absent file = new) ─────
if [ "$MODE" = "pre" ]; then
  mkdir -p "$DIR" 2>/dev/null || true
  if [ -f "$FP" ] && [ "$(size_of "$FP")" -le "$MAX_BYTES" ]; then
    cp -f "$FP" "$BEFORE" 2>/dev/null || true
  else
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
  ADDED="$(wc -l < "$FP" 2>/dev/null | tr -dc '0-9' || printf '0')"
fi
ADDED="$(printf '%s' "${ADDED:-0}" | tr -dc '0-9')"; ADDED="${ADDED:-0}"
REMOVED="$(printf '%s' "${REMOVED:-0}" | tr -dc '0-9')"; REMOVED="${REMOVED:-0}"

PROJ_DIR="${CLAUDE_PROJECT_DIR:-$PWD}"
EXECPLAN="${CRUX_FILEMOD_EXECPLAN:-$(cat "$PROJ_DIR/.crux/active-execplan" 2>/dev/null || printf '')}"
MILESTONE="${CRUX_FILEMOD_MILESTONE:-}"
TS="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"

BODY="$(jq -nc \
  --arg fp "$FP" --arg bh "$BEFORE_HASH" --arg ah "$AFTER_HASH" --arg algo "$HASH_ALGO" \
  --argjson add "$ADDED" --argjson rem "$REMOVED" \
  --arg tool "$TOOL" --arg ep "$EXECPLAN" --arg ms "$MILESTONE" --arg ts "$TS" '
  {kind:"filemod", provider:"claude-code", client_ts:$ts,
   payload:{path:$fp, hash_algo:$algo,
            content_hash_before:(if $bh=="" then null else $bh end),
            content_hash_after:(if $ah=="" then null else $ah end),
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
rmdir "$DIR" 2>/dev/null || true
exit 0
