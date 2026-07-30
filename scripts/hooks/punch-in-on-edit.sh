#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# PreToolUse hook — acquire a file-level punchcard for the file about to be edited.
#
# Workspace CLAUDE.md has long said "the PreToolUse hook checks leases on every
# Edit/Write". It did not exist. Punchcards were built, documented and unwired,
# so collision detection only ever saw sessions that remembered to announce.
# This is that hook.
#
# Contract:
#   * ADVISORY by default. A peer's lease prints a warning and the edit proceeds.
#     Set CRUX_PUNCH_MODE=enforce to block instead (exit 2).
#   * EXIT 0 ON ANY DAEMON ERROR. A coordination service being down must never
#     become a workstation outage — that trade is never worth it.
#   * File-level granularity (operator decision 2026-07-29): one card per file,
#     so "is anyone else in THIS file" is answerable and release-on-commit can be
#     exact.
#   * Idempotent + cached: a per-session marker means repeat edits of the same
#     file cost no network call at all.
#
# stdin: Claude Code hook JSON. stdout/stderr: operator-facing text only.

set -uo pipefail

# Machine-local overrides live outside the repository (see
# scripts/hooks/execplan-drift-boot.sh for why).
[ -f "${CRUX_HOOKS_ENV:-$HOME/.config/crux/hooks.env}" ] &&
  . "${CRUX_HOOKS_ENV:-$HOME/.config/crux/hooks.env}"

CRUX_URL="${CRUX_HTTP_URL:-http://127.0.0.1:14800}"
MODE="${CRUX_PUNCH_MODE:-advisory}"
TTL="${CRUX_PUNCH_TTL_SECS:-14400}"   # 4h — long enough for a work session, short enough to self-heal
TIMEOUT="${CRUX_PUNCH_TIMEOUT_SECS:-2}"

payload="$(cat)"

# jq is the only dependency; without it, do nothing rather than guess.
command -v jq >/dev/null 2>&1 || exit 0

file_path="$(printf '%s' "$payload" | jq -r '.tool_input.file_path // .tool_input.notebook_path // empty' 2>/dev/null)"
[ -n "$file_path" ] || exit 0

session_id="$(printf '%s' "$payload" | jq -r '.session_id // "unknown"' 2>/dev/null)"

# ── local dedupe cache ──────────────────────────────────────────────────────
# File granularity means a busy session touches many paths, and the same path
# many times. The cache is what keeps that from becoming one HTTP call per edit:
# only a FIRST touch in this session reaches the daemon.
cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/crux-punchcards/${session_id}"
key="$(printf '%s' "$file_path" | sha256sum | cut -c1-40)"
marker="${cache_dir}/${key}"
[ -f "$marker" ] && exit 0
mkdir -p "$cache_dir" 2>/dev/null || exit 0

resource="file://${file_path}"

resp="$(curl -sS -m "$TIMEOUT" -X POST "${CRUX_URL}/v1/punchcards/acquire" \
  -H 'content-type: application/json' \
  ${CRUX_AGENT_TOKEN:+-H "Authorization: Bearer ${CRUX_AGENT_TOKEN}"} \
  -d "$(jq -nc --arg r "$resource" --arg s "$session_id" --argjson t "$TTL" \
        '{resource:$r, mode:"modify", ttl_secs:$t, reason:("claude session " + $s)}')" \
  -w '\n%{http_code}' 2>/dev/null)" || {
    # Daemon unreachable. Say so once, then get out of the way.
    echo "crux: punchcard daemon unreachable (${CRUX_URL}) — proceeding unleased" >&2
    exit 0
  }

code="$(printf '%s' "$resp" | tail -n1)"
body="$(printf '%s' "$resp" | sed '$d')"

case "$code" in
  201|200)
    # Record the grant so repeat edits are free.
    printf '%s' "$resource" > "$marker" 2>/dev/null
    holder="$(printf '%s' "$body" | jq -r '.advisory_conflict.held_by // empty' 2>/dev/null)"
    if [ -n "$holder" ]; then
      echo "crux: ⚠ ${file_path} is also held by ${holder} — coordinate before you both land changes" >&2
    fi
    exit 0
    ;;
  409)
    holder="$(printf '%s' "$body" | jq -r '.held_by // "another session"' 2>/dev/null)"
    if [ "$MODE" = "enforce" ]; then
      echo "crux: ${file_path} is leased by ${holder}. Coordinate, or set CRUX_PUNCH_MODE=advisory." >&2
      exit 2
    fi
    echo "crux: ⚠ ${file_path} is leased by ${holder} — proceeding (advisory)" >&2
    exit 0
    ;;
  *)
    # 4xx/5xx that is not a lease conflict: misconfiguration, auth, feature off.
    # None of those are reasons to stop someone editing a file.
    [ "$code" = "000" ] || echo "crux: punchcard acquire returned ${code} — proceeding unleased" >&2
    exit 0
    ;;
esac
