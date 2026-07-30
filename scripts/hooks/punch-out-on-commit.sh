#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# PostToolUse hook — release the punchcards for the files a commit just landed.
#
# A lease you have to remember to release is a lease that expires instead, and
# an expiring lease teaches everyone to ignore leases. The commit is the natural
# end of "I am working on this file", so that is where release belongs.
#
# Contract:
#   * Releases ONLY the paths named by the commit. A file edited but left out of
#     the commit stays held — that is correct, not an edge case: you are still
#     working on it.
#   * Stamps `release_commit_sha`, so a card's end is tied to the change that
#     ended it rather than to a clock.
#   * EXIT 0 ALWAYS. Releasing is bookkeeping; failing it must never make a
#     successful commit look like a failure.
#
# stdin: Claude Code PostToolUse JSON for a Bash tool call.

set -uo pipefail

# Machine-local overrides live outside the repository (see
# scripts/hooks/execplan-drift-boot.sh for why).
[ -f "${CRUX_HOOKS_ENV:-$HOME/.config/crux/hooks.env}" ] &&
  . "${CRUX_HOOKS_ENV:-$HOME/.config/crux/hooks.env}"

CRUX_URL="${CRUX_HTTP_URL:-http://127.0.0.1:14800}"
TIMEOUT="${CRUX_PUNCH_TIMEOUT_SECS:-2}"

payload="$(cat)"
command -v jq >/dev/null 2>&1 || exit 0

command_run="$(printf '%s' "$payload" | jq -r '.tool_input.command // empty' 2>/dev/null)"
[ -n "$command_run" ] || exit 0

# Only react to a git commit. `git commit` inside a longer pipeline still counts;
# `git log --grep "commit"` does not.
printf '%s' "$command_run" | grep -qE '(^|[;&|[:space:]])git([[:space:]]+-[^[:space:]]+)*[[:space:]]+commit([[:space:]]|$)' || exit 0

# A failed commit released nothing, so there is nothing to release. Claude Code
# reports the tool result; absent a clear success signal, fall back to asking git.
cwd="$(printf '%s' "$payload" | jq -r '.cwd // empty' 2>/dev/null)"
[ -n "$cwd" ] && [ -d "$cwd" ] && cd "$cwd" 2>/dev/null

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0
sha="$(git rev-parse HEAD 2>/dev/null)" || exit 0
[ -n "$sha" ] || exit 0

# Paths in the commit we just made, absolute so they match the `file://` cards
# the PreToolUse hook acquired.
repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0
files="$(git show --name-only --format= "$sha" 2>/dev/null | grep . || true)"
[ -n "$files" ] || exit 0

session_id="$(printf '%s' "$payload" | jq -r '.session_id // "unknown"' 2>/dev/null)"
cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/crux-punchcards/${session_id}"

released=0
while IFS= read -r rel; do
  [ -n "$rel" ] || continue
  abs="${repo_root}/${rel}"
  resource="file://${abs}"
  code="$(curl -sS -m "$TIMEOUT" -o /dev/null -w '%{http_code}' \
    -X POST "${CRUX_URL}/v1/punchcards/release" \
    -H 'content-type: application/json' \
    ${CRUX_AGENT_TOKEN:+-H "Authorization: Bearer ${CRUX_AGENT_TOKEN}"} \
    -d "$(jq -nc --arg r "$resource" --arg s "$sha" '{resource:$r, release_commit_sha:$s}')" 2>/dev/null)" || continue
  if [ "$code" = "200" ] || [ "$code" = "201" ]; then
    released=$((released + 1))
    # Drop the dedupe marker too, so a later edit of this file re-acquires
    # rather than assuming a lease it no longer holds.
    key="$(printf '%s' "$abs" | sha256sum | cut -c1-40)"
    rm -f "${cache_dir}/${key}" 2>/dev/null
  fi
done <<< "$files"

[ "$released" -gt 0 ] && echo "crux: released ${released} punchcard(s) at ${sha:0:8}" >&2
exit 0
