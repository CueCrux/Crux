#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# Claude Code lifecycle hook → Crux Daemon observation capture.
#
# Reads the hook event JSON from stdin, extracts session_id + the relevant
# payload, and POSTs to corecruxd's /v1/sessions/{id}/observations endpoint.
# Fire-and-forget: a daemon outage MUST NOT block the Claude Code session,
# so failures are logged to ~/.claude/hooks/crux-observe.errors.log and the
# hook always exits 0.
#
# Hook event kind is passed as $1 (e.g. session_start, user_prompt, tool_use,
# stop, session_end), as configured in ~/.claude/settings.json.
#
# Requires: bash >=4, curl, jq.

set -u
KIND="${1:-unknown}"
CORECRUXD_URL="${CORECRUXD_URL:-http://127.0.0.1:14800}"
CORECRUXD_AUTH_TOKEN="${CORECRUXD_AUTH_TOKEN:-}"
TIMEOUT="${CRUX_OBSERVE_TIMEOUT:-0.5}"
LOG_DIR="${HOME}/.claude/hooks"
ERR_LOG="${LOG_DIR}/crux-observe.errors.log"
mkdir -p "${LOG_DIR}" 2>/dev/null || true

log_err() {
  local msg="$1"
  printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${KIND}" "${msg}" >> "${ERR_LOG}" 2>/dev/null || true
}

# Required deps. Missing tools → silent skip (we never break the session).
command -v curl >/dev/null 2>&1 || { log_err "curl not found, skipping"; exit 0; }
command -v jq   >/dev/null 2>&1 || { log_err "jq not found, skipping";   exit 0; }

PAYLOAD_RAW="$(cat)"
if [ -z "${PAYLOAD_RAW}" ]; then
  log_err "empty stdin"
  exit 0
fi

# Extract session_id (Claude Code hook contract). Fall back to a default if
# the event JSON doesn't include one (some lifecycle events may not).
SESSION_ID="$(printf '%s' "${PAYLOAD_RAW}" | jq -r '.session_id // .sessionId // empty' 2>/dev/null)"
if [ -z "${SESSION_ID}" ]; then
  SESSION_ID="claude-code-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi

CLIENT_TS="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"

# Build the observation body. We pass the entire hook event JSON through as
# the `payload` so the daemon can replay arbitrary lifecycle details without
# this script needing to know the schema for every hook kind.
BODY="$(jq -nc \
  --arg kind "${KIND}" \
  --arg provider "claude-code" \
  --arg client_ts "${CLIENT_TS}" \
  --argjson payload "${PAYLOAD_RAW}" \
  '{kind: $kind, provider: $provider, client_ts: $client_ts, payload: $payload}' 2>/dev/null)"

if [ -z "${BODY}" ]; then
  log_err "failed to build observation body"
  exit 0
fi

AUTH_ARGS=()
if [ -n "${CORECRUXD_AUTH_TOKEN}" ]; then
  AUTH_ARGS+=(-H "Authorization: Bearer ${CORECRUXD_AUTH_TOKEN}")
fi
# Daemons running in `dev_scopes` auth mode accept scopes via this header.
# Default to the minimum needed for POST /v1/sessions/{id}/observations.
SCOPES="${CORECRUXD_SCOPES:-sessions:write admin:read}"
AUTH_ARGS+=(-H "X-Corecrux-Scopes: ${SCOPES}")

# Fire-and-forget POST. We capture stderr to the error log but still exit 0
# so a daemon outage never propagates back to Claude Code.
HTTP_CODE="$(curl -sS \
  --max-time "${TIMEOUT}" \
  -o /dev/null \
  -w '%{http_code}' \
  -X POST \
  -H 'Content-Type: application/json' \
  "${AUTH_ARGS[@]}" \
  --data-raw "${BODY}" \
  "${CORECRUXD_URL}/v1/sessions/${SESSION_ID}/observations" 2>>"${ERR_LOG}")"

if [ "${HTTP_CODE}" != "201" ] && [ "${HTTP_CODE}" != "200" ]; then
  log_err "POST returned HTTP ${HTTP_CODE} for session=${SESSION_ID}"
fi

exit 0
