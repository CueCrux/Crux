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

# Build the observation body in a temp file. The hook payload can be large
# (full tool_use events), so we stream it to jq via stdin and write the rendered
# body to a file — it is never placed on a command line, which would blow past
# ARG_MAX ("Argument list too long") for big events. We pass the entire hook
# event JSON through as `payload` so the daemon can replay arbitrary lifecycle
# details without this script knowing the schema for every hook kind.
#
# Size guards: the daemon caps the per-observation payload (HTTP 413 above the
# cap), so we keep payloads small client-side. Every string field longer than
# MAX_FIELD_CHARS is truncated with a marker, and if the whole body still
# exceeds MAX_BODY_BYTES it is replaced with a compact stub — so an oversize
# event is still recorded (truncated) rather than silently dropped. Keep
# MAX_BODY_BYTES at or below the daemon's CORECRUXD_MAX_OBSERVATION_PAYLOAD_BYTES.
MAX_FIELD_CHARS="${CRUX_OBSERVE_MAX_FIELD_CHARS:-16384}"
MAX_BODY_BYTES="${CRUX_OBSERVE_MAX_BODY_BYTES:-262144}"

TMP_BODY="$(mktemp "${TMPDIR:-/tmp}/crux-observe.XXXXXX" 2>/dev/null)" || {
  log_err "mktemp failed"
  exit 0
}
trap 'rm -f "${TMP_BODY}"' EXIT

printf '%s' "${PAYLOAD_RAW}" | jq -c \
  --arg kind "${KIND}" \
  --arg provider "claude-code" \
  --arg client_ts "${CLIENT_TS}" \
  --argjson cap "${MAX_FIELD_CHARS}" '
    def trunc:
      walk(if type == "string" and (length > $cap)
           then .[0:$cap] + "…[crux-truncated " + ((length - $cap) | tostring) + " chars]"
           else . end);
    {kind: $kind, provider: $provider, client_ts: $client_ts, payload: (trunc)}
  ' > "${TMP_BODY}" 2>>"${ERR_LOG}"

if [ ! -s "${TMP_BODY}" ]; then
  log_err "failed to build observation body"
  exit 0
fi

# Final safety net: if per-field truncation still left an oversize body (very
# many fields, or large non-string structures), replace the payload with a stub
# that records the event existed and why it was reduced.
if [ "$(wc -c < "${TMP_BODY}")" -gt "${MAX_BODY_BYTES}" ]; then
  ORIG_BYTES="$(printf '%s' "${PAYLOAD_RAW}" | wc -c)"
  jq -nc \
    --arg kind "${KIND}" \
    --arg provider "claude-code" \
    --arg client_ts "${CLIENT_TS}" \
    --arg sid "${SESSION_ID}" \
    --argjson bytes "${ORIG_BYTES}" \
    --argjson cap "${MAX_BODY_BYTES}" \
    '{kind: $kind, provider: $provider, client_ts: $client_ts,
      payload: {session_id: $sid, crux_truncated: true, original_bytes: $bytes,
                note: ("observation body exceeded " + ($cap | tostring)
                       + " bytes after field truncation; reduced to stub")}}' \
    > "${TMP_BODY}" 2>>"${ERR_LOG}"
  if [ ! -s "${TMP_BODY}" ]; then
    log_err "failed to build truncation stub"
    exit 0
  fi
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
  --data-binary "@${TMP_BODY}" \
  "${CORECRUXD_URL}/v1/sessions/${SESSION_ID}/observations" 2>>"${ERR_LOG}")"

if [ "${HTTP_CODE}" != "201" ] && [ "${HTTP_CODE}" != "200" ]; then
  log_err "POST returned HTTP ${HTTP_CODE} for session=${SESSION_ID}"
fi

# ── Activity journal leg (crux-dual-surface-activity-log) ───────────────────
# Opt-in (CRUX_HOOK_ACTIVITY=1): map the hook event to a readable journal kind
# and append it to /v1/activity (the human-rich Activity lane that the console
# renders). Questions + commands are captured live; answers/reasoning ride the
# post-hoc `corecruxctl observe ingest` path. Fire-and-forget; fail-open.
if [ "${CRUX_HOOK_ACTIVITY:-0}" = "1" ]; then
  ACT_KIND=""
  case "${KIND}" in
    user_prompt) ACT_KIND="question" ;;
    tool_use)    ACT_KIND="command"  ;;
  esac
  if [ -n "${ACT_KIND}" ]; then
    ACT_TENANT="${CRUX_ACTIVITY_TENANT:-default}"
    ACT_MAXTEXT="${CRUX_ACTIVITY_MAX_TEXT:-4000}"
    ACT_BODY="$(mktemp "${TMPDIR:-/tmp}/crux-activity.XXXXXX" 2>/dev/null)" || ACT_BODY=""
    if [ -n "${ACT_BODY}" ]; then
      printf '%s' "${PAYLOAD_RAW}" | jq -c \
        --arg kind "${ACT_KIND}" \
        --arg sid "${SESSION_ID}" \
        --arg tenant "${ACT_TENANT}" \
        --argjson cap "${ACT_MAXTEXT}" '
        def clip($s): if ($s|type)=="string" and ($s|length)>$cap then ($s[0:$cap] + "…") else $s end;
        ( if $kind=="question" then (.prompt // .message // .text // "")
          elif $kind=="command" then
            ((.tool_name // .tool.name // "tool")
             + (if (.tool_input|type)=="object"
                then (": " + ((.tool_input.command // .tool_input.file_path // .tool_input.pattern // (.tool_input.description) // (.tool_input|tostring))|tostring))
                else "" end))
          else "" end ) as $txt
        | ( if $kind=="command" then {tool: (.tool_name // .tool.name // null)} else {} end ) as $meta
        | {tenant_id: $tenant, session_id: $sid, kind: $kind, text: clip($txt), meta: $meta, private: true}
      ' > "${ACT_BODY}" 2>>"${ERR_LOG}"
      if [ -s "${ACT_BODY}" ]; then
        # Activity append needs a write scope; on jwt daemons the bearer carries
        # it, on dev_scopes daemons the header does. Send both (header is ignored
        # where a bearer is required).
        ACT_AUTH=("${AUTH_ARGS[@]}")
        ACT_AUTH+=(-H "X-Corecrux-Scopes: ${CRUX_ACTIVITY_SCOPES:-facts:write admin:write}")
        ACT_CODE="$(curl -sS --max-time "${TIMEOUT}" -o /dev/null -w '%{http_code}' \
          -X POST -H 'Content-Type: application/json' "${ACT_AUTH[@]}" \
          --data-binary "@${ACT_BODY}" \
          "${CORECRUXD_URL}/v1/activity" 2>>"${ERR_LOG}")"
        [ "${ACT_CODE}" = "201" ] || log_err "activity POST HTTP ${ACT_CODE} (kind=${ACT_KIND})"
      fi
      rm -f "${ACT_BODY}"
    fi
  fi
fi

exit 0
