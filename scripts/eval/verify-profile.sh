#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Knock-out proved: the authoritative M0 buyer-fit profile advertises all six
# capabilities and every enabled HTTP surface is actually mounted (not 404).
# Prerequisites: a running Crux daemon at CRUX_URL, curl, and jq.
# Environment read exactly:
#   CRUX_URL   - daemon base URL (default: http://localhost:14800)
#   CRUX_TOKEN - optional bearer token for protected surface probes
#

set -euo pipefail

CRUX_URL="${CRUX_URL:-http://localhost:14800}"
CRUX_TOKEN="${CRUX_TOKEN:-}"

if ! command -v jq >/dev/null 2>&1; then
    printf 'FAIL: jq is required; install jq and rerun verify-profile.sh\n' >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    printf 'FAIL: curl is required; install curl and rerun verify-profile.sh\n' >&2
    exit 1
fi

AUTH_ARGS=()
if [[ -n "$CRUX_TOKEN" ]]; then
    AUTH_ARGS=(-H "Authorization: Bearer $CRUX_TOKEN")
fi

authed_curl() {
    curl --silent --show-error "${AUTH_ARGS[@]}" "$@"
}

FAILURES=0
REQUEST_NUMBER=0
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

pass() {
    printf 'PASS: %s\n' "$*"
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    FAILURES=$((FAILURES + 1))
}

skip() {
    printf 'SKIP: %s\n' "$*"
}

request() {
    local method="$1"
    local path="$2"
    shift 2
    REQUEST_NUMBER=$((REQUEST_NUMBER + 1))
    HTTP_BODY="$TMP_DIR/response-$REQUEST_NUMBER"
    if HTTP_STATUS="$(
        authed_curl \
            --request "$method" \
            "$@" \
            --output "$HTTP_BODY" \
            --write-out '%{http_code}' \
            "${CRUX_URL}${path}"
    )"; then
        return 0
    fi
    HTTP_STATUS="000"
    return 1
}

if request GET /v1/version; then
    if [[ "$HTTP_STATUS" == "200" ]]; then
        pass 'GET /v1/version returned HTTP 200'
        if jq -e . >/dev/null 2>&1 <"$HTTP_BODY"; then
            pass 'GET /v1/version returned valid JSON'
            CAPABILITY_CHECKS=(
                'coordination|.capabilities.coordination.enabled'
                'consolidation_scheduler|.capabilities.consolidation_scheduler.enabled'
                'context_surface|.capabilities.context_surface.enabled'
                'local_ingest|.capabilities.local_ingest.enabled'
                'status_feed|.capabilities.status_feed.enabled'
                'activity_log|.capabilities.activity_log.enabled'
            )
            for check in "${CAPABILITY_CHECKS[@]}"; do
                IFS='|' read -r name jq_path <<<"$check"
                if jq -e "$jq_path == true" >/dev/null 2>&1 <"$HTTP_BODY"; then
                    pass "$jq_path is true ($name enabled)"
                else
                    actual="$(jq -r "$jq_path | if . == null then \"missing\" else tostring end" <"$HTTP_BODY" 2>/dev/null || printf 'invalid')"
                    fail "$jq_path must be true (actual: $actual)"
                fi
            done
        else
            fail 'GET /v1/version body is not valid JSON'
            skip 'capability assertions require a valid /v1/version document'
        fi
    else
        fail "GET /v1/version expected HTTP 200, got $HTTP_STATUS"
        skip 'capability assertions require HTTP 200 from /v1/version'
    fi
else
    fail "GET /v1/version could not connect to $CRUX_URL"
    skip 'capability assertions require a reachable /v1/version endpoint'
fi

if request GET /readyz; then
    if [[ "$HTTP_STATUS" == "200" ]]; then
        pass 'GET /readyz returned HTTP 200'
    else
        fail "GET /readyz expected HTTP 200, got $HTTP_STATUS"
    fi
else
    fail "GET /readyz could not connect to $CRUX_URL"
fi

probe_not_404() {
    local label="$1"
    local method="$2"
    local path="$3"
    shift 3
    if request "$method" "$path" "$@"; then
        if [[ "$HTTP_STATUS" == "404" ]]; then
            fail "$label returned HTTP 404; its advertised capability gate is not active"
        else
            pass "$label is mounted (HTTP $HTTP_STATUS, not 404)"
        fi
    else
        fail "$label could not connect to $CRUX_URL"
    fi
}

# GET is the registered, non-mutating context probe. With the gate on it can
# return 200 or an auth error, but the handler's disabled branch returns 404.
probe_not_404 'GET /v1/context' GET /v1/context

# The handler takes Json<LocalIngestBody>, so this payload must deserialize to
# reach the feature gate. documents=[] is then rejected before any write.
probe_not_404 \
    'POST /v1/local/ingest' \
    POST \
    /v1/local/ingest \
    -H 'Content-Type: application/json' \
    --data '{"tenant_id":"__profile_probe__","corpus_id":"__profile_probe__","documents":[]}'

probe_not_404 'GET /v1/status-feed' GET /v1/status-feed

# Missing tenant_id is deliberately safe: enabled returns 400; disabled returns
# the activity handler's gate-specific 404.
probe_not_404 'GET /v1/activity' GET /v1/activity

if ((FAILURES > 0)); then
    printf 'PROFILE INCOMPLETE\n'
    exit 1
fi

printf 'PROFILE OK\n'
