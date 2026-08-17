#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Knock-out proved: a non-private fact survives a daemon stop/start cycle, so
# memory is durable and framework-independent rather than process-local state.
# The write path durably appends facts.jsonl before updating memory; daemon
# startup replays that append-only journal.
# Prerequisites: curl, jq, a running persistent Crux daemon, write/read scopes,
# and a synchronous operator-supplied command that stops then starts that daemon.
# Environment read exactly:
#   CRUX_URL         - daemon base URL (default: http://localhost:14800)
#   CRUX_TOKEN       - optional bearer token
#   CRUX_RESTART_CMD - shell command that stops and starts the target daemon
#

set -euo pipefail

CRUX_URL="${CRUX_URL:-http://localhost:14800}"
CRUX_TOKEN="${CRUX_TOKEN:-}"
CRUX_RESTART_CMD="${CRUX_RESTART_CMD:-}"
READY_RETRIES=30

if ! command -v jq >/dev/null 2>&1; then
    printf 'FAIL: jq is required; install jq and rerun demo-6-restart-survival.sh\n' >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    printf 'FAIL: curl is required; install curl and rerun demo-6-restart-survival.sh\n' >&2
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

if [[ -z "$CRUX_RESTART_CMD" ]]; then
    skip "restart-survival proof not run; set CRUX_RESTART_CMD to a synchronous stop+start command for the daemon at $CRUX_URL"
    exit 0
fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ENTITY="eval:restart-survival:$RUN_ID"
KEY="durable-fact-$RUN_ID"
VALUE="append-only-journal-survived-$RUN_ID"
WRITE_JSON="$(
    jq -cn \
        --arg entity "$ENTITY" \
        --arg key "$KEY" \
        --arg value "$VALUE" \
        '{entity:$entity,key:$key,value:$value,private:false,confidence:1.0}'
)"

FACT_ID=''
if request \
    PUT \
    /v1/facts \
    -H 'Content-Type: application/json' \
    --data "$WRITE_JSON"; then
    if [[ "$HTTP_STATUS" == "201" ]]; then
        if FACT_ID="$(jq -er '.fact_id | select(type == "string" and length > 0)' <"$HTTP_BODY" 2>/dev/null)"; then
            if jq -e \
                --arg entity "$ENTITY" \
                --arg key "$KEY" \
                --arg value "$VALUE" \
                '.entity == $entity and .key == $key and .value == $value and .private == false' \
                >/dev/null <"$HTTP_BODY"; then
                pass "PUT /v1/facts durably accepted fact $FACT_ID before restart"
            else
                fail 'PUT /v1/facts returned 201 without the exact non-private entity/key/value'
            fi
        else
            fail 'PUT /v1/facts returned 201 without a non-empty .fact_id'
        fi
    else
        fail "PUT /v1/facts expected HTTP 201, got $HTTP_STATUS"
    fi
else
    fail "PUT /v1/facts could not connect to $CRUX_URL"
fi

if ((FAILURES > 0)); then
    skip 'restart hook not invoked because the prerequisite fact write failed'
    exit 1
fi

if bash -c "$CRUX_RESTART_CMD"; then
    pass 'CRUX_RESTART_CMD completed its daemon stop+start hook'
else
    fail 'CRUX_RESTART_CMD failed'
    exit 1
fi

READY=false
for ((attempt = 1; attempt <= READY_RETRIES; attempt++)); do
    READY_STATUS='000'
    if READY_STATUS="$(
        authed_curl \
            --output /dev/null \
            --write-out '%{http_code}' \
            "${CRUX_URL}/readyz" \
            2>/dev/null
    )" && [[ "$READY_STATUS" == "200" ]]; then
        READY=true
        pass "GET /readyz returned HTTP 200 after restart (attempt $attempt/$READY_RETRIES)"
        break
    fi
    sleep 1
done

if [[ "$READY" != true ]]; then
    fail "GET /readyz did not return HTTP 200 within $READY_RETRIES bounded retries"
    exit 1
fi

if request GET "/v1/facts/$FACT_ID"; then
    if [[ "$HTTP_STATUS" == "200" ]]; then
        if jq -e \
            --arg id "$FACT_ID" \
            --arg entity "$ENTITY" \
            --arg key "$KEY" \
            --arg value "$VALUE" \
            '.fact_id == $id
             and .entity == $entity
             and .key == $key
             and .value == $value
             and .private == false
             and .deleted == false' \
            >/dev/null <"$HTTP_BODY"; then
            pass "GET /v1/facts/$FACT_ID returned the identical value after restart"
            pass 'fact survived via the daemon persistence journal, not in-memory process state'
        else
            fail 'post-restart fact response did not preserve the same id/entity/key/value'
        fi
    else
        fail "post-restart GET /v1/facts/$FACT_ID expected HTTP 200, got $HTTP_STATUS"
    fi
else
    fail "post-restart GET /v1/facts/$FACT_ID could not connect to $CRUX_URL"
fi

if ((FAILURES > 0)); then
    exit 1
fi
