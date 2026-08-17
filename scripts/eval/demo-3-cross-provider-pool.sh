#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Knock-out proved: one local Crux daemon exposes one non-private memory pool to
# different agent identities (Claude Code, Codex, and open-model clients can all
# mount the same daemon through MCP or use this same REST fact substrate).
# Prerequisites: a running Crux daemon, curl, jq, and credentials with
# facts:write plus query:read (or corresponding admin scopes).
# Environment read exactly:
#   CRUX_URL             - daemon base URL (default: http://localhost:14800)
#   CRUX_TOKEN           - optional fallback bearer token
#   CRUX_AGENT1_TOKEN    - writer bearer token for a true two-identity proof
#   CRUX_AGENT2_TOKEN    - reader bearer token for a true two-identity proof
#   CRUX_AGENT1_PASSPORT - writer passport bound to CRUX_AGENT1_TOKEN
#   CRUX_AGENT2_PASSPORT - reader passport bound to CRUX_AGENT2_TOKEN
#

set -euo pipefail

CRUX_URL="${CRUX_URL:-http://localhost:14800}"
CRUX_TOKEN="${CRUX_TOKEN:-}"
CRUX_AGENT1_TOKEN="${CRUX_AGENT1_TOKEN:-}"
CRUX_AGENT2_TOKEN="${CRUX_AGENT2_TOKEN:-}"
CRUX_AGENT1_PASSPORT="${CRUX_AGENT1_PASSPORT:-}"
CRUX_AGENT2_PASSPORT="${CRUX_AGENT2_PASSPORT:-}"

if ! command -v jq >/dev/null 2>&1; then
    printf 'FAIL: jq is required; install jq and rerun demo-3-cross-provider-pool.sh\n' >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    printf 'FAIL: curl is required; install curl and rerun demo-3-cross-provider-pool.sh\n' >&2
    exit 1
fi

AUTH_ARGS=()
if [[ -n "$CRUX_TOKEN" ]]; then
    AUTH_ARGS=(-H "Authorization: Bearer $CRUX_TOKEN")
fi

authed_curl() {
    curl --silent --show-error "${AUTH_ARGS[@]}" "$@"
}

identity_curl() {
    local token="$1"
    local passport="$2"
    shift 2
    local identity_args=()
    if [[ -n "$token" ]]; then
        identity_args+=(-H "Authorization: Bearer $token")
    fi
    if [[ -n "$passport" ]]; then
        identity_args+=(-H "X-Corecrux-Passport-Id: $passport")
    fi
    curl --silent --show-error "${identity_args[@]}" "$@"
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

request_default() {
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

request_identity() {
    local token="$1"
    local passport="$2"
    local method="$3"
    local path="$4"
    shift 4
    REQUEST_NUMBER=$((REQUEST_NUMBER + 1))
    HTTP_BODY="$TMP_DIR/response-$REQUEST_NUMBER"
    if HTTP_STATUS="$(
        identity_curl \
            "$token" \
            "$passport" \
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

CROSS_IDENTITY=false
if [[ -n "$CRUX_AGENT1_TOKEN" && -n "$CRUX_AGENT2_TOKEN" \
    && -n "$CRUX_AGENT1_PASSPORT" && -n "$CRUX_AGENT2_PASSPORT" \
    && "$CRUX_AGENT1_TOKEN" != "$CRUX_AGENT2_TOKEN" \
    && "$CRUX_AGENT1_PASSPORT" != "$CRUX_AGENT2_PASSPORT" ]]; then
    CROSS_IDENTITY=true
else
    skip 'true cross-identity proof needs two different CRUX_AGENT{1,2}_TOKEN values and two different bound CRUX_AGENT{1,2}_PASSPORT values; using CRUX_TOKEN for a write plus a separate query call'
fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ENTITY="eval:cross-provider-pool:$RUN_ID"
KEY="shared-memory-proof-$RUN_ID"
VALUE="one-daemon-shared-pool-$RUN_ID"
WRITE_JSON="$(
    jq -cn \
        --arg entity "$ENTITY" \
        --arg key "$KEY" \
        --arg value "$VALUE" \
        '{entity:$entity,key:$key,value:$value,private:false,confidence:1.0}'
)"

if [[ "$CROSS_IDENTITY" == true ]]; then
    write_ok=false
    if request_identity \
        "$CRUX_AGENT1_TOKEN" \
        "$CRUX_AGENT1_PASSPORT" \
        PUT \
        /v1/facts \
        -H 'Content-Type: application/json' \
        --data "$WRITE_JSON"; then
        write_ok=true
    fi
else
    write_ok=false
    if request_default \
        PUT \
        /v1/facts \
        -H 'Content-Type: application/json' \
        --data "$WRITE_JSON"; then
        write_ok=true
    fi
fi

FACT_ID=''
if [[ "$write_ok" == true && "$HTTP_STATUS" == "201" ]]; then
    if FACT_ID="$(jq -er '.fact_id | select(type == "string" and length > 0)' <"$HTTP_BODY" 2>/dev/null)"; then
        if jq -e \
            --arg entity "$ENTITY" \
            --arg key "$KEY" \
            --arg value "$VALUE" \
            '.entity == $entity and .key == $key and .value == $value and .private == false' \
            >/dev/null <"$HTTP_BODY"; then
            if [[ "$CROSS_IDENTITY" == true ]]; then
                pass "agent identity $CRUX_AGENT1_PASSPORT stored non-private fact $FACT_ID via PUT /v1/facts"
            else
                pass "configured agent stored non-private fact $FACT_ID via PUT /v1/facts"
            fi
        else
            fail 'PUT /v1/facts returned 201 but did not echo the stored entity/key/value as a non-private fact'
        fi
    else
        fail 'PUT /v1/facts returned 201 without a non-empty .fact_id'
    fi
elif [[ "$write_ok" == true ]]; then
    fail "PUT /v1/facts expected HTTP 201, got $HTTP_STATUS"
else
    fail "PUT /v1/facts could not connect to $CRUX_URL"
fi

if [[ -n "$FACT_ID" ]]; then
    if [[ "$CROSS_IDENTITY" == true ]]; then
        read_ok=false
        if request_identity \
            "$CRUX_AGENT2_TOKEN" \
            "$CRUX_AGENT2_PASSPORT" \
            GET \
            /v1/facts \
            --get \
            --data-urlencode "entity=$ENTITY" \
            --data-urlencode "query=$KEY" \
            --data-urlencode 'top_k=100'; then
            read_ok=true
        fi
    else
        read_ok=false
        if request_default \
            GET \
            /v1/facts \
            --get \
            --data-urlencode "entity=$ENTITY" \
            --data-urlencode "query=$KEY" \
            --data-urlencode 'top_k=100'; then
            read_ok=true
        fi
    fi

    if [[ "$read_ok" == true && "$HTTP_STATUS" == "200" ]]; then
        if jq -e \
            --arg id "$FACT_ID" \
            --arg entity "$ENTITY" \
            --arg key "$KEY" \
            --arg value "$VALUE" \
            'any(.facts[]?; .fact_id == $id and .entity == $entity and .key == $key and .value == $value and .private == false)' \
            >/dev/null <"$HTTP_BODY"; then
            if [[ "$CROSS_IDENTITY" == true ]]; then
                pass "different agent identity $CRUX_AGENT2_PASSPORT read writer $CRUX_AGENT1_PASSPORT's fact from the same daemon pool"
            else
                pass 'a separate GET /v1/facts query read the configured agent write from the same daemon pool'
            fi
        else
            fail "GET /v1/facts returned 200 but did not contain stored fact $FACT_ID"
        fi
    elif [[ "$read_ok" == true ]]; then
        fail "GET /v1/facts expected HTTP 200, got $HTTP_STATUS"
    else
        fail "GET /v1/facts could not connect to $CRUX_URL"
    fi
else
    skip 'readback assertion requires a successful fact write with a fact_id'
fi

if [[ "$CROSS_IDENTITY" == true && "$FAILURES" -eq 0 ]]; then
    pass 'two distinct token-bound passports shared one local MCP/REST memory substrate'
fi

if ((FAILURES > 0)); then
    exit 1
fi
