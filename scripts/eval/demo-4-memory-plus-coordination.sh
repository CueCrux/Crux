#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Knock-out proved: memory, live multi-agent coordination, and the work board
# coexist in one Crux daemon process and one fact-backed substrate; no second
# coordination product or service is contacted.
# Prerequisites: a running Crux daemon, curl, jq, admin:read plus query:read;
# facts:write is optional and enables creation of a discovered-project work item.
# Environment read exactly:
#   CRUX_URL   - daemon base URL (default: http://localhost:14800)
#   CRUX_TOKEN - optional bearer token
#

set -euo pipefail

CRUX_URL="${CRUX_URL:-http://localhost:14800}"
CRUX_TOKEN="${CRUX_TOKEN:-}"

if ! command -v jq >/dev/null 2>&1; then
    printf 'FAIL: jq is required; install jq and rerun demo-4-memory-plus-coordination.sh\n' >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    printf 'FAIL: curl is required; install curl and rerun demo-4-memory-plus-coordination.sh\n' >&2
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

COORD_OK=false
if request GET /v1/coord/active; then
    if [[ "$HTTP_STATUS" == "200" ]]; then
        if jq -e '
            (.now_unix_ms | type == "number")
            and (.presence_ttl_secs | type == "number")
            and (.active_sessions | type == "array")
            and (.work_in_flight | type == "array")
        ' >/dev/null <"$HTTP_BODY"; then
            pass 'GET /v1/coord/active returned the live coordination view'
            COORD_OK=true
        else
            fail 'GET /v1/coord/active returned 200 without the CoordActiveView shape'
        fi
    else
        fail "GET /v1/coord/active expected HTTP 200, got $HTTP_STATUS"
    fi
else
    fail "GET /v1/coord/active could not connect to $CRUX_URL"
fi

MEMORY_OK=false
if request GET /v1/facts --get --data-urlencode 'top_k=1'; then
    if [[ "$HTTP_STATUS" == "200" ]]; then
        if jq -e '(.facts | type == "array") and (.total_tokens | type == "number")' \
            >/dev/null <"$HTTP_BODY"; then
            pass 'GET /v1/facts queried memory on the same daemon'
            MEMORY_OK=true
        else
            fail 'GET /v1/facts returned 200 without .facts[] and numeric .total_tokens'
        fi
    else
        fail "GET /v1/facts expected HTTP 200, got $HTTP_STATUS"
    fi
else
    fail "GET /v1/facts could not connect to $CRUX_URL"
fi

WORK_OK=false
if request GET /v1/work --get --data-urlencode 'source=kanban'; then
    if [[ "$HTTP_STATUS" == "200" ]]; then
        if jq -e '
            .source == "kanban"
            and (.count | type == "number")
            and (.work | type == "array")
            and (.approvals | type == "array")
        ' >/dev/null <"$HTTP_BODY"; then
            pass 'GET /v1/work returned the fact-backed kanban board from the same daemon'
            WORK_OK=true
        else
            fail 'GET /v1/work returned 200 without the kanban work-board shape'
        fi
    else
        fail "GET /v1/work expected HTTP 200, got $HTTP_STATUS"
    fi
else
    fail "GET /v1/work could not connect to $CRUX_URL"
fi

# Work creation requires a real project id. Discover one instead of inventing
# "default"; a fresh store may have no usable project/passport pair.
if request GET /v1/projects; then
    if [[ "$HTTP_STATUS" == "200" ]]; then
        PROJECT_ROW="$(
            jq -r '
                first(
                    .projects[]?
                    | select(
                        (.id | type == "string" and length > 0)
                        and (.default_passport_id | type == "string" and length > 0)
                    )
                    | [.id, .default_passport_id]
                    | @tsv
                ) // empty
            ' <"$HTTP_BODY" 2>/dev/null || true
        )"
        if [[ -n "$PROJECT_ROW" ]]; then
            IFS=$'\t' read -r PROJECT_ID PASSPORT_ID <<<"$PROJECT_ROW"
            WORK_TITLE="Crux eval memory+coord $(date -u +%Y%m%dT%H%M%SZ)-$$"
            WORK_JSON="$(
                jq -cn \
                    --arg project_id "$PROJECT_ID" \
                    --arg title "$WORK_TITLE" \
                    --arg passport "$PASSPORT_ID" \
                    '{project_id:$project_id,title:$title,created_by_passport:$passport}'
            )"
            if request \
                POST \
                /v1/work \
                -H 'Content-Type: application/json' \
                --data "$WORK_JSON"; then
                if [[ "$HTTP_STATUS" == "201" ]]; then
                    if jq -e \
                        --arg project_id "$PROJECT_ID" \
                        --arg title "$WORK_TITLE" \
                        --arg passport "$PASSPORT_ID" \
                        '(.id | type == "string" and startswith("w_"))
                         and .project_id == $project_id
                         and .title == $title
                         and .created_by_passport == $passport
                         and .state == "planned"' \
                        >/dev/null <"$HTTP_BODY"; then
                        CREATED_WORK_ID="$(jq -r '.id' <"$HTTP_BODY")"
                        pass "POST /v1/work created $CREATED_WORK_ID in discovered project $PROJECT_ID"
                    else
                        fail 'POST /v1/work returned 201 without the expected planned WorkItem shape'
                    fi
                elif [[ "$HTTP_STATUS" == "401" || "$HTTP_STATUS" == "403" ]]; then
                    skip "work-item creation needs facts:write; POST /v1/work returned HTTP $HTTP_STATUS"
                else
                    fail "POST /v1/work expected HTTP 201, got $HTTP_STATUS"
                fi
            else
                fail "POST /v1/work could not connect to $CRUX_URL"
            fi
        else
            skip 'work-item creation needs an existing project with a non-empty default_passport_id; GET /v1/projects exposed none'
        fi
    elif [[ "$HTTP_STATUS" == "401" || "$HTTP_STATUS" == "403" ]]; then
        skip "work-item creation needs project discovery with admin:read; GET /v1/projects returned HTTP $HTTP_STATUS"
    else
        skip "work-item creation unavailable because GET /v1/projects returned HTTP $HTTP_STATUS"
    fi
else
    skip "work-item creation unavailable because GET /v1/projects could not connect to $CRUX_URL"
fi

if [[ "$COORD_OK" == true && "$MEMORY_OK" == true && "$WORK_OK" == true ]]; then
    pass "coordination, memory, and work all resolved through the single daemon URL $CRUX_URL"
fi

if ((FAILURES > 0)); then
    exit 1
fi
