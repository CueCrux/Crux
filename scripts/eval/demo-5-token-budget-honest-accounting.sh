#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# Knock-out proved: retrieval callers carry a mandatory token budget on the
# activity pull, while the deterministic local BM25 lane reports explicit,
# internally consistent token accounting and performs no LLM extraction fan-out.
# Prerequisites: a running buyer-fit-profile daemon, curl, jq, read authorization
# for CRUX_TENANT_ID, and an indexed corpus for the BM25 accounting assertions.
# Environment read exactly:
#   CRUX_URL       - daemon base URL (default: http://localhost:14800)
#   CRUX_TOKEN     - optional bearer token
#   CRUX_TENANT_ID - query tenant (default: default)
#   CRUX_QUERY     - lexical query text (default: crux)
#

set -euo pipefail

CRUX_URL="${CRUX_URL:-http://localhost:14800}"
CRUX_TOKEN="${CRUX_TOKEN:-}"
CRUX_TENANT_ID="${CRUX_TENANT_ID:-default}"
CRUX_QUERY="${CRUX_QUERY:-crux}"
TOKEN_BUDGET=500

if ! command -v jq >/dev/null 2>&1; then
    printf 'FAIL: jq is required; install jq and rerun demo-5-token-budget-honest-accounting.sh\n' >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    printf 'FAIL: curl is required; install curl and rerun demo-5-token-budget-honest-accounting.sh\n' >&2
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

# GET /v1/activity is the daemon's cheap retrieval pull. Unlike the general
# text-search request struct, this handler rejects a missing token_budget.
if request \
    GET \
    /v1/activity \
    --get \
    --data-urlencode "tenant_id=$CRUX_TENANT_ID" \
    --data-urlencode "token_budget=$TOKEN_BUDGET"; then
    if [[ "$HTTP_STATUS" == "200" ]]; then
        if jq -e \
            --argjson budget "$TOKEN_BUDGET" \
            '.token_budget == $budget
             and (.returned | type == "number")
             and (.truncated | type == "boolean")
             and (.rows | type == "array")' \
            >/dev/null <"$HTTP_BODY"; then
            pass "GET /v1/activity accepted and echoed mandatory token_budget=$TOKEN_BUDGET"
        else
            fail 'GET /v1/activity returned 200 without the budgeted activity-pull shape'
        fi
    else
        fail "budgeted GET /v1/activity expected HTTP 200, got $HTTP_STATUS"
    fi
else
    fail "budgeted GET /v1/activity could not connect to $CRUX_URL"
fi

if request \
    GET \
    /v1/activity \
    --get \
    --data-urlencode "tenant_id=$CRUX_TENANT_ID"; then
    if [[ "$HTTP_STATUS" == "400" ]]; then
        if jq -e \
            '(.detail // "") | contains("token_budget query parameter is required (QC.2)")' \
            >/dev/null <"$HTTP_BODY" 2>/dev/null; then
            pass 'GET /v1/activity rejects a missing token_budget with the QC.2 contract error'
        else
            fail 'GET /v1/activity returned 400 for a missing budget but not the QC.2 token_budget error'
        fi
    else
        fail "GET /v1/activity without token_budget expected HTTP 400, got $HTTP_STATUS"
    fi
else
    fail "unbudgeted GET /v1/activity could not connect to $CRUX_URL"
fi

QUERY_JSON="$(
    jq -cn \
        --arg tenant_id "$CRUX_TENANT_ID" \
        --arg query "$CRUX_QUERY" \
        --argjson budget "$TOKEN_BUDGET" \
        '{tenant_id:$tenant_id,query:$query,token_budget:$budget,limit:10,mode:"scan"}'
)"

if request \
    POST \
    /v1/query/text-search \
    -H 'Content-Type: application/json' \
    --data "$QUERY_JSON"; then
    if [[ "$HTTP_STATUS" == "200" ]]; then
        if jq -e '(.results | type == "array") and (.meta | type == "object")' \
            >/dev/null <"$HTTP_BODY"; then
            pass 'POST /v1/query/text-search returned HTTP 200 with a query result envelope'
        else
            fail 'POST /v1/query/text-search returned 200 without .results[] and .meta'
        fi

        if jq -e '
            .meta.backend == "corecrux-v5-bm25"
            and .meta.score_space == "bm25_lexical"
        ' >/dev/null <"$HTTP_BODY"; then
            pass 'deterministic 0-LLM lane reported backend=corecrux-v5-bm25 and score_space=bm25_lexical (the handler calls bm25_search directly; no extraction fan-out)'
        else
            fail 'text search did not report the grounded local BM25 backend and lexical score space'
        fi

        SEGMENTS_SEARCHED="$(jq -r '.meta.segments_searched // 0' <"$HTTP_BODY" 2>/dev/null || printf '0')"
        if [[ "$SEGMENTS_SEARCHED" =~ ^[0-9]+$ && "$SEGMENTS_SEARCHED" -eq 0 ]]; then
            skip 'token accounting needs a loaded .ccxi corpus; .meta.segments_searched is 0, and the handler empty-index fast path intentionally omits accounting fields'
        else
            if jq -e \
                --argjson budget "$TOKEN_BUDGET" \
                '.tokens_available == $budget
                 and (.tokens_used | type == "number")
                 and (.results_omitted | type == "number")' \
                >/dev/null <"$HTTP_BODY"; then
                pass "response reports tokens_available=$TOKEN_BUDGET, numeric tokens_used, and numeric results_omitted"
            else
                fail 'indexed text-search response is missing tokens_available/tokens_used/results_omitted accounting'
            fi

            if jq -e '([.results[]?.token_count] | add // 0) == .tokens_used' \
                >/dev/null <"$HTTP_BODY"; then
                pass 'honest accounting: tokens_used equals the sum of returned result token_count values'
            else
                fail 'tokens_used does not equal the sum of returned result token_count values'
            fi

            # Grounded handler rule: it normally stays within budget, but keeps
            # one first hit even when that single document alone is oversized.
            if jq -e '
                (.tokens_used <= .tokens_available)
                or (
                    (.results | length) == 1
                    and .results[0].token_count == .tokens_used
                    and .tokens_used > .tokens_available
                )
            ' >/dev/null <"$HTTP_BODY"; then
                pass 'budget selection stayed within the ceiling or used the explicit single-oversized-first-hit rule'
            else
                fail 'returned result set violates the handler token-budget selection rule'
            fi
        fi
    else
        fail "POST /v1/query/text-search expected HTTP 200, got $HTTP_STATUS"
    fi
else
    fail "POST /v1/query/text-search could not connect to $CRUX_URL"
fi

if ((FAILURES > 0)); then
    exit 1
fi
