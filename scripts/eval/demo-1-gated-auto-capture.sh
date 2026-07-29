#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Knock-out proved: #1 gated auto-capture — capture without a human calling a
# tool, but NEVER blindly. This is the M1 acceptance gate (ExecPlan
# crux-daemon-buyer-fit-buildout-2026-07-13):
#   1. a session transcript yields reviewable candidates (0-LLM deterministic);
#   2. POISON TEST — an extracted candidate is NEVER visible to recall
#      (GET /v1/facts) until promoted; it IS visible in the review queue;
#   3. FAIL-CLOSED — an unscored candidate cannot be auto-promoted;
#   4. ROUND-TRIP — explicit promote surfaces the fact in recall; reject keeps
#      another candidate out.
#
# Prereqs: a daemon at CRUX_URL with CORECRUXD_AUTO_CAPTURE=1, curl, jq.
# Env: CRUX_URL (default http://localhost:14800), CRUX_TOKEN (optional bearer).
set -euo pipefail

CRUX_URL="${CRUX_URL:-http://localhost:14800}"
CRUX_TOKEN="${CRUX_TOKEN:-}"
command -v jq >/dev/null || { echo "FAIL: jq required" >&2; exit 1; }

AUTH=()
[[ -n "$CRUX_TOKEN" ]] && AUTH=(-H "Authorization: Bearer $CRUX_TOKEN")
FAILURES=0
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; FAILURES=$((FAILURES + 1)); }

jcurl() { curl -sS "${AUTH[@]}" "$@"; }

# A transcript that mixes a real fact and a deliberately false ("poison") one.
TEXT='I currently drive a Tesla Model 3. I have three cats. I got pre-approved for a mortgage of $450,000. My previous occupation was a paramedic.'
POISON='person:user'

echo "── 1. extract candidates from a session transcript ──"
EXTRACT=$(jcurl -X POST "$CRUX_URL/v1/memory/extract" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg t "$TEXT" '{text:$t, session_id:"m1-gate", profile:"comprehensive"}')")
NCAND=$(echo "$EXTRACT" | jq '.written')
if [[ "${NCAND:-0}" -ge 2 ]]; then pass "extract produced $NCAND reviewable candidates"; else fail "expected >=2 candidates, got ${NCAND:-none}: $EXTRACT"; fi
# Pick a candidate id (the mortgage/money one is a good promote target).
CID=$(echo "$EXTRACT" | jq -r '.candidates[0].candidate_id')
[[ -n "$CID" && "$CID" != "null" ]] && pass "candidate id resolved ($CID)" || fail "no candidate id"

echo "── 2. POISON TEST: candidates are invisible to recall ──"
# Every extracted proposed fact must be ABSENT from normal recall.
LEAK=0
for key in $(echo "$EXTRACT" | jq -r '.candidates[].proposed_key'); do
  HITS=$(jcurl "$CRUX_URL/v1/facts?query=$key&top_k=20&token_budget=1000" | jq '[.facts[] | select(.entity=="'"$POISON"'")] | length')
  [[ "${HITS:-0}" -gt 0 ]] && { LEAK=$((LEAK+1)); echo "  leaked: $key ($HITS in recall)"; }
done
[[ "$LEAK" -eq 0 ]] && pass "no extracted candidate leaked into GET /v1/facts recall (poison contained)" || fail "$LEAK candidate(s) leaked into recall BEFORE promotion"
# ...but they ARE in the review queue.
QUEUE=$(jcurl "$CRUX_URL/v1/memory/candidates?status=candidate" | jq '.count')
[[ "${QUEUE:-0}" -ge 2 ]] && pass "candidates visible in the review queue ($QUEUE pending)" || fail "review queue empty/short ($QUEUE)"

echo "── 3. FAIL-CLOSED: unscored candidate cannot be auto-promoted ──"
CODE=$(jcurl -o /dev/null -w '%{http_code}' -X POST "$CRUX_URL/v1/memory/candidates/$CID/promote" \
  -H 'Content-Type: application/json' -d '{"auto_threshold":0.5}')
[[ "$CODE" == "422" ]] && pass "auto-promote of an unscored candidate refused (HTTP 422, fail-closed)" || fail "expected 422 for unscored auto-promote, got $CODE"

echo "── 4. ROUND-TRIP: explicit promote reaches recall; reject stays out ──"
PKEY=$(echo "$EXTRACT" | jq -r '.candidates[0].proposed_key')
PVAL=$(echo "$EXTRACT" | jq -r '.candidates[0].proposed_value')
jcurl -X POST "$CRUX_URL/v1/memory/candidates/$CID/promote" -H 'Content-Type: application/json' \
  -d '{"reviewer":"gate-test"}' | jq -e '.status=="promoted"' >/dev/null \
  && pass "explicit promote accepted" || fail "explicit promote failed"
# The promoted fact is now recallable.
FOUND=$(jcurl "$CRUX_URL/v1/facts?query=$PKEY&top_k=20&token_budget=1000" \
  | jq '[.facts[] | select(.entity=="'"$POISON"'" and .key=="'"$PKEY"'" and .value=="'"$PVAL"'")] | length')
[[ "${FOUND:-0}" -ge 1 ]] && pass "promoted fact ($PKEY=$PVAL) is now in recall" || fail "promoted fact not found in recall"
# Reject a second candidate; it must stay out of recall.
CID2=$(echo "$EXTRACT" | jq -r '.candidates[1].candidate_id')
RKEY=$(echo "$EXTRACT" | jq -r '.candidates[1].proposed_key')
jcurl -X POST "$CRUX_URL/v1/memory/candidates/$CID2/reject" -H 'Content-Type: application/json' \
  -d '{"reason":"gate-test rejection"}' | jq -e '.status=="rejected"' >/dev/null \
  && pass "reject accepted" || fail "reject failed"
RHITS=$(jcurl "$CRUX_URL/v1/facts?query=$RKEY&top_k=20&token_budget=1000" | jq '[.facts[] | select(.entity=="'"$POISON"'" and .key=="'"$RKEY"'")] | length')
[[ "${RHITS:-0}" -eq 0 ]] && pass "rejected candidate stayed out of recall" || fail "rejected candidate leaked into recall"

echo
if ((FAILURES > 0)); then echo "AUTO-CAPTURE GATE: FAILED ($FAILURES)"; exit 1; fi
echo "AUTO-CAPTURE GATE: OK"
