#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# deploy-train.sh — release train for the Crux Daemon, mirroring the serial
# merge-train idiom (.crux/merge-train.sh) but for the DEPLOY phase.
#
# It mints/updates a single per-host "train" fact in the Crux fact store and
# then wraps the EXISTING host deploy (scripts/crux-deploy.sh). Multiple
# ExecPlan slugs that ship in the same release JOIN one tag+restart: rather
# than each plan triggering its own daemon restart, they coalesce onto a
# shared `train:<tag>` fact and a single deploy/restart. The fact records who
# joined, which merge shas rode the train, and a monotonically-incrementing
# restart_count so a later joiner can see "already restarted on this tag".
#
# It is ADDITIVE operational tooling. It does NOT change daemon behaviour, it
# NEVER writes secrets, and it DOES NOT reinvent the deploy — crux-deploy.sh
# remains the single source of truth for pulling the image, recreating the
# service, and gating on the health/smoke probe.
#
# ── The train fact ──────────────────────────────────────────────────────────
#   PUT /v1/facts
#     entity = "deploy:<host>"
#     key    = "train:<tag>"
#     value  = JSON string of
#       { tag, status, execplans:[...], merge_shas:[...],
#         restart_count, holder_passport }
#
# Joining is idempotent w.r.t. a slug: re-running with the same slug does not
# duplicate it. `status` advances planned → deploying → deployed | failed.
#
# ── Usage ───────────────────────────────────────────────────────────────────
#   # Join the train for tag v0.5.22 with one or more ExecPlan slugs, then
#   # deploy (single restart shared by all joiners):
#   DEPLOY_TAG=v0.5.22 \
#   DEPLOY_EXECPLANS="token-burn-per-execplan,headroom-token-efficiency" \
#   DEPLOY_MERGE_SHAS="d432319,0d0d35b" \
#     bash scripts/deploy-train.sh
#
#   # Print the plan and the fact that WOULD be written, take no side effects:
#   DEPLOY_DRY_RUN=1 DEPLOY_TAG=v0.5.22 DEPLOY_EXECPLANS="foo" \
#     bash scripts/deploy-train.sh
#
#   # Join only (record intent on the train) without deploying yet:
#   DEPLOY_JOIN_ONLY=1 DEPLOY_TAG=v0.5.22 DEPLOY_EXECPLANS="foo" \
#     bash scripts/deploy-train.sh
#
# ── Environment ─────────────────────────────────────────────────────────────
#   DEPLOY_TAG          Release tag this train rides (required). Becomes the
#                       fact key suffix AND CRUX_IMAGE_TAG for crux-deploy.sh.
#   DEPLOY_EXECPLANS    Comma/space-separated ExecPlan slugs joining the train.
#   DEPLOY_MERGE_SHAS   Comma/space-separated merge shas on this train.
#   DEPLOY_HOST         Logical deploy host for the fact entity. Default: the
#                       short hostname (`hostname -s`).
#   DEPLOY_DRY_RUN      "1" ⇒ print the plan + fact, no fact write, no deploy.
#   DEPLOY_JOIN_ONLY    "1" ⇒ write/refresh the train fact, skip the deploy.
#   DEPLOY_BACKGROUND   "1" ⇒ launch crux-deploy.sh detached via the WSL-safe
#                       background triad (setsid+nohup+</dev/null+disown) and
#                       return immediately; logs to DEPLOY_LOG.
#   DEPLOY_LOG          Log file for a backgrounded deploy.
#                       Default: ./.crux-deploy-train-<tag>.log
#   DEPLOY_HOLDER_PASSPORT  Passport recorded as the train holder.
#                       Default: "$USER@$(hostname -s)".
#   CRUX_HTTP_URL       Daemon HTTP base. Default: http://127.0.0.1:14800
#   CORECRUXD_ADMIN_TOKEN   Bearer for /v1/facts. Empty under AuthMode::Off.
#   DEPLOY_SCRIPT       Path to the wrapped deploy script.
#                       Default: <this-dir>/crux-deploy.sh
#
# All remaining env (CRUX_COMPOSE_FILE, CRUX_SERVICE, CRUX_IMAGE, …) is passed
# straight through to crux-deploy.sh.
#
# Exit codes:
#   0 — fact written (and deploy succeeded, unless join-only / dry-run)
#   1 — deploy failed (fact marked status=failed)
#   2 — usage error (missing DEPLOY_TAG) / wrapped deploy script not found

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Configuration ───────────────────────────────────────────────────────────
DEPLOY_TAG="${DEPLOY_TAG:-}"
DEPLOY_HOST="${DEPLOY_HOST:-$(hostname -s 2>/dev/null || echo localhost)}"
DEPLOY_DRY_RUN="${DEPLOY_DRY_RUN:-0}"
DEPLOY_JOIN_ONLY="${DEPLOY_JOIN_ONLY:-0}"
DEPLOY_BACKGROUND="${DEPLOY_BACKGROUND:-0}"
DEPLOY_HOLDER_PASSPORT="${DEPLOY_HOLDER_PASSPORT:-${USER:-unknown}@${DEPLOY_HOST}}"
CRUX_HTTP_URL="${CRUX_HTTP_URL:-http://127.0.0.1:14800}"
DEPLOY_SCRIPT="${DEPLOY_SCRIPT:-${SCRIPT_DIR}/crux-deploy.sh}"
DEPLOY_LOG="${DEPLOY_LOG:-./.crux-deploy-train-${DEPLOY_TAG}.log}"

log() { printf '[deploy-train] %s\n' "$*"; }
err() { printf '[deploy-train] ERROR: %s\n' "$*" >&2; }

# ── Pre-flight ──────────────────────────────────────────────────────────────
if [ -z "${DEPLOY_TAG}" ]; then
  err "DEPLOY_TAG is required (the release tag this train rides)"
  exit 2
fi
command -v curl >/dev/null 2>&1 || { err "curl not found on PATH"; exit 2; }
if [ "${DEPLOY_DRY_RUN}" != "1" ] && [ "${DEPLOY_JOIN_ONLY}" != "1" ]; then
  if [ ! -x "${DEPLOY_SCRIPT}" ]; then
    err "wrapped deploy script not found / not executable: ${DEPLOY_SCRIPT}"
    exit 2
  fi
fi

ENTITY="deploy:${DEPLOY_HOST}"
KEY="train:${DEPLOY_TAG}"
FACT_URL="${CRUX_HTTP_URL}/v1/facts"

# ── List normalisation (comma OR whitespace separated → newline list) ───────
normalise_list() {
  printf '%s' "$1" | tr ',' '\n' | tr ' ' '\n' | sed '/^$/d'
}

# Read execplans/shas as newline lists (may be empty).
EXECPLANS_LIST="$(normalise_list "${DEPLOY_EXECPLANS:-}")"
MERGE_SHAS_LIST="$(normalise_list "${DEPLOY_MERGE_SHAS:-}")"

# ── JSON helpers ────────────────────────────────────────────────────────────
# Emit a JSON array of strings from a newline list on stdin.
json_array_from_lines() {
  awk 'BEGIN { printf "[" } { gsub(/"/,"\\\"",$0); printf "%s\"%s\"", (NR>1?",":""), $0 } END { print "]" }'
}

EXECPLANS_JSON="$(printf '%s\n' "${EXECPLANS_LIST}" | sed '/^$/d' | json_array_from_lines)"
MERGE_SHAS_JSON="$(printf '%s\n' "${MERGE_SHAS_LIST}" | sed '/^$/d' | json_array_from_lines)"

# ── Read the current train fact (to JOIN: merge slugs/shas, bump restarts) ──
# Returns the raw `value` string of the existing fact, or "" if none / no daemon.
current_train_value() {
  local resp
  if ! resp="$(curl -fsS --max-time 5 \
      -H "Authorization: Bearer ${CORECRUXD_ADMIN_TOKEN:-}" \
      "${FACT_URL}?entity=$(url_encode "${ENTITY}")&key=$(url_encode "${KEY}")&token_budget=500" \
      2>/dev/null)"; then
    return 0
  fi
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "${resp}" | jq -r '.facts[0].value // empty' 2>/dev/null || true
  fi
}

# Minimal URL encoder (matches check-execplan-drift.sh).
url_encode() {
  local raw="$1"
  raw="${raw//%/%25}"
  raw="${raw//:/%3A}"
  raw="${raw// /%20}"
  printf '%s' "${raw}"
}

# Build the new train value object, JOINING any existing fact. Prints the value
# JSON to stdout. Uses jq when available for a clean set-union join; otherwise
# falls back to this invocation's lists with restart_count=1.
build_train_value() {
  local status="$1"
  local prev_value
  prev_value="$(current_train_value)"

  if command -v jq >/dev/null 2>&1; then
    # restart_count bumps only when we actually (re)start, i.e. not join-only.
    local bump=0
    if [ "${DEPLOY_JOIN_ONLY}" != "1" ]; then bump=1; fi
    jq -cn \
      --arg tag "${DEPLOY_TAG}" \
      --arg status "${status}" \
      --arg holder "${DEPLOY_HOLDER_PASSPORT}" \
      --argjson new_execplans "${EXECPLANS_JSON}" \
      --argjson new_shas "${MERGE_SHAS_JSON}" \
      --argjson bump "${bump}" \
      --arg prev "${prev_value}" '
      ($prev | if . == "" then {} else (try fromjson catch {}) end) as $p
      | {
          tag: $tag,
          status: $status,
          execplans: (($p.execplans // []) + $new_execplans | unique),
          merge_shas: (($p.merge_shas // []) + $new_shas | unique),
          restart_count: (($p.restart_count // 0) + $bump),
          holder_passport: $holder
        }'
  else
    # jq-less fallback: no set-union with prior fact; record this run only.
    local rc=1
    if [ "${DEPLOY_JOIN_ONLY}" = "1" ]; then rc=0; fi
    printf '{"tag":"%s","status":"%s","execplans":%s,"merge_shas":%s,"restart_count":%s,"holder_passport":"%s"}\n' \
      "${DEPLOY_TAG}" "${status}" "${EXECPLANS_JSON}" "${MERGE_SHAS_JSON}" "${rc}" "${DEPLOY_HOLDER_PASSPORT}"
  fi
}

# PUT the train fact. `value` is a JSON STRING (StoreFact.value is String).
put_train_fact() {
  local value_json="$1"
  local body
  # Build the StoreFact body with the value object embedded as a string.
  if command -v jq >/dev/null 2>&1; then
    body="$(jq -cn --arg entity "${ENTITY}" --arg key "${KEY}" --arg value "${value_json}" \
      '{entity:$entity, key:$key, value:$value}')"
  else
    # Escape the value JSON for embedding as a JSON string literal.
    local esc="${value_json//\\/\\\\}"
    esc="${esc//\"/\\\"}"
    body="$(printf '{"entity":"%s","key":"%s","value":"%s"}' "${ENTITY}" "${KEY}" "${esc}")"
  fi
  curl -fsS --max-time 5 \
    -X PUT \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${CORECRUXD_ADMIN_TOKEN:-}" \
    --data-binary "${body}" \
    "${FACT_URL}" >/dev/null
}

# ── Plan summary ────────────────────────────────────────────────────────────
log "host         : ${DEPLOY_HOST}"
log "tag          : ${DEPLOY_TAG}"
log "fact         : entity=${ENTITY} key=${KEY}"
log "execplans    : $(printf '%s' "${EXECPLANS_LIST}" | tr '\n' ' ')"
log "merge_shas   : $(printf '%s' "${MERGE_SHAS_LIST}" | tr '\n' ' ')"
log "holder       : ${DEPLOY_HOLDER_PASSPORT}"
log "deploy script: ${DEPLOY_SCRIPT}"

# ── Dry-run: print the would-be fact and stop ───────────────────────────────
if [ "${DEPLOY_DRY_RUN}" = "1" ]; then
  log "DRY RUN — no fact write, no deploy. The train fact WOULD be:"
  build_train_value "deploying"
  log "DRY RUN — would invoke: CRUX_IMAGE_TAG=${DEPLOY_TAG} ${DEPLOY_SCRIPT}"
  exit 0
fi

# ── 1. JOIN the train: write/refresh the fact as 'deploying' ────────────────
TRAIN_VALUE="$(build_train_value "deploying")"
if put_train_fact "${TRAIN_VALUE}"; then
  log "train fact updated (status=deploying)"
else
  err "failed to write train fact to ${FACT_URL} — daemon down or auth rejected"
  exit 1
fi

# ── Join-only: intent recorded, do not deploy ───────────────────────────────
if [ "${DEPLOY_JOIN_ONLY}" = "1" ]; then
  log "JOIN ONLY — train fact recorded, skipping deploy. Run again without"
  log "DEPLOY_JOIN_ONLY=1 (or let the train captain run it) to restart."
  exit 0
fi

# ── 2. Run the wrapped deploy ───────────────────────────────────────────────
# crux-deploy.sh reads CRUX_IMAGE_TAG for the image to ship; map our tag onto it
# unless the operator overrode it explicitly.
export CRUX_IMAGE_TAG="${CRUX_IMAGE_TAG:-${DEPLOY_TAG}}"

run_deploy_foreground() {
  log "deploying via ${DEPLOY_SCRIPT} (CRUX_IMAGE_TAG=${CRUX_IMAGE_TAG}) ..."
  "${DEPLOY_SCRIPT}"
}

if [ "${DEPLOY_BACKGROUND}" = "1" ]; then
  # WSL-safe detach triad: setsid + nohup + </dev/null + disown. Bare `&` is
  # fragile under tty-detach (the deploy can be SIGHUP'd when the shell exits).
  log "launching deploy DETACHED → ${DEPLOY_LOG}"
  setsid nohup "${DEPLOY_SCRIPT}" </dev/null >"${DEPLOY_LOG}" 2>&1 &
  disown || true
  log "deploy launched in background (pid $!). Tail: tail -f ${DEPLOY_LOG}"
  log "NOTE: backgrounded — the train fact stays status=deploying until a"
  log "      follow-up run records the outcome. Watch ${DEPLOY_LOG}."
  exit 0
fi

if run_deploy_foreground; then
  # restart already counted on the 'deploying' write above; mark deployed
  # WITHOUT a second bump (DEPLOY_JOIN_ONLY=1 ⇒ bump=0).
  put_train_fact "$(DEPLOY_JOIN_ONLY=1 build_train_value "deployed")" || \
    err "deploy OK but failed to mark train fact deployed (non-fatal)"
  log "DEPLOY OK — train ${DEPLOY_TAG} on ${DEPLOY_HOST} marked deployed"
  exit 0
else
  rc=$?
  err "wrapped deploy failed (exit ${rc}) — marking train fact failed"
  put_train_fact "$(DEPLOY_JOIN_ONLY=1 build_train_value "failed")" || \
    err "also failed to mark train fact failed"
  exit 1
fi
