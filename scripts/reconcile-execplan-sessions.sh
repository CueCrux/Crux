#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# reconcile-execplan-sessions.sh — one-shot drift detector for the ExecPlan
# aggregator. Prints, does not mutate. The operator decides on cleanup.
#
# Reports three classes of drift between the on-disk plan tree and the
# Crux daemon's session registry:
#
#   1. Orphan sessions       — `execplan:<slug>` sessions in the registry
#                              that have NO corresponding `<slug>.md` file
#                              on disk. Candidates for `delete_session`.
#   2. Sessionless plans     — `<slug>.md` files with no matching session
#                              in the registry. Pure markdown plans that
#                              were never `save_session`'d (most plans).
#                              Informational; aggregator surfaces them
#                              automatically.
#   3. Unparsable plans     — files where `parse_plan` finds neither a
#                              `# Title` heading nor a `Risk class:` line.
#                              Likely scratch / WIP / non-conforming.
#                              Candidates for the `_<slug>.md` rename.
#
# Usage:
#   bash scripts/reconcile-execplan-sessions.sh [<execplans-dir>]
#
# Env:
#   CRUX_HTTP_URL         — daemon URL (default: http://127.0.0.1:14800)
#   CRUX_AGENT_TOKEN      — bearer for /v1/sessions/active. Under AuthMode::Off
#                            or DevScopes the X-Corecrux-Scopes header alone
#                            is enough; under JwtHs256/JwtJwks this must be a
#                            daemon-signed HS256 JWT with `admin:read` scope.
#                            See crux-console-data-plane-bridge memory for the
#                            mint procedure on the prod host.
#   CRUX_EXECPLANS_ROOT   — fallback for the plan dir when arg omitted
#
# Exit codes:
#   0 — report printed (orphans/unparsable may exist; this is informational)
#   2 — usage error or daemon unreachable

# Strict-but-not-paranoid: `set -u` interacts poorly with empty `declare -A`
# arrays accessed via `${arr[key]:-}` on bash 5.x, and this is a print-only
# diagnostic with no privilege escalation surface. Keep `-e` + `-o pipefail`
# to fail fast on real errors (curl non-zero, missing dir, etc.).
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRUX_HTTP_URL="${CRUX_HTTP_URL:-http://127.0.0.1:14800}"

PLAN_DIR="${1:-${CRUX_EXECPLANS_ROOT:-}}"

if [[ -z "${PLAN_DIR}" || ! -d "${PLAN_DIR}" ]]; then
  echo "ERROR: plan dir not found. Pass as arg or set CRUX_EXECPLANS_ROOT." >&2
  if [[ -n "${PLAN_DIR}" ]]; then
    echo "  Tried: ${PLAN_DIR}" >&2
  fi
  exit 2
fi

# ── Step 1: enumerate on-disk plan slugs ───────────────────────────────────
declare -A ON_DISK
for f in "${PLAN_DIR}"/*.md; do
  [[ -f "${f}" ]] || continue
  base="$(basename "${f}" .md)"
  # Match work_execplans::walk_execplans_root: skip underscore-prefixed
  # operator scratchpads (_cascade-m1-patch-…md etc.).
  [[ "${base}" == _* ]] && continue
  ON_DISK["${base}"]="${f}"
done
on_disk_count="${#ON_DISK[@]}"

# ── Step 2: fetch session registry ─────────────────────────────────────────
# /v1/sessions/active returns `{"sessions":[{"session_id":"…",…},…]}` per
# session.rs:219. Token is REQUIRED in JWT mode; falls back to X-Corecrux-Scopes
# under DevScopes; ignored under Off.
declare -A IN_REGISTRY
SESSIONS_REACHABLE=1
sessions_resp=""
if ! sessions_resp="$(curl -fsS \
    --max-time 5 \
    -H "X-Corecrux-Scopes: admin:read" \
    -H "Authorization: Bearer ${CRUX_AGENT_TOKEN:-}" \
    "${CRUX_HTTP_URL}/v1/sessions/active" 2>/dev/null)"; then
  SESSIONS_REACHABLE=0
fi

if [[ "${SESSIONS_REACHABLE}" == "1" && -n "${sessions_resp}" ]]; then
  # jq is the right tool but we can't assume it's installed on every host.
  # Fall back to a tight grep that extracts session_id strings.
  if command -v jq >/dev/null 2>&1; then
    mapfile -t ids < <(echo "${sessions_resp}" | jq -r '.sessions[]?.session_id // empty' 2>/dev/null)
  else
    mapfile -t ids < <(echo "${sessions_resp}" \
      | grep -oE '"session_id"[[:space:]]*:[[:space:]]*"[^"]+"' \
      | sed -E 's/.*"([^"]+)"$/\1/')
  fi
  for sid in "${ids[@]}"; do
    if [[ "${sid}" == execplan:* ]]; then
      slug="${sid#execplan:}"
      IN_REGISTRY["${slug}"]=1
    fi
  done
fi
registry_count="${#IN_REGISTRY[@]}"

# ── Step 3: classify ───────────────────────────────────────────────────────
declare -a ORPHANS=()        # registry only
declare -a SESSIONLESS=()    # on-disk only
declare -a UNPARSABLE=()    # on-disk but missing both title and risk class
declare -a AMBIGUOUS_STATUS=() # leading state token plus conflicting trailing state prose
declare -a BOTH=()           # registry + on-disk

for slug in "${!ON_DISK[@]}"; do
  if [[ -n "${IN_REGISTRY[${slug}]:-}" ]]; then
    BOTH+=("${slug}")
  else
    SESSIONLESS+=("${slug}")
  fi
  # Parse-quality probe: matches the cheap rules from work_execplans::parse_plan.
  content="$(cat "${ON_DISK[${slug}]}")"
  has_title=0; has_risk=0
  if grep -qE '^# .+' <<<"${content}"; then has_title=1; fi
  if grep -qiE '\*\*?Risk class:[[:space:]]*(low|medium|high)' <<<"${content}"; then has_risk=1; fi
  if [[ "${has_title}" == "0" && "${has_risk}" == "0" ]]; then
    UNPARSABLE+=("${slug}")
  fi
  # Print-only lint for the historical substring trap. A non-terminal leading
  # declaration containing a terminal state word later in its prose is valid
  # under the exact-token parser, but worth making visible to operators.
  if grep -qiE '^[[:space:]]*(>[[:space:]]*\*\*Status:\*\*|Status:)[[:space:]]*(Draft|In[ _]progress|Blocked|Parked|Planned|Backlog)\b.*\b(complete(d)?|archived|superseded)\b' <<<"${content}"; then
    AMBIGUOUS_STATUS+=("${slug}")
  fi
done

if [[ "${#IN_REGISTRY[@]}" -gt 0 ]]; then
  for slug in "${!IN_REGISTRY[@]}"; do
    if [[ -z "${ON_DISK[${slug}]:-}" ]]; then
      ORPHANS+=("${slug}")
    fi
  done
fi

# ── Step 4: print report ───────────────────────────────────────────────────
printf '== ExecPlan ↔ Session reconciliation ==\n'
printf 'Plan dir          : %s\n' "${PLAN_DIR}"
printf 'Daemon URL        : %s\n' "${CRUX_HTTP_URL}"
if [[ "${SESSIONS_REACHABLE}" == "0" ]]; then
  printf 'Session registry  : UNREACHABLE — orphan list will be empty (auth or daemon down)\n'
else
  printf 'Session registry  : %d entries (%d are execplan:*)\n' "$(echo "${sessions_resp}" | grep -oE '"session_id"' | wc -l || echo 0)" "${registry_count}"
fi
printf 'On-disk plans     : %d (after `_*.md` exclude)\n' "${on_disk_count}"
printf 'Both              : %d\n' "${#BOTH[@]}"
printf 'Sessionless plans : %d (info — aggregator picks these up via files alone)\n' "${#SESSIONLESS[@]}"
printf 'Orphan sessions   : %d (registry entry, no .md file — candidates for delete_session)\n' "${#ORPHANS[@]}"
printf 'Unparsable plans : %d (no title and no risk class — consider _<slug>.md scratch rename)\n' "${#UNPARSABLE[@]}"
printf 'Ambiguous Status : %d (safe exact-token parse; trailing terminal-state prose)\n' "${#AMBIGUOUS_STATUS[@]}"
printf '\n'

if (( ${#ORPHANS[@]} > 0 )); then
  printf '── Orphan sessions ──\n'
  printf '%s\n' "${ORPHANS[@]}" | sort
  printf '\n  To prune (review carefully first):\n'
  for slug in "${ORPHANS[@]}"; do
    printf '    mcp__crux__delete_session  session_id=execplan:%s\n' "${slug}"
  done
  printf '\n'
fi

if (( ${#UNPARSABLE[@]} > 0 )); then
  printf '── Unparsable plans ──\n'
  for slug in "${UNPARSABLE[@]}"; do
    printf '%s  (%s)\n' "${slug}" "${ON_DISK[${slug}]}"
  done | sort
  printf '\n  To rename to scratchpad (skips aggregator pickup):\n'
  for slug in "${UNPARSABLE[@]}"; do
    printf '    mv %q %q\n' "${ON_DISK[${slug}]}" "${PLAN_DIR}/_${slug}.md"
  done
  printf '\n'
fi

if (( ${#AMBIGUOUS_STATUS[@]} > 0 )); then
  printf '── Ambiguous Status lines (print-only lint) ──\n'
  for slug in "${AMBIGUOUS_STATUS[@]}"; do
    printf '%s  (%s)\n' "${slug}" "${ON_DISK[${slug}]}"
  done | sort
  printf '\n'
fi

exit 0
