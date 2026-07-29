#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# check-execplan-drift.sh — verify every (decision|gate|milestone|incident)
# reference cited in PlanCrux ExecPlans resolves to an actual fact in the
# Crux daemon's fact store. Catches "memory says X exists" drift where a
# plan references a fact that was never stored or has been deleted.
#
# Usage:
#   bash scripts/check-execplan-drift.sh [<execplans-dir>]
#   bash scripts/check-execplan-drift.sh --self-test
#
# Env:
#   CORECRUXD_ADMIN_TOKEN — bearer for /v1/facts (required for live mode)
#   CRUX_HTTP_URL         — daemon URL (default: http://127.0.0.1:14800)
#   CRUX_DRIFT_STRICT     — if "1", daemon-unreachable is a hard fail
#                           (default: graceful skip with stderr warning)
#
# Exit codes:
#   0 — all references resolve, or daemon unreachable in non-strict mode
#   1 — one or more dangling references (printed to stderr)
#   2 — usage error / daemon unreachable in strict mode

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CRUX_HTTP_URL="${CRUX_HTTP_URL:-http://127.0.0.1:14800}"
STRICT="${CRUX_DRIFT_STRICT:-0}"

# ── Reference extraction ───────────────────────────────────────────────────
# Match (decision|gate|milestone|incident):<value> where <value> is a
# tightly-bounded slug. Filter post-hoc to skip template placeholders
# (incident:date, incident:YYYY-MM-DD, gate:M with no number, etc.).
REF_REGEX='(decision|gate|milestone|incident):[A-Za-z0-9._-][A-Za-z0-9._-]*'

is_placeholder() {
  case "$1" in
    incident:date|incident:YYYY-*|incident:*MM-DD*|gate:M|gate:Mn|milestone:M|milestone:Mn|decision:topic)
      return 0 ;;
    *)
      return 1 ;;
  esac
}

# ── Fact lookup ────────────────────────────────────────────────────────────
# Returns 0 if the fact exists (non-empty facts[]), 1 if dangling, 2 if the
# daemon is unreachable or auth-rejected.
fact_exists() {
  local entity="$1" key="$2"
  local url="${CRUX_HTTP_URL}/v1/facts?entity=$(url_encode "${entity}")&key=$(url_encode "${key}")&token_budget=500"
  local resp
  if ! resp="$(curl -fsS \
      --max-time 5 \
      -H "Authorization: Bearer ${CORECRUXD_ADMIN_TOKEN:-}" \
      "${url}" 2>/dev/null)"; then
    return 2
  fi
  # Empty facts array → dangling.
  if [ "$(echo "${resp}" | jq -r '.facts | length' 2>/dev/null || echo 0)" = "0" ]; then
    return 1
  fi
  return 0
}

# Minimal URL encoder for the few characters that actually appear in our
# entities and keys (colon, slash, dot, hyphen, alnum). curl --data-urlencode
# isn't ergonomic for GET; this stays correct for our regex-bound input.
url_encode() {
  local raw="$1"
  raw="${raw//%/%25}"
  raw="${raw//:/%3A}"
  raw="${raw// /%20}"
  echo "${raw}"
}

# ── Dangling plan-reference check (filesystem; no daemon) ──────────────────
# Verify every typed plan reference — `Superseded by [[slug]]`,
# `Depends on [[slug]]`, `Extended by [[slug]]` — resolves to a real
# <slug>.md in the same directory. Declaration lines only (keyword at the line
# start after optional >/-/* and bold markup), mirroring the
# work_execplans.rs parser so prose mentions are ignored. Only the `[[…]]` form
# is linted; bare-token targets are parser-accepted but not checked here.
check_plan_refs() {
  local plans_dir="$1"
  local dangling=0 checked=0
  local log
  log="$(mktemp)"

  shopt -s nullglob
  local plan_files=("${plans_dir}"/*.md)
  shopt -u nullglob

  local plan slug targets t
  for plan in "${plan_files[@]}"; do
    slug="$(basename "${plan}" .md)"
    # Declaration lines carrying a [[…]] group; pull every [[slug]] target,
    # split comma groups, one per line.
    targets="$(grep -E '^[[:space:]]*>?[[:space:]]*([-*][[:space:]]+)?\*{0,2}(Superseded by|Depends on|Extended by)[: ].*\[\[' "${plan}" 2>/dev/null \
      | grep -oE '\[\[[^]]+\]\]' \
      | sed -E 's/\[\[|\]\]//g' \
      | tr ',' '\n' || true)"
    [ -z "${targets}" ] && continue
    while IFS= read -r t; do
      t="$(printf '%s' "${t}" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
      [ -z "${t}" ] && continue
      checked=$((checked + 1))
      if [ ! -f "${plans_dir}/${t}.md" ]; then
        printf '%s\t%s\n' "${slug}" "${t}" >> "${log}"
        dangling=$((dangling + 1))
      fi
    done <<< "${targets}"
  done

  echo "plan-refs: checked ${checked} declared [[…]] links, dangling ${dangling}"
  if [ "${dangling}" -gt 0 ]; then
    echo "" >&2
    echo "Dangling plan references ([[slug]] with no matching <slug>.md):" >&2
    while IFS=$'\t' read -r slug t; do
      echo "  ${slug}: ${t}" >&2
    done < "${log}"
    rm -f "${log}"
    return 1
  fi
  rm -f "${log}"
  return 0
}

# ── Plan walker ────────────────────────────────────────────────────────────
walk_plans() {
  local plans_dir="$1"
  local dangling_count=0 checked_count=0 placeholder_count=0
  local dangling_log
  dangling_log="$(mktemp)"
  trap "rm -f '${dangling_log}'" RETURN

  shopt -s nullglob
  local plan_files=("${plans_dir}"/*.md)
  shopt -u nullglob

  if [ "${#plan_files[@]}" -eq 0 ]; then
    echo "no ExecPlans found in ${plans_dir}" >&2
    return 0
  fi

  for plan in "${plan_files[@]}"; do
    local slug
    slug="$(basename "${plan}" .md)"
    local entity="execplan:${slug}"

    # Extract refs, strip trailing punctuation (e.g. "gate:M3." at sentence
    # end → "gate:M3"; preserves internal dots like "gate:M5.5"), dedupe.
    local refs
    refs="$(grep -oE "${REF_REGEX}" "${plan}" 2>/dev/null | sed 's/\.$//' | sort -u || true)"
    [ -z "${refs}" ] && continue

    while IFS= read -r ref; do
      if is_placeholder "${ref}"; then
        placeholder_count=$((placeholder_count + 1))
        continue
      fi
      checked_count=$((checked_count + 1))
      if fact_exists "${entity}" "${ref}"; then
        :
      else
        local rc=$?
        if [ "${rc}" -eq 2 ]; then
          if [ "${STRICT}" = "1" ]; then
            echo "ERROR: daemon unreachable at ${CRUX_HTTP_URL} (strict mode)" >&2
            return 2
          fi
          echo "WARN: daemon unreachable at ${CRUX_HTTP_URL}; skipping live checks" >&2
          return 0
        fi
        printf '%s\t%s\n' "${slug}" "${ref}" >> "${dangling_log}"
        dangling_count=$((dangling_count + 1))
      fi
    done <<< "${refs}"
  done

  echo "checked: ${checked_count} refs, skipped: ${placeholder_count} placeholders, dangling: ${dangling_count}"
  if [ "${dangling_count}" -gt 0 ]; then
    echo "" >&2
    echo "Dangling references (cited in ExecPlans but no matching fact):" >&2
    while IFS=$'\t' read -r slug ref; do
      echo "  ${slug}: ${ref}" >&2
    done < "${dangling_log}"
    return 1
  fi
  return 0
}

# ── Self-test ──────────────────────────────────────────────────────────────
self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap "rm -rf '${tmp}'" RETURN

  cat > "${tmp}/good-plan-2026-05-20.md" <<'EOF'
# Good Plan

When complete, store decision:passport-routing and gate:M3.
Cross-reference incident:2026-05-15 if regressions appear.
EOF
  cat > "${tmp}/placeholder-plan-2026-05-20.md" <<'EOF'
# Placeholder

Template references: incident:YYYY-MM-DD, gate:M, decision:topic — all skipped.
EOF

  # Verify extraction (mirrors the live walk: strip trailing dot, dedupe).
  local refs_good refs_placeholder
  refs_good="$(grep -oE "${REF_REGEX}" "${tmp}/good-plan-2026-05-20.md" | sed 's/\.$//' | sort -u)"
  refs_placeholder="$(grep -oE "${REF_REGEX}" "${tmp}/placeholder-plan-2026-05-20.md" | sed 's/\.$//' | sort -u)"

  local expected_good=$'decision:passport-routing\ngate:M3\nincident:2026-05-15'
  if [ "${refs_good}" != "${expected_good}" ]; then
    echo "FAIL: extracted refs from good-plan differ from expected" >&2
    echo "  got:      ${refs_good}" >&2
    echo "  expected: ${expected_good}" >&2
    return 1
  fi

  # Placeholder filter.
  local skipped=0
  while IFS= read -r ref; do
    if is_placeholder "${ref}"; then
      skipped=$((skipped + 1))
    fi
  done <<< "${refs_placeholder}"
  if [ "${skipped}" -lt 2 ]; then
    echo "FAIL: placeholder filter rejected fewer than 2 refs (got ${skipped})" >&2
    return 1
  fi

  # url_encode contract.
  local enc
  enc="$(url_encode "execplan:foo")"
  if [ "${enc}" != "execplan%3Afoo" ]; then
    echo "FAIL: url_encode produced '${enc}', expected 'execplan%3Afoo'" >&2
    return 1
  fi

  # ── plan-ref dangling detection ──
  # good-plan-2026-05-20.md exists in ${tmp} (created above); the Extended-by
  # target does not. The prose line must NOT be linted.
  cat > "${tmp}/refsrc-2026-05-20.md" <<'EOF'
# Ref Source

> Depends on [[good-plan-2026-05-20]]
Extended by [[missing-xyz-2026-01-01]]
This milestone depends on [[should-not-be-linted]] in prose.
EOF
  if check_plan_refs "${tmp}" >/dev/null 2>&1; then
    echo "FAIL: check_plan_refs should flag the missing-xyz dangling ref" >&2
    return 1
  fi
  rm -f "${tmp}/refsrc-2026-05-20.md"

  cat > "${tmp}/refok-2026-05-20.md" <<'EOF'
# Ref OK

Depends on [[good-plan-2026-05-20]]
EOF
  if ! check_plan_refs "${tmp}" >/dev/null 2>&1; then
    echo "FAIL: check_plan_refs should pass when every [[…]] target resolves" >&2
    return 1
  fi
  rm -f "${tmp}/refok-2026-05-20.md"

  echo "self-test: PASS"
  return 0
}

# ── Main ───────────────────────────────────────────────────────────────────
main() {
  case "${1:-}" in
    --self-test)
      self_test
      ;;
    -h|--help)
      sed -n '1,30p' "${BASH_SOURCE[0]}"
      ;;
    *)
      local plans_dir="${1:-${ROOT}/../PlanCrux/.agent/execplans}"
      if [ ! -d "${plans_dir}" ]; then
        if [ "${STRICT}" = "1" ]; then
          echo "ERROR: execplans directory not found: ${plans_dir} (strict mode)" >&2
          exit 2
        fi
        echo "NOTICE: execplans directory not found: ${plans_dir}; skipping" >&2
        exit 0
      fi
      local rc=0
      check_plan_refs "${plans_dir}" || rc=1
      walk_plans "${plans_dir}" || rc=$?
      exit "${rc}"
      ;;
  esac
}

main "$@"
