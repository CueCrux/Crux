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
# Every key stored under one entity, newline-separated on stdout.
# 0 ok · 2 transport failure · 3 credential rejected · 4 other HTTP error.
#
# Two independent defects converge here, and the fix for each is load-bearing.
#
# Status separation: these used to be one status. `curl -f` exits non-zero for a
# 401 exactly as it does for a refused connection, so the caller reported an auth
# failure as "daemon unreachable" and, in the default non-strict mode, exited 0
# having verified nothing — a green run that checked no references at all.
# Unreachable is a legitimate "cannot run here" skip, a rejected credential is a
# misconfiguration that must never pass, and a lone 5xx should cost one reference
# rather than the entire sweep.
#
# Key filtering: `/v1/facts` has NO key filter. `QueryFactsParams` accepts
# query / entity / entity_prefix / top_k / token_budget and nothing else, so a
# `key=` parameter is silently discarded by the extractor (measured 2026-08-06 —
# `key=gate:M1` and `key=gate:NONSENSE` return byte-identical responses). Asking
# the daemon for one key therefore answered "does this entity have ANY fact",
# true for every plan that ever stored one, so every cited reference resolved and
# nothing was ever reported dangling. Filtering has to happen client-side.
#
# `top_k` and `token_budget` are set high deliberately: results fill by
# descending score until the budget is exhausted and the response carries no
# truncation flag, so a mean budget silently drops keys and manufactures
# "dangling" reports. A 5-fact entity returned 1 fact at budget 500 while
# reporting total_tokens 278 — i.e. under the budget it was given.
entity_keys() {
  local entity="$1"
  local url="${CRUX_HTTP_URL}/v1/facts?entity=$(url_encode "${entity}")&top_k=500&token_budget=200000"
  local out code body curl_rc=0
  # Deliberately no -f: we need the status code, not a collapsed exit status.
  out="$(curl -sS --max-time 10 -w '\n%{http_code}' \
      -H "Authorization: Bearer ${CORECRUXD_ADMIN_TOKEN:-}" \
      "${url}" 2>/dev/null)" || curl_rc=$?
  if [ "${curl_rc}" -ne 0 ]; then
    return 2                       # no connection / DNS / timeout
  fi
  code="${out##*$'\n'}"
  body="${out%$'\n'*}"
  case "${code}" in
    200) ;;
    401|403) return 3 ;;           # credential problem, not a reachability problem
    *) return 4 ;;                 # transient or unexpected: costs one ref, not the run
  esac
  printf '%s' "${body}" | jq -r '.facts[]?.key' 2>/dev/null || true
  return 0
}

# Returns 0 if the fact exists, 1 if dangling, and propagates entity_keys'
# 2/3/4 transport-and-status codes unchanged so the caller can still tell a
# skip from a misconfiguration.
fact_exists() {
  local entity="$1" key="$2"
  local keys rc=0
  keys="$(entity_keys "${entity}")" || rc=$?
  [ "${rc}" -ne 0 ] && return "${rc}"
  if printf '%s\n' "${keys}" | grep -qxF "${key}"; then
    return 0
  fi
  return 1
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

# ── Gate-fact vs Progress-checkbox drift ───────────────────────────────────
# The board derives a plan's state from `gate:M<n>` facts; humans read the
# `## Progress` checklist. They drift, and the checkbox is the one that rots.
#
# Two disagreements, and they fail in opposite directions:
#   ticked-but-ungated — the box says done, no gate fact exists. The BOARD
#     understates the plan. This is the 25-plans-at-in_progress-0/N population.
#   gated-but-unticked — the fact says done, the box does not. The FILE
#     understates it, and a human reading the plan re-does finished work.
#
# Report only, never mutate: which side is wrong is a judgement (a missing gate
# fact may mean the milestone genuinely did not happen), and a script that
# silently ticks boxes would manufacture exactly the false green this checks for.
#
# Opt-in (`--gates`) because it costs one daemon call per milestone: the corpus
# is ~1100 plans, so an unconditional run would add thousands of round-trips to
# a check that is otherwise cheap. Exact-key lookups are used deliberately
# rather than one entity-wide listing per plan: `/v1/facts` truncates to
# `token_budget` with no truncation flag in the response (measured 2026-08-06 —
# a 5-fact entity returned 1 fact at budget 500 while reporting total_tokens
# 278, i.e. *below* the budget), so a listing-based check would silently invent
# "ungated" milestones. A drift check that under-reads is worse than none.
extract_progress_boxes() {
  # → "<state>\t<milestone>" per line, where state is x (ticked) or o (not),
  # scoped to the `## Progress` section so checkboxes elsewhere are ignored.
  awk '
    /^##[[:space:]]+Progress/ { inprog = 1; next }
    /^##[[:space:]]/          { inprog = 0 }
    inprog                    { print }
  ' "$1" 2>/dev/null \
    | sed -nE 's/^[[:space:]]*[-*][[:space:]]*\[([ xX])\][[:space:]]*(M[0-9A-Za-z.]+).*/\1\t\2/p' \
    | sed -E 's/^[xX]\t/x\t/; s/^ \t/o\t/'
}

check_gate_checkbox_drift() {
  local plans_dir="$1"
  local plans=0 milestones=0 ticked_ungated=0 gated_unticked=0
  local log
  log="$(mktemp)"
  trap "rm -f '${log}'" RETURN

  shopt -s nullglob
  local plan_files=("${plans_dir}"/*.md)
  shopt -u nullglob

  local plan slug boxes state ms keys rc
  for plan in "${plan_files[@]}"; do
    boxes="$(extract_progress_boxes "${plan}")"
    [ -z "${boxes}" ] && continue
    slug="$(basename "${plan}" .md)"
    # One daemon call per plan, not per milestone: the keys are all in the same
    # entity, so fetching them once turns an O(milestones) walk over ~1100 plans
    # into O(plans).
    rc=0
    keys="$(entity_keys "execplan:${slug}")" || rc=$?
    if [ "${rc}" -eq 2 ]; then
      if [ "${STRICT}" = "1" ]; then
        echo "ERROR: daemon unreachable at ${CRUX_HTTP_URL} (strict mode)" >&2
        return 2
      fi
      echo "WARN: daemon unreachable at ${CRUX_HTTP_URL}; skipping gate-drift checks" >&2
      return 0
    fi
    plans=$((plans + 1))
    while IFS=$'\t' read -r state ms; do
      [ -z "${ms}" ] && continue
      milestones=$((milestones + 1))
      if printf '%s\n' "${keys}" | grep -qxF "gate:${ms}"; then
        if [ "${state}" = "o" ]; then
          printf '%s\t%s\tgated-but-unticked\n' "${slug}" "${ms}" >> "${log}"
          gated_unticked=$((gated_unticked + 1))
        fi
      elif [ "${state}" = "x" ]; then
        printf '%s\t%s\tticked-but-ungated\n' "${slug}" "${ms}" >> "${log}"
        ticked_ungated=$((ticked_ungated + 1))
      fi
    done <<< "${boxes}"
  done

  echo "gate-drift: ${plans} plans, ${milestones} milestones, ticked-but-ungated ${ticked_ungated}, gated-but-unticked ${gated_unticked}"
  if [ -s "${log}" ]; then
    echo "" >&2
    echo "Gate-fact / Progress-checkbox disagreements (report only):" >&2
    local s m kind
    while IFS=$'\t' read -r s m kind; do
      echo "  ${s}: ${m} ${kind}" >&2
    done < "${log}"
  fi
  # Advisory: a disagreement is a prompt to look, not a broken build. The
  # dangling-reference checks above still fail the run.
  return 0
}

# ── Plan walker ────────────────────────────────────────────────────────────
walk_plans() {
  local plans_dir="$1"
  local dangling_count=0 checked_count=0 placeholder_count=0 unchecked_count=0
  local dangling_log unchecked_log
  dangling_log="$(mktemp)"
  unchecked_log="$(mktemp)"
  trap "rm -f '${dangling_log}' '${unchecked_log}'" RETURN

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
        case "${rc}" in
          2)
            # Genuinely unreachable: a global condition, so stopping is right.
            if [ "${STRICT}" = "1" ]; then
              echo "ERROR: daemon unreachable at ${CRUX_HTTP_URL} (strict mode)" >&2
              return 2
            fi
            echo "WARN: daemon unreachable at ${CRUX_HTTP_URL}; skipping live checks" >&2
            return 0
            ;;
          3)
            # Always fatal, strict or not. A missing or mis-scoped token would
            # otherwise skip every check and report success, which is worse than
            # a red run because nobody learns the references were never verified.
            echo "ERROR: daemon rejected the credential (HTTP 401/403) at ${CRUX_HTTP_URL}" >&2
            echo "       CORECRUXD_ADMIN_TOKEN is unset, expired, or wrongly scoped." >&2
            echo "       Refusing to report success on unverified references." >&2
            return 2
            ;;
          4)
            # One bad response costs one reference, not the whole sweep.
            printf '%s\t%s\n' "${slug}" "${ref}" >> "${unchecked_log}"
            unchecked_count=$((unchecked_count + 1))
            continue
            ;;
        esac
        printf '%s\t%s\n' "${slug}" "${ref}" >> "${dangling_log}"
        dangling_count=$((dangling_count + 1))
      fi
    done <<< "${refs}"
  done

  echo "checked: ${checked_count} refs, skipped: ${placeholder_count} placeholders, dangling: ${dangling_count}, unchecked: ${unchecked_count}"
  local walk_rc=0
  if [ "${dangling_count}" -gt 0 ]; then
    echo "" >&2
    echo "Dangling references (cited in ExecPlans but no matching fact):" >&2
    while IFS=$'\t' read -r slug ref; do
      echo "  ${slug}: ${ref}" >&2
    done < "${dangling_log}"
    walk_rc=1
  fi
  if [ "${unchecked_count}" -gt 0 ]; then
    # Reported separately from dangling: "we could not look" is a different
    # claim from "we looked and it was not there", and silently merging the two
    # is how a partial run reads as a clean one.
    echo "" >&2
    echo "Could not check ${unchecked_count} reference(s) — HTTP error, NOT a missing fact:" >&2
    while IFS=$'\t' read -r slug ref; do
      echo "  ${slug}: ${ref}" >&2
    done < "${unchecked_log}"
    walk_rc=1
  fi
  return "${walk_rc}"
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

  # ── fact_exists status separation ──
  # The defect this guards: `curl -f` gave a 401 and a refused connection the
  # same exit status, so an auth failure was reported as "daemon unreachable"
  # and non-strict mode exited 0 having checked nothing. Nothing tested it,
  # which is why it survived. Each status is now pinned against a real socket.
  local port stub_pid stub_rc
  port=""
  for p in 24971 24972 24973 24974; do
    if ! (exec 3<>"/dev/tcp/127.0.0.1/${p}") 2>/dev/null; then port="${p}"; break; fi
  done
  if [ -z "${port}" ] || ! command -v python3 >/dev/null 2>&1; then
    echo "self-test: SKIP fact_exists status cases (no free port or no python3)" >&2
  else
    # A stub that answers by ENTITY: execplan:401 → rejected, execplan:500 →
    # other, anything else → a 200 carrying one fact keyed "x".
    #
    # Dispatch moved from `key=` to the entity when the key filter was removed
    # from the request: `/v1/facts` ignores `key=`, so the URL no longer carries
    # one. A stub still keying off it would answer 200 to every case and quietly
    # assert nothing — the same shape of vacuous green this block exists to stop.
    python3 - "${port}" <<'PYSTUB' &
import sys, http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        code = 401 if "%3A401" in self.path else 500 if "%3A500" in self.path else 200
        body = b'{"facts":[{"key":"x"}]}' if code == 200 else b'{}'
        self.send_response(code); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PYSTUB
    stub_pid=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null && break
      sleep 0.2
    done

    local saved_url="${CRUX_HTTP_URL}"
    CRUX_HTTP_URL="http://127.0.0.1:${port}"

    stub_rc=0; fact_exists "execplan:t" "x" || stub_rc=$?
    if [ "${stub_rc}" -ne 0 ]; then
      echo "FAIL: fact_exists must return 0 when the entity carries the key (got ${stub_rc})" >&2
      kill "${stub_pid}" 2>/dev/null; CRUX_HTTP_URL="${saved_url}"; return 1
    fi

    # The key-filter regression guard: the entity has a fact, but not THIS key.
    # Before the client-side filter this returned 0 for every key ever asked.
    stub_rc=0; fact_exists "execplan:t" "not-a-stored-key" || stub_rc=$?
    if [ "${stub_rc}" -ne 1 ]; then
      echo "FAIL: a key absent from a non-empty entity must be dangling (1), got ${stub_rc}" >&2
      kill "${stub_pid}" 2>/dev/null; CRUX_HTTP_URL="${saved_url}"; return 1
    fi

    stub_rc=0; fact_exists "execplan:401" "x" || stub_rc=$?
    if [ "${stub_rc}" -ne 3 ]; then
      echo "FAIL: a 401 must return 3 (credential), not ${stub_rc} — this is the original defect" >&2
      kill "${stub_pid}" 2>/dev/null; CRUX_HTTP_URL="${saved_url}"; return 1
    fi

    stub_rc=0; fact_exists "execplan:500" "x" || stub_rc=$?
    if [ "${stub_rc}" -ne 4 ]; then
      echo "FAIL: a 500 must return 4 (per-call), not ${stub_rc}" >&2
      kill "${stub_pid}" 2>/dev/null; CRUX_HTTP_URL="${saved_url}"; return 1
    fi

    kill "${stub_pid}" 2>/dev/null; wait "${stub_pid}" 2>/dev/null || true

    # Nothing listening now → transport failure, which must stay distinct from 3.
    stub_rc=0; fact_exists "execplan:t" "ok" || stub_rc=$?
    if [ "${stub_rc}" -ne 2 ]; then
      echo "FAIL: a refused connection must return 2 (unreachable), not ${stub_rc}" >&2
      CRUX_HTTP_URL="${saved_url}"; return 1
    fi
    CRUX_HTTP_URL="${saved_url}"
  fi

  # ── Progress-checkbox extraction ──
  # Scoped to `## Progress`: a checkbox in Milestones or Test plan must not be
  # read as milestone progress, or every plan with a task list reports drift.
  cat > "${tmp}/boxes-2026-08-06.md" <<'EOF'
# Boxes

## Milestones
- [x] M9 — a checkbox outside Progress, must be ignored

## Progress (keep updated)
- [x] M0 — recon
- [ ] M1 — not done
* [X] M2 — capital X, bullet is a star
- [ ] M3 — also not done

## Decision log
- [x] M8 — after Progress ends, must be ignored
EOF
  local got expected
  got="$(extract_progress_boxes "${tmp}/boxes-2026-08-06.md")"
  expected=$'x\tM0\no\tM1\nx\tM2\no\tM3'
  if [ "${got}" != "${expected}" ]; then
    echo "FAIL: Progress-box extraction differs from expected" >&2
    echo "  got:      $(printf '%s' "${got}" | tr '\n' '|')" >&2
    echo "  expected: $(printf '%s' "${expected}" | tr '\n' '|')" >&2
    return 1
  fi

  # A plan with no Progress section yields nothing (and is skipped, not flagged).
  if [ -n "$(extract_progress_boxes "${tmp}/good-plan-2026-05-20.md")" ]; then
    echo "FAIL: a plan with no Progress section must yield no boxes" >&2
    return 1
  fi

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
    --gates)
      # Opt-in gate-fact vs Progress-checkbox drift. Separate verb because it
      # costs one daemon call per milestone across the whole corpus.
      local gates_dir="${2:-${ROOT}/../PlanCrux/.agent/execplans}"
      if [ ! -d "${gates_dir}" ]; then
        echo "NOTICE: execplans directory not found: ${gates_dir}; skipping" >&2
        exit 0
      fi
      check_gate_checkbox_drift "${gates_dir}"
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
