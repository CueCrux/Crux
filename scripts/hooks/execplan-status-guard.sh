#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# execplan-status-guard.sh — PostToolUse hook for mcp__crux__store_fact.
#
# Stops ExecPlan board drift at write time: when a session stores a *terminal*
# fact for an ExecPlan (a close decision, or a plan-terminal gate) but the plan
# .md's `Status:` line still reads in_progress, exit 2 with a nag so the closing
# session flips the Status line while it still has context.
#
# Exit codes: 0 = fine / not our business / hook bug (never block real work),
#             2 = terminal fact stored but Status line disagrees.
#
# Trigger policy:
#   - `decision:close*` keys are the RELIABLE trigger — a close decision closes
#     the whole plan, so always check.
#   - `gate:*` keys are per-milestone. A mid-plan `gate:M2 passed` is NOT plan-
#     terminal, so nagging on every gate would false-positive on every milestone.
#     We only check a gate fact when it carries an explicit plan-terminal marker
#     (value `"plan_complete": true`, or a status containing "final").
#
# Synonym set mirrored from corecruxd is_complete_status()
# (Crux/crates/corecruxd/src/work_execplans.rs:409-419) so hook and daemon agree.
set -euo pipefail

# Colon-separated list of directory globs to search for <slug>.md. Overridable
# for --self-test. Primary path first, then a bounded per-repo fallback.
EXECPLAN_DIRS="${EXECPLAN_DIRS:-${CRUX_EXECPLANS_ROOT:-$HOME/CueCrux/*/.agent/execplans}}"

# is_done: mirror of is_complete_status — case-insensitive substring match on the
# synonym set, with `incomplete` excluded first.
is_done() {
  local s="${1,,}"
  [[ "$s" == *incomplete* ]] && return 1
  local t
  for t in complete passed pass done merged shipped deployed landed; do
    [[ "$s" == *"$t"* ]] && return 0
  done
  return 1
}

main() {
  local payload tn entity key status plancomplete
  payload="$(cat)"

  # Parse with jq; flatten value to (status, plan_complete). Any parse error -> 0.
  local parsed
  if ! parsed="$(jq -r '
        [ .tool_name // "",
          .tool_input.entity // "",
          .tool_input.key // "",
          (.tool_input.value | if type=="object" then (.status // "") else tostring end),
          (.tool_input.value | if type=="object" then (.plan_complete==true) else false end)
        ] | @tsv' <<<"$payload" 2>/dev/null)"; then
    exit 0
  fi
  IFS=$'\t' read -r tn entity key status plancomplete <<<"$parsed"

  # Suffix match: Claude Code names the tool mcp__crux__store_fact; codex's
  # MCP bridge may prefix differently. Any *store_fact is ours.
  [[ "$tn" == *store_fact ]] || exit 0
  [[ "$entity" == execplan:* ]] || exit 0

  # Decide whether this fact closes the WHOLE plan.
  local trigger=no
  if [[ "$key" == decision:close* ]]; then
    trigger=yes
  elif [[ "$key" == gate:* ]]; then
    # Plan-terminal gate only: explicit marker required.
    if [[ "$plancomplete" == "true" ]]; then
      trigger=yes
    elif [[ "${status,,}" == *final* ]] && is_done "$status"; then
      trigger=yes
    fi
  fi
  [[ "$trigger" == yes ]] || exit 0

  # Locate the plan file. Missing -> 0 (don't block on unknowns).
  local slug="${entity#execplan:}"
  local plan_path="" dir cand
  IFS=':' read -ra roots <<<"$EXECPLAN_DIRS"
  for dir in "${roots[@]}"; do
    for cand in $dir/"$slug".md; do
      [[ -f "$cand" ]] && { plan_path="$cand"; break 2; }
    done
  done
  [[ -n "$plan_path" ]] || exit 0

  # First Status: line in the first ~30 lines.
  local line
  line="$(head -30 "$plan_path" | grep -im1 '^[[:space:]]*Status:' || true)"
  # Already terminal? -> 0. Match the LEADING token only, like the daemon's
  # declared_status: `Status: In progress (design complete)` is NOT terminal —
  # a substring match on the trailer false-negatives on the most common drift
  # shape (work_execplans.rs: "only the leading Status token is authoritative").
  local val
  val="$(sed -E 's/^[[:space:]]*[Ss][Tt][Aa][Tt][Uu][Ss]:[[:space:]]*//' <<<"$line")"
  case "${val,,}" in
    complete*|completed*|superseded*|archived*|parked*|done*) exit 0 ;;
  esac

  line="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<<"$line")"
  echo "execplan-status-guard: $plan_path Status line still reads '$line' but you just stored a terminal fact ($key). Update the Status: line to match." >&2
  exit 2
}

self_test() {
  tmp="$(mktemp -d)"  # global so the EXIT trap can see it after this returns
  trap 'rm -rf "$tmp"' EXIT
  export EXECPLAN_DIRS="$tmp"
  printf '# Fix widget\n\nStatus: In progress\n' >"$tmp/inprog.md"
  printf '# Fix widget\n\nStatus: Complete\n'    >"$tmp/donefile.md"
  printf '# Fix widget\n\nStatus: In progress (design complete; deploy human-gated)\n' >"$tmp/trailer.md"

  local fails=0
  check() { # name expected payload
    set +e; echo "$3" | bash "$0"; local rc=$?; set -e
    if [[ $rc -eq $2 ]]; then echo "ok   $1 (exit $rc)"; else echo "FAIL $1 (exit $rc, want $2)"; fails=$((fails+1)); fi
  }

  check "a: close decision + In progress -> 2" 2 \
    '{"tool_name":"mcp__crux__store_fact","tool_input":{"entity":"execplan:inprog","key":"decision:close","value":{"status":"done"}}}'
  check "b: close decision + Complete -> 0" 0 \
    '{"tool_name":"mcp__crux__store_fact","tool_input":{"entity":"execplan:donefile","key":"decision:close","value":{"status":"done"}}}'
  check "c: mid-plan gate:M2 non-final -> 0" 0 \
    '{"tool_name":"mcp__crux__store_fact","tool_input":{"entity":"execplan:inprog","key":"gate:M2","value":{"status":"passed"}}}'
  check "d: non-execplan entity -> 0" 0 \
    '{"tool_name":"mcp__crux__store_fact","tool_input":{"entity":"bench:foo","key":"decision:close","value":{"status":"done"}}}'
  check "e: 'complete' in trailer, leading token In progress -> 2" 2 \
    '{"tool_name":"mcp__crux__store_fact","tool_input":{"entity":"execplan:trailer","key":"decision:close","value":{"status":"done"}}}'

  [[ $fails -eq 0 ]] && echo "SELF-TEST PASS" || { echo "SELF-TEST FAIL ($fails)"; return 1; }
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  main
fi
