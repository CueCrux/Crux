#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# reconcile-execplan-status.sh — one-shot Status-line-vs-derived-state sweep for
# the ExecPlan aggregator. Prints, does not mutate.
#
# Layer 3 of the board-drift guard: the daemon (derive_state) and the write-time
# store_fact hook already agree on state; this catches the residual drift where a
# plan's derived state is terminal (complete/archive — facts say it's done) but
# the plan .md's LEADING `Status:` token still reads non-terminal (In progress /
# Draft / Planned / Blocked / missing). Those plans need a one-line Status flip so
# the markdown reads the same as the board.
#
# The LEADING-token rule mirrors corecruxd declared_status()
# (crates/corecruxd/src/work_execplans.rs): only the first token of the Status
# value is authoritative — `Status: In progress (design complete)` is NON-terminal
# (a trailing-substring match on "complete" would false-negative the commonest
# drift shape).
#
# Usage:
#   bash scripts/reconcile-execplan-status.sh          # full report
#   bash scripts/reconcile-execplan-status.sh --quiet  # SessionStart mode: silent
#                                                       # when clean, one compact
#                                                       # line when plans need a flip
#   bash scripts/reconcile-execplan-status.sh --self-test
#
# Env:
#   CRUX_HTTP_URL         — daemon URL (default: http://127.0.0.1:14800)
#   CRUX_AGENT_TOKEN      — bearer for /v1/work?source=all. Under AuthMode::Off or
#                            DevScopes the X-Corecrux-Scopes header alone suffices;
#                            under JWT modes this must be a daemon-signed token with
#                            `admin:read` scope.
#   CRUX_EXECPLANS_ROOT   — plan dir; used to resolve <slug>.md when a work item
#                            carries no plan_path. Also the arg default.
#   CRUX_DRIFT_STRICT     — if "1", daemon-unreachable is a hard fail (exit 2);
#                            default is a graceful skip (exit 0), so SessionStart
#                            hooks never block on a down daemon.
#
# Exit codes:
#   0 — report printed (drift may exist; this is informational), OR daemon
#       unreachable in non-strict mode
#   2 — usage error, or daemon unreachable in strict mode
set -eo pipefail

CRUX_HTTP_URL="${CRUX_HTTP_URL:-http://127.0.0.1:14800}"
STRICT="${CRUX_DRIFT_STRICT:-0}"

# classify_status <status-value> → prints one of: terminal | nonterminal
# Mirrors the LEADING-token contract of corecruxd declared_status(): strip
# leading markup, take the first token, match against the completion/archive
# vocabulary. A trailing prose word cannot change the verdict. Same synonym set
# as the execplan-status-guard PostToolUse hook so hook, daemon, and sweep agree.
classify_status() {
  # Strip leading whitespace, blockquote arrows, list markers, bold asterisks,
  # and an optional `Status:` prefix; lowercase.
  local v="${1,,}"
  v="$(sed -E 's/^[[:space:]]*(>[[:space:]]*)*([-*][[:space:]]+)?(\*+)?([[:space:]]*status:[[:space:]]*)?//' <<<"$v")"
  case "$v" in
    complete*|completed*|code-complete*|superseded*|archived*|parked*|done*|deployed*|shipped*|landed*|merged*)
      echo terminal ;;
    *)
      echo nonterminal ;;
  esac
}

# leading_status <plan-file> → prints the raw trimmed Status value, or empty.
# First `Status:` line (bare or `> **Status:**`) in the first ~30 lines.
leading_status() {
  local f="$1" line
  line="$(head -30 "$f" 2>/dev/null | grep -iEm1 '^[[:space:]]*(>[[:space:]]*\*\*status:\*\*|>?[[:space:]]*\*{0,2}status:)' || true)"
  sed -E 's/^[[:space:]]*(>[[:space:]]*)*([-*][[:space:]]+)?(\*+)?[[:space:]]*[Ss][Tt][Aa][Tt][Uu][Ss]:[[:space:]]*(\*+)?[[:space:]]*//; s/[[:space:]]+$//' <<<"$line"
}

# fetch_work → echoes the /v1/work?source=all JSON to stdout, or returns 2 if the
# daemon is unreachable. WORK_JSON_FILE overrides the fetch for --self-test.
fetch_work() {
  if [[ -n "${WORK_JSON_FILE:-}" ]]; then
    cat "${WORK_JSON_FILE}"
    return 0
  fi
  curl -fsS --max-time 5 \
    -H "X-Corecrux-Scopes: admin:read" \
    -H "Authorization: Bearer ${CRUX_AGENT_TOKEN:-}" \
    "${CRUX_HTTP_URL}/v1/work?source=all" 2>/dev/null
}

# run_sweep <plan-root> → populates the global FLIP[] and INVERSE[] arrays.
# FLIP:    "<slug>\t<state>\t<path>\t<statusval>"  (terminal state, non-terminal Status → needs flip)
# INVERSE: "<slug>\t<state>\t<path>\t<statusval>"  (non-terminal state, terminal Status → facts missing, info)
declare -a FLIP=()
declare -a INVERSE=()
SCANNED=0
run_sweep() {
  local root="$1" work_json="$2"
  if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required." >&2
    exit 2
  fi
  local rows id state plan_path slug path sval cls
  rows="$(jq -r '.work[]? | select(.id | startswith("execplan:")) | [.id, .state, (.plan_path // "")] | @tsv' <<<"$work_json" 2>/dev/null || true)"
  [[ -z "$rows" ]] && return 0
  while IFS=$'\t' read -r id state plan_path; do
    [[ -z "$id" ]] && continue
    slug="${id#execplan:}"
    path="$plan_path"
    [[ -z "$path" && -n "$root" ]] && path="${root}/${slug}.md"
    [[ -f "$path" ]] || continue
    SCANNED=$((SCANNED + 1))
    sval="$(leading_status "$path")"
    cls="$(classify_status "$sval")"
    local disp="${sval:-<no Status: line>}"
    case "$state" in
      complete|archive)
        [[ "$cls" == nonterminal ]] && FLIP+=("${slug}"$'\t'"${state}"$'\t'"${path}"$'\t'"${disp}")
        ;;
      in_progress|planned|blocked)
        # Only flag inverse when the Status line actually exists and reads terminal.
        [[ "$cls" == terminal && -n "$sval" ]] && INVERSE+=("${slug}"$'\t'"${state}"$'\t'"${path}"$'\t'"${disp}")
        ;;
    esac
  done <<<"$rows"
  return 0
}

report_full() {
  printf '== ExecPlan Status ↔ derived-state reconciliation ==\n'
  printf 'Daemon URL        : %s\n' "${CRUX_HTTP_URL}"
  printf 'ExecPlan items    : %d scanned (execplan:* with a resolvable .md)\n' "${SCANNED}"
  printf 'Need Status flip  : %d (derived terminal, leading Status non-terminal)\n' "${#FLIP[@]}"
  printf 'Inverse (info)    : %d (leading Status terminal, derived in_progress — facts missing)\n' "${#INVERSE[@]}"
  printf '\n'
  if (( ${#FLIP[@]} > 0 )); then
    printf '── Flip this Status line ──\n'
    local slug state path sval
    while IFS=$'\t' read -r slug state path sval; do
      printf '  %s\n    derived: %s | Status reads: %s\n    %s\n' "$slug" "$state" "$sval" "$path"
    done < <(printf '%s\n' "${FLIP[@]}" | sort)
    printf '\n'
  fi
  if (( ${#INVERSE[@]} > 0 )); then
    printf '── Inverse drift (informational — facts missing, not a Status bug) ──\n'
    local slug state path sval
    while IFS=$'\t' read -r slug state path sval; do
      printf '  %s\n    derived: %s | Status reads: %s\n    %s\n' "$slug" "$state" "$sval" "$path"
    done < <(printf '%s\n' "${INVERSE[@]}" | sort)
    printf '\n'
  fi
  if (( ${#FLIP[@]} == 0 && ${#INVERSE[@]} == 0 )); then
    printf 'No drift.\n'
  fi
  return 0
}

report_quiet() {
  (( ${#FLIP[@]} == 0 )) && return 0
  local slugs=()
  local slug _rest
  while IFS=$'\t' read -r slug _rest; do slugs+=("$slug"); done < <(printf '%s\n' "${FLIP[@]}" | sort)
  printf 'execplan-status drift: %d plan(s) need a Status flip: %s\n' "${#FLIP[@]}" "${slugs[*]}"
}

main() {
  local quiet=0
  case "${1:-}" in
    --quiet) quiet=1 ;;
    -h|--help) sed -n '1,60p' "${BASH_SOURCE[0]}"; exit 0 ;;
    "") ;;
    *) echo "ERROR: unknown flag '$1' (expected --quiet / --self-test / --help)" >&2; exit 2 ;;
  esac

  local root="${CRUX_EXECPLANS_ROOT:-}"
  local work_json
  if ! work_json="$(fetch_work)" || [[ -z "$work_json" ]]; then
    if [[ "$STRICT" == "1" ]]; then
      echo "ERROR: daemon unreachable at ${CRUX_HTTP_URL} (strict mode)" >&2
      exit 2
    fi
    [[ "$quiet" == "1" ]] || echo "NOTICE: daemon unreachable at ${CRUX_HTTP_URL}; skipping status sweep" >&2
    exit 0
  fi

  run_sweep "$root" "$work_json"
  if [[ "$quiet" == "1" ]]; then report_quiet; else report_full; fi
  exit 0
}

self_test() {
  local tmp; tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  # Fixtures. Filenames double as plan_path targets in the canned work JSON.
  printf '# Fix widget\n\nStatus: In progress\n'                                   >"$tmp/drift-inprog.md"
  printf '# Fix widget\n\nStatus: In progress (design complete; deploy gated)\n'   >"$tmp/drift-trailer.md"
  printf '# Fix widget\n\nStatus: Complete\n'                                       >"$tmp/aligned-complete.md"
  printf '# Fix widget\n\n> **Status:** Superseded by [[next]]\n'                   >"$tmp/aligned-superseded.md"
  printf '# Fix widget\n\nSome preamble, no status line here.\n'                    >"$tmp/drift-nostatus.md"
  printf '# Fix widget\n\nStatus: Complete\n'                                       >"$tmp/inverse-facts-missing.md"

  cat >"$tmp/work.json" <<EOF
{"count":6,"source":"all","work":[
  {"id":"execplan:drift-inprog","state":"complete","plan_path":"$tmp/drift-inprog.md"},
  {"id":"execplan:drift-trailer","state":"archive","plan_path":"$tmp/drift-trailer.md"},
  {"id":"execplan:aligned-complete","state":"complete","plan_path":"$tmp/aligned-complete.md"},
  {"id":"execplan:aligned-superseded","state":"archive","plan_path":"$tmp/aligned-superseded.md"},
  {"id":"execplan:drift-nostatus","state":"complete","plan_path":"$tmp/drift-nostatus.md"},
  {"id":"execplan:inverse-facts-missing","state":"in_progress","plan_path":"$tmp/inverse-facts-missing.md"},
  {"id":"w_kanban_ignored","state":"complete"}
]}
EOF

  local fails=0
  check() { if [[ "$2" == "$3" ]]; then echo "ok   $1"; else echo "FAIL $1 (got '$2', want '$3')"; fails=$((fails+1)); fi; }

  # Unit: classifier leading-token contract.
  check "classify In progress"                        "$(classify_status 'In progress')"                        nonterminal
  check "classify 'In progress (design complete)'"    "$(classify_status 'In progress (design complete)')"      nonterminal
  check "classify Complete"                           "$(classify_status 'Complete')"                           terminal
  check "classify Superseded by [[x]]"                "$(classify_status 'Superseded by [[x]]')"                terminal
  check "classify Draft"                              "$(classify_status 'Draft')"                              nonterminal
  check "classify empty"                              "$(classify_status '')"                                   nonterminal

  # Unit: leading_status extraction skips trailer + reads blockquote form.
  check "leading trailer"    "$(leading_status "$tmp/drift-trailer.md")"     "In progress (design complete; deploy gated)"
  check "leading blockquote" "$(leading_status "$tmp/aligned-superseded.md")" "Superseded by [[next]]"

  # Integration: full sweep against canned JSON (no live daemon).
  FLIP=(); INVERSE=(); SCANNED=0
  run_sweep "$tmp" "$(cat "$tmp/work.json")"
  check "scanned count"   "$SCANNED"        6
  check "flip count"      "${#FLIP[@]}"     3
  check "inverse count"   "${#INVERSE[@]}"  1

  local flip_slugs; flip_slugs="$(printf '%s\n' "${FLIP[@]}" | cut -f1 | sort | tr '\n' ' ')"
  check "flip slugs" "$flip_slugs" "drift-inprog drift-nostatus drift-trailer "

  # Quiet-mode output shape.
  local q; q="$(report_quiet)"
  case "$q" in
    "execplan-status drift: 3 plan(s) need a Status flip: "*) echo "ok   quiet line" ;;
    *) echo "FAIL quiet line (got '$q')"; fails=$((fails+1)) ;;
  esac
  # Quiet mode silent when clean.
  FLIP=(); local q2; q2="$(report_quiet)"
  check "quiet clean silent" "$q2" ""

  [[ $fails -eq 0 ]] && echo "SELF-TEST PASS" || { echo "SELF-TEST FAIL ($fails)"; return 1; }
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  main "$@"
fi
