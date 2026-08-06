#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# reconcile-execplan-status.sh — one-shot Status-line-vs-derived-state sweep for
# the ExecPlan aggregator. Prints by default; mutates only under --apply.
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
#   bash scripts/reconcile-execplan-status.sh --apply  # rewrite the drifted Status
#                                                       # lines in place (see below)
#   bash scripts/reconcile-execplan-status.sh --self-test
#
# --apply semantics (deliberately narrow):
#   * Only the FLIP set is touched — derived state is terminal (the daemon has
#     already decided the plan is done) and the .md's leading Status token is
#     not. The INVERSE set is NEVER auto-applied: there the markdown claims a
#     completion the board cannot corroborate, which is a missing-fact or
#     stale-mirror problem, not a Status-line bug. Guessing could close a live plan.
#   * Only the leading non-terminal token is replaced; every byte of trailing
#     prose (risk class, milestone notes, dates) is preserved. A line whose
#     leading token is outside the known vocabulary is SKIPPED, never guessed.
#   * A trailer reporting open PRs / operator gates / "N of M done" HOLDS the
#     flip: gate facts mean "milestone reached", not "merged".
#   * A plan with no Status: line gets one inserted after its first H1.
#   * No commit, no backup: these files live in git, so `git diff` is the review
#     surface and `git checkout` is the undo. Left dirty on purpose.
#   * Idempotent — a flipped plan is terminal next run, so it leaves the set.
#
# Env:
#   CRUX_HTTP_URL         — daemon URL (default: http://127.0.0.1:14800)
#   CRUX_AGENT_TOKEN      — bearer for /v1/work?source=all. Under AuthMode::Off or
#                            DevScopes the X-Corecrux-Scopes header alone suffices;
#                            under JWT modes this must be a daemon-signed token with
#                            `admin:read` scope. Falls back to the access_token in
#                            ~/.config/cuecrux/credentials.json so an unattended
#                            timer needs no secret in its unit file.
#   CRUX_EXECPLANS_ROOT   — plan dir; used to resolve <slug>.md when a work item
#                            carries no plan_path. Also the arg default.
#   CRUX_DRIFT_STRICT     — if "1", daemon-unreachable is a hard fail (exit 2);
#                            default is a graceful skip (exit 0), so SessionStart
#                            hooks never block on a down daemon.
#
# Exit codes:
#   0 — report printed (drift may exist; this is informational), OR daemon
#       unreachable in non-strict mode, OR --apply completed
#   2 — usage error, or daemon unreachable in strict mode
set -eo pipefail

CRUX_HTTP_URL_ENV="${CRUX_HTTP_URL:-}"
CRUX_HTTP_URL="${CRUX_HTTP_URL:-http://127.0.0.1:14800}"
STRICT="${CRUX_DRIFT_STRICT:-0}"

# Markup a Status declaration may carry before the `Status:` token: blockquote
# arrows, `- `/`* `/`1. ` list markers, bold. Shared by the detector, the value
# stripper (`leading_status`) and the rewriter (`flip_status_line`) so all three
# agree on what counts as a declaration.
STATUS_MARKUP='^[[:space:]]*(>[[:space:]]*)*([-*][[:space:]]+|[0-9]+\.[[:space:]]+)?\**'

# resolve_creds — fill CRUX_HTTP_URL / CRUX_AGENT_TOKEN from the corecruxctl
# credential store when the environment hasn't already supplied them. Lets a
# systemd timer run with an empty environment instead of a token pasted into a
# unit file. An explicit env var always wins; a missing/unreadable store is a
# no-op (the loopback default and header-only auth still work in dev modes).
resolve_creds() {
  local f="${XDG_CONFIG_HOME:-$HOME/.config}/cuecrux/credentials.json"
  [[ -r "$f" ]] || return 0
  command -v jq >/dev/null 2>&1 || return 0
  local url tok
  if [[ -z "$CRUX_HTTP_URL_ENV" ]]; then
    url="$(jq -r 'first(.daemons | to_entries[] | (.value.http_url // .key)) // empty' "$f" 2>/dev/null || true)"
    [[ -n "$url" ]] && CRUX_HTTP_URL="$url"
  fi
  if [[ -z "${CRUX_AGENT_TOKEN:-}" ]]; then
    tok="$(jq -r 'first(.daemons | to_entries[] | .value.access_token) // empty' "$f" 2>/dev/null || true)"
    [[ -n "$tok" ]] && CRUX_AGENT_TOKEN="$tok"
  fi
  return 0
}

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
    complete*|completed*|code-complete*|closed*|superseded*|archived*|parked*|done*|deployed*|shipped*|landed*|merged*)
      echo terminal ;;
    *)
      echo nonterminal ;;
  esac
}

# leading_status <plan-file> → prints the raw trimmed Status value, or empty.
# First `Status:` line (bare or `> **Status:**`) in the first ~30 lines.
leading_status() {
  local f="$1" line
  # CASE-SENSITIVE `Status:`, matching the daemon's parser
  # (work_execplans.rs `parse_plan`). The `-i` this used to carry made the sweep
  # disagree with the board: a lowercase `status: draft` in YAML frontmatter
  # matched first and shadowed the real declaration below it, so three plans
  # (corecrux-kv-compression, corecrux-kv-offload, llm-gate-completion) were
  # reported as "Status reads: draft" and counted as needing a flip while
  # actually declaring `Status: Parked` / `Status: Archived` correctly. A sweep
  # that reports drift the board does not see is worse than no sweep.
  #
  # The DETECTOR and the value-stripper below must accept the same markup set.
  # They did not: the stripper handled list markers and bold, the detector did
  # not, so a `- **Status:** Complete` line read as "no Status line" and the
  # sweep's inverse-drift check missed 2 of the 3 plans that needed a flip.
  # Same class of bug as the daemon's (work_execplans.rs `status_declaration`).
  # Markup accepted: blockquote arrows, `- `/`* `/`1. ` list markers, bold.
  # Hoisted to STATUS_MARKUP so `flip_status_line` targets exactly the line this
  # function reports on — a second copy here would reintroduce the very
  # detector/stripper split described above.
  local markup="$STATUS_MARKUP"
  line="$(head -30 "$f" 2>/dev/null | grep -Em1 "${markup}Status:" || true)"
  sed -E "s/${markup}Status:[[:space:]]*(\*+)?[[:space:]]*//; s/[[:space:]]+\$//" <<<"$line"
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
UNRESOLVED=0
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
    # plan_path is the DAEMON's absolute path (e.g. /srv/.../<slug>.md) and
    # usually doesn't exist on an operator machine. Use it only if it resolves
    # locally; otherwise fall back to ${root}/<slug>.md. A silent 100% miss (all
    # items skipped -> "No drift") is the worst failure mode for a drift
    # detector, so unresolvable items are counted, not quietly dropped.
    path=""
    if [[ -n "$plan_path" && -f "$plan_path" ]]; then
      path="$plan_path"
    elif [[ -n "$root" && -f "${root}/${slug}.md" ]]; then
      path="${root}/${slug}.md"
    fi
    if [[ -z "$path" ]]; then
      UNRESOLVED=$((UNRESOLVED + 1))
      continue
    fi
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

# Leading tokens we are willing to rewrite. Deliberately a closed vocabulary:
# anything outside it is skipped and reported rather than guessed at, because a
# wrong rewrite silently closes a live plan. Keep in sync with the NON-terminal
# side of classify_status() — no terminal word may appear here.
NONTERM_RE='[Ii]n[[:space:]_-]+([Pp]rogress|[Rr]eview)|[Dd]raft(ing)?|[Pp]lanned|[Bb]locked|[Aa]ctive|[Ww][Ii][Pp]|[Nn]ot[[:space:]_-]+started|[Tt][Oo][Dd][Oo]|[Oo]pen|[Pp]ending|[Pp]aused|[Oo]n[[:space:]_-]+hold|[Pp]roposed|[Rr]eady'

# Phrases in the Status TRAILER that mean the author believes work is still
# outstanding. The board derives terminal from gate FACTS, which record "the
# milestone was reached", not "it is merged" — so a plan can carry a full set of
# gates with PRs still open. When the human's own trailer says so, they win.
# ponytail: phrase heuristic over the line the author already wrote. The precise
# version resolves each `#<n>` against the forge; it needs a plan→repo mapping
# the .md does not carry, so build it only if this proves too coarse.
HOLD_RE='awaiting|unmerged|not[[:space:]]+yet[[:space:]]+merged|pr[s]?[[:space:]]+open|open[[:space:]]+pr|operator[[:space:]]+gate|pending[[:space:]]+(ci|review|merge|approval)|needs[[:space:]]+(merge|approval|sign-?off)|\bdraft\b'

# status_on_hold <status-value> → 0 when the trailer claims outstanding work.
# Two signals: the phrase list, and an explicit incomplete count — a trailer
# reading "2/9 done" states seven items remain, which no phrase would catch.
status_on_hold() {
  local v="$1" trailer frac n m
  # Examine the TRAILER only. The leading token is the declaration we intend to
  # rewrite — a plan reading plain "Draft" must stay flippable, while
  # "…#434 (npm OIDC provenance, DRAFT)" further along the line is a held PR.
  trailer="$(sed -E "s/^[[:space:]]*(${NONTERM_RE})//" <<<"$v")"
  grep -qiE "$HOLD_RE" <<<"$trailer" && return 0
  while read -r frac; do
    [[ -z "$frac" ]] && continue
    n="${frac%%/*}"
    m="${frac##*/}"; m="${m%%[^0-9]*}"
    [[ -n "$n" && -n "$m" ]] && (( n < m )) && return 0
  done < <(grep -oiE '[0-9]+/[0-9]+[[:space:]]+(done|complete|shipped|merged|landed)' <<<"$trailer" || true)
  return 1
}

# canonical_word <derived-state> → the terminal token to write.
# `archive` is reached by supersession OR by the stale-plan archive window, and
# the board row alone cannot say which, so we write the generic terminal word.
# ponytail: a plan naming a successor should read `Superseded by [[x]]` — flip
# that by hand; the sweep will not invent the edge.
canonical_word() {
  case "$1" in
    complete) echo Complete ;;
    archive)  echo Archived ;;
    *)        return 1 ;;
  esac
}

# flip_status_line <plan-file> <derived-state>
# Rewrites the plan's leading Status token in place. Returns 0 when the file
# changed, 1 when left alone (held / unknown token / unwritable). Prints the
# reason on skip.
flip_status_line() {
  local f="$1" state="$2" word ln line new at
  word="$(canonical_word "$state")" || { echo "unknown derived state '$state'"; return 1; }
  [[ -w "$f" ]] || { echo "not writable"; return 1; }
  if status_on_hold "$(leading_status "$f")"; then
    echo "trailer reports outstanding work (open PR / operator gate)"
    return 1
  fi

  # Case-SENSITIVE, same markup set as leading_status: this must target exactly
  # the line the sweep reported on. `|| true` because no match is an expected
  # path (plans with no Status: line) and pipefail would otherwise abort.
  ln="$(grep -nEm1 "${STATUS_MARKUP}Status:" "$f" | cut -d: -f1 || true)"

  if [[ -z "$ln" ]]; then
    # No Status: line — insert one after the first H1 (0 = top of file).
    at="$(grep -nEm1 '^#[[:space:]]' "$f" | cut -d: -f1 || true)"
    at="${at:-0}"
    { head -n "$at" "$f"; printf '\nStatus: %s\n' "$word"; tail -n +$((at + 1)) "$f"; } >"${f}.tmp" \
      && mv "${f}.tmp" "$f" || { rm -f "${f}.tmp"; echo "insert failed"; return 1; }
    return 0
  fi

  line="$(sed -n "${ln}p" "$f")"
  new="$(sed -E "s/(${STATUS_MARKUP}Status:[[:space:]]*(\*+)?[[:space:]]*)(${NONTERM_RE})/\1${word}/" <<<"$line")"
  if [[ "$new" == "$line" ]]; then
    echo "leading token not in the rewritable vocabulary"
    return 1
  fi
  # Splice by line number rather than sed -i so arbitrary plan prose
  # (backslashes, ampersands, slashes) can never be re-interpreted.
  { head -n $((ln - 1)) "$f"; printf '%s\n' "$new"; tail -n +$((ln + 1)) "$f"; } >"${f}.tmp" \
    && mv "${f}.tmp" "$f" || { rm -f "${f}.tmp"; echo "splice failed"; return 1; }
  return 0
}

# apply_flips → rewrites every FLIP entry, verifying each result now classifies
# terminal. One line per plan. Never touches INVERSE.
APPLIED=0
SKIPPED=0
apply_flips() {
  local slug state path sval reason
  if (( ${#FLIP[@]} == 0 )); then
    printf 'Nothing to apply.\n'
    return 0
  fi
  printf '── Applying %d Status flip(s) ──\n' "${#FLIP[@]}"
  while IFS=$'\t' read -r slug state path sval; do
    if reason="$(flip_status_line "$path" "$state")"; then
      # The point of the edit is that the plan now classifies the way the board
      # already does. If it does not, say so rather than count it a success.
      if [[ "$(classify_status "$(leading_status "$path")")" == terminal ]]; then
        APPLIED=$((APPLIED + 1))
        printf '  ✓ %-58s %s → %s\n' "$slug" "${sval:0:28}" "$(canonical_word "$state")"
      else
        SKIPPED=$((SKIPPED + 1))
        printf '  ! %-58s rewritten but still reads non-terminal — inspect\n' "$slug"
      fi
    else
      SKIPPED=$((SKIPPED + 1))
      printf '  – %-58s skipped: %s\n' "$slug" "$reason"
    fi
  done < <(printf '%s\n' "${FLIP[@]}" | sort)
  printf '\nApplied %d, skipped %d. Review with: git -C <plan repo> diff\n' "$APPLIED" "$SKIPPED"
  if (( ${#INVERSE[@]} > 0 )); then
    printf 'Left alone: %d inverse-drift plan(s) — Status claims done, board disagrees. Not auto-closable.\n' "${#INVERSE[@]}"
  fi
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
  if (( UNRESOLVED > 0 )); then
    printf '\nNOTE: %d execplan item(s) had no locally resolvable .md — set CRUX_EXECPLANS_ROOT\n' "${UNRESOLVED}"
    if (( SCANNED == 0 )); then
      printf '      (0 scanned: the sweep saw nothing — this is NOT a clean board)\n'
    fi
  fi
  return 0
}

report_quiet() {
  # Silent on unresolvables (boot noise) EXCEPT a 100% miss — 0 scanned while
  # items exist is the false-clean bug, so surface exactly that one case.
  if (( SCANNED == 0 && UNRESOLVED > 0 )); then
    printf 'execplan-status sweep: 0 of %d items had a locally resolvable .md — set CRUX_EXECPLANS_ROOT (board NOT verified)\n' "${UNRESOLVED}"
    return 0
  fi
  (( ${#FLIP[@]} == 0 )) && return 0
  local slugs=()
  local slug _rest
  while IFS=$'\t' read -r slug _rest; do slugs+=("$slug"); done < <(printf '%s\n' "${FLIP[@]}" | sort)
  printf 'execplan-status drift: %d plan(s) need a Status flip: %s\n' "${#FLIP[@]}" "${slugs[*]}"
}

main() {
  local quiet=0 apply=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --quiet) quiet=1 ;;
      --apply) apply=1 ;;
      -h|--help) sed -n '1,75p' "${BASH_SOURCE[0]}"; exit 0 ;;
      "") ;;
      *) echo "ERROR: unknown flag '$1' (expected --apply / --quiet / --self-test / --help)" >&2; exit 2 ;;
    esac
    shift
  done

  resolve_creds
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
  # A 100% resolve miss means the sweep saw nothing; applying then is a no-op
  # that reads like a clean board. Refuse rather than report success.
  if [[ "$apply" == "1" && "$SCANNED" -eq 0 ]]; then
    echo "ERROR: 0 of ${UNRESOLVED} items resolved to a local .md — refusing to apply (set CRUX_EXECPLANS_ROOT)" >&2
    exit 2
  fi
  if [[ "$apply" == "1" ]]; then
    report_full
    apply_flips
  elif [[ "$quiet" == "1" ]]; then
    report_quiet
  else
    report_full
  fi
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
  # Fixture reachable ONLY via the ${root}/<slug>.md fallback: its work item
  # carries a daemon-side plan_path that doesn't exist on this machine.
  printf '# Fix widget\n\nStatus: In progress\n'                                   >"$tmp/fallback-inprog.md"

  cat >"$tmp/work.json" <<EOF
{"count":7,"source":"all","work":[
  {"id":"execplan:drift-inprog","state":"complete","plan_path":"$tmp/drift-inprog.md"},
  {"id":"execplan:drift-trailer","state":"archive","plan_path":"$tmp/drift-trailer.md"},
  {"id":"execplan:aligned-complete","state":"complete","plan_path":"$tmp/aligned-complete.md"},
  {"id":"execplan:aligned-superseded","state":"archive","plan_path":"$tmp/aligned-superseded.md"},
  {"id":"execplan:drift-nostatus","state":"complete","plan_path":"$tmp/drift-nostatus.md"},
  {"id":"execplan:inverse-facts-missing","state":"in_progress","plan_path":"$tmp/inverse-facts-missing.md"},
  {"id":"execplan:fallback-inprog","state":"complete","plan_path":"/nonexistent/daemon/fallback-inprog.md"},
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

  # Unit: the DETECTOR must accept every markup form the stripper does. It did
  # not, and the resulting "no Status line" reading made the inverse-drift check
  # miss 2 of the 3 plans that needed a flip in the 2026-08-04 sweep.
  printf '# Fix widget\n\n**Status:** Complete\n'      >"$tmp/markup-bold.md"
  printf '# Fix widget\n\n- **Status:** Complete\n'    >"$tmp/markup-list.md"
  printf '# Fix widget\n\n1. **Status:** Complete\n'   >"$tmp/markup-ordered.md"
  check "leading bold"     "$(leading_status "$tmp/markup-bold.md")"    "Complete"
  check "leading list"     "$(leading_status "$tmp/markup-list.md")"    "Complete"
  check "leading ordered"  "$(leading_status "$tmp/markup-ordered.md")" "Complete"

  # Unit: case-sensitivity survives the widened markup — lowercase frontmatter
  # `status:` is metadata and must not shadow the declaration below it.
  printf -- '---\nstatus: draft\n---\n\n# Fix widget\n\nStatus: Parked — see follow-up\n' >"$tmp/markup-frontmatter.md"
  check "frontmatter not shadowing" "$(leading_status "$tmp/markup-frontmatter.md")" "Parked — see follow-up"

  # Unit: `Closed` is terminal, matching the daemon's declared_status vocabulary.
  check "classify Closed"  "$(classify_status 'Closed 2026-08-03 — all merged')" terminal

  # Integration: full sweep against canned JSON (no live daemon).
  # fallback-inprog resolves via ${root}/<slug>.md despite a dead plan_path.
  FLIP=(); INVERSE=(); SCANNED=0; UNRESOLVED=0
  run_sweep "$tmp" "$(cat "$tmp/work.json")"
  check "scanned count"      "$SCANNED"        7
  check "unresolved count"   "$UNRESOLVED"     0
  check "flip count"         "${#FLIP[@]}"     4
  check "inverse count"      "${#INVERSE[@]}"  1

  local flip_slugs; flip_slugs="$(printf '%s\n' "${FLIP[@]}" | cut -f1 | sort | tr '\n' ' ')"
  check "flip slugs (inc. fallback)" "$flip_slugs" "drift-inprog drift-nostatus drift-trailer fallback-inprog "

  # Quiet-mode output shape.
  local q; q="$(report_quiet)"
  case "$q" in
    "execplan-status drift: 4 plan(s) need a Status flip: "*) echo "ok   quiet line" ;;
    *) echo "FAIL quiet line (got '$q')"; fails=$((fails+1)) ;;
  esac
  # Quiet mode silent when clean.
  FLIP=(); local q2; q2="$(report_quiet)"
  check "quiet clean silent" "$q2" ""

  # All-unresolvable: every plan_path dead + no fixture at ${root}/<slug>.md.
  # This is the false-clean bug — must NOT read as clean.
  cat >"$tmp/allmiss.json" <<'EOF'
{"count":2,"source":"all","work":[
  {"id":"execplan:ghost-a","state":"complete","plan_path":"/nonexistent/a.md"},
  {"id":"execplan:ghost-b","state":"archive","plan_path":"/nonexistent/b.md"}
]}
EOF
  FLIP=(); INVERSE=(); SCANNED=0; UNRESOLVED=0
  run_sweep "$tmp/no-such-root" "$(cat "$tmp/allmiss.json")"
  check "allmiss scanned"    "$SCANNED"      0
  check "allmiss unresolved" "$UNRESOLVED"   2
  local qm; qm="$(report_quiet)"
  case "$qm" in
    "execplan-status sweep: 0 of 2 items had a locally resolvable .md"*) echo "ok   quiet 100%-miss warning" ;;
    *) echo "FAIL quiet 100%-miss warning (got '$qm')"; fails=$((fails+1)) ;;
  esac

  # ── --apply: rewrite contract ────────────────────────────────────────────
  # Trailing prose survives; only the leading token moves.
  printf '# P\n\n> **Status:** in progress** (2026-06-23). Risk class: **low** (a/b).\n' >"$tmp/ap-trailer.md"
  flip_status_line "$tmp/ap-trailer.md" complete >/dev/null
  check "apply keeps trailer" "$(leading_status "$tmp/ap-trailer.md")" \
    'Complete** (2026-06-23). Risk class: **low** (a/b).'
  check "apply → terminal" "$(classify_status "$(leading_status "$tmp/ap-trailer.md")")" terminal

  # Regex metacharacters in plan prose survive the splice verbatim.
  printf '# P\n\nStatus: Draft — path a\\b & c/d $x `y`\n' >"$tmp/ap-meta.md"
  flip_status_line "$tmp/ap-meta.md" archive >/dev/null
  check "apply preserves metachars" "$(leading_status "$tmp/ap-meta.md")" 'Archived — path a\b & c/d $x `y`'

  # Separator spellings are one token.
  local sep
  for sep in 'in_progress' 'in-progress' 'in progress' 'in_review'; do
    printf '# P\n\nStatus: %s — notes\n' "$sep" >"$tmp/ap-sep.md"
    flip_status_line "$tmp/ap-sep.md" complete >/dev/null
    check "separator '$sep'" "$(leading_status "$tmp/ap-sep.md")" "Complete — notes"
  done

  # Trailer hold: gate facts mean "reached", not "merged".
  printf '# P\n\nStatus: in_progress — nine done; PRs #70-#78 open, awaiting merge\n' >"$tmp/ap-hold.md"
  local held; held="$(cat "$tmp/ap-hold.md")"
  if flip_status_line "$tmp/ap-hold.md" complete >/dev/null; then
    echo "FAIL open-PR trailer should hold"; fails=$((fails+1)); else echo "ok   open-PR trailer holds"; fi
  check "held file untouched" "$(cat "$tmp/ap-hold.md")" "$held"
  check "hold: 2/9 done"  "$(status_on_hold 'in_progress — GATE re-audited: 2/9 done, 4 PRs' && echo y || echo n)" y
  check "hold: 9/9 done"  "$(status_on_hold 'in_progress — 9/9 done and merged' && echo y || echo n)" n
  check "hold: DRAFT pr"  "$(status_on_hold 'in_progress — #434 (npm OIDC, DRAFT)' && echo y || echo n)" y
  check "hold: plain"     "$(status_on_hold 'In progress — M4 gate PASSED' && echo y || echo n)" n

  # A lowercase frontmatter `status:` key is metadata, not the declaration; the
  # real `Status:` below it is what gets flipped (regression: the three kv/llm
  # plans this sweep once reported as needing a flip while already correct).
  printf -- '---\nversion: 0.1.0\nstatus: draft\n---\n\n# T\n\nStatus: In progress — n\n' >"$tmp/ap-fm.md"
  check "frontmatter not the declaration" "$(leading_status "$tmp/ap-fm.md")" "In progress — n"
  flip_status_line "$tmp/ap-fm.md" complete >/dev/null
  check "real Status flipped"      "$(leading_status "$tmp/ap-fm.md")" "Complete — n"
  check "frontmatter key untouched" "$(grep -c '^status: draft$' "$tmp/ap-fm.md")" 1

  # Unknown leading token is skipped, not guessed at; file untouched.
  printf '# P\n\nStatus: Marinating\n' >"$tmp/ap-unknown.md"
  local before; before="$(cat "$tmp/ap-unknown.md")"
  if flip_status_line "$tmp/ap-unknown.md" complete >/dev/null; then
    echo "FAIL unknown token should not rewrite"; fails=$((fails+1)); else echo "ok   unknown token skipped"; fi
  check "unknown token untouched" "$(cat "$tmp/ap-unknown.md")" "$before"

  # Missing Status line → inserted after the H1, body intact.
  printf '# Title\n\nBody line.\n' >"$tmp/ap-nostatus.md"
  flip_status_line "$tmp/ap-nostatus.md" complete >/dev/null
  check "insert when absent" "$(leading_status "$tmp/ap-nostatus.md")" "Complete"
  check "insert keeps body"  "$(grep -c 'Body line.' "$tmp/ap-nostatus.md")" 1

  # Idempotent: a flipped plan is terminal, so a second pass is a no-op.
  local once; once="$(cat "$tmp/ap-trailer.md")"
  flip_status_line "$tmp/ap-trailer.md" complete >/dev/null || true
  check "idempotent" "$(cat "$tmp/ap-trailer.md")" "$once"

  [[ $fails -eq 0 ]] && echo "SELF-TEST PASS" || { echo "SELF-TEST FAIL ($fails)"; return 1; }
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  main "$@"
fi
