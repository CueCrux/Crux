#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# setup-drift-guard.sh — one-shot installer for the ExecPlan board-drift guard on
# a fresh machine. Does two things:
#
#   1. Copies the two guard scripts into a stable per-user hooks dir
#      (${XDG_DATA_HOME:-$HOME/.local/share}/crux/hooks/) so agent configs can
#      point at a fixed path that survives repo moves.
#   2. Prints — does NOT auto-edit — the exact JSON snippets to merge into your
#      Claude Code `.claude/settings.json` and codex `.codex/hooks.json` so the
#      write-time guard (PostToolUse on store_fact) and the SessionStart status
#      sweep are wired.
#
# We never rewrite user agent configs from a script: merging into an existing
# `hooks` map is context-dependent (other hooks, matchers) and a bad merge is
# worse than a copy-paste. Print the snippet; the operator merges it.
#
# Usage:
#   bash scripts/setup-drift-guard.sh              # install + print snippets
#   bash scripts/setup-drift-guard.sh --print-only # print snippets, install nothing
#   bash scripts/setup-drift-guard.sh --self-test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/crux/hooks"
GUARD_SRC="${SCRIPT_DIR}/hooks/execplan-status-guard.sh"
SWEEP_SRC="${SCRIPT_DIR}/reconcile-execplan-status.sh"
GUARD_DST="${HOOKS_DIR}/execplan-status-guard.sh"
SWEEP_DST="${HOOKS_DIR}/reconcile-execplan-status.sh"

install_scripts() {
  mkdir -p "${HOOKS_DIR}"
  install -m 0755 "${GUARD_SRC}" "${GUARD_DST}"
  install -m 0755 "${SWEEP_SRC}" "${SWEEP_DST}"
  echo "Installed:"
  echo "  ${GUARD_DST}"
  echo "  ${SWEEP_DST}"
  echo
}

# Emit the Claude Code hooks fragment. Guard fires on the fully-qualified MCP
# tool name; the sweep runs quiet on SessionStart.
claude_snippet() {
  cat <<EOF
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "mcp__crux__store_fact",
        "hooks": [
          { "type": "command", "command": "${GUARD_DST}", "timeout": 5 }
        ]
      }
    ],
    "SessionStart": [
      {
        "matcher": "",
        "hooks": [
          { "type": "command", "command": "${SWEEP_DST} --quiet", "timeout": 5 }
        ]
      }
    ]
  }
}
EOF
}

# Emit the codex hooks fragment. Same shape; codex's MCP bridge exposes the tool
# under a bare `store_fact` suffix, so the matcher differs.
codex_snippet() {
  cat <<EOF
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "store_fact",
        "hooks": [
          { "type": "command", "command": "${GUARD_DST}", "timeout": 5 }
        ]
      }
    ],
    "SessionStart": [
      {
        "matcher": "",
        "hooks": [
          { "type": "command", "command": "${SWEEP_DST} --quiet", "timeout": 5 }
        ]
      }
    ]
  }
}
EOF
}

print_snippets() {
  echo "── Merge into .claude/settings.json (Claude Code) ──"
  claude_snippet
  echo
  echo "── Merge into .codex/hooks.json (codex) ──"
  codex_snippet
  echo
  echo "Note: merge the PostToolUse / SessionStart arrays into any existing"
  echo "'hooks' map — don't clobber hooks already wired there."
}

self_test() {
  local fails=0
  [[ -f "${GUARD_SRC}" ]] || { echo "FAIL guard source missing: ${GUARD_SRC}"; fails=$((fails+1)); }
  [[ -f "${SWEEP_SRC}" ]] || { echo "FAIL sweep source missing: ${SWEEP_SRC}"; fails=$((fails+1)); }
  if command -v jq >/dev/null 2>&1; then
    claude_snippet | jq -e '.hooks.PostToolUse[0].matcher == "mcp__crux__store_fact"' >/dev/null \
      && echo "ok   claude snippet valid JSON, correct matcher" \
      || { echo "FAIL claude snippet"; fails=$((fails+1)); }
    codex_snippet | jq -e '.hooks.PostToolUse[0].matcher == "store_fact"' >/dev/null \
      && echo "ok   codex snippet valid JSON, correct matcher" \
      || { echo "FAIL codex snippet"; fails=$((fails+1)); }
    claude_snippet | jq -e '.hooks.SessionStart[0].hooks[0].command | endswith("--quiet")' >/dev/null \
      && echo "ok   SessionStart runs the sweep --quiet" \
      || { echo "FAIL SessionStart wiring"; fails=$((fails+1)); }
  else
    echo "skip jq not present — snippet JSON not validated"
  fi
  [[ $fails -eq 0 ]] && echo "SELF-TEST PASS" || { echo "SELF-TEST FAIL ($fails)"; return 1; }
}

case "${1:-}" in
  --self-test)  self_test ;;
  --print-only) print_snippets ;;
  -h|--help)    sed -n '1,30p' "${BASH_SOURCE[0]}" ;;
  "")           install_scripts; print_snippets ;;
  *) echo "ERROR: unknown flag '$1'" >&2; exit 2 ;;
esac
