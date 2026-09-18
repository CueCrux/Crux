#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Stable Codex PreToolUse launcher for `crux-hook observe-pre`.
#
# Concurrent writers must start Codex with distinct authenticated agent tokens.
# The process environment takes precedence over the shared CueCrux env so one
# machine can run multiple isolated Codex workers without collapsing them onto
# the fallback `openai` passport.

set -uo pipefail

process_agent_name="${CRUX_CODEX_AGENT_NAME:-}"
process_agent_token="${CRUX_AGENT_TOKEN:-}"
process_mcp_url="${CRUX_MCP_URL:-}"
process_token_dir="${CRUX_AGENT_TOKEN_DIR:-}"
process_observe_capture="${CRUX_HOOK_OBSERVE_CAPTURE:-}"

env_file="${CRUX_HOOKS_ENV:-$HOME/.config/cuecrux/env}"
if [ -f "$env_file" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$env_file" 2>/dev/null || true
  set +a
fi

if [ -n "$process_agent_name" ]; then
  CRUX_CODEX_AGENT_NAME="$process_agent_name"
fi
if [ -n "$process_mcp_url" ]; then
  CRUX_MCP_URL="$process_mcp_url"
  export CRUX_MCP_URL
fi
if [ -n "$process_token_dir" ]; then
  CRUX_AGENT_TOKEN_DIR="$process_token_dir"
  export CRUX_AGENT_TOKEN_DIR
fi
if [ -n "$process_observe_capture" ]; then
  CRUX_HOOK_OBSERVE_CAPTURE="$process_observe_capture"
  export CRUX_HOOK_OBSERVE_CAPTURE
fi
agent_name="${CRUX_CODEX_AGENT_NAME:-openai}"
case "$agent_name" in
  *[!A-Za-z0-9._-]*|'')
    echo "crux: invalid CRUX_CODEX_AGENT_NAME; apply_patch enforcement unavailable" >&2
    exit 0
    ;;
esac
if [ "${#agent_name}" -gt 64 ]; then
  echo "crux: invalid CRUX_CODEX_AGENT_NAME; apply_patch enforcement unavailable" >&2
  exit 0
fi
export CRUX_CODEX_AGENT_NAME="$agent_name"

if [ -n "$process_agent_token" ]; then
  CRUX_AGENT_TOKEN="$process_agent_token"
else
  # Never inherit the shared env's generic token for a named worker. That
  # would collapse distinct Codex processes onto one authenticated passport.
  unset CRUX_AGENT_TOKEN
  token_dir="${CRUX_AGENT_TOKEN_DIR:-$HOME/.config/cuecrux/crux-tokens}"
  token_file="${token_dir}/${agent_name}.mcp-token"
  if [ ! -f "$token_file" ]; then
    echo "crux: token for Codex agent '$agent_name' is unavailable; apply_patch enforcement is fail-open" >&2
    exit 0
  fi
  CRUX_AGENT_TOKEN="$(tr -d ' \r\n' < "$token_file" 2>/dev/null)" || exit 0
fi

if [ -z "$CRUX_AGENT_TOKEN" ]; then
  echo "crux: empty Codex agent token; apply_patch enforcement is fail-open" >&2
  exit 0
fi
export CRUX_AGENT_TOKEN

exec "$HOME/.local/bin/crux-hook" observe-pre
