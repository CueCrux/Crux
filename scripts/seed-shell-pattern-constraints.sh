#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# seed-shell-pattern-constraints.sh — install the recommended baseline
# `shell_pattern` constraints into a running Crux daemon. Idempotent in
# spirit (each call appends a new constraint with a fresh UUID), but the
# matcher de-duplicates by behaviour — re-running is harmless apart from
# extra fact rows. To remove a baseline later, list with
# `get_constraints(constraint_type="shell_pattern")` and `delete_fact`
# the entity `__constraints__::<constraint_id>`.
#
# Patterns are warn-only at severity=medium by default. Operators raise
# specific ones to `high` or `critical` via separate `declare_constraint`
# calls.
#
# Usage:
#   bash scripts/seed-shell-pattern-constraints.sh
#
# Env:
#   CRUX_HTTP_URL          — HTTP base (default: http://127.0.0.1:14800)
#   CORECRUXD_ADMIN_TOKEN  — bearer for /v1/* (required)

set -euo pipefail

CRUX_HTTP_URL="${CRUX_HTTP_URL:-http://127.0.0.1:14800}"
TOKEN="${CORECRUXD_ADMIN_TOKEN:-}"
if [ -z "${TOKEN}" ]; then
  echo "ERROR: CORECRUXD_ADMIN_TOKEN not set" >&2
  exit 2
fi

# Each row: pattern\tdescription. Severity defaults to medium (warn).
# The Rust `regex` crate does not support lookaround, so patterns that
# would need "absent X" are reformulated as coarse positive matches the
# operator confirms case-by-case.
declare -a PATTERNS=(
  '^npx\s+(-y|--yes)\b	unattended npm package fetch'
  '^uvx\s+--from\s+git\+	uvx with git source (verify pin)'
  '@latest\b	unpinned @latest tag'
  '\bcurl\b[^|]*\|\s*(sh|bash)	pipe-to-shell installer'
  '--no-verify\b	commit hook bypass'
)

declare_one() {
  local pattern="$1" description="$2"
  local body
  body=$(jq -n \
    --arg ct "shell_pattern" \
    --arg as "${pattern}" \
    --arg sv "medium" \
    --arg ds "${description}" \
    '{constraint_type: $ct, assertion: $as, severity: $sv, description: $ds}')
  curl -fsS \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -X POST "${CRUX_HTTP_URL}/v1/tools/declare_constraint" \
    --data "${body}" | jq -r '.content[0].text // .'
}

# The declare_constraint HTTP route is the same as the MCP tool name; in
# the standard daemon HTTP surface this is `/v1/tools/{name}` (or, if your
# build only exposes MCP, route the same JSON through the MCP endpoint).
# The script tries the HTTP-tool path first and falls back to the MCP
# JSON-RPC path if the route 404s.

declare_via_mcp() {
  local pattern="$1" description="$2"
  local body
  body=$(jq -n \
    --arg ct "shell_pattern" \
    --arg as "${pattern}" \
    --arg sv "medium" \
    '{jsonrpc:"2.0", id:1, method:"tools/call", params:{name:"declare_constraint", arguments:{constraint_type:$ct, assertion:$as, severity:$sv}}}')
  curl -fsS \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -X POST "${CRUX_HTTP_URL/:14800/:14801}/mcp" \
    --data "${body}" | jq -r '.result.content[0].text // .result // .'
}

echo "==> seeding ${#PATTERNS[@]} baseline shell_pattern constraints into ${CRUX_HTTP_URL}"
for row in "${PATTERNS[@]}"; do
  pattern="${row%%	*}"
  description="${row#*	}"
  echo "  -> ${description}: /${pattern}/"
  if ! declare_one "${pattern}" "${description}" 2>/dev/null; then
    declare_via_mcp "${pattern}" "${description}"
  fi
done
echo "done. Verify with: curl -H \"Authorization: Bearer \$CORECRUXD_ADMIN_TOKEN\" \\"
echo "                     \"${CRUX_HTTP_URL/:14800/:14801}/mcp\" \\"
echo "                     -H 'Content-Type: application/json' \\"
echo "                     --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get_constraints\",\"arguments\":{\"constraint_type\":\"shell_pattern\"}}}'"
