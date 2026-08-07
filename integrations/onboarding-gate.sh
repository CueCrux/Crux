#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.
#
# The M6.4 gate: from a CLEAN profile, does ONE command per agent reach first
# recall?
#
# Each agent gets a throwaway $HOME, so "clean profile" is literal rather than
# "clean enough". The script follows exactly the command each README documents
# -- if a README drifts from the binary, this fails.
#
#   ./integrations/onboarding-gate.sh
#   CORECRUXD_BIN=... CORECRUXCTL_BIN=... ./integrations/onboarding-gate.sh

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
daemon_bin="${CORECRUXD_BIN:-$repo_root/target/debug/corecruxd}"
ctl_bin="${CORECRUXCTL_BIN:-$repo_root/target/debug/corecruxctl}"
# Free ports chosen at runtime, not fixed: a fixed port collides with any
# other daemon on the box and turns a real gate into a flake.
read -r port grpc_port mcp_port <<<"$(python3 - <<'PYPORTS'
import socket
def free():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
print(free(), free(), free())
PYPORTS
)"
base_url="http://127.0.0.1:${port}"
data_dir="$(mktemp -d)"
daemon_pid=""
status=0

cleanup() {
  [[ -n "$daemon_pid" ]] && kill "$daemon_pid" 2>/dev/null || true
  rm -rf "$data_dir"
}
trap cleanup EXIT

for bin in "$daemon_bin" "$ctl_bin"; do
  [[ -x "$bin" ]] || { echo "missing binary: $bin (cargo build -p corecruxd -p corecruxctl)" >&2; exit 1; }
done

echo "starting daemon on ${base_url}"
CORECRUXD_AUTH_MODE=off CORECRUXD_DATA_DIR="$data_dir" \
CORECRUXD_HTTP_PORT="$port" CORECRUXD_GRPC_PORT="$grpc_port" \
CORECRUXD_MCP_PORT="$mcp_port" \
  "$daemon_bin" >"${data_dir}/daemon.log" 2>&1 &
daemon_pid=$!

for _ in $(seq 1 60); do
  curl -fsS -o /dev/null "${base_url}/readyz" 2>/dev/null && break
  sleep 1
done
curl -fsS -o /dev/null "${base_url}/readyz" || {
  echo "daemon never became ready" >&2; tail -20 "${data_dir}/daemon.log" >&2; exit 1;
}
echo "daemon ready"

# The proof that the wiring is worth anything: a fact stored before onboarding
# must come back afterwards, through the endpoint the agent was pointed at.
curl -fsS -X PUT "${base_url}/v1/facts" -H 'Content-Type: application/json' \
  -d '{"entity":"onboarding:gate","key":"first-recall","value":"the daemon remembered this"}' \
  >/dev/null
echo "seeded a fact to recall"

check_agent() {
  local agent="$1" expect_path="$2"
  local fake_home; fake_home="$(mktemp -d)"
  echo
  echo "── ${agent} ──────────────────────────────────────────"
  echo "  clean HOME: ${fake_home}"

  # THE one-liner, exactly as the README documents it.
  if ! HOME="$fake_home" "$ctl_bin" start --agent "$agent" --url "$base_url" \
      >"${fake_home}/start.log" 2>&1; then
    echo "  FAIL: start --agent ${agent} exited non-zero"
    sed 's/^/    /' "${fake_home}/start.log"
    status=1
    rm -rf "$fake_home"
    return
  fi

  local target="${fake_home}/${expect_path}"
  if [[ ! -s "$target" ]]; then
    echo "  FAIL: expected ${expect_path} to be written"
    sed 's/^/    /' "${fake_home}/start.log"
    status=1
    rm -rf "$fake_home"
    return
  fi
  echo "  ok   wrote ${expect_path}"

  # No agent config may carry bearer material -- the token belongs in
  # ~/.config/cuecrux/env (0600), not in a file the user syncs between machines.
  if grep -qiE 'authorization|bearer|CRUX_AGENT_TOKEN' "$target"; then
    echo "  FAIL: ${expect_path} contains bearer material"
    status=1
  else
    echo "  ok   no bearer material in ${expect_path}"
  fi

  # First recall, through the endpoint onboarding configured.
  local configured
  configured="$(grep -E '^CRUX_HTTP_URL=' "${fake_home}/.config/cuecrux/env" 2>/dev/null | cut -d= -f2- || true)"
  if [[ -z "$configured" ]]; then
    echo "  FAIL: onboarding did not record CRUX_HTTP_URL"
    status=1
    rm -rf "$fake_home"
    return
  fi
  if curl -fsS "${configured}/v1/facts?query=first-recall&token_budget=500" \
      | grep -q "the daemon remembered this"; then
    echo "  ok   first recall via ${configured}"
  else
    echo "  FAIL: first recall returned nothing from ${configured}"
    status=1
  fi

  rm -rf "$fake_home"
}

check_agent claude ".claude/settings.json"
check_agent codex  ".codex/config.toml"
check_agent cursor ".cursor/mcp.json"

echo
if [[ $status -ne 0 ]]; then
  echo "onboarding gate: FAILED"
else
  echo "onboarding gate: every agent reaches first recall from one command"
fi
exit $status
