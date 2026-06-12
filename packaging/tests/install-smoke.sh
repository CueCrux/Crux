#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# Clean-VM install smoke test (release-gate criterion: scripted install →
# daemon ready → MCP handshake → uninstall, on a machine that has never seen
# Crux). Run this ON the clean VM (Ubuntu LTS / Debian / macOS / WSL2):
#
#   bash packaging/tests/install-smoke.sh v0.5.0
#
# Prerequisites on the VM: curl, cosign. Nothing else.
#
# NOTE: this script needs a published, signed release to run against — it is
# the *operator's* clean-VM gate, executed before announcing a release. It has
# not been faked locally; status lives in the ExecPlan Progress section.
set -euo pipefail

TAG="${1:?usage: install-smoke.sh vX.Y.Z}"
PREFIX="$(mktemp -d "${HOME}/crux-smoke.XXXXXX")"
FAILED=0

step() { echo; echo "== $* =="; }

step "1/6 download installer (two-step, never piped)"
curl -fsSL --proto '=https' --tlsv1.2 \
  -o "${PREFIX}/install.sh" \
  "https://github.com/CueCrux/Crux/releases/download/${TAG}/install.sh"

step "2/6 install with signature verification"
bash "${PREFIX}/install.sh" --version "${TAG}" --prefix "${PREFIX}"

step "3/6 boot daemon"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/crux"
CORECRUXD_AUTH_MODE=dev_scopes \
  CORECRUXD_DATA_DIR="${DATA_DIR}" \
  CORECRUXD_HTTP_PORT=14800 \
  "${PREFIX}/bin/crux" >"${PREFIX}/daemon.log" 2>&1 &
DPID=$!
trap 'kill "$DPID" 2>/dev/null || true' EXIT

READY=0
for _ in $(seq 1 60); do
  curl -sf http://127.0.0.1:14800/readyz >/dev/null 2>&1 && { READY=1; break; }
  kill -0 "$DPID" 2>/dev/null || break
  sleep 0.5
done
[ "$READY" -eq 1 ] || { echo "FAIL: daemon not ready"; tail -20 "${PREFIX}/daemon.log"; exit 1; }
echo "ready: $(curl -sf http://127.0.0.1:14800/v1/version)"

step "4/6 MCP handshake"
RESP="$(curl -sf -X POST http://127.0.0.1:14801/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"install-smoke","version":"0"}}}')"
echo "$RESP" | grep -q '"serverInfo"' || { echo "FAIL: MCP initialize: $RESP"; FAILED=1; }

step "5/6 stop daemon"
kill "$DPID" && wait "$DPID" 2>/dev/null || true
trap - EXIT

step "6/6 uninstall (data must survive)"
bash "${PREFIX}/install.sh" --uninstall --prefix "${PREFIX}"
[ ! -e "${PREFIX}/bin/crux" ] || { echo "FAIL: binary still present"; FAILED=1; }
[ -d "${DATA_DIR}" ] || { echo "FAIL: data dir was deleted by uninstall"; FAILED=1; }

echo
if [ "$FAILED" -eq 0 ]; then
  echo "PASS: install → ready → MCP → uninstall (data preserved)"
  echo "Cleanup is yours: rm -rf '${PREFIX}' '${DATA_DIR}'"
else
  echo "FAIL: see messages above"
  exit 1
fi
