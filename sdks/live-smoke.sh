#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.
#
# Run both SDKs' full surface against a locally-started daemon.
#
# This is the M6.1 gate evidence: the unit suites prove wire shape against a
# stub, this proves the daemon answers and the SDKs parse what comes back.
#
#   ./sdks/live-smoke.sh                       # build the daemon if needed, run both
#   CORECRUXD_BIN=/path/to/corecruxd ./sdks/live-smoke.sh   # reuse a built binary
#
# Not wired into CI: it needs a compiled daemon, which the SDK workflows do not
# build. Run it locally before tagging an SDK release.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port="${CRUX_SMOKE_PORT:-24810}"
base_url="http://127.0.0.1:${port}"
data_dir="$(mktemp -d)"
daemon_pid=""

cleanup() {
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -rf "$data_dir"
}
trap cleanup EXIT

bin="${CORECRUXD_BIN:-}"
if [[ -z "$bin" ]]; then
  bin="${repo_root}/target/debug/corecruxd"
  if [[ ! -x "$bin" ]]; then
    echo "building corecruxd (this is the slow part; set CORECRUXD_BIN to skip)"
    (cd "$repo_root" && cargo build -p corecruxd)
  fi
fi
[[ -x "$bin" ]] || { echo "no corecruxd binary at $bin" >&2; exit 1; }

echo "starting daemon on ${base_url} (data_dir ${data_dir})"
CORECRUXD_AUTH_MODE=off \
CORECRUXD_DATA_DIR="$data_dir" \
CORECRUXD_HTTP_PORT="$port" \
CORECRUXD_GRPC_PORT="$((port + 1))" \
CORECRUXD_MCP_PORT="$((port + 2))" \
CORECRUXD_CONTEXT_SURFACE=1 \
CORECRUXD_AUTO_CAPTURE=1 \
CORECRUXD_LOCAL_INGEST=1 \
CRUX_MEMORY_IMPORT=1 \
  "$bin" >"${data_dir}/daemon.log" 2>&1 &
daemon_pid=$!

for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null "${base_url}/readyz" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "daemon exited during startup:" >&2
    tail -30 "${data_dir}/daemon.log" >&2
    exit 1
  fi
  sleep 1
done

if ! curl -fsS -o /dev/null "${base_url}/readyz"; then
  echo "daemon never became ready:" >&2
  tail -30 "${data_dir}/daemon.log" >&2
  exit 1
fi
echo "daemon ready"
echo

status=0

echo "── python ─────────────────────────────────────────────"
python3 "${repo_root}/sdks/python/smoke.py" "$base_url" || status=1
echo

echo "── typescript ─────────────────────────────────────────"
(cd "${repo_root}/sdks/typescript" && npm run --silent build && node smoke.mjs "$base_url") || status=1
echo

if [[ $status -ne 0 ]]; then
  echo "live smoke FAILED — daemon log tail:" >&2
  tail -30 "${data_dir}/daemon.log" >&2
fi
exit $status
