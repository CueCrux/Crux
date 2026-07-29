#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# code-intel-bench.sh — drive both arms of the code-intel token benchmark.
#
# ExecPlan: crux-codemap-agent-surface-and-measured-savings-2026-07-27 (M2).
#
# The treatment arm answers from runtime evidence, so it needs a daemon that has
# actually captured spans. This starts one on a scratch data dir with capture on,
# registers the repo, drives a fixed traffic profile through it, then runs both
# arms and pairs them.
#
# The traffic profile is part of the measurement, not an implementation detail: a
# liveness or dead-code answer is only ever as strong as the window behind it, so
# the exact request list lives here where it can be read and criticised.
#
# Run:  bash scripts/code-intel-bench.sh [output-dir]
# Deliberately NOT a CI gate — it is a measurement, and it starts a daemon.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT/target/code-intel-bench}"
PORT="${CRUX_BENCH_PORT:-14899}"
GRPC_PORT="${CRUX_BENCH_GRPC_PORT:-14907}"
MCP_PORT="${CRUX_BENCH_MCP_PORT:-14908}"
BASE="http://127.0.0.1:$PORT"
DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/code-intel-bench.XXXXXX")"
TENANT=local
REPO=crux

mkdir -p "$OUT_DIR"

cleanup() {
  if [[ -n "${DAEMON_PID:-}" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    # Never kill by name: sibling sessions run their own daemons in this tree.
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$DATA_DIR"
}
trap cleanup EXIT

# Release, not debug. The registration below scans 500+ files inside the
# request; a debug daemon takes it past any sane HTTP timeout.
echo "==> building corecruxd (release)"
cargo build -q --release -p corecruxd --manifest-path "$ROOT/Cargo.toml"

echo "==> starting capture-enabled daemon on $PORT (data dir $DATA_DIR)"
# LOG_LEVEL must be info: the handler spans are `#[instrument(level = "info")]`
# and the global EnvFilter gates the capture layer along with everything else.
# At warn, capture is on and the ring stays empty — a silent empty window.
env -u RUST_LOG \
  CORECRUXD_DATA_DIR="$DATA_DIR" \
  CORECRUXD_HTTP_PORT="$PORT" CORECRUXD_HTTP_HOST=127.0.0.1 \
  CORECRUXD_GRPC_PORT="$GRPC_PORT" CORECRUXD_GRPC_HOST=127.0.0.1 \
  CORECRUXD_MCP_PORT="$MCP_PORT" CORECRUXD_MCP_HOST=127.0.0.1 \
  CORECRUXD_AUTH_MODE=off \
  CORECRUXD_LOG_LEVEL=info \
  CORECRUXD_UPDATE_CHECK_ENABLED=0 \
  CORECRUXD_QUERY_TEXT_SEARCH=1 \
  CORECRUXD_AST_SCAN=1 \
  CORECRUXD_CODEGRAPH_EDGES=1 \
  CORECRUXD_POLYGLOT_V=1 \
  CORECRUXD_TRACE_CAPTURE=1 \
  CORECRUXD_TRACE_PERSIST=1 \
  CORECRUXD_TRACE_FLUSH_SECS=2 \
  CORECRUXD_TRACE_CAPACITY=200000 \
  CORECRUXD_TRACE_SAMPLE_RATE=1 \
  CORECRUXD_TRACE_REPO_ID="$REPO" \
  CORECRUXD_TRACE_TENANT_ID="$TENANT" \
  "$ROOT/target/release/corecruxd" > "$OUT_DIR/daemon.log" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 120); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then break; fi
  kill -0 "$DAEMON_PID" 2>/dev/null || { echo "daemon exited early; see $OUT_DIR/daemon.log" >&2; exit 1; }
  sleep 1
done
curl -fsS "$BASE/healthz" >/dev/null || { echo "daemon never became healthy" >&2; exit 1; }

echo "==> registering $ROOT as $TENANT/$REPO (triggers a scan)"
curl -fsS --max-time 900 -X POST "$BASE/v1/repos" -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$TENANT\",\"repo_id\":\"$REPO\",\"root_path\":\"$ROOT\",\"languages\":[\"rust\"]}" \
  > "$OUT_DIR/registration.json"

# ── Traffic profile ─────────────────────────────────────────────────────────
# Chosen to exercise the handlers the corpus asks about plus a spread of the
# public surface, including error paths (problem_response runs only on those).
# Repeated so per-symbol counts are more than one, which is what makes a
# liveness answer worth anything.
echo "==> generating traffic"
ROUNDS="${CRUX_BENCH_ROUNDS:-5}"
for _ in $(seq 1 "$ROUNDS"); do
  curl -fsS  "$BASE/healthz"                                  >/dev/null || true
  curl -fsS  "$BASE/readyz"                                   >/dev/null || true
  curl -fsS  "$BASE/metrics"                                  >/dev/null || true
  curl -fsS  "$BASE/v1/version"                               >/dev/null || true
  curl -fsS  "$BASE/v1/repos?tenant_id=$TENANT"               >/dev/null || true
  curl -fsS  "$BASE/v1/repos/$REPO/codemap?tenant_id=$TENANT" >/dev/null || true
  curl -fsS  "$BASE/v1/repos/$REPO/spatial?tenant_id=$TENANT" >/dev/null || true
  curl -fsS  "$BASE/v1/console/summary"                       >/dev/null || true
  curl -fsS  "$BASE/v1/traces/stats"                          >/dev/null || true
  curl -fsS -X POST "$BASE/v1/query/text-search" -H 'Content-Type: application/json' \
       -d "{\"tenant_id\":\"$TENANT\",\"query\":\"runtime code map\",\"limit\":5}" >/dev/null || true
  # Error paths, so the shared problem/response helpers actually execute.
  curl -fsS  "$BASE/v1/receipts/does-not-exist"               >/dev/null 2>&1 || true
  curl -fsS  "$BASE/v1/repos/no-such-repo/codemap?tenant_id=$TENANT" >/dev/null 2>&1 || true
done

echo "==> waiting for the trace flusher (flush interval 2s)"
sleep 6
curl -fsS "$BASE/v1/traces/stats" > "$OUT_DIR/trace-stats.json" || true
echo "    $(cat "$OUT_DIR/trace-stats.json")"

echo "==> control arm"
cargo run -q -p crux-mcp --example code_intel_control --manifest-path "$ROOT/Cargo.toml" \
  > "$OUT_DIR/control.json"

echo "==> treatment arm + paired savings"
CRUX_BENCH_DAEMON="$BASE" CRUX_BENCH_REPO="$REPO" \
  cargo run -q -p crux-mcp --example code_intel_treatment --manifest-path "$ROOT/Cargo.toml" \
  -- "$OUT_DIR/control.json" > "$OUT_DIR/treatment.json"

echo
echo "wrote $OUT_DIR/{control,treatment,trace-stats}.json"
