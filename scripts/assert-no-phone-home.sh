#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Tier-1 "no phone-home" egress assertion (threat ref T.5; free-tier trust
# posture: no telemetry, no account requirement, no outbound dial on boot).
#
# Two modes, auto-selected:
#
#   strace mode (preferred; use in CI) — boots the daemon under strace network
#     syscall tracing in a clean non-git temp dir, serves traffic, then FAILS
#     if any non-loopback AF_INET/AF_INET6 connect/send was *attempted*.
#
#   netns mode (fallback when strace is unavailable) — boots the daemon inside
#     an unprivileged network namespace that has only loopback, and asserts it
#     becomes fully ready and serves /readyz + /v1/version with zero external
#     network. This proves offline-first functionality; it cannot observe
#     egress *attempts* (they just fail inside the namespace). Force with
#     NO_PHONE_HOME_MODE=netns.
#
# The temp dir is never a git checkout, so the git-based update-posture probe
# (a documented exception for repo-checkout deploys, update.rs) has nothing to
# fetch — exactly the binary-install shape we distribute.
#
# Usage:
#   scripts/assert-no-phone-home.sh [path/to/corecruxd]
#
# Defaults to target/release/corecruxd. Exits:
#   0  pass
#   1  egress detected / daemon failed offline boot (release blocker)
#   2  prerequisites missing (binary / curl / both trace mechanisms)
#
# CI wiring note: release-blocking in `.github/workflows/release.yml` on the
# linux release leg. PR-time coverage stays limited to pure-offline trust gates
# because shared self-hosted runners can retain daemon ports between jobs.
set -euo pipefail

BINARY="${1:-target/release/corecruxd}"
IDLE_SECS="${NO_PHONE_HOME_IDLE_SECS:-15}"
HTTP_PORT="${NO_PHONE_HOME_HTTP_PORT:-24800}"
GRPC_PORT="${NO_PHONE_HOME_GRPC_PORT:-24807}"
MCP_PORT="${NO_PHONE_HOME_MCP_PORT:-24801}"
MODE="${NO_PHONE_HOME_MODE:-auto}"

if ! command -v curl >/dev/null 2>&1; then
  echo "SKIP: required tool 'curl' not found" >&2
  exit 2
fi

if [ "$MODE" = "auto" ]; then
  if command -v strace >/dev/null 2>&1; then
    MODE=strace
  elif command -v unshare >/dev/null 2>&1 && command -v ip >/dev/null 2>&1; then
    MODE=netns
  else
    echo "SKIP: neither strace nor unshare+ip available" >&2
    exit 2
  fi
fi

# ── inner half: runs inside the network namespace (netns mode only) ────────
if [ "${NO_PHONE_HOME_INNER:-0}" = "1" ]; then
  ip link set lo up
  WORK="$2"
  cd "$WORK"
  env -i \
    PATH="$PATH" \
    HOME="$WORK" \
    CORECRUXD_AUTH_MODE=off \
    CORECRUXD_DATA_DIR="$WORK/data" \
    CORECRUXD_HTTP_HOST=127.0.0.1 \
    CORECRUXD_HTTP_PORT="$HTTP_PORT" \
    CORECRUXD_GRPC_HOST=127.0.0.1 \
    CORECRUXD_GRPC_PORT="$GRPC_PORT" \
    CORECRUXD_MCP_HOST=127.0.0.1 \
    CORECRUXD_MCP_PORT="$MCP_PORT" \
    ./corecruxd >"$WORK/daemon.log" 2>&1 &
  DPID=$!
  READY=0
  for _ in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:${HTTP_PORT}/readyz" >/dev/null 2>&1; then
      READY=1
      break
    fi
    kill -0 "$DPID" 2>/dev/null || break
    sleep 0.5
  done
  if [ "$READY" -ne 1 ]; then
    echo "FAIL: daemon did not become ready inside loopback-only netns" >&2
    tail -n 40 "$WORK/daemon.log" >&2 || true
    kill "$DPID" 2>/dev/null || true
    exit 1
  fi
  sleep "$IDLE_SECS"
  curl -sf "http://127.0.0.1:${HTTP_PORT}/v1/version" >/dev/null
  curl -sf "http://127.0.0.1:${HTTP_PORT}/healthz" >/dev/null
  curl -sf "http://127.0.0.1:${HTTP_PORT}/readyz" >/dev/null
  kill "$DPID" 2>/dev/null || true
  wait "$DPID" 2>/dev/null || true
  exit 0
fi

# ── outer half ──────────────────────────────────────────────────────────────
if [ ! -x "$BINARY" ]; then
  echo "SKIP: daemon binary not found/executable at: $BINARY" >&2
  echo "      build first: cargo build --locked --release --bin corecruxd" >&2
  exit 2
fi

WORK="$(mktemp -d /tmp/crux-no-phone-home.XXXXXX)"
STRACE_PID=""
cleanup() {
  if [ -n "$STRACE_PID" ] && kill -0 "$STRACE_PID" 2>/dev/null; then
    kill "$STRACE_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$STRACE_PID" 2>/dev/null || break
      sleep 0.25
    done
    kill -9 "$STRACE_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

cp "$BINARY" "$WORK/corecruxd"
mkdir -p "$WORK/data"

if [ "$MODE" = "netns" ]; then
  echo "== no-phone-home [netns mode]: offline-boot proof in loopback-only namespace =="
  echo "   (egress *attempt* detection requires strace — use strace mode in CI)"
  if NO_PHONE_HOME_INNER=1 unshare -r -n "$0" "$BINARY" "$WORK"; then
    echo "PASS: daemon fully ready + served /readyz, /healthz, /v1/version with zero external network"
    exit 0
  fi
  exit 1
fi

TRACE="$WORK/trace.log"
echo "== no-phone-home [strace mode]: booting daemon in clean dir $WORK (http :$HTTP_PORT) =="

(
  cd "$WORK"
  # Default-shaped local config: auth off on loopback, default update-check
  # env (deliberately NOT disabled — the assertion must hold with defaults).
  env -i \
    PATH="$PATH" \
    HOME="$WORK" \
    CORECRUXD_AUTH_MODE=off \
    CORECRUXD_DATA_DIR="$WORK/data" \
    CORECRUXD_HTTP_HOST=127.0.0.1 \
    CORECRUXD_HTTP_PORT="$HTTP_PORT" \
    CORECRUXD_GRPC_HOST=127.0.0.1 \
    CORECRUXD_GRPC_PORT="$GRPC_PORT" \
    CORECRUXD_MCP_HOST=127.0.0.1 \
    CORECRUXD_MCP_PORT="$MCP_PORT" \
    strace -f -qq -e trace=connect,sendto,sendmsg,sendmmsg \
      -o "$TRACE" ./corecruxd >"$WORK/daemon.log" 2>&1
) &
STRACE_PID=$!

READY=0
for _ in $(seq 1 60); do
  if curl -sf "http://127.0.0.1:${HTTP_PORT}/readyz" >/dev/null 2>&1; then
    READY=1
    break
  fi
  kill -0 "$STRACE_PID" 2>/dev/null || break
  sleep 0.5
done

if [ "$READY" -ne 1 ]; then
  echo "FAIL: daemon did not become ready on 127.0.0.1:${HTTP_PORT}" >&2
  echo "--- daemon.log (tail) ---" >&2
  tail -n 40 "$WORK/daemon.log" >&2 || true
  exit 1
fi

echo "== ready; idling ${IDLE_SECS}s to catch background dial-outs =="
sleep "$IDLE_SECS"

# Exercise request-path code under trace too.
curl -sf "http://127.0.0.1:${HTTP_PORT}/v1/version" >/dev/null 2>&1 || true
curl -sf "http://127.0.0.1:${HTTP_PORT}/healthz" >/dev/null 2>&1 || true
sleep 2

kill "$STRACE_PID" 2>/dev/null || true
wait "$STRACE_PID" 2>/dev/null || true
STRACE_PID=""

# Any AF_INET/AF_INET6 connect/send whose target is NOT loopback is egress.
# Loopback = 127.0.0.0/8 and ::1. AF_UNIX and AF_NETLINK are local by
# definition.
VIOLATIONS="$(grep -E 'sin6?_family=AF_INET6?' "$TRACE" 2>/dev/null \
  | grep -Ev 'inet_addr\("127\.[0-9.]+"\)' \
  | grep -Ev 'inet_pton\(AF_INET6, "::1"' \
  || true)"

if [ -n "$VIOLATIONS" ]; then
  echo "FAIL: non-loopback network egress detected (release blocker):" >&2
  echo "$VIOLATIONS" >&2
  exit 1
fi

echo "PASS: no non-loopback egress observed (trace: connect/sendto/sendmsg/sendmmsg)"
