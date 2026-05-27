#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# ci-cargo-with-fallback.sh — wrap a cargo invocation so a known-flaky
# `sccache` crash (server disconnect mid-build) triggers exactly one
# automatic retry with `RUSTC_WRAPPER=""`. Real code failures are NOT
# retried — only the documented sccache crash signatures fall through to
# the second attempt.
#
# Background. The CueCrux self-hosted runner pool exports
# `RUSTC_WRAPPER=/usr/local/bin/sccache` at the env level. When sccache's
# server process dies under load it surfaces as one of:
#   - `sccache: error: failed to execute compile`
#   - `Connection reset by peer (os error 104)`
#   - `Failed to read response header`
#   - `Compiler not supported: "failed to spawn Command …"`
# All four shipped on the same 24h cycle across PRs #104–#108 (2026-05-27)
# and were the dominant blocker on otherwise-green code.
#
# Behaviour:
#   1. Run `cargo "$@"` once. Stdout+stderr are tee'd to a log so we can
#      classify the failure without buffering many MB in memory.
#   2. If exit code is 0 → done.
#   3. If exit code != 0 AND the log contains one of the sccache crash
#      signatures → restart sccache (best-effort), unset `RUSTC_WRAPPER`,
#      run `cargo "$@"` again, exit with that code.
#   4. Otherwise → exit with the original code (real failure, no retry).
#
# Usage in a workflow step:
#   - run: bash scripts/ci-cargo-with-fallback.sh clippy --workspace -- -D warnings
#   - run: bash scripts/ci-cargo-with-fallback.sh test --workspace
#   - run: bash scripts/ci-cargo-with-fallback.sh doc --workspace --no-deps
#
# Safe for local use too — when sccache isn't present the first attempt
# succeeds and the retry path is never taken.

set -eo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <cargo-subcommand> [args...]" >&2
  exit 2
fi

LOG="$(mktemp -t ci-cargo-fallback.XXXXXX.log)"
trap 'rm -f "$LOG"' EXIT

# Signatures that indicate sccache crashed (not a real build error).
# Keep this list tight — over-matching would suppress legitimate failures.
SCCACHE_CRASH_SIGNATURES=(
  "sccache: error: failed to execute compile"
  "sccache: error: failed to send data to or receive data from server"
  "Failed to read response header"
  "Connection reset by peer (os error 104)"
  "sccache: caused by: Compiler not supported"
  "process didn't exit successfully:.*sccache.*exit status: 2"
)

run_cargo() {
  # Tee to log so we can inspect, but preserve cargo's actual exit code via
  # PIPESTATUS. The caller is responsible for wrapping this call in
  # `set +e` / `set -e`; if we toggle `set -e` inside the function the
  # `return` below trips the EXIT trap before the caller can inspect $?.
  cargo "$@" 2>&1 | tee "$LOG"
  return "${PIPESTATUS[0]}"
}

looks_like_sccache_crash() {
  for sig in "${SCCACHE_CRASH_SIGNATURES[@]}"; do
    if grep -qE "$sig" "$LOG"; then
      return 0
    fi
  done
  return 1
}

echo "::group::cargo $*"
set +e
run_cargo "$@"
FIRST_CODE=$?
set -e
echo "::endgroup::"

if [ "$FIRST_CODE" -eq 0 ]; then
  exit 0
fi

if ! looks_like_sccache_crash; then
  echo "::error::cargo $* failed (exit ${FIRST_CODE}); not an sccache crash signature, surfacing the failure."
  exit "$FIRST_CODE"
fi

echo "::warning::sccache crash detected in cargo $* output; retrying with RUSTC_WRAPPER=\"\""
# Best-effort restart of sccache so subsequent CI steps in the same job
# start from a clean server. Ignore failures — we're about to bypass it
# anyway via the unset wrapper.
if command -v sccache >/dev/null 2>&1; then
  sccache --stop-server >/dev/null 2>&1 || true
fi

echo "::group::cargo $* (sccache-disabled retry)"
# Truncate log between attempts so any second-attempt sccache messages
# don't trigger a third retry loop next time we read the log.
: > "$LOG"
set +e
RUSTC_WRAPPER="" cargo "$@" 2>&1 | tee "$LOG"
RETRY_CODE=${PIPESTATUS[0]}
set -e
echo "::endgroup::"

if [ "$RETRY_CODE" -eq 0 ]; then
  echo "::notice::cargo $* recovered on sccache-disabled retry."
fi
exit "$RETRY_CODE"
