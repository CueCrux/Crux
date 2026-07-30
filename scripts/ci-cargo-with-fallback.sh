#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# ci-cargo-with-fallback.sh — wrap a cargo invocation so a known-flaky
# `sccache` crash (server disconnect mid-build) triggers exactly one
# automatic retry with `RUSTC_WRAPPER=""`. Real code failures are NOT
# retried — only the documented sccache crash signatures fall through to
# the second attempt.
#
# Background. Some trusted local/protected runner environments export
# `RUSTC_WRAPPER=/usr/local/bin/sccache`. When that optional cache server dies
# under load it surfaces as one of:
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
# These steps also run under the merge queue's `merge_group` event (the
# Lint / Test / MSRV / Coverage jobs trigger on it), so this wrapper covers
# queue builds too — see .github/merge-queue-ruleset.README.md.
#
# Safe for local use too — when sccache isn't present the first attempt
# succeeds and the retry path is never taken.
#
# Note: the wrapper injects `--locked` into every invocation (see the
# supply-chain guard below), so all CI cargo calls share one lockfile
# policy choke point.

set -eo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <cargo-subcommand> [args...]" >&2
  exit 2
fi

# Supply-chain guard (ExecPlan crux-supply-chain-attestation-2026-06-11):
# every cargo invocation routed through this wrapper runs with `--locked`,
# so a Cargo.lock that drifts from the manifests fails loudly in CI instead
# of being silently regenerated mid-build. Fix for a red run is to commit
# the regenerated lock, not to remove the flag.
#
# The flag is injected AFTER the subcommand because cargo does not forward
# pre-subcommand global flags to external subcommands (llvm-cov etc.).
# Skipped when the caller already passed `--locked`, and overridable with
# CI_CARGO_NO_LOCKED=1 for deliberate local runs against a drifted lock.
SUBCOMMAND="$1"
shift
INJECT_LOCKED=1
if [ "${CI_CARGO_NO_LOCKED:-0}" = "1" ]; then
  INJECT_LOCKED=0
fi
for arg in "$@"; do
  if [ "$arg" = "--locked" ]; then
    INJECT_LOCKED=0
    break
  fi
done
if [ "$INJECT_LOCKED" -eq 1 ]; then
  set -- "$SUBCOMMAND" --locked "$@"
else
  set -- "$SUBCOMMAND" "$@"
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
