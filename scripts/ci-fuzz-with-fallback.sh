#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# ci-fuzz-with-fallback.sh — run a cargo-fuzz invocation with the same one-shot
# sccache-crash retry that scripts/ci-cargo-with-fallback.sh gives Lint / Test /
# MSRV / Coverage. The fuzz job (.github/workflows/fuzz.yml) previously called
# `cargo fuzz build` / `cargo fuzz run` RAW, so it was the only Rust CI job with
# no sccache fallback — a single sccache server death (it dies under load and
# surfaces as a connection reset while building ring's C sources) failed the
# whole PR with no retry. That made `Fuzz (...)` the dominant intermittent
# blocker on otherwise-green dependency bumps (#287/#288/#289, 2026-06-28).
#
# Why a separate script rather than reusing ci-cargo-with-fallback.sh: that
# wrapper injects `--locked` after the subcommand, which for cargo-fuzz would
# become `cargo fuzz --locked build <target>` (wrong — cargo-fuzz takes its
# target and libFuzzer args positionally). This wrapper runs the command
# verbatim instead.
#
# Keeping sccache (rather than just unsetting RUSTC_WRAPPER in the job) matters:
# the fuzz job builds each target in an isolated per-target CARGO_HOME with
# CARGO_INCREMENTAL=0, so the shared sccache server is the ONLY cross-target
# compile cache. We keep it for speed and fall back only when it crashes.
#
# Behaviour mirrors ci-cargo-with-fallback.sh:
#   1. Run `"$@"` once, tee'ing output to a log.
#   2. Exit 0 → done.
#   3. Non-zero AND the log matches a known sccache crash signature → restart
#      sccache (best-effort), unset RUSTC_WRAPPER, run `"$@"` once more.
#   4. Otherwise → surface the original exit code. A REAL libFuzzer crash in a
#      `cargo fuzz run` exits non-zero with a reproducer, NOT an sccache
#      signature, so it is surfaced (never retried/suppressed).
#
# Usage in a workflow step:
#   - run: bash scripts/ci-fuzz-with-fallback.sh cargo fuzz build <target>
#   - run: bash scripts/ci-fuzz-with-fallback.sh cargo fuzz run <target> -- <args...>
#
# Safe for local use too — when sccache isn't present the first attempt
# succeeds and the retry path is never taken.

set -eo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi

LOG="$(mktemp -t ci-fuzz-fallback.XXXXXX.log)"
trap 'rm -f "$LOG"' EXIT

# sccache crash signatures. The first six are the canonical, deliberately-tight
# list from scripts/ci-cargo-with-fallback.sh — keep them in sync (over-matching
# would suppress real build failures). The last entry is added here because the
# fuzz builds observed it directly on #288 (2026-06-28); it is only ever tested
# on a non-zero exit, so a successful sccache fallback (exit 0) never triggers a
# spurious retry.
SCCACHE_CRASH_SIGNATURES=(
  "sccache: error: failed to execute compile"
  "sccache: error: failed to send data to or receive data from server"
  "Failed to read response header"
  "Connection reset by peer (os error 104)"
  "sccache: caused by: Compiler not supported"
  "process didn't exit successfully:.*sccache.*exit status: 2"
  "The server looks like it shut down unexpectedly"
)

looks_like_sccache_crash() {
  for sig in "${SCCACHE_CRASH_SIGNATURES[@]}"; do
    if grep -qE "$sig" "$LOG"; then
      return 0
    fi
  done
  return 1
}

echo "::group::$*"
set +e
"$@" 2>&1 | tee "$LOG"
FIRST_CODE=${PIPESTATUS[0]}
set -e
echo "::endgroup::"

if [ "$FIRST_CODE" -eq 0 ]; then
  exit 0
fi

if ! looks_like_sccache_crash; then
  echo "::error::'$*' failed (exit ${FIRST_CODE}); not an sccache crash signature, surfacing the failure."
  exit "$FIRST_CODE"
fi

echo "::warning::sccache crash detected in '$*' output; retrying with RUSTC_WRAPPER=\"\""
# Best-effort restart so the retry (and any later steps in the job) start from a
# clean server. Ignore failures — we're bypassing it anyway via the unset.
if command -v sccache >/dev/null 2>&1; then
  sccache --stop-server >/dev/null 2>&1 || true
fi

echo "::group::$* (sccache-disabled retry)"
: > "$LOG"
set +e
RUSTC_WRAPPER="" "$@" 2>&1 | tee "$LOG"
RETRY_CODE=${PIPESTATUS[0]}
set -e
echo "::endgroup::"

if [ "$RETRY_CODE" -eq 0 ]; then
  echo "::notice::'$*' recovered on sccache-disabled retry."
fi
exit "$RETRY_CODE"
