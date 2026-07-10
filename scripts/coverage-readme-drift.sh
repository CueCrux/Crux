#!/usr/bin/env bash
set -euo pipefail

# Coverage drift gate: keep the README's hand-written coverage/test-count
# claims from silently diverging from the measured coverage artifact.
#
# Usage:
#   scripts/coverage-readme-drift.sh <coverage-summary.txt> [measured_test_count]
#
# Args:
#   $1  Path to a `cargo llvm-cov report --summary-only` output file. The TOTAL
#       row's column 4 is region coverage (matches coverage-attest-ci.sh and
#       the gate documented in docs/testing-and-coverage.md).
#   $2  Optional measured test count. If given, the check fails when the README
#       claims MORE tests than were measured. If omitted, the test-count check
#       is skipped with a note (never fails on a missing count).
#
# Env:
#   README_PATH   README to check (default: README.md relative to CWD).
#   COVERAGE_DRIFT_TOLERANCE  Allowed |claimed - measured| in percentage points
#                             (default: 2.0).

SUMMARY_PATH="${1:-coverage-summary.txt}"
MEASURED_TESTS="${2:-}"
README_PATH="${README_PATH:-README.md}"
TOLERANCE="${COVERAGE_DRIFT_TOLERANCE:-2.0}"

if [ ! -f "$SUMMARY_PATH" ]; then
  echo "coverage-readme-drift: coverage summary not found: $SUMMARY_PATH" >&2
  exit 2
fi
if [ ! -f "$README_PATH" ]; then
  echo "coverage-readme-drift: README not found: $README_PATH" >&2
  exit 2
fi

# Measured region coverage = column 4 of the TOTAL row (region Cover%).
MEASURED_COV="$(awk '/^TOTAL[[:space:]]/ { gsub("%", "", $4); print $4; exit }' "$SUMMARY_PATH")"
if [ -z "$MEASURED_COV" ]; then
  echo "coverage-readme-drift: no TOTAL row with a region-coverage column in $SUMMARY_PATH" >&2
  exit 2
fi

# Claimed coverage = the "NN% ... CI-gated region coverage" number in the README.
CLAIMED_COV="$(grep -oE '[0-9]+(\.[0-9]+)?%\*\* CI-gated region coverage' "$README_PATH" \
  | grep -oE '[0-9]+(\.[0-9]+)?' | head -1)"
if [ -z "$CLAIMED_COV" ]; then
  echo "coverage-readme-drift: could not find a '<NN>% ... CI-gated region coverage' claim in $README_PATH" >&2
  echo "coverage-readme-drift: the README wording must keep a parseable '**~NN%** CI-gated region coverage' anchor." >&2
  exit 2
fi

# Claimed test count = the "N,NNN+ tests and" number in the README.
CLAIMED_TESTS="$(grep -oE '[0-9][0-9,]*\+? tests and' "$README_PATH" \
  | grep -oE '[0-9][0-9,]*' | head -1 | tr -d ',')"

FAIL=0

# --- Coverage drift check -------------------------------------------------
DRIFT_BAD="$(awk -v c="$CLAIMED_COV" -v m="$MEASURED_COV" -v t="$TOLERANCE" \
  'BEGIN { d = c - m; if (d < 0) d = -d; print (d > t) ? 1 : 0 }')"
if [ "$DRIFT_BAD" = "1" ]; then
  echo "coverage-readme-drift: FAIL coverage drift: README claims ${CLAIMED_COV}% region coverage but the measured TOTAL is ${MEASURED_COV}% (|diff| > ${TOLERANCE} pp)." >&2
  echo "coverage-readme-drift: update README.md's 'CI-gated region coverage' number (or the coverage regressed and needs attention)." >&2
  FAIL=1
else
  echo "coverage-readme-drift: OK coverage: README ${CLAIMED_COV}% vs measured ${MEASURED_COV}% (tolerance ${TOLERANCE} pp)."
fi

# --- Test-count check -----------------------------------------------------
if [ -z "$CLAIMED_TESTS" ]; then
  echo "coverage-readme-drift: note: no '<N> tests and' claim found in $README_PATH; skipping test-count check."
elif [ -z "$MEASURED_TESTS" ]; then
  echo "coverage-readme-drift: note: no measured test count supplied; skipping test-count check (README claims ${CLAIMED_TESTS})."
else
  if [ "$CLAIMED_TESTS" -gt "$MEASURED_TESTS" ]; then
    echo "coverage-readme-drift: FAIL test count: README claims ${CLAIMED_TESTS} tests but only ${MEASURED_TESTS} were measured." >&2
    echo "coverage-readme-drift: lower the README test-count claim to match the measured suite." >&2
    FAIL=1
  else
    echo "coverage-readme-drift: OK test count: README claims ${CLAIMED_TESTS}, measured ${MEASURED_TESTS} (claim <= measured)."
  fi
fi

exit "$FAIL"
