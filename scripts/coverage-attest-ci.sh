#!/usr/bin/env bash
set -euo pipefail

SUMMARY_PATH="${COVERAGE_SUMMARY_PATH:-coverage-summary.txt}"
OUT_DIR="${COVERAGE_ATTEST_OUT_DIR:-coverage-attestation}"
FLOOR="${COVERAGE_ATTEST_FLOOR:-0.84}"
SUBJECT="${COVERAGE_ATTEST_SUBJECT:-crux-workspace-coverage}"
CORPUS="${COVERAGE_ATTEST_CORPUS:-crux-workspace-tests}"
METRIC="${COVERAGE_ATTEST_METRIC:-line_coverage}"
ACTOR="${COVERAGE_ATTEST_ACTOR:-github-actions}"
TENANT_ID="${COVERAGE_ATTEST_TENANT_ID:-ci}"
COMMIT_SHA="${COVERAGE_ATTEST_COMMIT_SHA:-${GITHUB_SHA:-$(git rev-parse HEAD)}}"
RUN_ID="${COVERAGE_ATTEST_RUN_ID:-${GITHUB_RUN_ID:-local}-$(date -u +%Y%m%dT%H%M%SZ)}"
CREATED_AT="${COVERAGE_ATTEST_CREATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
RECEIPT_ID="${COVERAGE_ATTEST_RECEIPT_ID:-coverage-${RUN_ID}}"
ATTESTATION_ID="${COVERAGE_ATTEST_ATTESTATION_ID:-${RECEIPT_ID}}"

if [ ! -f "$SUMMARY_PATH" ]; then
  echo "coverage summary not found: $SUMMARY_PATH" >&2
  exit 2
fi

TOTAL_PCT="$(awk '/^TOTAL[[:space:]]/ { gsub("%", "", $4); print $4; exit }' "$SUMMARY_PATH")"
if [ -z "$TOTAL_PCT" ]; then
  echo "coverage summary does not contain a TOTAL row: $SUMMARY_PATH" >&2
  exit 2
fi

SCORE="$(awk -v pct="$TOTAL_PCT" 'BEGIN { printf "%.6f", (pct + 0) / 100 }')"
BELOW_FLOOR="$(awk -v score="$SCORE" -v floor="$FLOOR" 'BEGIN { print ((score + 0) < (floor + 0)) ? 1 : 0 }')"

mkdir -p "$OUT_DIR"
REPORT_PATH="$OUT_DIR/coverage-report.json"
BODY_PATH="$OUT_DIR/coverage.body.cbor"
SIG_PATH="$OUT_DIR/coverage.sig.cbor"

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

{
  printf '{\n'
  printf '  "schema": "crux.coverage_attestation.report.v1",\n'
  printf '  "subject": "%s",\n' "$(json_escape "$SUBJECT")"
  printf '  "corpus": "%s",\n' "$(json_escape "$CORPUS")"
  printf '  "run_id": "%s",\n' "$(json_escape "$RUN_ID")"
  printf '  "commit_sha": "%s",\n' "$(json_escape "$COMMIT_SHA")"
  printf '  "metric": "%s",\n' "$(json_escape "$METRIC")"
  printf '  "score": %s,\n' "$SCORE"
  printf '  "floor": %s,\n' "$FLOOR"
  printf '  "below_floor": %s,\n' "$BELOW_FLOOR"
  printf '  "coverage_percent": %s,\n' "$TOTAL_PCT"
  printf '  "summary_path": "%s",\n' "$(json_escape "$SUMMARY_PATH")"
  printf '  "created_at": "%s"\n' "$(json_escape "$CREATED_AT")"
  printf '}\n'
} > "$REPORT_PATH"

SIGN_ARGS=()
if [ -n "${CORECRUX_COVERAGE_ATTEST_SIGNING_KEY_B64:-}" ]; then
  SIGN_ARGS=(
    --out-sig "$SIG_PATH"
    --signing-key-b64 "$CORECRUX_COVERAGE_ATTEST_SIGNING_KEY_B64"
    --key-id "${CORECRUX_COVERAGE_ATTEST_KEY_ID:-coverage-attest}"
  )
fi

cargo run --locked -p corecruxctl -- receipts coverage-attest \
  --out-body "$BODY_PATH" \
  "${SIGN_ARGS[@]}" \
  --tenant-id "$TENANT_ID" \
  --receipt-id "$RECEIPT_ID" \
  --attestation-id "$ATTESTATION_ID" \
  --actor-passport "$ACTOR" \
  --subject "$SUBJECT" \
  --corpus "$CORPUS" \
  --run-id "$RUN_ID" \
  --commit-sha "$COMMIT_SHA" \
  --lane-flags "${COVERAGE_ATTEST_LANE_FLAGS:-}" \
  --metric "$METRIC" \
  --score "$SCORE" \
  --floor "$FLOOR" \
  --below-floor "$BELOW_FLOOR" \
  --report "$REPORT_PATH" \
  --created-at "$CREATED_AT"
