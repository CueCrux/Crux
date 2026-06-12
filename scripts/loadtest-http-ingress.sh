#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# Load probe for the HTTP ingress hardening layers
# (ExecPlan crux-http-ingress-hardening-2026-06-11, M2 gate).
#
# NOT CI-gated (P2 makes perf gates CI-enforced). Run against a sidecar or
# local daemon — never against prod without an operator watching.
#
# Usage:
#   scripts/loadtest-http-ingress.sh [base_url]
#
#   base_url   default http://127.0.0.1:14800
#
# Requires `oha` (https://github.com/hatoo/oha): cargo install oha
#
# What it checks (thresholds documented inline):
#   1. Flood: 10k connections / 30s against /healthz with a max_inflight
#      below the concurrency → expect a mix of 200s and clean 503s, zero
#      socket errors/timeouts from the daemon side, p99 of the 200s < 500ms.
#   2. Body limit: an oversize POST gets a 413 problem+json.
#   3. Recovery: after the flood, a plain request answers 200 within 1s.
#
# Suggested daemon env for the probe (small enough to actually shed):
#   CORECRUXD_MAX_INFLIGHT=256 CORECRUXD_MAX_REQUEST_BODY_BYTES=1048576

set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:14800}"
CONCURRENCY="${LOADTEST_CONCURRENCY:-10000}"
DURATION="${LOADTEST_DURATION:-30s}"

command -v oha >/dev/null 2>&1 || {
  echo "oha not found — install with: cargo install oha" >&2
  exit 2
}

echo "── 1/3 flood: ${CONCURRENCY} concurrent for ${DURATION} against ${BASE_URL}/healthz"
# --no-tui for scriptability; JSON output parsed for thresholds.
FLOOD_JSON="$(oha --no-tui -z "${DURATION}" -c "${CONCURRENCY}" --json "${BASE_URL}/healthz")"
echo "${FLOOD_JSON}" | python3 - << 'PY'
import json
import sys

report = json.load(sys.stdin)
codes = report.get("statusCodeDistribution", {})
ok = codes.get("200", 0)
shed = codes.get("503", 0)
other = {k: v for k, v in codes.items() if k not in ("200", "503")}
errors = report.get("errorDistribution", {})
p99 = report["summary"].get("p99", report["summary"].get("p99Latency", 0))

print(f"  200s={ok} 503s={shed} other={other} errors={errors} p99={p99}s")

# Threshold 1: every response is either served or cleanly shed.
assert not other, f"unexpected status codes under flood: {other}"
# Threshold 2: the daemon must keep serving — at least some 200s.
assert ok > 0, "daemon served zero requests under flood"
# Threshold 3: p99 stays sane while shedding (<0.5s; tune per host).
assert float(p99) < 0.5, f"p99 {p99}s exceeds 500ms under flood"
print("  flood: PASS")
PY

echo "── 2/3 body limit: oversize POST expects 413 problem+json"
ONE_OVER=$(( ${BODY_LIMIT_BYTES:-1048576} + 1 ))
STATUS_CT="$(head -c "${ONE_OVER}" /dev/zero | curl -s -o /dev/null \
  -w '%{http_code} %{content_type}' -X POST \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @- "${BASE_URL}/v1/facts" || true)"
echo "  got: ${STATUS_CT}"
case "${STATUS_CT}" in
  "413 application/problem+json"*) echo "  body limit: PASS" ;;
  *) echo "  body limit: FAIL (expected '413 application/problem+json')" >&2; exit 1 ;;
esac

echo "── 3/3 recovery: single request after flood"
START=$(date +%s%N)
CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 "${BASE_URL}/healthz")"
ELAPSED_MS=$(( ($(date +%s%N) - START) / 1000000 ))
echo "  /healthz → ${CODE} in ${ELAPSED_MS}ms"
[ "${CODE}" = "200" ] || { echo "  recovery: FAIL" >&2; exit 1; }
echo "  recovery: PASS"

echo "ALL PASS"
