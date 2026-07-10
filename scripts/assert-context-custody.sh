#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# assert-context-custody.sh — "we run our own exit test" as a release gate.
#
# The context-custody surface is the reason people trust the daemon: you can
# EXPORT everything the daemon knows (facts + sessions) and everything it did
# (signed journal + receipt refs) into one passport-signed bundle, then VERIFY
# that bundle OFFLINE — no daemon, no network. This script self-runs that exit
# test in CI so every release proves the custody machinery round-trips and the
# offline verifier actually detects tampering.
#
# Flow:
#   1. Seed a minimal CROWN receipt into a fresh tmp data dir (offline, dev key).
#   2. `context export` → a passport-signed custody bundle (signed=true).
#   3. `context verify --json` (positive) — assert ok=true, all four checks pass,
#      and the CLI exits zero.
#   4. Tamper one byte inside memory.cruxpack (negative) — re-verify and assert
#      ok=false with a hash-mismatch failure and a NON-ZERO exit. This proves the
#      verifier is real, not a rubber stamp that always returns ok.
#   5. Clean up the tmp dirs on exit.
#
# The positive report is printed to stdout so the release job can publish it in
# the release notes.
#
# Requirements: bash, jq, a built `corecruxctl` (default lookup:
# target/release/corecruxctl, then target/debug/corecruxctl, then `which`).
# No daemon needed — pure offline export + verify.
#
# Usage:
#   bash scripts/assert-context-custody.sh
#   CORECRUXCTL=/path/to/corecruxctl bash scripts/assert-context-custody.sh

set -euo pipefail

# ── 0. Locate corecruxctl ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -n "${CORECRUXCTL:-}" ]]; then
  CTL="${CORECRUXCTL}"
elif [[ -x "${ROOT}/target/release/corecruxctl" ]]; then
  CTL="${ROOT}/target/release/corecruxctl"
elif [[ -x "${ROOT}/target/debug/corecruxctl" ]]; then
  CTL="${ROOT}/target/debug/corecruxctl"
elif command -v corecruxctl >/dev/null 2>&1; then
  CTL="$(command -v corecruxctl)"
else
  cat >&2 <<'EOF'
ERROR: corecruxctl not found.
Build it first:
  cargo build --release --bin corecruxctl
Or set CORECRUXCTL=/path/to/corecruxctl when invoking this script.
EOF
  exit 2
fi

command -v jq >/dev/null 2>&1 || { echo "ERROR: jq is required" >&2; exit 2; }

echo "Using corecruxctl: ${CTL}"

# ── 1. Tmp data dir + bundle out dir ───────────────────────────────────────
DATA_DIR="$(mktemp -d -t crux-custody-data-XXXXXX)"
OUT_DIR="$(mktemp -d -t crux-custody-out-XXXXXX)"
# `context export` creates the out dir itself; hand it a non-existent path.
rmdir "${OUT_DIR}"

SHARD=1
TENANT="custody-selftest"
RID="00000000-0000-4000-8000-c05700d17e57"

cleanup() {
  rm -rf "${DATA_DIR}" "${OUT_DIR}"
}
trap cleanup EXIT

echo
echo "── 1. Seed a CROWN receipt (${RID})"
"${CTL}" receipts seed-minimal \
  --data-dir "${DATA_DIR}" \
  --shard "${SHARD}" \
  --tenant-id "${TENANT}" \
  --receipt-id "${RID}" >/dev/null
echo "   seeded ✓"

# ── 2. Export the custody bundle ───────────────────────────────────────────
echo
echo "── 2. context export — expect signed=true"
EXPORT_LOG="$("${CTL}" context export \
  --data-dir "${DATA_DIR}" \
  --out "${OUT_DIR}" \
  --tenant "${TENANT}")"
echo "   ${EXPORT_LOG}"
if [[ "${EXPORT_LOG}" != *"signed=true"* ]]; then
  echo "FAIL: context export did not report signed=true" >&2
  exit 1
fi

# ── 3. Positive: verify the clean bundle — expect ok=true, exit 0 ──────────
echo
echo "── 3. context verify (clean) — expect ok=true and all four checks true"
set +e
VR1="$("${CTL}" context verify "${OUT_DIR}" --json 2>/dev/null)"
VR1_RC=$?
set -e

OK1="$(echo "${VR1}" | jq -r '.ok')"
SIG1="$(echo "${VR1}" | jq -r '.signature_valid')"
CPH1="$(echo "${VR1}" | jq -r '.cruxpack_hash_match')"
ABH1="$(echo "${VR1}" | jq -r '.audit_bundle_hash_match')"
CPV1="$(echo "${VR1}" | jq -r '.cruxpack_verify_ok')"
ABV1="$(echo "${VR1}" | jq -r '.audit_verify_ok')"

if [[ "${VR1_RC}" -ne 0 || "${OK1}" != "true" || "${SIG1}" != "true" || \
      "${CPH1}" != "true" || "${ABH1}" != "true" || \
      "${CPV1}" != "true" || "${ABV1}" != "true" ]]; then
  echo "FAIL: clean custody bundle did not verify" >&2
  echo "   exit=${VR1_RC} report:" >&2
  echo "${VR1}" | jq . >&2
  exit 1
fi
echo "   ok=true signature_valid=true cruxpack/audit hash+verify all ✓ (exit ${VR1_RC})"

# ── 4. Negative: tamper memory.cruxpack — expect ok=false, non-zero exit ────
echo
echo "── 4. Tamper memory.cruxpack — expect verify ok=false and non-zero exit"
CRUXPACK="${OUT_DIR}/memory.cruxpack"
if [[ ! -f "${CRUXPACK}" ]]; then
  echo "FAIL: expected ${CRUXPACK} to exist in the bundle" >&2
  ls -la "${OUT_DIR}" >&2 || true
  exit 1
fi
SZ="$(stat -c %s "${CRUXPACK}" 2>/dev/null || stat -f %z "${CRUXPACK}")"
FLIP_AT=$(( SZ / 2 ))
ORIG_BYTE="$(xxd -s "${FLIP_AT}" -l 1 -p "${CRUXPACK}")"
NEW_BYTE="$(printf '%02x' $(( 0x${ORIG_BYTE} ^ 0x55 )))"
printf '\x'"${NEW_BYTE}" | dd of="${CRUXPACK}" bs=1 count=1 seek="${FLIP_AT}" conv=notrunc 2>/dev/null
echo "   flipped byte at offset ${FLIP_AT}: 0x${ORIG_BYTE} -> 0x${NEW_BYTE}"

set +e
VR2="$("${CTL}" context verify "${OUT_DIR}" --json 2>/dev/null)"
VR2_RC=$?
set -e

OK2="$(echo "${VR2}" | jq -r '.ok')"
CPH2="$(echo "${VR2}" | jq -r '.cruxpack_hash_match')"
FAILS2="$(echo "${VR2}" | jq -r '.failures | length')"

if [[ "${VR2_RC}" -eq 0 || "${OK2}" != "false" || "${CPH2}" != "false" || "${FAILS2}" -lt 1 ]]; then
  echo "FAIL: tampered custody bundle was NOT rejected — the verifier is not enforcing" >&2
  echo "   exit=${VR2_RC} report:" >&2
  echo "${VR2}" | jq . >&2
  exit 1
fi
echo "   ok=false cruxpack_hash_match=false failures=${FAILS2} (exit ${VR2_RC}) ✓"

# ── 5. Done ────────────────────────────────────────────────────────────────
echo
echo "Context-custody exit test PASSED: a passport-signed bundle exports, verifies"
echo "offline (positive), and the offline verifier rejects a one-byte tamper (negative)."
echo
echo "Release-notes line:"
echo "${EXPORT_LOG}" | sed 's/^/  /'
