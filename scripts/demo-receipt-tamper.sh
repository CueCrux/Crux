#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# demo-receipt-tamper.sh — 60-second proof that CROWN receipt verification
# catches on-disk tampering. Operator-facing demo referenced from README.md.
#
# Flow:
#   1. Seed a minimal CROWN receipt into a fresh tmp data dir.
#      (`corecruxctl receipts seed-minimal` uses a fixed dev signing key for
#      repeatable local seeding — see crates/corecruxctl/src/receipts.rs.)
#   2. Run `corecruxctl verify-store --mode full` — assert OK.
#   3. Flip one byte deep inside the segment file holding the receipt body.
#   4. Re-run verify-store — assert NOT OK, with a payload-hash mismatch reason.
#   5. Clean up the tmp dir on exit.
#
# Requirements: bash, jq, a built `corecruxctl` binary (default lookup:
# target/release/corecruxctl, then target/debug/corecruxctl, then `which`).
# No daemon needed — this is pure offline verification.
#
# Usage:
#   bash scripts/demo-receipt-tamper.sh
#   CORECRUXCTL=/path/to/corecruxctl bash scripts/demo-receipt-tamper.sh

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

# ── 1. Tmp data dir ────────────────────────────────────────────────────────
DATA_DIR="$(mktemp -d -t crux-tamper-demo-XXXXXX)"
SHARD=1
TENANT="demo-tenant"
RID="00000000-0000-4000-8000-deadbeefcafe"

cleanup() {
  rm -rf "${DATA_DIR}"
}
trap cleanup EXIT

echo
echo "── 1. Seed a CROWN receipt (${RID})"
SEED_JSON="$("${CTL}" receipts seed-minimal \
  --data-dir "${DATA_DIR}" \
  --shard "${SHARD}" \
  --tenant-id "${TENANT}" \
  --receipt-id "${RID}")"

# Pull the body-frame location from the seed report; the body event is the
# first outcome (see receipts::seed_minimal_receipt_v1).
BODY_LOC_JSON="$(echo "${SEED_JSON}" | jq -e '.outcomes[0].location')"
SEGMENT_SEQ="$(echo "${BODY_LOC_JSON}" | jq -r '.segment_seq')"
OFFSET="$(echo "${BODY_LOC_JSON}" | jq -r '.offset')"
EPOCH="$(echo "${BODY_LOC_JSON}" | jq -r '.epoch')"

echo "   body frame at shard=${SHARD} epoch=${EPOCH} segment_seq=${SEGMENT_SEQ} offset=${OFFSET}"

# ── 2. Verify clean state ──────────────────────────────────────────────────
echo
echo "── 2. Verify clean state — expect ok=true"
VR1="$("${CTL}" verify-store \
  --data-dir "${DATA_DIR}" \
  --shard "${SHARD}" \
  --scope all \
  --mode full)"

OK1="$(echo "${VR1}" | jq -r '.ok')"
if [[ "${OK1}" != "true" ]]; then
  echo "FAIL: clean state verification returned ok=${OK1}; expected true" >&2
  echo "${VR1}" | jq . >&2
  exit 1
fi
echo "   ok=true ✓"

# ── 3. Tamper: flip one byte inside the segment ────────────────────────────
# Segment layout (see crates/corecrux-segment): per-shard segment files live
# at <data_dir>/shards/shard-XXXX/. The seed report told us where the body
# frame starts; we flip a byte well inside the payload region so we hit the
# body, not the header (header hash mismatch is a different reason).
SHARD_DIR="$(printf '%s/shards/shard-%04d' "${DATA_DIR}" "${SHARD}")"
echo
echo "── 3. Tamper — flip 1 byte inside ${SHARD_DIR}"

# Find the segment file matching this epoch+segment_seq. Naming convention
# is deterministic; if Crux changes it the script needs an update.
SEG_FILE="$(find "${SHARD_DIR}" -type f \( -name "segment-*" -o -name "*.seg" \) -print -quit)"
if [[ -z "${SEG_FILE}" || ! -f "${SEG_FILE}" ]]; then
  echo "FAIL: no segment file found under ${SHARD_DIR}" >&2
  ls -la "${SHARD_DIR}" >&2 || true
  exit 1
fi
echo "   target: ${SEG_FILE}"

# Flip the lowest bit at offset = frame_offset + 64 (well past the 56-byte
# frame header into the body payload). 64 bytes covers the standard frame
# header + magic; if the layout shifts, adjust.
FLIP_AT=$(( OFFSET + 64 ))
SEG_SIZE="$(stat -c %s "${SEG_FILE}" 2>/dev/null || stat -f %z "${SEG_FILE}")"
if (( FLIP_AT >= SEG_SIZE )); then
  echo "FAIL: flip offset ${FLIP_AT} >= segment size ${SEG_SIZE}" >&2
  exit 1
fi

ORIG_BYTE="$(xxd -s "${FLIP_AT}" -l 1 -p "${SEG_FILE}")"
NEW_BYTE="$(printf '%02x' $(( 0x${ORIG_BYTE} ^ 0x55 )))"
printf '\x'"${NEW_BYTE}" | dd of="${SEG_FILE}" bs=1 count=1 seek="${FLIP_AT}" conv=notrunc 2>/dev/null
echo "   flipped byte at offset ${FLIP_AT}: 0x${ORIG_BYTE} -> 0x${NEW_BYTE}"

# ── 4. Verify tampered state ───────────────────────────────────────────────
echo
echo "── 4. Verify tampered state — expect ok=false, reason=*PAYLOAD_HASH_MISMATCH"
# verify-store exits non-zero when verification fails; capture without -e.
set +e
VR2="$("${CTL}" verify-store \
  --data-dir "${DATA_DIR}" \
  --shard "${SHARD}" \
  --scope all \
  --mode full)"
VR2_RC=$?
set -e

OK2="$(echo "${VR2}" | jq -r '.ok')"
REASON="$(echo "${VR2}" | jq -r '.shards[0].reason // "<no reason>"')"

if [[ "${OK2}" == "false" ]] && [[ "${REASON}" == *"PAYLOAD_HASH_MISMATCH"* ]]; then
  echo "   ok=false reason=${REASON} ✓"
  echo
  echo "Tamper caught. CROWN receipt verification works."
  exit 0
fi

echo "FAIL: expected ok=false with PAYLOAD_HASH_MISMATCH reason" >&2
echo "   got ok=${OK2} reason=${REASON} exit=${VR2_RC}" >&2
echo "${VR2}" | jq . >&2
exit 1
