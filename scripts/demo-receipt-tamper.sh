#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# demo-receipt-tamper.sh — 60-second proof that CROWN receipt verification
# catches on-disk tampering. Operator-facing demo referenced from README.md.
#
# Flow:
#   1. Seed a minimal CROWN receipt into a fresh tmp data dir.
#      (`corecruxctl receipts seed-minimal` uses a fixed dev signing key for
#      repeatable local seeding — see crates/corecruxctl/src/receipts.rs.)
#   2. Run `corecruxctl verify-store --mode full --strict` — assert OK.
#   3. Flip one byte deep inside the segment file holding the receipt body.
#   4. Re-run verify-store — assert NOT OK, with a segment or frame integrity reason.
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

# Seed produces two events: outcomes[0] is the body frame, outcomes[1] is
# the sig frame. We use both: body to identify the target frame, sig.offset
# as an upper bound for the body frame's payload region.
BODY_OFFSET="$(echo "${SEED_JSON}" | jq -e -r '.outcomes[0].location.offset')"
SIG_OFFSET="$(echo "${SEED_JSON}" | jq -e -r '.outcomes[1].location.offset')"
EPOCH="$(echo "${SEED_JSON}" | jq -e -r '.outcomes[0].location.epoch')"
SEGMENT_SEQ="$(echo "${SEED_JSON}" | jq -e -r '.outcomes[0].location.segment_seq')"

echo "   body frame at shard=${SHARD} epoch=${EPOCH} segment_seq=${SEGMENT_SEQ} offset=${BODY_OFFSET}"
echo "   sig frame  at offset=${SIG_OFFSET} (used as body-frame upper bound)"

# ── 2. Verify clean state ──────────────────────────────────────────────────
echo
echo "── 2. Verify clean state — expect ok=true"
VR1="$("${CTL}" verify-store \
  --data-dir "${DATA_DIR}" \
  --shard "${SHARD}" \
  --scope all \
  --mode full \
  --strict)"

OK1="$(echo "${VR1}" | jq -r '.ok')"
if [[ "${OK1}" != "true" ]]; then
  echo "FAIL: clean state verification returned ok=${OK1}; expected true" >&2
  echo "${VR1}" | jq . >&2
  exit 1
fi
echo "   ok=true ✓"

# ── 3. Tamper: flip one byte inside the segment ────────────────────────────
# Segment layout (see crates/corecrux-segment):
#   <data_dir>/shards/shard-XXXX/segments/seg-<seq>-<uuid>.ccxseg
# The file is [4096-byte segment header][frames][TOC][256-byte footer].
# Each frame is [magic+canonical_header][payload][trailer]. To hit the body
# frame's payload (and trigger FRAME_PAYLOAD_HASH_MISMATCH), we flip a byte
# 16 bytes before where the sig frame begins — guaranteed to land in the
# tail of the body frame's CBOR payload, not in its header.
SHARD_DIR="$(printf '%s/shards/shard-%04d' "${DATA_DIR}" "${SHARD}")"
SEGMENTS_DIR="${SHARD_DIR}/segments"
echo
echo "── 3. Tamper — flip 1 byte inside ${SEGMENTS_DIR}"

# Segment file name pattern: seg-<segment_seq:020>-<uuid_hex>.ccxseg.
SEG_FILE="$(find "${SEGMENTS_DIR}" -type f -name "seg-*.ccxseg" -print -quit 2>/dev/null)"
if [[ -z "${SEG_FILE}" || ! -f "${SEG_FILE}" ]]; then
  echo "FAIL: no .ccxseg file found under ${SEGMENTS_DIR}" >&2
  ls -la "${SEGMENTS_DIR}" >&2 || true
  exit 1
fi
echo "   target: ${SEG_FILE}"

SEG_SIZE="$(stat -c %s "${SEG_FILE}" 2>/dev/null || stat -f %z "${SEG_FILE}")"
FLIP_AT=$(( SIG_OFFSET - 16 ))
if (( FLIP_AT <= BODY_OFFSET || FLIP_AT >= SEG_SIZE )); then
  echo "FAIL: computed flip offset ${FLIP_AT} is outside body-frame range [${BODY_OFFSET}, ${SEG_SIZE})" >&2
  exit 1
fi

ORIG_BYTE="$(xxd -s "${FLIP_AT}" -l 1 -p "${SEG_FILE}")"
NEW_BYTE="$(printf '%02x' $(( 0x${ORIG_BYTE} ^ 0x55 )))"
printf '\x'"${NEW_BYTE}" | dd of="${SEG_FILE}" bs=1 count=1 seek="${FLIP_AT}" conv=notrunc 2>/dev/null
echo "   flipped byte at offset ${FLIP_AT}: 0x${ORIG_BYTE} -> 0x${NEW_BYTE}"

# ── 4. Verify tampered state ───────────────────────────────────────────────
echo
echo "── 4. Verify tampered state — expect ok=false with an integrity failure"
# verify-store prints the JSON report to stdout and exits non-zero on failure;
# disable -e for this call so we can inspect both.
set +e
VR2="$("${CTL}" verify-store \
  --data-dir "${DATA_DIR}" \
  --shard "${SHARD}" \
  --scope all \
  --mode full \
  --strict 2>/dev/null)"
VR2_RC=$?
set -e

OK2="$(echo "${VR2}" | jq -r '.ok')"
REASON="$(echo "${VR2}" | jq -r '.shards[0].reason // "<no reason>"')"
ERROR_MSG="$(echo "${VR2}" | jq -r '.shards[0].error // ""')"

# Any one of these proves tampering was detected:
#   - shard reason names a *MISMATCH or *CORRUPT class
#   - shard error message mentions "hash mismatch" or "record_hash"
# The exact classification depends on which integrity layer (segment record
# hash, frame header hash, frame payload hash, trailer hash, TOC checksum)
# catches the flipped byte first.
if [[ "${OK2}" == "false" ]] && {
     [[ "${REASON}" == *MISMATCH* ]] ||
     [[ "${REASON}" == *CORRUPT* ]] ||
     [[ "${ERROR_MSG}" == *"hash mismatch"* ]] ||
     [[ "${ERROR_MSG}" == *"record_hash"* ]]
   }; then
  echo "   ok=false reason=${REASON} error=\"${ERROR_MSG}\" ✓"
  echo
  echo "Tamper caught. The on-disk byte flip was detected by verify-store --strict."
  echo "(Exact classification depends on which integrity layer fires first;"
  echo "the receipt-level verifier surfaces BODY_HASH_MISMATCH / SIG_INVALID"
  echo "at the corecrux-receipts API — see crates/corecrux-receipts/src/tests.rs"
  echo "for the equivalent unit-test demonstration.)"
  exit 0
fi

echo "FAIL: tamper not detected as expected" >&2
echo "   got ok=${OK2} reason=${REASON} error=\"${ERROR_MSG}\" exit=${VR2_RC}" >&2
echo "${VR2}" | jq . >&2
exit 1
