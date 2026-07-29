#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Smoke: generate a fixture observation JSONL, verify it, then tamper one
# byte and confirm the verifier rejects the tampered file. Proves the
# end-to-end signing/verification chain without a running daemon.
#
# Run from the Crux/ workspace root:
#   bash scripts/smoke-observations.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

OUT_DIR="$(mktemp -d)"
JSONL="${OUT_DIR}/observations.jsonl"
PUBKEY="${OUT_DIR}/pubkey.hex"

cleanup() { rm -rf "${OUT_DIR}"; }
trap cleanup EXIT

echo "==> generate fixture (3 observations)"
cargo run --quiet --example generate_observation_fixture -- \
  --out "${JSONL}" \
  --pubkey-out "${PUBKEY}" \
  --lines 3

echo
echo "==> verify untampered fixture (expect: 0)"
cargo run --quiet --example verify_observations -- \
  --jsonl "${JSONL}" \
  --pubkey-hex "$(cat "${PUBKEY}")"
echo "OK"

echo
echo "==> tamper byte in line 2 (expect: verifier rejects)"
# Flip a byte inside the payload of line 2 — anywhere that survives JSON
# parsing but changes the hash. Easiest: rewrite the file with one line's
# observation_id mutated.
python3 - <<PY
import json
with open("${JSONL}") as f:
    lines = f.readlines()
record = json.loads(lines[1])
record["observation_id"] = "tampered-" + record["observation_id"]
lines[1] = json.dumps(record) + "\n"
with open("${JSONL}", "w") as f:
    f.writelines(lines)
PY

if cargo run --quiet --example verify_observations -- \
   --jsonl "${JSONL}" \
   --pubkey-hex "$(cat "${PUBKEY}")"; then
  echo "FAIL: verifier accepted per-record tampered fixture"
  exit 1
fi

echo
echo "==> regenerate clean fixture then tamper the CHAIN (drop line 2)"
cargo run --quiet --example generate_observation_fixture -- \
  --out "${JSONL}" \
  --pubkey-out "${PUBKEY}" \
  --lines 3

# Remove the middle line. Each remaining record still verifies per-record
# (its own hash + sig are intact) BUT the chain breaks: line 3 expected
# prev_hash to point at line 2, which is no longer present.
python3 - <<PY
with open("${JSONL}") as f:
    lines = f.readlines()
with open("${JSONL}", "w") as f:
    f.writelines([lines[0], lines[2]])
PY

if cargo run --quiet --example verify_observations -- \
   --jsonl "${JSONL}" \
   --pubkey-hex "$(cat "${PUBKEY}")"; then
  echo "FAIL: verifier accepted chain-tampered fixture"
  exit 1
fi

echo
echo "smoke OK: per-record signing, per-record tamper, AND chain tamper all detected."
