#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

required=(
  "LICENCE-CODE.md"
  "LICENCE-CONTENT.md"
  "TRUST-CONTRACT.md"
  "content/MANIFEST.json"
)

for path in "${required[@]}"; do
  if [[ ! -f "$root/$path" ]]; then
    echo "missing required daemon distribution file: $path" >&2
    exit 1
  fi
done

scan_output="$(mktemp)"
trap 'rm -f "$scan_output"' EXIT

if rg -in '(cuda|cudart|nvcc|libcuda|corecrux-gpu)' "$root/Cargo.toml" "$root/crates" --glob 'Cargo.toml' >"$scan_output"; then
  cat "$scan_output" >&2
  echo "daemon distribution boundary violation: hosted GPU/CUDA surface found" >&2
  exit 1
fi

echo "daemon release boundary OK"
