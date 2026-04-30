#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

required=(
  "LICENCE-CODE.md"
  "LICENCE-CONTENT.md"
  "TRUST-CONTRACT.md"
  "README.md"
  "config.example.env"
  "config.example.yaml"
  "docs/release-packaging.md"
  "content/MANIFEST.json"
  "content/README.md"
  "scripts/package-daemon-release.sh"
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

package_script="$root/scripts/package-daemon-release.sh"
for needle in \
  "corecruxd-" \
  "crux-" \
  "corecruxctl-" \
  "LICENCE-CODE.md" \
  "LICENCE-CONTENT.md" \
  "TRUST-CONTRACT.md" \
  "config.example.env" \
  "config.example.yaml" \
  "docs/release-packaging.md" \
  "content/MANIFEST.json" \
  "RELEASE-MANIFEST"; do
  if ! rg -q "$needle" "$package_script"; then
    echo "daemon release package script missing required artifact marker: $needle" >&2
    exit 1
  fi
done

if [[ -x "$root/target/release/corecruxd" && -x "$root/target/release/corecruxctl" ]]; then
  dist="$(mktemp -d)"
  trap 'rm -f "$scan_output"; rm -rf "$dist"' EXIT
  bash "$package_script" boundary-smoke "$dist" >/dev/null
  for artifact in \
    "corecruxd-boundary-smoke" \
    "crux-boundary-smoke" \
    "corecruxctl-boundary-smoke" \
    "LICENCE-CODE.md" \
    "LICENCE-CONTENT.md" \
    "TRUST-CONTRACT.md" \
    "config.example.env" \
    "config.example.yaml" \
    "docs/release-packaging.md" \
    "content/MANIFEST.json" \
    "content/README.md" \
    "RELEASE-MANIFEST-boundary-smoke.txt"; do
    if [[ ! -f "$dist/$artifact" ]]; then
      echo "daemon release package smoke missing artifact: $artifact" >&2
      exit 1
    fi
  done
fi

echo "daemon release boundary OK"
