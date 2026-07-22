#!/usr/bin/env bash
# shellcheck disable=SC2016 # GitHub/installer template expressions are literal markers.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

required=(
  "LICENCE.md"
  "content/LICENCE-CONTENT.md"
  "TRUST-CONTRACT.md"
  "README.md"
  "config.example.env"
  "config.example.yaml"
  "docs/release-packaging.md"
  "content/MANIFEST.json"
  "content/README.md"
  "packaging/install.sh"
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

if command -v rg >/dev/null 2>&1; then
  scan_cmd=(rg -in '(cuda|cudart|nvcc|libcuda|corecrux-gpu)' "$root/Cargo.toml" "$root/crates" --glob 'Cargo.toml')
else
  scan_cmd=(grep -RInEi --include 'Cargo.toml' '(cuda|cudart|nvcc|libcuda|corecrux-gpu)' "$root/Cargo.toml" "$root/crates")
fi

if "${scan_cmd[@]}" >"$scan_output"; then
  cat "$scan_output" >&2
  echo "daemon distribution boundary violation: hosted GPU/CUDA surface found" >&2
  exit 1
fi

package_script="$root/scripts/package-daemon-release.sh"
for needle in \
  "corecruxd-" \
  "crux-" \
  "corecruxctl-" \
  "crux-hook-" \
  "LICENCE.md" \
  "content/LICENCE-CONTENT.md" \
  "TRUST-CONTRACT.md" \
  "config.example.env" \
  "config.example.yaml" \
  "docs/release-packaging.md" \
  "content/MANIFEST.json" \
  "CONTENT-README.md" \
  'cp "$root/packaging/install.sh" "$dist/install.sh"' \
  "RELEASE-MANIFEST"; do
  if ! grep -Fq -- "$needle" "$package_script"; then
    echo "daemon release package script missing required artifact marker: $needle" >&2
    exit 1
  fi
done

require_marker() {
  local path="$1"
  local needle="$2"
  if ! grep -Fq -- "$needle" "$root/$path"; then
    echo "$path missing required hook-distribution marker: $needle" >&2
    exit 1
  fi
}

# `crux-hook` is part of the supported daemon distribution, not an incidental
# workspace binary. Keep every release/install surface in the regression gate
# so a future packaging edit cannot silently strand users on an old hook.
require_marker ".github/workflows/release.yml" \
  '--bin corecruxd --bin corecruxctl --bin crux-hook'
require_marker ".github/workflows/release.yml" \
  'cp "target/${{ matrix.target }}/release/crux-hook" target/release/crux-hook'
require_marker ".github/workflows/release.yml" \
  '"dist/crux-hook-${{ matrix.suffix }}"'
require_marker ".github/workflows/release.yml" \
  '"crux-hook-${{ matrix.suffix }}"'
require_marker "packaging/install.sh" '"crux-hook-${SUFFIX}"'
require_marker "packaging/install.sh" \
  'install -m 0755 "${WORK}/crux-hook-${SUFFIX}" "${BIN_DIR}/crux-hook"'
require_marker "packaging/deb/nfpm.yaml" 'src: dist/crux-hook-linux-amd64'
require_marker "packaging/homebrew/crux.rb" 'resource "crux-hook" do'
require_marker "scripts/generate-homebrew-formula.sh" \
  'sha_hook_linux_amd64="$(sha_for linux-amd64 "crux-hook-linux-amd64")"'
require_marker "scripts/generate-update-manifest.sh" 'name="standalone-${asset_name}"'
require_marker "scripts/generate-update-manifest.sh" 'asset_name:$a'
require_marker "packaging/tests/install-smoke.sh" \
  '"${PREFIX}/bin/crux-hook" --version'
require_marker "packaging/tests/install-smoke.sh" \
  'cosign verify-blob'
require_marker "packaging/tests/install-smoke.sh" \
  'RELEASE-MANIFEST-linux-amd64.txt'
require_marker "packaging/tests/install-smoke.sh" \
  'install.sh does not match signed release manifest'
require_marker ".github/workflows/release.yml" \
  'package-daemon-release.sh has already staged install.sh before generating'
require_marker ".github/workflows/release.yml" \
  'Assert unique release asset basenames'

if [[ -x "$root/target/release/corecruxd" \
  && -x "$root/target/release/corecruxctl" \
  && -x "$root/target/release/crux-hook" ]]; then
  dist="$(mktemp -d)"
  trap 'rm -f "$scan_output"; rm -rf "$dist"' EXIT
  # Use the linux-amd64 release suffix so the single-copy installer path is
  # exercised even when this structural smoke runs on another native runner.
  bash "$package_script" linux-amd64 "$dist" >/dev/null
  for artifact in \
    "corecruxd-linux-amd64" \
    "crux-linux-amd64" \
    "corecruxctl-linux-amd64" \
    "crux-hook-linux-amd64" \
    "install.sh" \
    "LICENCE.md" \
    "content/LICENCE-CONTENT.md" \
    "TRUST-CONTRACT.md" \
    "config.example.env" \
    "config.example.yaml" \
    "docs/release-packaging.md" \
    "content/MANIFEST.json" \
    "content/CONTENT-README.md" \
    "RELEASE-MANIFEST-linux-amd64.txt"; do
    if [[ ! -f "$dist/$artifact" ]]; then
      echo "daemon release package smoke missing artifact: $artifact" >&2
      exit 1
    fi
  done
  if ! grep -Eq '[[:space:]]+\./install\.sh$' \
    "$dist/RELEASE-MANIFEST-linux-amd64.txt"; then
    echo "daemon release manifest does not cover install.sh" >&2
    exit 1
  fi
  if ! cmp -s "$root/README.md" "$dist/README.md"; then
    echo "staged README.md does not match the repository README" >&2
    exit 1
  fi
  if ! cmp -s "$root/content/README.md" "$dist/content/CONTENT-README.md"; then
    echo "staged CONTENT-README.md does not match the content guide" >&2
    exit 1
  fi
  duplicate_basenames="$(find "$dist" -type f -exec basename {} \; | sort | uniq -d)"
  if [[ -n "$duplicate_basenames" ]]; then
    echo "daemon release package contains duplicate asset basenames:" >&2
    printf '%s\n' "$duplicate_basenames" >&2
    exit 1
  fi
fi

echo "daemon release boundary OK"
