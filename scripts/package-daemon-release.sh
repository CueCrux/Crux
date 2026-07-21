#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <target-suffix> [dist-dir]" >&2
  exit 64
fi

suffix="$1"
dist_arg="${2:-dist}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$dist_arg" = /* ]]; then
  dist="$dist_arg"
else
  dist="$root/$dist_arg"
fi

mkdir -p "$dist/content" "$dist/docs"

cp "$root/target/release/corecruxd" "$dist/corecruxd-$suffix"
cp "$root/target/release/corecruxd" "$dist/crux-$suffix"
cp "$root/target/release/corecruxctl" "$dist/corecruxctl-$suffix"
cp "$root/target/release/crux-hook" "$dist/crux-hook-$suffix"
cp "$root/LICENCE.md" "$root/TRUST-CONTRACT.md" "$dist/"
cp "$root/README.md" "$root/config.example.env" "$root/config.example.yaml" "$dist/"
cp "$root/docs/release-packaging.md" "$dist/docs/"
cp "$root/content/MANIFEST.json" "$root/content/README.md" "$root/content/LICENCE-CONTENT.md" "$dist/content/"

manifest="$dist/RELEASE-MANIFEST-$suffix.txt"
(
  cd "$dist"
  if command -v sha256sum >/dev/null 2>&1; then
    find . -type f ! -name "RELEASE-MANIFEST-$suffix.txt" -print0 | sort -z | xargs -0 sha256sum
  else
    find . -type f ! -name "RELEASE-MANIFEST-$suffix.txt" -print0 | sort -z | xargs -0 shasum -a 256
  fi
) >"$manifest"

echo "daemon release package staged at $dist for $suffix"
