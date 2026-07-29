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
cp "$root/LICENSE" "$root/NOTICE" "$root/TRUST-CONTRACT.md" "$dist/"
cp "$root/README.md" "$root/config.example.env" "$root/config.example.yaml" "$dist/"
cp "$root/docs/release-packaging.md" "$dist/docs/"
cp "$root/content/MANIFEST.json" "$root/content/LICENCE-CONTENT.md" "$dist/content/"
# GitHub release assets are a flat namespace. Keep the content guide distinct
# from the repository README so both can be uploaded without a basename race.
cp "$root/content/README.md" "$dist/content/CONTENT-README.md"

# The installer is platform-agnostic and uploaded once from the linux-amd64
# release leg. Stage it before hashing so its signed-manifest coverage matches
# the public verification claim; the workflow also signs it directly.
if [[ "$suffix" == "linux-amd64" ]]; then
  cp "$root/packaging/install.sh" "$dist/install.sh"
fi

bash "$root/scripts/assert-release-asset-basenames.sh" "$dist" >/dev/null

manifest="$dist/RELEASE-MANIFEST-$suffix.txt"
(
  cd "$dist"
  if command -v sha256sum >/dev/null 2>&1; then
    hash_cmd=(sha256sum)
  else
    hash_cmd=(shasum -a 256)
  fi
  # GitHub release assets are flat. The basename guard above makes this
  # checksum namespace unambiguous, so a downloaded asset verifies without
  # recreating the staging-only content/ and docs/ directories.
  while IFS= read -r -d '' file; do
    checksum="$("${hash_cmd[@]}" "$file" | awk '{print $1}')"
    printf '%s  %s\n' "$checksum" "${file##*/}"
  done < <(find . -type f ! -name "RELEASE-MANIFEST-$suffix.txt" -print0 | LC_ALL=C sort -z)
) >"$manifest"

echo "daemon release package staged at $dist for $suffix"
