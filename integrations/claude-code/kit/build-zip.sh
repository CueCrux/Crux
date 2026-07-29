#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# build-zip.sh — assemble the deliverable Compaction Survival Kit archive.
# Bundles the kit files with a copy of the free preset's hook scripts + fixture,
# so the delivered zip installs without the Crux repo present. Uses `zip` if
# available, else python3's zipfile module.
#
# Usage: build-zip.sh [out_dir]   (default: ./dist). Linux/macOS.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
preset="$here/../compaction-survival"
name="compaction-survival-kit"

# Canonicalize out_dir to an absolute path BEFORE any cd (relative $1 must not
# break once we cd into the staging dir).
out_arg="${1:-$here/dist}"
mkdir -p "$out_arg"
out="$(cd "$out_arg" && pwd)"

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
stage="$work/$name"
mkdir -p "$stage/hooks/fixtures"

cp "$here/install.sh" "$here/event-report.sh" "$here/COMPARISON.md" "$here/README.md" "$here/codex-hooks.snippet.json" "$stage/"
cp "$preset/snapshot.sh" "$preset/restore.sh" "$preset/selftest.sh" "$stage/hooks/"
cp "$preset/settings.snippet.json" "$stage/claude-settings.snippet.json"
cp "$preset/fixtures/transcript.jsonl" "$stage/hooks/fixtures/"
chmod 0755 "$stage/install.sh" "$stage/event-report.sh" "$stage/hooks/"*.sh

archive="$out/$name.zip"
rm -f "$archive"
if command -v zip >/dev/null 2>&1; then
  ( cd "$work" && zip -rq "$archive" "$name" )
else
  ( cd "$work" && python3 -m zipfile -c "$archive" "$name" )
fi

echo "built: $archive"
if command -v unzip >/dev/null 2>&1; then
  unzip -l "$archive"
else
  python3 -m zipfile -l "$archive"
fi
