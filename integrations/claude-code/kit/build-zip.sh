#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# build-zip.sh — assemble the deliverable Compaction Survival Kit archive.
# Bundles the kit files together with a copy of the free preset's hook scripts
# and fixture, so the delivered zip is self-contained (installs without the Crux
# repo present). Uses `zip` if available, else falls back to python3's zipfile.
#
# Usage: build-zip.sh [out_dir]   (default: ./dist)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
preset="$here/../compaction-survival"
out="${1:-$here/dist}"
name="compaction-survival-kit"

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
stage="$work/$name"
mkdir -p "$stage/hooks/fixtures"

cp "$here/install.sh" "$here/proof-report.sh" "$here/COMPARISON.md" "$here/README.md" "$here/codex-hooks.snippet.json" "$stage/"
cp "$preset/snapshot.sh" "$preset/restore.sh" "$preset/proof.sh" "$stage/hooks/"
cp "$preset/settings.snippet.json" "$stage/claude-settings.snippet.json"
cp "$preset/fixtures/transcript.jsonl" "$stage/hooks/fixtures/"
chmod +x "$stage/install.sh" "$stage/proof-report.sh" "$stage/hooks/"*.sh

mkdir -p "$out"
archive="$out/$name.zip"
rm -f "$archive"
if command -v zip >/dev/null 2>&1; then
  ( cd "$work" && zip -rq "$archive" "$name" )
else
  ( cd "$work" && python3 -m zipfile -c "$archive" "$name" )
fi

echo "built: $archive"
( cd "$out" && command -v unzip >/dev/null 2>&1 && unzip -l "$archive" || python3 -m zipfile -l "$archive" )
