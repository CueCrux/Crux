#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Build the crux-daemon .deb from already-built (and, in the release flow,
# already-signed) artifacts. Run from the repo root:
#
#   1. Stage binaries:
#        cargo build --locked --release \
#          --bin corecruxd --bin corecruxctl --bin crux-hook
#        mkdir -p dist
#        cp target/release/corecruxd dist/crux-linux-amd64
#        cp target/release/corecruxctl dist/corecruxctl-linux-amd64
#        cp target/release/crux-hook dist/crux-hook-linux-amd64
#      (In the release flow these come from the signed release artifacts
#       instead — verify per docs/verify-release.md before packaging.)
#   2. Build:
#        CRUX_VERSION=0.5.0 bash packaging/deb/build-deb.sh
#
# Output: dist/crux-daemon_<version>_amd64.deb
# Attaching the .deb to the GitHub Release (and signing it like the other
# artifacts) is a release-workflow step, gated until PR #172 merges.
set -euo pipefail

: "${CRUX_VERSION:?set CRUX_VERSION, e.g. CRUX_VERSION=0.5.0}"

if ! command -v nfpm >/dev/null 2>&1; then
  echo "ERROR: nfpm not found. Install: https://nfpm.goreleaser.com/install/" >&2
  exit 2
fi

for f in \
  dist/crux-linux-amd64 \
  dist/corecruxctl-linux-amd64 \
  dist/crux-hook-linux-amd64; do
  [ -f "$f" ] || { echo "ERROR: missing $f — stage binaries first (see header)" >&2; exit 2; }
done

export CRUX_VERSION
nfpm package \
  --config packaging/deb/nfpm.yaml \
  --packager deb \
  --target "dist/crux-daemon_${CRUX_VERSION}_amd64.deb"

echo "Built dist/crux-daemon_${CRUX_VERSION}_amd64.deb"
echo "Lint (optional): lintian dist/crux-daemon_${CRUX_VERSION}_amd64.deb"
