#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <release-assets-dir>" >&2
  exit 64
fi

assets_dir="$1"
if [[ ! -d "$assets_dir" ]]; then
  echo "release assets directory not found: $assets_dir" >&2
  exit 1
fi

duplicates="$(find "$assets_dir" -type f -exec basename -- {} \; | LC_ALL=C sort | uniq -d)"
if [[ -n "$duplicates" ]]; then
  echo "duplicate release asset basenames detected:" >&2
  printf '%s\n' "$duplicates" >&2
  exit 1
fi

echo "release asset basenames OK"
