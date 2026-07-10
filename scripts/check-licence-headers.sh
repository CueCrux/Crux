#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# check-licence-headers.sh — enforce the CCL source header on every crate .rs.
#
# Two independent requirements, both must hold for every file under crates/:
#   1. the human-readable licence line ("Licensed under the CueCrux Community
#      Licence (CCL v1.0).") — the long-standing header rule (CLAUDE.md); and
#   2. the machine-readable SPDX identifier ("SPDX-License-Identifier:
#      LicenseRef-CCL-1.0") so SBOM/compliance scanners get a parseable answer
#      instead of "Unknown" (the CCL is a custom licence GitHub's licensee will
#      never detect — this line is what scanners consume).
#
# Offline, no toolchain, no network. Wired into the CI `lint` job.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

licensed_re='Licensed under the CueCrux Community Licence \(CCL v1\.0\)\.'
spdx_re='SPDX-License-Identifier: LicenseRef-CCL-1\.0'

# Files missing the human-readable licence line.
missing_licensed="$(grep -rL -E "$licensed_re" --include='*.rs' "$root/crates" || true)"
# Files missing the machine-readable SPDX identifier.
missing_spdx="$(grep -rL -E "$spdx_re" --include='*.rs' "$root/crates" || true)"

status=0
if [[ -n "$missing_licensed" ]]; then
  echo "::error::.rs files missing the CCL licence header line ('Licensed under the CueCrux Community Licence (CCL v1.0).'):" >&2
  echo "$missing_licensed" | sed 's/^/  /' >&2
  status=1
fi
if [[ -n "$missing_spdx" ]]; then
  echo "::error::.rs files missing the SPDX identifier line ('// SPDX-License-Identifier: LicenseRef-CCL-1.0'):" >&2
  echo "$missing_spdx" | sed 's/^/  /' >&2
  echo "::error::Add it as the second header line (after the copyright line). See docs/LICENCE-FAQ.md." >&2
  status=1
fi

if [[ "$status" -ne 0 ]]; then
  exit 1
fi

count="$(find "$root/crates" -name '*.rs' | wc -l | tr -d ' ')"
echo "licence headers OK — CCL + SPDX present on all ${count} crate .rs files"
