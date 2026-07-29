#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Fail the build if source files or user-facing docs reference paths inside the
# private CueCrux planning monorepo (`PlanCrux/`). The planning monorepo is not
# part of this repository — any reference is a dead link for external readers
# and operators.
#
# Allowed exceptions:
#   - The `.agent/` planning area itself (excluded from CI triggers anyway).
#   - Workflow files under `.github/` (which intentionally name `.agent/`
#     in their `paths-ignore` lists).
#   - `crates/crux-config-wizard/profiles/workspace-cuecrux.md` — an
#     explicitly CueCrux-scoped profile that operators outside the
#     CueCrux workspace are warned not to enable.
#
# Invoked by the `private-paths` job in `.github/workflows/ci.yml`. Also
# runnable locally:  `bash scripts/check-no-private-paths.sh`

set -euo pipefail

# Files allowed to mention `PlanCrux/`. Add to this list deliberately; don't
# silently widen the exception surface.
ALLOWLIST=(
  # CueCrux-scoped config-wizard profile; operators outside CueCrux are warned
  # against enabling it (see profile header).
  "crates/crux-config-wizard/profiles/workspace-cuecrux.md"
  # The guard itself names the forbidden pattern for matching purposes.
  "scripts/check-no-private-paths.sh"
  # Existing operator-facing drift-check tool with a CueCrux-relative default
  # path. Generalising it (accept any execplans dir, drop the hard-coded
  # `../PlanCrux/.agent/execplans` default) is tracked as a Wave-2 cleanup.
  "scripts/check-execplan-drift.sh"
)

# Collect candidate matches, then drop the allowlisted ones.
mapfile -t HITS < <(
  git grep -lE 'PlanCrux/' \
    -- '*.rs' '*.md' '*.toml' '*.yaml' '*.yml' '*.sh' \
    ':(exclude).agent/' \
    ':(exclude).github/' \
    2>/dev/null || true
)

VIOLATIONS=()
for f in "${HITS[@]}"; do
  allowed=0
  for a in "${ALLOWLIST[@]}"; do
    if [[ "$f" == "$a" ]]; then
      allowed=1
      break
    fi
  done
  if [[ "$allowed" -eq 0 ]]; then
    VIOLATIONS+=("$f")
  fi
done

if [[ "${#VIOLATIONS[@]}" -gt 0 ]]; then
  echo "::error::Forbidden references to the private CueCrux planning monorepo ('PlanCrux/') in:" >&2
  for f in "${VIOLATIONS[@]}"; do
    echo "  $f" >&2
  done
  cat >&2 <<'MSG'

Why this fails: the `PlanCrux/` path tree is not part of this repository. Any
reference is a dead link for external readers and a leaked breadcrumb for
operators who installed bundled config-wizard profiles.

How to fix:
  - Source doc comments: replace the link with a rationale comment, or drop
    it (the rationale belongs in-source; the planning artefact's location is
    not load-bearing).
  - User-facing docs: lift the relevant content into Crux/docs/ as a
    self-contained design note.
  - Bundled config-wizard profiles: rewrite as standalone, or scope to the
    workspace-cuecrux profile (which is allowlisted by name).

If a new file legitimately needs to mention the planning monorepo (e.g. an
audit report), add it to ALLOWLIST in this script with a one-line comment
explaining why.
MSG
  exit 1
fi

echo "OK — no private-path references found outside the allowlist."
