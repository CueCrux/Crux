#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Constraint C7 of ExecPlan `crux-companion-vocabulary-unification-2026-08-08`:
# the CE ports the READER half of every CoreCrux companion container and never
# the builder.
#
# Why this is a CI gate rather than a review convention. OD-4 ruled that the
# ported readers compile into the default, public, Apache-2.0 binary. That makes
# "reader-only" the *sole* remaining barrier between a CE operator and authoring
# their own companions — the moat is not the format's secrecy (the source ships
# either way), it is that artifacts only the platform can produce are the thing
# a reader is inert without. A `Ccx*Builder` added here, however innocently,
# removes that barrier for one lane and nothing else would notice.
#
# Two builders are legitimate and are allowlisted below:
#
#   CcxiBuilder  — `.ccxi` BM25 index. Always shipped in the CE; the daemon
#                  builds it at seal time from its own prose. BM25 is not the moat.
#   CcxeBuilder  — `.ccxe` dense vectors. The single deliberate C7 exception:
#                  the CE writes vectors it embedded itself, locally or through
#                  the metered delegate door.
#
# Adding a third entry is a commercial decision, not a refactor. If you are here
# because this gate failed, the fix is almost always to delete the builder, not
# to widen the list.
#
# Usage: scripts/assert-reader-only-companions.sh
# Exits 0 on pass, 1 when an unexpected builder is present.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

ALLOWED_RE='^(CcxiBuilder|CcxeBuilder)$'

# Every `Ccx<name>Builder` identifier appearing in Rust sources under crates/.
#
# Restricted to *.rs deliberately. The first version scanned everything and fired
# on this crate's own VENDORED_FROM.md, which names the excised builders in prose
# while explaining why they are excised — a gate that cannot survive being
# documented is a gate people delete. Markdown cannot construct a builder; only
# Rust can, so Rust is what needs policing. Note this does still catch a builder
# in a #[cfg(test)] module or a tests/ fixture, which is intended: a test helper
# is exactly the shape a builder would first reappear in.
mapfile -t found < <(
  grep -rhoE --include='*.rs' '\bCcx[A-Za-z0-9]*Builder\b' crates/ 2>/dev/null | sort -u
)

status=0
for name in "${found[@]:-}"; do
  [ -n "$name" ] || continue
  if [[ ! "$name" =~ $ALLOWED_RE ]]; then
    echo "::error::C7 violation: $name exists in the CE. Companion ports are reader-only." >&2
    grep -rnE "\b${name}\b" crates/ | head -20 >&2
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo "" >&2
  echo "Only CcxiBuilder and CcxeBuilder may exist in this repository." >&2
  echo "See scripts/assert-reader-only-companions.sh for why, and constraint C7 of" >&2
  echo "ExecPlan crux-companion-vocabulary-unification-2026-08-08." >&2
  exit 1
fi

# Positive control: a gate that matches nothing passes vacuously and would keep
# passing if the grep, the path, or the identifier convention ever changed.
if [ "${#found[@]}" -eq 0 ]; then
  echo "::error::found no Ccx*Builder at all — the scan is broken, not the tree." >&2
  exit 1
fi

echo "reader-only companion check: OK (${#found[@]} builder(s), all allowlisted: ${found[*]})"
