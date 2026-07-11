#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# Fail when a crate adds non-test unwrap()/expect() lines above its recorded
# baseline. The awk scan intentionally matches scripts/unwrap-baseline.txt.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
baseline_file="$root/scripts/unwrap-baseline.txt"

if [[ ! -f "$baseline_file" ]]; then
  echo "unwrap ratchet baseline is missing: $baseline_file" >&2
  exit 1
fi

declare -A baseline_counts=()
while read -r crate baseline _; do
  if [[ -z "${crate:-}" || "$crate" == \#* ]]; then
    continue
  fi
  if [[ ! "${baseline:-}" =~ ^[0-9]+$ ]]; then
    echo "invalid unwrap ratchet baseline for $crate: ${baseline:-<missing>}" >&2
    exit 1
  fi
  baseline_counts["$crate"]="$baseline"
done < "$baseline_file"

count_sites() {
  local crate_dir="$1"

  find "$crate_dir" -type f -name '*.rs' ! -path '*/tests/*' \
    -exec awk '
      FNR == 1 { intest=0 }
      /#\[cfg\(test\)\]/ { intest=1 }
      !intest && (/\.unwrap\(\)/ || /\.expect\(/) { count++ }
      END { print count+0 }
    ' {} + \
    | awk '{ total += $1 } END { print total+0 }'
}

checked=0
failures=0
reductions=0
baseline_total=0
current_total=0

for crate_dir in "$root"/crates/*; do
  if [[ ! -d "$crate_dir" || ! -f "$crate_dir/Cargo.toml" ]]; then
    continue
  fi

  crate="$(basename "$crate_dir")"
  baseline="${baseline_counts[$crate]:-0}"
  current="$(count_sites "$crate_dir")"

  checked=$((checked + 1))
  baseline_total=$((baseline_total + baseline))
  current_total=$((current_total + current))

  if ((current > baseline)); then
    echo "ERROR: $crate unwrap/expect count exceeds baseline: baseline=$baseline current=$current; either remove the new unwrap/expect or (if deliberate) add a justified #[allow] and update the baseline in this same PR" >&2
    failures=$((failures + 1))
  elif ((current < baseline)); then
    echo "INFO: $crate unwrap/expect count is below baseline: baseline=$baseline current=$current; can be ratcheted down"
    reductions=$((reductions + 1))
  fi
done

if ((failures > 0)); then
  echo "unwrap ratchet FAILED: crates=$checked baseline_total=$baseline_total current_total=$current_total failures=$failures reductions=$reductions" >&2
  exit 1
fi

echo "unwrap ratchet OK: crates=$checked baseline_total=$baseline_total current_total=$current_total failures=0 reductions=$reductions"
