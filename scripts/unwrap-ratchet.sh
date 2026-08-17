#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
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

  # tests.rs is test-only but gated from its parent mod (out-of-file #[path]
  # decl), so it carries no in-file #[cfg(test)] for the scan to key on.
  # mutants_tests_*.rs are the same case: one per-source-file mutation-killing
  # module, each declared `#[cfg(test)] mod ...` from its crate root, so the
  # gate is out-of-file and invisible to this scan. Excluded by name rather than
  # absorbed into the baselines — inflating a baseline to cover test expects
  # would permanently license that many new PRODUCTION unwrap sites.
  # metrics.rs is the allowlisted Prometheus register!() surface (docs/unwrap-triage.md).
  # All are excluded by name so the count reflects production code only.
  find "$crate_dir" -type f -name '*.rs' ! -path '*/tests/*' \
    ! -name 'tests.rs' ! -name 'metrics.rs' ! -name 'mutants_tests_*.rs' \
    -exec awk '
      # Track brace depth so an inline #[cfg(test)] exempts only its own item,
      # not the rest of the file. Counting happens on the line-entry state so a
      # single-line test module does not leak its own body into the count.
      FNR == 1 { intest=0; depth=0; testdepth=-1 }
      { was = intest }
      /#\[cfg\(test\)\]/ && !intest { intest=1; testdepth=depth; was=1 }
      !was && $0 !~ /^[ \t]*\/\// && ($0 ~ /\.unwrap\(\)/ || $0 ~ /\.expect\(/) { count++ }
      {
        l = $0; opens = gsub(/\{/, "", l)
        l = $0; closes = gsub(/\}/, "", l)
        depth += opens - closes
        if (intest && (opens || closes) && depth <= testdepth) intest=0
      }
      END { print count+0 }
    ' {} + \
    | awk '{ total += $1 } END { print total+0 }'
}

# Regression fixture for the mid-file #[cfg(test)] blind spot: before the
# brace-depth fix, a #[cfg(test)] anywhere in a file exempted every line after
# it, so production code below a test module was silently outside the gate.
if [[ "${1:-}" == "--self-test" ]]; then
  fixture_dir="$(mktemp -d)"
  trap 'rm -rf "$fixture_dir"' EXIT
  cat > "$fixture_dir/fixture.rs" <<'FIXTURE'
fn prod_before() { let a = x.unwrap(); }
#[cfg(test)]
mod tests {
    #[test]
    fn t() { let b = y.unwrap(); let c = z.expect("no"); }
}
fn prod_after() { let d = w.unwrap(); }
mod inner {
    #[cfg(test)]
    mod nested { fn t2() { let e = q.unwrap(); } }
    fn prod_nested() { let f = r.expect("yes"); }
    // a full-line comment mentioning .unwrap() is not a site
}
FIXTURE
  got="$(count_sites "$fixture_dir")"
  if [[ "$got" != "3" ]]; then
    echo "unwrap ratchet SELF-TEST FAILED: expected 3 production sites, got $got" >&2
    exit 1
  fi
  echo "unwrap ratchet self-test OK: mid-file #[cfg(test)] does not exempt following code"
  exit 0
fi

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
