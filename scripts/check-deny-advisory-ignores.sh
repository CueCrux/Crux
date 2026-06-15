#!/usr/bin/env bash
set -euo pipefail

deny_file="${1:-deny.toml}"

if [ ! -f "$deny_file" ]; then
  echo "missing cargo-deny config: $deny_file" >&2
  exit 1
fi

awk '
  /^\[advisories\]/ { in_advisories=1; in_ignore=0; next }
  /^\[/ && !/^\[advisories\]/ { in_advisories=0; in_ignore=0 }
  in_advisories && /^[[:space:]]*ignore[[:space:]]*=/ { in_ignore=1 }
  in_ignore && /^[[:space:]]*\]/ { in_ignore=0 }
  in_ignore && /"RUSTSEC-[0-9]+-[0-9]+"/ {
    advisory=$0
    gsub(/^[[:space:]]+|[[:space:],]+$/, "", advisory)
    if (prev2 !~ /owner:[[:space:]]*[^[:space:]]+/ || prev1 !~ /expires:[[:space:]]*[0-9]{4}-[0-9]{2}-[0-9]{2}/) {
      print "advisory ignore lacks owner/expires metadata before " advisory > "/dev/stderr"
      failed=1
    }
  }
  { prev2=prev1; prev1=$0 }
  END { exit failed ? 1 : 0 }
' "$deny_file"
