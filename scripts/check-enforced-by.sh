#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# check-enforced-by.sh — every `enforced-by:` pointer names a test that exists.
#
# WHY. On 2026-08-22 the device-grant module docs asserted that issued scopes
# were "a concrete subset of the authenticated approver's verified grants".
# Nothing enforced it, and scope matching is exact — `admin:write` does not
# imply `facts:write` — so an approver could mint authority it did not hold.
# The claim had been sitting in the docs, true-sounding and unenforced. The
# passport binding added days earlier turned it into a route to resolving work
# gates.
#
# A doc comment that asserts a security invariant is a promise. This makes the
# promise carry the name of the test that keeps it:
#
#     //! - **Tenant leakage (T.1):** issued scopes are a subset of the
#     //!   approver's verified grants.
#     //!   enforced-by: attack_device_approve_cannot_grant_scopes_the_approver_lacks
#
# HONEST LIMIT. This proves a test of that NAME exists — not that it tests the
# claim. That is the same bound as the repo's other citation lints
# (check-execplan-drift.sh for qc_ref/threat_ref, check-od-refs.mjs for OD ids),
# and it buys the same thing: drift stops being silent. Deleting or renaming the
# test now breaks the build instead of quietly unmaking the promise.
#
# Scope is deliberately narrow — the modules where a false claim is a
# vulnerability rather than a documentation bug. Widen it by adding paths here.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Files whose doc claims are load-bearing enough to require a pointer.
SCOPE=(
  "crates/corecruxd/src/auth.rs"
  "crates/corecruxd/src/http/auth_rails.rs"
  "crates/corecruxd/src/http/auth_device.rs"
  "crates/corecruxd/src/http/work.rs"
  "crates/corecruxd/src/http/approval_receipts.rs"
)

fail=0
found=0

for f in "${SCOPE[@]}"; do
  [ -f "$f" ] || { echo "check-enforced-by: MISSING scoped file $f" >&2; fail=1; continue; }
  # `enforced-by: <test_name>` — one pointer per line, in a comment.
  while IFS=: read -r lineno _; do
    [ -n "$lineno" ] || continue
    name="$(sed -n "${lineno}p" "$f" | sed -E 's/.*enforced-by:[[:space:]]*//; s/[[:space:]].*$//; s/[^A-Za-z0-9_].*$//')"
    found=$((found + 1))
    if [ -z "$name" ]; then
      echo "check-enforced-by: $f:$lineno — 'enforced-by:' with no test name" >&2
      fail=1
      continue
    fi
    # The named test must exist as a `fn <name>` somewhere in the crate tree.
    if ! grep -rqE "fn[[:space:]]+${name}[[:space:]]*\(" crates/ 2>/dev/null; then
      echo "check-enforced-by: $f:$lineno — names test '${name}', which does not exist" >&2
      echo "    the claim above it is now unenforced; restore the test or drop the claim" >&2
      fail=1
    fi
  done < <(grep -n "enforced-by:" "$f" || true)
done

if [ "$fail" -ne 0 ]; then
  echo "check-enforced-by: FAILED" >&2
  exit 1
fi
echo "check-enforced-by OK: ${found} claim(s) across ${#SCOPE[@]} scoped files, every pointer resolves"
