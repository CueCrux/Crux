#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# check-agent-docs.sh — keep the agent-facing docs (docs/agent/*) honest.
#
# Asserts that every symbol, test, crate directory, and fuzz target referenced by
# docs/agent/repo-manifest.yaml -> `ci_assertions` still exists in the tree. This converts
# the doc set from "hopefully current" to "provably current" — the same standard the
# product itself sells. A rename that orphans a doc reference fails the build here.
#
# Usage: bash scripts/check-agent-docs.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/docs/agent/repo-manifest.yaml"
fail=0

if [[ ! -f "$MANIFEST" ]]; then
  echo "FATAL: $MANIFEST not found" >&2
  exit 1
fi

# Extract a block-sequence list nested under `ci_assertions:` (one `- item` per line).
# $1 = the 2-space-indented key (e.g. "symbols").
yaml_list() {
  awk -v key="$1" '
    /^ci_assertions:/      { in_block=1; next }
    in_block && /^[^ ]/    { in_block=0 }            # left ci_assertions
    in_block && $0 ~ "^  "key":[[:space:]]*$" { grab=1; next }
    grab && /^  [a-z_]+:/  { grab=0 }                # next sibling key
    grab && /^    - /      { sub(/^    - /,""); gsub(/[[:space:]]/,""); print }
  ' "$MANIFEST"
}

# Grep the crate sources for an extended-regex pattern. Prefer ripgrep when present
# (fast, and available in dev shells); fall back to GNU grep so CI never depends on rg.
if command -v rg >/dev/null 2>&1; then
  code_has() { rg -qP "$1" "$ROOT/crates"; }
else
  code_has() { grep -rEq --include='*.rs' "$1" "$ROOT/crates"; }
fi

check() {  # $1 = label, $2 = token, $3 = pass/fail bool
  if [[ "$3" == "ok" ]]; then
    printf '  ok   %-12s %s\n' "$1" "$2"
  else
    printf '  MISS %-12s %s\n' "$1" "$2" >&2
    fail=1
  fi
}

echo "==> crate dirs"
while IFS= read -r c; do
  [[ -z "$c" ]] && continue
  [[ -d "$ROOT/crates/$c" ]] && check crate "$c" ok || check crate "$c" miss
done < <(yaml_list crate_dirs)

echo "==> symbols (pub fn/struct/enum/trait/type/const)"
while IFS= read -r s; do
  [[ -z "$s" ]] && continue
  # match a definition site, not merely a call site
  if code_has "(fn|struct|enum|trait|type|const|mod)[[:space:]]+${s}\b"; then
    check symbol "$s" ok
  else
    check symbol "$s" miss
  fi
done < <(yaml_list symbols)

echo "==> tests (#[test]/#[tokio::test] fns)"
while IFS= read -r t; do
  [[ -z "$t" ]] && continue
  code_has "fn[[:space:]]+${t}\b" && check test "$t" ok || check test "$t" miss
done < <(yaml_list tests)

echo "==> fuzz targets"
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  [[ -f "$ROOT/fuzz/fuzz_targets/$f.rs" ]] && check fuzz "$f" ok || check fuzz "$f" miss
done < <(yaml_list fuzz_targets)

echo "==> referenced docs exist"
for d in \
  AGENTS.md llms.txt \
  docs/agent/CODEMAP.md docs/agent/CLAIMS.md docs/agent/INVARIANTS.md \
  docs/agent/GLOSSARY.md docs/agent/repo-manifest.yaml \
  docs/THREAT_MODEL.md docs/spec/receipt-v1.md; do
  [[ -f "$ROOT/$d" ]] && check doc "$d" ok || check doc "$d" miss
done

echo
if [[ "$fail" -ne 0 ]]; then
  echo "FAIL: agent docs reference names that no longer exist in the tree." >&2
  echo "Fix the rename, or update docs/agent/repo-manifest.yaml (ci_assertions)." >&2
  exit 1
fi
echo "PASS: every agent-doc reference resolves in the tree."
