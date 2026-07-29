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
# v2 additionally asserts:
#   - every local link in llms.txt resolves (link parity),
#   - every cargo crate under crates/ ships a nested AGENTS.md, small enough to stay
#     under harness truncation limits (≤60 lines hard),
#   - llms-full.txt is fresh (regenerate-and-diff via scripts/build-llms-full.sh --check).
#
# Usage: bash scripts/check-agent-docs.sh [--exec]
#   --exec  additionally EXECUTE the cheap documented commands (cargo fmt --check).
#           Heavyweight commands (build/test/clippy) stay in ci.yml where they already run.
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

echo "==> workspace version parity"
# The reference checks below only prove a name still resolves; they cannot see a
# version that has gone stale. AGENTS.md and repo-manifest.yaml both restate the
# workspace version, and both sat at 0.5.37 through sixteen releases because
# nothing compared them to Cargo.toml.
ws_version="$(awk -F'"' '/^version = "/ { print $2; exit }' "$ROOT/Cargo.toml")"
if [[ -z "$ws_version" ]]; then
  check version "could not read [workspace.package] version from Cargo.toml" miss
else
  if grep -q "workspace_version: \"$ws_version\"" "$ROOT/docs/agent/repo-manifest.yaml"; then
    check version "repo-manifest.yaml workspace_version=$ws_version" ok
  else
    check version "repo-manifest.yaml workspace_version != $ws_version (Cargo.toml)" miss
  fi
  if grep -q "workspace version \*\*$ws_version\*\*\|workspace version $ws_version" "$ROOT/AGENTS.md"; then
    check version "AGENTS.md workspace version=$ws_version" ok
  else
    check version "AGENTS.md workspace version != $ws_version (Cargo.toml)" miss
  fi
fi

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
  AGENTS.md llms.txt llms-full.txt \
  docs/agent/CODEMAP.md docs/agent/CLAIMS.md docs/agent/INVARIANTS.md \
  docs/agent/GLOSSARY.md docs/agent/repo-manifest.yaml \
  docs/THREAT_MODEL.md docs/spec/receipt-v1.md; do
  [[ -f "$ROOT/$d" ]] && check doc "$d" ok || check doc "$d" miss
done

echo "==> llms.txt link parity (every local link resolves)"
while IFS= read -r target; do
  [[ -z "$target" ]] && continue
  case "$target" in
    http://*|https://*|mailto:*) continue ;;
  esac
  if [[ -f "$ROOT/$target" || -d "$ROOT/${target%/}" ]]; then
    check link "$target" ok
  else
    check link "$target" miss
  fi
done < <(grep -oE '\]\([^)]+\)' "$ROOT/llms.txt" | sed 's/^](\(.*\))$/\1/')

echo "==> nested per-crate AGENTS.md (present, ≤60 lines)"
for crate_dir in "$ROOT"/crates/*/; do
  name="$(basename "$crate_dir")"
  agents="$crate_dir/AGENTS.md"
  if [[ ! -f "$agents" ]]; then
    check agents.md "crates/$name" miss
    continue
  fi
  lines=$(wc -l < "$agents")
  if (( lines > 60 )); then
    check agents.md "crates/$name (${lines} lines > 60)" miss
  else
    check agents.md "crates/$name" ok
  fi
done

echo "==> llms-full.txt freshness"
if bash "$ROOT/scripts/build-llms-full.sh" --check >/dev/null 2>&1; then
  check freshness llms-full.txt ok
else
  check freshness "llms-full.txt (stale — run scripts/build-llms-full.sh)" miss
fi

if [[ "${1:-}" == "--exec" ]]; then
  echo "==> exec: cheap documented commands"
  if (cd "$ROOT" && cargo fmt --check >/dev/null 2>&1); then
    check exec "cargo fmt --check" ok
  else
    check exec "cargo fmt --check" miss
  fi
fi

echo
if [[ "$fail" -ne 0 ]]; then
  echo "FAIL: agent docs reference names that no longer exist in the tree." >&2
  echo "Fix the rename, or update docs/agent/repo-manifest.yaml (ci_assertions)." >&2
  exit 1
fi
echo "PASS: every agent-doc reference resolves in the tree."
