#!/usr/bin/env bash
# Cut a Crux release with the crate version locked to the tag.
#
# Usage: scripts/cut-release.sh <X.Y.Z>        (no leading 'v')
#
# Bumps [workspace.package].version, refreshes Cargo.lock (so the Dockerfile's
# `cargo build --locked` stays valid), commits "chore(release): vX.Y.Z", and
# creates the annotated v* tag. It does NOT push — review, then push the printed
# commands. The Version-sync CI gate (.github/workflows/version-sync.yml) fails
# the tag build if the crate version ever drifts from the tag, so this script is
# the supported way to keep /v1/version, MCP initialize, and the agent card in
# sync with releases.
set -euo pipefail

ver="${1:-}"
if [ -z "$ver" ]; then
  echo "usage: scripts/cut-release.sh <X.Y.Z>" >&2
  exit 64
fi
ver="${ver#v}"
if ! [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: '$ver' is not a X.Y.Z version" >&2
  exit 64
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [ -n "$(git status --porcelain)" ]; then
  echo "error: working tree is dirty — commit or stash first" >&2
  # Name what is dirty. This guard used to fail with the bare message above
  # while the only offender was an untracked directory (a local `git worktree`
  # under .worktrees/, now gitignored), which is a slow thing to work out.
  git status --porcelain >&2
  exit 1
fi
if git rev-parse "v$ver" >/dev/null 2>&1; then
  echo "error: tag v$ver already exists" >&2
  exit 1
fi

# Bump the version only within the [workspace.package] section.
sed -i -E '/^\[workspace\.package\]/,/^\[/ s/^version = "[^"]+"/version = "'"$ver"'"/' Cargo.toml

# Refresh Cargo.lock for the workspace members (no external dep churn).
cargo update --workspace >/dev/null

# The agent-doc surface carries the workspace version too, and the required
# `Verify agent-doc references resolve` check asserts parity across all three
# (scripts/check-agent-docs.sh, "workspace version parity"). Bumping only
# Cargo.toml therefore produced a release PR that FAILED CI — the script and the
# gate disagreed about what cutting a release means. Keep them in lock-step here.
sed -i -E 's/^workspace_version: "[^"]+"/workspace_version: "'"$ver"'"/' docs/agent/repo-manifest.yaml
sed -i -E 's/(edition 2021; workspace version )[0-9]+\.[0-9]+\.[0-9]+/\1'"$ver"'/' AGENTS.md

# llms-full.txt embeds AGENTS.md, the manifest and the CHANGELOG, and the same
# gate checks its freshness. Regenerate after the edits above, never before.
bash scripts/build-llms-full.sh >/dev/null

git add Cargo.toml Cargo.lock docs/agent/repo-manifest.yaml AGENTS.md llms-full.txt
git commit -m "chore(release): v$ver"
git tag -a "v$ver" -m "v$ver"

cat <<EOF

Cut v$ver — commit + annotated tag created locally (not pushed).

Bumped: Cargo.toml, Cargo.lock, docs/agent/repo-manifest.yaml, AGENTS.md, llms-full.txt

STILL YOURS TO DO: write the CHANGELOG entry. Per CHANGELOG.md's own cadence
note, "if you tag a release, you write its entry" — rename [Unreleased] to
[$ver] with today's date, open a fresh [Unreleased], and add the compare link.
This script deliberately does not guess at release notes.

Review the bump, then:
  git push origin HEAD
  git push origin v$ver
EOF
