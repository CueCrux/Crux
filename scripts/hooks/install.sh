#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# install.sh — link this directory's hooks into a Claude Code / Codex hooks dir.
#
# WHY SYMLINKS AND NOT COPIES
#
# These hooks previously lived ONLY at `<workspace>/.claude/hooks/`, which is not
# a git repository — the CueCrux workspace root is a container of ~40 independent
# repos, not a repo itself. Three of the four hooks existed nowhere in version
# control, and the fourth had drifted: the live copy had gained real fixes (extra
# terminal status tokens, a documented false-positive) that were never pushed
# back, while also acquiring a hardcoded `/home/myles/...` path that would break
# on any other machine.
#
# Copying would recreate exactly that: two copies, no arbiter, silent divergence.
# A symlink has one copy. Editing the live path edits the repo file, so the next
# `git status` shows it and review is unavoidable.
#
# Usage:
#   scripts/hooks/install.sh [target-hooks-dir]     # default: $HOME/CueCrux/.claude/hooks
#   scripts/hooks/install.sh --check [dir]          # verify links, mutate nothing
#
# --check exits non-zero if any hook is missing, is a real file rather than a
# link, or points somewhere other than this checkout. That is the state that lets
# drift back in, so it is worth failing on.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mode="install"
if [ "${1:-}" = "--check" ]; then
  mode="check"
  shift
fi
target="${1:-$HOME/CueCrux/.claude/hooks}"

hooks=()
for f in "$here"/*.sh; do
  base="$(basename "$f")"
  # install.sh is the installer, not a hook.
  [ "$base" = "install.sh" ] && continue
  hooks+=("$base")
done

if [ "${#hooks[@]}" -eq 0 ]; then
  echo "install.sh: no hooks found in $here" >&2
  exit 1
fi

rc=0

if [ "$mode" = "check" ]; then
  for h in "${hooks[@]}"; do
    link="$target/$h"
    want="$here/$h"
    if [ ! -e "$link" ]; then
      printf '  MISSING   %s\n' "$h"
      rc=1
    elif [ ! -L "$link" ]; then
      # A real file here is the pre-symlink failure mode: it can be edited
      # without git ever seeing it.
      printf '  UNLINKED  %s (real file — edits here are invisible to git)\n' "$h"
      rc=1
    elif [ "$(readlink -f "$link")" != "$(readlink -f "$want")" ]; then
      printf '  WRONG     %s -> %s\n' "$h" "$(readlink "$link")"
      rc=1
    else
      printf '  ok        %s\n' "$h"
    fi
  done
  [ "$rc" -eq 0 ] && echo "hooks: all ${#hooks[@]} linked to $here" || echo "hooks: drift detected — run scripts/hooks/install.sh" >&2
  exit "$rc"
fi

mkdir -p "$target" || { echo "install.sh: cannot create $target" >&2; exit 1; }

for h in "${hooks[@]}"; do
  link="$target/$h"
  # Preserve anything that is a real file — it may hold live fixes that were
  # never committed, which is precisely how this situation arose. Back it up and
  # say so rather than overwriting it.
  if [ -f "$link" ] && [ ! -L "$link" ]; then
    if ! diff -q "$link" "$here/$h" >/dev/null 2>&1; then
      cp "$link" "$link.pre-symlink.bak"
      printf '  BACKED UP %s -> %s.pre-symlink.bak (differed from the repo copy — diff it before deleting)\n' "$h" "$h"
    fi
    rm -f "$link"
  fi
  ln -sfn "$here/$h" "$link"
  chmod +x "$here/$h"
  printf '  linked    %s\n' "$h"
done

cat <<'WIRING'

Wire them in the workspace settings.json (see settings.reference.json here):

  PreToolUse   Edit|Write|NotebookEdit  -> punch-in-on-edit.sh
  PostToolUse  Bash                     -> punch-out-on-commit.sh
  PostToolUse  mcp__crux__store_fact    -> execplan-status-guard.sh
  SessionStart                          -> execplan-drift-boot.sh
WIRING
