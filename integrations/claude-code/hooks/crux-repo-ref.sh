#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# crux-repo-ref.sh — SessionStart. Name every workspace repo whose checkout is
# NOT on main, because a shared checkout answers existence questions about
# whatever branch another session left it on.
#
# WHY. Over one ExecPlan, four claims read from the shared Crux checkout did not
# hold on origin/main: a helper function, a scope-attenuation guard, a test file,
# and a module contract. Two would have shipped a fix built on a helper that did
# not exist. One was the reverse — the guard the docs promised was missing on
# main, a live privilege escalation that surfaced only because the claim happened
# to get checked. `grep`, `ls` and `Read` all answered confidently and none of
# them said which ref they were answering about.
#
# This does not block anything and cannot be relied on to catch every case. It
# makes the trap visible at the moment it starts mattering. The actual fix is to
# branch a worktree off origin/main BEFORE research, not before writing.
#
#   CRUX_REPO_REF_ROOT   workspace root to scan (default: this script's ../..)
#   CRUX_REPO_REF_SKIP   space-separated repo dir names to ignore
#
# Fail-open: any error exits 0 silently. A boot hook must never cost a session.
#
# CANONICAL SOURCE. This file is the version-controlled copy; install it to the
# workspace's `.claude/hooks/` and wire it as a SessionStart hook. The
# workspace root is not itself a repository, so a hook that lives only there has
# no reviewable history — the failure the sibling `execplan-drift-boot.sh`
# header records, where the only copy of a hook hardcoded one workstation's
# paths and nothing made that visible. Edit here, then reinstall.
set -uo pipefail

root="${CRUX_REPO_REF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)}"
[ -n "$root" ] && [ -d "$root" ] || exit 0
skip=" ${CRUX_REPO_REF_SKIP:-} "

tmp="$(mktemp 2>/dev/null)" || exit 0
trap 'rm -f "$tmp"' EXIT

for dir in "$root"/*/; do
    name="$(basename "$dir")"
    case "$skip" in *" $name "*) continue ;; esac
    # Worktrees are intentionally off-main; only flag primary checkouts.
    [ -d "$dir/.git" ] || continue

    head="$(git -C "$dir" symbolic-ref --quiet --short HEAD 2>/dev/null)" || continue
    [ -n "$head" ] || continue

    # Which branch is this repo's trunk? Skip when it cannot be resolved —
    # guessing "main" turned a master-trunk repo into a standing false positive.
    trunk="$(git -C "$dir" symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null)"
    trunk="${trunk#origin/}"
    # origin/HEAD is often unset on a clone, so fall back by probing rather than
    # assuming "main" — assuming it made a master-trunk repo a false positive,
    # and skipping outright hid the worst-drifted repo in the workspace.
    if [ -z "$trunk" ]; then
        for cand in main master trunk; do
            if git -C "$dir" rev-parse --verify --quiet "refs/remotes/origin/$cand" >/dev/null 2>&1; then
                trunk="$cand"; break
            fi
        done
    fi
    [ -n "$trunk" ] || continue
    git -C "$dir" rev-parse --verify --quiet "refs/remotes/origin/$trunk" >/dev/null 2>&1 || continue
    [ "$head" = "$trunk" ] && continue

    # Divergence, not branch name, is what makes a tree misleading: a branch
    # level with trunk reads the same as trunk. Report only real drift.
    counts="$(git -C "$dir" rev-list --left-right --count "origin/$trunk...HEAD" 2>/dev/null)" || continue
    behind="$(printf '%s' "$counts" | awk '{print $1}')"
    ahead="$(printf '%s' "$counts" | awk '{print $2}')"
    [ "${behind:-0}" -eq 0 ] && [ "${ahead:-0}" -eq 0 ] && continue

    printf '%06d\t  · %s on %s (%s behind, %s ahead of origin/%s)\n' \
        "$behind" "$name" "$head" "$behind" "$ahead" "$trunk"
done > "$tmp"

[ -s "$tmp" ] || exit 0

total="$(wc -l < "$tmp" | tr -d " ")"
# Worst drift first — a checkout hundreds of commits behind is far likelier to
# answer an existence question wrongly than one that is a few behind.
body="$(sort -rn "$tmp" | head -6 | cut -f2-)"

printf '⚠ %s checkout(s) NOT on trunk — `grep`/`ls`/`Read` there answer about that branch, not trunk:\n%s\n' "$total" "$body"
[ "$total" -gt 6 ] && printf '  · … and %s more\n' "$((total - 6))"
printf 'Before asking "does X exist?": `git show origin/<trunk>:<path>`, or branch a worktree\n'
printf 'off origin/<trunk> first, so the tree you read is one you chose.\n'
exit 0
