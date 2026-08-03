#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Push the local ExecPlan directory to a daemon's projection replica.
#
# WHY THIS EXISTS
#
# `/v1/work` is a read-time projection: the daemon walks its own replica of
# `*.md` on every request and re-derives state. Nothing is pushed to it by the
# agent that edits a plan. So the replica has to be got there somehow, and on a
# deployment without git backing the only mechanism is this copy.
#
# That copy was tribal knowledge and manual, and it drifted: on 2026-08-02 the
# replica on host `crux` was four days stale and missing nine plans, including a
# completed one — so the board had never shown it. Eighteen hours later ten more
# files had changed. A step that must run daily and lives only in someone's head
# is a step that silently stops running.
#
# THIS IS THE INTERIM MECHANISM, NOT THE INTENDED ONE.
#
# The daemon supports git backing, which makes the replica self-updating and
# makes `POST /v1/execplans/refresh` work instead of returning 409:
#
#   CRUX_EXECPLANS_GIT_REMOTE        clone URL
#   CRUX_EXECPLANS_GIT_BRANCH        defaults to `main`
#   CRUX_EXECPLANS_GIT_INTERVAL_SECS background pull cadence (0/unset = on demand)
#   CRUX_EXECPLANS_GIT_CHECKOUT      where the clone lives. THE CHECKOUT IS THE
#                                    REPOSITORY; the projection root is normally
#                                    `<checkout>/.agent/execplans`. Getting this
#                                    wrong is silent — git clones happily into
#                                    the wrong place and the board stays empty.
#
# Configuring it against a PRIVATE plans repo needs a credential the daemon host
# does not currently have. As of 2026-08-03 host `crux` has no deploy key, no
# credential helper, and no `ssh` binary inside the container — so an SSH deploy
# key needs an image change, and HTTPS needs a token that only a human can mint.
# Until one of those is decided, this script is the mechanism. See
# docs/execplan-drift-guard.md → "Keeping the daemon's replica current".
#
# Usage:
#   scripts/sync-execplans-replica.sh [--dry-run]
#
#   EXECPLANS_SRC   local plans dir   (default: ../PlanCrux/.agent/execplans)
#   EXECPLANS_DEST  rsync destination (default: root@crux:/srv/plancrux-execplans/)
#
# Additive by design: no `--delete`. A plan removed upstream lingers in the
# replica rather than vanishing from the board mid-session; prune deliberately.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="${EXECPLANS_SRC:-$root/../PlanCrux/.agent/execplans}"
dest="${EXECPLANS_DEST:-root@crux:/srv/plancrux-execplans/}"
dry=""
[ "${1:-}" = "--dry-run" ] && dry="--dry-run"

if [ ! -d "$src" ]; then
  echo "error: plans dir not found: $src" >&2
  echo "  set EXECPLANS_SRC to your PlanCrux .agent/execplans directory" >&2
  exit 1
fi

count="$(find "$src" -maxdepth 1 -name '*.md' | wc -l | tr -d ' ')"
if [ "$count" = "0" ]; then
  # Refuse to "sync" an empty directory: with no --delete it is a harmless no-op,
  # but it is also the signature of a wrong EXECPLANS_SRC, and reporting success
  # for that is how a stale replica goes unnoticed for another four days.
  echo "error: no *.md under $src — refusing to sync (wrong EXECPLANS_SRC?)" >&2
  exit 1
fi

# A non-empty check is NOT enough on its own: this pushes to a production
# projection root, and any directory containing stray *.md — `/tmp` does —
# would sail past it and publish junk onto the board. Require the directory to
# actually be an execplans dir. Override deliberately, never by accident.
if [ "$(basename "$src")" != "execplans" ] && [ "${EXECPLANS_ALLOW_ANY_DIR:-0}" != "1" ]; then
  echo "error: $src is not an 'execplans' directory — refusing to publish it" >&2
  echo "  this pushes to a live board; set EXECPLANS_ALLOW_ANY_DIR=1 if you mean it" >&2
  exit 1
fi

echo "syncing $count plan(s)"
echo "  from: $src"
echo "  to:   $dest"
# shellcheck disable=SC2086
rsync -a $dry --info=stats2 "$src"/*.md "$dest"

if [ -n "$dry" ]; then
  echo "(dry run — nothing copied)"
else
  echo "done. The board re-projects on the next /v1/work read; no restart needed."
fi
