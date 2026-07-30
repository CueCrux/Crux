#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# execplan-drift-boot.sh — SessionStart wrapper. Prints an ExecPlan board-drift
# summary IF the reconcile script exists, else exits 0 silently. Fail-open:
# never blocks a session boot, whatever goes wrong.
#
# Every path and address is overridable, because the previous live copy of this
# hook hardcoded one workstation's layout (`/home/myles/CueCrux/...`) and one
# tailnet IP. That copy also never existed in the repository, so nothing made
# the hardcoding visible.
#
#   CRUX_HOOKS_RECONCILE  path to reconcile-execplan-status.sh
#                         (default: sibling of this script's parent)
#   CRUX_HTTP_URL         daemon base URL. NOTE: on a host whose daemon binds a
#                         tailnet address, loopback is wrong and the sweep
#                         silently no-ops — set this explicitly there.
#   CRUX_EXECPLANS_ROOT   plan directory the sweep compares against.
set -uo pipefail

# Machine-local overrides live OUTSIDE the repository, so the script stays
# portable and the box-specific bits stay on the box. This is the seam that was
# missing: the previous copy solved the same problem by hardcoding one
# workstation's paths into the only existing copy of the file.
[ -f "${CRUX_HOOKS_ENV:-$HOME/.config/crux/hooks.env}" ] &&
  . "${CRUX_HOOKS_ENV:-$HOME/.config/crux/hooks.env}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
s="${CRUX_HOOKS_RECONCILE:-${here}/../reconcile-execplan-status.sh}"
[ -x "$s" ] || exit 0

# No default for the plan root: it lives in a private planning repo whose name
# must not appear in this repository (CI gate: "No private-monorepo refs"). The
# sweep already handles an unset root by reporting it could not verify the board,
# which is the honest outcome — a wrong guess would report a false clean. Set
# CRUX_EXECPLANS_ROOT in $HOME/.config/crux/hooks.env.
CRUX_HTTP_URL="${CRUX_HTTP_URL:-http://127.0.0.1:14800}" "$s" --quiet 2>/dev/null || true
exit 0
