#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
# See LICENCE.md in the repository root.
#
# runner-hel1-per-runner-home.sh — durable fix for runner-hel1 gotcha #6
# (and #5): give each numbered GitHub Actions runner service a PRIVATE $HOME so
# that ~/.install-action/tmp, ~/.cargo and ~/.rustup are no longer shared across
# parallel jobs (the shared-cache SHA-mismatch / toolchain-rewrite races).
#
# RUN THIS ON THE RUNNER HOST (runner-hel1, tailnet 100.118.26.100) AS ROOT.
# It is NOT run by CI and touches no Crux daemon code.
#
# SAFETY:
#   * Default mode is --check: it only REPORTS current state and mutates nothing.
#   * --apply makes changes, but is fully idempotent (re-running is a no-op) and
#     STAGED: it configures + restarts ONE runner first, verifies HOME landed in
#     the live process, and only then proceeds to the rest. It refuses to restart
#     a runner that is mid-job (Listener busy) unless --force is given.
#   * --revert removes the drop-ins and restarts, restoring the shared HOME.
#
# Per the gotchas memo (runner-hel1-followup-gotchas-2026-05-20, updated
# 2026-06-05) this fix may ALREADY be applied in prod. --check will say so; if
# it is, --apply is a clean no-op. This script exists so the fix is auditable and
# reproducible on the NEXT bare-metal runner, not a one-shot `rm` band-aid.
#
#   Drop-in written: /etc/systemd/system/<svc>.service.d/10-home.conf
#                    Environment=HOME=${HOMES_ROOT}/runner-N
#   Service N -> install dir runner-N (runner-hel1-N -> runner-N).
#   caddy-hooks (runner-6) is DELIBERATELY excluded (single non-CI runner).
#   SCCACHE_DIR stays a shared path (intended) — this script never touches it.

set -euo pipefail

HOMES_ROOT="${CRUX_RUNNER_HOMES_ROOT:-/srv/data/gha-runner-homes}"
SHARED_HOME="${CRUX_RUNNER_SHARED_HOME:-/home/gha-runner}"
RUNNER_USER="${CRUX_RUNNER_USER:-gha-runner}"
SERVICE_GLOB='actions.runner.CueCrux.runner-hel1-*.service'
DROPIN_NAME='10-home.conf'

MODE="check"
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --check)  MODE="check" ;;
    --apply)  MODE="apply" ;;
    --revert) MODE="revert" ;;
    --force)  FORCE=1 ;;
    -h|--help)
      sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg (use --check|--apply|--revert [--force])" >&2; exit 2 ;;
  esac
done

log() { printf '[runner-home] %s\n' "$*"; }
err() { printf '[runner-home] ERROR: %s\n' "$*" >&2; }

[ "$(id -u)" -eq 0 ] || { err "must run as root"; exit 1; }

# Probe LIVE services — never assume the count (memo gotcha #4: was 4, now 5).
mapfile -t SERVICES < <(systemctl list-units --type=service --all --no-legend "$SERVICE_GLOB" \
  | awk '{print $1}' | sort -V)
if [ "${#SERVICES[@]}" -eq 0 ]; then
  err "no services match $SERVICE_GLOB — wrong host? (expected runner-hel1)"; exit 1
fi
log "found ${#SERVICES[@]} numbered runner services: ${SERVICES[*]}"

# Map a service unit to its runner index N (runner-hel1-N -> N).
index_of() { sed -E 's/.*runner-hel1-([0-9]+)\.service/\1/' <<<"$1"; }

dropin_dir()  { echo "/etc/systemd/system/$1.d"; }
dropin_path() { echo "$(dropin_dir "$1")/$DROPIN_NAME"; }
home_for()    { echo "${HOMES_ROOT}/runner-$1"; }

# Is the runner's Listener currently executing a job? Best-effort: a Worker
# process under the listener pid means busy. Absence => idle.
runner_busy() {
  local svc="$1" pid
  pid="$(systemctl show -p MainPID --value "$svc" 2>/dev/null || echo 0)"
  [ "${pid:-0}" -gt 0 ] || return 1
  pgrep -P "$pid" -f 'Runner.Worker' >/dev/null 2>&1
}

# Read HOME out of the live listener process environment.
live_home() {
  local svc="$1" pid
  pid="$(systemctl show -p MainPID --value "$svc" 2>/dev/null || echo 0)"
  [ "${pid:-0}" -gt 0 ] || { echo "(no pid)"; return; }
  tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | sed -n 's/^HOME=//p' | head -n1
}

print_state() {
  local svc n want have dropin
  for svc in "${SERVICES[@]}"; do
    n="$(index_of "$svc")"; want="$(home_for "$n")"; dropin="$(dropin_path "$svc")"
    have="$(live_home "$svc")"
    printf '  %-46s idx=%-2s dropin=%-7s liveHOME=%s want=%s%s\n' \
      "$svc" "$n" \
      "$([ -f "$dropin" ] && echo yes || echo NO)" \
      "${have:-?}" "$want" \
      "$(runner_busy "$svc" && echo '  [BUSY]' || true)"
  done
}

# Ensure the per-runner home exists, seeded from the shared home's warm caches
# (.cargo ~1.2G, .rustup ~1.6G) so toolchains/sccache stay warm. Idempotent.
seed_home() {
  local home="$1"
  if [ -d "$home" ]; then return 0; fi
  log "creating $home (seeding .cargo/.rustup from $SHARED_HOME)"
  install -d -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0755 "$home"
  local sub
  for sub in .cargo .rustup; do
    if [ -d "$SHARED_HOME/$sub" ] && [ ! -e "$home/$sub" ]; then
      cp -a "$SHARED_HOME/$sub" "$home/$sub"
    fi
  done
  chown -R "$RUNNER_USER:$RUNNER_USER" "$home"
}

write_dropin() {
  local svc="$1" n want dir path
  n="$(index_of "$svc")"; want="$(home_for "$n")"
  dir="$(dropin_dir "$svc")"; path="$(dropin_path "$svc")"
  local desired="[Service]
Environment=HOME=${want}
"
  if [ -f "$path" ] && [ "$(cat "$path")" = "$desired" ]; then
    return 1   # already correct -> signal "no change"
  fi
  install -d -m 0755 "$dir"
  printf '%s' "$desired" > "$path"
  return 0       # changed
}

apply_one() {
  local svc="$1" n want changed=0
  n="$(index_of "$svc")"; want="$(home_for "$n")"
  seed_home "$want"
  if write_dropin "$svc"; then changed=1; log "wrote drop-in for $svc -> HOME=$want"; else log "$svc drop-in already correct"; fi
  if [ "$changed" -eq 1 ]; then
    if runner_busy "$svc" && [ "$FORCE" -ne 1 ]; then
      err "$svc is BUSY — skipping restart (re-run with --force or wait for idle). Drop-in is staged; takes effect on next restart."
      return 0
    fi
    systemctl daemon-reload
    systemctl restart "$svc"
    sleep 2
  fi
  local got; got="$(live_home "$svc")"
  if [ "$got" = "$want" ]; then
    log "VERIFIED $svc live HOME=$got"
  else
    err "$svc live HOME=$got != $want — investigate before continuing"
    return 1
  fi
}

case "$MODE" in
  check)
    log "current state (read-only):"; print_state
    log "run with --apply to converge (idempotent, staged), --revert to undo."
    ;;
  apply)
    log "STAGED apply: first runner, verify, then the rest."
    # Stage 1: the first service only.
    apply_one "${SERVICES[0]}"
    log "first runner converged + verified; proceeding with the remainder."
    for svc in "${SERVICES[@]:1}"; do apply_one "$svc"; done
    log "done. final state:"; print_state
    ;;
  revert)
    log "removing drop-ins and restoring shared HOME ($SHARED_HOME)."
    for svc in "${SERVICES[@]}"; do
      path="$(dropin_path "$svc")"
      if [ -f "$path" ]; then rm -f "$path"; log "removed $path"; fi
    done
    systemctl daemon-reload
    for svc in "${SERVICES[@]}"; do
      if runner_busy "$svc" && [ "$FORCE" -ne 1 ]; then err "$svc BUSY — skip restart"; continue; fi
      systemctl restart "$svc"
    done
    log "reverted. (Per-runner home dirs under $HOMES_ROOT are left in place; rm manually if desired.)"
    print_state
    ;;
esac
