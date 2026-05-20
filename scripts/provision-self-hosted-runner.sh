#!/usr/bin/env bash
# provision-self-hosted-runner.sh — bootstrap a GitHub Actions self-hosted
# runner (the `[self-hosted, ci]` label) for the Crux Daemon CI matrix.
#
# Run ONCE on the runner host as a user with sudo. Idempotent: re-running is
# safe and only patches what's missing. See `docs/self-hosted-runner.md` for
# the operator runbook.
#
# Symptoms this script prevents:
#   - `error: linker 'cc' not found` during `cargo build`
#   - `sudo: a password is required` during `taiki-e/install-action`
#   - `error: failed to run custom build command for proc-macro2` (missing
#     pkg-config / build-essential)
#
# Recorded as the operator side of fact `incident:2026-05-19,
# key=crux-ci-runner-broken`.

set -euo pipefail

RUNNER_USER="${RUNNER_USER:-gha-runner}"
RUNBOOK_URL="https://github.com/CueCrux/Crux/blob/main/docs/self-hosted-runner.md"

log() { printf '\033[1;36m[provision]\033[0m %s\n' "$*"; }
ok()  { printf '\033[1;32m[ ok ]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }

ensure_root() {
  if [[ "$(id -u)" -ne 0 ]] && ! sudo -n true 2>/dev/null; then
    echo "ERROR: this script needs root or passwordless sudo."
    echo "       run: sudo $0"
    exit 1
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    exec sudo -E "$0" "$@"
  fi
}

install_build_toolchain() {
  log "installing build toolchain (build-essential, pkg-config, libssl-dev, clang, lld, curl, jq, git)"
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential \
      pkg-config \
      libssl-dev \
      clang \
      lld \
      curl \
      jq \
      git \
      cmake \
      protobuf-compiler
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y gcc gcc-c++ make pkgconf-pkg-config openssl-devel clang lld curl jq git cmake protobuf-compiler
  else
    warn "no apt-get or dnf detected; install build toolchain manually"
    return 1
  fi
  ok "build toolchain installed"
}

ensure_runner_sudo() {
  log "ensuring $RUNNER_USER has passwordless sudo (for taiki-e/install-action)"
  if ! id "$RUNNER_USER" >/dev/null 2>&1; then
    warn "user $RUNNER_USER does not exist on this host; skipping sudoers"
    return 0
  fi
  local sudoers_file="/etc/sudoers.d/${RUNNER_USER}-nopasswd"
  if [[ ! -f "$sudoers_file" ]]; then
    echo "$RUNNER_USER ALL=(ALL) NOPASSWD:ALL" > "$sudoers_file"
    chmod 0440 "$sudoers_file"
    visudo -cf "$sudoers_file"
    ok "wrote $sudoers_file"
  else
    ok "$sudoers_file already present"
  fi
}

verify_cc() {
  log "verifying cc linker"
  if ! command -v cc >/dev/null 2>&1; then
    echo "ERROR: cc not on PATH after install; aborting"
    exit 1
  fi
  cc --version | head -1
  ok "cc OK"
}

verify_runner_sudo() {
  log "verifying $RUNNER_USER passwordless sudo"
  if ! id "$RUNNER_USER" >/dev/null 2>&1; then
    warn "no $RUNNER_USER user, skipping verify"
    return 0
  fi
  if sudo -u "$RUNNER_USER" sudo -n true 2>/dev/null; then
    ok "$RUNNER_USER passwordless sudo OK"
  else
    echo "ERROR: $RUNNER_USER cannot sudo without password"
    echo "       see $RUNBOOK_URL"
    exit 1
  fi
}

main() {
  ensure_root "$@"
  install_build_toolchain
  ensure_runner_sudo
  verify_cc
  verify_runner_sudo
  echo
  ok "self-hosted runner provisioned. Restart the actions-runner service if it's running."
  echo "    runbook: $RUNBOOK_URL"
}

main "$@"
