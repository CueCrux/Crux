#!/usr/bin/env bash
# provision-self-hosted-runner.sh — bootstrap a GitHub Actions self-hosted
# runner (the `[self-hosted, hel1]` labels) for protected Crux workflows.
#
# Run as root on the runner host. The service account remains unprivileged:
# this script removes the legacy sudoers grant and fails if any other
# non-interactive sudo policy still applies. See `docs/self-hosted-runner.md`.
#
# IMPORTANT: this is not an in-place compromise-remediation tool. Reimage any
# host that previously executed PR code with the legacy NOPASSWD grant before
# provisioning and registering a new protected listener.
#
# Symptoms this script prevents:
#   - `error: linker 'cc' not found` during `cargo build`
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
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: this script must run as root."
    echo "       run: sudo -E bash $0"
    exit 1
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

revoke_legacy_runner_sudo() {
  log "removing the legacy unrestricted sudo grant for $RUNNER_USER"
  if ! id "$RUNNER_USER" >/dev/null 2>&1; then
    warn "user $RUNNER_USER does not exist on this host; no grant to revoke"
    return 0
  fi
  local legacy_file="/etc/sudoers.d/${RUNNER_USER}-nopasswd"
  local disabled_file="${legacy_file}.disabled"
  if [[ -e "$legacy_file" ]]; then
    if [[ -e "$disabled_file" ]]; then
      echo "ERROR: cannot preserve $legacy_file: $disabled_file already exists"
      echo "       inspect both files, remove the active grant, then rerun"
      exit 1
    fi
    mv -- "$legacy_file" "$disabled_file"
    ok "disabled $legacy_file (recoverable at $disabled_file)"
  else
    ok "legacy sudoers grant is absent"
  fi
}

require_runner_user() {
  if ! id "$RUNNER_USER" >/dev/null 2>&1; then
    echo "ERROR: runner service account $RUNNER_USER does not exist"
    echo "       create the unprivileged account and install its trusted Rust toolchain"
    echo "       before running this provisioner"
    exit 1
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

verify_runner_toolchain() {
  local runner_home
  runner_home="$(getent passwd "$RUNNER_USER" | cut -d: -f6)"
  if [[ -z "$runner_home" || ! -d "$runner_home" ]]; then
    echo "ERROR: cannot resolve a real home for $RUNNER_USER"
    exit 1
  fi
  log "verifying trusted rustup/cargo bootstrap for $RUNNER_USER"
  if ! sudo -u "$RUNNER_USER" -H env \
    PATH="$runner_home/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    rustup --version >/dev/null 2>&1; then
    echo "ERROR: rustup is not installed for $RUNNER_USER"
    echo "       install a verified rustup-init build into the clean runner image"
    echo "       see $RUNBOOK_URL"
    exit 1
  fi
  if ! sudo -u "$RUNNER_USER" -H env \
    PATH="$runner_home/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    cargo --version >/dev/null 2>&1; then
    echo "ERROR: cargo is not installed for $RUNNER_USER"
    exit 1
  fi
  ok "$RUNNER_USER rustup/cargo bootstrap is available"
}

verify_runner_unprivileged() {
  log "verifying $RUNNER_USER has no non-interactive sudo policy"
  if sudo -u "$RUNNER_USER" -H sudo -n -l >/dev/null 2>&1; then
    echo "ERROR: $RUNNER_USER still has a non-interactive sudo policy"
    echo "       remove every NOPASSWD grant before starting the runner"
    echo "       see $RUNBOOK_URL"
    exit 1
  fi
  ok "$RUNNER_USER cannot use non-interactive sudo"
}

main() {
  ensure_root "$@"
  require_runner_user
  install_build_toolchain
  revoke_legacy_runner_sudo
  verify_cc
  verify_runner_toolchain
  verify_runner_unprivileged
  echo
  ok "self-hosted runner provisioned. Restart the actions-runner service if it's running."
  echo "    runbook: $RUNBOOK_URL"
}

main "$@"
