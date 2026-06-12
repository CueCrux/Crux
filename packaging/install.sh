#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# Crux daemon installer.
#
#   ┌─────────────────────────────────────────────────────────────────┐
#   │  Do NOT pipe this script into a shell.                          │
#   │                                                                 │
#   │  1. Download it:   curl -fsSLO https://github.com/CueCrux/Crux/ │
#   │                      releases/latest/download/install.sh        │
#   │  2. Read it:       less install.sh                              │
#   │  3. Run it:        bash install.sh                              │
#   │                                                                 │
#   │  The script itself is covered by the signed release manifest    │
#   │  (docs/verify-release.md §2), so you can verify it too.         │
#   └─────────────────────────────────────────────────────────────────┘
#
# What it does (and nothing else):
#   - downloads the crux + corecruxctl binaries for your platform from the
#     pinned GitHub Release,
#   - VERIFIES their cosign keyless signatures before installing (hard
#     requirement — there is no skip flag),
#   - installs them into PREFIX/bin (default: ~/.local),
#   - creates a private data directory (default: ~/.local/share/crux, 0700),
#   - optionally installs a systemd user unit / launchd agent (opt-in flag;
#     never auto-starts anything without you running the printed command).
#
# It does NOT: phone home, collect telemetry, require an account, touch your
# shell rc files, or start services unasked.
#
# Usage:
#   bash install.sh [--version vX.Y.Z] [--prefix DIR] [--with-service]
#   bash install.sh --uninstall [--prefix DIR]
#
# Options:
#   --version vX.Y.Z   Install a specific release (default: latest).
#                      Re-running with a newer version is the upgrade path.
#   --prefix DIR       Install prefix (default: ~/.local → binaries in
#                      ~/.local/bin). Use /usr/local for system-wide (sudo).
#   --with-service     Also install a systemd user unit (Linux) or launchd
#                      agent (macOS). Prints — but does not run — the
#                      enable/start command.
#   --uninstall        Remove installed binaries + service unit. Data is
#                      NEVER deleted; the data dir path is printed instead.
set -euo pipefail

REPO="CueCrux/Crux"
VERSION="latest"
PREFIX="${HOME}/.local"
WITH_SERVICE=0
UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --with-service) WITH_SERVICE=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 64 ;;
  esac
done

BIN_DIR="${PREFIX}/bin"
if [ "$PREFIX" = "/usr/local" ] || [ "$PREFIX" = "/usr" ]; then
  DATA_DIR="/var/lib/crux"
else
  DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/crux"
fi

# ── platform detection (must match release.yml artifact suffixes) ──────────
OS="$(uname -s)"
ARCH="$(uname -m)"
case "${OS}-${ARCH}" in
  Linux-x86_64) SUFFIX="linux-amd64" ;;
  Darwin-arm64) SUFFIX="darwin-arm64" ;;
  Darwin-x86_64) SUFFIX="darwin-amd64" ;;
  Linux-aarch64)
    echo "ERROR: linux-arm64 release binaries are not published yet." >&2
    echo "Build from source instead: https://github.com/${REPO}#quickstart" >&2
    exit 1
    ;;
  *)
    echo "ERROR: unsupported platform: ${OS}/${ARCH}" >&2
    echo "Windows: run the Linux install inside WSL2 (see docs/getting-started.md)." >&2
    exit 1
    ;;
esac

# ── uninstall ───────────────────────────────────────────────────────────────
if [ "$UNINSTALL" -eq 1 ]; then
  echo "Removing binaries from ${BIN_DIR} ..."
  rm -f "${BIN_DIR}/crux" "${BIN_DIR}/corecruxd" "${BIN_DIR}/corecruxctl"
  if [ "$OS" = "Linux" ]; then
    UNIT="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/crux.service"
    if [ -f "$UNIT" ]; then
      systemctl --user disable --now crux.service 2>/dev/null || true
      rm -f "$UNIT"
      systemctl --user daemon-reload 2>/dev/null || true
      echo "Removed systemd user unit."
    fi
  else
    PLIST="${HOME}/Library/LaunchAgents/com.cuecrux.crux.plist"
    if [ -f "$PLIST" ]; then
      launchctl unload "$PLIST" 2>/dev/null || true
      rm -f "$PLIST"
      echo "Removed launchd agent."
    fi
  fi
  echo
  echo "Your data was NOT deleted. It remains at: ${DATA_DIR}"
  echo "Export it first if you are leaving (console → Settings → Export), then"
  echo "delete it yourself with: rm -rf '${DATA_DIR}'"
  exit 0
fi

# ── prerequisites ───────────────────────────────────────────────────────────
for tool in curl cosign; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: '$tool' is required." >&2
    if [ "$tool" = "cosign" ]; then
      echo "  Signature verification is mandatory — this installer will not" >&2
      echo "  install unverified binaries. Install cosign first:" >&2
      echo "    https://docs.sigstore.dev/cosign/system_config/installation/" >&2
    fi
    exit 1
  fi
done

# ── resolve version ─────────────────────────────────────────────────────────
if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    "https://github.com/${REPO}/releases/latest" | sed 's|.*/tag/||')"
  [ -n "$VERSION" ] || { echo "ERROR: could not resolve latest release tag" >&2; exit 1; }
fi
case "$VERSION" in
  v*) : ;;
  *) echo "ERROR: --version must look like vX.Y.Z (got: $VERSION)" >&2; exit 64 ;;
esac

BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
CERT_IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

WORK="$(mktemp -d /tmp/crux-install.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

echo "Installing Crux ${VERSION} (${SUFFIX}) → ${BIN_DIR}"
echo

# ── download + verify ───────────────────────────────────────────────────────
fetch() {
  echo "  fetch  $1"
  curl -fsSL --proto '=https' --tlsv1.2 -o "${WORK}/$1" "${BASE_URL}/$1"
}

verify() {
  echo "  verify $1 (cosign keyless)"
  cosign verify-blob \
    --certificate "${WORK}/$1.pem" \
    --signature "${WORK}/$1.sig" \
    --certificate-identity "${CERT_IDENTITY}" \
    --certificate-oidc-issuer "${OIDC_ISSUER}" \
    "${WORK}/$1" >/dev/null 2>&1 \
    || { echo "ERROR: signature verification FAILED for $1 — refusing to install." >&2
         echo "Report this via SECURITY.md; do not run the artifact." >&2
         exit 1; }
}

for artifact in "crux-${SUFFIX}" "corecruxctl-${SUFFIX}"; do
  fetch "${artifact}"
  fetch "${artifact}.sig"
  fetch "${artifact}.pem"
  verify "${artifact}"
done

# ── install ─────────────────────────────────────────────────────────────────
mkdir -p "${BIN_DIR}"
install -m 0755 "${WORK}/crux-${SUFFIX}" "${BIN_DIR}/crux"
install -m 0755 "${WORK}/corecruxctl-${SUFFIX}" "${BIN_DIR}/corecruxctl"
# Same binary, service-manager-friendly name (matches release artifact set).
ln -sf "${BIN_DIR}/crux" "${BIN_DIR}/corecruxd"

mkdir -p "${DATA_DIR}"
chmod 700 "${DATA_DIR}"

# ── optional service unit (installed, never auto-started) ───────────────────
if [ "$WITH_SERVICE" -eq 1 ]; then
  if [ "$OS" = "Linux" ]; then
    UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    mkdir -p "$UNIT_DIR"
    cat > "${UNIT_DIR}/crux.service" <<EOF
[Unit]
Description=Crux daemon (local-first agent memory + receipts)
Documentation=https://github.com/${REPO}/blob/main/docs/getting-started.md
After=network.target

[Service]
ExecStart=${BIN_DIR}/corecruxd
Environment=CORECRUXD_DATA_DIR=${DATA_DIR}
Environment=CORECRUXD_AUTH_MODE=dev_scopes
# Binary installs have no git checkout to compare against; keep the
# no-phone-home posture explicit.
Environment=CORECRUXD_UPDATE_CHECK_ENABLED=0
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload 2>/dev/null || true
    SERVICE_HINT="systemctl --user enable --now crux.service"
  else
    PLIST="${HOME}/Library/LaunchAgents/com.cuecrux.crux.plist"
    mkdir -p "${HOME}/Library/LaunchAgents"
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.cuecrux.crux</string>
  <key>ProgramArguments</key>
  <array><string>${BIN_DIR}/corecruxd</string></array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>CORECRUXD_DATA_DIR</key><string>${DATA_DIR}</string>
    <key>CORECRUXD_AUTH_MODE</key><string>dev_scopes</string>
    <key>CORECRUXD_UPDATE_CHECK_ENABLED</key><string>0</string>
  </dict>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
EOF
    SERVICE_HINT="launchctl load '${PLIST}'"
  fi
fi

# ── done ────────────────────────────────────────────────────────────────────
echo
echo "Installed:"
echo "  ${BIN_DIR}/crux          (the daemon)"
echo "  ${BIN_DIR}/corecruxd     (same binary, service-manager name)"
echo "  ${BIN_DIR}/corecruxctl   (admin CLI)"
echo "  ${DATA_DIR}              (data dir, 0700)"
case ":${PATH}:" in
  *":${BIN_DIR}:"*) : ;;
  *) echo; echo "NOTE: ${BIN_DIR} is not on your PATH." ;;
esac
echo
echo "Next steps:"
if [ "$WITH_SERVICE" -eq 1 ]; then
  echo "  1. Start the service (your call, not ours):"
  echo "       ${SERVICE_HINT}"
else
  echo "  1. Start the daemon:"
  echo "       CORECRUXD_AUTH_MODE=dev_scopes CORECRUXD_DATA_DIR='${DATA_DIR}' '${BIN_DIR}/crux'"
fi
echo "  2. Open the console:    http://127.0.0.1:14800"
echo "  3. Guided first fact:   '${BIN_DIR}/corecruxctl' quickstart"
echo "  4. Docs:                https://github.com/${REPO}/blob/main/docs/getting-started.md"
echo
echo "Upgrade later: re-run this script with --version vX.Y.Z (data is kept)."
