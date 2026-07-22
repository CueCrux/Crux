#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# Render packaging/homebrew/crux.rb from a release's signed RELEASE-MANIFEST
# files. Run after the release workflow has published artifacts:
#
#   bash scripts/generate-homebrew-formula.sh v0.5.0 > /tmp/crux.rb
#   # then commit /tmp/crux.rb to CueCrux/homebrew-tap as Formula/crux.rb
#
# Verifies each manifest's cosign signature before trusting its sha256 list,
# so the formula's pins inherit the release's supply-chain guarantees
# (docs/verify-release.md §2).
set -euo pipefail

TAG="${1:?usage: generate-homebrew-formula.sh vX.Y.Z}"
REPO="CueCrux/Crux"
VERSION="${TAG#v}"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
CERT_IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
TEMPLATE="packaging/homebrew/crux.rb"

command -v cosign >/dev/null 2>&1 || { echo "ERROR: cosign required" >&2; exit 2; }
[ -f "$TEMPLATE" ] || { echo "ERROR: run from the repo root ($TEMPLATE missing)" >&2; exit 2; }

WORK="$(mktemp -d /tmp/crux-formula.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

sha_for() {
  # $1 = suffix, $2 = artifact filename → print sha256 from verified manifest
  local manifest="RELEASE-MANIFEST-$1.txt"
  if [ ! -f "${WORK}/${manifest}" ]; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "${WORK}/${manifest}" "${BASE_URL}/${manifest}"
    curl -fsSL --proto '=https' --tlsv1.2 -o "${WORK}/${manifest}.sig" "${BASE_URL}/${manifest}.sig"
    curl -fsSL --proto '=https' --tlsv1.2 -o "${WORK}/${manifest}.pem" "${BASE_URL}/${manifest}.pem"
    cosign verify-blob \
      --certificate "${WORK}/${manifest}.pem" \
      --signature "${WORK}/${manifest}.sig" \
      --certificate-identity "${CERT_IDENTITY}" \
      --certificate-oidc-issuer "${OIDC_ISSUER}" \
      "${WORK}/${manifest}" >/dev/null
  fi
  # Current manifests use public flat basenames. Keep the ./ match for releases
  # produced before the basename collision hardening.
  awk -v f="$2" '$2 == f || $2 == "*"f || $2 == "./"f {print $1; found=1} END {exit !found}' \
    "${WORK}/${manifest}" \
    || { echo "ERROR: $2 not in ${manifest}" >&2; exit 1; }
}

# Capture each sha into a variable FIRST: a sha_for failure inside a sed -e
# "$(...)" argument only aborts the subshell (sed still runs with an empty
# pin), whereas a failed command substitution in an assignment trips set -e.
sha_crux_darwin_arm64="$(sha_for darwin-arm64 "crux-darwin-arm64")"
sha_crux_darwin_amd64="$(sha_for darwin-amd64 "crux-darwin-amd64")"
sha_crux_linux_amd64="$(sha_for linux-amd64 "crux-linux-amd64")"
sha_ctl_darwin_arm64="$(sha_for darwin-arm64 "corecruxctl-darwin-arm64")"
sha_ctl_darwin_amd64="$(sha_for darwin-amd64 "corecruxctl-darwin-amd64")"
sha_ctl_linux_amd64="$(sha_for linux-amd64 "corecruxctl-linux-amd64")"
sha_hook_darwin_arm64="$(sha_for darwin-arm64 "crux-hook-darwin-arm64")"
sha_hook_darwin_amd64="$(sha_for darwin-amd64 "crux-hook-darwin-amd64")"
sha_hook_linux_amd64="$(sha_for linux-amd64 "crux-hook-linux-amd64")"

sed \
  -e "s|{{VERSION}}|${VERSION}|g" \
  -e "s|{{SHA256_CRUX_DARWIN_ARM64}}|${sha_crux_darwin_arm64}|" \
  -e "s|{{SHA256_CRUX_DARWIN_AMD64}}|${sha_crux_darwin_amd64}|" \
  -e "s|{{SHA256_CRUX_LINUX_AMD64}}|${sha_crux_linux_amd64}|" \
  -e "s|{{SHA256_CTL_DARWIN_ARM64}}|${sha_ctl_darwin_arm64}|" \
  -e "s|{{SHA256_CTL_DARWIN_AMD64}}|${sha_ctl_darwin_amd64}|" \
  -e "s|{{SHA256_CTL_LINUX_AMD64}}|${sha_ctl_linux_amd64}|" \
  -e "s|{{SHA256_HOOK_DARWIN_ARM64}}|${sha_hook_darwin_arm64}|" \
  -e "s|{{SHA256_HOOK_DARWIN_AMD64}}|${sha_hook_darwin_amd64}|" \
  -e "s|{{SHA256_HOOK_LINUX_AMD64}}|${sha_hook_linux_amd64}|" \
  "$TEMPLATE"
