#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# Generate update-manifest.json (schema crux.update_manifest.v2) for a
# release tag, from the release's cosign-verified RELEASE-MANIFEST files —
# the emitted sha256 pins inherit the supply-chain guarantees.
#
#   bash scripts/generate-update-manifest.sh v0.5.0 > update-manifest.json
#
# Release-flow placement: run after artifacts publish, attach the output to
# the same release (and cosign-sign it like the other artifacts). The stable
# consumer URL is releases/latest/download/update-manifest.json — see
# docs/update-channel.md. CI wiring is gated until PR #172 merges.
set -euo pipefail

TAG="${1:?usage: generate-update-manifest.sh vX.Y.Z}"
REPO="CueCrux/Crux"
VERSION="${TAG#v}"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
CERT_IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
SUFFIXES=(linux-amd64 darwin-arm64 darwin-amd64)

command -v cosign >/dev/null 2>&1 || { echo "ERROR: cosign required" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq required" >&2; exit 2; }

WORK="$(mktemp -d /tmp/crux-update-manifest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

artifacts="[]"
for suffix in "${SUFFIXES[@]}"; do
  manifest="RELEASE-MANIFEST-${suffix}.txt"
  curl -fsSL --proto '=https' --tlsv1.2 -o "${WORK}/${manifest}" "${BASE_URL}/${manifest}"
  curl -fsSL --proto '=https' --tlsv1.2 -o "${WORK}/${manifest}.sig" "${BASE_URL}/${manifest}.sig"
  curl -fsSL --proto '=https' --tlsv1.2 -o "${WORK}/${manifest}.pem" "${BASE_URL}/${manifest}.pem"
  cosign verify-blob \
    --certificate "${WORK}/${manifest}.pem" \
    --signature "${WORK}/${manifest}.sig" \
    --certificate-identity "${CERT_IDENTITY}" \
    --certificate-oidc-issuer "${OIDC_ISSUER}" \
    "${WORK}/${manifest}" >/dev/null

  asset_name="crux-${suffix}"
  # Logical name is deliberately invisible to pre-M5 self-updaters. Those
  # clients would otherwise replace only the daemon and omit the newly bundled
  # hook/CLI; failing lookup forces the complete installer transition.
  name="standalone-${asset_name}"
  # Current manifests use public flat basenames. Keep the ./ match for releases
  # produced before the basename collision hardening.
  sha="$(awk -v f="$asset_name" '$2 == f || $2 == "*"f || $2 == "./"f {print $1}' "${WORK}/${manifest}")"
  [ -n "$sha" ] || { echo "ERROR: ${asset_name} not found in ${manifest}" >&2; exit 1; }
  artifacts="$(jq -c --arg n "$name" --arg a "$asset_name" --arg s "$sha" '. + [{name:$n, asset_name:$a, sha256:$s}]' <<<"$artifacts")"
done

jq -n \
  --arg tag "$TAG" \
  --arg version "$VERSION" \
  --arg published_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg notes_url "https://github.com/${REPO}/releases/tag/${TAG}" \
  --arg verify_doc "https://github.com/${REPO}/blob/${TAG}/docs/verify-release.md" \
  --argjson artifacts "$artifacts" \
  '{schema:"crux.update_manifest.v2", tag:$tag, version:$version,
    published_at:$published_at, notes_url:$notes_url, verify_doc:$verify_doc,
    artifacts:$artifacts}'
