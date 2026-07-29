#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Clean-VM install smoke test (release-gate criterion: scripted install →
# daemon ready → MCP handshake → fact round-trip → uninstall, on a machine that
# has never seen Crux). Run this ON the clean VM (Ubuntu LTS / Debian / macOS /
# WSL2):
#
#   bash packaging/tests/install-smoke.sh v0.5.0
#
# Prerequisites on the VM: curl, cosign. Nothing else.
#
# NOTE: this script needs a published, signed release to run against — it is
# the *operator's* clean-VM gate, executed before announcing a release. It has
# not been faked locally; status lives in the ExecPlan Progress section.
set -euo pipefail

TAG="${1:?usage: install-smoke.sh vX.Y.Z}"
REPO="CueCrux/Crux"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
CERT_IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
PREFIX="$(mktemp -d "${HOME}/crux-smoke.XXXXXX")"
SMOKE_DATA_HOME="${PREFIX}/xdg-data"
DATA_DIR="${SMOKE_DATA_HOME}/crux"
FAILED=0

step() { echo; echo "== $* =="; }

step "1/9 download installer and verification material (never piped)"
for artifact in \
  install.sh \
  install.sh.sig \
  install.sh.pem \
  RELEASE-MANIFEST-linux-amd64.txt \
  RELEASE-MANIFEST-linux-amd64.txt.sig \
  RELEASE-MANIFEST-linux-amd64.txt.pem; do
  curl -fsSL --proto '=https' --tlsv1.2 \
    -o "${PREFIX}/${artifact}" \
    "${BASE_URL}/${artifact}"
done

step "2/9 authenticate installer and signed manifest"
cosign verify-blob \
  --certificate "${PREFIX}/install.sh.pem" \
  --signature "${PREFIX}/install.sh.sig" \
  --certificate-identity "${CERT_IDENTITY}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  "${PREFIX}/install.sh" >/dev/null
cosign verify-blob \
  --certificate "${PREFIX}/RELEASE-MANIFEST-linux-amd64.txt.pem" \
  --signature "${PREFIX}/RELEASE-MANIFEST-linux-amd64.txt.sig" \
  --certificate-identity "${CERT_IDENTITY}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  "${PREFIX}/RELEASE-MANIFEST-linux-amd64.txt" >/dev/null
EXPECTED_INSTALLER_SHA="$(awk '$2 == "./install.sh" || $2 == "install.sh" || $2 == "*install.sh" {print $1; found=1} END {exit !found}' \
  "${PREFIX}/RELEASE-MANIFEST-linux-amd64.txt")" \
  || { echo "FAIL: signed manifest does not cover install.sh"; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_INSTALLER_SHA="$(sha256sum "${PREFIX}/install.sh" | awk '{print $1}')"
else
  ACTUAL_INSTALLER_SHA="$(shasum -a 256 "${PREFIX}/install.sh" | awk '{print $1}')"
fi
[ "$ACTUAL_INSTALLER_SHA" = "$EXPECTED_INSTALLER_SHA" ] \
  || { echo "FAIL: install.sh does not match signed release manifest"; exit 1; }

step "3/9 install with per-binary signature verification"
XDG_DATA_HOME="${SMOKE_DATA_HOME}" \
  bash "${PREFIX}/install.sh" --version "${TAG}" --prefix "${PREFIX}"

step "4/9 verify hook binary"
HOOK_VERSION="$("${PREFIX}/bin/crux-hook" --version)"
EXPECTED_HOOK_VERSION="crux-hook ${TAG#v}"
[ "$HOOK_VERSION" = "$EXPECTED_HOOK_VERSION" ] \
  || { echo "FAIL: hook version '$HOOK_VERSION' != '$EXPECTED_HOOK_VERSION'"; exit 1; }

step "5/9 boot daemon"
CORECRUXD_AUTH_MODE=dev_scopes \
  CORECRUXD_DATA_DIR="${DATA_DIR}" \
  CORECRUXD_HTTP_PORT=14800 \
  "${PREFIX}/bin/crux" >"${PREFIX}/daemon.log" 2>&1 &
DPID=$!
trap 'kill "$DPID" 2>/dev/null || true' EXIT

READY=0
for _ in $(seq 1 60); do
  curl -sf http://127.0.0.1:14800/readyz >/dev/null 2>&1 && { READY=1; break; }
  kill -0 "$DPID" 2>/dev/null || break
  sleep 0.5
done
[ "$READY" -eq 1 ] || { echo "FAIL: daemon not ready"; tail -20 "${PREFIX}/daemon.log"; exit 1; }
echo "ready: $(curl -sf http://127.0.0.1:14800/v1/version)"

step "6/9 MCP handshake"
RESP="$(curl -sf -X POST http://127.0.0.1:14801/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"install-smoke","version":"0"}}}')"
echo "$RESP" | grep -q '"serverInfo"' || { echo "FAIL: MCP initialize: $RESP"; FAILED=1; }

step "7/9 fact round-trip"
SMOKE_ENTITY="install-smoke:${TAG}:$(date +%s)"
SMOKE_VALUE="clean-vm-fact-round-trip"
curl -sf -X PUT http://127.0.0.1:14800/v1/facts \
  -H 'Content-Type: application/json' \
  -H 'X-Corecrux-Scopes: facts:write,query:read' \
  -d "{\"entity\":\"${SMOKE_ENTITY}\",\"key\":\"probe\",\"value\":\"${SMOKE_VALUE}\",\"confidence\":1.0}" \
  >/dev/null || { echo "FAIL: fact write"; FAILED=1; }
FACT_RESP="$(curl -sfG http://127.0.0.1:14800/v1/facts \
  -H 'X-Corecrux-Scopes: facts:write,query:read' \
  --data-urlencode "entity=${SMOKE_ENTITY}" \
  --data-urlencode "token_budget=500")" \
  || { echo "FAIL: fact read"; FAILED=1; FACT_RESP=""; }
echo "$FACT_RESP" | grep -q "$SMOKE_VALUE" || { echo "FAIL: fact round-trip: $FACT_RESP"; FAILED=1; }

step "8/9 stop daemon"
kill "$DPID" && wait "$DPID" 2>/dev/null || true
trap - EXIT

step "9/9 uninstall (data must survive)"
XDG_DATA_HOME="${SMOKE_DATA_HOME}" \
  bash "${PREFIX}/install.sh" --uninstall --prefix "${PREFIX}"
[ ! -e "${PREFIX}/bin/crux" ] || { echo "FAIL: binary still present"; FAILED=1; }
[ ! -e "${PREFIX}/bin/crux-hook" ] || { echo "FAIL: hook binary still present"; FAILED=1; }
[ -d "${DATA_DIR}" ] || { echo "FAIL: data dir was deleted by uninstall"; FAILED=1; }

echo
if [ "$FAILED" -eq 0 ]; then
  echo "PASS: install → hook version → ready → MCP → fact round-trip → uninstall (data preserved)"
  echo "Cleanup is yours: rm -rf '${PREFIX}' '${DATA_DIR}'"
else
  echo "FAIL: see messages above"
  exit 1
fi
