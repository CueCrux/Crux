#!/usr/bin/env bash
# Rebuild the Claude Desktop bundle (../assets/crux.mcpb) from manifest.json.
#
# The packed artifact is COMMITTED so `cargo build` never needs npm and can never
# resolve a different dependency version. Run this only to refresh the vendored
# mcp-remote, then commit the resulting crux.mcpb as a reviewable diff.
#
# Versions are pinned exactly: an unpinned `npx -y ...@latest` reaching a dev
# machine is threat-ref T.5.
set -euo pipefail

MCP_REMOTE_VERSION="0.1.38"
MCPB_CLI_VERSION="2.1.2"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${here}/../assets/crux.mcpb"

command -v node >/dev/null || { echo "build.sh: node not found" >&2; exit 1; }
command -v npm  >/dev/null || { echo "build.sh: npm not found" >&2; exit 1; }

# mcpb packs whatever sits next to the manifest, so stage the runtime in server/.
rm -rf "${here}/server"
mkdir -p "${here}/server"
(
  cd "${here}/server"
  npm init -y --silent >/dev/null
  npm install "mcp-remote@${MCP_REMOTE_VERSION}" --omit=dev --silent
)

# `mcpb pack <dir> <out>` validates the manifest as part of packing.
npx --yes "@anthropic-ai/mcpb@${MCPB_CLI_VERSION}" pack "${here}" "${out}"

echo
echo "built: ${out}"
echo "sha256: $(sha256sum "${out}" | cut -d' ' -f1)"
echo
echo "Commit ../assets/crux.mcpb. The staged server/ tree is gitignored."
