#!/usr/bin/env bash
set -euo pipefail

cargo test -q -p crux-router hosted_bridge
cargo test -q -p crux-router credit_ledger
cargo test -q -p crux-mcp pro_hosted_token_lists_hosted_gated_tools
cargo test -q -p crux-mcp hosted_gated_tool_capability_uses_hosted_backend

echo "hosted bridge contract OK"
