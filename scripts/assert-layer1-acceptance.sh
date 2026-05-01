#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

run() {
  echo "+ $*"
  "$@"
}

# Crux daemon v2.0 M3 acceptance: prove the local Layer 1 path remains
# executable and replayable without hosted services.
run cargo test -q -p corecrux-storage replay_from_cursor_continues_deterministically
run cargo test -q -p corecrux-storage build_ccxi_companion_writes_index_and_uses_stream_hash_fallback_for_bad_headers
run cargo test -q -p corecrux-retrieval basic_bm25_retrieval
run cargo test -q -p corecrux-retrieval cat12_bm25_recall
run cargo test -q -p corecrux-receipts verify_ed25519_ok_and_zip_deterministic
run cargo test -q -p corecrux-projections rebuild_from_genesis_batch_size_1_matches_large_batch
run cargo test -q -p corecrux-projections session_plans_by_principal
run cargo test -q -p crux-session ce_full_parity_open_session_10_invocations_restart_verify
run cargo test -q -p crux-session ce_install_exports_verifiable_bundle
run cargo test -q -p corecruxd text_search
run cargo test -q -p corecruxd get_receipt
run cargo test -q -p corecruxd post_query_graph_expand_uses_http_dataplane_fake

echo "daemon layer1 acceptance OK"
