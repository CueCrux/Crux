#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${CORECRUXD_BINARY:-}" == "" ]]; then
  echo "Building corecruxd for standalone integration tests..."
  cargo build -p corecruxd --manifest-path "$repo_root/Cargo.toml"
  export CORECRUXD_BINARY="$repo_root/target/debug/corecruxd"
fi

echo "Using CORECRUXD_BINARY=$CORECRUXD_BINARY"
exec cargo test --manifest-path "$repo_root/Cargo.toml" -p crux-integration-tests "$@"
