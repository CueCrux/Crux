# Crux Daemon — Claude Code Instructions

## Scope

These rules apply when working inside the `Crux/` repository.

## Build & Test

```bash
cargo build --release                    # Build Crux Daemon (CPU-only)
cargo test --workspace                   # Run all tests
cargo fmt --check                        # Check formatting
cargo clippy --workspace -- -D warnings  # Lint
```

## Architecture

- 28 Rust crates in a workspace under `crates/` — full atlas: `docs/agent/CODEMAP.md` (see `AGENTS.md` for the agent reading order)
- `corecruxd` — HTTP (axum, port 14800) + gRPC (tonic) daemon
- `corecruxctl` — CLI tool with subcommands
- `corecrux-retrieval` — BM25 + graph + dense-cosine signal fusion (CPU path). The dense lane is a free, **uncapped** local capability via a pluggable `DenseProvider` (exact CPU cosine in the CE; GPU `.ccxe` in the dataplane). Better dense (reranking) and extraction are the metered upsell — never a clip on local dense. See ExecPlan `dense-lane-and-extraction-upsell-2026-06-26`.
- `corecrux-storage` — Append-only shard store with sealed segments
- `corecrux-receipts` — Ed25519 CROWN receipt signing
- GPU/CUDA acceleration requires a dataplane-enabled distribution (not included in this repo)

## Key Rules

- **No GPU/CUDA code.** Crux Daemon is CPU-only. No `--features cuda`, no CUDA imports, no GPU readiness checks.
- **No proprietary crates.** `corecrux-analytics`, `corecrux-decision`, `corecrux-coordinator` do NOT exist in this repo.
- **Licence headers.** Every `.rs` file must start with the Apache-2.0 header (copyright + `SPDX-License-Identifier: Apache-2.0`). Run `./scripts/check-licence-headers.sh` to check.
- **Port 14800.** The Crux Daemon HTTP port. Do not change this default.

## Licence

Apache License, Version 2.0. See `LICENSE`. Open source (OSI-approved).
