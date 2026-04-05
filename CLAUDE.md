# CoreCrux Community Edition — Claude Code Instructions

## Scope

These rules apply when working inside the `Crux/` repository.

## Build & Test

```bash
cargo build --release                    # Build community edition (CPU-only)
cargo test --workspace                   # Run all tests
cargo fmt --check                        # Check formatting
cargo clippy --workspace -- -D warnings  # Lint
```

## Architecture

- 15 Rust crates in a workspace under `crates/`
- `corecruxd` — HTTP (axum, port 14800) + gRPC (tonic) daemon
- `corecruxctl` — CLI tool with subcommands
- `corecrux-retrieval` — BM25 + graph signal fusion (CPU path)
- `corecrux-storage` — Append-only shard store with sealed segments
- `corecrux-receipts` — Ed25519 CROWN receipt signing
- GPU stub crates (`corecrux-gpu`, `corecrux-alloc`, `corecrux-io`, `corecrux-kernels`) provide no-op implementations

## Key Rules

- **No GPU code.** Community edition compiles without `cuda` feature. Never add `--features cuda`.
- **No proprietary crates.** `corecrux-analytics`, `corecrux-decision`, `corecrux-coordinator` do NOT exist in this repo.
- **Licence headers.** Every `.rs` file must start with the CCL header. Run `grep -rL "Licensed under" crates/**/*.rs` to check.
- **Port 14800.** The community edition HTTP port. Do not change this default.

## Licence

CueCrux Community Licence (CCL v1.0). See `LICENCE.md`. Source-available, not open-source.
