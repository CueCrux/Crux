# Contributing to Crux Daemon

Thank you for your interest in contributing to Crux Daemon.

## Building from Source

```bash
git clone https://github.com/CueCrux/Crux.git
cd Crux
cargo build --release
```

The binaries are at `target/release/corecruxd` and `target/release/corecruxctl`.

## Prerequisites

- Rust stable (see `rust-toolchain.toml`)
- `protoc` (Protocol Buffers compiler) — required by `corecrux-proto`

## Running Tests

```bash
cargo test --workspace                    # All unit tests
./scripts/run-integration-tests.sh        # HTTP + gRPC + MCP integration tests
```

The helper builds `corecruxd`, exports `CORECRUXD_BINARY`, and then runs the
integration crate. You can still invoke Cargo directly if you want, but then
you need to build the daemon binary first:
```bash
cargo build --bin corecruxd
CORECRUXD_BINARY=target/debug/corecruxd cargo test -p crux-integration-tests
```

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy --workspace -- -D warnings` and fix all warnings
- Follow existing patterns in the codebase

## Contribution Types

We welcome:

- **Bug fixes** with a clear description of the issue and how you verified the fix
- **Corrections** to documentation or code comments
- **Performance improvements** with benchmark evidence
- **Test coverage** improvements

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes with clear, descriptive commits
4. Ensure `cargo fmt`, `cargo clippy`, and `cargo test` all pass
5. Open a pull request with a description of what changed and why

## Changelog

When making user-facing changes, add an entry to the `[Unreleased]` section of `CHANGELOG.md`:
- `### Added` — new features
- `### Fixed` — bug fixes
- `### Changed` — behavior changes
- `### Security` — vulnerability fixes

## Licence

Crux Daemon is licensed under the Apache License, Version 2.0. Contributions are
inbound=outbound: by submitting a contribution you agree it is licensed under
Apache-2.0, per section 5 of the licence ("Submission of Contributions"), and you
confirm you have the right to submit it. There is no separate CLA to sign, and
you keep your own copyright. See [LICENSE](LICENSE) for details.

New source files should carry the standard header:

```rust
// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.
```

`./scripts/check-licence-headers.sh` enforces this on every `.rs` under `crates/`
and runs in CI.
