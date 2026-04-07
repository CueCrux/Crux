# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- JSONL persistence for fact store and session store — facts survive daemon restarts
- Paginated fact export endpoint (`GET /v1/facts/export`) with cursor pagination
- Bidirectional sync client — pull enriched facts from remote CoreCrux, push local facts back
- Background sync task with configurable interval (`CORECRUXD_SYNC_INTERVAL_SECS`)
- Privacy controls for sync: `private` flag on facts, 14 default entity-prefix blocklist, preview-before-push
- 3 new MCP tools: `sync_pull`, `sync_push`, `sync_status` (21 tools total)
- Architecture Decision Records (`docs/adr/`): append-only segments, CROWN receipts, CPU-only edition
- Benchmark documentation (`docs/benchmarks.md`)
- gRPC integration tests covering all data-plane RPCs
- Runnable Rust example (`examples/rust/append_and_query.rs`)

### Changed

- Split `corecrux-storage/src/lib.rs` (13k LOC) into 9 domain modules
- Split `corecruxd/src/http.rs` (10k LOC) into 10 handler sub-modules
- Migrated CI to self-hosted Hetzner runners
- Stripped all GPU/CUDA data-plane code (~10k LOC removed) — Community Edition is CPU-only

### Fixed

- Flaky `crux-observe` config test (env-var race condition)
- `SessionStore::put` TTL parameter across all callers
- `arduino/setup-protoc` GitHub API rate limit (added `repo-token`)

### Security

- Fact sync privacy: sensitive entity prefixes (`finance:`, `health:`, `personal:`, etc.) are never pushed upstream
- Sync push requires explicit `confirm: true` via MCP tool — preview mode by default

## [0.1.0] - 2026-04-03

### Added

- Append-only event store with sealed segments, BLAKE3 integrity, and crash recovery
- CPU BM25 retrieval via `.ccxi` companion indexes with PForDelta compression
- Graph signal fusion for relation-aware retrieval
- CROWN receipt generation with Ed25519 signatures and BLAKE3 chain
- Token-budgeted retrieval (fill results until token budget exhausted)
- Relevance floor (minimum BM25 score threshold with `below_floor` count)
- Progressive retrieval (scan/expand two-pass pattern)
- Coverage and gap reporting on every query response
- Fact store (receipted key-value entity memory with BM25 search)
- Session store (scoped state per session with token counting)
- CLI tools: `corecruxctl verify-store`, `replay`, `inspect-receipt`, `explain`, `gaps`
- Contribution manifest (`crux-contrib`) with BLAKE3 content-addressed envelopes
- Sync client (`crux-sync`) with outbox-based offline-first VaultCrux sync
- HTTP API on port 14800 (`/healthz`, `/readyz`, `/metrics`, `/v1/append`, `/v1/query/*`, `/v1/facts/*`, `/v1/sessions/*`)
- gRPC data plane (append, read, replay, export)
- Prometheus metrics endpoint (100+ operational metrics)
- Docker image (Debian bookworm-slim) with docker-compose.yml
- GitHub Actions CI (lint, test, 82%+ coverage, release binaries, Docker push)
- Strict linting (`unsafe_code` forbidden, pedantic clippy, 81% coverage floor)

### Security

- CueCrux Community Licence (CCL v1.0) with 3-year Apache 2.0 conversion
- No telemetry, no phone-home, no tracking in standalone mode
- `cargo-deny` supply chain and licence audit in CI
- `cargo-audit` CVE scanning in CI

[unreleased]: https://github.com/CueCrux/Crux/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/CueCrux/Crux/releases/tag/v0.1.0
