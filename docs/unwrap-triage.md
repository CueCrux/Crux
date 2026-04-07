# Unwrap/Expect Triage — corecruxd

The `corecruxd` binary enforces `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` at the crate root.

## Production Code Status

**8 unwrap/expect call sites** in production code (excluding tests and metrics):

| File | Count | Category | Rationale |
|------|-------|----------|-----------|
| `main.rs` | 2 | Process init (`expect`) | OTLP exporter and SIGTERM handler — failure is fatal at startup |
| `grpc.rs` | 3 | Mutex lock (`expect`) | Lock poisoning is process-fatal by design |
| `config.rs` | 2 | Literal parsing (`expect`) | Parsing `"127.0.0.1"` as IP — cannot fail |
| `shard_map.rs` | 1 | BLAKE3 on static data (`expect`) | Computing hash of default dev map — cannot fail |

All 8 are structurally safe (provably infallible or intentionally fatal on failure).

## Allowlisted Modules

### `metrics` (~250 call sites)

Prometheus client `register!()` / `register_*!()` macros use `expect()` internally. These run once at init and panic only on duplicate metric registration, which is a programmer error caught by tests.

**Reduction plan:** None. This is a Prometheus client library constraint.

## Policy

New code in `corecruxd` **must not** use `unwrap()`, `expect()`, or `panic!()`. If a call site is provably safe, add `#[allow(clippy::unwrap_used)]` with a `// SAFETY:` comment explaining why.
