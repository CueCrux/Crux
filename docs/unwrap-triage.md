# Unwrap/Expect Triage — corecruxd

The `corecruxd` binary enforces `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`
at the crate root, so every site below carries an explicit `#[allow]` with a justification.

**Counts are measured, not asserted.** Regenerate with:

```bash
scripts/unwrap-ratchet.sh            # per-crate totals vs scripts/unwrap-baseline.txt
scripts/unwrap-ratchet.sh --self-test
```

The numbers here match `count_sites()` in that script: `crates/corecruxd/**/*.rs`, excluding
`*/tests/*`, files named `tests.rs` or `metrics.rs`, full-line comments, and items under an
inline `#[cfg(test)]` (brace-scoped).

## Production Code Status

**38 unwrap/expect call sites** in `crates/corecruxd/src`, plus **9** in `crates/corecruxd/examples`
(benchmark harnesses — see below). Last measured 2026-07-29.

| File | Count | Category | Justification |
|------|-------|----------|---------------|
| `http/session_metrics.rs` | 22 | Prometheus registration (`expect`) | Metric constructors and `registry.register()` at init. Fails only on duplicate registration — a programmer error, caught by tests. Same class as the allowlisted `metrics.rs`; counted because it lives outside that file. |
| `http/receipts.rs` | 3 | Static parse (`unwrap` ×2), static date (`expect`) | `content_type()` returns a `&'static str` ASCII MIME. `zip::DateTime::from_date_and_time(1980,1,1,0,0,0)` is a compile-time-constant valid date. |
| `grpc.rs` | 3 | Mutex lock (`expect`) | Lock poisoning is process-fatal by design; a poisoned throttle/queue mutex means an earlier panic already invalidated the state. |
| `storybook.rs` | 2 | Narrative builder (`unwrap`) | File-level `#![allow(clippy::unwrap_used)]` at `storybook.rs:19`. Operates on data constructed a few lines above. |
| `encrypted_secrets.rs` | 2 | Crypto invariants (`expect`) | `XNonce::try_from` on an exactly-24-byte array (XNonce length is a compile-time constant); `XChaCha20Poly1305::encrypt` fails only on programmer error (its only error case is a plaintext-length overflow that cannot occur here). |
| `main.rs` | 1 | Process init (`expect`) | SIGTERM handler registration at startup; failure is fatal and must be loud. |
| `http/replay.rs` | 1 | Static parse (`unwrap`) | `content_type()` static ASCII MIME, as above. |
| `shard_map.rs` | 1 | BLAKE3 on static data (`expect`) | Hash of the built-in default dev shard map. |
| `redaction.rs` | 1 | Prometheus counter (`expect`) | Same class as `session_metrics.rs`. |
| `memory_extract.rs` | 1 | Static regex (`expect`) | `Regex::new` over a literal pattern; a malformed pattern is a build-time bug. |
| `dossier.rs` | 1 | Non-empty by construction (`unwrap`) | `entries.iter().next()` in the `else` of `agents.len() >= 2` (`dossier.rs:769`). `by_triple` keys exist only where at least one entry was inserted, so the branch holds exactly one. **Relies on a non-local invariant** — re-check if `by_triple`'s construction changes. |

### `examples/` (9 sites)

`ast_scan_bench.rs` (5) and `symbol_resolve_gate.rs` (4). Measurement harnesses carrying
`#![allow(clippy::expect_used, clippy::unwrap_used)]`. A benchmark that panics on malformed
input is correct; one that swallows the error reports a number that is quietly wrong.

`count_sites()` excludes `*/tests/*` but not `*/examples/*`, deliberately — widening the
exclusion would reduce the ratchet's coverage for every crate.

## Allowlisted Modules

### `metrics.rs` (240 sites)

Prometheus `register!()` / `register_*!()` macros use `expect()` internally. Init-time only;
panics only on duplicate metric registration. **Reduction plan:** none — a client library constraint.

### `http/tests.rs` (590 sites)

Test code. It carries no in-file `#[cfg(test)]` because it is gated from `http/mod.rs` via an
out-of-file `#[path]` module declaration, which is why the ratchet counted it until 2026-07-29.

## Policy

New code in `corecruxd` **must not** use `unwrap()`, `expect()`, or `panic!()`. If a call site is
provably safe, add `#[allow(clippy::unwrap_used)]` with a `// SAFETY:` comment explaining why.

A `// SAFETY:` comment is a claim, and claims are checkable. Two comments in `http/receipts.rs`
asserted "filename is sanitised above" when no sanitisation existed on that path — the filename
interpolated `receipt_id` / `stream_type` / `stream_id` straight off the request path into a
`HeaderValue`, which rejects CR/LF and non-ASCII, so a hostile path parameter panicked into the
`CatchPanicLayer` as a 500. Fixed 2026-07-29 by routing all three export handlers through
`http::replay::attachment_disposition`, which sanitises and cannot fail. Regression test:
`http::replay::tests::attachment_disposition_survives_hostile_path_params`.

When writing a `// SAFETY:` comment, name the invariant and where it is established. If the
invariant lives in another function, say so.

## History

- **2026-07-29** — Rebuilt from measurement. The previous revision claimed 8 sites across
  `main.rs`, `grpc.rs`, `config.rs` and `shard_map.rs`, and asserted all 8 were provably
  infallible. The real count was 38: `config.rs` had since dropped to zero, `session_metrics.rs`
  (22) and the two trust-path files `receipts.rs` / `encrypted_secrets.rs` were absent from the
  table, and `main.rs`'s SIGTERM `expect` sat in a scanner blind spot. See
  `scripts/unwrap-baseline.txt` for the corresponding ratchet re-baseline.
