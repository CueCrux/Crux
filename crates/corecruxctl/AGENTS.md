# corecruxctl — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

CoreCrux CLI (clap dispatcher in `src/main.rs`, handlers as library modules). Reads and
writes the same on-disk substrate as `corecruxd` but never over the network — operators
run it locally against a stopped or quiesced daemon. ~33k LOC — index only.

## Where to start
- `src/start.rs` — `start::run`: the canonical zero→first-loop on-ramp (detect daemon,
  authenticate, wire MCP + hooks, round-trip a fact); delegates to `login`
- `src/verify_store.rs` — `verify_store(&VerifyStoreOptions)`: store integrity walk;
  `--strict` re-derives segment hashes and walks the seal chain
- `src/replay.rs` — `replay_digest_from_pack` / `replay_digest_from_jsonl`
- `src/export.rs` — context export/verify custody proof (see Invariants)
- `src/gaps.rs` — segment indexed-vs-not coverage (NOT the feature-registry gaps —
  that is `crux-lens-features`; see CODEMAP "Notes")
- `src/receipts.rs`, `src/inspect_receipt.rs`, `src/c2pa_x509.rs` — receipt
  verification surface; `src/audit_pack.rs` / `src/audit_export.rs` — audit bundles

## Key symbols
- `start::run` — the on-ramp entry point
- `verify_store` — returns `VerifyStoreReport`; main.rs exits non-zero on failures
- `run_context_export` / `run_context_verify` (`src/export.rs`) — passport-signed
  context bundle out, offline fail-closed verification back

## Invariants
- Checks I1 + I2: `verify-store --strict` drives
  `corecrux_storage::verify_segment_hashes_all` and the seal-chain walk.
- Establishes + checks I6: `run_context_export` / `run_context_verify` — the
  export → offline-verify → tamper-rejection cycle is a release-blocking CI gate.
- Checks I3 shape in `src/c2pa_x509.rs` (boolean-AND report, adds `&& chain_pass`).

## Test & verify
- `cargo test -p corecruxctl`

## Local rules
- `verify-store` and `replay` are the trust tools: they must stay offline,
  deterministic, and fail-closed — never add network calls or "warn and pass" paths.
- `start` is the canonical on-ramp; new onboarding behaviour goes through it (or
  `login`), not a new parallel subcommand.
- Do not weaken the I6 CI gate tests in `src/export.rs`
  (`tampered_component_fails_verification` etc.) to make a change pass.
