# crux-session — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

VaultCrux Session Handshake v1 — a schema-lock crate. Owns the canonical CBOR encoder,
the RFC 8785 JCS JSON mirror, BLAKE3 zeroed-receipt hashing, and Ed25519 signing/
verification for the `SessionPlan` type family. Protocol summary lives in
`docs/session-handshake.md`.

## Where to start
- `src/canonical.rs` — hand-rolled canonical CBOR (RFC 8949 §4.2.1); the byte contract
- `src/plan.rs` — `SessionPlan`, `SESSION_PLAN_VERSION`, `ReceiptEnvelope`
- `src/receipt.rs` — `plan_receipt_hash`, `verify_plan_signature`, `to_canonical_cbor`
- `src/handshake.rs` — `mint`: `HandshakeRequest` + inputs → `SealedPlan`
- `src/invocation.rs` — `mint_invocation_receipt` / `verify_invocation_receipt`
- `src/signer.rs` / `src/sealer.rs` / `src/registry.rs` — pluggable signing, sealing,
  session-registry backends (in-memory and file variants)
- `src/export.rs` — `build_bundle`: CE export bundle (`BUNDLE_SCHEMA_VERSION`)

## Key symbols
- `plan_receipt_hash` — BLAKE3 over canonical CBOR with the receipt fields zeroed (§3.3)
- `verify_plan_signature` — Ed25519 verification over the plan hash
- `mint` (`handshake.rs`) — the handshake entry point producing a `SealedPlan`
- `mint_invocation_receipt` / `verify_invocation_receipt` — per-invocation receipts
- `generate_default` / `generate_graph` (`generator.rs`) — capability-graph generation

## Invariants
- None of I1–I6 directly; the crate's own invariants are documented in `src/lib.rs`
  module docs (CBOR-is-truth, zeroed-receipt rule, deterministic map-key ordering,
  TS byte-parity).

## Test & verify
- `cargo test -p crux-session`

## Local rules
- Canonical CBOR is the source of truth for hashing; JSON/JCS is a transport/display
  mirror. Verification always re-encodes to canonical CBOR — never hash the JSON.
- Byte-parity with the TypeScript mirror (`CueCrux-Shared/packages/session/`) is a
  contract: any change that alters canonical bytes requires a `plan_version` bump and
  a matching TS change.
- Do not replace `canonical.rs` with a generic CBOR library — it is hand-rolled
  precisely because stock encoders differ on map-key ordering and length-head edges.
- Zeroed-receipt rule when computing the plan hash: `receipt.hash` = 32 zero bytes,
  `receipt.signature` and `receipt.signer_kid` = null.
