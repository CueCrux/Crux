# rcx-capability-token — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

RCX Capability Token v1.0 schema-lock crate (`RCX_CT_SPEC_VERSION = "rcx-ct/1.0"`).
Intentionally pure: token model, deterministic CBOR/JSON mirror, token hash input,
structural validation, and strict Ed25519 verification used by the daemon router
(`crux-router`), enterprise shim, and hosted issuer. Single-file crate (`src/lib.rs`).

## Key symbols
- `RcxCapabilityToken` — the token model; `to_canonical_cbor()` / `to_cbor_value(zero_signature)`
  produce the deterministic encoding (signature zeroed for the hash/signing input)
- `verify_token` — strict verification against a trust-root pubkey (ed25519-dalek
  `verify_strict`) + expiry; returns `VerifyOutcome`
- `validate_basic` — structural validation → `TokenValidationResult`
- `RcxTier` / `ReceiptClass` — tier and receipt-class enums
- `CORECRUX_PREMIUM_LANE_SLUGS` / `corecrux_lane_capability` / `corecrux_lane_credit_cost` —
  the 13 premium retrieval-lane capabilities (mint side)

## Test & verify
- `cargo test -p rcx-capability-token` (tests module at the bottom of `src/lib.rs`)
- Workspace fuzz target: `fuzz/fuzz_targets/rcx_canonical_token.rs`

## Local rules
- Schema-locked at v1.0: field set, CBOR key order, and the canonical encoding are frozen.
  Any wire change means a new spec version string, not an edit to the v1.0 encoding.
- Canonical CBOR is the signature/hash input — the CBOR and JSON mirrors must stay
  byte-consistent; never introduce nondeterminism (map ordering, float forms).
- `CORECRUX_PREMIUM_LANE_SLUGS` must stay identical to CoreCrux's `lanes::Lane` vocabulary,
  and `corecrux_lane_credit_cost` must match the hosted TS minter
  (`@cuecrux-shared/contracts::CORECRUX_LANE_CREDIT_COST`) — changes must land in both.
- Free baseline lanes (bm25/dense/sparse) are never minted as capabilities and never
  gated; local dense stays free and uncapped (root CLAUDE.md, constraint C1).
- Keep the crate pure — no I/O, no daemon deps; verification must work offline.
