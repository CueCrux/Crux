# crux-router — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

RCX daemon router primitives: consumes an `RcxCapabilityToken` and returns deterministic
routing/refusal decisions (capability / egress / attestation / credit gates). Deliberately
pure — the caller supplies the clock (`now_unix_seconds`); no network, no serde. Revocation
IO is modelled on the token but not yet consulted by `decide()`.

## Where to start
- `src/lib.rs` — `RcxRouter::decide` (the whole decision pipeline), token minting helpers
- `src/hosted.rs` — `CreditLedger` (refill/debit/overdraft for hosted Tier 2 calls)
- `src/quota.rs` — per-surface token-bucket request quota (G20 third fragment)

## Key symbols
- `RcxRouter::decide` — token → `RouterDecision` (`RouterMode`: Local / Hosted /
  CustomerHosted / DegradedLocal / DegradedQueued / Refused)
- `mint_free_local_token` / `build_paid_local_token` — daemon-minted local tokens
  (paid adds `corecrux.lane.*` capabilities + credit balance, `OverdraftPolicy::Forbid`)
- `CreditLedger` + `debit_lane_usage` / `ingest_usage_report` — lane-usage billing side
- `filter_mcp_tools` — tool-name filter through the token's capability matrix
- `QuotaPolicy` / `SurfaceClass` — hosted-only rate limits (`quota.rs`)

## Invariants
- None of I1–I6. The crate-local invariant lives on `token_signature_permits_backend`:
  the `local` backend skips signature verification ONLY because tokens reaching
  `decide()` are daemon-minted; pinned by test
  `local_signature_bypass_does_not_extend_to_hosted_backend`.

## Test & verify
- `cargo test -p crux-router` (includes a hot-path latency guard on `decide()`)

## Local rules
- Decisions fail closed. A router built via `RcxRouter::new` (no trusted issuer pubkey)
  refuses every non-local backend with `denied:token_invalid`; client-supplied tokens
  MUST go through `new_with_trusted_issuer_pubkey`. `DegradedLocal`/`DegradedQueued`
  are reachable only via the token's own `FallbackPolicy` — never invent a fallback.
- `CruxModeStamp.revocation_checked` is always `false` today. Do not flip it to `true`
  until a real CRL/push-channel consult runs inside `decide()`.
- Local compute is never rate-limited (`SurfaceClass::LocalCompute`, normative in
  `quota.rs`); quota applies to hosted surfaces only.
- Keep the crate pure and serde-free — JSON (de)serialisation belongs to the daemon
  HTTP routes (see `UsageReport` doc comment).
