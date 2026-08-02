# rcx-revocation — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Consumes the `crl_url` / `push_channel` fields of `RcxCapabilityToken.revocation`,
which were previously carried on the wire and read by nothing. Fetches the CRL,
caches it with an explicit freshness window, and answers "is this principal
revoked?" in a shape the caller can **fail closed** on. Single-file crate
(`src/lib.rs`). ExecPlan `crux-hosted-relay-gateway-2026-07-30`, M2.

## Key symbols
- `RevocationSnapshot` — tri-state `Fresh` / `Stale` / `Unavailable`
- `RevocationSnapshot::checker` — `Option<impl Fn(&str) -> bool>` for
  `rcx_capability_token::verify_token_attenuated`; `None` unless `Fresh`
- `authorize_when_known` — owns the fail-closed branch: the verify closure is
  never invoked unless revocation is known
- `RevocationFeed` — the cache; `refresh`, `snapshot`, `snapshot_refreshing`, `apply_push`
- `CrlTransport` / `HttpCrlTransport` — fetch seam; `CrlDocument`, `CRL_SCHEMA_V1`

## Test & verify
- `cargo test -p rcx-revocation` (tests module at the bottom of `src/lib.rs`)
- All tests use a scripted transport — no network, and time is injected, so
  freshness and rollback are deterministic

## Local rules
- **Why tri-state.** `verify_token_attenuated` takes `Fn(&str) -> bool`, and a bare
  `bool` cannot say "I don't know". A closure answering `false` on an unreachable
  CRL turns an outage into "nobody is revoked". The fail-closed decision therefore
  cannot live inside the verifier — it lives here. Never add a
  `checker()`-equivalent that yields a closure from `Stale` or `Unavailable`.
- **Opposite polarity to the sync boundary.** `corecruxd/src/http/sync.rs` is
  deliberately fail-*open* because it reads a local identity-links plane where
  absence means "no link". Here absence means "could not ask". Do not unify them.
- **Sequence must never go backwards.** Replaying an older CRL is the cheapest
  un-revoke attack — no key material, just a cached response. Rollbacks are
  refused and the prior cache is retained.
- **HTTPS only**, enforced in the transport rather than left to callers: a
  cleartext CRL is attacker-editable and stripping entries un-revokes devices.
- **`apply_push` is additive only.** A push may add revocations, never remove
  them. The push transport needs a WebSocket (none in this tree yet — M4
  introduces the first), so only the hook lives here.
- Keep the crate thin: no daemon deps, no async runtime.
