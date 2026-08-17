# crux-escrow — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Vault key recovery and escrow. Pure crate: no I/O, no daemon deps, no clock. Three layers,
each usable without the next — see the module docs on `src/lib.rs` and the adversary model
in `docs/THREAT_MODEL.md` § "Key Escrow and Recovery", which is the contract the tests
assert against.

## Key symbols
- `RecoveryCode` — 256 bits of CSPRNG; `render()`/`parse()` do the Crockford base-32
  transcription round trip with a 2-symbol checksum. `Debug` redacted; zeroed on drop
- `WrappedDek` — **the only thing the server stores**: `{vault_id, nonce, ciphertext}`. `vault_id`
  is AEAD associated data, so a blob moved between vaults fails to authenticate
- `wrap_dek` / `unwrap_dek` (+ `_with_key` variants) — XChaCha20-Poly1305 under a key
  derived by `blake3::derive_key`
- `VaultSetup` — the storable blob is reachable **only** through `acknowledge()`, making
  the show-the-customer-their-code gate a type rather than a review item
- `split_escrow` / `combine_shares` / `EscrowShare` / `ShareHolder` — Shamir 2-of-3 over
  GF(2^8) via `vsss-rs`, each share carrying a BLAKE3 integrity tag
- `release::ReleaseRequest` — `open`/`cancel`/`complete`/`replay`, plus `RELEASE_DELAY`
- `verify::all_checks` — the published no-secret check list (M5), mirrored by
  `scripts/verify-escrow.py` and run by `corecruxctl verify-escrow`

## Test & verify
- `cargo test -p crux-escrow` (`src/tests.rs` for layers 0/1, `release.rs` for the state
  machine)
- The two tests that justify the crate's existence: `server_dump_yields_nothing` and
  `one_share_yields_nothing`. Neither can pass if our holdings alone ever become
  sufficient to reconstruct a customer's key. Treat a change that touches either as a
  threat-model change, not a test fix.

## Local rules
- **Insufficient by construction.** Any change that would let server-side holdings alone
  reconstruct a wrapping key is out of scope at every tier — there is deliberately no "we
  hold the key" mode.
- `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` is load-bearing: a
  panic on a wrap/unwrap path is an availability bug on the customer's only route back to
  their data, and panic messages carry operands.
- Never add a `Debug`/`Display`/`Serialize` impl rendering `RecoveryCode` or `WrappingKey`
  (pinned by `recovery_code_is_never_rendered_by_debug`).
- Adding a field to `WrappedDek` fails `server_dump_yields_nothing` on purpose. Re-argue
  the threat model first; the test pins the field set, not just the absence of the DEK.
- `RELEASE_DELAY` is a `const`, not configuration: a value an operator can lower under
  support pressure is a value an attacker can have lowered. The release state machine owns
  no device registry and no clock — the caller passes the devices and `now`.
- No novel cryptography — every primitive is library-provided (`blake3`,
  `chacha20poly1305`, `vsss-rs`, the last with `default-features = false`).
- `verify` and `scripts/verify-escrow.py` are a published pair: change one, change both, or
  `python_reference_agrees` fails. CI sets `CRUX_REQUIRE_PYTHON_REFERENCE=1` so it cannot skip.

## Wiring
`corecruxd::http::escrow` (M3b) persists `WrappedDek` as a private, daemon-owned fact under
`__escrow__::vault::<vault_id>` and appends every `ReleaseEvent` to a per-request signed,
hash-linked observation chain. Release state there is **derived from that chain, never
stored beside it** — a cached state record could disagree with the receipts; don't add one.
`corecruxctl verify-escrow` (M5) is the other consumer.

Still not wired: notification *delivery*. `paired_device_ids` names the devices to tell and
the chain records that they were told, but no transport pushes the message.
