# crux-escrow — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Vault key recovery and escrow. Pure crate: no I/O, no daemon deps, no clock. Three layers,
each usable without the next — see the module docs on `src/lib.rs` and the adversary model
in `docs/THREAT_MODEL.md` § "Key Escrow and Recovery", which is the contract the tests
assert against.

## Key symbols
- `RecoveryCode` — 256 bits of CSPRNG; `render()` / `parse()` do the Crockford base-32
  transcription round trip with a 2-symbol checksum. `Debug` is redacted; zeroed on drop
- `WrappedDek` — **the only thing the server stores**: `{vault_id, nonce, ciphertext}`.
  `vault_id` is AEAD associated data, so a blob moved between vaults fails to authenticate
- `wrap_dek` / `unwrap_dek` (+ `_with_key` variants) — XChaCha20-Poly1305 under a key
  derived by `blake3::derive_key`
- `VaultSetup` — setup whose storable blob is reachable **only** through `acknowledge()`,
  which makes the show-the-customer-their-code gate a type rather than a review item
- `split_escrow` / `combine_shares` / `EscrowShare` / `ShareHolder` — Shamir 2-of-3 over
  GF(2^8) via `vsss-rs`, each share carrying a BLAKE3 integrity tag
- `release::ReleaseRequest` — `open` / `cancel` / `complete` / `replay`, plus
  `release::RELEASE_DELAY`

## Test & verify
- `cargo test -p crux-escrow` (`src/tests.rs` for layers 0/1, `release.rs` for the state
  machine)
- The two tests that justify the crate's existence: `server_dump_yields_nothing` and
  `one_share_yields_nothing`. Neither can pass if our holdings alone ever become
  sufficient to reconstruct a customer's key. Treat a change that touches either as a
  threat-model change, not a test fix.

## Local rules
- **Insufficient by construction.** We hold exactly one of three shares. Any change that
  would let server-side holdings alone reconstruct a wrapping key is out of scope at every
  tier — there is deliberately no "we hold the key" mode.
- `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` is load-bearing: a
  panic on a wrap/unwrap path is an availability bug on the customer's only route back to
  their data, and panic messages carry operands.
- Never add a `Debug`/`Display`/`Serialize` impl that can render `RecoveryCode` or
  `WrappingKey`. The redaction is pinned by `recovery_code_is_never_rendered_by_debug`.
- Adding a field to `WrappedDek` fails `server_dump_yields_nothing` on purpose. Re-argue
  the threat model first; the test pins the field set, not just the absence of the DEK.
- `RELEASE_DELAY` is a `const`, not configuration. A value an operator can lower under
  support pressure is a value an attacker can have lowered.
- The release state machine owns no device registry and no clock — the caller passes the
  registered devices and `now`. The relay gateway plan's device-identity plane is not
  frozen; do not pin a protocol here ahead of it.
- No novel cryptography. Every primitive is library-provided (`blake3`,
  `chacha20poly1305`, `vsss-rs`); `vsss-rs` is pulled `default-features = false` to keep
  its prime-field/elliptic-curve half out of the tree.

## Not wired yet
Nothing in `corecruxd` persists a `WrappedDek` or writes `ReleaseEvent`s as CROWN
receipts. Gates proved here are properties of the types, not of a running system.
