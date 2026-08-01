# corecrux-secrets — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Authenticated encryption for secrets at rest. XChaCha20-Poly1305 seal/open over a
32-byte symmetric key the *caller* supplies — this crate never sources, derives,
persists or logs a key. A dependency-free leaf: no other workspace crate is
imported, which is what lets both `corecrux-providers` and `corecruxd` depend on
it without a layering cycle.

## Key symbols
- `seal` — encrypt plaintext under a `&[u8; 32]`, returning an `EncryptedEnvelope`
- `open` — decrypt an envelope; every failure mode is an `EncryptedSecretError`
- `EncryptedEnvelope` — the serde-serialised on-disk shape (scheme, nonce, ciphertext)
- `SCHEME_V1` (`xchacha20poly1305-v1`) — the scheme tag written into every envelope

## Invariants
- A fresh random 24-byte nonce per `seal` call. Never reuse a nonce under one key —
  XChaCha20-Poly1305 loses confidentiality *and* integrity if a nonce repeats.
- `EncryptedEnvelope` is a persisted format. Callers hold sealed envelopes on disk
  (GitHub PAT, OpenAI API key), so a field change is a new `SCHEME_*`, not an edit.
- `open` rejects an envelope whose `scheme` is not recognised rather than guessing.

## Test & verify
- `cargo test -p corecrux-secrets`
- Round-trip and tamper-detection cases live in the crate's own `#[cfg(test)]` module.

## Local rules
- Never add a "decrypt without verifying the tag" path, and never widen an error to
  report *why* decryption failed to an untrusted caller — that is a padding-oracle
  shape.
- Keep this crate dependency-free of other workspace crates. It sits below
  `corecrux-providers` and `corecruxd` precisely so both can use it; adding an
  internal dep would invert that.
- Do not add key derivation or key storage here. Key custody is the caller's
  (the daemon derives a subkey from the daemon-root passport).
