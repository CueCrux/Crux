# corecrux-receipts — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Receipt formats (bytes-first), Ed25519 signing, strict verification, witness anchoring,
and export bundles. Receipt bodies are stored and returned as opaque canonical bytes
(typically CBOR); hashing/verification operates over the stored bytes exactly — no
re-serialization. Each format is a `*_v1` module exposing concrete `build_*_v1` /
`sign_*_v1` / `verify_*_v1` functions (the module names are not functions).

## Key symbols
- `verify_receipt_v1` — core receipt verification (`verify_v1.rs`); report `VerificationReportV1`
- `build_c2pa_manifest_v1` / `verify_c2pa_manifest_v1` — C2PA manifest + `C2paVerificationReportV1`
- `build_bundle_v1` / `verify_bundle_v1` — audit export bundles (tar.zst manifest+events+receipts)
- `build_external_anchor_body_v1` / `verify_rfc6962_inclusion_proof_v1` — witness anchoring (`witness_v1.rs`)
- `sign_stream_v1` — stream lifecycle receipts (`stream_v1.rs`)
- `Ed25519KeyRingV1` — signing/verifying key registry (`keyring_v1.rs`)

## Invariants
- Establishes/checks I3 (fail-closed): `verify_c2pa_manifest_v1` reports `ok` only when
  `canonical_hash_match && signature_valid && content_hash_match`; a non-Ed25519 signature
  path yields `signature_valid = false`, never a skipped check. All per-format verifiers
  use ed25519-dalek `verify_strict` (rejects malleable/non-canonical signatures).
- Establishes I5 (witness anchoring): `build_external_anchor_body_v1` commits to the
  RFC-6962 inclusion proof; checked by `verify_rfc6962_inclusion_proof_v1`.

## Test & verify
- `cargo test -p corecrux-receipts` (tests in `src/tests.rs` + per-module tests)
- Golden vectors: `vectors/audit-bundle-v1/{valid-minimal,invalid-events-hash}` —
  `include_bytes!`-pinned in `audit_bundle_v1.rs` tests
- Workspace fuzz target: `fuzz/fuzz_targets/receipt_verify_cbor.rs`

## Local rules
- Never weaken fail-closed: every new verifier must be a boolean-AND of all component
  checks, and unknown algorithms/kinds must fail, not skip.
- Never re-serialize a stored body before hashing/verifying — bytes-first is the contract.
- Changing any receipt body schema or bundle format requires a version bump
  (`*_SCHEMA_V1` → v2, `BUNDLE_FORMAT_VERSION`) and new golden vectors under `vectors/`;
  existing vectors must keep verifying.
- Use `verify_strict`, never plain `verify`, for Ed25519.
