# crux-contrib — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Contribution-manifest builder and envelope signing. Builds self-contained
contribution envelopes (corrections, citations, gap reports, skills) with
content-addressed references, provenance from the local receipt chain, and an
Ed25519 signature. Tiny crate (~0.2k LOC), single module: `manifest.rs`.

## Key symbols
- `build_manifest` — assembles a `ContributionManifest` from contribution content + provenance.
- `ContributionManifest` — the envelope type; `envelope_signature` is empty at build time and set after signing.
- `Provenance` — receipt-chain provenance embedded in the envelope (includes `signed_at`).

## Test & verify
- `cargo test -p crux-contrib`

## Local rules
- Signatures are over the envelope with `envelope_signature` unset — keep the build-then-sign ordering; do not sign a manifest that already contains a signature value.
