# CoreCrux Fuzz Targets

Audit II G5 tracks untrusted-byte parser fuzzing. This workspace is intentionally
outside the main Cargo workspace and is driven by `cargo-fuzz`.

Targets:

- `segment_decode` covers `corecrux_segment::decode_segment_v1`.
- `storage_scan_frames` covers the storage block frame scanner via a
  `cfg(fuzzing)` wrapper.
- `receipt_verify_cbor` covers receipt body/signature CBOR verification decode.
- `rcx_canonical_token` covers RCX canonical CBOR decode plus typed token
  validation/verification paths. A full byte-to-token parser does not exist yet.
- `escrow_recovery_code` covers the vault recovery path: `RecoveryCode::parse`
  over a transcribed code, and `combine_shares` over escrow shares. It
  recomputes the crate's share integrity tag so fuzz-derived share bodies get
  past the tag check and into `vsss-rs` reconstruction; a tagged share that is
  still rejected fails the target on purpose, because it means that copy of the
  tag context has drifted and everything below the gate is unfuzzed.

Smoke:

```bash
cargo install cargo-fuzz
cargo fuzz run segment_decode -- -runs=1
cargo fuzz run storage_scan_frames -- -runs=1
cargo fuzz run receipt_verify_cbor -- -runs=1
cargo fuzz run rcx_canonical_token -- -runs=1
cargo fuzz run escrow_recovery_code -- -runs=1
```

Long runs belong in scheduled CI with corpus persistence. These targets must not
use production data or network access.
