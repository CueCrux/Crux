# CLAIMS — product claim → enforcing code → proving test

> The showcase artefact. Every claim points at the symbol that enforces it and a test
> that proves it. **Don't trust this file — run the tests** (`cargo test --workspace`).
> Symbols and test names here are verified to exist in the tree by
> `scripts/check-agent-docs.sh` in CI; a rename that orphans a reference fails the build.

Files are repo-relative; tests are named by their `fn`.

| # | Claim | Enforced by | File | Proven by (test fn) |
|---|---|---|---|---|
| 1 | Receipt signatures are strongly unforgeable (malleable / non-canonical sigs rejected) | `verify_receipt_v1`, `verify_c2pa_manifest_v1`, `verify_bundle_v1` — each calls ed25519-dalek `verify_strict` | `crates/corecrux-receipts/src/verify_v1.rs`, `c2pa_manifest_v1.rs`, `audit_bundle_v1.rs` | `tampering_with_signature_breaks_signature_check`, `wrong_verifying_key_fails`, `verify_receipt_sig_payload_hash_mismatch`, `tamper_with_signature_breaks_verification` |
| 2 | Sealed-segment content matches its footer hashes (1-bit tamper is caught) | `decode_segment_v1` re-derives header/record/toc/segment hashes | `crates/corecrux-segment/src/decoder.rs` | `detects_footer_corruption` |
| 3 | `verify-store` does cryptographic (BLAKE3) checks, not just CRC | `verify_segment_hashes_all` re-decodes each segment (via `decode_segment_v1`) and compares the recomputed `segment_hash` to the manifest record | `crates/corecrux-storage/src/integrity.rs` | `strict_scan_verifies_segment_hashes_and_detects_manifest_mismatch` |
| 4 | Each sealed segment is signed and hash-chained to its predecessor | `SegmentSealMaterialV1` (binds `segment_hash` + `previous_segment_hash`) + `sign_segment_seal_material` | `crates/corecrux-storage/src/lib.rs`, `crates/corecruxd/src/grpc.rs` | `segment_seal_receipt_signing_commits_to_segment_chain`, `append_batch_seal_receipt_links_previous_segment_hash` |
| 5 | Chain heads can be externally witnessed / timestamped | `witness_v1`: external-anchor body, RFC-6962 inclusion proof, RFC-3161 timestamp | `crates/corecrux-receipts/src/witness_v1.rs` | `rfc6962_inclusion_proof_verifies_two_leaf_tree`, `external_anchor_body_binds_inclusion_proof`, `rfc3161_timestamp_body_binds_token_hash_and_imprint` |
| 6 | Capability tokens are verified against a trusted issuer key | `verify_token` (`verify_strict` against `trust_root_pubkey`), `validate_basic` | `crates/rcx-capability-token/src/lib.rs` | `strict_verify_rejects_tampered_token`, `strict_verify_rejects_wrong_trust_root` |
| 7 | Memory updates are non-destructive and versioned (history retained) | `store` → `supersede_prior_version` → `mark_superseded` (predecessor marked, not deleted) | `crates/corecrux-memory/src/fact_store.rs` | `store_same_key_auto_supersedes_prior_version_in_recall`, `consolidate_facts_v1_supersedes_targets_without_deleting_history` |
| 8 | Capability coverage is provable (no silent gaps) | `compute_coverage_report`, `compute_gaps` | `crates/crux-lens-features/src/analytics.rs` | `gaps_identifies_critical_no_tests_for_shipped`, `coverage_report_tallies_per_system` |
| 9 | Untrusted bytes never panic the parsers | fuzz targets (libfuzzer) | `fuzz/fuzz_targets/` | `segment_decode`, `storage_scan_frames`, `receipt_verify_cbor`, `rcx_canonical_token` |
| 10 | `.cruxpack` export excludes private/reserved/deleted facts by default, and a pack carrying deleted facts fails verification | `CRUXPACK_SCHEMA_V1`, `build_manifest` (cruxpack) | `crates/corecrux-memory/src/cruxpack.rs` | `export_excludes_private_and_reserved_by_default`, `verify_rejects_pack_carrying_deleted_facts`, `valid_pack_verifies` |
| 11 | Context export is a signed custody proof — any tampered component or signed field fails offline verification | `run_context_export`, `run_context_verify` | `crates/corecruxctl/src/export.rs` | `context_export_round_trips_and_is_a_signed_custody_proof`, `tampered_component_fails_verification`, `tampered_signed_field_fails_signature` |
| 12 | Usage receipts carry metadata only (never content) and sign/verify round-trip | `usage_receipt_v1` module | `crates/corecrux-receipts/src/usage_receipt_v1.rs` | `body_carries_only_metadata`, `build_sign_verify_round_trip`, `assert_kind_rejects_content_bearing_body` |
| 13 | Metered credit spend is signed and idempotent — a retried quote cannot double-debit | `post_credit_spend` | `crates/corecruxd/src/http/credit_meter.rs` | `spends_seeded_comped_wallet_and_returns_signed_receipt`, `quote_mutation_retry_conflicts_without_second_debit` |
| 14 | Passports are issued `unverified` and tier rank is earned, strictly ordered | `handle_issue_passport` | `crates/crux-mcp/src/tools/passport.rs` | `issue_passport_creates_unverified`, `tier_rank_ordering`, `issue_passport_idempotent` |
| 15 | Constraints are validated at declaration — unknown types/severities are rejected, not stored | `handle_declare_constraint` | `crates/crux-mcp/src/tools/constraint.rs` | `declare_constraint_basic`, `declare_constraint_invalid_type`, `declare_constraint_invalid_severity` |

## Caveats (kept honest)

- **Claim 1 — `verify_strict`** is ed25519-dalek's `VerifyingKey::verify_strict` (strong
  unforgeability / non-malleability), called *by* the per-format `verify_*` fns above. It is
  not a CueCrux symbol; the CueCrux-defined entry points are the `verify_*_v1` functions.
- **Claim 3** — there is no "strict vs CRC mode flag" on `verify_segment_hashes_all`; the
  function is unconditional and delegates the BLAKE3 re-derivation to `decode_segment_v1`.
  CRC is a separate, lower-tier check inside the decoder (the `CrcMismatch` path that backs
  claim 2). The claim holds — it *is* a cryptographic check — but the "strict mode" framing
  overstates a toggle that does not exist.
- **Claim 8** — the proving tests live in `crux-lens-features` (feature-registry coverage).
  Do **not** use `corecruxctl`'s `gaps.rs` tests (`partial_coverage_reports_gap`,
  `full_coverage_no_gaps`) here: those test a *different* coverage concept
  (`.ccxseg`/`.ccxi` segment-indexed-vs-not), not feature-registry gaps.
- **Claim 9** — fuzz targets run on the scheduled `fuzz.yml` workflow (nightly toolchain),
  not in the per-PR `cargo test` run. Reproduce locally with `cargo fuzz run <target>`.
