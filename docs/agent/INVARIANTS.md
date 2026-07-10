# INVARIANTS — the guarantees and where they hold

> Each invariant: the statement as the code actually implements it, where it is
> **established** (written), and where it is **checked** (verified). Symbols are greppable
> and CI-verified. ADRs in `docs/adr/` carry the rationale.

## I1 — segment_hash binding

```
segment_hash = BLAKE3( header_hash ‖ record_hash ‖ toc_payload_hash )
  where header_hash      = blake3(canonical header bytes)
        record_hash      = blake3(record area)
        toc_payload_hash = compute_toc_payload_hash(toc_payload)
```

Concatenation order is exactly header → record → toc_payload (verified against source).

- **established:** `corecrux-segment/src/sealer.rs` (`seal_segment_v1_from_record_area`) and
  the mirror in `corecrux-segment/src/builder.rs` (`build_segment_v1`) — stored into
  `SegmentFooterV1.segment_hash`.
- **checked:** `corecrux-segment/src/decoder.rs` (`decode_segment_v1`, re-derives all four
  hashes; `SegmentError::CrcMismatch` on divergence) and
  `corecrux-storage/src/integrity.rs` (`verify_segment_hashes_all`, used by
  `corecruxctl verify-store --strict`).

## I2 — segment chain

```
seal(N).previous_segment_hash == seal(N-1).segment_hash   (within a shard)
seal(0).previous_segment_hash == None                     (first segment)
```

- **established:** `corecrux-storage/src/lib.rs` (`SegmentSealMaterialV1`, fields
  `segment_hash` / `previous_segment_seq` / `previous_segment_hash`) — populated on the
  append/seal path (`corecrux-storage/src/append.rs`), which links each seal to the
  highest-seq prior segment in the same shard. The receipt is signed by
  `sign_segment_seal_material` (`corecruxd/src/grpc.rs`).
- **checked:** `corecrux-storage/src/tests.rs`
  (`append_batch_seal_receipt_links_previous_segment_hash`); the `verify-store --strict`
  chain walk; `build_segment_seal_receipt` gates on both previous-link fields being present.

## I3 — fail-closed verification

```
report.ok  ⟺  canonical_hash_match && signature_valid && content_hash_match
```

A verification report is `ok` only if **all** component checks pass. A non-Ed25519
signature path yields `signature_valid = false` (fail-closed), not a skipped check.

- **enforced:** `corecrux-receipts/src/c2pa_manifest_v1.rs` (`verify_c2pa_manifest_v1`,
  report `C2paVerificationReportV1`). The same boolean-AND shape recurs in the MCP verify
  tools (`crux-mcp/src/tools/receipt_verify.rs`, `observations.rs`) and
  `corecruxctl/src/c2pa_x509.rs` (adds `&& chain_pass`).

## I4 — monotonic fact versioning

```
A new value for (entity, key) gets version = prev.version + 1, supersedes = prev.fact_id;
the predecessor is marked superseded_by (not deleted) and remains in history.
First version = 1.
```

- **established:** `corecrux-memory/src/fact_store.rs` — `build_fact` assigns the monotonic
  version + `supersedes` link; `store` → `supersede_prior_version` → `mark_superseded`
  flips the predecessor's `superseded_by` marker (journaled for restart survival). Both
  rows are retained in the store.
- **checked / observed:** recall filters on `superseded_by.is_none()` by default
  (`crux-mcp/src/tools/facts.rs`); `include_superseded=true` / `memory_view` expose the
  full chain. Tests: `store_same_key_auto_supersedes_prior_version_in_recall`,
  `auto_supersede_survives_replay`, `consolidate_facts_v1_supersedes_targets_without_deleting_history`.

## I5 — external witness anchoring

```
external_anchor_body commits to (field set includes): receipt_id, tenant_id, anchor_id,
actor_passport, transparency_log, log_url, leaf_hash, log_index, tree_size, root_hash,
and the RFC-6962 inclusion proof
```

An anchored CROWN chain head is bound to an external transparency-log entry: the inclusion
proof must verify leaf → root, and the anchor body commits to the proof, so neither can be
swapped independently.

- **established:** `corecrux-receipts/src/witness_v1.rs` (`build_external_anchor_body_v1`).
- **checked:** `verify_rfc6962_inclusion_proof_v1`; tests
  `rfc6962_inclusion_proof_verifies_two_leaf_tree`,
  `external_anchor_body_binds_inclusion_proof`, and the RFC-3161 variant
  `rfc3161_timestamp_body_binds_token_hash_and_imprint`.

## I6 — custody-proof export

An exported context bundle (facts + sessions + signed journal + receipt refs) is
passport-signed; verification is offline and fail-closed — any tampered component or signed
field fails the check.

- **established:** `corecruxctl/src/export.rs` (`run_context_export`).
- **checked:** `run_context_verify` (offline, no network); tests
  `context_export_round_trips_and_is_a_signed_custody_proof`,
  `tampered_component_fails_verification`, `tampered_signed_field_fails_signature`.
  The export → offline-verify → tamper-rejection cycle is a release-blocking CI gate.

---

*The I1–I4 formulas are quoted from current source (the audit's guessed forms for I1 and I3
matched the implementation verbatim; I2/I4 field names confirmed exact). I5–I6 statements are
derived from the named builders/verifiers and their proving tests, not quoted formulas.*
