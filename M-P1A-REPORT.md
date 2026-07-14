# M-P1A witness-to-daemon delivery report

Date: 2026-07-13

Status: implemented. The cloud-witness flag remains default OFF, and daemon
acceptance remains behind the existing default-OFF
`CORECRUXD_STREAM_RECEIPTS=1` gate.

## A1 — daemon routing, verification, and persistence

`post_mediation_receipt` now recognizes a nested cloud-witness envelope before
the existing top-level `kind` dispatch. The discriminator is an object with a
`witness` object and a `record` object whose `schema` is
`cuecrux.mediation.witness.v1`. With stream receipts disabled, the envelope
still reaches the legacy parser and is rejected as before.

`handle_witness_receipt` uses the same `require_session_write_ctx` posture as
stream receipt drafts. It performs one strict Ed25519 verification against the
envelope's raw 32-byte public key, validates standard padded Base64 and exact
key/signature lengths, and checks that `kid` equals `wit_` plus the first 16
lowercase hexadecimal characters of SHA-256 over the Ed25519 RFC 8410 SPKI DER
public key. Invalid signatures return a 400 problem detail with
`witness_signature_invalid`; malformed records or key/KID mismatches return
`witness_envelope_invalid`. Neither path persists. An internal canonicalization
or key-encoding error returns 503 `witness_verification_unavailable`, also
without persistence; the non-2xx response causes the shim to use its durable
JSONL fallback instead of treating an unpersisted record as delivered.

After verification, a deny-unknown-fields wire type constrains the retained
record to the metadata-only witness-v1 fields. Provider/path, digest form,
bounded model/tool/session/response metadata, and numeric token-only usage are
validated. This prevents a signed extension carrying prompt or response
content from entering the observation payload.

Valid `cloud_request_witnessed` and `cloud_response_witnessed` records are
persisted through `append_one`, the signed-observation path used by stream
receipts. That produces the chained observation JSONL source of truth, a daemon
CROWN Ed25519 signature, and the existing best-effort dataplane observation
stream. The exact signed metadata-only `record`, its witness proof, derived
`kid`, and `witness_verified: true` are retained. The response is 201 and
mirrors the stream receipt response with `receipt_id`, `kind`, `body_hash`,
`signature_hex`, `observation_id`, `signed_by`, and `witness_kid`.

Request and response records are grouped under
`mediation::witness::<verified-kid>`, because witness-v1 responses do not carry
the request's self-asserted `session_hint`. Incident reconstruction consumes
the resulting source-of-truth records through `read_all_observations`; the
entity projection receives the existing best-effort dataplane write when that
dataplane is configured.

## Server-side canonicalization

The signature input exactly matches
`crux_claude_hooks::llm_shim::witness::canonical_json_bytes`:

1. Recursively sort every JSON object by Rust `String` ordering of its keys.
2. Preserve array order.
3. Leave strings, numbers, booleans, and null unchanged.
4. Compact-serialize the resulting `serde_json::Value` with
   `serde_json::to_vec`.
5. Verify the Ed25519 signature directly over those bytes with
   `VerifyingKey::verify_strict`.

This is the witness-v1 sorted-key encoding; it is not claimed to be RFC 8785
JCS.

## A2 — delivery test and assurance documentation

`signed_witness_pair_is_delivered_to_daemon_with_auth_without_spool_fallback`
constructs `CloudWitnessConfig` with `daemon_receipts=true`, drives the real
cloud-witness request/response flow, and uses a two-request daemon stub. It
asserts the mediation route, Bearer authentication, nested schema, linked
request/response kinds, persisted-key signature verification, and no local
spool fallback after two successful daemon responses. The existing helper
continues to use `daemon_receipts=false`, so default behavior is unchanged.

Daemon-side tests exercise the actual handler and signed store: a valid pair
returns 201 and appears through the same aggregate observation read helper used
by incidents; an altered record, a signature made by a key different from the
claimed public key, and a self-consistent re-sign whose KID is replaced with an
existing key's KID are all rejected with no records appended.

The cloud-model-call row in `docs/assurance-coverage-matrix.md` and the delivery
section in `docs/llm-shim.md` now describe verified daemon delivery, signed
observation/incident visibility, configured-only dataplane projection, and
spool fallback. They retain the same-UID custody, unauthenticated session hint,
no-replay, and no independent key-enrolment/pinning limitations.

## Tests

New daemon tests, all passing in the real worktree as part of the 41-test
`http::observations::tests::` slice:

- `canonical_witness_json_matches_shim_signing_bytes`
- `nested_witness_shape_is_recognized_without_top_level_kind`
- `valid_witness_pair_routes_verifies_and_persists_for_incidents`
- `altered_witness_record_is_rejected_without_persisting`
- `wrong_key_witness_signature_is_rejected_without_persisting`
- `wrong_key_resign_for_existing_kid_is_rejected_without_persisting`
- `signed_content_bearing_extension_is_rejected_without_persisting`
- `witness_envelope_is_inert_when_stream_receipts_are_disabled`
- `witness_envelope_requires_the_existing_session_write_auth`

Regression tests passing:

- `post_mediation_receipt_happy_path_records_attributed_receipt`
- `mediation_route_lifts_drafts_when_flag_on_and_rejects_when_off`
- `usage_route_lifts_when_flag_on_and_rejects_when_off`

New hook delivery test:

- `signed_witness_pair_is_delivered_to_daemon_with_auth_without_spool_fallback`
  compiles, but cannot execute in this sandbox: its first loopback stub bind is
  rejected with `PermissionDenied` (`Operation not permitted`). It is
  structured as a live listener test for the orchestrator to rerun outside the
  bind-restricted sandbox.

Quality-gate results:

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --locked --offline -- -D warnings`: pass.
- `cargo doc --no-deps -p corecruxd -p crux-claude-hooks --locked --offline`:
  pass.
- `bash scripts/build-llms-full.sh --check`: pass.
- CCL header check for touched Rust files: pass.
- `cargo test -p corecruxd -p crux-claude-hooks --locked --offline`:
  `corecruxd` completed with 1,878 passed, 20 failed, and 2 ignored. Every
  failure was an existing test's loopback bind rejected with `PermissionDenied`;
  Cargo stopped after the failed package before running `crux-claude-hooks`.
- `cargo test -p crux-claude-hooks --locked --offline`: 151 passed and one
  existing loopback-bind test failed with `PermissionDenied`; Cargo stopped
  before integration tests.
- `cargo test -p corecruxd --locked --offline http::observations::tests::`: 41
  passed, 0 failed.
- `cargo test -p corecruxd --locked --offline route_lifts`: 2 passed, 0 failed.

## Deferred / unchanged limits

- No witness key registry, enrolment, or daemon-side expected-key pinning was
  added. Verification proves integrity under the envelope's embedded key and
  KID derivation. A wholesale, self-consistent replacement of key, KID, record,
  and signature by a caller already holding daemon write authorization still
  requires separate identity pinning to detect.
- No nonce, sequence, freshness window, deduplication, or replay protection was
  added.
- The witness key remains readable to a same-UID compromise, and the request
  session hint remains caller-supplied rather than authenticated.
- Observation JSONL is the authoritative incident input. Entity-timeline
  projection remains best effort and depends on a configured dataplane.
