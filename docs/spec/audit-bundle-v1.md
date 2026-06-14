# Audit Bundle v1

`audit-bundle-v1` is the offline BYO audit-trail bundle format produced by
`corecruxctl audit-export` and verified by `corecruxctl audit-verify`.

## Container

The production bundle is `tar.zst` with these members:

| Path | Encoding | Required |
|---|---|---|
| `manifest.json` | UTF-8 JSON | yes |
| `events.jsonl` | UTF-8 JSON Lines | yes |
| `receipts.cbor` | CBOR array | yes |

Unknown tar members are ignored for forward compatibility. Verification is
offline: no daemon, network, or key fetch is allowed.

## Manifest

`manifest.json` is signed Ed25519 over canonical JSON bytes. The signing input
is the manifest object with `signature_b64` set to the empty string, serialized
without extra whitespace and with fields in this order:

1. `bundle_format_version`
2. `bundle_id`
3. `since`
4. `until`
5. `generated_at`
6. `scope`
7. `fact_count`
8. `receipt_count`
9. `events_jsonl_sha256`
10. `receipts_cbor_sha256`
11. `signer_public_key_b64`
12. `signer_key_id`
13. `signature_b64`

`bundle_format_version` is `1`. Verifiers must reject any other version.

`scope` records the export slice. Its current fields are:

| Field | Type | Notes |
|---|---|---|
| `entity_prefix` | string, optional | Included only when the export was prefix-scoped. |
| `include_reserved` | boolean | Whether reserved-prefix entries were included. |
| `caller` | string, optional | Passport/operator label supplied by the caller. |

## Data Members

`events.jsonl` contains one exported fact event per line. Each line is an object
matching `AuditEventV1` in `corecrux-receipts`:

| Field | Type |
|---|---|
| `fact_id` | string |
| `entity` | string |
| `key` | string |
| `value` | string |
| `source_receipt` | string, optional |
| `confidence` | number |
| `stored_at` | RFC3339 string |
| `tokens` | integer |
| `deleted` | boolean |
| `version` | integer |
| `supersedes` | string, optional |

`receipts.cbor` is a CBOR array of `AuditReceiptRefV1` objects:

| Field | Type |
|---|---|
| `fact_id` | string |
| `receipt_id` | string |

## Verification

A conforming verifier must:

1. Load exactly the required members.
2. Reject unsupported `bundle_format_version`.
3. Recompute SHA-256 over the raw `events.jsonl` bytes.
4. Recompute SHA-256 over the raw `receipts.cbor` bytes.
5. Decode `signer_public_key_b64` as a 32-byte Ed25519 public key.
6. Decode `signature_b64` as a 64-byte Ed25519 signature.
7. Verify the signature over the canonical manifest signing bytes.

`ok=true` only when all checks pass.

## Conformance Vectors

Text-friendly vector directories live under
`crates/corecrux-receipts/vectors/audit-bundle-v1/`. Each vector contains the
three bundle members plus `expected.json`. The generator is
`tools/gen_audit_bundle_vectors.py`; the independent verifier is
`tools/verify_audit_bundle_v1.py`.
