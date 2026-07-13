# Audit Bundle v1

`audit-bundle-v1` is the offline BYO audit-trail bundle family produced by
`corecruxctl audit-export` and verified by `corecruxctl audit-verify`. New
bundles use `bundle_format_version: 3`; the verifier retains v1 and v2 support.

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

`manifest.json` is signed Ed25519 over canonical JSON bytes. For v3 the signing
input is `cuecrux.audit_bundle.v3\0` followed by the manifest object with
`signature_b64` set to the empty string, serialized without extra whitespace
and with object keys sorted recursively. Field declaration order is not
load-bearing.

The signed manifest fields are:

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
13. `key_class`
14. `signature_b64`

`bundle_format_version` is `3` for new bundles. `key_class` is one of
`persistent`, `env`, or `ephemeral`: `persistent` means the issuer key was
generated once and stored owner-only in the daemon data directory; `env` means
the operator supplied `CORECRUXD_AUDIT_EXPORT_SIGNING_KEY_B64`; and `ephemeral`
is the fallback only when no data directory is available. The embedded
`signer_public_key_b64` remains the key used for offline cryptographic
verification; `key_class` records signed provenance rather than replacing that
check.

Compatibility is fail-closed and version-specific: v1 uses declaration-order
compact JSON without a domain tag; v2 uses recursively key-sorted compact JSON
prefixed by `cuecrux.audit_bundle.v2\0`; and v3 uses the equivalent v3 domain
and requires `key_class`. Verifiers reject any other version.

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
2. Reject unsupported `bundle_format_version`, and reject v3 without a valid
   `key_class`.
3. Recompute SHA-256 over the raw `events.jsonl` bytes.
4. Recompute SHA-256 over the raw `receipts.cbor` bytes.
5. Decode `signer_public_key_b64` as a 32-byte Ed25519 public key.
6. Decode `signature_b64` as a 64-byte Ed25519 signature.
7. Verify the signature over the canonical manifest signing bytes.

`ok=true` only when all checks pass.

## Conformance Vectors

Text-friendly vector directories live under
`crates/corecrux-receipts/vectors/audit-bundle-v1/`. The v1, v2, and v3 valid
vectors preserve compatibility across all supported signing inputs. Each vector contains the
three bundle members plus `expected.json`, and a packed `audit-bundle.tar.zst`
holding the same three members in the production archive layout.

`tools/gen_audit_bundle_vectors.py` emits both forms (the unpacked members and
the `.tar.zst`); the byte-canonical archive is also reproducible via the Rust
example `cargo run -p corecrux-receipts --example
gen_audit_bundle_archive_vectors`. The independent verifier
`tools/verify_audit_bundle_v1.py` accepts either an unpacked vector directory
or an `audit-bundle.tar.zst` and compares the verdict against `expected.json`.

The generator and verifier need the `cryptography` (Ed25519) and `zstandard`
(zstd) Python modules; the verifier and generator also accept the `zstd` CLI as
a fallback when the module is unavailable. CI exercises every vector in both
forms in `.github/workflows/audit-vectors.yml`.
