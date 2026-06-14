# Receipt v1

Receipt v1 is bytes-first: receipt bodies are stored and verified as opaque
canonical bytes. Producers are responsible for body canonicalization; verifiers
must not reserialize a receipt body and then verify the new bytes.

## Body Event

The generic receipt body event uses:

| Field | Value |
|---|---|
| Stream type | `receipt` |
| Event type | `receipt.body.v1` |
| Content type | `application/cbor; profile=cuecrux-receipt-body-v1` |

Typed receipt bodies include at least:

| Field | Type | Notes |
|---|---|---|
| `schema` | string | Current family: `cuecrux.receipt.body.v1`. |
| `kind` | string | Type discriminator such as `memory_use`, `stream_completed`, or `approval_decision`. |
| `receipt_id` | string | Stable receipt id. |
| `tenant_id` | string | Tenant scope. |

Additional fields are kind-specific and must be documented by the module that
builds the kind.

## Audit II Receipt Kinds

Audit II gap closure adds these typed bodies in `corecrux-receipts`:

| Kind | Builder | Purpose |
|---|---|---|
| `model_invocation` | `build_model_invocation_body_v1` | AI-call provenance: binds provider/model metadata, prompt hash, retrieval-set hash, output hash, and request timing. |
| `chain_reanchor` | `build_chain_reanchor_body_v1` | Crypto migration: records old/new chain heads, hash algorithms, receipt window, and linked migration receipts. |
| `redaction` | `build_redaction_receipt_body_v1` | Crypto-shred erasure: records subject scope, CEK commitment, destruction timestamp, and before/after content commitments without storing plaintext. |
| `consolidation` | `build_consolidation_body_v1` | Memory consolidation: records canonical fact, superseded fact ids, source receipts, and deterministic strategy. |
| `coverage_attestation` | `build_coverage_attestation_body_v1` | Reproducible coverage/eval: binds corpus, run id, commit, lane flags, score, floor, gaps hash, and report hash. |
| `external_anchor` | `build_external_anchor_body_v1` | External anchoring: binds a Rekor/Sigstore/private transparency-log UUID, RFC6962 leaf/root/tree metadata, and an inclusion proof. |
| `rfc3161_timestamp` | `build_rfc3161_timestamp_body_v1` | Trusted timestamping: binds TSA metadata, RFC3161 TimeStampToken DER bytes, token hash, message-imprint algorithm, and message-imprint hash. |

Each kind uses the same `cuecrux.receipt.body.v1` schema family and the same
detached `ReceiptSigV1` signature envelope. Kind-specific assertions are cheap
post-verification checks; they do not replace generic signature verification.

Offline witness verification:

| CLI | Check |
|---|---|
| `corecruxctl receipts verify-external-anchor --body <body.cbor>` | Recomputes RFC6962 inclusion path against the stored leaf hash, log index, tree size, and root hash. |
| `corecruxctl receipts verify-rfc3161-timestamp --body <body.cbor> [--expected-imprint-hash <sha256>]` | Recomputes the stored timestamp-token SHA-256 and optionally checks the expected message imprint hash. |
| `corecruxctl receipts verify-rfc3161-timestamp --body <body.cbor> --tsa-root-cert <root.pem> [--expected-policy-oid <oid>] [--expected-nonce-hex <hex>]` | Enables strict RFC3161 validation: parses the TimeStampToken CMS, checks TSTInfo content type, signed attributes, message imprint, policy, nonce, CMS signature, TSA time-stamping EKU, signer validity at `genTime`, and a certificate chain to the supplied TSA trust anchor. |
| `corecruxctl receipts witness-smoke [--witness-enabled --witness-provider rekor --rekor-url <url>] [--tsa-enabled --tsa-url <url> --tsa-root-cert <root.pem>]` | Local-only preflight for default-off live witness/TSA rollout. It does not submit to Rekor or a TSA; it checks required settings, readable Rekor public key paths when provided, and DER/PEM TSA trust roots. |
| `corecruxctl receipts verify-chain-reanchor --body <body.cbor>` | Checks a `chain_reanchor` body has the expected kind, non-empty old/new chain heads, distinct heads, supported algorithm labels, non-zero receipt count, and non-empty linked receipt IDs. |

Migration attestation:

| CLI | Output |
|---|---|
| `corecruxctl receipts chain-reanchor-attest ...` | Writes a structurally verified `chain_reanchor` body and, when `--out-sig` plus `--signing-key-b64` are provided, a detached `receipt.sig.v1`. |

Witness attestation:

| CLI | Output |
|---|---|
| `corecruxctl receipts external-anchor-attest ...` | Writes an `external_anchor` body from transparency-log inclusion proof fields after deterministic RFC6962 verification. |
| `corecruxctl receipts rfc3161-timestamp-attest ...` | Writes an `rfc3161_timestamp` body from a TSA token file after token-hash and message-imprint binding checks. |

Daemon live witness submission is controlled by default-off env knobs:
`CORECRUXD_WITNESS_ENABLED`, `CORECRUXD_WITNESS_PROVIDER`,
`CORECRUXD_WITNESS_TIMEOUT_MS`, `CORECRUXD_REKOR_URL`,
`CORECRUXD_REKOR_PUBLIC_KEY_PATH`, `CORECRUXD_TSA_ENABLED`,
`CORECRUXD_TSA_URL`, `CORECRUXD_TSA_ROOT_CERT_PATH`, and
`CORECRUXD_TSA_POLICY_OID`.
The daemon exposes the same local-only preflight at `GET /v1/witness/smoke`.

Staged crypto-shred support:

| Artifact | Schema / method | Notes |
|---|---|---|
| Crypto-shred envelope | `cuecrux.crypto_shred.envelope.v1` / `xchacha20poly1305-subject-cek-v1` | Non-destructive staging artifact. The envelope stores ciphertext, nonce, AAD hash, plaintext/ciphertext hashes, and a CEK commitment. It never stores CEK bytes. |
| Redaction receipt | `kind = "redaction"` | Hash-only receipt body that records subject scope, `subject_cek_id`, `subject_cek_commitment`, optional `cek_destroyed_at`, and linked forget/redaction receipts. |

`corecruxctl receipts redaction-attest` can build a redaction receipt body.
When called with `--crypto-shred-staged`, it can also seal a local plaintext
fixture into a crypto-shred envelope so tests can prove retained ciphertext is
unreadable without the per-subject CEK. Production CEK destruction is not part
of this command and remains a separately gated operation.

## Signature Event

The detached signature event uses:

| Field | Value |
|---|---|
| Stream type | `receipt` |
| Event type | `receipt.sig.v1` |
| Content type | `application/cbor; profile=cuecrux-receipt-sig-v1` |

`ReceiptSigV1` fields:

| Field | Type | Notes |
|---|---|---|
| `schema` | string | `cuecrux.receipt.sig.v1`. |
| `receipt_id` | string | Must match the body receipt id. |
| `alg` | string | Currently `ed25519`. |
| `key_id` | string | Keyring lookup id. |
| `signed_at` | string | Stable verification timestamp. |
| `signature` | bytes | 64-byte Ed25519 signature over the body bytes. |
| `signed_payload_hash` | bytes | 32-byte BLAKE3 hash of the body bytes. |

## Verification

A conforming verifier must:

1. Hash the stored body bytes and compare to the event header payload hash.
2. Parse body bytes as CBOR only for validation and trace extraction.
3. Parse signature bytes as `ReceiptSigV1`.
4. Reject unsupported signature algorithms.
5. Verify `receipt_id` and `signed_payload_hash` match the body.
6. Resolve `key_id` in the supplied keyring.
7. Verify Ed25519 over the original body bytes.

Trace checks are derived metadata. The stored body bytes and detached signature
remain canonical truth.
