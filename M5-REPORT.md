# M5 Report — COSE_Sign1 export for CROWN receipts

## Outcome

Crux now exports compatible CROWN retrieval receipts as tagged COSE_Sign1
signed statements conforming to the published
[CROWN SCITT Application Profile v0.2](https://github.com/CueCrux/ResearchCrux/blob/main/protocol/scitt-compat/crown-scitt-profile.md)
and
[crown-receipt.cddl](https://github.com/CueCrux/ResearchCrux/blob/main/protocol/scitt-compat/crown-receipt.cddl).
This is an interoperability export representation; it does not replace Crux's
stored bytes-first receipt body and detached signature.

The emitted statement is CBOR tag 18 around a four-element COSE_Sign1 array. Its
protected header contains exactly labels `1`, `3`, `4`, and `15`; its
unprotected header is empty; and its Ed25519 signature covers the RFC 9052
`Sig_structure` with an empty external AAD. Verification uses
Ed25519 `verify_strict` and fails closed on envelope, header, payload, signature,
or CWT subject-binding errors.

The CLI surface is:

- `corecruxctl receipts export-cose <receipt.json> [--out <file.cose>]`
  with exactly one of `--key-b64`, `--key-file`, or `--gen-dev-key`, plus
  `--kid`; `--iss` defaults to `https://crux.local`.
- `corecruxctl receipts verify-cose <file.cose> [--pubkey-b64 <BASE64>]`.
  Omitting the public key deliberately selects only the documented fixed
  development key.

The deterministic development key is public ResearchCrux test material. It is
for fixtures and local interoperability checks only and must never sign a
production receipt.

## Profile and CDDL mapping

Deserialization accepts the daemon/ResearchCrux JSON spellings shown below and
serialization emits only the normative kebab-case CBOR labels.

| CDDL field | Accepted JSON / Rust field | Mapping |
|---|---|---|
| `snap-id` | `snapshotId`, `snapId` / `snap_id` | Required UUID text; also binds protected CWT `sub = urn:crown:receipt:<snap-id>`. |
| `answer-id` | `answerId` / `answer_id` | Required UUID text. |
| `parent-snap-id` | `parentSnapId` / `parent_snap_id` | Required UUID text or explicit null. |
| `generated-at` | `generatedAt` / `generated_at` | Required RFC 3339 text. |
| `mode` | `mode` | Required; restricted to `light`, `verified`, or `audit`. |
| `mode-requested` | `modeRequested` / `mode_requested` | Required text. |
| `query-hash` | `queryHash` / `query_hash` | Required `blake3:` plus 64 hexadecimal characters. |
| `query-text` | `queryText` / `query_text` | Required text, as required by the CDDL. |
| `receipt-hash` | `receiptHash` / `receipt_hash` | Required `blake3:` plus 64 hexadecimal characters. |
| `tenant-id` | `tenantId` / `tenant_id` | Required non-empty text. |
| `signature` | `signature` | Optional text representation. |
| `signing-kid`, `signing-pub`, `signed-at` | `signingKid`, `signingPub`, `signedAt` | Optional text; `signed-at`, when present, is checked as RFC 3339. |
| `llm-model`, `llm-request-id` | `llmModel`, `llmRequestId` | Optional text. |
| `trigger-action-receipt-id` | `triggerActionReceiptId` | Optional UUID text or explicit null. |
| `knowledge-state-cursor` | `knowledgeStateCursor` | Optional map: `shard-id`, `epoch`, `segment-seq`, and `offset`. |

Nested groups map as follows:

| CDDL group | Accepted JSON aliases | Emitted fields |
|---|---|---|
| `fusion` | `w_bm25`/`bm25Weight`, `w_vec`/`vectorWeight`, `rrf_k`/`rrfK` | Required `bm25-weight`, `vector-weight`, `rrf-k`; weights must already be finite and exactly representable as float16, so export never silently changes a hash-bound value. |
| `retrieval` | `topK`, `minDomains`; normative names also accepted | Optional `top-k`, boolean `rerank`, `min-domains`, `budget`. |
| `selection` | `miSESSize`, `citationIds`, `distinctDomains`, `fragilityScore`, `loadBearingCitations` | Required `mi-ses-size` and `citation-ids`; optional `coverage`, `distinct-domains`, `fragility-score`, `load-bearing-citations`, and typed `counterfactual`. |
| `counterfactual` | `rejectReason` in candidate entries | Optional `considered`, `rejected`, and candidates containing `id`, float16 `score`, and `reject-reason`. |
| `timings` | `retrieveMs`, `rerankMs`, `llmMs`, `totalMs` | Required `retrieve-ms`, `rerank-ms`, `llm-ms`, and `total-ms`. |

The protected-header mapping is exact:

| Label | Emitted protected value |
|---|---|
| `1` | `-8` (EdDSA/Ed25519) |
| `3` | `application/vnd.crown.receipt+cbor` |
| `4` | non-empty UTF-8 `kid` bytes |
| `15` | CWT claims map `{1: <absolute iss URI>, 2: "urn:crown:receipt:<snap-id>"}` |

## Deliberately unmapped or limited fields

No values are invented to bridge shape differences:

- Daemon/ResearchCrux `receiptId` is not exported because it is distinct from
  `snapshotId`, the normative source of `snap-id`.
- `evidence` is not embedded because the ResearchCrux CDDL defines it as a
  separate `crown-evidence` record.
- Legacy top-level `citations` and `counterfactual` are not promoted; the CDDL
  locates those concepts under `selection`.
- Legacy `retrieval.rerankK` is not converted to CDDL `rerank`, because the
  former is a count and the latter is a boolean.
- Unknown daemon fields and arbitrary extension keys are ignored rather than
  converted into unreviewed profile claims.
- The CDDL permits the optional `signature` value to be bytes, text, or null;
  the JSON adapter currently maps its text form only.
- A generic stored `cuecrux.receipt.body.v1` is not automatically convertible:
  its common `schema`, `kind`, `receipt_id`, and `tenant_id` fields do not supply
  the profile's required answer, retrieval, selection, and timing claims.

`verify_cose_sign1` verifies the COSE signature, exact profile header and
envelope shape, typed payload constraints, and the CWT subject-to-`snap-id`
binding. It validates the syntax of `receipt-hash`, but it does **not** recompute
the legacy CROWN canonical-JSON `receipt-hash`. That independent check requires
the legacy canonical JSON rules and source representation. The helper also does
not claim SCITT Transparency Service countersignature/inclusion verification or
full application chain/temporal verification.

## Files

- `crates/corecrux-receipts/src/cose_sign1_v1.rs` — typed CDDL adapter,
  COSE_Sign1 encode/decode/strict verify, and conformance tests.
- `crates/corecrux-receipts/src/lib.rs` — public module exports.
- `crates/corecrux-receipts/Cargo.toml` and `Cargo.lock` — direct use of
  already-locked `ciborium`, `ciborium-ll`, `half`, `chrono`, `url`, `uuid`,
  and `ed25519-dalek`; no new package was introduced into the lockfile.
- `crates/corecruxctl/src/main.rs` — clap subcommands and human summary lines.
- `crates/corecruxctl/src/receipts.rs` — JSON/file IO, key resolution, export,
  and offline verification handlers.
- `crates/corecrux-receipts/vectors/cose-sign1-v1/README.md` — fixture
  provenance, reproduction, verification, and development-key warning.
- `crates/corecrux-receipts/vectors/cose-sign1-v1/deterministic-dev/receipt.json`
  — reviewable source receipt.
- `crates/corecrux-receipts/vectors/cose-sign1-v1/deterministic-dev/signed-statement.cose`
  — deterministic Crux signed statement.
- `crates/corecrux-receipts/vectors/cose-sign1-v1/researchcrux-v0.2/signed-statement.cbor`
  — byte-for-byte copy of the ResearchCrux worked example for decoder interop.
- `docs/spec/receipt-v1.md` — profile/CDDL links and CLI usage, explicitly
  describing COSE as an export representation.
- `llms-full.txt` — regenerated because the linked receipt spec changed.
- `M5-REPORT.md` — this report.

Every new Rust source retains the repository CCL header.

## Interoperability fixtures

| Fixture | Size | SHA-256 | Provenance |
|---|---:|---|---|
| `deterministic-dev/receipt.json` | 1,534 bytes | `007ce00828be3964fc4e620c047e905c9eef4f24aaea072038652dd74dece521` | Hand-reviewable JSON source. Its `receiptHash` was recomputed with ResearchCrux's canonical payload/stringification rules. |
| `deterministic-dev/signed-statement.cose` | 1,138 bytes | `429fcfcc9192aaed86f5215f62761b4d8540f6e3c234a3d2a108300fbf2017a4` | Generated by the exact Crux command below with the public ResearchCrux development seed. |
| `researchcrux-v0.2/signed-statement.cbor` | 1,188 bytes | `ad5ca0651c0828fedfda8ac17cf1efe7a7508a2cfaef8f86d4102a87ca461441` | Byte-identical copy of `ResearchCrux/protocol/scitt-compat/cose-example/signed-statement.cbor`; header parsing is cross-checked without requiring its signature under another key. |

The fixed development public key used by `--gen-dev-key` is
`lSeDZswguHg6GlB53SY2jPcrNqPN+Z2TLBKkGUtDUEE=`.

## Exact export and cross-verification commands

From the Crux worktree root, reproduce the committed `.cose`:

```bash
cargo run -p corecruxctl -- receipts export-cose \
  crates/corecrux-receipts/vectors/cose-sign1-v1/deterministic-dev/receipt.json \
  --out crates/corecrux-receipts/vectors/cose-sign1-v1/deterministic-dev/signed-statement.cose \
  --gen-dev-key \
  --iss https://crux.local \
  --kid crux-cose-vector-v1
```

Verify it with Crux:

```bash
cargo run -p corecruxctl -- receipts verify-cose \
  crates/corecrux-receipts/vectors/cose-sign1-v1/deterministic-dev/signed-statement.cose
```

Cross-verify the same bytes with the checked-out ResearchCrux tool:

```bash
cd /home/myles/CueCrux/ResearchCrux/verify
node --import tsx src/cli.ts --cose \
  /home/myles/CueCrux/Crux-tierpkg-m5-wt/crates/corecrux-receipts/vectors/cose-sign1-v1/deterministic-dev/signed-statement.cose \
  --pub "lSeDZswguHg6GlB53SY2jPcrNqPN+Z2TLBKkGUtDUEE="
```

## Test and gate status

Completed targeted checks at report time:

- Eight targeted COSE library tests pass: encode/strict-verify roundtrip and
  wrong-key rejection, payload-byte tamper rejection, exact protected labels
  and claims, required kebab-case CDDL payload keys and float16 widths,
  rejection of lossy input and a validly signed non-float16 payload,
  byte-for-byte deterministic fixture reproduction, and parsing the committed
  ResearchCrux example's protected header.
- The CLI `export-cose` to `verify-cose` subprocess roundtrip passed using a
  JSON file and `--gen-dev-key`; clap validates that exactly one signing-key
  source is selected and covers the verify command shape. The handler supports
  base64, raw/base64 key files, and the fixed development key.
- Targeted `corecrux-receipts` clippy completed with warnings denied after the
  COSE changes.
- Fixture sizes and SHA-256 values above were recomputed from the committed
  bytes; the copied ResearchCrux example matches its source byte-for-byte.
- ResearchCrux's independent verifier passes the deterministic Crux fixture
  (`cose:valid`) and reads the expected kid, content type, issuer, subject,
  receipt hash, snap id, and tenant id.

The attempted full `corecruxctl` test run reported **754 passed and 44 failed**.
All 44 failures were sandbox-only loopback socket bind failures with
`Operation not permitted`; the COSE tests and CLI roundtrip were not among the
failures. The user brief explicitly notes that this sandbox denies loopback
binds, so the orchestrator must rerun this gate outside the sandbox.

Final gate results:

- `cargo fmt --all -- --check` — passed.
- `cargo clippy --workspace -- -D warnings` — passed.
- `cargo test -p corecrux-receipts -p corecruxctl` —
  `corecrux-receipts`: 225 passed; `corecruxctl`: 754 passed and the 44
  bind-denied failures described above. The focused COSE CLI subprocess test
  separately passed 1/1.
- `cargo doc --no-deps -p corecrux-receipts -p corecruxctl` — passed.
- CCL header checks for both new Rust files — passed.
- `bash scripts/build-llms-full.sh --check` — passed after regeneration.
- `bash scripts/check-agent-docs.sh` — passed.
- ResearchCrux independent COSE verification — passed with 0 issues.

The remaining orchestrator rerun is:

```text
cargo test -p corecrux-receipts -p corecruxctl
```

Run it outside the loopback-restricted sandbox. Treat only the 44 named
bind-denied tests as the sandbox exception and investigate any different
failure.
