// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! The reference pack for `pack.conformance.v1` — a real, committed,
//! validly-signed manifest that carries a conformance declaration.
//!
//! A schema nobody has instantiated is a design document. This pack is the
//! worked example an implementer copies, and it is also the fixture the gate
//! tests here and on the daemon side load: it proves the block survives a
//! round trip through disk, parses, and is inside the publisher's signature.
//!
//! Like `studio-board-example`, it is generated and signed from a fixed
//! example seed so the committed artefact is reproducible. Regenerate with:
//!
//! ```text
//! cargo test -p crux-integrations --test conformance_reference_pack -- --ignored regen_conformance_reference_pack
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use crux_integrations::conformance::{
    BehaviouralEnvelope, CompatibilityAssertions, DecayEnvelope, DeclaredCase, ExpectedFactMutation, ExpectedMutations,
    ExpectedReceiptMutation, FactMutationOp, InvariantKind, InvariantTest, MigrationAssertion, MigrationKind,
    PackConformance, ReceiptMutationKind, ReplayCorpus, UndoEnvelope, PACK_CONFORMANCE_SCHEMA_V1,
};
use crux_integrations::{
    DataAccess, EntryKind, ExternalToolDefinition, IntegrationEntry, IntegrationError, IntegrationManifest,
    ManifestHashes, NetworkAccess, SafetyPolicy, SandboxKind, ValidationPolicy, INTEGRATION_SCHEMA_V1,
};
use sha2::{Digest, Sha256};

const PACK_ID: &str = "ext.conformance.reference";
const PACK_VERSION: &str = "0.2.0";
const PACK_DIR: &str = "integrations/community/ext.conformance.reference/0.2.0";
const CORPUS_ID: &str = "conformance-reference-v1";
const CORPUS_FILE: &str = "replay-corpus.json";
const TOOLS_FILE: &str = "tools/ext.conformance.reference.json";

/// Endpoint host is in the RFC 2606 `.invalid` TLD: a reference artefact must
/// name a destination that can never resolve, so copying it cannot point a
/// reader's daemon at anything real.
const ENDPOINT: &str = "https://reference.pack.invalid/tools";
const ENDPOINT_HOST: &str = "reference.pack.invalid";

/// Fixed example signing seed — a documented non-production identity, exactly
/// as `studio-board-example` uses. It exists so the committed pack is
/// reproducible and validly self-signed for the CI gate; a real publisher
/// signs with their own key.
const EXAMPLE_SEED: [u8; 32] = *b"cuecrux-pack-conformance-ref-v1!";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn pack_dir() -> PathBuf {
    repo_root().join(PACK_DIR)
}

fn read_reference_manifest() -> IntegrationManifest {
    let path = pack_dir().join("manifest.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

/// Trust the pack's own inline signing key, the same way the community-pack
/// CI gate does: at submission time the publisher's key is in no operator
/// keyring, so the check that matters is "validly self-signed over these
/// exact bytes".
fn policy_trusting_inline_key(manifest: &IntegrationManifest) -> ValidationPolicy {
    let mut policy = ValidationPolicy {
        allow_unsigned_first_party: false,
        allow_unsigned: false,
        ..ValidationPolicy::default()
    };
    if let Some(signature) = &manifest.signature {
        if let Some(public_key_hex) = &signature.public_key_hex {
            policy
                .trusted_public_keys
                .insert(signature.passport_fpr.clone(), public_key_hex.clone());
        }
    }
    policy
}

#[test]
fn reference_pack_ships_a_conformance_manifest_the_daemon_parses() {
    let manifest = read_reference_manifest();
    assert_eq!(manifest.id, PACK_ID);
    assert_eq!(manifest.version, PACK_VERSION);
    assert_eq!(manifest.entry.kind, EntryKind::ExternalTool);

    let declaration = manifest
        .conformance
        .as_ref()
        .expect("the reference pack must ship a conformance declaration");
    assert_eq!(declaration.schema, PACK_CONFORMANCE_SCHEMA_V1);
    assert_eq!(declaration.replay_corpus.corpus_id, CORPUS_ID);
    assert_eq!(declaration.replay_corpus.cases.len(), 3);
    assert!(
        !declaration.invariants.is_empty(),
        "a declaration with no invariants proves nothing at replay time"
    );
    // The block covers every part of the pack's surface, which is what makes
    // a later replay a statement about the whole pack rather than a sample.
    let mut claimed = declaration.claimed_capabilities.clone();
    let mut declared = manifest.capabilities.clone();
    claimed.sort();
    declared.sort();
    assert_eq!(claimed, declared);
}

#[test]
fn reference_pack_conformance_manifest_signature_checks() {
    let manifest = read_reference_manifest();
    assert!(
        manifest.signature.is_some() && manifest.hashes.manifest.is_some(),
        "the reference pack must be signed and carry its manifest hash"
    );
    manifest
        .validate(&policy_trusting_inline_key(&manifest))
        .expect("the reference pack must parse and signature-check");
}

#[test]
fn reference_pack_conformance_block_is_covered_by_the_signature() {
    // The load-bearing claim of M0. If the declaration were beside the
    // signature rather than inside it, a pack could ship a modest envelope,
    // earn a clean conformance receipt, and then have its bounds widened by
    // anyone who could edit the file — and every downstream verifier would
    // still say the manifest was valid.
    let mut manifest = read_reference_manifest();
    let policy = policy_trusting_inline_key(&manifest);
    manifest.validate(&policy).expect("baseline must validate");

    let Some(declaration) = manifest.conformance.as_mut() else {
        panic!("the reference pack must ship a conformance declaration");
    };
    // A legal edit — the widened envelope still satisfies every structural
    // rule, so only the signature can catch it.
    declaration.envelope.max_tokens_per_call += 1;
    declaration.envelope.max_tokens_per_run += 1;

    let error = manifest
        .validate(&policy)
        .expect_err("a widened envelope must be rejected");
    assert!(
        matches!(
            error,
            IntegrationError::SignatureInvalid | IntegrationError::ManifestHashMismatch { .. }
        ),
        "expected a signature or hash rejection, got {error}"
    );
}

#[test]
fn reference_pack_replay_corpus_is_content_addressed() {
    let manifest = read_reference_manifest();
    let declaration = manifest.conformance.as_ref().expect("declaration");

    let corpus_path = pack_dir().join(&declaration.replay_corpus.path);
    let bytes = fs::read(&corpus_path).unwrap_or_else(|err| panic!("read {}: {err}", corpus_path.display()));
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        declaration.replay_corpus.sha256,
        "the committed corpus does not hash to the digest the signed manifest declares — \
         'replayed against corpus X' has to name bytes, not a filename"
    );

    // The corpus file and the manifest must agree on the cases, or the
    // declaration and the artefact an implementer reads describe different
    // replays.
    let corpus: serde_json::Value = serde_json::from_slice(&bytes).expect("parse corpus");
    assert_eq!(corpus["corpus_id"], CORPUS_ID);
    let declared: serde_json::Value = serde_json::to_value(&declaration.replay_corpus.cases).expect("encode cases");
    assert_eq!(corpus["cases"], declared);
}

#[test]
#[ignore = "writer: run with -- --ignored regen_conformance_reference_pack to regenerate the reference pack"]
fn regen_conformance_reference_pack() {
    let dir = pack_dir();
    fs::create_dir_all(dir.join("tools")).expect("create reference pack dir");

    let tools = reference_tools();
    let tools_document = serde_json::json!({
        "schema": INTEGRATION_SCHEMA_V1,
        "id": PACK_ID,
        "version": PACK_VERSION,
        "external_tool_endpoint": ENDPOINT,
        "tools": tools,
    });
    write_pretty(&dir.join(TOOLS_FILE), &tools_document);

    let cases = reference_cases();
    let corpus_document = serde_json::json!({
        "corpus_id": CORPUS_ID,
        "description": "Three declared operations replayed against a local shadow corpus: two reads that must be deterministic, and one write that must stay inside the declared namespace and be reversible.",
        "cases": cases,
    });
    let corpus_bytes = write_pretty(&dir.join(CORPUS_FILE), &corpus_document);
    let corpus_sha256 = hex::encode(Sha256::digest(&corpus_bytes));

    let key = ed25519_dalek::SigningKey::from_bytes(&EXAMPLE_SEED);
    let publisher_fpr = crux_integrations::fingerprint_from_public_key(&key.verifying_key());
    let mut manifest = IntegrationManifest {
        schema: INTEGRATION_SCHEMA_V1.to_string(),
        id: PACK_ID.to_string(),
        name: "Conformance Reference Pack".to_string(),
        version: PACK_VERSION.to_string(),
        publisher_passport_fpr: publisher_fpr.clone(),
        summary: "Worked example of a pack.conformance.v1 declaration: claimed capabilities, expected mutations, a content-addressed replay corpus, invariants, a behavioural envelope, and migration assertions.".to_string(),
        entry: IntegrationEntry {
            kind: EntryKind::ExternalTool,
            path: TOOLS_FILE.to_string(),
        },
        capabilities: vec!["facts:read".to_string(), "facts:write".to_string()],
        network: NetworkAccess {
            allowed_hosts: vec![ENDPOINT_HOST.to_string()],
            requires_user_token: false,
        },
        data_access: DataAccess {
            tenant_scopes: vec!["selected".to_string()],
            content_preview: false,
            private_facts: false,
        },
        safety: SafetyPolicy {
            sandbox: SandboxKind::None,
            max_runtime_ms: 2_000,
            max_output_bytes: 16_384,
        },
        hashes: ManifestHashes::default(),
        signature: None,
        external_tool_endpoint: Some(ENDPOINT.to_string()),
        tools,
        wasm_module_path: None,
        wasm_module_url: None,
        wasm_module_sha256: None,
        conformance: Some(reference_declaration(corpus_sha256)),
    };
    // Signs over the payload including the conformance block, then fills
    // hashes.manifest from that same payload.
    crux_integrations::sign_manifest(&mut manifest, &key, publisher_fpr).expect("sign reference manifest");
    manifest
        .validate(&policy_trusting_inline_key(&manifest))
        .expect("the regenerated pack must validate before it is written");
    write_pretty(&dir.join("manifest.json"), &manifest);

    fs::write(dir.join("README.md"), README).expect("write README.md");
}

fn write_pretty<T: serde::Serialize>(path: &Path, value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("encode json");
    bytes.push(b'\n');
    fs::write(path, &bytes).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
    bytes
}

fn reference_tools() -> Vec<ExternalToolDefinition> {
    vec![
        ExternalToolDefinition {
            name: "ext.conformance.reference.recall".to_string(),
            description: "Return notes the pack previously stored. Read-only.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": { "topic": { "type": "string" } }
            }),
            consequence_metadata: None,
            auth_shared_secret_id: None,
        },
        ExternalToolDefinition {
            name: "ext.conformance.reference.remember".to_string(),
            description: "Store one note under the pack's declared entity namespace.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["note"],
                "properties": { "note": { "type": "string" } }
            }),
            consequence_metadata: None,
            auth_shared_secret_id: None,
        },
    ]
}

fn reference_cases() -> Vec<DeclaredCase> {
    vec![
        DeclaredCase {
            case_id: "recall-default".to_string(),
            tool_name: "ext.conformance.reference.recall".to_string(),
            args: serde_json::json!({}),
        },
        DeclaredCase {
            case_id: "recall-topic".to_string(),
            tool_name: "ext.conformance.reference.recall".to_string(),
            args: serde_json::json!({ "topic": "conformance" }),
        },
        DeclaredCase {
            case_id: "remember-note".to_string(),
            tool_name: "ext.conformance.reference.remember".to_string(),
            args: serde_json::json!({ "note": "A pack proves what it does." }),
        },
    ]
}

fn reference_declaration(corpus_sha256: String) -> PackConformance {
    PackConformance {
        schema: PACK_CONFORMANCE_SCHEMA_V1.to_string(),
        claimed_capabilities: vec!["facts:read".to_string(), "facts:write".to_string()],
        expected_mutations: ExpectedMutations {
            facts: vec![ExpectedFactMutation {
                entity_prefix: "ext.conformance.reference::notes::".to_string(),
                keys: vec!["content".to_string()],
                operation: FactMutationOp::Write,
                private: false,
                max_per_call: 1,
            }],
            receipts: vec![
                ExpectedReceiptMutation {
                    receipt_kind: ReceiptMutationKind::Dispatch,
                    max_per_call: 1,
                },
                ExpectedReceiptMutation {
                    receipt_kind: ReceiptMutationKind::FactWrite,
                    max_per_call: 1,
                },
            ],
        },
        replay_corpus: ReplayCorpus {
            corpus_id: CORPUS_ID.to_string(),
            path: CORPUS_FILE.to_string(),
            sha256: corpus_sha256,
            cases: reference_cases(),
        },
        invariants: vec![
            InvariantTest {
                id: "writes-stay-in-namespace".to_string(),
                description: "Every fact write lands under ext.conformance.reference::notes::.".to_string(),
                kind: InvariantKind::NoUndeclaredFactWrites,
                applies_to_cases: Vec::new(),
            },
            InvariantTest {
                id: "no-private-reads".to_string(),
                description: "The pack never reads a private fact; its data_access does not grant it.".to_string(),
                kind: InvariantKind::NoPrivateFactAccess,
                applies_to_cases: Vec::new(),
            },
            InvariantTest {
                id: "egress-pinned".to_string(),
                description: "The pack reaches no host outside network.allowed_hosts.".to_string(),
                kind: InvariantKind::NoEgressOutsideAllowlist,
                applies_to_cases: Vec::new(),
            },
            InvariantTest {
                id: "recall-is-deterministic".to_string(),
                description: "Replaying either read twice yields the same observed behaviour.".to_string(),
                kind: InvariantKind::DeterministicReplay,
                applies_to_cases: vec!["recall-default".to_string(), "recall-topic".to_string()],
            },
            InvariantTest {
                id: "writes-are-reversible".to_string(),
                description: "The stored note can be fully reversed by one supersession.".to_string(),
                kind: InvariantKind::ReversibleWrites,
                applies_to_cases: vec!["remember-note".to_string()],
            },
        ],
        envelope: BehaviouralEnvelope {
            max_tokens_per_call: 512,
            max_tokens_per_run: 2_048,
            max_latency_ms_per_call: 2_000,
            max_latency_ms_per_run: 8_000,
            max_response_bytes_per_call: 16_384,
            max_fact_writes_per_call: 1,
            decay: DecayEnvelope {
                min_half_life_seconds: 604_800,
                max_refreshes_per_call: 0,
            },
            max_contradiction_rate_ppm: 0,
            undo: UndoEnvelope {
                max_operations_per_call: 1,
                max_latency_ms: 500,
            },
        },
        compatibility: CompatibilityAssertions {
            min_daemon_version: "0.5.0".to_string(),
            manifest_schema: INTEGRATION_SCHEMA_V1.to_string(),
            supersedes: vec!["0.1.0".to_string()],
            migrations: vec![MigrationAssertion {
                from_version: "0.1.0".to_string(),
                to_version: PACK_VERSION.to_string(),
                kind: MigrationKind::SupersedeFacts,
                reversible: true,
                description: "Notes written by 0.1.0 are superseded by re-derived ones carrying the 0.2.0 key set; the superseded versions remain readable, so a rollback loses nothing.".to_string(),
            }],
            rollback_safe: true,
        },
    }
}

const README: &str = r#"# Conformance Reference Pack

A worked example of **`pack.conformance.v1`** — the signed block a Crux memory
pack uses to declare what it does, so a replay can later prove whether it did
that. Format spec: [`docs/spec/pack-conformance-v1.md`](../../../../docs/spec/pack-conformance-v1.md).
Schema (MIT): [`docs/spec/pack.conformance.v1.schema.json`](../../../../docs/spec/pack.conformance.v1.schema.json).

Tool names carry the `ext.` prefix on purpose: the MCP layer only surfaces an
extension tool whose name starts with `ext.`, so a pack that drops it ships
tools no agent ever sees.

This pack is **not installable against a live endpoint**: `external_tool_endpoint`
points at `reference.pack.invalid`, a name reserved by RFC 2606 that can never
resolve. It exists to be read, copied, and parsed.

## What it declares

| Part | This pack |
|---|---|
| Claimed capabilities | `facts:read`, `facts:write` — equal to the manifest's declared set, which the validator requires |
| Expected fact mutations | one write per call under `ext.conformance.reference::notes::`, key `content`, non-private |
| Expected receipt mutations | one `dispatch` and one `fact_write` per call |
| Replay corpus | `replay-corpus.json`, content-addressed by SHA-256, three declared cases |
| Invariants | writes stay in namespace, no private reads, egress pinned, reads are deterministic, the write is reversible |
| Behavioural envelope | 512 tokens/call (2048/run), 2000 ms/call (8000 ms/run), 16 KiB/call, 1 fact write/call, 7-day minimum half-life, zero new contradictions, one-operation undo within 500 ms |
| Compatibility | daemon >= 0.5.0, supersedes 0.1.0 with a reversible `supersede_facts` migration, rollback-safe |

## Trust and safety

Signed with a **fixed example identity** (a documented, non-production seed) so
the committed artefact is reproducible and validly self-signed for the CI gate.
A real publisher signs with their own key and gets their own passport
fingerprint. The declaration is inside the manifest's signing payload, so
widening a bound after signing invalidates the signature — that is the property
the whole trust layer rests on.

## Regenerate

```bash
cargo test -p crux-integrations --test conformance_reference_pack -- --ignored regen_conformance_reference_pack
```
"#;
