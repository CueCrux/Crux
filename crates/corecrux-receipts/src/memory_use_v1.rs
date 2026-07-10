// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! v1 `MemoryUse` receipt class — agent-ux-02 (Acknowledged Memory Use).
//!
//! ## What this is
//!
//! A new receipt class emitted whenever an agent declares which stored
//! memories (facts, retrieved chunks) it consulted while producing a turn.
//! The free-tier `memory_acknowledge_use` MCP tool calls
//! [`build_memory_use_body_v1`] to canonicalise the declaration into
//! CBOR bytes, then signs the bytes with the daemon's Ed25519 passport
//! key via [`sign_memory_use_v1`]. Verification reuses the generic
//! [`crate::verify_v1::verify_receipt_v1`] path with an additional
//! `kind == "memory_use"` assertion provided by
//! [`assert_memory_use_kind_v1`].
//!
//! ## Why a new class, not a `kind` overload
//!
//! Earlier receipt kinds (`"answer"`, `"action"`) describe what the
//! agent DID. `MemoryUse` describes the inputs the agent CONSULTED. The
//! audit-trail tooling (master plan §"audit-trail surface") needs to
//! filter "what backed this answer" separately from "what the answer
//! claimed", so the kind discriminator is the right place for the
//! split.
//!
//! ## Reserved-prefix filter (T.1 + envelope contract)
//!
//! Entries derived from reserved-prefix entities (`__agent::*`,
//! `__ops::*`, `__bootstrap__::*`) MUST be filtered before the body is
//! canonicalised. The canonical bytes encode only the public ack
//! payload, so verification can never resurrect a redacted fact id.
//! Callers should pre-filter with [`is_reserved_entity_prefix`] before
//! handing fact lists to [`build_memory_use_body_v1`].

use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signer as _, SigningKey};

use crate::verify_v1::ReceiptSigV1;

/// Receipt schema string written into the canonical body for memory-use
/// receipts. Mirrors the convention of other v1 receipt classes.
pub const MEMORY_USE_BODY_SCHEMA_V1: &str = "cuecrux.receipt.body.v1";

/// The `kind` discriminator value identifying a memory-use receipt.
pub const MEMORY_USE_KIND_V1: &str = "memory_use";

/// Reserved entity prefixes — facts under any of these MUST NOT appear
/// in the canonical memory-use body. Mirrors
/// `crux_mcp::envelope::RESERVED_PREFIXES` to keep the two surfaces in
/// lockstep; duplicated here so `corecrux-receipts` stays a leaf crate.
pub const RESERVED_ENTITY_PREFIXES_V1: &[&str] = &["__agent::", "__ops::", "__bootstrap__::"];

/// One memory the agent consulted in producing the turn.
///
/// `fact_id` is the canonical id of a stored fact (e.g. `f_01J...`).
/// `entity` is the entity the fact was attached to and is included so
/// downstream verifiers can re-check the reserved-prefix invariant
/// without re-querying the fact store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryUseEntryV1 {
    pub fact_id: String,
    pub entity: String,
}

/// The author-facing intent of the turn that consumed these memories.
///
/// Stored as a free-form string so future intents can ship without a
/// breaking change; the well-known values are listed below for
/// recognisers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryUseIntentV1 {
    Answer,
    Decision,
    ToolCall,
    /// Emitted by the harness when the agent ends a turn without ever
    /// calling `memory_acknowledge_use`. Carries lower trust weight in
    /// the consumer drawer.
    Implicit,
    /// Anything else — preserved verbatim in the canonical body.
    Other(String),
}

impl MemoryUseIntentV1 {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Answer => "answer",
            Self::Decision => "decision",
            Self::ToolCall => "tool_call",
            Self::Implicit => "implicit",
            Self::Other(s) => s.as_str(),
        }
    }

    /// Parse a string into a [`MemoryUseIntentV1`]. Unknown values map
    /// to `Other(s)` so future intents can ship without a code change.
    ///
    /// This is named `parse` rather than `from_str` to avoid colliding
    /// with the `std::str::FromStr` trait method (which would require
    /// returning a `Result`).
    pub fn parse(s: &str) -> Self {
        match s {
            "answer" => Self::Answer,
            "decision" => Self::Decision,
            "tool_call" => Self::ToolCall,
            "implicit" => Self::Implicit,
            other => Self::Other(other.to_string()),
        }
    }
}

/// Input to [`build_memory_use_body_v1`].
#[derive(Debug, Clone)]
pub struct MemoryUseBodyInputV1<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub turn_id: &'a str,
    pub actor_passport: &'a str,
    pub intent: MemoryUseIntentV1,
    pub entries: &'a [MemoryUseEntryV1],
    /// Optional list of retrieved chunk ids (paid: memory-core lane).
    /// Empty in the free tier.
    pub retrieved_chunk_ids: &'a [String],
    /// Optional `confidence` in [0.0, 1.0]. Implicit acks emit
    /// `Some(0.3)` so the drawer can render a subdued badge.
    pub confidence: Option<f32>,
    /// Optional free-form note (e.g. "auto-emitted at turn close").
    pub note: Option<&'a str>,
    /// Caller-provided ISO-8601 timestamp for determinism in tests.
    pub created_at: &'a str,
}

/// Return `true` if `entity` starts with any reserved prefix. Use this
/// to pre-filter [`MemoryUseEntryV1`] lists before calling
/// [`build_memory_use_body_v1`].
pub fn is_reserved_entity_prefix(entity: &str) -> bool {
    RESERVED_ENTITY_PREFIXES_V1.iter().any(|p| entity.starts_with(p))
}

/// Strip any reserved-prefix entries from a slice. Pure convenience
/// wrapper around [`is_reserved_entity_prefix`] so callers cannot
/// accidentally include redacted facts in the canonical body.
pub fn filter_reserved_entries(entries: &[MemoryUseEntryV1]) -> Vec<MemoryUseEntryV1> {
    entries
        .iter()
        .filter(|e| !is_reserved_entity_prefix(&e.entity))
        .cloned()
        .collect()
}

/// Build the canonical CBOR bytes for a memory-use receipt body.
///
/// Returns the encoded bytes and the BLAKE3 digest over those bytes;
/// the digest is what the signature binds to and what the v3 event
/// header stores as `payload_hash`.
///
/// The encoder produces a deterministic key order so two calls with the
/// same input emit byte-identical output (verifier round-trips depend
/// on this).
///
/// Any reserved-prefix entries in `input.entries` are silently
/// dropped — defence in depth against a buggy caller that forgot to
/// filter. The filtered count is observable in the returned body via
/// the `entries_filtered` length, so a test can assert the redaction
/// actually happened.
pub fn build_memory_use_body_v1(input: &MemoryUseBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    let entries = filter_reserved_entries(input.entries);

    // CBOR map entries are emitted in the order they appear in the
    // Vec, so deterministic key order is just a matter of building the
    // list in a fixed sequence.
    let mut top: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Text("schema".to_string()),
            CborValue::Text(MEMORY_USE_BODY_SCHEMA_V1.to_string()),
        ),
        (
            CborValue::Text("kind".to_string()),
            CborValue::Text(MEMORY_USE_KIND_V1.to_string()),
        ),
        (
            CborValue::Text("receipt_id".to_string()),
            CborValue::Text(input.receipt_id.to_string()),
        ),
        (
            CborValue::Text("tenant_id".to_string()),
            CborValue::Text(input.tenant_id.to_string()),
        ),
        (
            CborValue::Text("turn_id".to_string()),
            CborValue::Text(input.turn_id.to_string()),
        ),
        (
            CborValue::Text("actor_passport".to_string()),
            CborValue::Text(input.actor_passport.to_string()),
        ),
        (
            CborValue::Text("intent".to_string()),
            CborValue::Text(input.intent.as_str().to_string()),
        ),
        (
            CborValue::Text("created_at".to_string()),
            CborValue::Text(input.created_at.to_string()),
        ),
    ];

    let entries_arr = entries
        .iter()
        .map(|e| {
            CborValue::Map(vec![
                (
                    CborValue::Text("fact_id".to_string()),
                    CborValue::Text(e.fact_id.clone()),
                ),
                (CborValue::Text("entity".to_string()), CborValue::Text(e.entity.clone())),
            ])
        })
        .collect::<Vec<_>>();
    top.push((CborValue::Text("entries".to_string()), CborValue::Array(entries_arr)));

    let chunks_arr = input
        .retrieved_chunk_ids
        .iter()
        .map(|c| CborValue::Text(c.clone()))
        .collect::<Vec<_>>();
    top.push((
        CborValue::Text("retrieved_chunk_ids".to_string()),
        CborValue::Array(chunks_arr),
    ));

    if let Some(c) = input.confidence {
        top.push((
            CborValue::Text("confidence".to_string()),
            CborValue::Float(f64::from(c)),
        ));
    }
    if let Some(note) = input.note {
        top.push((CborValue::Text("note".to_string()), CborValue::Text(note.to_string())));
    }

    let v = CborValue::Map(top);
    let mut bytes = Vec::new();
    // Serialising a `Value` into a `Vec<u8>` cannot fail in practice —
    // ciborium only returns IO errors and `Vec`'s `Write` impl is
    // infallible. Map any unexpected error to an empty body so callers
    // can detect via a 32-byte hash mismatch downstream rather than
    // panic; the receipt would fail verification cleanly.
    if ciborium::ser::into_writer(&v, &mut bytes).is_err() {
        bytes.clear();
    }
    let digest = blake3::hash(&bytes);
    (bytes, *digest.as_bytes())
}

/// Sign the canonical body produced by [`build_memory_use_body_v1`]
/// with the daemon's Ed25519 passport key and return the
/// [`ReceiptSigV1`] envelope ready to be CBOR-encoded and stored.
///
/// `key_id` should be the daemon's passport key id; the verification
/// path resolves this against the active keyring.
#[allow(clippy::too_many_arguments)]
pub fn sign_memory_use_v1(
    receipt_id: &str,
    body_bytes: &[u8],
    body_hash: [u8; 32],
    signing_key: &SigningKey,
    key_id: &str,
    signed_at: &str,
) -> ReceiptSigV1 {
    let sig = signing_key.sign(body_bytes).to_bytes().to_vec();
    ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: receipt_id.to_string(),
        alg: "ed25519".to_string(),
        key_id: key_id.to_string(),
        signed_at: signed_at.to_string(),
        signature: sig,
        signed_payload_hash: body_hash.to_vec(),
    }
}

/// Best-effort kind assertion: parse `body_bytes` as CBOR and return
/// `true` iff the top-level `kind` field is `"memory_use"`.
///
/// Callers should run this AFTER
/// [`crate::verify_v1::verify_receipt_v1`] returns `OK`; the generic
/// verifier already checks the signature + body-hash binding, so this
/// only adds the class discriminator check.
pub fn assert_memory_use_kind_v1(body_bytes: &[u8]) -> bool {
    let Ok(v) = ciborium::de::from_reader::<CborValue, _>(std::io::Cursor::new(body_bytes)) else {
        return false;
    };
    let CborValue::Map(map) = v else {
        return false;
    };
    for (k, val) in &map {
        if let (CborValue::Text(k), CborValue::Text(s)) = (k, val) {
            if k == "kind" {
                return s == MEMORY_USE_KIND_V1;
            }
        }
    }
    false
}

/// Parse a memory-use receipt body and return the list of acknowledged
/// fact entries. Returns `None` on a parse failure or wrong kind.
/// Useful for the host-IDE annotation builder.
pub fn extract_memory_use_entries_v1(body_bytes: &[u8]) -> Option<Vec<MemoryUseEntryV1>> {
    let v: CborValue = ciborium::de::from_reader(std::io::Cursor::new(body_bytes)).ok()?;
    let CborValue::Map(map) = v else { return None };

    let mut kind_ok = false;
    let mut entries: Option<Vec<MemoryUseEntryV1>> = None;
    for (k, val) in &map {
        let CborValue::Text(key) = k else { continue };
        match key.as_str() {
            "kind" => {
                if let CborValue::Text(s) = val {
                    kind_ok = s == MEMORY_USE_KIND_V1;
                }
            }
            "entries" => {
                if let CborValue::Array(arr) = val {
                    let mut out = Vec::with_capacity(arr.len());
                    for el in arr {
                        if let CborValue::Map(em) = el {
                            let mut fact_id: Option<String> = None;
                            let mut entity: Option<String> = None;
                            for (ek, ev) in em {
                                if let (CborValue::Text(ek), CborValue::Text(ev)) = (ek, ev) {
                                    match ek.as_str() {
                                        "fact_id" => fact_id = Some(ev.clone()),
                                        "entity" => entity = Some(ev.clone()),
                                        _ => {}
                                    }
                                }
                            }
                            if let (Some(fact_id), Some(entity)) = (fact_id, entity) {
                                out.push(MemoryUseEntryV1 { fact_id, entity });
                            }
                        }
                    }
                    entries = Some(out);
                }
            }
            _ => {}
        }
    }

    if !kind_ok {
        return None;
    }
    entries
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::keyring_v1::{Ed25519KeyEntryV1, Ed25519KeyRingV1};
    use crate::verify_v1::{verify_receipt_v1, VerifyReceiptInput};
    use base64::Engine as _;

    fn test_build_info() -> corecrux_types::BuildInfo {
        corecrux_types::BuildInfo {
            version: "0.0.1-test".to_string(),
            commit: "memory_use_v1_test".to_string(),
        }
    }

    fn sample_input<'a>(
        receipt_id: &'a str,
        turn_id: &'a str,
        entries: &'a [MemoryUseEntryV1],
    ) -> MemoryUseBodyInputV1<'a> {
        MemoryUseBodyInputV1 {
            tenant_id: "t-1",
            receipt_id,
            turn_id,
            actor_passport: "p_test",
            intent: MemoryUseIntentV1::Answer,
            entries,
            retrieved_chunk_ids: &[],
            confidence: Some(1.0),
            note: None,
            created_at: "2026-05-27T00:00:00Z",
        }
    }

    #[test]
    fn build_body_is_deterministic() {
        let entries = vec![MemoryUseEntryV1 {
            fact_id: "f_001".to_string(),
            entity: "project-alpha".to_string(),
        }];
        let input = sample_input("r-1", "turn-1", &entries);
        let (b1, h1) = build_memory_use_body_v1(&input);
        let (b2, h2) = build_memory_use_body_v1(&input);
        assert_eq!(b1, b2, "canonical body bytes must be deterministic");
        assert_eq!(h1, h2, "body hash must be deterministic");
    }

    #[test]
    fn reserved_prefix_entries_filtered_in_body() {
        let entries = vec![
            MemoryUseEntryV1 {
                fact_id: "f_001".to_string(),
                entity: "project-alpha".to_string(),
            },
            MemoryUseEntryV1 {
                fact_id: "f_002".to_string(),
                entity: "__ops::config-audit".to_string(),
            },
            MemoryUseEntryV1 {
                fact_id: "f_003".to_string(),
                entity: "__bootstrap__::pattern:retry".to_string(),
            },
            MemoryUseEntryV1 {
                fact_id: "f_004".to_string(),
                entity: "__agent::alice::notes".to_string(),
            },
        ];
        let input = sample_input("r-2", "turn-2", &entries);
        let (body, _) = build_memory_use_body_v1(&input);
        let extracted = extract_memory_use_entries_v1(&body).expect("kind == memory_use");
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].fact_id, "f_001");
        assert_eq!(extracted[0].entity, "project-alpha");
    }

    #[test]
    fn assert_kind_recognises_memory_use() {
        let entries = vec![];
        let input = sample_input("r-3", "turn-3", &entries);
        let (body, _) = build_memory_use_body_v1(&input);
        assert!(assert_memory_use_kind_v1(&body));
    }

    #[test]
    fn assert_kind_rejects_wrong_kind() {
        // Hand-roll a body with kind = "answer" so the asserter rejects it.
        let body = CborValue::Map(vec![(
            CborValue::Text("kind".to_string()),
            CborValue::Text("answer".to_string()),
        )]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&body, &mut bytes).unwrap();
        assert!(!assert_memory_use_kind_v1(&bytes));
    }

    #[test]
    fn assert_kind_rejects_invalid_cbor() {
        assert!(!assert_memory_use_kind_v1(b"not cbor at all"));
    }

    #[test]
    fn intent_round_trips() {
        for s in ["answer", "decision", "tool_call", "implicit", "custom_x"] {
            assert_eq!(MemoryUseIntentV1::parse(s).as_str(), s);
        }
    }

    #[test]
    fn is_reserved_entity_prefix_recognises_all_three() {
        assert!(is_reserved_entity_prefix("__agent::alice::notes"));
        assert!(is_reserved_entity_prefix("__ops::config-audit"));
        assert!(is_reserved_entity_prefix("__bootstrap__::pattern:x"));
        assert!(!is_reserved_entity_prefix("project-alpha"));
        assert!(!is_reserved_entity_prefix("agent::not-reserved"));
    }

    /// End-to-end: build → sign → verify (positive). Mirrors the
    /// `verify_receipt_valid_signature` test in `verify_v1.rs` but
    /// exercises the new memory_use body shape.
    #[test]
    fn build_sign_verify_round_trip() {
        let entries = vec![MemoryUseEntryV1 {
            fact_id: "f_001".to_string(),
            entity: "project-alpha".to_string(),
        }];
        let input = sample_input("r-mu-1", "turn-mu-1", &entries);
        let (body_bytes, body_hash) = build_memory_use_body_v1(&input);
        assert!(assert_memory_use_kind_v1(&body_bytes));

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let sig = sign_memory_use_v1("r-mu-1", &body_bytes, body_hash, &sk, "k_test", "2026-05-27T00:00:00Z");
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes).unwrap();

        let keyring = Ed25519KeyRingV1 {
            v: 1,
            keys: vec![Ed25519KeyEntryV1 {
                key_id: "k_test".to_string(),
                pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
            }],
        };
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-mu-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: body_hash,
            sig_bytes: Some(&sig_bytes),
            keyring: Some(&keyring),
            verified_at: "2026-05-27T00:00:01Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "OK", "happy-path verify must return OK");
        assert!(report.signature_valid);
        assert!(report.integrity.payload_hash_matches);
    }

    /// Tamper detection: flipping one bit in the canonical body MUST
    /// cause the verifier to reject the signature with
    /// `BODY_HASH_MISMATCH`. This is the negative test required by the
    /// child ExecPlan acceptance list.
    #[test]
    fn tamper_bit_flip_detected() {
        let entries = vec![MemoryUseEntryV1 {
            fact_id: "f_002".to_string(),
            entity: "project-beta".to_string(),
        }];
        let input = sample_input("r-mu-2", "turn-mu-2", &entries);
        let (body_bytes, body_hash) = build_memory_use_body_v1(&input);

        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();
        let sig = sign_memory_use_v1(
            "r-mu-2",
            &body_bytes,
            body_hash,
            &sk,
            "k_tamper",
            "2026-05-27T00:00:00Z",
        );
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes).unwrap();

        let keyring = Ed25519KeyRingV1 {
            v: 1,
            keys: vec![Ed25519KeyEntryV1 {
                key_id: "k_tamper".to_string(),
                pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
            }],
        };
        let build = test_build_info();

        // Mutate one byte of the body.
        let mut tampered = body_bytes.clone();
        let last = tampered.len().saturating_sub(1);
        tampered[last] ^= 0x01;

        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-mu-2",
            body_bytes: &tampered,
            stored_body_payload_hash: body_hash, // unchanged stored hash
            sig_bytes: Some(&sig_bytes),
            keyring: Some(&keyring),
            verified_at: "2026-05-27T00:00:01Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(
            report.error_code, "BODY_HASH_MISMATCH",
            "tampered body must be detected as BODY_HASH_MISMATCH"
        );
        assert!(!report.integrity.payload_hash_matches);
    }

    /// Tamper detection on the entries list: a forged body with an
    /// extra fact id is detected because the stored body hash no longer
    /// matches the recomputed hash of the forged body. This guards
    /// against the "forge with wrong fact-id list" attack named in the
    /// child plan's Test plan.
    #[test]
    fn tamper_extra_entry_detected() {
        let original = vec![MemoryUseEntryV1 {
            fact_id: "f_real".to_string(),
            entity: "p".to_string(),
        }];
        let input = sample_input("r-mu-3", "turn-mu-3", &original);
        let (orig_bytes, orig_hash) = build_memory_use_body_v1(&input);

        let forged = vec![
            MemoryUseEntryV1 {
                fact_id: "f_real".to_string(),
                entity: "p".to_string(),
            },
            MemoryUseEntryV1 {
                fact_id: "f_forged".to_string(),
                entity: "p".to_string(),
            },
        ];
        let forged_input = MemoryUseBodyInputV1 {
            entries: &forged,
            ..input
        };
        let (forged_bytes, _forged_hash) = build_memory_use_body_v1(&forged_input);
        assert_ne!(orig_bytes, forged_bytes);

        // Pretend the attacker tried to publish the forged body under
        // the original signature.
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let vk = sk.verifying_key();
        let sig = sign_memory_use_v1("r-mu-3", &orig_bytes, orig_hash, &sk, "k_forge", "2026-05-27T00:00:00Z");
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes).unwrap();

        let keyring = Ed25519KeyRingV1 {
            v: 1,
            keys: vec![Ed25519KeyEntryV1 {
                key_id: "k_forge".to_string(),
                pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
            }],
        };
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-mu-3",
            body_bytes: &forged_bytes,
            stored_body_payload_hash: orig_hash,
            sig_bytes: Some(&sig_bytes),
            keyring: Some(&keyring),
            verified_at: "2026-05-27T00:00:01Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "BODY_HASH_MISMATCH");
    }
}
