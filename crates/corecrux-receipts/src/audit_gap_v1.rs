// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Audit II gap-closure receipt classes.
//!
//! These builders provide the stable receipt vocabulary needed by the
//! Audit II remediation plan before daemon routes mint them. They follow
//! the existing v1 receipt contract: deterministic CBOR body bytes,
//! BLAKE3 body hashes, Ed25519 `ReceiptSigV1` envelopes, and cheap kind
//! assertions after generic verification.

use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signer as _, SigningKey};

use crate::verify_v1::ReceiptSigV1;

pub const AUDIT_GAP_BODY_SCHEMA_V1: &str = "cuecrux.receipt.body.v1";

pub const MODEL_INVOCATION_KIND_V1: &str = "model_invocation";
pub const CHAIN_REANCHOR_KIND_V1: &str = "chain_reanchor";
pub const REDACTION_RECEIPT_KIND_V1: &str = "redaction";
pub const CONSOLIDATION_KIND_V1: &str = "consolidation";
pub const COVERAGE_ATTESTATION_KIND_V1: &str = "coverage_attestation";

#[derive(Debug, Clone)]
pub struct ModelInvocationBodyInputV1<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub invocation_id: &'a str,
    pub actor_passport: &'a str,
    pub provider: &'a str,
    pub model_id: &'a str,
    pub model_version: Option<&'a str>,
    pub provider_request_id: Option<&'a str>,
    pub prompt_hash: &'a str,
    pub retrieval_set_hash: Option<&'a str>,
    pub output_hash: Option<&'a str>,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<i64>,
    pub max_tokens: Option<u64>,
    pub started_at: &'a str,
    pub completed_at: Option<&'a str>,
    pub created_at: &'a str,
}

#[derive(Debug, Clone)]
pub struct ChainReanchorBodyInputV1<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub migration_id: &'a str,
    pub actor_passport: &'a str,
    pub old_chain_head: &'a str,
    pub new_chain_head: &'a str,
    pub old_hash_alg: &'a str,
    pub new_hash_alg: &'a str,
    pub first_receipt_id: &'a str,
    pub last_receipt_id: &'a str,
    pub receipt_count: u64,
    pub reason: &'a str,
    pub linked_receipts: &'a [&'a str],
    pub created_at: &'a str,
}

#[derive(Debug, Clone)]
pub struct RedactionReceiptBodyInputV1<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub redaction_id: &'a str,
    pub actor_passport: &'a str,
    pub subject_type: &'a str,
    pub subject_id: &'a str,
    pub request_id: &'a str,
    pub scope: &'a str,
    pub method: &'a str,
    pub subject_cek_id: &'a str,
    pub subject_cek_commitment: &'a str,
    pub cek_destroyed_at: Option<&'a str>,
    pub prior_content_hash: Option<&'a str>,
    pub redacted_content_hash: Option<&'a str>,
    pub linked_receipts: &'a [&'a str],
    pub created_at: &'a str,
}

#[derive(Debug, Clone)]
pub struct ConsolidationBodyInputV1<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub consolidation_id: &'a str,
    pub actor_passport: &'a str,
    pub target_entity: &'a str,
    pub target_key: Option<&'a str>,
    pub canonical_fact_id: &'a str,
    pub canonical_hash: &'a str,
    pub strategy: &'a str,
    pub superseded_fact_ids: &'a [&'a str],
    pub source_receipts: &'a [&'a str],
    pub created_at: &'a str,
}

#[derive(Debug, Clone)]
pub struct CoverageAttestationBodyInputV1<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub attestation_id: &'a str,
    pub actor_passport: &'a str,
    pub subject: &'a str,
    pub corpus: &'a str,
    pub run_id: &'a str,
    pub commit_sha: &'a str,
    pub lane_flags: &'a str,
    pub metric: &'a str,
    pub score: f64,
    pub floor: Option<f64>,
    pub below_floor: u64,
    pub capability_count: Option<u64>,
    pub covered_count: Option<u64>,
    pub gaps_hash: Option<&'a str>,
    pub report_hash: &'a str,
    pub created_at: &'a str,
}

fn text_entry(key: &str, value: &str) -> (CborValue, CborValue) {
    (CborValue::Text(key.to_string()), CborValue::Text(value.to_string()))
}

fn uint_entry(key: &str, value: u64) -> (CborValue, CborValue) {
    (CborValue::Text(key.to_string()), CborValue::Integer(value.into()))
}

fn int_entry(key: &str, value: i64) -> (CborValue, CborValue) {
    (CborValue::Text(key.to_string()), CborValue::Integer(value.into()))
}

fn float_entry(key: &str, value: f64) -> (CborValue, CborValue) {
    (CborValue::Text(key.to_string()), CborValue::Float(value))
}

fn text_array(values: &[&str]) -> CborValue {
    CborValue::Array(values.iter().map(|v| CborValue::Text((*v).to_string())).collect())
}

fn encode(top: Vec<(CborValue, CborValue)>) -> (Vec<u8>, [u8; 32]) {
    let v = CborValue::Map(top);
    let mut bytes = Vec::new();
    if ciborium::ser::into_writer(&v, &mut bytes).is_err() {
        bytes.clear();
    }
    let digest = blake3::hash(&bytes);
    (bytes, *digest.as_bytes())
}

fn sign_receipt_body_v1(
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

pub fn build_model_invocation_body_v1(input: &ModelInvocationBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    let mut top = vec![
        text_entry("schema", AUDIT_GAP_BODY_SCHEMA_V1),
        text_entry("kind", MODEL_INVOCATION_KIND_V1),
        text_entry("receipt_id", input.receipt_id),
        text_entry("tenant_id", input.tenant_id),
        text_entry("invocation_id", input.invocation_id),
        text_entry("actor_passport", input.actor_passport),
        text_entry("provider", input.provider),
        text_entry("model_id", input.model_id),
        text_entry("prompt_hash", input.prompt_hash),
        text_entry("started_at", input.started_at),
        text_entry("created_at", input.created_at),
    ];
    if let Some(v) = input.model_version {
        top.push(text_entry("model_version", v));
    }
    if let Some(v) = input.provider_request_id {
        top.push(text_entry("provider_request_id", v));
    }
    if let Some(v) = input.retrieval_set_hash {
        top.push(text_entry("retrieval_set_hash", v));
    }
    if let Some(v) = input.output_hash {
        top.push(text_entry("output_hash", v));
    }
    if let Some(v) = input.temperature {
        top.push(float_entry("temperature", v));
    }
    if let Some(v) = input.top_p {
        top.push(float_entry("top_p", v));
    }
    if let Some(v) = input.seed {
        top.push(int_entry("seed", v));
    }
    if let Some(v) = input.max_tokens {
        top.push(uint_entry("max_tokens", v));
    }
    if let Some(v) = input.completed_at {
        top.push(text_entry("completed_at", v));
    }
    encode(top)
}

pub fn build_chain_reanchor_body_v1(input: &ChainReanchorBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    encode(vec![
        text_entry("schema", AUDIT_GAP_BODY_SCHEMA_V1),
        text_entry("kind", CHAIN_REANCHOR_KIND_V1),
        text_entry("receipt_id", input.receipt_id),
        text_entry("tenant_id", input.tenant_id),
        text_entry("migration_id", input.migration_id),
        text_entry("actor_passport", input.actor_passport),
        text_entry("old_chain_head", input.old_chain_head),
        text_entry("new_chain_head", input.new_chain_head),
        text_entry("old_hash_alg", input.old_hash_alg),
        text_entry("new_hash_alg", input.new_hash_alg),
        text_entry("first_receipt_id", input.first_receipt_id),
        text_entry("last_receipt_id", input.last_receipt_id),
        uint_entry("receipt_count", input.receipt_count),
        text_entry("reason", input.reason),
        (
            CborValue::Text("linked_receipts".to_string()),
            text_array(input.linked_receipts),
        ),
        text_entry("created_at", input.created_at),
    ])
}

pub fn build_redaction_receipt_body_v1(input: &RedactionReceiptBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    let mut top = vec![
        text_entry("schema", AUDIT_GAP_BODY_SCHEMA_V1),
        text_entry("kind", REDACTION_RECEIPT_KIND_V1),
        text_entry("receipt_id", input.receipt_id),
        text_entry("tenant_id", input.tenant_id),
        text_entry("redaction_id", input.redaction_id),
        text_entry("actor_passport", input.actor_passport),
        text_entry("subject_type", input.subject_type),
        text_entry("subject_id", input.subject_id),
        text_entry("request_id", input.request_id),
        text_entry("scope", input.scope),
        text_entry("method", input.method),
        text_entry("subject_cek_id", input.subject_cek_id),
        text_entry("subject_cek_commitment", input.subject_cek_commitment),
        (
            CborValue::Text("linked_receipts".to_string()),
            text_array(input.linked_receipts),
        ),
        text_entry("created_at", input.created_at),
    ];
    if let Some(v) = input.cek_destroyed_at {
        top.push(text_entry("cek_destroyed_at", v));
    }
    if let Some(v) = input.prior_content_hash {
        top.push(text_entry("prior_content_hash", v));
    }
    if let Some(v) = input.redacted_content_hash {
        top.push(text_entry("redacted_content_hash", v));
    }
    encode(top)
}

pub fn build_consolidation_body_v1(input: &ConsolidationBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    let mut top = vec![
        text_entry("schema", AUDIT_GAP_BODY_SCHEMA_V1),
        text_entry("kind", CONSOLIDATION_KIND_V1),
        text_entry("receipt_id", input.receipt_id),
        text_entry("tenant_id", input.tenant_id),
        text_entry("consolidation_id", input.consolidation_id),
        text_entry("actor_passport", input.actor_passport),
        text_entry("target_entity", input.target_entity),
        text_entry("canonical_fact_id", input.canonical_fact_id),
        text_entry("canonical_hash", input.canonical_hash),
        text_entry("strategy", input.strategy),
        (
            CborValue::Text("superseded_fact_ids".to_string()),
            text_array(input.superseded_fact_ids),
        ),
        (
            CborValue::Text("source_receipts".to_string()),
            text_array(input.source_receipts),
        ),
        text_entry("created_at", input.created_at),
    ];
    if let Some(v) = input.target_key {
        top.push(text_entry("target_key", v));
    }
    encode(top)
}

pub fn build_coverage_attestation_body_v1(input: &CoverageAttestationBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    let mut top = vec![
        text_entry("schema", AUDIT_GAP_BODY_SCHEMA_V1),
        text_entry("kind", COVERAGE_ATTESTATION_KIND_V1),
        text_entry("receipt_id", input.receipt_id),
        text_entry("tenant_id", input.tenant_id),
        text_entry("attestation_id", input.attestation_id),
        text_entry("actor_passport", input.actor_passport),
        text_entry("subject", input.subject),
        text_entry("corpus", input.corpus),
        text_entry("run_id", input.run_id),
        text_entry("commit_sha", input.commit_sha),
        text_entry("lane_flags", input.lane_flags),
        text_entry("metric", input.metric),
        float_entry("score", input.score),
        uint_entry("below_floor", input.below_floor),
        text_entry("report_hash", input.report_hash),
        text_entry("created_at", input.created_at),
    ];
    if let Some(v) = input.floor {
        top.push(float_entry("floor", v));
    }
    if let Some(v) = input.capability_count {
        top.push(uint_entry("capability_count", v));
    }
    if let Some(v) = input.covered_count {
        top.push(uint_entry("covered_count", v));
    }
    if let Some(v) = input.gaps_hash {
        top.push(text_entry("gaps_hash", v));
    }
    encode(top)
}

pub fn sign_model_invocation_v1(
    receipt_id: &str,
    body_bytes: &[u8],
    body_hash: [u8; 32],
    signing_key: &SigningKey,
    key_id: &str,
    signed_at: &str,
) -> ReceiptSigV1 {
    sign_receipt_body_v1(receipt_id, body_bytes, body_hash, signing_key, key_id, signed_at)
}

pub fn sign_chain_reanchor_v1(
    receipt_id: &str,
    body_bytes: &[u8],
    body_hash: [u8; 32],
    signing_key: &SigningKey,
    key_id: &str,
    signed_at: &str,
) -> ReceiptSigV1 {
    sign_receipt_body_v1(receipt_id, body_bytes, body_hash, signing_key, key_id, signed_at)
}

pub fn sign_redaction_receipt_v1(
    receipt_id: &str,
    body_bytes: &[u8],
    body_hash: [u8; 32],
    signing_key: &SigningKey,
    key_id: &str,
    signed_at: &str,
) -> ReceiptSigV1 {
    sign_receipt_body_v1(receipt_id, body_bytes, body_hash, signing_key, key_id, signed_at)
}

pub fn sign_consolidation_v1(
    receipt_id: &str,
    body_bytes: &[u8],
    body_hash: [u8; 32],
    signing_key: &SigningKey,
    key_id: &str,
    signed_at: &str,
) -> ReceiptSigV1 {
    sign_receipt_body_v1(receipt_id, body_bytes, body_hash, signing_key, key_id, signed_at)
}

pub fn sign_coverage_attestation_v1(
    receipt_id: &str,
    body_bytes: &[u8],
    body_hash: [u8; 32],
    signing_key: &SigningKey,
    key_id: &str,
    signed_at: &str,
) -> ReceiptSigV1 {
    sign_receipt_body_v1(receipt_id, body_bytes, body_hash, signing_key, key_id, signed_at)
}

fn top_level_text(body_bytes: &[u8], field: &str) -> Option<String> {
    let v: CborValue = ciborium::de::from_reader(std::io::Cursor::new(body_bytes)).ok()?;
    let CborValue::Map(map) = v else { return None };
    for (k, val) in &map {
        if let (CborValue::Text(k), CborValue::Text(s)) = (k, val) {
            if k == field {
                return Some(s.clone());
            }
        }
    }
    None
}

fn assert_kind(body_bytes: &[u8], kind: &str) -> bool {
    top_level_text(body_bytes, "kind").as_deref() == Some(kind)
}

pub fn assert_model_invocation_kind_v1(body_bytes: &[u8]) -> bool {
    assert_kind(body_bytes, MODEL_INVOCATION_KIND_V1)
}

pub fn assert_chain_reanchor_kind_v1(body_bytes: &[u8]) -> bool {
    assert_kind(body_bytes, CHAIN_REANCHOR_KIND_V1)
}

pub fn assert_redaction_receipt_kind_v1(body_bytes: &[u8]) -> bool {
    assert_kind(body_bytes, REDACTION_RECEIPT_KIND_V1)
}

pub fn assert_consolidation_kind_v1(body_bytes: &[u8]) -> bool {
    assert_kind(body_bytes, CONSOLIDATION_KIND_V1)
}

pub fn assert_coverage_attestation_kind_v1(body_bytes: &[u8]) -> bool {
    assert_kind(body_bytes, COVERAGE_ATTESTATION_KIND_V1)
}

pub fn verify_chain_reanchor_body_v1(body_bytes: &[u8]) -> bool {
    let Some(map) = top_level_map(body_bytes) else {
        return false;
    };
    required_text(&map, "schema") == Some(AUDIT_GAP_BODY_SCHEMA_V1)
        && required_text(&map, "kind") == Some(CHAIN_REANCHOR_KIND_V1)
        && required_nonempty_text(&map, "receipt_id")
        && required_nonempty_text(&map, "tenant_id")
        && required_nonempty_text(&map, "migration_id")
        && required_nonempty_text(&map, "actor_passport")
        && required_nonempty_text(&map, "first_receipt_id")
        && required_nonempty_text(&map, "last_receipt_id")
        && required_nonempty_text(&map, "reason")
        && valid_chain_heads(&map)
        && valid_chain_alg(&map, "old_hash_alg")
        && valid_chain_alg(&map, "new_hash_alg")
        && required_uint(&map, "receipt_count").is_some_and(|v| v > 0)
        && text_array_len(&map, "linked_receipts").is_some_and(|v| v > 0)
}

fn top_level_map(body_bytes: &[u8]) -> Option<Vec<(CborValue, CborValue)>> {
    let v: CborValue = ciborium::de::from_reader(std::io::Cursor::new(body_bytes)).ok()?;
    let CborValue::Map(map) = v else { return None };
    Some(map)
}

fn required_text<'a>(map: &'a [(CborValue, CborValue)], field: &str) -> Option<&'a str> {
    for (k, val) in map {
        if let (CborValue::Text(k), CborValue::Text(s)) = (k, val) {
            if k == field {
                return Some(s);
            }
        }
    }
    None
}

fn required_nonempty_text(map: &[(CborValue, CborValue)], field: &str) -> bool {
    required_text(map, field).is_some_and(|v| !v.trim().is_empty())
}

fn required_uint(map: &[(CborValue, CborValue)], field: &str) -> Option<u64> {
    for (k, val) in map {
        if let (CborValue::Text(k), CborValue::Integer(i)) = (k, val) {
            if k == field {
                return u64::try_from(*i).ok();
            }
        }
    }
    None
}

fn text_array_len(map: &[(CborValue, CborValue)], field: &str) -> Option<usize> {
    for (k, val) in map {
        if let (CborValue::Text(k), CborValue::Array(values)) = (k, val) {
            if k == field
                && values
                    .iter()
                    .all(|v| matches!(v, CborValue::Text(s) if !s.trim().is_empty()))
            {
                return Some(values.len());
            }
        }
    }
    None
}

fn valid_chain_heads(map: &[(CborValue, CborValue)]) -> bool {
    let Some(old) = required_text(map, "old_chain_head") else {
        return false;
    };
    let Some(new) = required_text(map, "new_chain_head") else {
        return false;
    };
    !old.trim().is_empty() && !new.trim().is_empty() && old != new
}

fn valid_chain_alg(map: &[(CborValue, CborValue)], field: &str) -> bool {
    matches!(
        required_text(map, field),
        Some(
            "blake3"
                | "blake3+ed25519"
                | "blake3+external-anchor"
                | "blake3+rfc3161"
                | "blake3+sigstore"
                | "blake3+tsa"
                | "sha256"
                | "sha256+rfc3161"
        )
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;

    fn model_input() -> ModelInvocationBodyInputV1<'static> {
        ModelInvocationBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "mi_1",
            invocation_id: "inv_1",
            actor_passport: "passport:agent",
            provider: "openai",
            model_id: "gpt-5.4",
            model_version: Some("2026-06-01"),
            provider_request_id: Some("req_123"),
            prompt_hash: "blake3:prompt",
            retrieval_set_hash: Some("blake3:retrieval"),
            output_hash: Some("blake3:output"),
            temperature: Some(0.2),
            top_p: Some(0.9),
            seed: Some(42),
            max_tokens: Some(2048),
            started_at: "2026-06-14T10:00:00Z",
            completed_at: Some("2026-06-14T10:00:02Z"),
            created_at: "2026-06-14T10:00:02Z",
        }
    }

    fn chain_input<'a>(links: &'a [&'a str]) -> ChainReanchorBodyInputV1<'a> {
        ChainReanchorBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "cr_1",
            migration_id: "migration-1",
            actor_passport: "passport:operator",
            old_chain_head: "blake3:old",
            new_chain_head: "blake3:new",
            old_hash_alg: "blake3",
            new_hash_alg: "blake3+tsa",
            first_receipt_id: "r_1",
            last_receipt_id: "r_9",
            receipt_count: 9,
            reason: "external-anchor-upgrade",
            linked_receipts: links,
            created_at: "2026-06-14T10:00:00Z",
        }
    }

    fn redaction_input<'a>(links: &'a [&'a str]) -> RedactionReceiptBodyInputV1<'a> {
        RedactionReceiptBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "red_1",
            redaction_id: "redaction-1",
            actor_passport: "passport:operator",
            subject_type: "fact",
            subject_id: "f_1",
            request_id: "forget-1",
            scope: "subject",
            method: "crypto_shred",
            subject_cek_id: "cek:f_1",
            subject_cek_commitment: "blake3:cek-commitment",
            cek_destroyed_at: Some("2026-06-14T10:01:00Z"),
            prior_content_hash: Some("blake3:prior"),
            redacted_content_hash: Some("blake3:redacted"),
            linked_receipts: links,
            created_at: "2026-06-14T10:01:00Z",
        }
    }

    fn consolidation_input<'a>(superseded: &'a [&'a str], receipts: &'a [&'a str]) -> ConsolidationBodyInputV1<'a> {
        ConsolidationBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "con_1",
            consolidation_id: "consolidation-1",
            actor_passport: "passport:agent",
            target_entity: "topic:alpha",
            target_key: Some("summary"),
            canonical_fact_id: "f_canonical",
            canonical_hash: "blake3:canonical",
            strategy: "newest_non_conflicting",
            superseded_fact_ids: superseded,
            source_receipts: receipts,
            created_at: "2026-06-14T10:02:00Z",
        }
    }

    fn coverage_input() -> CoverageAttestationBodyInputV1<'static> {
        CoverageAttestationBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "cov_1",
            attestation_id: "coverage-1",
            actor_passport: "passport:agent",
            subject: "feature_registry",
            corpus: "LME-S",
            run_id: "run-1",
            commit_sha: "deadbeef",
            lane_flags: "dense=on,sparse=on",
            metric: "capability_coverage",
            score: 0.92,
            floor: Some(0.9),
            below_floor: 0,
            capability_count: Some(100),
            covered_count: Some(92),
            gaps_hash: Some("blake3:gaps"),
            report_hash: "blake3:report",
            created_at: "2026-06-14T10:03:00Z",
        }
    }

    fn get_array_len(body: &[u8], field: &str) -> usize {
        let v: CborValue = ciborium::de::from_reader(std::io::Cursor::new(body)).unwrap();
        let CborValue::Map(map) = v else { return 0 };
        for (k, val) in map {
            if let (CborValue::Text(k), CborValue::Array(arr)) = (k, val) {
                if k == field {
                    return arr.len();
                }
            }
        }
        0
    }

    #[test]
    fn model_invocation_body_is_byte_deterministic() {
        let (a, ha) = build_model_invocation_body_v1(&model_input());
        let (b, hb) = build_model_invocation_body_v1(&model_input());
        assert_eq!(a, b);
        assert_eq!(ha, hb);
        assert_eq!(ha, *blake3::hash(&a).as_bytes());
        assert!(assert_model_invocation_kind_v1(&a));
    }

    #[test]
    fn all_audit_gap_kinds_are_specific() {
        let links = ["r_1", "r_2"];
        let superseded = ["f_old_1", "f_old_2"];
        let source_receipts = ["r_old_1", "r_old_2"];
        let (model, _) = build_model_invocation_body_v1(&model_input());
        let (chain, _) = build_chain_reanchor_body_v1(&chain_input(&links));
        let (redaction, _) = build_redaction_receipt_body_v1(&redaction_input(&links));
        let (consolidation, _) = build_consolidation_body_v1(&consolidation_input(&superseded, &source_receipts));
        let (coverage, _) = build_coverage_attestation_body_v1(&coverage_input());

        assert!(assert_model_invocation_kind_v1(&model));
        assert!(!assert_chain_reanchor_kind_v1(&model));
        assert!(assert_chain_reanchor_kind_v1(&chain));
        assert!(assert_redaction_receipt_kind_v1(&redaction));
        assert!(assert_consolidation_kind_v1(&consolidation));
        assert!(assert_coverage_attestation_kind_v1(&coverage));
        assert!(!assert_coverage_attestation_kind_v1(b"not cbor"));
    }

    #[test]
    fn linked_receipt_arrays_are_canonicalized() {
        let links = ["r_1", "r_2", "r_3"];
        let superseded = ["f_old_1", "f_old_2"];
        let source_receipts = ["r_old_1", "r_old_2"];
        let (chain, _) = build_chain_reanchor_body_v1(&chain_input(&links));
        let (redaction, _) = build_redaction_receipt_body_v1(&redaction_input(&links));
        let (consolidation, _) = build_consolidation_body_v1(&consolidation_input(&superseded, &source_receipts));

        assert_eq!(get_array_len(&chain, "linked_receipts"), 3);
        assert_eq!(get_array_len(&redaction, "linked_receipts"), 3);
        assert_eq!(get_array_len(&consolidation, "superseded_fact_ids"), 2);
        assert_eq!(get_array_len(&consolidation, "source_receipts"), 2);
    }

    #[test]
    fn verify_chain_reanchor_accepts_valid_body() {
        let links = ["r_1", "r_2"];
        let (body, _) = build_chain_reanchor_body_v1(&chain_input(&links));
        assert!(verify_chain_reanchor_body_v1(&body));
    }

    #[test]
    fn verify_chain_reanchor_rejects_zero_count() {
        let links = ["r_1"];
        let mut input = chain_input(&links);
        input.receipt_count = 0;
        let (body, _) = build_chain_reanchor_body_v1(&input);
        assert!(!verify_chain_reanchor_body_v1(&body));
    }

    #[test]
    fn verify_chain_reanchor_rejects_empty_linked_receipts() {
        let links: [&str; 0] = [];
        let (body, _) = build_chain_reanchor_body_v1(&chain_input(&links));
        assert!(!verify_chain_reanchor_body_v1(&body));
    }

    #[test]
    fn verify_chain_reanchor_rejects_same_heads() {
        let links = ["r_1"];
        let mut input = chain_input(&links);
        input.new_chain_head = input.old_chain_head;
        let (body, _) = build_chain_reanchor_body_v1(&input);
        assert!(!verify_chain_reanchor_body_v1(&body));
    }

    #[test]
    fn verify_chain_reanchor_rejects_unsupported_alg() {
        let links = ["r_1"];
        let mut input = chain_input(&links);
        input.new_hash_alg = "md5";
        let (body, _) = build_chain_reanchor_body_v1(&input);
        assert!(!verify_chain_reanchor_body_v1(&body));
    }

    #[test]
    fn verify_chain_reanchor_rejects_blank_linked_receipt_id() {
        let links = ["r_1", ""];
        let (body, _) = build_chain_reanchor_body_v1(&chain_input(&links));
        assert!(!verify_chain_reanchor_body_v1(&body));
    }

    #[test]
    fn sign_and_verify_model_invocation_body() {
        let (bytes, hash) = build_model_invocation_body_v1(&model_input());
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let sig = sign_model_invocation_v1("mi_1", &bytes, hash, &signing_key, "key-1", "2026-06-14T10:00:03Z");
        assert_eq!(sig.signed_payload_hash, hash.to_vec());
        let vk: VerifyingKey = signing_key.verifying_key();
        let sig_bytes: [u8; 64] = sig.signature.as_slice().try_into().unwrap();
        vk.verify_strict(&bytes, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .expect("signature verifies over canonical body bytes");

        let mut tampered = bytes.clone();
        tampered[0] ^= 0xFF;
        assert!(vk
            .verify_strict(&tampered, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .is_err());
    }

    #[test]
    fn sign_helpers_share_receipt_sig_contract() {
        let links = ["r_1"];
        let superseded = ["f_old_1"];
        let source_receipts = ["r_old_1"];
        let signing_key = SigningKey::from_bytes(&[12u8; 32]);
        let cases = [
            {
                let (body, hash) = build_chain_reanchor_body_v1(&chain_input(&links));
                sign_chain_reanchor_v1("cr_1", &body, hash, &signing_key, "kid", "2026-06-14T10:00:00Z")
            },
            {
                let (body, hash) = build_redaction_receipt_body_v1(&redaction_input(&links));
                sign_redaction_receipt_v1("red_1", &body, hash, &signing_key, "kid", "2026-06-14T10:00:00Z")
            },
            {
                let (body, hash) = build_consolidation_body_v1(&consolidation_input(&superseded, &source_receipts));
                sign_consolidation_v1("con_1", &body, hash, &signing_key, "kid", "2026-06-14T10:00:00Z")
            },
            {
                let (body, hash) = build_coverage_attestation_body_v1(&coverage_input());
                sign_coverage_attestation_v1("cov_1", &body, hash, &signing_key, "kid", "2026-06-14T10:00:00Z")
            },
        ];

        for sig in cases {
            assert_eq!(sig.schema, "cuecrux.receipt.sig.v1");
            assert_eq!(sig.alg, "ed25519");
            assert_eq!(sig.key_id, "kid");
            assert_eq!(sig.signature.len(), 64);
            assert_eq!(sig.signed_payload_hash.len(), 32);
        }
    }
}
