// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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

/// G7 coverage-attestation finish: a signed *window* report attesting how
/// many events, receipts and external anchors a tenant's store held over a
/// `[from, to)` interval, plus the gaps (events with no receipt; receipts
/// with no anchor). The report is bound by hash into the receipt body so the
/// signature covers the exact counts — a gap can never be hidden from the
/// signed object.
pub const COVERAGE_WINDOW_KIND_V1: &str = "coverage_window";

/// Schema tag for the standalone coverage-window report JSON (the object the
/// receipt body's `report_hash` is computed over).
pub const COVERAGE_WINDOW_REPORT_SCHEMA_V1: &str = "cuecrux.coverage.window.report.v1";

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

/// Deterministic counts for a coverage window. `events` is the population of
/// non-receipt events in the window that *should* carry a receipt; `receipts`
/// is the receipt-body population; `anchored` is the receipt subset that is an
/// external anchor / RFC3161 timestamp (or is linked from one). Gaps are
/// computed, never supplied, so the two summands always reconcile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CoverageWindowCountsV1 {
    /// Non-receipt events observed in the window.
    pub events: u64,
    /// Receipt bodies observed in the window.
    pub receipts: u64,
    /// Receipt bodies that are anchored (anchor-kind, or linked from an anchor).
    pub anchored: u64,
    /// Events in the window with no corresponding receipt.
    pub events_without_receipt: u64,
    /// Receipts in the window with no external anchor.
    pub receipts_without_anchor: u64,
}

impl CoverageWindowCountsV1 {
    /// Total gap count surfaced by the window = unreceipted events +
    /// unanchored receipts. This is the headline "gaps" figure.
    #[must_use]
    pub fn gaps(&self) -> u64 {
        self.events_without_receipt.saturating_add(self.receipts_without_anchor)
    }
}

/// A standalone, signable coverage-window report. Serialized to canonical
/// JSON (sorted keys via [`coverage_window_report_canonical_json_v1`]); its
/// BLAKE3 hash is bound into the [`COVERAGE_WINDOW_KIND_V1`] receipt body.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CoverageWindowReportV1 {
    pub schema: String,
    pub tenant_id: String,
    /// RFC3339 lower bound, inclusive.
    pub from: String,
    /// RFC3339 upper bound, exclusive.
    pub to: String,
    pub events: u64,
    pub receipts: u64,
    pub anchored: u64,
    pub gaps: u64,
    pub events_without_receipt: u64,
    pub receipts_without_anchor: u64,
    /// Rolling BLAKE3 head over the ordered in-window payload hashes;
    /// `blake3:<64-hex>` of an empty window is the all-zero seed digest.
    pub chain_head: String,
}

impl CoverageWindowReportV1 {
    /// Build a report from a tenant id, `[from, to)` bounds, the reconciled
    /// counts, and a precomputed `chain_head`.
    #[must_use]
    pub fn new(tenant_id: &str, from: &str, to: &str, counts: CoverageWindowCountsV1, chain_head: &str) -> Self {
        Self {
            schema: COVERAGE_WINDOW_REPORT_SCHEMA_V1.to_string(),
            tenant_id: tenant_id.to_string(),
            from: from.to_string(),
            to: to.to_string(),
            events: counts.events,
            receipts: counts.receipts,
            anchored: counts.anchored,
            gaps: counts.gaps(),
            events_without_receipt: counts.events_without_receipt,
            receipts_without_anchor: counts.receipts_without_anchor,
            chain_head: chain_head.to_string(),
        }
    }

    /// `blake3:<64-hex>` of the canonical JSON serialization.
    #[must_use]
    pub fn report_hash(&self) -> String {
        let bytes = coverage_window_report_canonical_json_v1(self);
        format!("blake3:{}", blake3::hash(&bytes).to_hex())
    }
}

#[derive(Debug, Clone)]
pub struct CoverageWindowBodyInputV1<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub attestation_id: &'a str,
    pub actor_passport: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub events: u64,
    pub receipts: u64,
    pub anchored: u64,
    pub gaps: u64,
    pub events_without_receipt: u64,
    pub receipts_without_anchor: u64,
    pub chain_head: &'a str,
    pub report_hash: &'a str,
    pub created_at: &'a str,
}

/// Canonical (sorted-key) JSON bytes for a coverage-window report. Pure and
/// deterministic so the standalone report and the hash bound into the receipt
/// body always agree, independent of struct field order or `serde` settings.
#[must_use]
pub fn coverage_window_report_canonical_json_v1(report: &CoverageWindowReportV1) -> Vec<u8> {
    // BTreeMap gives sorted keys; numeric values are exact integers.
    let mut map: std::collections::BTreeMap<&str, serde_json::Value> = std::collections::BTreeMap::new();
    map.insert("schema", serde_json::Value::String(report.schema.clone()));
    map.insert("tenant_id", serde_json::Value::String(report.tenant_id.clone()));
    map.insert("from", serde_json::Value::String(report.from.clone()));
    map.insert("to", serde_json::Value::String(report.to.clone()));
    map.insert("events", serde_json::Value::from(report.events));
    map.insert("receipts", serde_json::Value::from(report.receipts));
    map.insert("anchored", serde_json::Value::from(report.anchored));
    map.insert("gaps", serde_json::Value::from(report.gaps));
    map.insert(
        "events_without_receipt",
        serde_json::Value::from(report.events_without_receipt),
    );
    map.insert(
        "receipts_without_anchor",
        serde_json::Value::from(report.receipts_without_anchor),
    );
    map.insert("chain_head", serde_json::Value::String(report.chain_head.clone()));
    serde_json::to_vec(&map).unwrap_or_default()
}

/// Fold one payload hash into a rolling coverage-window chain head.
/// `head_{n} = blake3(head_{n-1} || payload_hash)`. Seed is all-zero.
#[must_use]
pub fn coverage_window_chain_fold_v1(head: [u8; 32], payload_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&head);
    hasher.update(payload_hash);
    *hasher.finalize().as_bytes()
}

/// Render a 32-byte chain head as `blake3:<64-hex>`.
#[must_use]
pub fn coverage_window_chain_head_hex_v1(head: [u8; 32]) -> String {
    format!("blake3:{}", blake3::Hash::from(head).to_hex())
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

pub fn build_coverage_window_body_v1(input: &CoverageWindowBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    encode(vec![
        text_entry("schema", AUDIT_GAP_BODY_SCHEMA_V1),
        text_entry("kind", COVERAGE_WINDOW_KIND_V1),
        text_entry("receipt_id", input.receipt_id),
        text_entry("tenant_id", input.tenant_id),
        text_entry("attestation_id", input.attestation_id),
        text_entry("actor_passport", input.actor_passport),
        text_entry("from", input.from),
        text_entry("to", input.to),
        uint_entry("events", input.events),
        uint_entry("receipts", input.receipts),
        uint_entry("anchored", input.anchored),
        uint_entry("gaps", input.gaps),
        uint_entry("events_without_receipt", input.events_without_receipt),
        uint_entry("receipts_without_anchor", input.receipts_without_anchor),
        text_entry("chain_head", input.chain_head),
        text_entry("report_hash", input.report_hash),
        text_entry("created_at", input.created_at),
    ])
}

pub fn sign_coverage_window_v1(
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

pub fn assert_coverage_window_kind_v1(body_bytes: &[u8]) -> bool {
    assert_kind(body_bytes, COVERAGE_WINDOW_KIND_V1)
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

/// Structural verification of a coverage-window receipt body. Confirms the
/// schema/kind, required string fields, and — critically — that the gap
/// arithmetic reconciles: `gaps == events_without_receipt +
/// receipts_without_anchor`, `anchored <= receipts`, and
/// `receipts_without_anchor == receipts - anchored`. A receipt that under-
/// reports its gaps therefore fails verification — gaps cannot be hidden.
pub fn verify_coverage_window_body_v1(body_bytes: &[u8]) -> bool {
    let Some(map) = top_level_map(body_bytes) else {
        return false;
    };
    if required_text(&map, "schema") != Some(AUDIT_GAP_BODY_SCHEMA_V1)
        || required_text(&map, "kind") != Some(COVERAGE_WINDOW_KIND_V1)
        || !required_nonempty_text(&map, "receipt_id")
        || !required_nonempty_text(&map, "tenant_id")
        || !required_nonempty_text(&map, "attestation_id")
        || !required_nonempty_text(&map, "actor_passport")
        || !required_nonempty_text(&map, "from")
        || !required_nonempty_text(&map, "to")
        || !required_nonempty_text(&map, "chain_head")
        || !required_nonempty_text(&map, "report_hash")
        || !required_nonempty_text(&map, "created_at")
    {
        return false;
    }
    let (Some(events), Some(receipts), Some(anchored), Some(gaps), Some(ewr), Some(rwa)) = (
        required_uint(&map, "events"),
        required_uint(&map, "receipts"),
        required_uint(&map, "anchored"),
        required_uint(&map, "gaps"),
        required_uint(&map, "events_without_receipt"),
        required_uint(&map, "receipts_without_anchor"),
    ) else {
        return false;
    };
    anchored <= receipts && rwa == receipts.saturating_sub(anchored) && ewr <= events && gaps == ewr.saturating_add(rwa)
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

    fn window_counts() -> CoverageWindowCountsV1 {
        // 10 events, 8 receipts (so 2 events lack a receipt), 5 anchored
        // (so 3 receipts lack an anchor). Gaps = 2 + 3 = 5.
        CoverageWindowCountsV1 {
            events: 10,
            receipts: 8,
            anchored: 5,
            events_without_receipt: 2,
            receipts_without_anchor: 3,
        }
    }

    fn window_body_input<'a>(report_hash: &'a str, counts: CoverageWindowCountsV1) -> CoverageWindowBodyInputV1<'a> {
        CoverageWindowBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "cw_1",
            attestation_id: "coverage-window-1",
            actor_passport: "passport:operator",
            from: "2026-06-14T00:00:00Z",
            to: "2026-06-15T00:00:00Z",
            events: counts.events,
            receipts: counts.receipts,
            anchored: counts.anchored,
            gaps: counts.gaps(),
            events_without_receipt: counts.events_without_receipt,
            receipts_without_anchor: counts.receipts_without_anchor,
            chain_head: "blake3:00",
            report_hash,
            created_at: "2026-06-15T00:01:00Z",
        }
    }

    #[test]
    fn coverage_window_counts_gaps_reconcile() {
        let c = window_counts();
        assert_eq!(c.gaps(), 5);
    }

    #[test]
    fn coverage_window_report_hash_is_deterministic_and_self_consistent() {
        let head = coverage_window_chain_head_hex_v1([0u8; 32]);
        let report = CoverageWindowReportV1::new(
            "tenant-a",
            "2026-06-14T00:00:00Z",
            "2026-06-15T00:00:00Z",
            window_counts(),
            &head,
        );
        let h1 = report.report_hash();
        let h2 = report.report_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("blake3:"));
        // Mutating any count changes the hash (no hidden gaps).
        let mut tampered = report.clone();
        tampered.gaps = 0;
        assert_ne!(report.report_hash(), tampered.report_hash());
        // Canonical JSON is sorted-key stable.
        let bytes = coverage_window_report_canonical_json_v1(&report);
        let json = String::from_utf8(bytes).unwrap();
        assert!(json.contains("\"gaps\":5"));
        assert!(json.contains("\"events_without_receipt\":2"));
    }

    #[test]
    fn coverage_window_chain_fold_changes_head_per_event() {
        let h0 = [0u8; 32];
        let h1 = coverage_window_chain_fold_v1(h0, blake3::hash(b"e1").as_bytes());
        let h2 = coverage_window_chain_fold_v1(h1, blake3::hash(b"e2").as_bytes());
        assert_ne!(h0, h1);
        assert_ne!(h1, h2);
        // Order-sensitive: folding the same hashes in a different order differs.
        let alt = coverage_window_chain_fold_v1(
            coverage_window_chain_fold_v1(h0, blake3::hash(b"e2").as_bytes()),
            blake3::hash(b"e1").as_bytes(),
        );
        assert_ne!(h2, alt);
    }

    #[test]
    fn coverage_window_body_verifies_and_is_specific() {
        let head = coverage_window_chain_head_hex_v1([7u8; 32]);
        let report = CoverageWindowReportV1::new(
            "tenant-a",
            "2026-06-14T00:00:00Z",
            "2026-06-15T00:00:00Z",
            window_counts(),
            &head,
        );
        let report_hash = report.report_hash();
        let (body, _) = build_coverage_window_body_v1(&window_body_input(&report_hash, window_counts()));
        assert!(verify_coverage_window_body_v1(&body));
        assert!(assert_coverage_window_kind_v1(&body));
        // Not confused with the older coverage_attestation kind.
        assert!(!assert_coverage_attestation_kind_v1(&body));
        assert!(!verify_coverage_window_body_v1(b"not cbor"));
    }

    #[test]
    fn coverage_window_body_rejects_understated_gaps() {
        // Claim zero gaps despite 8 receipts / 5 anchored / 10 events / 8 receipts.
        let mut input = window_body_input("blake3:report", window_counts());
        input.gaps = 0;
        input.events_without_receipt = 0;
        input.receipts_without_anchor = 0;
        let (body, _) = build_coverage_window_body_v1(&input);
        // anchored (5) != receipts (8) so receipts_without_anchor must be 3, not 0.
        assert!(!verify_coverage_window_body_v1(&body));
    }

    #[test]
    fn coverage_window_body_rejects_anchored_exceeding_receipts() {
        let counts = CoverageWindowCountsV1 {
            events: 4,
            receipts: 2,
            anchored: 5, // impossible
            events_without_receipt: 2,
            receipts_without_anchor: 0,
        };
        let (body, _) = build_coverage_window_body_v1(&window_body_input("blake3:report", counts));
        assert!(!verify_coverage_window_body_v1(&body));
    }

    #[test]
    fn coverage_window_empty_window_verifies() {
        let counts = CoverageWindowCountsV1 {
            events: 0,
            receipts: 0,
            anchored: 0,
            events_without_receipt: 0,
            receipts_without_anchor: 0,
        };
        let (body, _) = build_coverage_window_body_v1(&window_body_input("blake3:report", counts));
        assert!(verify_coverage_window_body_v1(&body));
    }

    #[test]
    fn sign_and_verify_coverage_window_body() {
        let report = CoverageWindowReportV1::new(
            "tenant-a",
            "2026-06-14T00:00:00Z",
            "2026-06-15T00:00:00Z",
            window_counts(),
            &coverage_window_chain_head_hex_v1([1u8; 32]),
        );
        let report_hash = report.report_hash();
        let (bytes, hash) = build_coverage_window_body_v1(&window_body_input(&report_hash, window_counts()));
        let signing_key = SigningKey::from_bytes(&[13u8; 32]);
        let sig = sign_coverage_window_v1("cw_1", &bytes, hash, &signing_key, "key-1", "2026-06-15T00:01:00Z");
        assert_eq!(sig.signed_payload_hash, hash.to_vec());
        let vk: VerifyingKey = signing_key.verifying_key();
        let sig_bytes: [u8; 64] = sig.signature.as_slice().try_into().unwrap();
        vk.verify_strict(&bytes, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .expect("signature verifies over canonical body bytes");

        // Tamper any byte → signature fails (the report counts are inside the body).
        let mut tampered = bytes.clone();
        tampered[0] ^= 0xFF;
        assert!(vk
            .verify_strict(&tampered, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .is_err());
    }

    // A fully-valid coverage-window entry set (arithmetic reconciles); used as
    // the baseline for single-field tamper tests below.
    fn valid_window_entries() -> Vec<(CborValue, CborValue)> {
        let counts = window_counts();
        vec![
            text_entry("schema", AUDIT_GAP_BODY_SCHEMA_V1),
            text_entry("kind", COVERAGE_WINDOW_KIND_V1),
            text_entry("receipt_id", "cw_1"),
            text_entry("tenant_id", "tenant-a"),
            text_entry("attestation_id", "coverage-window-1"),
            text_entry("actor_passport", "passport:operator"),
            text_entry("from", "2026-06-14T00:00:00Z"),
            text_entry("to", "2026-06-15T00:00:00Z"),
            uint_entry("events", counts.events),
            uint_entry("receipts", counts.receipts),
            uint_entry("anchored", counts.anchored),
            uint_entry("gaps", counts.gaps()),
            uint_entry("events_without_receipt", counts.events_without_receipt),
            uint_entry("receipts_without_anchor", counts.receipts_without_anchor),
            text_entry("chain_head", "blake3:00"),
            text_entry("report_hash", "blake3:report"),
            text_entry("created_at", "2026-06-15T00:01:00Z"),
        ]
    }

    fn set_text_field(entries: &mut [(CborValue, CborValue)], field: &str, value: &str) {
        for (k, v) in entries.iter_mut() {
            if let CborValue::Text(ks) = k {
                if ks == field {
                    *v = CborValue::Text(value.to_string());
                }
            }
        }
    }

    #[test]
    fn coverage_window_body_rejects_each_blank_required_string() {
        // Sanity: the fully-populated entry set verifies.
        assert!(verify_coverage_window_body_v1(&encode(valid_window_entries()).0));
        // Blank exactly one required string field at a time (every other field
        // valid) — the verifier's OR-chain guard must reject on the single bad
        // field. This pins each `||` in the guard against `&&`: with `&&` an
        // isolated bad field no longer forces rejection.
        for field in [
            "receipt_id",
            "tenant_id",
            "attestation_id",
            "actor_passport",
            "from",
            "to",
            "chain_head",
            "report_hash",
            "created_at",
        ] {
            let mut entries = valid_window_entries();
            set_text_field(&mut entries, field, "   ");
            let (body, _) = encode(entries);
            assert!(
                !verify_coverage_window_body_v1(&body),
                "blank `{field}` must be rejected"
            );
        }
    }

    #[test]
    fn coverage_window_body_rejects_wrong_kind_with_all_else_valid() {
        // Only `kind` is wrong; schema + every other field valid. Pins the
        // schema/kind boundary of the OR-chain.
        let mut entries = valid_window_entries();
        set_text_field(&mut entries, "kind", COVERAGE_ATTESTATION_KIND_V1);
        let (body, _) = encode(entries);
        assert!(!verify_coverage_window_body_v1(&body));
    }

    #[test]
    fn coverage_window_body_rejects_wrong_schema_with_all_else_valid() {
        let mut entries = valid_window_entries();
        set_text_field(&mut entries, "schema", "cuecrux.receipt.body.WRONG");
        let (body, _) = encode(entries);
        assert!(!verify_coverage_window_body_v1(&body));
    }
}
