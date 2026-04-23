// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Extraction-cache event types (M1 of stateful-extraction-flywheel.md).
//!
//! These events back the content-addressed chunk-extraction cache that shortcuts
//! repeated LLM calls on byte-identical chunks. All events are JSON-encoded — the
//! extracted entities payload is itself variable-shape JSON, so a binary layout
//! would add serialization cost without saving space.
//!
//! Stream naming (owned by VaultCrux append callers):
//!   `__global__:extraction:cache`            — cross-tenant cache stream
//!   `<tenant>:extraction:confidence`         — per-tenant confidence deltas (M7)
//!   `__global__:extraction:negative_facts`   — negative-fact patterns (M8)
//!   `__global__:extraction:canonical_entity` — entity alias clusters (M6)
//!   `__global__:extraction:canonical_predicate` — predicate canonicalization (M6)
//!
//! Event types defined here:
//!   * [`ExtractionCacheInsertV1`]     — new extraction completed, store entities
//!   * [`ExtractionCacheHitV1`]        — projection derives hit_count from these
//!   * [`ExtractionVerifierScoredV1`]  — M4 attaches cross-encoder support score
//!   * [`ExtractionConfidenceDeltaV1`] — M7 adjusts confidence from downstream signal
//!   * [`ExtractionCacheInvalidateV1`] — explicit invalidation (prompt change, etc.)
//!
//! See `PlanCrux/.agent/execplans/stateful-extraction-flywheel.md` §M1 for
//! the full design rationale.

use crate::{ProjectionError, Result};

// ── Event-type constants ───────────────────────────────────────────────────────

pub const EVT_EXTRACTION_CACHE_INSERT_V1: &str = "corecrux.proj.extraction.cache_insert.v1";
pub const EVT_EXTRACTION_CACHE_HIT_V1: &str = "corecrux.proj.extraction.cache_hit.v1";
pub const EVT_EXTRACTION_VERIFIER_SCORED_V1: &str = "corecrux.proj.extraction.verifier_scored.v1";
pub const EVT_EXTRACTION_CONFIDENCE_DELTA_V1: &str = "corecrux.proj.extraction.confidence_delta.v1";
pub const EVT_EXTRACTION_CACHE_INVALIDATE_V1: &str = "corecrux.proj.extraction.cache_invalidate.v1";

pub const CONTENT_TYPE_EXTRACTION_JSON_V1: &str = "application/x-corecrux-extraction-json-v1";

// ── Signal-source enum (free-form string, documented here for reference) ──────
//
// `ExtractionConfidenceDeltaV1.source` is a free string so new signal sources can
// be added without a schema bump. The canonical values are:
//   "judge_correct"   — GPT-4o auto-eval marked an answer citing this fact as correct
//   "judge_wrong"     — marked as wrong
//   "user_affirm"     — user explicitly confirmed this fact
//   "user_retract"    — user explicitly retracted this fact
//   "verifier_pass"   — M4 reranker scored above threshold
//   "verifier_fail"   — below threshold
//   "contradiction_found" — another fact in the same (entity, predicate) cluster conflicts
//   "near_hit_replay" — served via semantic near-hit (M13), adjust confidence to match origin

// ── Event structs ──────────────────────────────────────────────────────────────

/// CacheInsert — new extraction completed, store entities + metadata.
///
/// `cache_key` is the full hash: `sha256(chunk_text || prompt_hash || model || grammar_version)`.
/// `chunk_hash` is `sha256(chunk_text)` alone — for cross-model analytics and
/// the optional semantic near-hit path (M13) that keys on content, not prompt.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtractionCacheInsertV1 {
    /// Hex-encoded sha256 of (chunk_text || prompt_hash || model || grammar_version).
    /// Used as the exact-match lookup key.
    pub cache_key: String,

    /// Hex-encoded sha256(chunk_text) — stable across prompt/model variations.
    pub chunk_hash: String,

    /// Hex-encoded sha256(prompt_template) — invalidates cache on prompt change.
    pub prompt_hash: String,

    /// Fully-qualified model id (e.g. "claude-haiku-4-5-20251001", "Qwen/Qwen2.5-7B-Instruct-AWQ").
    pub model: String,

    /// Grammar version stamp; "v0" means no grammar constraint (pre-M3).
    pub grammar_version: String,

    /// Extracted entities as an arbitrary JSON array. Shape is owned by
    /// `ExtractedFactSchema` in CueCrux-Shared; this layer is schema-agnostic.
    pub entities: serde_json::Value,

    /// Optional chunk embedding (Nomic-embed-text-v1.5 default dimension: 768).
    /// Populated on insert so the optional semantic near-hit cache (M13) can
    /// key on this without a second ingest pass. Dormant until M13 flag flips.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_embedding: Option<Vec<f32>>,

    /// Optional cross-encoder support score from M4 verifier, set at insert
    /// if verifier ran inline; otherwise attached later via VerifierScoredV1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_score: Option<f32>,

    /// Initial confidence. Normally 1.0 at insert; updated by ConfidenceDelta events.
    pub confidence_mean: f32,

    /// Tenant whose chunk produced this cache entry. The cache is cross-tenant
    /// (any tenant can hit the key) but we record provenance for audit.
    pub source_tenant_id: String,

    /// Event timestamp (microseconds since unix epoch).
    pub created_at_micros: i64,
}

impl ExtractionCacheInsertV1 {
    pub fn decode_json(payload: &[u8]) -> Result<Self> {
        serde_json::from_slice(payload).map_err(|e| ProjectionError::InvalidEvent {
            msg: format!("ExtractionCacheInsertV1 JSON decode: {e}"),
        })
    }

    pub fn encode_json(&self) -> Vec<u8> {
        #[allow(clippy::expect_used)]
        serde_json::to_vec(self).expect("ExtractionCacheInsertV1 serialization should not fail")
    }
}

/// CacheHit — recorded when a lookup finds an existing entry.
/// Projection uses these to derive `hit_count` and `last_hit_at` for the cache row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtractionCacheHitV1 {
    pub cache_key: String,
    /// Which tenant served a hit (tenant-agnostic cache, tenant-scoped usage).
    pub tenant_id: String,
    pub hit_at_micros: i64,
}

impl ExtractionCacheHitV1 {
    pub fn decode_json(payload: &[u8]) -> Result<Self> {
        serde_json::from_slice(payload).map_err(|e| ProjectionError::InvalidEvent {
            msg: format!("ExtractionCacheHitV1 JSON decode: {e}"),
        })
    }

    pub fn encode_json(&self) -> Vec<u8> {
        #[allow(clippy::expect_used)]
        serde_json::to_vec(self).expect("ExtractionCacheHitV1 serialization should not fail")
    }
}

/// VerifierScored — M4 cross-encoder score attached post-hoc to an existing cache entry.
/// Projection upserts `verifier_score` on the matching `cache_key`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtractionVerifierScoredV1 {
    pub cache_key: String,
    /// Verifier model identifier, e.g. "bge-reranker-v2-m3".
    pub verifier_model: String,
    /// Cross-encoder support score in [0.0, 1.0].
    pub score: f32,
    pub scored_at_micros: i64,
}

impl ExtractionVerifierScoredV1 {
    pub fn decode_json(payload: &[u8]) -> Result<Self> {
        serde_json::from_slice(payload).map_err(|e| ProjectionError::InvalidEvent {
            msg: format!("ExtractionVerifierScoredV1 JSON decode: {e}"),
        })
    }

    pub fn encode_json(&self) -> Vec<u8> {
        #[allow(clippy::expect_used)]
        serde_json::to_vec(self).expect("ExtractionVerifierScoredV1 serialization should not fail")
    }
}

/// ConfidenceDelta — per-tenant fact confidence adjustment from downstream signal.
/// Projection applies time-decayed mean (half-life ~30 days).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtractionConfidenceDeltaV1 {
    pub cache_key: String,
    /// Tenant scope — confidence deltas are per-tenant because feedback is tenant-local.
    pub tenant_id: String,
    /// Additive delta on [-1.0, +1.0]. Sign indicates direction, magnitude the strength.
    pub delta: f32,
    /// Free-form tag, canonical values documented at top of this file.
    pub source: String,
    /// Optional correlation to the bench run or user action that produced this signal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_run_id: Option<String>,
    pub occurred_at_micros: i64,
}

impl ExtractionConfidenceDeltaV1 {
    pub fn decode_json(payload: &[u8]) -> Result<Self> {
        serde_json::from_slice(payload).map_err(|e| ProjectionError::InvalidEvent {
            msg: format!("ExtractionConfidenceDeltaV1 JSON decode: {e}"),
        })
    }

    pub fn encode_json(&self) -> Vec<u8> {
        #[allow(clippy::expect_used)]
        serde_json::to_vec(self).expect("ExtractionConfidenceDeltaV1 serialization should not fail")
    }
}

/// CacheInvalidate — explicit invalidation. Used when a model is retired, a
/// prompt version is deprecated, or operations manually marks entries stale.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtractionCacheInvalidateV1 {
    pub cache_key: String,
    /// Human-readable reason; examples: "prompt_v2_migration", "model_retired",
    /// "grammar_v1_upgrade", "operator_purge_command".
    pub reason: String,
    pub invalidated_at_micros: i64,
}

impl ExtractionCacheInvalidateV1 {
    pub fn decode_json(payload: &[u8]) -> Result<Self> {
        serde_json::from_slice(payload).map_err(|e| ProjectionError::InvalidEvent {
            msg: format!("ExtractionCacheInvalidateV1 JSON decode: {e}"),
        })
    }

    pub fn encode_json(&self) -> Vec<u8> {
        #[allow(clippy::expect_used)]
        serde_json::to_vec(self).expect("ExtractionCacheInvalidateV1 serialization should not fail")
    }
}

// ── Materialized state (projection of the event stream) ──────────────────────────

/// Current-state row for one `cache_key`. Derived by applying the 5 event types
/// in `ProjectionEventV1` to an `ExtractionCacheMaterializer`.
///
/// Omits `chunk_embedding` — that's a 3 KB float vector per row and only needed
/// by the optional M13 near-hit path. When M13 ships, a parallel map can hold
/// the embeddings keyed on `cache_key`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtractionCacheCurrentRowV1 {
    pub cache_key: String,
    pub chunk_hash: String,
    pub prompt_hash: String,
    pub model: String,
    pub grammar_version: String,
    pub entities: serde_json::Value,
    pub verifier_score: Option<f32>,
    pub verifier_model: Option<String>,
    pub confidence_mean: f32,
    pub source_tenant_id: String,
    pub created_at_micros: i64,
    pub hit_count: u64,
    pub last_hit_at_micros: i64,
    pub invalidated: bool,
    pub invalidation_reason: Option<String>,
    /// How many confidence-delta events have contributed to the rolled mean.
    pub confidence_update_count: u32,
}

/// In-memory materializer for the `extraction_cache_current` projection.
///
/// Keyed on `cache_key`. Apply one event at a time via `apply_insert`,
/// `apply_hit`, `apply_verifier`, `apply_confidence`, `apply_invalidate`.
/// Read via `get` / `batch_get` / `len` / `stats`.
///
/// Deterministic: BTreeMap preserves sort order; all operations are pure.
#[derive(Debug, Default)]
pub struct ExtractionCacheMaterializer {
    rows: std::collections::BTreeMap<String, ExtractionCacheCurrentRowV1>,
}

impl ExtractionCacheMaterializer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Single-key lookup. Returns `None` if absent OR invalidated.
    /// Invalidated entries are left in the map for audit but won't serve hits.
    pub fn get(&self, cache_key: &str) -> Option<&ExtractionCacheCurrentRowV1> {
        self.rows.get(cache_key).filter(|r| !r.invalidated)
    }

    /// Raw getter — returns the row even if invalidated. Use for audits.
    pub fn get_raw(&self, cache_key: &str) -> Option<&ExtractionCacheCurrentRowV1> {
        self.rows.get(cache_key)
    }

    /// Batched lookup. Positions correspond 1:1 with input keys.
    pub fn batch_get(&self, cache_keys: &[String]) -> Vec<Option<ExtractionCacheCurrentRowV1>> {
        cache_keys.iter().map(|k| self.get(k).cloned()).collect()
    }

    /// Aggregate stats for observability (Grafana / /readyz integration).
    pub fn stats(&self) -> ExtractionCacheStats {
        let mut hit_count_total: u64 = 0;
        let mut invalidated_count: usize = 0;
        let mut verified_count: usize = 0;
        for row in self.rows.values() {
            hit_count_total = hit_count_total.saturating_add(row.hit_count);
            if row.invalidated {
                invalidated_count += 1;
            }
            if row.verifier_score.is_some() {
                verified_count += 1;
            }
        }
        ExtractionCacheStats {
            total_rows: self.rows.len(),
            invalidated_count,
            verified_count,
            hit_count_total,
        }
    }

    // ── Event appliers ──

    /// Apply a CacheInsert event. Upsert semantics: later inserts for the same
    /// `cache_key` overwrite payload fields but reset `hit_count` to 0 and
    /// `invalidated` to false (a re-insert is effectively a fresh extraction).
    pub fn apply_insert(&mut self, ev: &ExtractionCacheInsertV1) {
        let row = ExtractionCacheCurrentRowV1 {
            cache_key: ev.cache_key.clone(),
            chunk_hash: ev.chunk_hash.clone(),
            prompt_hash: ev.prompt_hash.clone(),
            model: ev.model.clone(),
            grammar_version: ev.grammar_version.clone(),
            entities: ev.entities.clone(),
            verifier_score: ev.verifier_score,
            verifier_model: None,
            confidence_mean: ev.confidence_mean,
            source_tenant_id: ev.source_tenant_id.clone(),
            created_at_micros: ev.created_at_micros,
            hit_count: 0,
            last_hit_at_micros: ev.created_at_micros,
            invalidated: false,
            invalidation_reason: None,
            confidence_update_count: 0,
        };
        self.rows.insert(ev.cache_key.clone(), row);
    }

    /// Apply a CacheHit event. Bumps counters on the target row; no-op if absent.
    pub fn apply_hit(&mut self, ev: &ExtractionCacheHitV1) {
        if let Some(row) = self.rows.get_mut(&ev.cache_key) {
            row.hit_count = row.hit_count.saturating_add(1);
            if ev.hit_at_micros > row.last_hit_at_micros {
                row.last_hit_at_micros = ev.hit_at_micros;
            }
        }
    }

    /// Apply a VerifierScored event. Upserts the score + model on an existing
    /// row; no-op if no matching insert was seen (events out of order ⇒ deferred).
    pub fn apply_verifier(&mut self, ev: &ExtractionVerifierScoredV1) {
        if let Some(row) = self.rows.get_mut(&ev.cache_key) {
            row.verifier_score = Some(ev.score);
            row.verifier_model = Some(ev.verifier_model.clone());
        }
    }

    /// Apply a ConfidenceDelta event. Clamps to [0.0, 1.0] after applying delta.
    /// Increments `confidence_update_count` so downstream can weight certainty.
    pub fn apply_confidence(&mut self, ev: &ExtractionConfidenceDeltaV1) {
        if let Some(row) = self.rows.get_mut(&ev.cache_key) {
            let next = row.confidence_mean + ev.delta;
            row.confidence_mean = next.clamp(0.0, 1.0);
            row.confidence_update_count = row.confidence_update_count.saturating_add(1);
        }
    }

    /// Apply a CacheInvalidate event. Marks row invalidated; subsequent reads
    /// via `get` will skip it. Row itself is retained for audit trail.
    pub fn apply_invalidate(&mut self, ev: &ExtractionCacheInvalidateV1) {
        if let Some(row) = self.rows.get_mut(&ev.cache_key) {
            row.invalidated = true;
            row.invalidation_reason = Some(ev.reason.clone());
        }
    }
}

/// Aggregate stats for the `extraction_cache_current` projection.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct ExtractionCacheStats {
    pub total_rows: usize,
    pub invalidated_count: usize,
    pub verified_count: usize,
    pub hit_count_total: u64,
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cache_insert_roundtrip() {
        let orig = ExtractionCacheInsertV1 {
            cache_key: "deadbeef".repeat(8),
            chunk_hash: "cafef00d".repeat(8),
            prompt_hash: "ba5eba11".repeat(8),
            model: "claude-haiku-4-5-20251001".to_string(),
            grammar_version: "v0".to_string(),
            entities: json!([
                {"subject": "User", "predicate": "bought", "object": "camera", "subject_type": "Person"}
            ]),
            chunk_embedding: None,
            verifier_score: None,
            confidence_mean: 1.0,
            source_tenant_id: "__longmemeval_s_001".to_string(),
            created_at_micros: 1_700_000_000_000_000,
        };
        let bytes = orig.encode_json();
        let decoded = ExtractionCacheInsertV1::decode_json(&bytes).unwrap();
        assert_eq!(decoded.cache_key, orig.cache_key);
        assert_eq!(decoded.model, orig.model);
        assert_eq!(decoded.entities, orig.entities);
        assert_eq!(decoded.confidence_mean, orig.confidence_mean);
    }

    #[test]
    fn cache_insert_with_embedding() {
        let orig = ExtractionCacheInsertV1 {
            cache_key: "a".repeat(64),
            chunk_hash: "b".repeat(64),
            prompt_hash: "c".repeat(64),
            model: "Qwen/Qwen2.5-7B-Instruct-AWQ".to_string(),
            grammar_version: "v1".to_string(),
            entities: json!([]),
            chunk_embedding: Some(vec![0.1, 0.2, 0.3]),
            verifier_score: Some(0.87),
            confidence_mean: 0.95,
            source_tenant_id: "t1".to_string(),
            created_at_micros: 1,
        };
        let bytes = orig.encode_json();
        let decoded = ExtractionCacheInsertV1::decode_json(&bytes).unwrap();
        assert_eq!(decoded.chunk_embedding, Some(vec![0.1, 0.2, 0.3]));
        assert_eq!(decoded.verifier_score, Some(0.87));
    }

    #[test]
    fn cache_hit_roundtrip() {
        let orig = ExtractionCacheHitV1 {
            cache_key: "x".repeat(64),
            tenant_id: "t1".to_string(),
            hit_at_micros: 2_000_000_000_000_000,
        };
        let bytes = orig.encode_json();
        let decoded = ExtractionCacheHitV1::decode_json(&bytes).unwrap();
        assert_eq!(decoded.cache_key, orig.cache_key);
        assert_eq!(decoded.tenant_id, orig.tenant_id);
    }

    #[test]
    fn verifier_scored_roundtrip() {
        let orig = ExtractionVerifierScoredV1 {
            cache_key: "k".repeat(64),
            verifier_model: "bge-reranker-v2-m3".to_string(),
            score: 0.92,
            scored_at_micros: 1,
        };
        let bytes = orig.encode_json();
        let decoded = ExtractionVerifierScoredV1::decode_json(&bytes).unwrap();
        assert!((decoded.score - 0.92).abs() < f32::EPSILON);
    }

    #[test]
    fn confidence_delta_roundtrip() {
        let orig = ExtractionConfidenceDeltaV1 {
            cache_key: "k".repeat(64),
            tenant_id: "t1".to_string(),
            delta: -0.15,
            source: "judge_wrong".to_string(),
            source_run_id: Some("lme-s-sonnet-4-6-F1-202604221028-c5a1d9".to_string()),
            occurred_at_micros: 1,
        };
        let bytes = orig.encode_json();
        let decoded = ExtractionConfidenceDeltaV1::decode_json(&bytes).unwrap();
        assert!((decoded.delta - -0.15).abs() < f32::EPSILON);
        assert_eq!(decoded.source, "judge_wrong");
        assert_eq!(decoded.source_run_id.as_deref(), Some("lme-s-sonnet-4-6-F1-202604221028-c5a1d9"));
    }

    #[test]
    fn cache_invalidate_roundtrip() {
        let orig = ExtractionCacheInvalidateV1 {
            cache_key: "k".repeat(64),
            reason: "prompt_v2_migration".to_string(),
            invalidated_at_micros: 1,
        };
        let bytes = orig.encode_json();
        let decoded = ExtractionCacheInvalidateV1::decode_json(&bytes).unwrap();
        assert_eq!(decoded.reason, orig.reason);
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(ExtractionCacheInsertV1::decode_json(b"{not json").is_err());
        assert!(ExtractionCacheHitV1::decode_json(b"").is_err());
    }

    // ── Materializer tests ──

    fn sample_insert(cache_key: &str) -> ExtractionCacheInsertV1 {
        ExtractionCacheInsertV1 {
            cache_key: cache_key.to_string(),
            chunk_hash: "chunk_hash".to_string(),
            prompt_hash: "prompt_hash".to_string(),
            model: "claude-haiku-4-5".to_string(),
            grammar_version: "v0".to_string(),
            entities: json!([{"subject": "User", "predicate": "bought", "object": "camera"}]),
            chunk_embedding: None,
            verifier_score: None,
            confidence_mean: 1.0,
            source_tenant_id: "t1".to_string(),
            created_at_micros: 1_000,
        }
    }

    #[test]
    fn materializer_empty_start() {
        let m = ExtractionCacheMaterializer::new();
        assert_eq!(m.len(), 0);
        assert!(m.is_empty());
        assert!(m.get("absent").is_none());
    }

    #[test]
    fn insert_and_get() {
        let mut m = ExtractionCacheMaterializer::new();
        m.apply_insert(&sample_insert("k1"));
        let row = m.get("k1").expect("present");
        assert_eq!(row.cache_key, "k1");
        assert_eq!(row.hit_count, 0);
        assert_eq!(row.last_hit_at_micros, 1_000);
        assert!(!row.invalidated);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn hit_increments_counter() {
        let mut m = ExtractionCacheMaterializer::new();
        m.apply_insert(&sample_insert("k1"));
        m.apply_hit(&ExtractionCacheHitV1 {
            cache_key: "k1".to_string(),
            tenant_id: "t2".to_string(),
            hit_at_micros: 2_000,
        });
        m.apply_hit(&ExtractionCacheHitV1 {
            cache_key: "k1".to_string(),
            tenant_id: "t3".to_string(),
            hit_at_micros: 3_000,
        });
        let row = m.get("k1").expect("present");
        assert_eq!(row.hit_count, 2);
        assert_eq!(row.last_hit_at_micros, 3_000);
    }

    #[test]
    fn hit_no_op_when_key_absent() {
        let mut m = ExtractionCacheMaterializer::new();
        m.apply_hit(&ExtractionCacheHitV1 {
            cache_key: "absent".to_string(),
            tenant_id: "t1".to_string(),
            hit_at_micros: 1,
        });
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn verifier_attaches_score() {
        let mut m = ExtractionCacheMaterializer::new();
        m.apply_insert(&sample_insert("k1"));
        m.apply_verifier(&ExtractionVerifierScoredV1 {
            cache_key: "k1".to_string(),
            verifier_model: "bge-reranker-v2-m3".to_string(),
            score: 0.87,
            scored_at_micros: 5_000,
        });
        let row = m.get("k1").expect("present");
        assert_eq!(row.verifier_score, Some(0.87));
        assert_eq!(row.verifier_model.as_deref(), Some("bge-reranker-v2-m3"));
    }

    #[test]
    fn confidence_delta_clamps_range() {
        let mut m = ExtractionCacheMaterializer::new();
        m.apply_insert(&sample_insert("k1"));

        // Negative delta brings confidence down, clamped at 0.0
        m.apply_confidence(&ExtractionConfidenceDeltaV1 {
            cache_key: "k1".to_string(),
            tenant_id: "t1".to_string(),
            delta: -1.5,
            source: "judge_wrong".to_string(),
            source_run_id: None,
            occurred_at_micros: 1,
        });
        assert_eq!(m.get("k1").unwrap().confidence_mean, 0.0);
        assert_eq!(m.get("k1").unwrap().confidence_update_count, 1);

        // Positive delta, clamped at 1.0
        m.apply_confidence(&ExtractionConfidenceDeltaV1 {
            cache_key: "k1".to_string(),
            tenant_id: "t1".to_string(),
            delta: 2.0,
            source: "judge_correct".to_string(),
            source_run_id: None,
            occurred_at_micros: 2,
        });
        assert_eq!(m.get("k1").unwrap().confidence_mean, 1.0);
        assert_eq!(m.get("k1").unwrap().confidence_update_count, 2);
    }

    #[test]
    fn invalidate_hides_from_get_keeps_in_raw() {
        let mut m = ExtractionCacheMaterializer::new();
        m.apply_insert(&sample_insert("k1"));
        m.apply_invalidate(&ExtractionCacheInvalidateV1 {
            cache_key: "k1".to_string(),
            reason: "prompt_v2_migration".to_string(),
            invalidated_at_micros: 1,
        });
        assert!(m.get("k1").is_none(), "get should skip invalidated rows");
        let raw = m.get_raw("k1").expect("raw still present");
        assert!(raw.invalidated);
        assert_eq!(raw.invalidation_reason.as_deref(), Some("prompt_v2_migration"));
    }

    #[test]
    fn batch_get_returns_hits_and_misses() {
        let mut m = ExtractionCacheMaterializer::new();
        m.apply_insert(&sample_insert("k1"));
        m.apply_insert(&sample_insert("k2"));

        let keys = vec!["k1".to_string(), "absent".to_string(), "k2".to_string()];
        let results = m.batch_get(&keys);
        assert_eq!(results.len(), 3);
        assert!(results[0].is_some());
        assert!(results[1].is_none());
        assert!(results[2].is_some());
    }

    #[test]
    fn re_insert_resets_hits_but_preserves_row() {
        let mut m = ExtractionCacheMaterializer::new();
        m.apply_insert(&sample_insert("k1"));
        m.apply_hit(&ExtractionCacheHitV1 {
            cache_key: "k1".to_string(),
            tenant_id: "t1".to_string(),
            hit_at_micros: 100,
        });
        assert_eq!(m.get("k1").unwrap().hit_count, 1);

        // Re-insert (e.g. grammar version bump) — fresh row, zero hits
        m.apply_insert(&sample_insert("k1"));
        let row = m.get("k1").expect("still present after re-insert");
        assert_eq!(row.hit_count, 0);
    }

    #[test]
    fn stats_aggregate_correctly() {
        let mut m = ExtractionCacheMaterializer::new();
        m.apply_insert(&sample_insert("k1"));
        m.apply_insert(&sample_insert("k2"));
        m.apply_insert(&sample_insert("k3"));
        m.apply_hit(&ExtractionCacheHitV1 {
            cache_key: "k1".to_string(),
            tenant_id: "t1".to_string(),
            hit_at_micros: 1,
        });
        m.apply_hit(&ExtractionCacheHitV1 {
            cache_key: "k1".to_string(),
            tenant_id: "t2".to_string(),
            hit_at_micros: 2,
        });
        m.apply_verifier(&ExtractionVerifierScoredV1 {
            cache_key: "k2".to_string(),
            verifier_model: "bge".to_string(),
            score: 0.5,
            scored_at_micros: 1,
        });
        m.apply_invalidate(&ExtractionCacheInvalidateV1 {
            cache_key: "k3".to_string(),
            reason: "r".to_string(),
            invalidated_at_micros: 1,
        });

        let s = m.stats();
        assert_eq!(s.total_rows, 3);
        assert_eq!(s.hit_count_total, 2);
        assert_eq!(s.verified_count, 1);
        assert_eq!(s.invalidated_count, 1);
    }
}
