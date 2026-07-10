// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Dense vector lane — pluggable cosine-similarity provider.
//!
//! Per ExecPlan `dense-lane-and-extraction-upsell-2026-06-26`, the dense lane is
//! a **first-class, uncapped, local** capability. `fused_retrieve` calls a
//! [`DenseProvider`] for each BM25 candidate; the provider holds the query
//! embedding plus a vector store and returns a cosine score in `[0.0, 1.0]`.
//!
//! Supersedes the historical ADR-CORECRUX-0001 stance ("dense is CoreCrux-owned;
//! the lane reports inactive"). The boundary is now:
//!
//! - **CE (this crate, free, uncapped):** [`CosineDenseProvider`] — exact CPU
//!   cosine over Bring-Your-Own-embedder vectors. No corpus cap, no quantisation,
//!   deterministic.
//! - **Dataplane (paid):** a GPU `.ccxe` provider behind this same trait.
//! - **No provider supplied:** the lane stays inert (`dense_component = 0.0`,
//!   `dense_lane_active = false`) — bit-identical to the pre-plan behaviour.
//!
//! ## Recall scope (v1)
//!
//! In the fused design the dense lane **re-ranks the BM25 candidate pool**
//! (over-retrieved at `top_k * 4`); it does not yet contribute independent ANN
//! recall. A document BM25 misses entirely cannot be surfaced by dense alone.
//! True union recall (BM25 ∪ dense-ANN candidates) is a follow-up (see plan M2
//! Decision Log); re-ranking is a correct, shippable first increment.

use std::collections::HashMap;

/// Cosine-similarity provider for the dense retrieval lane.
///
/// Implementors hold the query embedding and a vector store. `fused_retrieve`
/// calls [`DenseProvider::dense_score`] once per BM25 candidate.
pub trait DenseProvider {
    /// Cosine similarity in `[0.0, 1.0]` for the candidate identified by
    /// `(doc_id, segment_index)` against the query this provider was built for,
    /// or `None` if the candidate has no stored vector (or a dimension mismatch).
    fn dense_score(&self, doc_id: u32, segment_index: usize) -> Option<f32>;
}

/// Exact, uncapped CPU cosine provider — the Community Edition dense lane.
///
/// Holds a unit-normalised query vector and a map of candidate vectors keyed by
/// `(doc_id, segment_index)`. There is deliberately **no corpus cap**: every
/// stored vector is eligible. Scoring is exact cosine (no quantisation), so
/// output is deterministic for a given input.
pub struct CosineDenseProvider {
    query_unit: Vec<f32>,
    vectors: HashMap<(u32, usize), Vec<f32>>,
}

impl CosineDenseProvider {
    /// Build a provider from a query embedding and candidate vectors.
    ///
    /// The query is unit-normalised once here; candidate norms are computed at
    /// score time, so callers need not pre-normalise. Dimension mismatches and
    /// zero-norm vectors score `None` rather than panicking.
    pub fn new(query_embedding: &[f32], vectors: HashMap<(u32, usize), Vec<f32>>) -> Self {
        Self {
            query_unit: unit_normalize(query_embedding),
            vectors,
        }
    }

    /// Number of candidate vectors held (no cap is applied).
    pub fn len(&self) -> usize {
        self.vectors.len()
    }

    /// True when the provider holds no candidate vectors.
    pub fn is_empty(&self) -> bool {
        self.vectors.is_empty()
    }
}

impl DenseProvider for CosineDenseProvider {
    fn dense_score(&self, doc_id: u32, segment_index: usize) -> Option<f32> {
        let v = self.vectors.get(&(doc_id, segment_index))?;
        if v.is_empty() || v.len() != self.query_unit.len() {
            return None;
        }
        let unit = unit_normalize(v);
        // Cosine of two unit vectors == dot product. The dense lane is a
        // non-negative boost (like the bm25/graph lanes), so a negatively
        // correlated candidate contributes nothing rather than subtracting:
        // clamp to [0, 1].
        let dot: f32 = self.query_unit.iter().zip(unit.iter()).map(|(a, b)| a * b).sum();
        Some(dot.clamp(0.0, 1.0))
    }
}

/// Return `v` scaled to unit L2 norm; a zero-norm vector is returned unchanged.
fn unit_normalize(v: &[f32]) -> Vec<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        v.iter().map(|x| x / norm).collect()
    } else {
        v.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_vector_scores_one() {
        let q = vec![1.0, 0.0, 0.0];
        let mut vecs = HashMap::new();
        vecs.insert((0u32, 0usize), vec![1.0, 0.0, 0.0]);
        let p = CosineDenseProvider::new(&q, vecs);
        let s = p.dense_score(0, 0).unwrap();
        assert!((s - 1.0).abs() < 1e-6, "identical vectors → cosine 1, got {s}");
    }

    #[test]
    fn orthogonal_vector_scores_zero() {
        let q = vec![1.0, 0.0];
        let mut vecs = HashMap::new();
        vecs.insert((0u32, 0usize), vec![0.0, 1.0]);
        let p = CosineDenseProvider::new(&q, vecs);
        assert_eq!(p.dense_score(0, 0).unwrap(), 0.0);
    }

    #[test]
    fn negative_correlation_clamps_to_zero() {
        let q = vec![1.0, 0.0];
        let mut vecs = HashMap::new();
        vecs.insert((0u32, 0usize), vec![-1.0, 0.0]);
        let p = CosineDenseProvider::new(&q, vecs);
        assert_eq!(p.dense_score(0, 0).unwrap(), 0.0, "negative cosine clamps to 0");
    }

    #[test]
    fn missing_vector_and_dim_mismatch_score_none() {
        let q = vec![1.0, 0.0, 0.0];
        let mut vecs = HashMap::new();
        vecs.insert((0u32, 0usize), vec![1.0, 0.0]); // wrong dim
        let p = CosineDenseProvider::new(&q, vecs);
        assert_eq!(p.dense_score(0, 0), None, "dim mismatch → None");
        assert_eq!(p.dense_score(9, 9), None, "missing candidate → None");
    }

    #[test]
    fn no_cap_holds_many_vectors() {
        let q = vec![1.0, 0.0];
        let mut vecs = HashMap::new();
        for i in 0..10_000u32 {
            vecs.insert((i, 0usize), vec![1.0, 0.0]);
        }
        let p = CosineDenseProvider::new(&q, vecs);
        assert_eq!(p.len(), 10_000, "provider applies no corpus cap");
        assert!((p.dense_score(9_999, 0).unwrap() - 1.0).abs() < 1e-6);
    }
}
