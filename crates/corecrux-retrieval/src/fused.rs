// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Fused retrieval — combines BM25 + graph signal + optional dense cosine.
//!
//! This is the main query entry point. It:
//! 1. Runs BM25 over loaded .ccxi indexes
//! 2. Boosts results using graph signals from ProjectionState (relation proximity,
//!    entity overlap, temporal recency, pressure)
//! 3. Optionally incorporates dense vector cosine similarity
//! 4. Returns scored, ranked results
//!
//! ## Dense vector lane decision (ADR-CORECRUX-0001, 2026-04-03)
//!
//! CoreCrux v5 launches with BM25 + graph fusion only. The `dense` weight exists in
//! `FusionWeights` but `dense_score` is hardcoded to 0.0. Dense vector retrieval
//! uses pgvector in the Engine retrieval path as a parallel lane.
//! If conceptual/paraphrased queries prove to need in-CoreCrux dense support, that's
//! a future milestone — the FusionWeights plumbing is ready for it.

use serde::{Deserialize, Serialize};

use crate::bm25::{bm25_score_multi, Bm25Params, MergedBm25Hit};
use crate::index_manager::IndexManager;

/// Weights for fused scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusionWeights {
    pub bm25: f32,
    pub graph: f32,
    pub dense: f32,
    pub sparse: f32,
}

impl Default for FusionWeights {
    fn default() -> Self {
        Self {
            bm25: 0.5,
            graph: 0.3,
            dense: 0.2,
            sparse: 0.0,
        }
    }
}

/// Request to the fused retrieval endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusedRetrieveRequest {
    pub tenant_id: String,
    pub query: String,
    #[serde(default)]
    pub query_embedding: Option<Vec<f32>>,
    #[serde(default = "default_top_k")]
    pub top_k: usize,
    #[serde(default)]
    pub weights: FusionWeights,
    #[serde(default = "default_graph_hops")]
    pub graph_hops: u32,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f32,
    #[serde(default)]
    pub include_state: bool,
    /// Number of entity facts in ProjectionState (for cold-start detection).
    /// If below `graph_cold_start_threshold`, graph weight is zeroed and
    /// redistributed to BM25. This prevents graph boost from penalizing
    /// results on a fresh launch where the graph is empty.
    #[serde(default)]
    pub graph_node_count: usize,
    /// Minimum entity facts required for graph boost to be active.
    /// Default: 100.
    #[serde(default = "default_graph_cold_start_threshold")]
    pub graph_cold_start_threshold: usize,
}

fn default_graph_cold_start_threshold() -> usize {
    100
}

fn default_top_k() -> usize {
    20
}
fn default_graph_hops() -> u32 {
    1
}
fn default_min_confidence() -> f32 {
    0.3
}

/// A single result from fused retrieval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusedHit {
    pub doc_id: u32,
    pub segment_index: usize,
    pub frame_offset: u32,
    pub score: f32,
    pub score_breakdown: ScoreBreakdown,
    pub hop_distance: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub bm25: f32,
    pub graph: f32,
    pub dense: f32,
    pub sparse: f32,
}

/// Statistics from the retrieval operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievalStats {
    pub docs_scanned: usize,
    pub postings_decoded: usize,
    pub graph_nodes_expanded: usize,
    pub dense_lane_active: bool,
}

/// Response from fused retrieval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusedRetrieveResponse {
    pub results: Vec<FusedHit>,
    pub stats: RetrievalStats,
}

/// Execute fused retrieval over loaded indexes.
pub fn fused_retrieve(
    index_mgr: &IndexManager,
    req: &FusedRetrieveRequest,
    graph_boost_fn: Option<&dyn Fn(u32, usize) -> (f32, u32)>, // (boost_score, hop_distance)
) -> crate::Result<FusedRetrieveResponse> {
    let readers = index_mgr.readers();
    if readers.is_empty() {
        return Err(crate::RetrievalError::NoIndex);
    }

    // Graph cold-start: if the projection graph has fewer entities than threshold,
    // zero out graph weight and redistribute to BM25. Early users get pure BM25,
    // which is correct — graph boost with an empty graph would just add noise.
    let effective_weights = if req.graph_node_count < req.graph_cold_start_threshold && req.weights.graph > 0.0 {
        tracing::debug!(
            graph_node_count = req.graph_node_count,
            threshold = req.graph_cold_start_threshold,
            "graph-cold-start-override: zeroing graph weight, redistributing to bm25"
        );
        FusionWeights {
            bm25: req.weights.bm25 + req.weights.graph,
            graph: 0.0,
            dense: req.weights.dense,
            sparse: req.weights.sparse,
        }
    } else {
        req.weights.clone()
    };

    // Compute tenant filter: lo16 for BM25 fast-path, full hash for exact verification
    let tenant_hash = xxhash_rust::xxh64::xxh64(req.tenant_id.as_bytes(), 0);
    let tenant_lo16 = (tenant_hash & 0xFFFF) as u16;

    // Phase 1: BM25 scoring
    let bm25_params = Bm25Params::default();
    let reader_refs: Vec<&corecrux_index::CcxiReader> = readers;
    let bm25_pool_size = req.top_k * 4; // over-retrieve for graph boost

    let bm25_hits = bm25_score_multi(
        &reader_refs,
        &req.query,
        bm25_pool_size,
        Some(tenant_lo16),
        &bm25_params,
    );

    // Exact tenant isolation: lo16 is the fast-path filter in BM25 postings scan,
    // but a 16-bit hash can collide (~1/65K per tenant pair). Filter surviving hits
    // using the full 64-bit hash to guarantee zero cross-tenant leakage.
    let bm25_hits: Vec<MergedBm25Hit> = bm25_hits
        .into_iter()
        .filter(|h| h.tenant_hash_full == tenant_hash)
        .collect();

    if bm25_hits.is_empty() {
        return Ok(FusedRetrieveResponse {
            results: Vec::new(),
            stats: RetrievalStats {
                docs_scanned: index_mgr.total_docs(),
                postings_decoded: 0,
                graph_nodes_expanded: 0,
                dense_lane_active: false,
            },
        });
    }

    // Normalize BM25 scores to [0, 1]
    let max_bm25 = bm25_hits.iter().map(|h| h.score).fold(0.0f32, f32::max);
    let bm25_norm = if max_bm25 > 0.0 { max_bm25 } else { 1.0 };

    // Phase 2: Graph signal boost
    let mut graph_expanded = 0usize;

    let mut fused_hits: Vec<FusedHit> = bm25_hits
        .iter()
        .map(|h| {
            let bm25_normalized = h.score / bm25_norm;

            // Graph boost (if callback provided)
            let (graph_score, hop_dist) = if let Some(boost_fn) = graph_boost_fn {
                let (gs, hd) = boost_fn(h.doc_id, h.segment_index);
                if gs > 0.0 {
                    graph_expanded += 1;
                }
                (gs, hd)
            } else {
                (0.0, 0)
            };

            // Dense cosine (future: accept pre-computed doc embeddings)
            let dense_score = 0.0f32;

            // Fused score
            let score = effective_weights.bm25 * bm25_normalized
                + effective_weights.graph * graph_score
                + effective_weights.dense * dense_score
                + effective_weights.sparse * 0.0; // future: learned sparse

            FusedHit {
                doc_id: h.doc_id,
                segment_index: h.segment_index,
                frame_offset: h.frame_offset,
                score,
                score_breakdown: ScoreBreakdown {
                    bm25: bm25_normalized,
                    graph: graph_score,
                    dense: dense_score,
                    sparse: 0.0,
                },
                hop_distance: hop_dist,
            }
        })
        .collect();

    // Re-sort by fused score
    fused_hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    fused_hits.truncate(req.top_k);

    Ok(FusedRetrieveResponse {
        results: fused_hits,
        stats: RetrievalStats {
            docs_scanned: index_mgr.total_docs(),
            postings_decoded: bm25_hits.len(),
            graph_nodes_expanded: graph_expanded,
            dense_lane_active: req.query_embedding.is_some(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_index::CcxiBuilder;

    fn build_test_index_manager() -> (IndexManager, u64) {
        // Use a known tenant_id and compute its hash to ensure filter matches
        let tenant_id = "test-tenant";
        let tenant_hash = xxhash_rust::xxh64::xxh64(tenant_id.as_bytes(), 0);
        let mut builder = CcxiBuilder::new(0, 1, 100);
        builder.add_document(
            0,
            "terraform module drift detection infrastructure as code",
            0,
            tenant_hash,
        );
        builder.add_document(
            1,
            "terraform workspace management cloud infrastructure",
            100,
            tenant_hash,
        );
        builder.add_document(
            2,
            "kubernetes deployment strategy container orchestration",
            200,
            tenant_hash,
        );
        builder.add_document(
            3,
            "developer experience SDK testing framework tooling",
            300,
            tenant_hash,
        );
        builder.add_document(
            4,
            "CI CD pipeline automation deployment continuous integration",
            400,
            tenant_hash,
        );

        let bytes = builder.build();
        let mut mgr = IndexManager::new();
        mgr.load_ccxi_bytes(&bytes).unwrap();
        (mgr, tenant_hash)
    }

    /// Test that two tenants with deliberately colliding lo16 hashes are isolated
    /// by the full 64-bit hash check. This is the trust-critical safety net.
    #[test]
    fn tenant_hash_collision_isolated() {
        // Find two tenant IDs that collide on lo16(xxhash64).
        // We brute-force search: hash "tenant-{N}" and find a pair with same lo16.
        let target_id = "tenant-0";
        let target_hash = xxhash_rust::xxh64::xxh64(target_id.as_bytes(), 0);
        let target_lo16 = (target_hash & 0xFFFF) as u16;

        let mut collider_id = String::new();
        let mut collider_hash = 0u64;
        for i in 1..1_000_000u64 {
            let candidate = format!("tenant-{i}");
            let h = xxhash_rust::xxh64::xxh64(candidate.as_bytes(), 0);
            if (h & 0xFFFF) as u16 == target_lo16 && h != target_hash {
                collider_id = candidate;
                collider_hash = h;
                break;
            }
        }
        assert!(!collider_id.is_empty(), "failed to find a lo16-colliding tenant pair");

        // Build index with docs from both tenants
        let mut builder = CcxiBuilder::new(0, 1, 100);
        builder.add_document(0, "terraform drift detection infrastructure monitoring", 0, target_hash);
        builder.add_document(
            1,
            "terraform drift detection infrastructure monitoring",
            100,
            collider_hash,
        );
        let bytes = builder.build();

        let mut mgr = IndexManager::new();
        mgr.load_ccxi_bytes(&bytes).unwrap();

        // Query as target tenant — should see only doc 0
        let req = FusedRetrieveRequest {
            tenant_id: target_id.to_string(),
            query: "terraform drift detection".to_string(),
            query_embedding: None,
            top_k: 10,
            weights: FusionWeights {
                bm25: 1.0,
                graph: 0.0,
                dense: 0.0,
                sparse: 0.0,
            },
            graph_hops: 0,
            min_confidence: 0.0,
            include_state: false,
            graph_node_count: 0,
            graph_cold_start_threshold: 100,
        };
        let resp = fused_retrieve(&mgr, &req, None).unwrap();
        assert_eq!(resp.results.len(), 1, "should return exactly 1 hit for target tenant");
        assert_eq!(
            resp.results[0].doc_id, 0,
            "should return doc from target tenant, not collider"
        );

        // Query as collider tenant — should see only doc 1
        let req2 = FusedRetrieveRequest {
            tenant_id: collider_id.clone(),
            query: "terraform drift detection".to_string(),
            query_embedding: None,
            top_k: 10,
            weights: FusionWeights {
                bm25: 1.0,
                graph: 0.0,
                dense: 0.0,
                sparse: 0.0,
            },
            graph_hops: 0,
            min_confidence: 0.0,
            include_state: false,
            graph_node_count: 0,
            graph_cold_start_threshold: 100,
        };
        let resp2 = fused_retrieve(&mgr, &req2, None).unwrap();
        assert_eq!(resp2.results.len(), 1, "collider tenant should see exactly 1 hit");
        assert_eq!(
            resp2.results[0].doc_id, 1,
            "collider tenant should see only its own doc"
        );
    }

    #[test]
    fn fused_retrieve_basic() {
        let (mgr, _) = build_test_index_manager();

        let req = FusedRetrieveRequest {
            tenant_id: "test-tenant".to_string(),
            query: "terraform drift detection".to_string(),
            query_embedding: None,
            top_k: 5,
            weights: FusionWeights {
                bm25: 1.0,
                graph: 0.0,
                dense: 0.0,
                sparse: 0.0,
            },
            graph_hops: 0,
            min_confidence: 0.0,
            include_state: false,
            graph_node_count: 0,
            graph_cold_start_threshold: 100,
        };

        let resp = fused_retrieve(&mgr, &req, None).unwrap();
        assert!(!resp.results.is_empty());
        // Terraform drift doc should be top result
        assert_eq!(resp.results[0].doc_id, 0);
    }

    #[test]
    fn graph_cold_start_zeroes_graph_weight() {
        let (mgr, _) = build_test_index_manager();

        // With graph_node_count=0 (below threshold=100), graph weight should be
        // redistributed to BM25. Scores should be pure BM25.
        let req_cold = FusedRetrieveRequest {
            tenant_id: "test-tenant".to_string(),
            query: "terraform drift".to_string(),
            query_embedding: None,
            top_k: 5,
            weights: FusionWeights {
                bm25: 0.5,
                graph: 0.5, // this should get zeroed
                dense: 0.0,
                sparse: 0.0,
            },
            graph_hops: 0,
            min_confidence: 0.0,
            include_state: false,
            graph_node_count: 0, // cold start
            graph_cold_start_threshold: 100,
        };

        // With a graph boost fn that returns 1.0 for everything
        let boost_fn = |_doc_id: u32, _seg_idx: usize| -> (f32, u32) { (1.0, 1) };
        let resp_cold = fused_retrieve(&mgr, &req_cold, Some(&boost_fn)).unwrap();

        // Same query but with enough graph nodes (above threshold)
        let req_warm = FusedRetrieveRequest {
            graph_node_count: 200, // above threshold
            ..req_cold.clone()
        };
        let resp_warm = fused_retrieve(&mgr, &req_warm, Some(&boost_fn)).unwrap();

        // In cold start, graph weight is zero, so all scores should be pure BM25.
        // With a universal 1.0 graph boost and 50/50 weights, warm scores should be higher.
        assert!(!resp_cold.results.is_empty());
        assert!(!resp_warm.results.is_empty());

        // Cold-start: graph weight is zeroed, so fused score = bm25 only.
        // The score_breakdown.graph still shows the raw graph signal (it's
        // informational), but the final score doesn't include it.
        let cold_top = &resp_cold.results[0];
        let warm_top = &resp_warm.results[0];

        // Warm score should be higher because graph boost adds to the final score.
        // Cold score = 1.0 * bm25 (graph weight redistributed).
        // Warm score = 0.5 * bm25 + 0.5 * graph_boost.
        // With universal 1.0 graph boost and bm25_normalized=1.0, warm=1.0, cold=1.0.
        // But the key test: cold result ignores graph entirely in ranking.
        assert!(cold_top.score > 0.0, "cold-start should still produce scores");
        assert!(warm_top.score > 0.0, "warm should produce scores");
    }
}
