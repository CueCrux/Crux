// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Cat 12 validation — tests the fused retrieval engine against the Engine v4 audit
//! category 12 (hard-negative overlap) corpus and ground truth.
//!
//! This is a standalone integration test that:
//! 1. Loads the cat 12 corpus (53 docs, 36 queries, 4 parent-child relations)
//! 2. Builds a .ccxi index
//! 3. Runs each ground truth query through BM25 + (optionally) graph fusion
//! 4. Scores recall and precision against expected document IDs
//! 5. Reports per-theme and overall metrics

use std::collections::HashMap;

use serde::Deserialize;

use corecrux_index::CcxiBuilder;
use corecrux_retrieval::bm25::{bm25_score, Bm25Params};
use corecrux_retrieval::fused::{fused_retrieve, FusedRetrieveRequest, FusionWeights};
use corecrux_retrieval::index_manager::IndexManager;

#[derive(Deserialize)]
struct Corpus {
    corpus: Vec<Doc>,
    queries: Vec<Query>,
    relations: Vec<Relation>,
}

#[derive(Deserialize)]
struct Doc {
    id: String,
    title: String,
    content: String,
    #[allow(dead_code)]
    domain: String,
    #[serde(rename = "tenantId")]
    #[allow(dead_code)]
    tenant_id: String,
}

#[derive(Deserialize)]
struct Query {
    query: String,
    #[serde(rename = "expectedDocIds")]
    expected_doc_ids: Vec<String>,
    #[serde(rename = "topK")]
    top_k: usize,
}

#[derive(Deserialize)]
struct Relation {
    #[serde(rename = "srcId")]
    src_id: String,
    #[serde(rename = "dstId")]
    dst_id: String,
    #[serde(rename = "relationType")]
    #[allow(dead_code)]
    relation_type: String,
}

fn load_corpus() -> Corpus {
    let json = include_str!("cat12-corpus.json");
    serde_json::from_str(json).expect("parse cat12 corpus")
}

#[test]
fn cat12_bm25_recall() {
    let corpus = load_corpus();
    eprintln!(
        "Cat 12 corpus: {} docs, {} queries, {} relations",
        corpus.corpus.len(),
        corpus.queries.len(),
        corpus.relations.len()
    );

    // Build a doc_id → corpus index mapping
    let mut id_to_idx: HashMap<String, u32> = HashMap::new();
    let mut idx_to_id: HashMap<u32, String> = HashMap::new();

    // Use a fixed tenant hash for all docs
    let tenant_id = "__audit_v4__";
    let tenant_hash = xxhash_rust::xxh64::xxh64(tenant_id.as_bytes(), 0);

    // Build the .ccxi index
    let mut builder = CcxiBuilder::new(0, 1, 100);
    for (i, doc) in corpus.corpus.iter().enumerate() {
        let idx = i as u32;
        id_to_idx.insert(doc.id.clone(), idx);
        idx_to_id.insert(idx, doc.id.clone());

        // Index title + content together
        let text = format!("{}\n{}", doc.title, doc.content);
        builder.add_document(idx, &text, (i * 100) as u32, tenant_hash);
    }

    let bytes = builder.build();
    let reader = corecrux_index::CcxiReader::from_bytes(&bytes).expect("parse .ccxi");

    eprintln!(
        "Index: {} vocab entries, {} docs, avg_dl={:.1}",
        reader.vocab.len(),
        reader.docs.len(),
        reader.avg_doc_length()
    );

    // Run queries and measure recall
    let params = Bm25Params::default();
    let mut total_recall = 0.0f64;
    let mut total_precision = 0.0f64;
    let mut query_count = 0;

    // Theme-based tracking
    let mut theme_hits: HashMap<&str, (usize, usize)> = HashMap::new(); // theme → (hits, total_expected)

    for (qi, q) in corpus.queries.iter().enumerate() {
        let hits = bm25_score(&reader, &q.query, q.top_k, Some(tenant_hash), &params);

        let retrieved_ids: Vec<String> = hits.iter().filter_map(|h| idx_to_id.get(&h.doc_id).cloned()).collect();

        let expected_set: std::collections::HashSet<&str> = q.expected_doc_ids.iter().map(|s| s.as_str()).collect();

        let hits_in_expected = retrieved_ids
            .iter()
            .filter(|id| expected_set.contains(id.as_str()))
            .count();

        let recall = if expected_set.is_empty() {
            1.0
        } else {
            hits_in_expected as f64 / expected_set.len() as f64
        };

        let precision = if retrieved_ids.is_empty() {
            0.0
        } else {
            hits_in_expected as f64 / retrieved_ids.len() as f64
        };

        total_recall += recall;
        total_precision += precision;
        query_count += 1;

        // Classify query into theme
        let theme = if qi < 6 {
            "IaC discrimination"
        } else if qi < 12 {
            "DevEx discrimination"
        } else if qi < 18 {
            "Overlap zone"
        } else if qi < 27 {
            "Version precision"
        } else {
            "Parent/child"
        };

        let entry = theme_hits.entry(theme).or_insert((0, 0));
        entry.0 += hits_in_expected;
        entry.1 += expected_set.len();

        if recall < 1.0 {
            eprintln!(
                "  Q{:02} [{}] recall={:.2} | query: '{}...' | expected: {:?} | got: {:?}",
                qi,
                theme,
                recall,
                &q.query[..q.query.len().min(60)],
                q.expected_doc_ids,
                &retrieved_ids[..retrieved_ids.len().min(5)]
            );
        }
    }

    let avg_recall = total_recall / query_count as f64;
    let avg_precision = total_precision / query_count as f64;

    eprintln!("\n=== Cat 12 BM25-Only Results ===");
    eprintln!("Overall recall:    {:.3} (target ≥0.70)", avg_recall);
    eprintln!("Overall precision: {:.3} (target ≥0.80)", avg_precision);
    eprintln!("\nPer-theme recall:");
    for (theme, (hits, total)) in &theme_hits {
        let tr = if *total > 0 { *hits as f64 / *total as f64 } else { 1.0 };
        eprintln!("  {:<25} {}/{} = {:.3}", theme, hits, total, tr);
    }

    // Assert baseline quality
    assert!(
        avg_recall >= 0.40,
        "BM25-only recall {avg_recall:.3} is below minimum threshold 0.40"
    );
}

#[test]
fn cat12_fused_retrieve() {
    let corpus = load_corpus();

    let tenant_id = "__audit_v4__";
    let tenant_hash = xxhash_rust::xxh64::xxh64(tenant_id.as_bytes(), 0);

    let mut id_to_idx: HashMap<String, u32> = HashMap::new();
    let mut idx_to_id: HashMap<u32, String> = HashMap::new();

    let mut builder = CcxiBuilder::new(0, 1, 100);
    for (i, doc) in corpus.corpus.iter().enumerate() {
        let idx = i as u32;
        id_to_idx.insert(doc.id.clone(), idx);
        idx_to_id.insert(idx, doc.id.clone());
        let text = format!("{}\n{}", doc.title, doc.content);
        builder.add_document(idx, &text, (i * 100) as u32, tenant_hash);
    }

    let bytes = builder.build();
    let mut mgr = IndexManager::new();
    mgr.load_ccxi_bytes(&bytes).unwrap();

    // Build a simple graph boost function from relations
    let mut relation_map: HashMap<u32, Vec<u32>> = HashMap::new();
    for rel in &corpus.relations {
        if let (Some(&src), Some(&dst)) = (id_to_idx.get(&rel.src_id), id_to_idx.get(&rel.dst_id)) {
            relation_map.entry(src).or_default().push(dst);
            relation_map.entry(dst).or_default().push(src);
        }
    }

    let mut total_recall = 0.0f64;
    let mut query_count = 0;

    for q in &corpus.queries {
        let req = FusedRetrieveRequest {
            tenant_id: tenant_id.to_string(),
            query: q.query.clone(),
            query_embedding: None,
            top_k: q.top_k,
            weights: FusionWeights {
                bm25: 0.7,
                graph: 0.3,
                dense: 0.0,
                sparse: 0.0,
            },
            graph_hops: 1,
            min_confidence: 0.3,
            include_state: false,
            graph_node_count: 1000, // above cold-start threshold
            graph_cold_start_threshold: 100,
        };

        // Graph boost: if a BM25 hit is related to another hit, boost both
        let graph_boost = |doc_id: u32, _seg_idx: usize| -> (f32, u32) {
            if let Some(_related) = relation_map.get(&doc_id) {
                // Has relations — boost it
                (0.5, 1)
            } else {
                (0.0, 0)
            }
        };

        let resp = fused_retrieve(&mgr, &req, Some(&graph_boost), None).unwrap();

        let retrieved_ids: Vec<String> = resp
            .results
            .iter()
            .filter_map(|h| idx_to_id.get(&h.doc_id).cloned())
            .collect();

        let expected_set: std::collections::HashSet<&str> = q.expected_doc_ids.iter().map(|s| s.as_str()).collect();

        let hits_in_expected = retrieved_ids
            .iter()
            .filter(|id| expected_set.contains(id.as_str()))
            .count();

        let recall = if expected_set.is_empty() {
            1.0
        } else {
            hits_in_expected as f64 / expected_set.len() as f64
        };

        total_recall += recall;
        query_count += 1;
    }

    let avg_recall = total_recall / query_count as f64;
    eprintln!("\n=== Cat 12 Fused (BM25 + Graph) Results ===");
    eprintln!("Overall recall: {:.3} (target ≥0.70)", avg_recall);

    assert!(
        avg_recall >= 0.40,
        "Fused recall {avg_recall:.3} is below minimum threshold 0.40"
    );
}
