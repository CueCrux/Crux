// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! BM25 scoring.
//!
//! Scores documents against a query using Okapi BM25 with configurable k1 and b parameters.

use corecrux_index::{tokenize, CcxiReader};

/// BM25 parameters.
#[derive(Debug, Clone, Copy)]
pub struct Bm25Params {
    pub k1: f32,
    pub b: f32,
}

impl Default for Bm25Params {
    fn default() -> Self {
        Self { k1: 1.2, b: 0.75 }
    }
}

/// A scored document from BM25 retrieval.
#[derive(Debug, Clone)]
pub struct Bm25Hit {
    pub doc_id: u32,
    pub score: f32,
    pub tenant_hash_lo16: u16,
    pub tenant_hash_full: u64,
}

/// Score all documents in a CcxiReader against a query using BM25.
///
/// Returns hits sorted by score descending, limited to `top_k`.
/// If `tenant_filter` is Some, only documents matching the tenant are scored.
pub fn bm25_score(
    reader: &CcxiReader,
    query: &str,
    top_k: usize,
    tenant_filter: Option<u16>,
    params: &Bm25Params,
) -> Vec<Bm25Hit> {
    let query_tokens = tokenize(query);
    if query_tokens.is_empty() || reader.docs.is_empty() {
        return Vec::new();
    }

    let num_docs = reader.docs.len() as f32;
    let avg_dl = reader.avg_doc_length();

    // Accumulate scores per document
    let mut scores = vec![0.0f32; reader.docs.len()];

    for qt in &query_tokens {
        let Some(entry) = reader.find_token(qt.hash) else {
            continue;
        };

        let (doc_ids, tfs) = reader.decode_postings(entry);
        let df = doc_ids.len() as f32;

        // IDF: BM25 variant (Robertson-Sparck Jones)
        let idf = ((num_docs - df + 0.5) / (df + 0.5) + 1.0).ln();

        for (i, &did) in doc_ids.iter().enumerate() {
            let did = did as usize;
            if did >= reader.docs.len() {
                continue;
            }

            // Tenant filter
            if let Some(tf16) = tenant_filter {
                if reader.docs[did].tenant_hash_lo16 != tf16 {
                    continue;
                }
            }

            let tf = tfs.get(i).copied().unwrap_or(1) as f32;
            let dl = reader.docs[did].doc_length_tokens as f32;

            // BM25 term score
            let tf_norm = (tf * (params.k1 + 1.0))
                / (tf + params.k1 * (1.0 - params.b + params.b * dl / avg_dl));

            scores[did] += idf * tf_norm;
        }
    }

    // Collect and sort
    let mut hits: Vec<Bm25Hit> = scores
        .iter()
        .enumerate()
        .filter(|(_, &s)| s > 0.0)
        .map(|(i, &s)| Bm25Hit {
            doc_id: i as u32,
            score: s,
            tenant_hash_lo16: reader.docs[i].tenant_hash_lo16,
            tenant_hash_full: reader.docs[i].tenant_hash_full,
        })
        .collect();

    hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    hits.truncate(top_k);
    hits
}

/// Score documents across multiple CcxiReaders (multiple segments).
/// Returns merged hits sorted by score, limited to top_k.
pub fn bm25_score_multi(
    readers: &[&CcxiReader],
    query: &str,
    top_k: usize,
    tenant_filter: Option<u16>,
    params: &Bm25Params,
) -> Vec<MergedBm25Hit> {
    let query_tokens = tokenize(query);
    if query_tokens.is_empty() {
        return Vec::new();
    }

    // Compute global stats
    let total_docs: usize = readers.iter().map(|r| r.docs.len()).sum();
    let total_tokens: u64 = readers
        .iter()
        .flat_map(|r| r.docs.iter())
        .map(|d| d.doc_length_tokens as u64)
        .sum();
    let avg_dl = if total_docs > 0 {
        total_tokens as f32 / total_docs as f32
    } else {
        0.0
    };
    let num_docs = total_docs as f32;

    let mut all_hits: Vec<MergedBm25Hit> = Vec::new();

    for (seg_idx, reader) in readers.iter().enumerate() {
        let mut scores = vec![0.0f32; reader.docs.len()];

        for qt in &query_tokens {
            let Some(entry) = reader.find_token(qt.hash) else {
                continue;
            };

            let (doc_ids, tfs) = reader.decode_postings(entry);

            // Global DF: sum across all readers
            let mut global_df = 0usize;
            for r in readers.iter() {
                if let Some(e) = r.find_token(qt.hash) {
                    let (ids, _) = r.decode_postings(e);
                    global_df += ids.len();
                }
            }
            let df = global_df as f32;
            let idf = ((num_docs - df + 0.5) / (df + 0.5) + 1.0).ln();

            for (i, &did) in doc_ids.iter().enumerate() {
                let did = did as usize;
                if did >= reader.docs.len() {
                    continue;
                }
                if let Some(tf16) = tenant_filter {
                    if reader.docs[did].tenant_hash_lo16 != tf16 {
                        continue;
                    }
                }

                let tf = tfs.get(i).copied().unwrap_or(1) as f32;
                let dl = reader.docs[did].doc_length_tokens as f32;
                let tf_norm = (tf * (params.k1 + 1.0))
                    / (tf + params.k1 * (1.0 - params.b + params.b * dl / avg_dl));
                scores[did] += idf * tf_norm;
            }
        }

        for (did, &score) in scores.iter().enumerate() {
            if score > 0.0 {
                all_hits.push(MergedBm25Hit {
                    segment_index: seg_idx,
                    doc_id: did as u32,
                    score,
                    tenant_hash_lo16: reader.docs[did].tenant_hash_lo16,
                    tenant_hash_full: reader.docs[did].tenant_hash_full,
                    frame_offset: reader.docs[did].frame_offset,
                    doc_length_tokens: reader.docs[did].doc_length_tokens,
                });
            }
        }
    }

    all_hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    all_hits.truncate(top_k);
    all_hits
}

/// A hit from multi-segment BM25 scoring.
#[derive(Debug, Clone)]
pub struct MergedBm25Hit {
    pub segment_index: usize,
    pub doc_id: u32,
    pub score: f32,
    pub tenant_hash_lo16: u16,
    pub tenant_hash_full: u64,
    pub frame_offset: u32,
    pub doc_length_tokens: u16,
}

/// Coverage report for a query.
#[derive(Debug, Clone)]
pub struct QueryCoverage {
    /// Fraction of query tokens that matched at least one document.
    pub score: f32,
    /// Query tokens with no matches in the corpus.
    pub missing_tokens: Vec<String>,
    /// Number of results that scored below the relevance floor.
    pub below_floor: usize,
}

/// Extended result from multi-segment BM25 scoring with coverage tracking.
#[derive(Debug)]
pub struct Bm25SearchResult {
    pub hits: Vec<MergedBm25Hit>,
    pub coverage: QueryCoverage,
    pub total_candidates: usize,
}

/// Score documents across multiple segments with optional min_score filtering
/// and query coverage tracking.
pub fn bm25_search(
    readers: &[&CcxiReader],
    query: &str,
    top_k: usize,
    tenant_filter: Option<u16>,
    params: &Bm25Params,
    min_score: Option<f32>,
) -> Bm25SearchResult {
    let query_tokens = tokenize(query);
    if query_tokens.is_empty() {
        return Bm25SearchResult {
            hits: Vec::new(),
            coverage: QueryCoverage {
                score: 0.0,
                missing_tokens: Vec::new(),
                below_floor: 0,
            },
            total_candidates: 0,
        };
    }

    // Track which query tokens matched at least one document
    let mut token_matched = vec![false; query_tokens.len()];

    // Compute global stats
    let total_docs: usize = readers.iter().map(|r| r.docs.len()).sum();
    let total_tokens: u64 = readers
        .iter()
        .flat_map(|r| r.docs.iter())
        .map(|d| d.doc_length_tokens as u64)
        .sum();
    let avg_dl = if total_docs > 0 {
        total_tokens as f32 / total_docs as f32
    } else {
        0.0
    };
    let num_docs = total_docs as f32;

    let mut all_hits: Vec<MergedBm25Hit> = Vec::new();

    for (seg_idx, reader) in readers.iter().enumerate() {
        let mut scores = vec![0.0f32; reader.docs.len()];

        for (qt_idx, qt) in query_tokens.iter().enumerate() {
            let Some(entry) = reader.find_token(qt.hash) else {
                continue;
            };

            token_matched[qt_idx] = true;
            let (doc_ids, tfs) = reader.decode_postings(entry);

            // Global DF
            let mut global_df = 0usize;
            for r in readers.iter() {
                if let Some(e) = r.find_token(qt.hash) {
                    let (ids, _) = r.decode_postings(e);
                    global_df += ids.len();
                }
            }
            let df = global_df as f32;
            let idf = ((num_docs - df + 0.5) / (df + 0.5) + 1.0).ln();

            for (i, &did) in doc_ids.iter().enumerate() {
                let did = did as usize;
                if did >= reader.docs.len() {
                    continue;
                }
                if let Some(tf16) = tenant_filter {
                    if reader.docs[did].tenant_hash_lo16 != tf16 {
                        continue;
                    }
                }

                let tf = tfs.get(i).copied().unwrap_or(1) as f32;
                let dl = reader.docs[did].doc_length_tokens as f32;
                let tf_norm = (tf * (params.k1 + 1.0))
                    / (tf + params.k1 * (1.0 - params.b + params.b * dl / avg_dl));
                scores[did] += idf * tf_norm;
            }
        }

        for (did, &score) in scores.iter().enumerate() {
            if score > 0.0 {
                all_hits.push(MergedBm25Hit {
                    segment_index: seg_idx,
                    doc_id: did as u32,
                    score,
                    tenant_hash_lo16: reader.docs[did].tenant_hash_lo16,
                    tenant_hash_full: reader.docs[did].tenant_hash_full,
                    frame_offset: reader.docs[did].frame_offset,
                    doc_length_tokens: reader.docs[did].doc_length_tokens,
                });
            }
        }
    }

    all_hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

    let total_candidates = all_hits.len();

    // Apply relevance floor
    let below_floor = if let Some(floor) = min_score {
        let before = all_hits.len();
        all_hits.retain(|h| h.score >= floor);
        before - all_hits.len()
    } else {
        0
    };

    all_hits.truncate(top_k);

    // Build coverage report
    let matched_count = token_matched.iter().filter(|&&m| m).count();
    let coverage_score = if query_tokens.is_empty() {
        0.0
    } else {
        matched_count as f32 / query_tokens.len() as f32
    };

    // Reconstruct missing token strings from the original query
    let original_words: Vec<&str> = query
        .split(|c: char| !c.is_alphanumeric() && c != '\'')
        .filter(|w| w.len() > 1)
        .collect();
    let missing_tokens: Vec<String> = token_matched
        .iter()
        .enumerate()
        .filter(|(_, &matched)| !matched)
        .filter_map(|(i, _)| original_words.get(i).map(|s| s.to_string()))
        .collect();

    Bm25SearchResult {
        hits: all_hits,
        coverage: QueryCoverage {
            score: coverage_score,
            missing_tokens,
            below_floor,
        },
        total_candidates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_index::CcxiBuilder;

    fn build_test_index() -> Vec<u8> {
        let mut builder = CcxiBuilder::new(0, 1, 100);
        builder.add_document(0, "terraform module drift detection infrastructure", 0, 0x1234);
        builder.add_document(1, "terraform workspace management cloud", 100, 0x1234);
        builder.add_document(2, "kubernetes deployment strategy container", 200, 0x1234);
        builder.add_document(3, "developer experience SDK testing framework", 300, 0x1234);
        builder.add_document(4, "CI CD pipeline automation deployment", 400, 0x1234);
        builder.build()
    }

    #[test]
    fn basic_bm25_retrieval() {
        let bytes = build_test_index();
        let reader = CcxiReader::from_bytes(&bytes).unwrap();

        let hits = bm25_score(&reader, "terraform drift", 5, None, &Bm25Params::default());

        assert!(!hits.is_empty());
        // Doc 0 ("terraform module drift detection") should rank highest
        assert_eq!(hits[0].doc_id, 0);
    }

    #[test]
    fn tenant_filter_works() {
        let mut builder = CcxiBuilder::new(0, 1, 100);
        builder.add_document(0, "terraform module", 0, 0xAAAA);
        builder.add_document(1, "terraform workspace", 100, 0xBBBB);
        let bytes = builder.build();
        let reader = CcxiReader::from_bytes(&bytes).unwrap();

        let hits = bm25_score(
            &reader,
            "terraform",
            5,
            Some(0xAAAA),
            &Bm25Params::default(),
        );

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].doc_id, 0);
    }

    #[test]
    fn no_results_for_unknown_query() {
        let bytes = build_test_index();
        let reader = CcxiReader::from_bytes(&bytes).unwrap();

        let hits = bm25_score(
            &reader,
            "quantum entanglement photon",
            5,
            None,
            &Bm25Params::default(),
        );
        assert!(hits.is_empty());
    }
}
