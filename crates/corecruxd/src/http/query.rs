// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Retrieval routes — `/v1/query/text-search`, `/text-search/expand`, `/graph-expand`, `/time-range`.
//!
//! Text search is available by default; set `CORECRUXD_QUERY_TEXT_SEARCH=0`
//! or `false` to make both text-search routes return 404. Graph expansion and
//! time-range queries remain opt-in.

use super::*;
use corecrux_memory::semantic::{
    MIXED_PROFILE_MERGE_RULE, SCORE_MERGE_RULE_SINGLE_SPACE, SCORE_MERGE_RULE_WEIGHTED_LINEAR,
    SCORE_SPACE_BM25_DENSE_FUSED, SCORE_SPACE_BM25_LEXICAL,
};

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub(super) struct GraphExpandBody {
    pub(super) tenant_id: String,
    pub(super) seed_artifact_ids: Vec<u32>,
    #[serde(default)]
    pub(super) edge_types: Vec<String>,
    #[serde(default = "default_max_hops")]
    pub(super) max_hops: u32,
    #[serde(default = "default_budget")]
    pub(super) budget: usize,
    #[serde(default)]
    pub(super) min_confidence: f32,
    #[serde(default)]
    pub(super) include_state: bool,
}

pub(super) fn default_max_hops() -> u32 {
    2
}
pub(super) fn default_budget() -> usize {
    50
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub(super) struct TimeRangeBody {
    pub(super) tenant_id: String,
    pub(super) start_micros: i64,
    pub(super) end_micros: i64,
    #[serde(default)]
    pub(super) artifact_ids: Vec<u32>,
    #[serde(default)]
    pub(super) include_relations: bool,
    #[serde(default = "default_time_range_limit")]
    pub(super) limit: usize,
}

pub(super) fn default_time_range_limit() -> usize {
    100
}

fn tenant_hash(tenant_id: &str) -> u64 {
    xxhash_rust::xxh64::xxh64(tenant_id.as_bytes(), 0)
}

// Same axum-Response-is-large-by-clippy issue as the helpers in
// http::facts. The Err arm is the idiomatic carry-the-built-response
// shape; suppress at the helper boundary so call sites stay clean.
#[allow(clippy::result_large_err)]
fn authorize_query_tenant(state: &AppState, headers: &HeaderMap, tenant_id: &str) -> Result<Option<u64>, Response> {
    let ctx = http_scope_context(&state.auth, headers).map_err(IntoResponse::into_response)?;
    let tenant_id = tenant_id.trim();

    if tenant_id.is_empty() {
        if ctx.has_scope("admin:read") {
            return Ok(None);
        }
        require_http_any_scope(&state.auth, headers, &["query:read"]).map_err(IntoResponse::into_response)?;
        return Err(problem_response(
            StatusCode::BAD_REQUEST,
            "tenant_id must not be empty for query:read",
        ));
    }

    if tenant_id == "*" {
        if ctx.has_scope("admin:read") {
            return Ok(None);
        }
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "tenant_id=* requires admin:read",
        ));
    }

    if ctx.has_scope("admin:read") {
        return Ok(Some(tenant_hash(tenant_id)));
    }

    require_http_scopes_for_tenant(&state.auth, headers, &["query:read"], tenant_id)
        .map_err(IntoResponse::into_response)?;
    Ok(Some(tenant_hash(tenant_id)))
}

#[allow(clippy::result_large_err)]
fn authorize_concrete_query_tenant(state: &AppState, headers: &HeaderMap, tenant_id: &str) -> Result<u64, Response> {
    match authorize_query_tenant(state, headers, tenant_id)? {
        Some(hash) => Ok(hash),
        None => Err(problem_response(
            StatusCode::BAD_REQUEST,
            "tenant_id must name one concrete tenant for this query route",
        )),
    }
}

fn delegated_stored_profile_problem(error: crate::local_ingest::DenseProfileCompatibilityError) -> Response {
    let detail = match error {
        crate::local_ingest::DenseProfileCompatibilityError::MissingProfile { .. } => {
            "A stored dense segment has no semantic profile, so compatibility with the remote provider cannot be proven."
        }
        crate::local_ingest::DenseProfileCompatibilityError::FingerprintMismatch { .. } => {
            "The remote provider semantic profile is incompatible with a stored dense segment; reindex with the configured model."
        }
        crate::local_ingest::DenseProfileCompatibilityError::InvalidProfile { .. } => {
            "A stored dense segment has a non-canonical semantic profile, so its vector identity cannot be trusted."
        }
        crate::local_ingest::DenseProfileCompatibilityError::DimensionMismatch { .. } => {
            "A stored dense segment's vector dimension disagrees with its semantic profile or the remote provider."
        }
        crate::local_ingest::DenseProfileCompatibilityError::InvalidVectorCompanion { .. } => {
            "A stored dense segment has a malformed or non-finite vector companion, so delegated scoring cannot proceed safely."
        }
    };
    embedding_semantic_profile_mismatch_response(detail)
}

// ── v4.2 query handlers ──────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/v1/query/graph-expand",
    tag = "Query",
    request_body = GraphExpandBody,
    responses(
        (status = 200, description = "Graph expand results"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Feature not enabled"),
    ),
    security(("bearer_auth" = []))
)]
#[tracing::instrument(level = "info", skip(state, headers, body), fields(tenant_id = %body.tenant_id))]
pub(super) async fn post_query_graph_expand(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GraphExpandBody>,
) -> impl IntoResponse {
    if let Err(response) = authorize_concrete_query_tenant(&state, &headers, &body.tenant_id) {
        return response;
    }

    if !is_query_feature_enabled("CORECRUXD_QUERY_GRAPH_EXPAND") {
        return problem_response(StatusCode::NOT_FOUND, "graph-expand query not enabled");
    }

    if !state.http_dataplane.enabled() {
        return platform_upgrade_response("graph_expand");
    }

    if body.seed_artifact_ids.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "seed_artifact_ids must not be empty");
    }

    let t0 = std::time::Instant::now();
    let combined = match state
        .http_dataplane
        .graph_expand(super::dataplane::GraphExpandRequest {
            tenant_id: &body.tenant_id,
            seed_artifact_ids: &body.seed_artifact_ids,
            edge_types: &body.edge_types,
            max_hops: body.max_hops,
            budget: body.budget,
            min_confidence: body.min_confidence,
            include_state: body.include_state,
        })
        .await
    {
        Ok(response) => response,
        Err(err) => return map_http_dataplane_error(err),
    };

    state
        .metrics
        .observe_graph_expand(t0.elapsed().as_secs_f64(), combined.stats.nodes_visited);

    #[derive(serde::Serialize)]
    struct Resp {
        artifacts: Vec<ArtifactResp>,
        traversal_stats: StatsResp,
    }
    #[derive(serde::Serialize)]
    struct ArtifactResp {
        artifact_id: u32,
        score: f32,
        hop_distance: u32,
        edge_types_used: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        state: Option<ArtifactStateResp>,
    }
    #[derive(serde::Serialize)]
    struct ArtifactStateResp {
        living_status: String,
        confidence: f32,
        updated_at_micros: i64,
        trunk_tier: u8,
    }
    #[derive(serde::Serialize)]
    struct StatsResp {
        nodes_visited: u32,
        hops_used: u32,
        budget_remaining: usize,
        edges_traversed: u64,
    }

    let stats = combined.stats;
    let artifacts: Vec<ArtifactResp> = combined
        .artifacts
        .into_iter()
        .map(|a| {
            let state_resp = a.state.map(|s| ArtifactStateResp {
                living_status: s.living_status.as_engine_str().to_string(),
                confidence: corecrux_projections::dequantize_confidence_f32(s.confidence_q16),
                updated_at_micros: s.updated_at_micros,
                trunk_tier: s.trunk_tier,
            });
            ArtifactResp {
                artifact_id: a.artifact_id,
                score: a.score,
                hop_distance: a.hop_distance,
                edge_types_used: a
                    .edge_types_used
                    .iter()
                    .map(|t| t.as_engine_str().to_string())
                    .collect(),
                state: state_resp,
            }
        })
        .collect();

    (
        StatusCode::OK,
        Json(Resp {
            artifacts,
            traversal_stats: StatsResp {
                nodes_visited: stats.nodes_visited,
                hops_used: stats.hops_used,
                budget_remaining: stats.budget_remaining,
                edges_traversed: stats.edges_traversed,
            },
        }),
    )
        .into_response()
}

#[utoipa::path(
    post,
    path = "/v1/query/time-range",
    tag = "Query",
    request_body = TimeRangeBody,
    responses(
        (status = 200, description = "Time range results"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Feature not enabled"),
    ),
    security(("bearer_auth" = []))
)]
#[tracing::instrument(level = "info", skip(state, headers, body), fields(tenant_id = %body.tenant_id))]
pub(super) async fn post_query_time_range(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TimeRangeBody>,
) -> impl IntoResponse {
    if let Err(response) = authorize_concrete_query_tenant(&state, &headers, &body.tenant_id) {
        return response;
    }

    if !is_query_feature_enabled("CORECRUXD_QUERY_TIME_RANGE") {
        return problem_response(StatusCode::NOT_FOUND, "time-range query not enabled");
    }

    if !state.http_dataplane.enabled() {
        return platform_upgrade_response("time_range");
    }

    if body.start_micros >= body.end_micros {
        return problem_response(StatusCode::BAD_REQUEST, "start_micros must be less than end_micros");
    }

    // Reject windows > 365 days
    let max_window = 365i64 * 86_400_000_000;
    if body.end_micros - body.start_micros > max_window {
        return problem_response(StatusCode::BAD_REQUEST, "time window must not exceed 365 days");
    }

    let t0 = std::time::Instant::now();
    let response = match state
        .http_dataplane
        .time_range(
            &body.tenant_id,
            body.start_micros,
            body.end_micros,
            &body.artifact_ids,
            body.include_relations,
            body.limit,
        )
        .await
    {
        Ok(response) => response,
        Err(err) => return map_http_dataplane_error(err),
    };

    state
        .metrics
        .observe_time_range(t0.elapsed().as_secs_f64(), response.stats.artifacts_scanned);

    #[derive(serde::Serialize)]
    struct Resp {
        artifacts_changed: Vec<ArtifactChanged>,
        scan_stats: ScanStats,
    }
    #[derive(serde::Serialize)]
    struct ArtifactChanged {
        artifact_id: u32,
        living_status: String,
        confidence: f32,
        updated_at_micros: i64,
        relations_changed: Vec<RelChanged>,
        relation_change_count: u32,
    }
    #[derive(serde::Serialize)]
    struct RelChanged {
        src_artifact_id: u32,
        dst_artifact_id: u32,
        relation_type: String,
        confidence: f32,
        created_at_micros: i64,
        updated_at_micros: i64,
    }
    #[derive(serde::Serialize)]
    struct ScanStats {
        artifacts_scanned: u32,
        relations_scanned: u64,
        total_changes: u32,
    }

    let stats = response.stats;
    let artifacts_changed: Vec<ArtifactChanged> = response
        .artifacts
        .into_iter()
        .map(|a| ArtifactChanged {
            artifact_id: a.artifact_id,
            living_status: a.current_state.living_status.as_engine_str().to_string(),
            confidence: corecrux_projections::dequantize_confidence_f32(a.current_state.confidence_q16),
            updated_at_micros: a.current_state.updated_at_micros,
            relations_changed: a
                .relations_changed
                .iter()
                .map(|r| RelChanged {
                    src_artifact_id: r.src_artifact_id,
                    dst_artifact_id: r.dst_artifact_id,
                    relation_type: r.relation_type.as_engine_str().to_string(),
                    confidence: r.confidence,
                    created_at_micros: r.created_at_micros,
                    updated_at_micros: r.updated_at_micros,
                })
                .collect(),
            relation_change_count: a.relation_change_count,
        })
        .collect();

    (
        StatusCode::OK,
        Json(Resp {
            artifacts_changed,
            scan_stats: ScanStats {
                artifacts_scanned: stats.artifacts_scanned,
                relations_scanned: stats.relations_scanned,
                total_changes: stats.total_changes,
            },
        }),
    )
        .into_response()
}

// ── v5 general-purpose HTTP append ──────────────────────────────────

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub(super) struct TextSearchBody {
    pub(super) tenant_id: String,
    pub(super) query: String,
    #[serde(default = "default_text_search_limit", alias = "top_k")]
    pub(super) limit: usize,
    /// Token budget: if set, fill results by descending score until budget is exhausted.
    /// Overrides `limit` when provided.
    pub(super) token_budget: Option<usize>,
    /// Minimum BM25 score threshold. Results below this floor are excluded.
    pub(super) min_score: Option<f32>,
    /// Query mode: "normal" (default) returns full results, "scan" returns metadata only.
    #[serde(default)]
    pub(super) mode: Option<String>,
    /// Include CROWN receipt in response.
    #[serde(default)]
    #[allow(dead_code)] // Deserialized from request; receipt inclusion planned for Phase 2.
    pub(super) include_receipt: Option<bool>,
}

pub(super) fn default_text_search_limit() -> usize {
    10
}

#[utoipa::path(
    post,
    path = "/v1/query/text-search",
    tag = "Query",
    request_body = TextSearchBody,
    responses(
        (status = 200, description = "Text search results"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Text search explicitly disabled"),
    ),
    security(("bearer_auth" = []))
)]
#[tracing::instrument(level = "info", skip(state, headers, body))]
pub(super) async fn post_query_text_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TextSearchBody>,
) -> impl IntoResponse {
    let tenant_filter = match authorize_query_tenant(&state, &headers, &body.tenant_id) {
        Ok(filter) => filter,
        Err(response) => return response,
    };

    if body.query.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "query must not be empty");
    }

    if !is_query_feature_enabled("CORECRUXD_QUERY_TEXT_SEARCH") {
        return problem_response(StatusCode::NOT_FOUND, "text-search query not enabled");
    }

    let rcx_decision = enforce_rcx_local_query(&state);
    if let Some(decision) = rcx_decision.as_ref().filter(|decision| !decision.authorised) {
        return rcx_refusal_response(decision);
    }

    let limit = body.limit.clamp(1, 100);
    let is_scan_mode = body.mode.as_deref() == Some("scan");
    let mut semantic_profile = state.fact_store.read().await.semantic_profile();
    let mut local_semantic_profile_id = semantic_profile.as_ref().map(|profile| profile.profile_id.clone());
    let mut embedding_fingerprint = semantic_profile
        .as_ref()
        .map(|profile| profile.embedding_fingerprint.clone());

    let t0 = std::time::Instant::now();

    let index = state.retrieval_index.read().await;
    let readers = index.readers();

    if readers.is_empty() {
        return response_with_rcx_mode(
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({
                    "results": [],
                    "coverage": { "score": 0.0, "gaps": [], "below_floor": 0 },
                    "meta": {
                        "backend": "corecrux-v5-bm25",
                        "took_ms": t0.elapsed().as_millis(),
                        "segments_searched": 0,
                        "total_docs": 0,
                        "source_label": "local_tenant_index",
                        "score_space": SCORE_SPACE_BM25_LEXICAL,
                        "score_merge_rule": SCORE_MERGE_RULE_SINGLE_SPACE,
                        "mixed_profile_merge_rule": MIXED_PROFILE_MERGE_RULE,
                        "semantic_profile_id": null,
                        "local_semantic_profile_id": local_semantic_profile_id,
                        "local_semantic_profile": semantic_profile,
                        "embedding_fingerprint": embedding_fingerprint,
                    }
                })),
            )
                .into_response(),
            rcx_decision.as_ref(),
        );
    }

    // Use the extended search function with min_score and coverage tracking
    let mut search_result = corecrux_retrieval::bm25::bm25_search(
        &readers,
        &body.query,
        if body.token_budget.is_some() { 1000 } else { limit },
        tenant_filter,
        &corecrux_retrieval::bm25::Bm25Params::default(),
        body.min_score,
        tenant_filter.and_then(|h| index.forgotten_watermark(h)),
    );

    // Dense re-rank (buyer-fit M3.2): when the node has an embedder (the
    // pure-Rust LocalHashEmbedder by default) AND this corpus has `.ccxe`
    // companions, embed the query and re-rank the BM25 candidate pool by a fused
    // score = 0.7*bm25_norm + 0.3*cosine. Absent an embedder or vectors the lane
    // stays inert — bit-identical BM25. BM25 coverage reporting is preserved.
    const BM25_WEIGHT: f32 = 0.7;
    const DENSE_WEIGHT: f32 = 0.3;
    let (query_embedding, refreshed_semantic_profile, delegation_configured) = {
        let store = state.fact_store.read().await;
        let embedding = match store.try_embed_text(&body.query) {
            Ok(embedding) => embedding,
            Err(err) => {
                tracing::warn!(error = %err, "query-embedding-failed");
                if let Some(status) = store.delegation_status() {
                    return embedding_delegation_degraded_response(&status);
                }
                // Preserve the established BM25-only degradation for local
                // and generic external embedders. Crux delegation is
                // different: its configured capability fails closed above.
                None
            }
        };
        (embedding, store.semantic_profile(), store.delegation_status().is_some())
    };
    // A delegate pins the provider's complete profile on its first response.
    // Refresh after the call so that first-call vectors are compared against
    // the provider fingerprint, never the configured model/dimension placeholder.
    semantic_profile = refreshed_semantic_profile;
    local_semantic_profile_id = semantic_profile.as_ref().map(|profile| profile.profile_id.clone());
    embedding_fingerprint = semantic_profile
        .as_ref()
        .map(|profile| profile.embedding_fingerprint.clone());
    let dense_provider = if let Some(query_embedding) = query_embedding.as_ref() {
        if delegation_configured {
            let Some(expected_fingerprint) = embedding_fingerprint.as_ref() else {
                return ProblemResponse(
                    ProblemDetails::service_unavailable(
                        "Remote embedding delegation did not publish a semantic fingerprint.",
                    )
                    .with_extensions(serde_json::json!({
                        "code": "EMBEDDING_SEMANTIC_PROFILE_MISMATCH",
                        "capability": "embedding_delegation",
                        "availability": "degraded",
                        "reason_code": "embedding_semantic_profile_mismatch",
                    })),
                )
                .into_response();
            };
            match crate::local_ingest::build_dense_provider_strict(
                &index,
                &state.data_dir,
                query_embedding,
                &expected_fingerprint.hash,
                semantic_profile.as_ref().map(|profile| profile.model.as_str()),
            ) {
                Ok(provider) => {
                    state.fact_store.read().await.clear_semantic_profile_mismatch();
                    provider
                }
                Err(error) => {
                    tracing::warn!(?error, "delegated-stored-semantic-profile-mismatch");
                    state.fact_store.read().await.report_semantic_profile_mismatch();
                    return delegated_stored_profile_problem(error);
                }
            }
        } else {
            crate::local_ingest::build_dense_provider(
                &index,
                &state.data_dir,
                query_embedding,
                embedding_fingerprint
                    .as_ref()
                    .map(|fingerprint| fingerprint.hash.as_str()),
                semantic_profile.as_ref().map(|profile| profile.model.as_str()),
            )
        }
    } else {
        None
    };
    let dense_lane_active = dense_provider.is_some();
    if let Some(provider) = dense_provider.as_ref() {
        use corecrux_retrieval::dense::DenseProvider;
        let max_bm25 = search_result
            .hits
            .iter()
            .map(|h| h.score)
            .fold(0.0f32, f32::max)
            .max(1e-9);
        for h in &mut search_result.hits {
            let dense = provider.dense_score(h.doc_id, h.segment_index).unwrap_or(0.0);
            // Overwrite the reported score with the fused value so ordering and
            // the per-hit `score` stay consistent (score_space labels it fused).
            h.score = BM25_WEIGHT * (h.score / max_bm25) + DENSE_WEIGHT * dense;
        }
        search_result
            .hits
            .sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    }
    let (score_space, score_merge_rule) = if dense_lane_active {
        (SCORE_SPACE_BM25_DENSE_FUSED, SCORE_MERGE_RULE_WEIGHTED_LINEAR)
    } else {
        (SCORE_SPACE_BM25_LEXICAL, SCORE_MERGE_RULE_SINGLE_SPACE)
    };

    let took_ms = t0.elapsed().as_millis();

    // Apply token budget if specified
    let (results, tokens_used, results_omitted) = if let Some(budget) = body.token_budget {
        let mut used: usize = 0;
        let mut included = Vec::new();
        let mut omitted = 0usize;

        for h in &search_result.hits {
            let token_count = h.doc_length_tokens as usize;
            if used + token_count > budget && !included.is_empty() {
                omitted += 1;
                continue;
            }
            used += token_count;
            included.push(h.clone());
            if used >= budget {
                omitted = search_result.hits.len() - included.len();
                break;
            }
        }
        (included, used, omitted)
    } else {
        let tokens: usize = search_result.hits.iter().map(|h| h.doc_length_tokens as usize).sum();
        (search_result.hits, tokens, 0)
    };

    // Build coverage gaps array
    let gaps: Vec<serde_json::Value> = search_result
        .coverage
        .missing_tokens
        .iter()
        .map(|term| {
            serde_json::json!({
                "query_terms": [term],
                "match_quality": "none",
                "suggestion": format!("No documents in corpus contain '{}'", term)
            })
        })
        .collect();

    #[derive(serde::Serialize)]
    struct HitResp {
        result_id: String,
        rank: usize,
        segment_index: usize,
        /// The sealed segment's own sequence — the value `/v1/local/ingest`
        /// returned as `segment_seq` in its receipt. `segment_index` is a
        /// position in the loaded-reader list and is NOT the same number, so a
        /// consumer joining a receipt to a result joins on this
        /// (ExecPlan `corecrux-ingest-dense-silent-failure-2026-08-07`, B2).
        segment_seq: Option<u64>,
        doc_id: u32,
        score: f32,
        source_label: &'static str,
        score_space: &'static str,
        semantic_profile_id: Option<String>,
        local_semantic_profile_id: Option<String>,
        frame_offset: u32,
        token_count: u16,
    }

    let result_items: Vec<HitResp> = results
        .iter()
        .enumerate()
        .map(|(idx, h)| HitResp {
            result_id: format!("{}:{}", h.segment_index, h.doc_id),
            rank: idx + 1,
            segment_index: h.segment_index,
            segment_seq: readers.get(h.segment_index).map(|r| r.header.segment_seq),
            doc_id: h.doc_id,
            score: h.score,
            source_label: "local_tenant_index",
            score_space,
            semantic_profile_id: None,
            local_semantic_profile_id: local_semantic_profile_id.clone(),
            frame_offset: h.frame_offset,
            token_count: h.doc_length_tokens,
        })
        .collect();

    // Surface 3 of 4: provenance of the segments behind THIS answer, not of the
    // corpus. Always present, clean or not — an absent block cannot be told
    // apart from a daemon too old to check.
    let provenance = index.provenance_tally_for_reader_indices(results.iter().map(|h| h.segment_index));

    let mut response = serde_json::json!({
        "results": result_items,
        "coverage": {
            "score": search_result.coverage.score,
            "gaps": gaps,
            "below_floor": search_result.coverage.below_floor,
        },
        "meta": {
            "backend": "corecrux-v5-bm25",
            "provenance": provenance,
            "took_ms": took_ms,
            "segments_searched": readers.len(),
            "total_docs": index.total_docs(),
            "total_candidates": search_result.total_candidates,
            "source_label": "local_tenant_index",
            "score_space": score_space,
            "score_merge_rule": score_merge_rule,
            "mixed_profile_merge_rule": MIXED_PROFILE_MERGE_RULE,
            "dense_lane_active": dense_lane_active,
            "semantic_profile_id": null,
            "local_semantic_profile_id": local_semantic_profile_id,
            "local_semantic_profile": semantic_profile,
            "embedding_fingerprint": embedding_fingerprint,
        }
    });

    // Add token budget metadata when applicable
    if let Some(budget) = body.token_budget {
        response["tokens_used"] = serde_json::json!(tokens_used);
        response["tokens_available"] = serde_json::json!(budget);
        response["results_omitted"] = serde_json::json!(results_omitted);
    }

    if is_scan_mode {
        response["scan_mode"] = serde_json::json!(true);
    }

    // crux-observe: record low-coverage queries as ops facts
    if crux_observe::config::self_observe_enabled()
        && search_result.coverage.score < 0.3
        && !search_result.coverage.missing_tokens.is_empty()
    {
        let fs = state.fact_store.clone();
        let missing = search_result.coverage.missing_tokens.clone();
        let score = search_result.coverage.score;
        let query_text = body.query.clone();
        tokio::spawn(async move {
            let event = serde_json::json!({
                "event_type": crux_observe::schema::EVT_OPS_QUERY_COVERAGE_V1,
                "query_terms": query_text.split_whitespace().collect::<Vec<&str>>(),
                "coverage_score": score,
                "missing_tokens": missing,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });
            let json = serde_json::to_string(&event).unwrap_or_default();
            let mut store = fs.write().await;
            {
                store.store(query_coverage_store_fact(json, score));
            };
        });
    }

    response_with_rcx_mode(
        (StatusCode::OK, axum::Json(response)).into_response(),
        rcx_decision.as_ref(),
    )
}

fn enforce_rcx_local_query(state: &AppState) -> Option<crux_router::RouterDecision> {
    state.rcx_router.as_ref().map(|router| {
        router.decide(
            &crux_router::CallContext::local("corecrux.query.local"),
            current_unix_seconds(),
        )
    })
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn rcx_refusal_response(decision: &crux_router::RouterDecision) -> Response {
    let refusal_receipt = decision.refusal_receipt.as_ref().map(|receipt| {
        serde_json::json!({
            "event_type": &receipt.event_type,
            "token_id": &receipt.token_id,
            "token_hash": &receipt.token_hash,
            "capability": &receipt.capability,
            "backend_id": &receipt.backend_id,
            "data_egress_classes": &receipt.data_egress_classes,
            "required_attestations": &receipt.required_attestations,
            "present_attestations": &receipt.present_attestations,
            "reason_code": &receipt.reason_code,
            "receipt_class": &receipt.receipt_class,
        })
    });
    response_with_rcx_mode(
        (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": "rcx_capability_denied",
                "reason_code": decision.reason_code,
                "mode": decision.mode.as_str(),
                "token_id": decision.token_id,
                "token_hash": decision.token_hash,
                "refusal_receipt": refusal_receipt,
            })),
        )
            .into_response(),
        Some(decision),
    )
}

fn response_with_rcx_mode(mut response: Response, decision: Option<&crux_router::RouterDecision>) -> Response {
    if let Some(decision) = decision {
        if let Ok(value) = HeaderValue::from_str(&decision.stamp.mode) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("x-crux-mode"), value);
        }
    }
    response
}

// ── Progressive retrieval: expand ──────────────────────────────────────

/// Hydration tiers, spelled the way `crux-mcp`'s CRC-v1 envelope spells them
/// ([`crux_mcp::crc_v1`]) rather than inventing a second vocabulary for the same
/// idea. `mixed` is an outcome, never a request: it is what a `full` request
/// degrades to when part of the set is withheld.
const HYDRATE_POINTER: &str = "pointer";
const HYDRATE_FULL: &str = "full";
const HYDRATE_MIXED: &str = "mixed";

/// Per-chunk hydration outcomes, reported on the chunk in `full` mode only.
/// `demoted` is over budget and re-askable; `unavailable` is a segment that
/// could not be read and is not. Collapsing them into one word would hide which
/// of "ask again with a bigger budget" and "escalate" the caller needs.
const HYDRATE_DEMOTED: &str = "demoted";
const HYDRATE_UNAVAILABLE: &str = "unavailable";

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub(super) struct TextSearchExpandBody {
    /// Tenant ID for the expand request (must match original scan).
    pub(super) tenant_id: String,
    /// Result IDs to expand (segment_index:doc_id pairs).
    pub(super) result_ids: Vec<ExpandResultId>,
    /// Hydration tier. `"pointer"` — the default, and what an absent field
    /// means — returns exactly the fields this route has always returned.
    /// `"full"` additionally carries each chunk's `stream_id` (the `doc_id`
    /// string supplied at ingest) and `content`.
    #[serde(default)]
    pub(super) hydrate: Option<String>,
    /// Token budget for the hydrated tier, priced in the same `token_count`
    /// each pointer already advertises, so a caller can budget from the
    /// pointer response without guessing. Chunks hydrate in the order
    /// `result_ids` lists them until it is spent; the rest stay pointers and
    /// are counted in `meta.demoted`. Ignored in `"pointer"` mode.
    #[serde(default)]
    pub(super) token_budget: Option<usize>,
}

/// A chunk that has already passed the tenant check and may therefore be
/// hydrated: where its bytes live, and what hydrating it would cost.
struct HydrationCandidate {
    /// Position in the emitted `chunks` array.
    chunk_index: usize,
    segment_index: usize,
    frame_offset: u32,
    token_cost: usize,
}

/// Every frame of the segment behind `segment_index`, or `None` if it cannot be
/// read.
///
/// Reading is deliberately whole-segment: `frame_offset` in a `.ccxi` doc table
/// is an offset into the *logical* record stream, and a sealed segment's record
/// area is neither that stream nor addressable by it — blocks are padded to
/// 4 KiB and may be compressed. `decode_segment_frames_v1` reassembles the
/// stream first, which is the only thing that makes the offset mean what the
/// companion says it means. The cost is why hydration is opt-in and budgeted,
/// and why the decode is cached per segment for the life of one request.
fn segment_frames_for_reader(
    index: &corecrux_retrieval::IndexManager,
    segment_index: usize,
) -> Option<Vec<corecrux_segment::SegmentFrameV1>> {
    let path = index.reader_segment_path(segment_index)?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "expand-hydrate-segment-unreadable");
            return None;
        }
    };
    match corecrux_segment::decode_segment_frames_v1(&bytes) {
        Ok(frames) => Some(frames),
        Err(error) => {
            tracing::warn!(path = %path.display(), error = %format!("{error:?}"), "expand-hydrate-segment-undecodable");
            None
        }
    }
}

/// The `(stream_id, content)` behind one indexed document.
///
/// `tenant_hash` is re-checked here against the frame's own canonical header —
/// the same field, from the authoritative source, that the `.ccxi` doc table
/// only caches a hash of. The caller has already refused every doc whose cached
/// tenant differs; this asks the segment the same question, so a companion that
/// disagrees with the segment beside it cannot turn into a cross-tenant read.
fn hydrate_frame(
    frames: &[corecrux_segment::SegmentFrameV1],
    frame_offset: u32,
    tenant_hash: u64,
) -> Option<(String, String)> {
    // Frames come back sorted on `record_off`, which is the value a `.ccxi`
    // doc entry stores as `frame_offset` — so this is a join on the key, not a
    // positional guess at `doc_id` (the companion skips non-indexable frames).
    let position = frames
        .binary_search_by_key(&frame_offset, |frame| frame.record_off)
        .ok()?;
    let frame = frames.get(position)?;
    let header = corecrux_frame::decode_canonical_header_bytes_v1(&frame.header_bytes).ok()?;
    if xxhash_rust::xxh64::xxh64(header.tenant_id.as_bytes(), 0) != tenant_hash {
        tracing::warn!(
            frame_offset,
            "expand-hydrate-tenant-mismatch: .ccxi doc table disagrees with its segment"
        );
        return None;
    }
    let content = std::str::from_utf8(&frame.payload_bytes).ok()?;
    Some((header.stream_id, content.to_string()))
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub(super) struct ExpandResultId {
    pub(super) segment_index: usize,
    pub(super) doc_id: u32,
}

#[utoipa::path(
    post,
    path = "/v1/query/text-search/expand",
    tag = "Query",
    request_body = TextSearchExpandBody,
    responses(
        (status = 200, description = "Expanded text search results"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Text search explicitly disabled"),
    ),
    security(("bearer_auth" = []))
)]
#[tracing::instrument(level = "info", skip(state, headers, body))]
pub(super) async fn post_query_text_search_expand(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TextSearchExpandBody>,
) -> impl IntoResponse {
    let tenant_hash = match authorize_concrete_query_tenant(&state, &headers, &body.tenant_id) {
        Ok(hash) => hash,
        Err(response) => return response,
    };

    if body.result_ids.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "result_ids must not be empty");
    }

    if !is_query_feature_enabled("CORECRUXD_QUERY_TEXT_SEARCH") {
        return problem_response(StatusCode::NOT_FOUND, "text-search query not enabled");
    }

    // An unrecognised tier is refused rather than silently served as pointers:
    // a caller who typed `"Full"` would otherwise read a pointer response and
    // conclude hydration is broken.
    let hydrate_full = match body.hydrate.as_deref().map(str::trim) {
        None | Some("") | Some(HYDRATE_POINTER) => false,
        Some(HYDRATE_FULL) => true,
        Some(_) => return problem_response(StatusCode::BAD_REQUEST, "hydrate must be \"pointer\" or \"full\""),
    };

    let semantic_profile = state.fact_store.read().await.semantic_profile();
    let local_semantic_profile_id = semantic_profile.as_ref().map(|profile| profile.profile_id.clone());
    let embedding_fingerprint = semantic_profile
        .as_ref()
        .map(|profile| profile.embedding_fingerprint.clone());
    let index = state.retrieval_index.read().await;
    let readers = index.readers();

    let mut tokens_loaded: usize = 0;
    let mut chunks: Vec<serde_json::Value> = Vec::new();
    let mut candidates: Vec<HydrationCandidate> = Vec::new();

    for rid in &body.result_ids {
        if rid.segment_index >= readers.len() {
            continue;
        }
        let reader = readers[rid.segment_index];
        let doc_id = rid.doc_id as usize;
        if doc_id >= reader.docs.len() {
            continue;
        }
        let doc = &reader.docs[doc_id];
        if doc.tenant_hash_full != tenant_hash {
            continue;
        }
        // Past this line the document belongs to the caller's tenant. Hydration
        // reads content, so it is only *recorded* here and performed after the
        // loop — a read placed above this check would be a cross-tenant leak.
        tokens_loaded += doc.doc_length_tokens as usize;

        candidates.push(HydrationCandidate {
            chunk_index: chunks.len(),
            segment_index: rid.segment_index,
            frame_offset: doc.frame_offset,
            token_cost: doc.doc_length_tokens as usize,
        });

        chunks.push(serde_json::json!({
            "segment_index": rid.segment_index,
            // B2: the ingest receipt's `segment_seq`, so an expand result joins
            // back to the ingest that produced it without a positional guess.
            "segment_seq": reader.header.segment_seq,
            "doc_id": rid.doc_id,
            "source_label": "local_tenant_index",
            "score_space": SCORE_SPACE_BM25_LEXICAL,
            "semantic_profile_id": null,
            "local_semantic_profile_id": local_semantic_profile_id.clone(),
            "frame_offset": doc.frame_offset,
            "token_count": doc.doc_length_tokens,
        }));
    }

    let mut hydrated = 0usize;
    let mut demoted = 0usize;
    let mut unavailable = 0usize;
    let mut tokens_hydrated = 0usize;

    if hydrate_full {
        // Greedy prefix over the caller's own `result_ids` order — the same
        // boundary `crux_mcp::budget` applies to the fact path, reused rather
        // than re-derived. At least one chunk always hydrates, and everything
        // past the budget is demoted to the pointer it already is rather than
        // dropped, so nothing is lost by asking for more than fits.
        let costs: Vec<usize> = candidates.iter().map(|candidate| candidate.token_cost).collect();
        let full_count = match body.token_budget {
            Some(budget) => crux_mcp::budget::fact_full_within_budget(&costs, budget),
            None => costs.len(),
        };

        // One decode per segment per request, not per chunk: expanding ten hits
        // out of one segment must not read that segment ten times.
        let mut frames_by_segment: std::collections::BTreeMap<usize, Option<Vec<corecrux_segment::SegmentFrameV1>>> =
            std::collections::BTreeMap::new();

        for (rank, candidate) in candidates.iter().enumerate() {
            let chunk = &mut chunks[candidate.chunk_index];
            if rank >= full_count {
                demoted += 1;
                chunk["hydrate"] = serde_json::json!(HYDRATE_DEMOTED);
                continue;
            }
            let frames = frames_by_segment
                .entry(candidate.segment_index)
                .or_insert_with(|| segment_frames_for_reader(&index, candidate.segment_index));
            match frames
                .as_deref()
                .and_then(|frames| hydrate_frame(frames, candidate.frame_offset, tenant_hash))
            {
                Some((stream_id, content)) => {
                    hydrated += 1;
                    tokens_hydrated += candidate.token_cost;
                    chunk["hydrate"] = serde_json::json!(HYDRATE_FULL);
                    chunk["stream_id"] = serde_json::json!(stream_id);
                    chunk["content"] = serde_json::json!(content);
                }
                None => {
                    unavailable += 1;
                    chunk["hydrate"] = serde_json::json!(HYDRATE_UNAVAILABLE);
                }
            }
        }
    }

    let mut meta = serde_json::json!({
        "source_label": "local_tenant_index",
        "score_space": SCORE_SPACE_BM25_LEXICAL,
        "semantic_profile_id": null,
        "local_semantic_profile_id": local_semantic_profile_id,
        "local_semantic_profile": semantic_profile,
        "embedding_fingerprint": embedding_fingerprint,
    });
    if hydrate_full {
        // Only the hydrated path adds keys. Pointer mode — the default, and
        // what every existing caller sends — is byte-for-byte what it was.
        let tier = if demoted == 0 && unavailable == 0 {
            HYDRATE_FULL
        } else if hydrated == 0 {
            HYDRATE_POINTER
        } else {
            HYDRATE_MIXED
        };
        meta["hydrate_tier"] = serde_json::json!(tier);
        meta["hydrated"] = serde_json::json!(hydrated);
        meta["demoted"] = serde_json::json!(demoted);
        meta["unavailable"] = serde_json::json!(unavailable);
        meta["tokens_hydrated"] = serde_json::json!(tokens_hydrated);
        meta["token_budget"] = serde_json::json!(body.token_budget);
    }

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "chunks": chunks,
            "tokens_loaded": tokens_loaded,
            "meta": meta,
        })),
    )
        .into_response()
}

fn query_coverage_store_fact(value: String, score: f32) -> corecrux_memory::fact_store::StoreFact {
    let entity = crux_observe::schema::ops_entity("coverage", &uuid::Uuid::new_v4().to_string());
    let mut sf = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity,
        key: crux_observe::schema::EVT_OPS_QUERY_COVERAGE_V1.to_string(),
        value,
        source_receipt: None,
        confidence: score,
        private: true,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    sf
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_observe_query_coverage_facts_private() {
        let fact = super::query_coverage_store_fact("{}".to_string(), 0.1);
        assert!(fact.entity.starts_with("__ops__::coverage:"));
        assert!(fact.private);
    }
}

// ── Fact Store API (Phase 1.5) ──────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod query_tests {
    use super::super::tests::{enabled_dataplane, test_app_state};
    use super::*;

    #[derive(Debug)]
    struct DegradedDelegation;

    impl corecrux_memory::embeddings::Embedder for DegradedDelegation {
        fn embed_batch(&self, _texts: &[&str]) -> Result<Vec<Vec<f32>>, corecrux_memory::embeddings::EmbeddingError> {
            Err(corecrux_memory::embeddings::EmbeddingError::CircuitOpen { retry_after_ms: 30_000 })
        }

        fn dimensions(&self) -> usize {
            2
        }

        fn model(&self) -> &str {
            "mock-delegate"
        }

        fn semantic_profile(&self) -> corecrux_memory::embeddings::SemanticProfile {
            corecrux_memory::embeddings::SemanticProfile::from_parts("mock-delegate", 2, "mock", "none", "l2")
        }

        fn delegation_status(&self) -> Option<corecrux_memory::embeddings::DelegationStatus> {
            Some(corecrux_memory::embeddings::DelegationStatus {
                availability: corecrux_memory::embeddings::DelegationAvailability::Degraded,
                circuit_state: corecrux_memory::embeddings::DelegationCircuitState::Open,
                reason_code: "embedding_delegate_circuit_open",
                reason: "mock circuit open",
                consecutive_failures: 3,
            })
        }
    }

    fn enabled() -> AppState {
        let mut s = test_app_state(16);
        s.http_dataplane = enabled_dataplane(vec![], None);
        s
    }

    fn graph_body(seeds: Vec<u32>) -> GraphExpandBody {
        GraphExpandBody {
            tenant_id: "t1".to_string(),
            seed_artifact_ids: seeds,
            edge_types: vec![],
            max_hops: 2,
            budget: 64,
            min_confidence: 0.0,
            include_state: false,
        }
    }

    #[test]
    fn tenant_hash_is_deterministic_and_distinct() {
        assert_eq!(tenant_hash("acme"), tenant_hash("acme"));
        assert_ne!(tenant_hash("acme"), tenant_hash("globex"));
    }

    #[test]
    fn current_unix_seconds_is_nonzero() {
        assert!(current_unix_seconds() > 0);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn graph_expand_feature_and_dataplane_gates() {
        std::env::remove_var("CORECRUXD_QUERY_GRAPH_EXPAND");
        // Feature flag off → 404.
        let resp = post_query_graph_expand(State(enabled()), HeaderMap::new(), Json(graph_body(vec![1])))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        std::env::set_var("CORECRUXD_QUERY_GRAPH_EXPAND", "1");
        // Feature on but dataplane disabled → upgrade 501.
        let resp = post_query_graph_expand(State(test_app_state(16)), HeaderMap::new(), Json(graph_body(vec![1])))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

        // Feature on, dataplane enabled, empty seeds → 400.
        let resp = post_query_graph_expand(State(enabled()), HeaderMap::new(), Json(graph_body(vec![])))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        std::env::remove_var("CORECRUXD_QUERY_GRAPH_EXPAND");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn time_range_feature_and_dataplane_gates() {
        std::env::remove_var("CORECRUXD_QUERY_TIME_RANGE");
        let body = TimeRangeBody {
            tenant_id: "t1".to_string(),
            start_micros: 0,
            end_micros: 1_000_000,
            artifact_ids: vec![],
            include_relations: false,
            limit: 10,
        };
        let resp = post_query_time_range(State(enabled()), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        std::env::set_var("CORECRUXD_QUERY_TIME_RANGE", "1");
        let body = TimeRangeBody {
            tenant_id: "t1".to_string(),
            start_micros: 0,
            end_micros: 1_000_000,
            artifact_ids: vec![],
            include_relations: false,
            limit: 10,
        };
        let resp = post_query_time_range(State(test_app_state(16)), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        std::env::remove_var("CORECRUXD_QUERY_TIME_RANGE");
    }

    /// B2: every result carries the `segment_seq` its ingest receipt returned,
    /// so a consumer joins on that value instead of guessing at the positional
    /// `segment_index`. Two separate ingests → seqs 1 and 2 at indices 0 and 1.
    #[tokio::test]
    #[serial_test::serial]
    async fn text_search_results_carry_the_ingest_segment_seq() {
        std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
        let state = enabled();

        let mut sealed_seqs = Vec::new();
        for (doc, text) in [("d1", "peregrine falcon dives"), ("d2", "peregrine falcon nests")] {
            let documents = vec![crate::local_ingest::ProseDocument {
                doc_id: doc.to_string(),
                chunks: vec![crate::local_ingest::ProseChunk {
                    chunk_id: format!("{doc}::0"),
                    text: text.to_string(),
                    dense_vector: None,
                }],
            }];
            let summary = crate::local_ingest::seal_prose_documents(
                &state.data_dir,
                0,
                1,
                "t1",
                "corpus",
                "2026-08-07T00:00:00Z",
                &documents,
                None,
            )
            .unwrap();
            sealed_seqs.push(summary.segment_seq);
        }
        state
            .retrieval_index
            .write()
            .await
            .scan_and_load(&state.data_dir.join("shards").join("shard-0000").join("segments"))
            .unwrap();

        let response = post_query_text_search(
            State(state),
            HeaderMap::new(),
            Json(TextSearchBody {
                tenant_id: "t1".to_string(),
                query: "peregrine falcon".to_string(),
                limit: 10,
                token_budget: None,
                min_score: None,
                mode: None,
                include_receipt: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let results = json["results"].as_array().expect("results");
        assert_eq!(results.len(), 2, "both sealed chunks retrieved");

        let mut seen = std::collections::HashSet::new();
        for hit in results {
            let seq = hit["segment_seq"].as_u64().expect("segment_seq present on every hit");
            assert!(
                sealed_seqs.contains(&seq),
                "segment_seq {seq} must be a value an ingest receipt returned (receipts: {sealed_seqs:?})"
            );
            assert!(seen.insert(seq), "each hit's segment must resolve distinctly");
            // Deliberately NOT asserting `seq == segment_index + 1`. It happens
            // to hold on this fixture — one tenant, two segments, nothing else
            // loaded — and asserting it would enshrine an offset that is a
            // position in the daemon-wide reader list: measured at 1, then 18,
            // then 17 on one host within hours as unrelated segments came and
            // went. The join key is the contract; the offset is not.
            assert!(hit["segment_index"].is_u64(), "segment_index still reported");
        }
    }

    // ── M8: search-hit hydration (`hydrate: "full"`) ──────────────────
    //
    // ExecPlan `unified-skills-registry-rcx-trust-2026-08-08`. M6 proved a
    // search hit could not be resolved back to the document it came from:
    // `doc_id` is a daemon-assigned integer and expand echoed pointers only.

    /// The captured pre-M8 response shape of this route. It is a fixture, not a
    /// description: the default path must keep returning exactly these keys, so
    /// a caller that sends no `hydrate` field pays nothing for the new tier.
    const POINTER_CHUNK_KEYS: [&str; 9] = [
        "doc_id",
        "frame_offset",
        "local_semantic_profile_id",
        "score_space",
        "segment_index",
        "segment_seq",
        "semantic_profile_id",
        "source_label",
        "token_count",
    ];
    const POINTER_META_KEYS: [&str; 6] = [
        "embedding_fingerprint",
        "local_semantic_profile",
        "local_semantic_profile_id",
        "score_space",
        "semantic_profile_id",
        "source_label",
    ];

    fn segments_dir(state: &AppState) -> std::path::PathBuf {
        state.data_dir.join("shards").join("shard-0000").join("segments")
    }

    /// Seal one prose document per entry into its own segment, then load the
    /// shard directory into the retrieval index. Each `seal_prose_documents`
    /// call force-seals its head, so entry `n` is segment `n`.
    async fn seal_and_load(state: &AppState, docs: &[(&str, &str, &str)]) {
        for (tenant, doc_id, text) in docs {
            let documents = vec![crate::local_ingest::ProseDocument {
                doc_id: (*doc_id).to_string(),
                chunks: vec![crate::local_ingest::ProseChunk {
                    chunk_id: format!("{doc_id}::0"),
                    text: (*text).to_string(),
                    dense_vector: None,
                }],
            }];
            crate::local_ingest::seal_prose_documents(
                &state.data_dir,
                0,
                1,
                tenant,
                "corpus",
                "2026-08-20T00:00:00Z",
                &documents,
                None,
            )
            .unwrap();
        }
        state
            .retrieval_index
            .write()
            .await
            .scan_and_load(&segments_dir(state))
            .unwrap();
    }

    fn expand_body(
        tenant: &str,
        ids: &[(usize, u32)],
        hydrate: Option<&str>,
        token_budget: Option<usize>,
    ) -> TextSearchExpandBody {
        TextSearchExpandBody {
            tenant_id: tenant.to_string(),
            result_ids: ids
                .iter()
                .map(|(segment_index, doc_id)| ExpandResultId {
                    segment_index: *segment_index,
                    doc_id: *doc_id,
                })
                .collect(),
            hydrate: hydrate.map(str::to_string),
            token_budget,
        }
    }

    async fn expand_bytes(state: AppState, body: TextSearchExpandBody) -> (StatusCode, Vec<u8>) {
        let response = post_query_text_search_expand(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, bytes.to_vec())
    }

    async fn expand_json(state: AppState, body: TextSearchExpandBody) -> (StatusCode, serde_json::Value) {
        let (status, bytes) = expand_bytes(state, body).await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// The `(segment_index, doc_id)` pointers a scan hands a caller — the only
    /// handles expand accepts, and the reason hydration exists at all.
    async fn search_ids(state: AppState, tenant: &str, query: &str) -> Vec<(usize, u32)> {
        let response = post_query_text_search(
            State(state),
            HeaderMap::new(),
            Json(TextSearchBody {
                tenant_id: tenant.to_string(),
                query: query.to_string(),
                limit: 10,
                token_budget: None,
                min_score: None,
                mode: None,
                include_receipt: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["results"]
            .as_array()
            .expect("results")
            .iter()
            .map(|hit| {
                (
                    hit["segment_index"].as_u64().expect("segment_index") as usize,
                    hit["doc_id"].as_u64().expect("doc_id") as u32,
                )
            })
            .collect()
    }

    fn sorted_keys(value: &serde_json::Value) -> Vec<String> {
        let mut keys: Vec<String> = value
            .as_object()
            .expect("object")
            .keys()
            .map(ToString::to_string)
            .collect();
        keys.sort();
        keys
    }

    /// Gate 1: an absent `hydrate` field costs an existing caller nothing —
    /// not a key, not a byte. Asserted against the captured key fixture and by
    /// comparing the serialised bodies, not by eye.
    #[tokio::test]
    #[serial_test::serial]
    async fn text_search_expand_pointer_mode_is_byte_identical_to_the_pre_hydration_shape() {
        std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
        let state = enabled();
        seal_and_load(&state, &[("t1", "doc-a", "peregrine falcon dives")]).await;
        let ids = search_ids(state.clone(), "t1", "peregrine falcon").await;
        assert_eq!(ids.len(), 1);

        let (status, absent) = expand_bytes(state.clone(), expand_body("t1", &ids, None, None)).await;
        assert_eq!(status, StatusCode::OK);
        let (_, explicit) = expand_bytes(state, expand_body("t1", &ids, Some("pointer"), None)).await;
        assert_eq!(
            absent, explicit,
            "an absent hydrate field and an explicit \"pointer\" must serialise identically"
        );

        let json: serde_json::Value = serde_json::from_slice(&absent).unwrap();
        assert_eq!(sorted_keys(&json["chunks"][0]), POINTER_CHUNK_KEYS);
        assert_eq!(sorted_keys(&json["meta"]), POINTER_META_KEYS);
    }

    /// Gate 2: `hydrate: "full"` resolves a pointer to the `doc_id` string the
    /// caller supplied at ingest and to the chunk's own text. This is the hop
    /// M6 found missing.
    #[tokio::test]
    #[serial_test::serial]
    async fn text_search_expand_hydrate_full_returns_the_ingest_doc_id_and_chunk_text() {
        std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
        let state = enabled();
        seal_and_load(&state, &[("t1", "skill://parse-yaml", "peregrine falcon dives")]).await;
        let ids = search_ids(state.clone(), "t1", "peregrine falcon").await;

        let (status, json) = expand_json(state, expand_body("t1", &ids, Some("full"), None)).await;
        assert_eq!(status, StatusCode::OK);
        let chunk = &json["chunks"][0];
        assert_eq!(chunk["hydrate"], "full");
        assert_eq!(
            chunk["stream_id"], "skill://parse-yaml",
            "stream_id is the doc_id string supplied at ingest, not the daemon's integer"
        );
        assert_eq!(chunk["content"], "peregrine falcon dives");
        // The pointer fields are additive-safe: still there, still the same.
        assert_eq!(chunk["doc_id"], ids[0].1);
        assert_eq!(json["meta"]["hydrate_tier"], "full");
        assert_eq!(json["meta"]["hydrated"], 1);
        assert_eq!(json["meta"]["demoted"], 0);
    }

    /// Gate 3, and the single most dangerous way to get M8 wrong: the frame
    /// read must sit strictly after the `tenant_hash_full` check. Here t2 asks
    /// to hydrate a pointer that addresses t1's document — a valid
    /// `(segment_index, doc_id)` that simply is not theirs.
    #[tokio::test]
    #[serial_test::serial]
    async fn text_search_expand_hydrate_never_reads_another_tenants_content() {
        std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
        let state = enabled();
        seal_and_load(
            &state,
            &[
                ("t1", "t1-secret-doc", "peregrine falcon dives"),
                ("t2", "t2-own-doc", "kestrel hovers"),
            ],
        )
        .await;
        let t1_ids = search_ids(state.clone(), "t1", "peregrine falcon").await;
        assert_eq!(t1_ids.len(), 1, "t1 owns exactly one matching chunk");

        let (status, json) = expand_json(state, expand_body("t2", &t1_ids, Some("full"), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            json["chunks"].as_array().expect("chunks").is_empty(),
            "another tenant's result_id resolves to nothing"
        );
        let rendered = serde_json::to_string(&json).unwrap();
        assert!(
            !rendered.contains("peregrine") && !rendered.contains("t1-secret-doc"),
            "no trace of t1's content or stream_id may appear in t2's response: {rendered}"
        );
        assert_eq!(json["meta"]["hydrated"], 0);
    }

    /// Gate 4: `token_budget` governs the hydrated tier. Over-budget chunks are
    /// demoted to the pointer they already are and counted, never dropped —
    /// the `wrap_facts_tiered` demotion contract, applied to chunks.
    #[tokio::test]
    #[serial_test::serial]
    async fn text_search_expand_hydration_honours_token_budget_and_discloses_demotion() {
        std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
        let state = enabled();
        seal_and_load(
            &state,
            &[
                ("t1", "doc-a", "peregrine falcon dives"),
                ("t1", "doc-b", "peregrine falcon nests"),
            ],
        )
        .await;
        let ids = search_ids(state.clone(), "t1", "peregrine falcon").await;
        assert_eq!(ids.len(), 2);

        let (status, json) = expand_json(state, expand_body("t1", &ids, Some("full"), Some(1))).await;
        assert_eq!(status, StatusCode::OK);
        let chunks = json["chunks"].as_array().expect("chunks");
        assert_eq!(chunks.len(), 2, "demotion withholds content, never the pointer");
        assert_eq!(chunks[0]["hydrate"], "full");
        assert!(chunks[0]["content"].is_string());
        assert_eq!(chunks[1]["hydrate"], "demoted");
        assert!(chunks[1].get("content").is_none(), "a demoted chunk carries no content");
        assert_eq!(json["meta"]["hydrate_tier"], "mixed");
        assert_eq!(json["meta"]["hydrated"], 1);
        assert_eq!(json["meta"]["demoted"], 1);
        assert_eq!(json["meta"]["token_budget"], 1);
    }

    /// A segment whose file has gone is reported as `unavailable`, distinct
    /// from a budget demotion: one is re-askable with a bigger budget, the
    /// other is an operational fault. The pointer survives either way.
    #[tokio::test]
    #[serial_test::serial]
    async fn text_search_expand_reports_an_unreadable_segment_rather_than_failing() {
        std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
        let state = enabled();
        seal_and_load(&state, &[("t1", "doc-a", "peregrine falcon dives")]).await;
        let ids = search_ids(state.clone(), "t1", "peregrine falcon").await;
        for entry in std::fs::read_dir(segments_dir(&state)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) == Some("ccxseg") {
                std::fs::remove_file(&path).unwrap();
            }
        }

        let (status, json) = expand_json(state, expand_body("t1", &ids, Some("full"), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["chunks"][0]["hydrate"], "unavailable");
        assert!(json["chunks"][0].get("content").is_none());
        assert_eq!(json["meta"]["unavailable"], 1);
        assert_eq!(json["meta"]["hydrate_tier"], "pointer");
    }

    /// A misspelt tier is refused. Serving pointers for `"Full"` would look
    /// exactly like hydration being broken, which is a worse failure than a 400.
    #[tokio::test]
    #[serial_test::serial]
    async fn text_search_expand_rejects_an_unknown_hydrate_tier() {
        std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
        let state = enabled();
        seal_and_load(&state, &[("t1", "doc-a", "peregrine falcon dives")]).await;

        let (status, _) = expand_json(state, expand_body("t1", &[(0, 0)], Some("Full"), None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn text_search_is_on_by_default_and_explicitly_disabled() {
        std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
        let body = || TextSearchBody {
            tenant_id: "t1".to_string(),
            query: "hello".to_string(),
            limit: 10,
            token_budget: None,
            min_score: None,
            mode: None,
            include_receipt: None,
        };

        let resp = post_query_text_search(State(enabled()), HeaderMap::new(), Json(body()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        std::env::set_var("CORECRUXD_QUERY_TEXT_SEARCH", "0");
        let resp = post_query_text_search(State(enabled()), HeaderMap::new(), Json(body()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        std::env::set_var("CORECRUXD_QUERY_TEXT_SEARCH", "false");
        let resp = post_query_text_search(State(enabled()), HeaderMap::new(), Json(body()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn delegated_text_search_failure_returns_503_without_bm25_fallback() {
        std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
        let state = enabled();
        let documents = vec![crate::local_ingest::ProseDocument {
            doc_id: "existing-doc".to_string(),
            chunks: vec![crate::local_ingest::ProseChunk {
                chunk_id: "existing-doc::0".to_string(),
                text: "hello from stored prose".to_string(),
                dense_vector: None,
            }],
        }];
        crate::local_ingest::seal_prose_documents(
            &state.data_dir,
            0,
            1,
            "t1",
            "corpus",
            "2026-07-20T00:00:00Z",
            &documents,
            None,
        )
        .unwrap();
        state
            .retrieval_index
            .write()
            .await
            .scan_and_load(&state.data_dir.join("shards").join("shard-0000").join("segments"))
            .unwrap();
        state
            .fact_store
            .write()
            .await
            .set_embedder(Box::new(DegradedDelegation));

        let response = post_query_text_search(
            State(state),
            HeaderMap::new(),
            Json(TextSearchBody {
                tenant_id: "t1".to_string(),
                query: "hello".to_string(),
                limit: 10,
                token_budget: None,
                min_score: None,
                mode: None,
                include_receipt: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["code"], "EMBEDDING_DELEGATION_DEGRADED");
        assert_eq!(body["reason_code"], "embedding_delegate_circuit_open");
    }
}
