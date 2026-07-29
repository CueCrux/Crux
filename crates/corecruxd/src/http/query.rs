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
    );

    // Dense re-rank (buyer-fit M3.2): when the node has an embedder (the
    // pure-Rust LocalHashEmbedder by default) AND this corpus has `.ccxv`
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

    let mut response = serde_json::json!({
        "results": result_items,
        "coverage": {
            "score": search_result.coverage.score,
            "gaps": gaps,
            "below_floor": search_result.coverage.below_floor,
        },
        "meta": {
            "backend": "corecrux-v5-bm25",
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

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub(super) struct TextSearchExpandBody {
    /// Tenant ID for the expand request (must match original scan).
    #[allow(dead_code)] // Deserialized from request; tenant validation planned for multi-tenant expand.
    pub(super) tenant_id: String,
    /// Result IDs to expand (segment_index:doc_id pairs).
    pub(super) result_ids: Vec<ExpandResultId>,
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

    let semantic_profile = state.fact_store.read().await.semantic_profile();
    let local_semantic_profile_id = semantic_profile.as_ref().map(|profile| profile.profile_id.clone());
    let embedding_fingerprint = semantic_profile
        .as_ref()
        .map(|profile| profile.embedding_fingerprint.clone());
    let index = state.retrieval_index.read().await;
    let readers = index.readers();

    let mut tokens_loaded: usize = 0;
    let mut chunks = Vec::new();

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
        tokens_loaded += doc.doc_length_tokens as usize;

        chunks.push(serde_json::json!({
            "segment_index": rid.segment_index,
            "doc_id": rid.doc_id,
            "source_label": "local_tenant_index",
            "score_space": SCORE_SPACE_BM25_LEXICAL,
            "semantic_profile_id": null,
            "local_semantic_profile_id": local_semantic_profile_id.clone(),
            "frame_offset": doc.frame_offset,
            "token_count": doc.doc_length_tokens,
        }));
    }

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "chunks": chunks,
            "tokens_loaded": tokens_loaded,
            "meta": {
                "source_label": "local_tenant_index",
                "score_space": SCORE_SPACE_BM25_LEXICAL,
                "semantic_profile_id": null,
                "local_semantic_profile_id": local_semantic_profile_id,
                "local_semantic_profile": semantic_profile,
                "embedding_fingerprint": embedding_fingerprint,
            }
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
