// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Local engram/session-procedure compatibility routes.
//!
//! Hosted MemoryCrux exposes `/v1/engrams`, `/v1/memory/session-init`, and
//! `/v1/memory/engrams/resolve`. The daemon keeps a small built-in catalog
//! plus optional fact-backed overlays under `__engram__::*` so local-first
//! agents can use the same pre-execution contract without a cloud dependency.
//!
//! Catalog logic lives in `corecrux_memory::engrams` (shared with the MCP
//! `engram_resolve` tool); this module is the axum-facing shim.

use serde::Deserialize;
use serde_json::json;

use corecrux_memory::engrams::{
    build_engram_manifest, compute_engram_set_hash, current_session_procedure, hash_json, local_catalog_with_overlays,
    model_id_to_capability_class, prompt_hash, resolve_from_catalog, SESSION_PROCEDURE_SCHEMA,
};

use super::{
    problem_response, require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, Query, State, StatusCode,
};

#[derive(Debug, Deserialize)]
pub(super) struct ListEngramsQuery {
    #[serde(default)]
    pub intent_bucket: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SessionInitBody {
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default, alias = "tenantId")]
    pub tenant_id_camel: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default, alias = "agentId")]
    pub agent_id_camel: Option<String>,
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default, alias = "modelId")]
    pub model_id_camel: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ResolveEngramsBody {
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default, alias = "tenantId")]
    pub tenant_id_camel: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default, alias = "agentId")]
    pub agent_id_camel: Option<String>,
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub manifest_hash: Option<String>,
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default, alias = "modelId")]
    pub model_id_camel: Option<String>,
}

/// `GET /v1/engrams` — list active engrams without content.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn list_engrams(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListEngramsQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["query:read", "admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let mut engrams = local_catalog_with_overlays(&store);
    drop(store);
    if let Some(bucket) = query.intent_bucket.as_deref().filter(|s| !s.trim().is_empty()) {
        engrams.retain(|e| e.intent_bucket == bucket);
    }
    let rows: Vec<_> = engrams
        .into_iter()
        .filter(|e| e.enabled)
        .map(|e| {
            json!({
                "id": e.id,
                "name": e.name,
                "version": e.version,
                "intent_bucket": e.intent_bucket,
                "query_pattern": e.query_pattern,
                "prompt_hash": prompt_hash(&e.content),
                "capability_class_min": e.capability_class_min,
                "capability_class_max": e.capability_class_max,
                "generated_class": &e.generated_class,
                "source_chunk_hashes": &e.source_chunk_hashes,
                "source_chunk_set_hash": &e.source_chunk_set_hash,
                "inherited_reason": &e.inherited_reason,
                "policy_hash": &e.policy_hash,
                "enabled": e.enabled,
                "created_at_unix_ms": e.created_at_unix_ms,
            })
        })
        .collect();
    let total = rows.len();
    (
        StatusCode::OK,
        Json(json!({
            "schema": "crux.local.engrams.list.v1",
            "engrams": rows,
            "total": total,
        })),
    )
        .into_response()
}

/// `POST /v1/memory/session-init` — hosted-compatible session procedure +
/// engram manifest handshake.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn memory_session_init(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SessionInitBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["sessions:read", "query:read", "admin:read"])
    {
        return problem.into_response();
    }
    let tenant_id = body
        .tenant_id
        .or(body.tenant_id_camel)
        .unwrap_or_else(|| "local".to_string());
    let agent_id = body
        .agent_id
        .or(body.agent_id_camel)
        .unwrap_or_else(|| "memory-agent".to_string());
    let model_id = body.model_id.or(body.model_id_camel);
    let capability_class = model_id_to_capability_class(model_id.as_deref());
    let store = state.fact_store.read().await;
    let engrams = local_catalog_with_overlays(&store);
    drop(store);
    let session_procedure = current_session_procedure();
    let manifest = build_engram_manifest(&engrams, &tenant_id, &capability_class);
    (
        StatusCode::OK,
        Json(json!({
            "schema": "crux.memory.session_init.v1",
            "passport_id": format!("local:{tenant_id}:{agent_id}:{capability_class}"),
            "capability_class": capability_class,
            "session_procedure": {
                "schema": SESSION_PROCEDURE_SCHEMA,
                "body": session_procedure,
                "hash": hash_json(&session_procedure),
            },
            "session_procedure_hash": hash_json(&session_procedure),
            "engram_manifest": manifest,
        })),
    )
        .into_response()
}

/// `POST /v1/memory/engrams/resolve` — resolve requested `name@version`
/// engrams and return content when the local capability class may use them.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn resolve_engrams(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ResolveEngramsBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["query:read", "admin:read"]) {
        return problem.into_response();
    }
    if body.names.is_empty() || body.names.len() > 20 {
        return problem_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "names must contain 1..=20 name@version entries",
        );
    }
    let tenant_id = body
        .tenant_id
        .or(body.tenant_id_camel)
        .unwrap_or_else(|| "local".to_string());
    let agent_id = body
        .agent_id
        .or(body.agent_id_camel)
        .unwrap_or_else(|| "memory-agent".to_string());
    let model_id = body.model_id.or(body.model_id_camel);
    let capability_class = model_id_to_capability_class(model_id.as_deref());
    let store = state.fact_store.read().await;
    let engrams = local_catalog_with_overlays(&store);
    drop(store);
    let manifest = build_engram_manifest(&engrams, &tenant_id, &capability_class);
    let manifest_status = match body.manifest_hash.as_deref() {
        Some(hash) if hash != manifest["manifest_hash"].as_str().unwrap_or_default() => "stale",
        Some(_) => "current",
        None => "unknown",
    };
    let outcome = resolve_from_catalog(&engrams, &body.names, &capability_class);
    if !outcome.malformed.is_empty() {
        return problem_response(StatusCode::UNPROCESSABLE_ENTITY, "names must use name@version form");
    }
    if !outcome.missing.is_empty() {
        return problem_response(
            StatusCode::FORBIDDEN,
            format!("capability_class_mismatch_or_missing: {}", outcome.missing.join(", ")),
        );
    }
    let resolved = outcome.resolved;
    let engram_set_hash = compute_engram_set_hash(&resolved);
    let receipt_hash = engram_set_hash["hash"].as_str().unwrap_or_default();
    let receipt_suffix: String = receipt_hash.chars().take(16).collect();
    let receipt_linkage = json!({
        "receipt_id": format!("local-engram-dispatch:{receipt_suffix}"),
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "engram_set_hash": engram_set_hash,
    });
    (
        StatusCode::OK,
        Json(json!({
            "schema": "crux.memory.engrams.resolve.v1",
            "engrams": resolved.iter().map(|e| json!({
                "name": e.name,
                "version": e.version,
                "content": e.content,
                "prompt_hash": prompt_hash(&e.content),
                "applicable_why": e.applicable_why,
                "generated_class": &e.generated_class,
                "source_chunk_hashes": &e.source_chunk_hashes,
                "source_chunk_set_hash": &e.source_chunk_set_hash,
                "inherited_reason": &e.inherited_reason,
                "policy_hash": &e.policy_hash,
            })).collect::<Vec<_>>(),
            "manifest_status": manifest_status,
            "manifest_hash": manifest["manifest_hash"],
            "engram_set_hash": receipt_linkage["engram_set_hash"],
            "receipt_linkage": receipt_linkage,
        })),
    )
        .into_response()
}
