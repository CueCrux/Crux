// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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
    model_id_to_capability_class, prompt_hash, resolve_from_catalog, validate_local_engram, LocalEngram,
    ENGRAM_ENTITY_PREFIX, SESSION_PROCEDURE_SCHEMA,
};

use super::{
    http_scope_context, problem_response, require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, Path, Query,
    State, StatusCode,
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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(super) struct UpsertEngramBody {
    pub version: String,
    pub intent_bucket: String,
    #[serde(default)]
    pub query_pattern: Option<String>,
    pub content: String,
    #[serde(default)]
    pub applicable_why: Option<String>,
    #[serde(default)]
    pub capability_class_min: Option<String>,
    #[serde(default)]
    pub capability_class_max: Option<String>,
    #[serde(default)]
    pub generated_class: Option<String>,
    #[serde(default)]
    pub source_chunk_hashes: Vec<String>,
    #[serde(default)]
    pub source_chunk_set_hash: Option<String>,
    #[serde(default)]
    pub inherited_reason: Option<String>,
    #[serde(default)]
    pub policy_hash: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
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

/// Typed, authenticated engram overlay upsert. Generic fact writers cannot
/// address `__engram__::`; this path validates the complete control object and
/// stamps server-owned identity, time, privacy, and provenance fields.
#[utoipa::path(
    put,
    path = "/v1/engrams/{name}",
    tag = "Engrams",
    params(("name" = String, Path, description = "Engram name")),
    request_body = UpsertEngramBody,
    responses(
        (status = 201, description = "Validated engram overlay stored"),
        (status = 400, description = "Invalid engram"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "admin:write required"),
    ),
    security(("bearer_auth" = []))
)]
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn upsert_engram(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<UpsertEngramBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let ctx = match http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };
    let now_ms = chrono::Utc::now().timestamp_millis().max(1) as u64;
    let identity_seed = format!("{name}@{}", body.version);
    let id_hash = blake3::hash(identity_seed.as_bytes()).to_hex().to_string();
    let engram = LocalEngram {
        id: format!("eng_overlay_{}", &id_hash[..16]),
        name,
        version: body.version,
        intent_bucket: body.intent_bucket,
        query_pattern: body.query_pattern,
        content: body.content,
        applicable_why: body.applicable_why,
        capability_class_min: body.capability_class_min,
        capability_class_max: body.capability_class_max,
        generated_class: body.generated_class,
        source_chunk_hashes: body.source_chunk_hashes,
        source_chunk_set_hash: body.source_chunk_set_hash,
        inherited_reason: body.inherited_reason,
        policy_hash: body.policy_hash,
        enabled: body.enabled,
        created_at_unix_ms: now_ms,
    };
    if let Err(err) = validate_local_engram(&engram) {
        return problem_response(StatusCode::BAD_REQUEST, err);
    }
    let tenant_hash = match super::facts::tenant_hash_for_write_context(&ctx) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let actor = ctx.passport_id.clone().unwrap_or_else(|| state.passport_fpr.clone());
    let value = match serde_json::to_string(&engram) {
        Ok(value) => value,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    let receipt_material = format!("{actor}\0{value}");
    let source_receipt = format!(
        "engram-upsert:blake3:{}",
        blake3::hash(receipt_material.as_bytes()).to_hex()
    );
    let entity = format!("{ENGRAM_ENTITY_PREFIX}{}::{}", engram.name, engram.version);
    let stored = {
        let mut store = state.fact_store.write().await;
        match store.try_store(corecrux_memory::fact_store::StoreFact {
            tenant_hash,
            entity: entity.clone(),
            key: "engram".to_string(),
            value,
            source_receipt: Some(source_receipt.clone()),
            confidence: 1.0,
            private: true,
            horizon_class: Some(corecrux_memory::fact_store::HorizonClass::Stable),
            actor: Some(actor.clone()),
        }) {
            Ok(fact) => fact,
            Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        }
    };

    (
        StatusCode::CREATED,
        Json(json!({
            "schema": "crux.local.engram_upsert.v1",
            "fact_id": stored.fact_id,
            "entity": entity,
            "name": engram.name,
            "version": engram.version,
            "prompt_hash": prompt_hash(&engram.content),
            "actor": actor,
            "source_receipt": source_receipt,
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
