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

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    problem_response, require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, Query, State, StatusCode,
};

const ENGRAM_ENTITY_PREFIX: &str = "__engram__::";
const LOCAL_ENGRAM_MANIFEST_SCHEMA: &str = "crux.local.engram_manifest.v1";
const SESSION_PROCEDURE_SCHEMA: &str = "cuecrux.memory.session_procedure.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalEngram {
    pub id: String,
    pub name: String,
    pub version: String,
    pub intent_bucket: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_pattern: Option<String>,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applicable_why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_class_min: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_class_max: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_class: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_chunk_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_chunk_set_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub created_at_unix_ms: u64,
}

fn default_enabled() -> bool {
    true
}

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
    let mut resolved = Vec::new();
    let mut missing = Vec::new();
    for name in &body.names {
        let Some((want_name, want_version)) = parse_name_version(name) else {
            return problem_response(StatusCode::UNPROCESSABLE_ENTITY, "names must use name@version form");
        };
        let found = engrams
            .iter()
            .find(|e| e.enabled && e.name == want_name && e.version == want_version);
        match found {
            Some(e) if class_allows(&capability_class, e) => resolved.push(e.clone()),
            _ => missing.push(name.clone()),
        }
    }
    if !missing.is_empty() {
        return problem_response(
            StatusCode::FORBIDDEN,
            format!("capability_class_mismatch_or_missing: {}", missing.join(", ")),
        );
    }
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

fn local_catalog_with_overlays(store: &corecrux_memory::FactStore) -> Vec<LocalEngram> {
    let mut out = builtin_engrams();
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(ENGRAM_ENTITY_PREFIX.trim_end_matches("::").to_string() + "::"),
        top_k: 500,
        token_budget: None,
    });
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.value.is_empty() {
            continue;
        }
        if let Ok(engram) = serde_json::from_str::<LocalEngram>(&fact.value) {
            out.retain(|e| !(e.name == engram.name && e.version == engram.version));
            out.push(engram);
        }
    }
    out.sort_by(|a, b| a.intent_bucket.cmp(&b.intent_bucket).then_with(|| a.name.cmp(&b.name)));
    out
}

fn builtin_engrams() -> Vec<LocalEngram> {
    vec![
        LocalEngram {
            id: "eng_local_investigate_v1".to_string(),
            name: "local-investigation-rhythm".to_string(),
            version: "v1".to_string(),
            intent_bucket: "investigation".to_string(),
            query_pattern: Some("audit|review|investigate|triage|bug|failure".to_string()),
            content: "Before acting, gather the active project context, the latest relevant facts, the route/storyline if code is involved, and the last verification or receipt touching the same object.".to_string(),
            applicable_why: Some("Local daemon baseline for agent investigation sessions.".to_string()),
            capability_class_min: None,
            capability_class_max: None,
            generated_class: None,
            source_chunk_hashes: Vec::new(),
            source_chunk_set_hash: None,
            inherited_reason: None,
            policy_hash: None,
            enabled: true,
            created_at_unix_ms: 1_776_710_400_000,
        },
        LocalEngram {
            id: "eng_route_preflight_v1".to_string(),
            name: "route-impact-preflight".to_string(),
            version: "v1".to_string(),
            intent_bucket: "developer_surface".to_string(),
            query_pattern: Some("route|api|handler|scope|openapi|storyline".to_string()),
            content: "For HTTP/gRPC work, inspect the route storyline, route auth scopes, request/response shape, and nearest tests before editing. Record any scope drift or missing OpenAPI coverage separately from code style cleanup.".to_string(),
            applicable_why: Some("Useful when daemon API work touches handlers or MCP surfaces.".to_string()),
            capability_class_min: None,
            capability_class_max: None,
            generated_class: None,
            source_chunk_hashes: Vec::new(),
            source_chunk_set_hash: None,
            inherited_reason: None,
            policy_hash: None,
            enabled: true,
            created_at_unix_ms: 1_776_710_400_000,
        },
        LocalEngram {
            id: "eng_session_expansion_v1".to_string(),
            name: "aggregation-session-expansion".to_string(),
            version: "v1".to_string(),
            intent_bucket: "aggregation_count".to_string(),
            query_pattern: Some("count|list|how many|aggregate|enumerate".to_string()),
            content: "When multiple chunks from one session match an aggregation question, expand nearby turns from that session before concluding the count or list is complete.".to_string(),
            applicable_why: Some("Matches hosted MemoryCrux aggregation-session-expansion behavior.".to_string()),
            capability_class_min: None,
            capability_class_max: None,
            generated_class: None,
            source_chunk_hashes: Vec::new(),
            source_chunk_set_hash: None,
            inherited_reason: None,
            policy_hash: None,
            enabled: true,
            created_at_unix_ms: 1_776_710_400_000,
        },
    ]
}

fn current_session_procedure() -> serde_json::Value {
    json!({
        "steps": [
            "Resolve session procedure and engram manifest before the first retrieval-heavy turn.",
            "Use the daemon-local context first, then cloud mirrors or hosted MemoryCrux only when the task requires shared tenant memory.",
            "Carry returned prompt_hash, engram_set_hash, semantic_profile_id, and receipt ids into any answer replay capsule.",
            "If evidence is stale, superseded, or policy-constrained, report that separately from the historical answer."
        ],
        "delivery": "first_call_or_hash_mismatch",
    })
}

fn build_engram_manifest(engrams: &[LocalEngram], tenant_id: &str, capability_class: &str) -> serde_json::Value {
    let rows: Vec<_> = engrams
        .iter()
        .filter(|e| e.enabled && class_allows(capability_class, e))
        .map(|e| {
            json!({
                "name": e.name,
                "version": e.version,
                "intent_bucket": e.intent_bucket,
                "prompt_hash": prompt_hash(&e.content),
                "generated_class": &e.generated_class,
                "source_chunk_hashes": &e.source_chunk_hashes,
                "source_chunk_set_hash": &e.source_chunk_set_hash,
                "inherited_reason": &e.inherited_reason,
                "policy_hash": &e.policy_hash,
            })
        })
        .collect();
    let payload = json!({
        "schema": LOCAL_ENGRAM_MANIFEST_SCHEMA,
        "tenant_id": tenant_id,
        "capability_class": capability_class,
        "engrams": rows,
    });
    json!({
        "schema": LOCAL_ENGRAM_MANIFEST_SCHEMA,
        "tenant_id": tenant_id,
        "capability_class": capability_class,
        "manifest_hash": hash_json(&payload),
        "engrams": payload["engrams"],
    })
}

fn compute_engram_set_hash(engrams: &[LocalEngram]) -> serde_json::Value {
    let rows: Vec<_> = engrams
        .iter()
        .map(|e| json!({"name": e.name, "version": e.version, "prompt_hash": prompt_hash(&e.content)}))
        .collect();
    let row_value = serde_json::Value::Array(rows);
    let count = row_value.as_array().map_or(0, Vec::len);
    json!({
        "schema": "crux.local.engram_set_hash.v1",
        "hash": hash_json(&row_value),
        "count": count,
    })
}

fn prompt_hash(content: &str) -> String {
    format!("blake3:{}", blake3::hash(content.as_bytes()).to_hex())
}

fn hash_json(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

fn parse_name_version(value: &str) -> Option<(&str, &str)> {
    let idx = value.rfind('@')?;
    if idx == 0 || idx == value.len() - 1 {
        return None;
    }
    Some((&value[..idx], &value[idx + 1..]))
}

fn model_id_to_capability_class(model_id: Option<&str>) -> String {
    let Some(model) = model_id.map(str::to_ascii_lowercase) else {
        return "capable".to_string();
    };
    if model.contains("mini") || model.contains("haiku") || model.contains("flash") {
        "fast".to_string()
    } else if model.contains("opus") || model.contains("frontier") || model.contains("gpt-5.5") {
        "frontier".to_string()
    } else {
        "capable".to_string()
    }
}

fn class_allows(capability_class: &str, engram: &LocalEngram) -> bool {
    const ORDER: &[&str] = &["fast", "capable", "frontier"];
    let rank = |value: &str| ORDER.iter().position(|x| *x == value).unwrap_or(1);
    let actual = rank(capability_class);
    if let Some(min) = engram.capability_class_min.as_deref() {
        if actual < rank(min) {
            return false;
        }
    }
    if let Some(max) = engram.capability_class_max.as_deref() {
        if actual > rank(max) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_version_requires_at_version() {
        assert_eq!(parse_name_version("a@v1"), Some(("a", "v1")));
        assert_eq!(parse_name_version("a"), None);
        assert_eq!(parse_name_version("@v1"), None);
    }

    #[test]
    fn manifest_hash_changes_with_catalog() {
        let one = builtin_engrams();
        let mut two = one.clone();
        two[0].content.push_str(" changed");
        let a = build_engram_manifest(&one, "t", "capable");
        let b = build_engram_manifest(&two, "t", "capable");
        assert_ne!(a["manifest_hash"], b["manifest_hash"]);
    }

    #[test]
    fn manifest_round_trips_generated_metadata() {
        let engrams = vec![LocalEngram {
            id: "generated-1".to_string(),
            name: "shared-date-header".to_string(),
            version: "v1".to_string(),
            intent_bucket: "temporal_duration".to_string(),
            query_pattern: None,
            content: "The docs store effective dates in the nearest Date header.".to_string(),
            applicable_why: Some("generated_inheritance=exact_chunk_hash".to_string()),
            capability_class_min: None,
            capability_class_max: None,
            generated_class: Some("chunk_bound".to_string()),
            source_chunk_hashes: vec!["a".repeat(64)],
            source_chunk_set_hash: Some("b".repeat(64)),
            inherited_reason: Some("exact_chunk_hash".to_string()),
            policy_hash: Some("policy-hash-1".to_string()),
            enabled: true,
            created_at_unix_ms: 1,
        }];

        let manifest = build_engram_manifest(&engrams, "tenant-a", "capable");

        assert_eq!(manifest["engrams"][0]["generated_class"], "chunk_bound");
        assert_eq!(manifest["engrams"][0]["source_chunk_hashes"][0], "a".repeat(64));
        assert_eq!(manifest["engrams"][0]["inherited_reason"], "exact_chunk_hash");
    }
}
