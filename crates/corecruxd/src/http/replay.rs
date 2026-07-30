// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Deterministic answer replay HTTP surfaces.
//!
//! Historical replay renders the stored answer and selected evidence from a
//! private local capsule. Validity checks are separate: they compare the
//! capsule's evidence hashes against current local facts without invoking an
//! agent or LLM.

use super::*;
use corecrux_memory::fact_store::{Fact, FactStore, StoreFact};
use corecrux_memory::replay::{
    answer_capsule_entity, hash_text, AnswerReplayCapsule, ReplayEvidenceRef, ANSWER_REPLAY_EXPORT_SCHEMA,
    ANSWER_REPLAY_RESPONSE_SCHEMA, ANSWER_REPLAY_VALIDITY_SCHEMA,
};
use serde_json::{json, Value};

#[derive(Debug, serde::Deserialize)]
pub(super) struct ReplayQuery {
    pub(super) tenant_id: String,
    #[serde(default)]
    pub(super) shard_id: Option<String>,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_answer_replay(
    State(state): State<AppState>,
    Path(answer_id): Path<String>,
    Query(q): Query<ReplayQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = require_answer_replay(&state, &headers, &q.tenant_id) {
        return response;
    }
    let ctx = match http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };
    let tenant_hash = super::facts::tenant_hash_for_read_context(&ctx);
    let Some(capsule) = load_answer_capsule(&state, &q.tenant_id, &answer_id, &tenant_hash).await else {
        return problem_response(StatusCode::NOT_FOUND, "answer replay capsule not found");
    };

    Json(json!({
        "schema": ANSWER_REPLAY_RESPONSE_SCHEMA,
        "status": "ok",
        "mode": "historical_replay",
        "tenant_id": q.tenant_id,
        "answer_id": answer_id,
        "agent_required": false,
        "llm_required": false,
        "rendered_answer": capsule.rendered_answer,
        "stored_answer": capsule.stored_answer,
        "evidence": capsule.evidence,
        "capsule": capsule,
    }))
    .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_answer_replay_validity(
    State(state): State<AppState>,
    Path(answer_id): Path<String>,
    Query(q): Query<ReplayQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = require_answer_replay(&state, &headers, &q.tenant_id) {
        return response;
    }
    let ctx = match http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };
    let tenant_hash = super::facts::tenant_hash_for_read_context(&ctx);
    let Some(capsule) = load_answer_capsule(&state, &q.tenant_id, &answer_id, &tenant_hash).await else {
        return problem_response(StatusCode::NOT_FOUND, "answer replay capsule not found");
    };

    let (evidence_status, semantic_profile_status) = {
        let store = state.fact_store.read().await;
        (
            evidence_validity(&store, &capsule, &tenant_hash),
            semantic_profile_validity(&store, &capsule),
        )
    };
    let projection_module_status = projection_modules_validity(&state, &capsule, q.shard_id.as_deref()).await;
    let living_object_status = living_object_validity(&state, &capsule).await;
    let drift_categories = drift_categories(
        &evidence_status,
        &semantic_profile_status,
        &projection_module_status,
        &living_object_status,
    );
    let current_answer_status = if drift_categories.is_empty() {
        "current"
    } else if drift_categories.iter().all(|category| {
        matches!(
            category.as_str(),
            "living_object_not_projected" | "projection_query_failed"
        )
    }) {
        "unknown"
    } else {
        "stale"
    };
    let overall = if drift_categories.is_empty() {
        "historically_replayable"
    } else {
        "drift_detected"
    };

    Json(json!({
        "schema": ANSWER_REPLAY_VALIDITY_SCHEMA,
        "tenant_id": q.tenant_id,
        "answer_id": answer_id,
        "overall": overall,
        "historical_replay_available": true,
        "agent_required": false,
        "llm_required": false,
        "capsule_hash": capsule.capsule_hash,
        "historical_answer": {
            "status": "verified",
            "render_strategy": "render_stored_answer",
            "agent_required": false,
            "llm_required": false,
        },
        "current_answer": {
            "status": current_answer_status,
            "stale": current_answer_status == "stale",
            "drift_categories": drift_categories,
        },
        "evidence": evidence_status,
        "semantic_profile": semantic_profile_status,
        "projection_modules": projection_module_status,
        "living_objects": living_object_status
    }))
    .into_response()
}

// In the default Community Edition binary the only writer of answer-replay
// capsules is the Pro GPU-1 answer path (`http::gpu1`), which is compiled out
// (ExecPlan crux-external-findings-remediation M4); the replay READ endpoints
// remain mounted. Test builds still exercise this writer directly.
#[cfg_attr(not(feature = "hosted-surfaces"), allow(dead_code))]
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn store_answer_capsule(state: &AppState, capsule: &AnswerReplayCapsule) -> std::io::Result<()> {
    let mut fact = StoreFact {
        tenant_hash: "default".to_string(),
        entity: answer_capsule_entity(&capsule.tenant_id, &capsule.answer_id),
        key: "capsule".to_string(),
        value: serde_json::to_string(capsule).map_err(std::io::Error::other)?,
        source_receipt: capsule.source_receipts.last().cloned(),
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce(&state.privacy_policy, &mut fact);
    state.fact_store.write().await.try_store(fact)?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn load_answer_capsule(
    state: &AppState,
    tenant_id: &str,
    answer_id: &str,
    tenant_hash: &str,
) -> Option<AnswerReplayCapsule> {
    let store = state.fact_store.read().await;
    load_answer_capsule_from_store(&store, tenant_id, answer_id, tenant_hash)
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn export_answer_capsule_if_present(
    state: &AppState,
    tenant_id: &str,
    answer_id: &str,
    tenant_hash: &str,
    opts: ReceiptExportOptionsV1,
) -> Option<Response> {
    let capsule = load_answer_capsule(state, tenant_id, answer_id, tenant_hash).await?;
    Some(export_answer_capsule(state, &capsule, opts))
}

fn load_answer_capsule_from_store(
    store: &FactStore,
    tenant_id: &str,
    answer_id: &str,
    tenant_hash: &str,
) -> Option<AnswerReplayCapsule> {
    let entity = answer_capsule_entity(tenant_id, answer_id);
    store
        .get_by_entity_for_tenant(&entity, tenant_hash)
        .into_iter()
        .filter(|fact| fact.key == "capsule")
        .max_by_key(|fact| fact.version)
        .and_then(|fact| serde_json::from_str::<AnswerReplayCapsule>(&fact.value).ok())
}

fn require_answer_replay(state: &AppState, headers: &HeaderMap, tenant_id: &str) -> Option<Response> {
    let tenant_id = tenant_id.trim();
    if tenant_id.is_empty() {
        return Some(problem_response(StatusCode::BAD_REQUEST, "tenant_id must not be empty"));
    }
    if require_http_any_scope(&state.auth, headers, &["admin:read"]).is_err() {
        if let Err(problem) = require_http_scopes_for_tenant(&state.auth, headers, &["replay:answer"], tenant_id) {
            return Some(problem.into_response());
        }
    }
    let product = crate::product::ProductPosture::new(state.operating_mode, &state.enabled_pro_services);
    if !product
        .enabled_pro_services
        .iter()
        .any(|service| service == "replay:answer")
    {
        return Some(
            (
                StatusCode::PAYMENT_REQUIRED,
                Json(json!({
                    "schema": ANSWER_REPLAY_RESPONSE_SCHEMA,
                    "status": "pro_service_not_enabled",
                    "capability": "replay:answer",
                    "fallback": {
                        "reason_code": "pro_service_not_enabled",
                        "detail": "enable Answer Replay under Pro before using deterministic replay surfaces"
                    }
                })),
            )
                .into_response(),
        );
    }
    None
}

fn evidence_validity(store: &FactStore, capsule: &AnswerReplayCapsule, tenant_hash: &str) -> Vec<Value> {
    capsule
        .evidence
        .iter()
        .map(|evidence| evidence_ref_validity(store, evidence, tenant_hash))
        .collect()
}

fn evidence_ref_validity(store: &FactStore, evidence: &ReplayEvidenceRef, tenant_hash: &str) -> Value {
    let Some(fact) = store.get_for_tenant(&evidence.record_id, tenant_hash) else {
        return json!({
            "record_id": evidence.record_id,
            "artifact_id": evidence.artifact_id,
            "status": "missing",
            "drift_category": "fact_missing",
            "captured_text_hash": evidence.text_hash,
            "captured_content_hash": evidence.content_hash,
        });
    };
    let current_text_hash = hash_text(&fact.value);
    let latest = latest_fact_for_entity_key(store, fact, tenant_hash);
    let latest_id = latest.map(|fact| fact.fact_id.clone());
    let captured_hash = evidence.text_hash.as_ref().or(evidence.content_hash.as_ref());
    let hash_matches = captured_hash.is_some_and(|hash| hash == &current_text_hash)
        || evidence
            .content_hash
            .as_ref()
            .is_some_and(|hash| hash == &current_text_hash);
    let status = if latest_id.as_deref().is_some_and(|id| id != evidence.record_id) {
        "superseded"
    } else if hash_matches {
        "current"
    } else {
        "changed"
    };
    let drift_category = match status {
        "superseded" => Some("fact_superseded"),
        "changed" => Some("fact_changed"),
        _ => None,
    };
    json!({
        "record_id": evidence.record_id,
        "artifact_id": evidence.artifact_id,
        "status": status,
        "drift_category": drift_category,
        "current_fact_id": fact.fact_id,
        "latest_fact_id": latest_id,
        "captured_text_hash": evidence.text_hash,
        "captured_content_hash": evidence.content_hash,
        "current_text_hash": current_text_hash,
        "source_label": evidence.source_label,
        "receipt_id": evidence.receipt_id,
        "supersession_chain": supersession_chain_for_entity_key(store, fact, tenant_hash),
    })
}

fn latest_fact_for_entity_key<'a>(store: &'a FactStore, fact: &Fact, tenant_hash: &str) -> Option<&'a Fact> {
    store
        .get_by_entity_for_tenant(&fact.entity, tenant_hash)
        .into_iter()
        .filter(|candidate| candidate.key == fact.key)
        .max_by_key(|candidate| candidate.version)
}

fn supersession_chain_for_entity_key(store: &FactStore, fact: &Fact, tenant_hash: &str) -> Vec<Value> {
    let mut chain = store
        .get_by_entity_for_tenant(&fact.entity, tenant_hash)
        .into_iter()
        .filter(|candidate| candidate.key == fact.key)
        .collect::<Vec<_>>();
    chain.sort_by_key(|candidate| candidate.version);
    chain
        .into_iter()
        .map(|candidate| {
            json!({
                "fact_id": candidate.fact_id,
                "version": candidate.version,
                "deleted": candidate.deleted,
                "value_hash": hash_text(&candidate.value),
                "source_receipt": candidate.source_receipt,
                "stored_at": candidate.stored_at.to_rfc3339(),
            })
        })
        .collect()
}

fn semantic_profile_validity(store: &FactStore, capsule: &AnswerReplayCapsule) -> Value {
    let current = store.semantic_profile();
    let current_id = current.as_ref().map(|profile| profile.profile_id.clone());
    let captured = capsule
        .local_semantic_profile_id
        .clone()
        .or_else(|| capsule.semantic_profile_id.clone());
    let status = match (captured.as_deref(), current_id.as_deref()) {
        (None, _) => "not_recorded",
        (Some(_), None) => "not_configured",
        (Some(a), Some(b)) if a == b => "current",
        (Some(_), Some(_)) => "changed",
    };
    json!({
        "status": status,
        "captured_semantic_profile_id": captured,
        "current_semantic_profile_id": current_id,
        "current_semantic_profile": current,
    })
}

async fn projection_modules_validity(state: &AppState, capsule: &AnswerReplayCapsule, shard_id: Option<&str>) -> Value {
    if capsule.projection_refs.is_empty() {
        return json!({
            "status": "not_recorded",
            "historical_replay_available": true,
            "current_projection_drift": false,
            "refs": [],
        });
    }

    let mut source = "runtime_current";
    let mut commit_id = Value::Null;
    let registry = if let Some(shard_id) = shard_id.filter(|value| !value.trim().is_empty()) {
        if state.http_dataplane.enabled() {
            match state.http_dataplane.projection_meta(shard_id).await {
                Ok(Some(meta)) => {
                    source = "projection_meta";
                    commit_id = json!(meta.commit_id);
                    if meta.projection_module_registry.is_empty() {
                        corecrux_projections::current_projection_module_versions_v1()
                    } else {
                        meta.projection_module_registry
                    }
                }
                Ok(None) | Err(_) => corecrux_projections::current_projection_module_versions_v1(),
            }
        } else {
            corecrux_projections::current_projection_module_versions_v1()
        }
    } else {
        corecrux_projections::current_projection_module_versions_v1()
    };

    let items = capsule
        .projection_refs
        .iter()
        .map(|reference| {
            let matched = registry.iter().find(|module| {
                module.matches_ref(
                    &reference.module_id,
                    &reference.module_version,
                    reference.code_hash.as_deref(),
                    reference.config_hash.as_deref(),
                ) && reference
                    .schema_version
                    .is_none_or(|schema_version| schema_version == module.schema_version)
            });
            let status = matched.map_or("unavailable", |module| match &module.status {
                corecrux_projections::ProjectionModuleStatusV1::Active => "current",
                corecrux_projections::ProjectionModuleStatusV1::RetainedForReplay => "retained_for_replay",
                corecrux_projections::ProjectionModuleStatusV1::Deprecated => "deprecated",
                corecrux_projections::ProjectionModuleStatusV1::Unavailable => "unavailable",
            });
            json!({
                "module_id": reference.module_id.clone(),
                "module_version": reference.module_version.clone(),
                "code_hash": reference.code_hash.clone(),
                "config_hash": reference.config_hash.clone(),
                "schema_version": reference.schema_version,
                "projection_commit_id": reference.projection_commit_id,
                "projection_registry_hash": reference.projection_registry_hash.clone(),
                "projection_snapshot_hash": reference.projection_snapshot_hash.clone(),
                "install_receipt_id": reference.install_receipt_id.clone(),
                "captured_availability": reference.availability.clone(),
                "status": status,
                "historical_replay_available": matched.is_some_and(|module| module.status.replay_available()),
                "current_module": matched,
            })
        })
        .collect::<Vec<_>>();

    let unavailable = items.iter().any(|item| {
        item["status"]
            .as_str()
            .is_some_and(|status| matches!(status, "unavailable" | "deprecated"))
    });
    let retained = items.iter().any(|item| {
        item["status"]
            .as_str()
            .is_some_and(|status| status == "retained_for_replay")
    });
    let status = if unavailable {
        "unavailable"
    } else if retained {
        "retained_for_replay"
    } else {
        "current"
    };

    json!({
        "status": status,
        "source": source,
        "shard_id": shard_id,
        "commit_id": commit_id,
        "historical_replay_available": !unavailable,
        "current_projection_drift": retained || unavailable,
        "refs": items,
    })
}

async fn living_object_validity(state: &AppState, capsule: &AnswerReplayCapsule) -> Value {
    let artifact_ids = replay_artifact_ids(capsule);
    if artifact_ids.is_empty() {
        return json!({
            "status": "not_recorded",
            "source": "capsule",
            "historical_replay_available": true,
            "current_answer_stale": false,
            "drift_categories": [],
            "artifact_ids": [],
            "artifacts": [],
            "affected_downstream_projections": {
                "dependent_count": 0,
                "dependent_types": [],
            },
        });
    }

    let artifacts = if state.http_dataplane.enabled() {
        dataplane_living_object_artifacts(state, capsule, &artifact_ids).await
    } else {
        local_living_object_artifacts(state, capsule, &artifact_ids).await
    };
    let mut categories = std::collections::BTreeSet::new();
    let mut dependent_types = std::collections::BTreeSet::new();
    let mut dependent_count = 0usize;
    for artifact in &artifacts {
        if let Some(items) = artifact["drift_categories"].as_array() {
            for item in items {
                if let Some(category) = item.as_str() {
                    categories.insert(category.to_string());
                }
            }
        }
        if let Some(items) = artifact["downstream_dependents"].as_array() {
            dependent_count += items.len();
            for item in items {
                if let Some(dependent_type) = item["dependent_type"].as_str() {
                    dependent_types.insert(dependent_type.to_string());
                }
            }
        }
    }
    let categories = categories.into_iter().collect::<Vec<_>>();
    let status = if categories.is_empty() {
        "current"
    } else if categories.iter().all(|category| {
        matches!(
            category.as_str(),
            "living_object_not_projected" | "projection_query_failed"
        )
    }) {
        "unknown"
    } else {
        "stale"
    };

    json!({
        "status": status,
        "source": if state.http_dataplane.enabled() { "dataplane_projection_api" } else { "local_projection_state" },
        "historical_replay_available": true,
        "current_answer_stale": status == "stale",
        "drift_categories": categories,
        "artifact_ids": artifact_ids,
        "projection_tables_checked": [
            "artifact_living_state",
            "artifact_relations",
            "artifact_dependents",
            "pressure_events"
        ],
        "affected_downstream_projections": {
            "dependent_count": dependent_count,
            "dependent_types": dependent_types.into_iter().collect::<Vec<_>>(),
        },
        "artifacts": artifacts,
    })
}

fn replay_artifact_ids(capsule: &AnswerReplayCapsule) -> Vec<u32> {
    capsule
        .evidence
        .iter()
        .filter_map(|evidence| evidence.artifact_id)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

async fn dataplane_living_object_artifacts(
    state: &AppState,
    capsule: &AnswerReplayCapsule,
    artifact_ids: &[u32],
) -> Vec<Value> {
    let mut artifacts = Vec::new();
    for artifact_id in artifact_ids {
        let living = match state
            .http_dataplane
            .projection_artifact_state(&capsule.tenant_id, *artifact_id)
            .await
        {
            Ok(value) => value,
            Err(err) => {
                artifacts.push(projection_query_failed_artifact(*artifact_id, err));
                continue;
            }
        };
        let relations_out = match state
            .http_dataplane
            .projection_relations(&capsule.tenant_id, *artifact_id, "out", None, 50, 0)
            .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|row| dataplane_relation_json("out", row))
                .collect::<Vec<_>>(),
            Err(err) => {
                artifacts.push(projection_query_failed_artifact(*artifact_id, err));
                continue;
            }
        };
        let relations_in = match state
            .http_dataplane
            .projection_relations(&capsule.tenant_id, *artifact_id, "in", None, 50, 0)
            .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|row| dataplane_relation_json("in", row))
                .collect::<Vec<_>>(),
            Err(err) => {
                artifacts.push(projection_query_failed_artifact(*artifact_id, err));
                continue;
            }
        };
        let dependents = match state
            .http_dataplane
            .projection_dependents(&capsule.tenant_id, *artifact_id, None, 50, 0)
            .await
        {
            Ok(rows) => rows.into_iter().map(dataplane_dependent_json).collect::<Vec<_>>(),
            Err(err) => {
                artifacts.push(projection_query_failed_artifact(*artifact_id, err));
                continue;
            }
        };
        let pressure_events = match state
            .http_dataplane
            .projection_pressure_events(&capsule.tenant_id, *artifact_id, true, 50, 0)
            .await
        {
            Ok(rows) => rows.into_iter().map(dataplane_pressure_json).collect::<Vec<_>>(),
            Err(err) => {
                artifacts.push(projection_query_failed_artifact(*artifact_id, err));
                continue;
            }
        };

        artifacts.push(living_artifact_json(
            *artifact_id,
            living.as_ref(),
            relations_out,
            relations_in,
            dependents,
            pressure_events,
        ));
    }
    artifacts
}

async fn local_living_object_artifacts(
    state: &AppState,
    capsule: &AnswerReplayCapsule,
    artifact_ids: &[u32],
) -> Vec<Value> {
    let tenant_hash = corecrux_projections::tenant_hash_xxhash64(&capsule.tenant_id);
    let projection = state.projection_state.read().await;
    let uuid_max = uuid::Uuid::from_bytes([0xff; 16]);
    artifact_ids
        .iter()
        .map(|artifact_id| {
            let living = projection.living.get(&(tenant_hash, *artifact_id));
            let mut relations_out = Vec::new();
            let start = (tenant_hash, *artifact_id, 0u32, 0u8);
            let end = (tenant_hash, *artifact_id, u32::MAX, u8::MAX);
            for ((_tenant, src, dst, relation_type), edge) in projection.relations.range(start..=end) {
                relations_out.push(local_relation_json("out", *src, *dst, *relation_type, edge));
            }

            let mut relations_in = Vec::new();
            let tenant_start = (tenant_hash, 0u32, *artifact_id, 0u8);
            let tenant_end = (tenant_hash, u32::MAX, *artifact_id, u8::MAX);
            for ((_tenant, src, dst, relation_type), edge) in projection.relations.range(tenant_start..=tenant_end) {
                if *dst == *artifact_id {
                    relations_in.push(local_relation_json("in", *src, *dst, *relation_type, edge));
                }
            }

            let dep_start = (tenant_hash, *artifact_id, 0u8, uuid::Uuid::nil());
            let dep_end = (tenant_hash, *artifact_id, u8::MAX, uuid_max);
            let dependents = projection
                .dependents
                .range(dep_start..=dep_end)
                .map(|((_tenant, _artifact, dependent_type, dependent_id), edge)| {
                    local_dependent_json(*dependent_type, *dependent_id, edge)
                })
                .collect::<Vec<_>>();

            let pressure_start = (tenant_hash, *artifact_id, uuid::Uuid::nil());
            let pressure_end = (tenant_hash, *artifact_id, uuid_max);
            let pressure_events = projection
                .pressure
                .range(pressure_start..=pressure_end)
                .filter(|((_tenant, _artifact, _event_id), row)| row.resolved_at_micros <= 0)
                .map(|((_tenant, _artifact, event_id), row)| local_pressure_json(*event_id, row))
                .collect::<Vec<_>>();

            living_artifact_json(
                *artifact_id,
                living,
                relations_out,
                relations_in,
                dependents,
                pressure_events,
            )
        })
        .collect()
}

fn projection_query_failed_artifact(artifact_id: u32, err: super::dataplane::HttpDataplaneError) -> Value {
    json!({
        "artifact_id": artifact_id,
        "status": "unknown",
        "drift_categories": ["projection_query_failed"],
        "error": format!("{err:?}"),
        "living_state": Value::Null,
        "relations_out": [],
        "relations_in": [],
        "downstream_dependents": [],
        "pressure_events": [],
    })
}

fn living_artifact_json(
    artifact_id: u32,
    living: Option<&corecrux_projections::LivingStateRowV1>,
    relations_out: Vec<Value>,
    relations_in: Vec<Value>,
    dependents: Vec<Value>,
    pressure_events: Vec<Value>,
) -> Value {
    let mut categories = std::collections::BTreeSet::new();
    if living.is_none()
        && relations_out.is_empty()
        && relations_in.is_empty()
        && dependents.is_empty()
        && pressure_events.is_empty()
    {
        categories.insert("living_object_not_projected".to_string());
    }
    if let Some(row) = living {
        if let Some(category) = living_status_drift_category(row.living_status) {
            categories.insert(category.to_string());
        }
    }
    for relation in relations_out.iter().chain(relations_in.iter()) {
        match relation["relation_type"].as_str() {
            Some("contradicts") => {
                categories.insert("relation_contradicts".to_string());
            }
            Some("supersedes") => {
                categories.insert("relation_supersedes".to_string());
            }
            _ => {}
        }
    }
    if !pressure_events.is_empty() {
        categories.insert("pressure_open".to_string());
    }
    let categories = categories.into_iter().collect::<Vec<_>>();
    let status = if categories.is_empty() {
        "current"
    } else if categories
        .iter()
        .all(|category| category == "living_object_not_projected")
    {
        "unknown"
    } else {
        "stale"
    };

    json!({
        "artifact_id": artifact_id,
        "status": status,
        "drift_categories": categories,
        "living_state": living.map(living_state_json),
        "relations_out": relations_out,
        "relations_in": relations_in,
        "downstream_dependents": dependents,
        "pressure_events": pressure_events,
    })
}

fn living_status_drift_category(status: corecrux_projections::LivingStatusV1) -> Option<&'static str> {
    match status {
        corecrux_projections::LivingStatusV1::Stale => Some("living_state_stale"),
        corecrux_projections::LivingStatusV1::Contested => Some("living_state_contested"),
        corecrux_projections::LivingStatusV1::Superseded => Some("living_state_superseded"),
        corecrux_projections::LivingStatusV1::Deprecated => Some("living_state_deprecated"),
        corecrux_projections::LivingStatusV1::Dormant | corecrux_projections::LivingStatusV1::Active => None,
    }
}

fn living_state_json(row: &corecrux_projections::LivingStateRowV1) -> Value {
    json!({
        "living_status": row.living_status.as_engine_str(),
        "confidence": corecrux_projections::dequantize_confidence_f32(row.confidence_q16),
        "last_validated_at_micros": row.last_validated_at_micros,
        "next_review_at_micros": row.next_review_at_micros,
        "pressure_level": row.pressure_level,
        "pressure_reasons_mask": row.pressure_reasons_mask,
        "trunk_tier": row.trunk_tier,
        "relations_out_count": row.relations_out_count,
        "relations_in_count": row.relations_in_count,
        "dependents_count": row.dependents_count,
        "updated_at_micros": row.updated_at_micros,
    })
}

fn dataplane_relation_json(direction: &str, row: crate::dataplane_store::ProjectionRelationRowV1) -> Value {
    json!({
        "direction": direction,
        "src_artifact_id": row.src_artifact_id,
        "dst_artifact_id": row.dst_artifact_id,
        "relation_type": relation_type_name(row.relation_type),
        "confidence": corecrux_projections::dequantize_confidence_f32(row.confidence_q16),
        "evidence_ref_hash16": hex_bytes(&row.evidence_ref_hash16),
        "created_at_micros": row.created_at_micros,
        "updated_at_micros": row.updated_at_micros,
    })
}

fn local_relation_json(
    direction: &str,
    src_artifact_id: u32,
    dst_artifact_id: u32,
    relation_type: u8,
    row: &corecrux_projections::RelationEdgeV1,
) -> Value {
    json!({
        "direction": direction,
        "src_artifact_id": src_artifact_id,
        "dst_artifact_id": dst_artifact_id,
        "relation_type": relation_type_name(relation_type),
        "confidence": corecrux_projections::dequantize_confidence_f32(row.confidence_q16),
        "evidence_ref_hash16": hex_bytes(&row.evidence_ref_hash16),
        "created_at_micros": row.created_at_micros,
        "updated_at_micros": row.updated_at_micros,
    })
}

fn dataplane_dependent_json(row: crate::dataplane_store::ProjectionDependentRowV1) -> Value {
    json!({
        "dependent_type": dependent_type_name(row.dependent_type),
        "dependent_id": row.dependent_id,
        "last_seen_at_micros": row.last_seen_at_micros,
        "usage_weight": corecrux_projections::dequantize_confidence_f32(row.usage_weight_q16),
    })
}

fn local_dependent_json(
    dependent_type: u8,
    dependent_id: uuid::Uuid,
    row: &corecrux_projections::DependentEdgeV1,
) -> Value {
    json!({
        "dependent_type": dependent_type_name(dependent_type),
        "dependent_id": dependent_id.to_string(),
        "last_seen_at_micros": row.last_seen_at_micros,
        "usage_weight": corecrux_projections::dequantize_confidence_f32(row.usage_weight_q16),
    })
}

fn dataplane_pressure_json(row: crate::dataplane_store::ProjectionPressureEventRowV1) -> Value {
    json!({
        "event_id": row.event_id.to_string(),
        "pressure_code_id": row.pressure_code_id,
        "severity": row.severity,
        "observed_at_micros": row.observed_at_micros,
        "acknowledged_at_micros": row.acknowledged_at_micros,
        "resolved_at_micros": row.resolved_at_micros,
        "receipt_id": row.receipt_id.map(|id| id.to_string()),
    })
}

fn local_pressure_json(event_id: uuid::Uuid, row: &corecrux_projections::PressureEventRowV1) -> Value {
    json!({
        "event_id": event_id.to_string(),
        "pressure_code_id": row.pressure_code_id,
        "severity": row.severity,
        "observed_at_micros": row.observed_at_micros,
        "acknowledged_at_micros": row.acknowledged_at_micros,
        "resolved_at_micros": row.resolved_at_micros,
        "receipt_id": row.receipt_id.map(|id| id.to_string()),
    })
}

fn relation_type_name(relation_type: u8) -> String {
    corecrux_projections::RelationTypeV1::from_u8(relation_type).map_or_else(
        || format!("unknown({relation_type})"),
        |relation| relation.as_engine_str().to_string(),
    )
}

fn dependent_type_name(dependent_type: u8) -> String {
    corecrux_projections::DependentTypeV1::from_u8(dependent_type).map_or_else(
        || format!("unknown({dependent_type})"),
        |dependent| dependent.as_engine_str().to_string(),
    )
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn drift_categories(
    evidence: &[Value],
    semantic: &Value,
    projection_modules: &Value,
    living_objects: &Value,
) -> Vec<String> {
    let mut categories = std::collections::BTreeSet::new();
    for item in evidence {
        if let Some(category) = item["drift_category"].as_str() {
            categories.insert(category.to_string());
        }
    }
    match semantic["status"].as_str() {
        Some("changed") => {
            categories.insert("semantic_profile_changed".to_string());
        }
        Some("not_configured") => {
            categories.insert("semantic_profile_not_configured".to_string());
        }
        _ => {}
    }
    match projection_modules["status"].as_str() {
        Some("retained_for_replay") => {
            categories.insert("projection_module_retained_for_replay".to_string());
        }
        Some("unavailable") => {
            categories.insert("projection_module_unavailable".to_string());
        }
        Some("deprecated") => {
            categories.insert("projection_module_deprecated".to_string());
        }
        _ => {}
    }
    if let Some(items) = living_objects["drift_categories"].as_array() {
        for item in items {
            if let Some(category) = item.as_str() {
                categories.insert(category.to_string());
            }
        }
    }
    categories.into_iter().collect()
}

fn export_answer_capsule(state: &AppState, capsule: &AnswerReplayCapsule, opts: ReceiptExportOptionsV1) -> Response {
    let exported_capsule = if matches!(opts.redaction, ExportRedactionV1::MetadataOnly) {
        capsule.metadata_only()
    } else {
        capsule.clone()
    };
    let capsule_json = match serde_json::to_vec_pretty(&exported_capsule) {
        Ok(value) => value,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    let rendered = if matches!(opts.redaction, ExportRedactionV1::MetadataOnly) {
        Vec::new()
    } else {
        capsule.rendered_answer.as_bytes().to_vec()
    };
    let evidence_jsonl = match build_evidence_jsonl(&exported_capsule.evidence) {
        Ok(value) => value,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    let receipts_json = match serde_json::to_vec_pretty(&capsule.source_receipts) {
        Ok(value) => value,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    let projections_json = match serde_json::to_vec_pretty(&capsule.projection_refs) {
        Ok(value) => value,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    let mut files = vec![
        ("answer/capsule.json".to_string(), capsule_json),
        ("answer/evidence.jsonl".to_string(), evidence_jsonl),
        ("answer/source_receipts.json".to_string(), receipts_json),
        ("answer/projection_refs.json".to_string(), projections_json),
        (
            "raw_frames/README.json".to_string(),
            br#"{"status":"not_included","detail":"local replay capsule export has no raw dataplane frame bundle"}"#
                .to_vec(),
        ),
    ];
    if !rendered.is_empty() {
        files.push(("answer/rendered_answer.txt".to_string(), rendered));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let included_files = files
        .iter()
        .map(|(path, bytes)| {
            json!({
                "path": path,
                "blake3": blake3::hash(bytes).to_hex().to_string(),
                "size": bytes.len() as u64,
            })
        })
        .collect::<Vec<_>>();
    let manifest = json!({
        "export_schema": ANSWER_REPLAY_EXPORT_SCHEMA,
        "generated_at": capsule.created_at,
        "tenant_id": capsule.tenant_id,
        "answer_id": capsule.answer_id,
        "capsule_hash": capsule.capsule_hash,
        "corecrux_build": {
            "version": state.build.version,
            "commit": state.build.commit,
        },
        "format": opts.format.as_str(),
        "redaction": opts.redaction.as_str(),
        "include": opts.include.iter().map(ReceiptExportIncludeV1::as_str).collect::<Vec<_>>(),
        "included_files": included_files,
        "historical_replay": {
            "agent_required": false,
            "llm_required": false,
            "render_strategy": "render_stored_answer"
        },
    });
    let manifest_json = match serde_json::to_vec_pretty(&manifest) {
        Ok(value) => value,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    files.push(("manifest.json".to_string(), manifest_json));
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let archive = match opts.format {
        ExportFormatV1::Zip => super::receipts::build_zip_deterministic_bytes(&files),
        ExportFormatV1::TarZst => super::receipts::build_tar_zst_deterministic_bytes(&files),
    };
    let archive = match archive {
        Ok(value) => value,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    let filename = format!(
        "answer-replay-{}-{}.{}",
        sanitize_filename_part(&capsule.tenant_id),
        sanitize_filename_part(&capsule.answer_id),
        opts.format.filename_ext()
    );

    let mut response = axum::response::Response::new(axum::body::Body::from(archive));
    *response.status_mut() = StatusCode::OK;
    #[allow(clippy::unwrap_used)] // content_type() returns a static ASCII MIME string.
    {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, opts.format.content_type().parse().unwrap());
    }
    response
        .headers_mut()
        .insert(header::CONTENT_DISPOSITION, attachment_disposition(&filename));
    response
}

fn build_evidence_jsonl(evidence: &[ReplayEvidenceRef]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for item in evidence {
        serde_json::to_writer(&mut out, item).map_err(|err| err.to_string())?;
        out.push(b'\n');
    }
    Ok(out)
}

/// Build a `Content-Disposition: attachment` header value from an untrusted
/// filename. Every byte that survives [`sanitize_filename_part`] is ASCII
/// alphanumeric, `-`, `_` or `.`, so the resulting string is always a valid
/// header value and this cannot fail — the callers below rely on that rather
/// than unwrapping a `parse()` on raw path parameters.
pub(super) fn attachment_disposition(filename: &str) -> header::HeaderValue {
    let safe = sanitize_filename_part(filename);
    header::HeaderValue::from_str(&format!("attachment; filename=\"{safe}\""))
        .unwrap_or_else(|_| header::HeaderValue::from_static("attachment"))
}

pub(super) fn sanitize_filename_part(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[test]
    fn attachment_disposition_survives_hostile_path_params() {
        // CR/LF and non-ASCII reach these filenames straight off the request
        // path (GET /v1/replay/exports/streams/{streamType}/{streamId}), which
        // HeaderValue::from_str rejects. Previously this was `.parse().unwrap()`
        // and panicked into the CatchPanicLayer as a 500.
        for hostile in ["a\r\nX-Evil: 1", "réçeipt", "id\u{0}null", "", "../../etc/passwd"] {
            let v = super::attachment_disposition(hostile);
            let s = v.to_str().expect("header value is valid ASCII");
            assert!(s.starts_with("attachment"), "unexpected disposition: {s}");
            assert!(!s.contains('\r') && !s.contains('\n'), "header injection: {s}");
        }
        assert_eq!(
            super::attachment_disposition("receipt-abc.zip").to_str().unwrap(),
            "attachment; filename=\"receipt-abc.zip\""
        );
    }

    use super::*;
    use crate::dataplane_store::{ProjectionDependentRowV1, ProjectionPressureEventRowV1, ProjectionRelationRowV1};
    use crate::http::tests::{dev_scope_headers, test_app_state, test_app_state_with_auth};
    use corecrux_memory::replay::{BuildAnswerReplayCapsule, ProjectionReplayRef};
    use corecrux_projections::{
        DependentEdgeV1, LivingStateRowV1, LivingStatusV1, PressureEventRowV1, ProjectionModuleStatusV1,
        ProjectionModuleVersionV1, ProjectionsMetaV1, RelationEdgeV1, RelationTypeV1,
    };
    use std::io::Read as _;

    // ---------------------------------------------------------------- helpers

    async fn body_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    async fn body_bytes(resp: Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), 1 << 22)
            .await
            .expect("read body")
            .to_vec()
    }

    /// `replay:answer` is a Pro capability claim, so every replay surface answers
    /// 402 unless the operating mode includes Pro *and* the service is enabled.
    fn pro_replay_state() -> AppState {
        let mut state = test_app_state(16);
        state.operating_mode = crate::product::OperatingMode::ProHybrid;
        state.enabled_pro_services = vec!["replay:answer".to_string()];
        state
    }

    fn pro_replay_state_dev_scopes() -> AppState {
        let mut state = test_app_state_with_auth(16, crate::auth::AuthMode::DevScopes);
        state.operating_mode = crate::product::OperatingMode::ProHybrid;
        state.enabled_pro_services = vec!["replay:answer".to_string()];
        state
    }

    fn query(tenant_id: &str) -> ReplayQuery {
        ReplayQuery {
            tenant_id: tenant_id.to_string(),
            shard_id: None,
        }
    }

    fn evidence_ref(record_id: &str) -> ReplayEvidenceRef {
        ReplayEvidenceRef {
            record_id: record_id.to_string(),
            artifact_id: None,
            source_label: Some("local-fact".to_string()),
            text: Some("captured evidence text".to_string()),
            text_hash: None,
            content_hash: None,
            semantic_profile_id: None,
            local_semantic_profile_id: None,
            score_space: None,
            receipt_id: Some("crx_ev_1".to_string()),
        }
    }

    fn capsule_with(
        tenant_id: &str,
        answer_id: &str,
        evidence: Vec<ReplayEvidenceRef>,
        projection_refs: Vec<ProjectionReplayRef>,
    ) -> AnswerReplayCapsule {
        AnswerReplayCapsule::build(BuildAnswerReplayCapsule {
            answer_id: answer_id.to_string(),
            tenant_id: tenant_id.to_string(),
            source: "test".to_string(),
            question: "why".to_string(),
            stored_answer: json!({ "answer": "the stored answer" }),
            evidence,
            projection_refs,
            source_receipts: vec!["crx_receipt_1".to_string()],
            context_pack_receipt_id: None,
            semantic_profile_id: None,
            local_semantic_profile_id: None,
            created_at: "2026-05-07T00:00:00Z".to_string(),
        })
    }

    fn put_fact(store: &mut FactStore, tenant_hash: &str, entity: &str, key: &str, value: &str) -> Fact {
        store.store(StoreFact {
            tenant_hash: tenant_hash.to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        })
    }

    /// A capsule whose single evidence ref points at a fact that is still
    /// byte-identical to what was captured — the "nothing drifted" baseline.
    async fn state_with_matching_evidence(tenant_id: &str, answer_id: &str) -> (AppState, AnswerReplayCapsule) {
        let state = pro_replay_state();
        let fact = {
            let mut store = state.fact_store.write().await;
            put_fact(&mut store, "default", "tenant::doc", "content", "stable body")
        };
        let mut evidence = evidence_ref(&fact.fact_id);
        evidence.text_hash = Some(hash_text(&fact.value));
        let capsule = capsule_with(tenant_id, answer_id, vec![evidence], Vec::new());
        store_answer_capsule(&state, &capsule).await.expect("store capsule");
        (state, capsule)
    }

    /// Which projection query the fake dataplane should fail, so the five
    /// independent `Err(..) => continue` arms in `dataplane_living_object_artifacts`
    /// can each be exercised.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FailStage {
        State,
        RelationsOut,
        RelationsIn,
        Dependents,
        Pressure,
    }

    #[derive(Default)]
    struct FakeReplayDataplane {
        enabled: bool,
        projection_meta: Option<ProjectionsMetaV1>,
        living: Option<LivingStateRowV1>,
        relations_out: Vec<ProjectionRelationRowV1>,
        relations_in: Vec<ProjectionRelationRowV1>,
        dependents: Vec<ProjectionDependentRowV1>,
        pressure: Vec<ProjectionPressureEventRowV1>,
        fail_stage: Option<FailStage>,
    }

    impl FakeReplayDataplane {
        fn enabled() -> Self {
            Self {
                enabled: true,
                ..Self::default()
            }
        }

        fn fails_at(stage: FailStage) -> Self {
            Self {
                enabled: true,
                fail_stage: Some(stage),
                ..Self::default()
            }
        }

        fn shared(self) -> SharedHttpDataplane {
            std::sync::Arc::new(self)
        }

        fn boom() -> HttpDataplaneError {
            HttpDataplaneError::Store(AppendError::Internal("fake projection failure".to_string()))
        }
    }

    #[tonic::async_trait]
    impl HttpDataplane for FakeReplayDataplane {
        fn enabled(&self) -> bool {
            self.enabled
        }

        async fn append_batch(
            &self,
            _tenant_id: &str,
            _stream_type: &str,
            _stream_id: &str,
            _expected_next_seq: u64,
            _events: &[AppendEvent],
        ) -> Result<(), HttpDataplaneError> {
            Ok(())
        }

        async fn read_stream(
            &self,
            _tenant_id: &str,
            _stream_type: &str,
            _stream_id: &str,
            _from_seq: u64,
            _max_events: u32,
        ) -> Result<Vec<crate::dataplane_store::StoredEvent>, HttpDataplaneError> {
            Ok(Vec::new())
        }

        async fn read_tail(
            &self,
            _tenant_id: &str,
            _stream_type: &str,
            _stream_id: &str,
            _count: u32,
        ) -> Result<Vec<crate::dataplane_store::StoredEvent>, HttpDataplaneError> {
            Ok(Vec::new())
        }

        async fn verify_receipt_stream(
            &self,
            _tenant_id: &str,
            _receipt_id: &str,
            _shard_id_hint: Option<u32>,
        ) -> Result<Option<corecrux_receipts::VerificationReportV1>, HttpDataplaneError> {
            Ok(None)
        }

        async fn graph_expand(
            &self,
            _req: super::super::dataplane::GraphExpandRequest<'_>,
        ) -> Result<corecrux_projections::query::graph_expand::GraphExpandResponse, HttpDataplaneError> {
            Ok(corecrux_projections::query::graph_expand::GraphExpandResponse {
                artifacts: Vec::new(),
                stats: Default::default(),
            })
        }

        async fn time_range(
            &self,
            _tenant_id: &str,
            _start_micros: i64,
            _end_micros: i64,
            _artifact_ids: &[u32],
            _include_relations: bool,
            _limit: usize,
        ) -> Result<corecrux_projections::query::time_range::TimeRangeResponse, HttpDataplaneError> {
            Ok(corecrux_projections::query::time_range::TimeRangeResponse {
                artifacts: Vec::new(),
                stats: Default::default(),
            })
        }

        async fn projection_meta(&self, _shard_id: &str) -> Result<Option<ProjectionsMetaV1>, HttpDataplaneError> {
            Ok(self.projection_meta.clone())
        }

        async fn projection_artifact_state(
            &self,
            _tenant_id: &str,
            _artifact_id: u32,
        ) -> Result<Option<LivingStateRowV1>, HttpDataplaneError> {
            if self.fail_stage == Some(FailStage::State) {
                return Err(Self::boom());
            }
            Ok(self.living.clone())
        }

        async fn projection_relations(
            &self,
            _tenant_id: &str,
            _artifact_id: u32,
            direction: &str,
            _relation_type: Option<&str>,
            _limit: usize,
            _offset: usize,
        ) -> Result<Vec<ProjectionRelationRowV1>, HttpDataplaneError> {
            if direction == "out" {
                if self.fail_stage == Some(FailStage::RelationsOut) {
                    return Err(Self::boom());
                }
                return Ok(self.relations_out.clone());
            }
            if self.fail_stage == Some(FailStage::RelationsIn) {
                return Err(Self::boom());
            }
            Ok(self.relations_in.clone())
        }

        async fn projection_dependents(
            &self,
            _tenant_id: &str,
            _artifact_id: u32,
            _dependent_type: Option<&str>,
            _limit: usize,
            _offset: usize,
        ) -> Result<Vec<ProjectionDependentRowV1>, HttpDataplaneError> {
            if self.fail_stage == Some(FailStage::Dependents) {
                return Err(Self::boom());
            }
            Ok(self.dependents.clone())
        }

        async fn projection_pressure_events(
            &self,
            _tenant_id: &str,
            _artifact_id: u32,
            _open_only: bool,
            _limit: usize,
            _offset: usize,
        ) -> Result<Vec<ProjectionPressureEventRowV1>, HttpDataplaneError> {
            if self.fail_stage == Some(FailStage::Pressure) {
                return Err(Self::boom());
            }
            Ok(self.pressure.clone())
        }

        async fn rebuild_projections_online(
            &self,
            _max_frames: u32,
        ) -> Result<Vec<(String, Result<crate::dataplane_store::ForceSealAndTickResult, String>)>, HttpDataplaneError>
        {
            Ok(Vec::new())
        }

        async fn entity_count(
            &self,
            _tenant_id: &str,
            _entity_type: &str,
            _predicate: &str,
        ) -> Result<Vec<String>, HttpDataplaneError> {
            Ok(Vec::new())
        }

        async fn entity_timeline(
            &self,
            _tenant_id: &str,
            _entity_type: &str,
            _predicate: &str,
        ) -> Result<Vec<(String, String, i64)>, HttpDataplaneError> {
            Ok(Vec::new())
        }

        async fn entity_current_state(
            &self,
            _tenant_id: &str,
            _entity_name: &str,
            _predicate: &str,
        ) -> Result<Option<(String, i64, Option<String>, Option<i64>)>, HttpDataplaneError> {
            Ok(None)
        }
    }

    // ---------------------------------------------------- gate / auth surface

    #[tokio::test]
    async fn replay_rejects_blank_tenant_id_before_touching_the_store() {
        // `tenant_id` is trimmed, so a whitespace-only value must not silently
        // become a lookup against the empty-tenant entity namespace.
        for tenant in ["", "   "] {
            let resp = get_answer_replay(
                State(pro_replay_state()),
                Path("ans_1".to_string()),
                Query(query(tenant)),
                HeaderMap::new(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "tenant {tenant:?}");
        }
        let resp = get_answer_replay_validity(
            State(pro_replay_state()),
            Path("ans_1".to_string()),
            Query(query("  ")),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn replay_is_payment_required_when_pro_service_is_off() {
        // Default CE posture is FreeLocal: the deterministic replay surfaces must
        // advertise the capability + a fallback reason, never leak a capsule.
        for resp in [
            get_answer_replay(
                State(test_app_state(16)),
                Path("ans_1".to_string()),
                Query(query("tenant-a")),
                HeaderMap::new(),
            )
            .await,
            get_answer_replay_validity(
                State(test_app_state(16)),
                Path("ans_1".to_string()),
                Query(query("tenant-a")),
                HeaderMap::new(),
            )
            .await,
        ] {
            assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
            let body = body_json(resp).await;
            assert_eq!(body["status"], "pro_service_not_enabled");
            assert_eq!(body["capability"], "replay:answer");
            assert_eq!(body["fallback"]["reason_code"], "pro_service_not_enabled");
        }
    }

    #[tokio::test]
    async fn replay_pro_gate_rejects_pro_service_enabled_on_a_free_mode() {
        // `enabled_pro_services` alone is not enough — ProductPosture filters it
        // by operating mode, so a FreeLocal daemon with the service listed in
        // config still must not serve replay.
        let mut state = test_app_state(16);
        state.enabled_pro_services = vec!["replay:answer".to_string()];
        let resp = get_answer_replay(
            State(state),
            Path("ans_1".to_string()),
            Query(query("tenant-a")),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn replay_requires_authentication_before_the_pro_gate() {
        // No scope header at all under DevScopes ⇒ 401, not 403 and not 402:
        // an unauthenticated caller must not learn the Pro posture.
        let resp = get_answer_replay(
            State(pro_replay_state_dev_scopes()),
            Path("ans_1".to_string()),
            Query(query("tenant-a")),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn replay_rejects_authenticated_caller_without_replay_scope() {
        let resp = get_answer_replay(
            State(pro_replay_state_dev_scopes()),
            Path("ans_1".to_string()),
            Query(query("tenant-a")),
            dev_scope_headers("facts:read"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = get_answer_replay_validity(
            State(pro_replay_state_dev_scopes()),
            Path("ans_1".to_string()),
            Query(query("tenant-a")),
            dev_scope_headers("facts:read"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn replay_accepts_either_admin_read_or_replay_answer_scope() {
        // 404 (capsule absent) rather than 403 is the signal that the scope gate
        // let the caller through — `admin:read` short-circuits the tenant-scoped
        // `replay:answer` check.
        for scopes in ["admin:read", "replay:answer"] {
            let resp = get_answer_replay(
                State(pro_replay_state_dev_scopes()),
                Path("ans_1".to_string()),
                Query(query("tenant-a")),
                dev_scope_headers(scopes),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "scopes {scopes}");
        }
    }

    // ------------------------------------------------------- replay behaviour

    #[tokio::test]
    async fn get_answer_replay_renders_stored_answer_without_agent_or_llm() {
        let (state, capsule) = state_with_matching_evidence("tenant-a", "ans_1").await;
        let resp = get_answer_replay(
            State(state),
            Path("ans_1".to_string()),
            Query(query("tenant-a")),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["schema"], ANSWER_REPLAY_RESPONSE_SCHEMA);
        assert_eq!(body["mode"], "historical_replay");
        // The module doc promises replay never invokes an agent or an LLM.
        assert_eq!(body["agent_required"], false);
        assert_eq!(body["llm_required"], false);
        assert_eq!(body["rendered_answer"], capsule.rendered_answer);
        assert_eq!(body["stored_answer"]["answer"], "the stored answer");
        assert_eq!(body["capsule"]["capsule_hash"], capsule.capsule_hash);
        assert_eq!(body["evidence"].as_array().expect("evidence array").len(), 1);
    }

    #[tokio::test]
    async fn get_answer_replay_is_scoped_to_the_requested_tenant() {
        // The capsule entity embeds the tenant id; asking for the same answer id
        // under a different tenant must 404 rather than cross-serve.
        let (state, _capsule) = state_with_matching_evidence("tenant-a", "ans_1").await;
        let resp = get_answer_replay(
            State(state.clone()),
            Path("ans_1".to_string()),
            Query(query("tenant-b")),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = get_answer_replay_validity(
            State(state),
            Path("ans_1".to_string()),
            Query(query("tenant-b")),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_answer_replay_missing_capsule_is_a_problem_404() {
        let resp = get_answer_replay(
            State(pro_replay_state()),
            Path("nope".to_string()),
            Query(query("tenant-a")),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = body_json(resp).await;
        assert_eq!(body["detail"], "answer replay capsule not found");
    }

    // ----------------------------------------------------- validity behaviour

    #[tokio::test]
    async fn validity_reports_historically_replayable_when_nothing_drifted() {
        let (state, capsule) = state_with_matching_evidence("tenant-a", "ans_1").await;
        let resp = get_answer_replay_validity(
            State(state),
            Path("ans_1".to_string()),
            Query(query("tenant-a")),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["schema"], ANSWER_REPLAY_VALIDITY_SCHEMA);
        assert_eq!(body["overall"], "historically_replayable");
        assert_eq!(body["capsule_hash"], capsule.capsule_hash);
        assert_eq!(body["current_answer"]["status"], "current");
        assert_eq!(body["current_answer"]["stale"], false);
        assert_eq!(body["current_answer"]["drift_categories"], json!([]));
        // Historical replay stays available regardless of current-world drift.
        assert_eq!(body["historical_replay_available"], true);
        assert_eq!(body["historical_answer"]["status"], "verified");
        assert_eq!(body["historical_answer"]["render_strategy"], "render_stored_answer");
        assert_eq!(body["evidence"][0]["status"], "current");
        assert_eq!(body["semantic_profile"]["status"], "not_recorded");
        assert_eq!(body["projection_modules"]["status"], "not_recorded");
        assert_eq!(body["living_objects"]["status"], "not_recorded");
    }

    #[tokio::test]
    async fn validity_marks_current_answer_stale_when_the_evidence_fact_changed() {
        let state = pro_replay_state();
        let fact = {
            let mut store = state.fact_store.write().await;
            put_fact(&mut store, "default", "tenant::doc", "content", "body v1")
        };
        let mut evidence = evidence_ref(&fact.fact_id);
        evidence.text_hash = Some(hash_text("something else entirely"));
        let capsule = capsule_with("tenant-a", "ans_1", vec![evidence], Vec::new());
        store_answer_capsule(&state, &capsule).await.expect("store capsule");

        let resp = get_answer_replay_validity(
            State(state),
            Path("ans_1".to_string()),
            Query(query("tenant-a")),
            HeaderMap::new(),
        )
        .await;
        let body = body_json(resp).await;
        assert_eq!(body["overall"], "drift_detected");
        assert_eq!(body["current_answer"]["status"], "stale");
        assert_eq!(body["current_answer"]["stale"], true);
        assert_eq!(body["current_answer"]["drift_categories"], json!(["fact_changed"]));
        // Even with drift the stored answer is still replayable.
        assert_eq!(body["historical_replay_available"], true);
    }

    #[tokio::test]
    async fn validity_is_unknown_not_stale_when_only_the_living_object_is_unprojected() {
        // An artifact that was never projected locally is missing information,
        // not evidence of staleness — collapsing the two would make every fresh
        // daemon report every historical answer as stale.
        let state = pro_replay_state();
        let fact = {
            let mut store = state.fact_store.write().await;
            put_fact(&mut store, "default", "tenant::doc", "content", "stable body")
        };
        let mut evidence = evidence_ref(&fact.fact_id);
        evidence.text_hash = Some(hash_text(&fact.value));
        evidence.artifact_id = Some(77);
        let capsule = capsule_with("tenant-a", "ans_1", vec![evidence], Vec::new());
        store_answer_capsule(&state, &capsule).await.expect("store capsule");

        let resp = get_answer_replay_validity(
            State(state),
            Path("ans_1".to_string()),
            Query(query("tenant-a")),
            HeaderMap::new(),
        )
        .await;
        let body = body_json(resp).await;
        assert_eq!(body["overall"], "drift_detected");
        assert_eq!(body["current_answer"]["status"], "unknown");
        assert_eq!(body["current_answer"]["stale"], false);
        assert_eq!(
            body["current_answer"]["drift_categories"],
            json!(["living_object_not_projected"])
        );
        assert_eq!(body["living_objects"]["source"], "local_projection_state");
    }

    // ------------------------------------------------------ capsule store/load

    #[tokio::test]
    async fn store_then_load_answer_capsule_round_trips() {
        let state = pro_replay_state();
        let capsule = capsule_with("tenant-a", "ans_1", vec![evidence_ref("f_1")], Vec::new());
        store_answer_capsule(&state, &capsule).await.expect("store capsule");
        let loaded = load_answer_capsule(&state, "tenant-a", "ans_1", "default")
            .await
            .expect("capsule present");
        assert_eq!(loaded, capsule);
        assert!(load_answer_capsule(&state, "tenant-a", "ans_2", "default")
            .await
            .is_none());
    }

    #[test]
    fn load_answer_capsule_from_store_never_crosses_tenant_hashes() {
        // Capsules are stored private under a tenant hash; a read context that
        // resolves to a different hash must see nothing at all.
        let mut store = FactStore::new();
        let capsule = capsule_with("tenant-a", "ans_1", vec![evidence_ref("f_1")], Vec::new());
        put_fact(
            &mut store,
            "tenant-hash-a",
            &answer_capsule_entity("tenant-a", "ans_1"),
            "capsule",
            &serde_json::to_string(&capsule).unwrap(),
        );
        assert!(load_answer_capsule_from_store(&store, "tenant-a", "ans_1", "tenant-hash-a").is_some());
        assert!(load_answer_capsule_from_store(&store, "tenant-a", "ans_1", "tenant-hash-b").is_none());
        assert!(load_answer_capsule_from_store(&store, "tenant-a", "ans_1", "default").is_none());
    }

    #[test]
    fn load_answer_capsule_from_store_takes_the_latest_version_and_ignores_other_keys() {
        let mut store = FactStore::new();
        let entity = answer_capsule_entity("tenant-a", "ans_1");
        let v1 = capsule_with("tenant-a", "ans_1", vec![evidence_ref("f_1")], Vec::new());
        let v2 = capsule_with("tenant-a", "ans_1", vec![evidence_ref("f_2")], Vec::new());
        put_fact(
            &mut store,
            "default",
            &entity,
            "capsule",
            &serde_json::to_string(&v1).unwrap(),
        );
        put_fact(
            &mut store,
            "default",
            &entity,
            "capsule",
            &serde_json::to_string(&v2).unwrap(),
        );
        // A sibling key on the same entity must not be mistaken for a capsule.
        put_fact(&mut store, "default", &entity, "note", "not a capsule");
        let loaded = load_answer_capsule_from_store(&store, "tenant-a", "ans_1", "default").expect("capsule");
        assert_eq!(loaded.evidence[0].record_id, "f_2");
    }

    #[test]
    fn load_answer_capsule_from_store_degrades_to_none_on_corrupt_json() {
        // A hand-edited or truncated capsule fact must not panic the read path.
        let mut store = FactStore::new();
        put_fact(
            &mut store,
            "default",
            &answer_capsule_entity("tenant-a", "ans_1"),
            "capsule",
            "{not json",
        );
        assert!(load_answer_capsule_from_store(&store, "tenant-a", "ans_1", "default").is_none());
    }

    #[test]
    fn load_answer_capsule_from_store_returns_none_when_entity_absent() {
        let store = FactStore::new();
        assert!(load_answer_capsule_from_store(&store, "tenant-a", "ans_1", "default").is_none());
    }

    // ------------------------------------------------------ evidence validity

    #[test]
    fn evidence_ref_validity_reports_missing_fact() {
        let store = FactStore::new();
        let value = evidence_ref_validity(&store, &evidence_ref("f_gone"), "default");
        assert_eq!(value["status"], "missing");
        assert_eq!(value["drift_category"], "fact_missing");
        assert_eq!(value["record_id"], "f_gone");
        // A missing fact carries no current/latest ids to leak.
        assert!(value.get("current_fact_id").is_none());
    }

    #[test]
    fn evidence_ref_validity_reports_current_when_the_text_hash_still_matches() {
        let mut store = FactStore::new();
        let fact = put_fact(&mut store, "default", "tenant::doc", "content", "unchanged body");
        let mut evidence = evidence_ref(&fact.fact_id);
        evidence.text_hash = Some(hash_text(&fact.value));
        let value = evidence_ref_validity(&store, &evidence, "default");
        assert_eq!(value["status"], "current");
        assert_eq!(value["drift_category"], Value::Null);
        assert_eq!(value["current_fact_id"], fact.fact_id);
        assert_eq!(value["latest_fact_id"], fact.fact_id);
        assert_eq!(value["current_text_hash"], hash_text("unchanged body"));
        assert_eq!(value["supersession_chain"].as_array().expect("chain").len(), 1);
    }

    #[test]
    fn evidence_ref_validity_falls_back_to_the_content_hash() {
        // A capsule written by a producer that only recorded `content_hash` must
        // still verify, and a stale `text_hash` must not veto a matching
        // `content_hash`.
        let mut store = FactStore::new();
        let fact = put_fact(&mut store, "default", "tenant::doc", "content", "unchanged body");

        let mut only_content = evidence_ref(&fact.fact_id);
        only_content.content_hash = Some(hash_text(&fact.value));
        assert_eq!(
            evidence_ref_validity(&store, &only_content, "default")["status"],
            "current"
        );

        let mut stale_text_hash = evidence_ref(&fact.fact_id);
        stale_text_hash.text_hash = Some(hash_text("older body"));
        stale_text_hash.content_hash = Some(hash_text(&fact.value));
        assert_eq!(
            evidence_ref_validity(&store, &stale_text_hash, "default")["status"],
            "current"
        );
    }

    #[test]
    fn evidence_ref_validity_reports_changed_when_no_captured_hash_matches() {
        let mut store = FactStore::new();
        let fact = put_fact(&mut store, "default", "tenant::doc", "content", "new body");
        let mut evidence = evidence_ref(&fact.fact_id);
        evidence.text_hash = Some(hash_text("old body"));
        let value = evidence_ref_validity(&store, &evidence, "default");
        assert_eq!(value["status"], "changed");
        assert_eq!(value["drift_category"], "fact_changed");

        // No captured hash at all is also "changed", never a silent "current".
        let value = evidence_ref_validity(&store, &evidence_ref(&fact.fact_id), "default");
        assert_eq!(value["status"], "changed");
    }

    #[test]
    fn evidence_validity_marks_superseded_fact() {
        let mut store = FactStore::new();
        let first = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "tenant-a::doc".to_string(),
            key: "content".to_string(),
            value: "old answer context".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "tenant-a::doc".to_string(),
            key: "content".to_string(),
            value: "new answer context".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let capsule = AnswerReplayCapsule::build(BuildAnswerReplayCapsule {
            answer_id: "ans_1".to_string(),
            tenant_id: "tenant-a".to_string(),
            source: "test".to_string(),
            question: "q".to_string(),
            stored_answer: json!({ "answer": "a" }),
            evidence: vec![ReplayEvidenceRef {
                record_id: first.fact_id.clone(),
                artifact_id: None,
                source_label: None,
                text: Some(first.value.clone()),
                text_hash: Some(hash_text(&first.value)),
                content_hash: None,
                semantic_profile_id: None,
                local_semantic_profile_id: None,
                score_space: None,
                receipt_id: None,
            }],
            projection_refs: vec![ProjectionReplayRef {
                module_id: "projection.placeholder".to_string(),
                module_version: "pending_m8".to_string(),
                code_hash: None,
                config_hash: None,
                schema_version: None,
                projection_commit_id: None,
                projection_registry_hash: None,
                projection_snapshot_hash: None,
                install_receipt_id: None,
                availability: "pending_m8".to_string(),
            }],
            source_receipts: Vec::new(),
            context_pack_receipt_id: None,
            semantic_profile_id: None,
            local_semantic_profile_id: None,
            created_at: "2026-05-07T00:00:00Z".to_string(),
        });

        let status = evidence_validity(&store, &capsule, "default");
        assert_eq!(status[0]["status"], "superseded");
        assert_eq!(status[0]["drift_category"], "fact_superseded");
        // The chain is version-ordered so an auditor can follow the supersession.
        let chain = status[0]["supersession_chain"].as_array().expect("chain");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0]["version"], 1);
        assert_eq!(chain[1]["version"], 2);
        assert_eq!(chain[0]["value_hash"], hash_text("old answer context"));
        assert_eq!(chain[0]["deleted"], false);
        assert!(chain[0]["stored_at"].as_str().is_some_and(|ts| ts.contains('T')));
    }

    #[test]
    fn evidence_validity_maps_one_entry_per_evidence_ref() {
        let store = FactStore::new();
        let capsule = capsule_with(
            "tenant-a",
            "ans_1",
            vec![evidence_ref("f_a"), evidence_ref("f_b")],
            Vec::new(),
        );
        let status = evidence_validity(&store, &capsule, "default");
        assert_eq!(status.len(), 2);
        assert_eq!(status[1]["record_id"], "f_b");
    }

    // ------------------------------------------------ semantic profile status

    #[test]
    fn semantic_profile_validity_distinguishes_not_recorded_from_not_configured() {
        let store = FactStore::new();
        let capsule = capsule_with("tenant-a", "ans_1", Vec::new(), Vec::new());
        assert_eq!(semantic_profile_validity(&store, &capsule)["status"], "not_recorded");

        let mut recorded = capsule.clone();
        recorded.semantic_profile_id = Some("profile-x".to_string());
        let value = semantic_profile_validity(&store, &recorded);
        assert_eq!(value["status"], "not_configured");
        assert_eq!(value["captured_semantic_profile_id"], "profile-x");
        assert_eq!(value["current_semantic_profile_id"], Value::Null);
    }

    #[test]
    fn semantic_profile_validity_compares_captured_against_the_live_profile() {
        let mut store = FactStore::new();
        store.set_embedder(Box::new(corecrux_memory::embeddings::LocalHashEmbedder::default()));
        let current = store.semantic_profile().expect("local profile").profile_id;

        let mut matching = capsule_with("tenant-a", "ans_1", Vec::new(), Vec::new());
        matching.local_semantic_profile_id = Some(current.clone());
        assert_eq!(semantic_profile_validity(&store, &matching)["status"], "current");

        let mut drifted = capsule_with("tenant-a", "ans_1", Vec::new(), Vec::new());
        drifted.semantic_profile_id = Some("some-other-profile".to_string());
        let value = semantic_profile_validity(&store, &drifted);
        assert_eq!(value["status"], "changed");
        assert_eq!(value["current_semantic_profile_id"], current);
    }

    #[test]
    fn semantic_profile_validity_prefers_the_local_profile_id() {
        let store = FactStore::new();
        let mut capsule = capsule_with("tenant-a", "ans_1", Vec::new(), Vec::new());
        capsule.semantic_profile_id = Some("remote".to_string());
        capsule.local_semantic_profile_id = Some("local".to_string());
        assert_eq!(
            semantic_profile_validity(&store, &capsule)["captured_semantic_profile_id"],
            "local"
        );
    }

    // ---------------------------------------------------- projection modules

    fn ref_for(module: &ProjectionModuleVersionV1, schema_version: Option<u32>) -> ProjectionReplayRef {
        ProjectionReplayRef {
            module_id: module.module_id.clone(),
            module_version: module.module_version.clone(),
            code_hash: Some(module.code_hash.clone()),
            config_hash: Some(module.config_hash.clone()),
            schema_version,
            projection_commit_id: Some(9),
            projection_registry_hash: Some("registry-hash".to_string()),
            projection_snapshot_hash: Some("snapshot-hash".to_string()),
            install_receipt_id: None,
            availability: "available".to_string(),
        }
    }

    fn registry_with_status(status: ProjectionModuleStatusV1) -> Vec<ProjectionModuleVersionV1> {
        let mut registry = corecrux_projections::current_projection_module_versions_v1();
        registry[0].status = status;
        registry
    }

    fn meta_with_registry(commit_id: u64, registry: Vec<ProjectionModuleVersionV1>) -> ProjectionsMetaV1 {
        let mut meta = ProjectionsMetaV1::empty_now();
        meta.commit_id = commit_id;
        meta.projection_module_registry = registry;
        meta
    }

    #[tokio::test]
    async fn projection_modules_validity_is_not_recorded_without_refs() {
        let state = pro_replay_state();
        let capsule = capsule_with("tenant-a", "ans_1", Vec::new(), Vec::new());
        let value = projection_modules_validity(&state, &capsule, None).await;
        assert_eq!(value["status"], "not_recorded");
        assert_eq!(value["historical_replay_available"], true);
        assert_eq!(value["current_projection_drift"], false);
        assert_eq!(value["refs"], json!([]));
    }

    #[tokio::test]
    async fn projection_modules_validity_matches_the_runtime_registry() {
        let state = pro_replay_state();
        let registry = corecrux_projections::current_projection_module_versions_v1();
        let capsule = capsule_with(
            "tenant-a",
            "ans_1",
            Vec::new(),
            vec![ref_for(&registry[0], Some(registry[0].schema_version))],
        );
        let value = projection_modules_validity(&state, &capsule, None).await;
        assert_eq!(value["status"], "current");
        assert_eq!(value["source"], "runtime_current");
        assert_eq!(value["commit_id"], Value::Null);
        assert_eq!(value["refs"][0]["status"], "current");
        assert_eq!(value["refs"][0]["historical_replay_available"], true);
        assert_eq!(value["refs"][0]["captured_availability"], "available");
    }

    #[tokio::test]
    async fn projection_modules_validity_flags_an_unknown_module_as_unavailable() {
        let state = pro_replay_state();
        let capsule = capsule_with(
            "tenant-a",
            "ans_1",
            Vec::new(),
            vec![ProjectionReplayRef {
                module_id: "projection.does_not_exist".to_string(),
                module_version: "v0".to_string(),
                code_hash: None,
                config_hash: None,
                schema_version: None,
                projection_commit_id: None,
                projection_registry_hash: None,
                projection_snapshot_hash: None,
                install_receipt_id: None,
                availability: "unknown".to_string(),
            }],
        );
        let value = projection_modules_validity(&state, &capsule, None).await;
        assert_eq!(value["status"], "unavailable");
        assert_eq!(value["historical_replay_available"], false);
        assert_eq!(value["current_projection_drift"], true);
        assert_eq!(value["refs"][0]["current_module"], Value::Null);
    }

    #[tokio::test]
    async fn projection_modules_validity_requires_the_schema_version_to_match() {
        // A module whose schema moved on is no longer a valid replay target even
        // if id/version/hashes still line up.
        let state = pro_replay_state();
        let registry = corecrux_projections::current_projection_module_versions_v1();
        let capsule = capsule_with("tenant-a", "ans_1", Vec::new(), vec![ref_for(&registry[0], Some(4242))]);
        let value = projection_modules_validity(&state, &capsule, None).await;
        assert_eq!(value["status"], "unavailable");
    }

    #[tokio::test]
    async fn projection_modules_validity_ignores_a_blank_shard_id() {
        let mut state = pro_replay_state();
        state.http_dataplane = FakeReplayDataplane {
            projection_meta: Some(meta_with_registry(
                7,
                registry_with_status(ProjectionModuleStatusV1::Active),
            )),
            ..FakeReplayDataplane::enabled()
        }
        .shared();
        let registry = corecrux_projections::current_projection_module_versions_v1();
        let capsule = capsule_with("tenant-a", "ans_1", Vec::new(), vec![ref_for(&registry[0], None)]);
        let value = projection_modules_validity(&state, &capsule, Some("   ")).await;
        assert_eq!(value["source"], "runtime_current");
        assert_eq!(value["shard_id"], "   ");
    }

    #[tokio::test]
    async fn projection_modules_validity_uses_shard_projection_meta_when_available() {
        let mut state = pro_replay_state();
        state.http_dataplane = FakeReplayDataplane {
            projection_meta: Some(meta_with_registry(
                4242,
                registry_with_status(ProjectionModuleStatusV1::RetainedForReplay),
            )),
            ..FakeReplayDataplane::enabled()
        }
        .shared();
        let registry = corecrux_projections::current_projection_module_versions_v1();
        let capsule = capsule_with("tenant-a", "ans_1", Vec::new(), vec![ref_for(&registry[0], None)]);
        let value = projection_modules_validity(&state, &capsule, Some("0001")).await;
        assert_eq!(value["source"], "projection_meta");
        assert_eq!(value["commit_id"], 4242);
        assert_eq!(value["status"], "retained_for_replay");
        // Retained-for-replay modules still replay; they only flag drift.
        assert_eq!(value["historical_replay_available"], true);
        assert_eq!(value["current_projection_drift"], true);
    }

    #[tokio::test]
    async fn projection_modules_validity_treats_deprecated_as_replay_blocking() {
        let mut state = pro_replay_state();
        state.http_dataplane = FakeReplayDataplane {
            projection_meta: Some(meta_with_registry(
                1,
                registry_with_status(ProjectionModuleStatusV1::Deprecated),
            )),
            ..FakeReplayDataplane::enabled()
        }
        .shared();
        let registry = corecrux_projections::current_projection_module_versions_v1();
        let capsule = capsule_with("tenant-a", "ans_1", Vec::new(), vec![ref_for(&registry[0], None)]);
        let value = projection_modules_validity(&state, &capsule, Some("0001")).await;
        assert_eq!(value["refs"][0]["status"], "deprecated");
        assert_eq!(value["status"], "unavailable");
        assert_eq!(value["refs"][0]["historical_replay_available"], false);
    }

    #[tokio::test]
    async fn projection_modules_validity_reports_registry_marked_unavailable() {
        let mut state = pro_replay_state();
        state.http_dataplane = FakeReplayDataplane {
            projection_meta: Some(meta_with_registry(
                1,
                registry_with_status(ProjectionModuleStatusV1::Unavailable),
            )),
            ..FakeReplayDataplane::enabled()
        }
        .shared();
        let registry = corecrux_projections::current_projection_module_versions_v1();
        let capsule = capsule_with("tenant-a", "ans_1", Vec::new(), vec![ref_for(&registry[0], None)]);
        let value = projection_modules_validity(&state, &capsule, Some("0001")).await;
        assert_eq!(value["refs"][0]["status"], "unavailable");
        assert_eq!(value["status"], "unavailable");
    }

    #[tokio::test]
    async fn projection_modules_validity_falls_back_when_shard_meta_is_absent() {
        let mut state = pro_replay_state();
        state.http_dataplane = FakeReplayDataplane::enabled().shared();
        let registry = corecrux_projections::current_projection_module_versions_v1();
        let capsule = capsule_with("tenant-a", "ans_1", Vec::new(), vec![ref_for(&registry[0], None)]);
        let value = projection_modules_validity(&state, &capsule, Some("0001")).await;
        assert_eq!(value["source"], "runtime_current");
        assert_eq!(value["status"], "current");
    }

    #[tokio::test]
    async fn projection_modules_validity_falls_back_when_shard_meta_registry_is_empty() {
        let mut state = pro_replay_state();
        state.http_dataplane = FakeReplayDataplane {
            projection_meta: Some(meta_with_registry(5, Vec::new())),
            ..FakeReplayDataplane::enabled()
        }
        .shared();
        let registry = corecrux_projections::current_projection_module_versions_v1();
        let capsule = capsule_with("tenant-a", "ans_1", Vec::new(), vec![ref_for(&registry[0], None)]);
        let value = projection_modules_validity(&state, &capsule, Some("0001")).await;
        assert_eq!(value["source"], "projection_meta");
        assert_eq!(value["commit_id"], 5);
        assert_eq!(value["status"], "current");
    }

    #[tokio::test]
    async fn projection_modules_validity_ignores_shard_id_when_dataplane_is_disabled() {
        let state = pro_replay_state();
        assert!(!state.http_dataplane.enabled());
        let registry = corecrux_projections::current_projection_module_versions_v1();
        let capsule = capsule_with("tenant-a", "ans_1", Vec::new(), vec![ref_for(&registry[0], None)]);
        let value = projection_modules_validity(&state, &capsule, Some("0001")).await;
        assert_eq!(value["source"], "runtime_current");
    }

    // ------------------------------------------------------- living objects

    fn evidence_with_artifact(record_id: &str, artifact_id: u32) -> ReplayEvidenceRef {
        let mut evidence = evidence_ref(record_id);
        evidence.artifact_id = Some(artifact_id);
        evidence
    }

    #[test]
    fn replay_artifact_ids_are_deduped_and_sorted() {
        let capsule = capsule_with(
            "tenant-a",
            "ans_1",
            vec![
                evidence_with_artifact("f_1", 9),
                evidence_with_artifact("f_2", 3),
                evidence_with_artifact("f_3", 9),
                evidence_ref("f_4"),
            ],
            Vec::new(),
        );
        assert_eq!(replay_artifact_ids(&capsule), vec![3, 9]);
    }

    #[tokio::test]
    async fn living_object_validity_is_not_recorded_without_artifact_ids() {
        let state = pro_replay_state();
        let capsule = capsule_with("tenant-a", "ans_1", vec![evidence_ref("f_1")], Vec::new());
        let value = living_object_validity(&state, &capsule).await;
        assert_eq!(value["status"], "not_recorded");
        assert_eq!(value["source"], "capsule");
        assert_eq!(value["current_answer_stale"], false);
        assert_eq!(value["affected_downstream_projections"]["dependent_count"], 0);
    }

    #[tokio::test]
    async fn living_object_validity_reads_local_projection_state() {
        let state = pro_replay_state();
        let tenant_hash = corecrux_projections::tenant_hash_xxhash64("tenant-a");
        {
            let mut projection = state.projection_state.write().await;
            projection.living.insert(
                (tenant_hash, 5),
                LivingStateRowV1 {
                    living_status: LivingStatusV1::Active,
                    confidence_q16: 32768,
                    ..LivingStateRowV1::default()
                },
            );
            projection.relations.insert(
                (tenant_hash, 5, 6, RelationTypeV1::Supports.to_u8()),
                RelationEdgeV1 {
                    confidence_q16: 65535,
                    evidence_ref_hash16: [0xab; 16],
                    created_at_micros: 1,
                    updated_at_micros: 2,
                },
            );
            projection.relations.insert(
                (tenant_hash, 4, 5, RelationTypeV1::Cites.to_u8()),
                RelationEdgeV1 {
                    confidence_q16: 100,
                    evidence_ref_hash16: [0x01; 16],
                    created_at_micros: 3,
                    updated_at_micros: 4,
                },
            );
            projection.dependents.insert(
                (tenant_hash, 5, 0u8, uuid::Uuid::from_u128(1)),
                DependentEdgeV1 {
                    last_seen_at_micros: 7,
                    usage_weight_q16: 1000,
                },
            );
        }
        let capsule = capsule_with("tenant-a", "ans_1", vec![evidence_with_artifact("f_1", 5)], Vec::new());
        let value = living_object_validity(&state, &capsule).await;
        assert_eq!(value["source"], "local_projection_state");
        assert_eq!(value["status"], "current");
        assert_eq!(value["artifact_ids"], json!([5]));
        let artifact = &value["artifacts"][0];
        assert_eq!(artifact["living_state"]["living_status"], "active");
        assert_eq!(artifact["relations_out"][0]["direction"], "out");
        assert_eq!(artifact["relations_out"][0]["relation_type"], "supports");
        assert_eq!(artifact["relations_out"][0]["evidence_ref_hash16"], "ab".repeat(16));
        assert_eq!(artifact["relations_in"][0]["direction"], "in");
        assert_eq!(artifact["relations_in"][0]["src_artifact_id"], 4);
        assert_eq!(artifact["downstream_dependents"][0]["dependent_type"], "answer");
        assert_eq!(value["affected_downstream_projections"]["dependent_count"], 1);
        assert_eq!(
            value["affected_downstream_projections"]["dependent_types"],
            json!(["answer"])
        );
    }

    #[tokio::test]
    async fn living_object_validity_flags_contradicting_and_superseding_relations_as_stale() {
        let state = pro_replay_state();
        let tenant_hash = corecrux_projections::tenant_hash_xxhash64("tenant-a");
        {
            let mut projection = state.projection_state.write().await;
            for (dst, relation) in [(6u32, RelationTypeV1::Contradicts), (7, RelationTypeV1::Supersedes)] {
                projection.relations.insert(
                    (tenant_hash, 5, dst, relation.to_u8()),
                    RelationEdgeV1 {
                        confidence_q16: 65535,
                        evidence_ref_hash16: [0; 16],
                        created_at_micros: 1,
                        updated_at_micros: 2,
                    },
                );
            }
        }
        let capsule = capsule_with("tenant-a", "ans_1", vec![evidence_with_artifact("f_1", 5)], Vec::new());
        let value = living_object_validity(&state, &capsule).await;
        assert_eq!(value["status"], "stale");
        assert_eq!(value["current_answer_stale"], true);
        assert_eq!(
            value["drift_categories"],
            json!(["relation_contradicts", "relation_supersedes"])
        );
    }

    #[tokio::test]
    async fn living_object_validity_counts_only_unresolved_pressure_events() {
        let state = pro_replay_state();
        let tenant_hash = corecrux_projections::tenant_hash_xxhash64("tenant-a");
        {
            let mut projection = state.projection_state.write().await;
            projection.pressure.insert(
                (tenant_hash, 5, uuid::Uuid::from_u128(1)),
                PressureEventRowV1 {
                    pressure_code_id: 3,
                    severity: 2,
                    observed_at_micros: 10,
                    acknowledged_at_micros: 0,
                    resolved_at_micros: 0,
                    receipt_id: Some(uuid::Uuid::from_u128(9)),
                },
            );
            projection.pressure.insert(
                (tenant_hash, 5, uuid::Uuid::from_u128(2)),
                PressureEventRowV1 {
                    pressure_code_id: 4,
                    severity: 1,
                    observed_at_micros: 11,
                    acknowledged_at_micros: 12,
                    resolved_at_micros: 13,
                    receipt_id: None,
                },
            );
        }
        let capsule = capsule_with("tenant-a", "ans_1", vec![evidence_with_artifact("f_1", 5)], Vec::new());
        let value = living_object_validity(&state, &capsule).await;
        assert_eq!(value["drift_categories"], json!(["pressure_open"]));
        let events = value["artifacts"][0]["pressure_events"].as_array().expect("events");
        assert_eq!(events.len(), 1, "resolved events must be filtered out");
        assert_eq!(events[0]["pressure_code_id"], 3);
        assert_eq!(events[0]["receipt_id"], uuid::Uuid::from_u128(9).to_string());
    }

    #[tokio::test]
    async fn living_object_validity_surfaces_dataplane_rows() {
        let mut state = pro_replay_state();
        state.http_dataplane = FakeReplayDataplane {
            living: Some(LivingStateRowV1 {
                living_status: LivingStatusV1::Stale,
                ..LivingStateRowV1::default()
            }),
            relations_out: vec![ProjectionRelationRowV1 {
                src_artifact_id: 5,
                dst_artifact_id: 6,
                relation_type: RelationTypeV1::Contradicts.to_u8(),
                confidence_q16: 65535,
                evidence_ref_hash16: [0x0f; 16],
                created_at_micros: 1,
                updated_at_micros: 2,
            }],
            dependents: vec![ProjectionDependentRowV1 {
                dependent_type: 2,
                dependent_id: "coll-1".to_string(),
                last_seen_at_micros: 5,
                usage_weight_q16: 32768,
            }],
            pressure: vec![ProjectionPressureEventRowV1 {
                event_id: uuid::Uuid::from_u128(3),
                pressure_code_id: 8,
                severity: 4,
                observed_at_micros: 6,
                acknowledged_at_micros: 0,
                resolved_at_micros: 0,
                receipt_id: None,
            }],
            ..FakeReplayDataplane::enabled()
        }
        .shared();
        let capsule = capsule_with("tenant-a", "ans_1", vec![evidence_with_artifact("f_1", 5)], Vec::new());
        let value = living_object_validity(&state, &capsule).await;
        assert_eq!(value["source"], "dataplane_projection_api");
        assert_eq!(value["status"], "stale");
        assert_eq!(
            value["drift_categories"],
            json!(["living_state_stale", "pressure_open", "relation_contradicts"])
        );
        let artifact = &value["artifacts"][0];
        assert_eq!(artifact["relations_out"][0]["evidence_ref_hash16"], "0f".repeat(16));
        assert_eq!(artifact["downstream_dependents"][0]["dependent_type"], "collection");
        assert_eq!(artifact["downstream_dependents"][0]["dependent_id"], "coll-1");
        assert_eq!(
            artifact["pressure_events"][0]["event_id"],
            uuid::Uuid::from_u128(3).to_string()
        );
        assert_eq!(artifact["pressure_events"][0]["receipt_id"], Value::Null);
        assert_eq!(
            value["affected_downstream_projections"]["dependent_types"],
            json!(["collection"])
        );
    }

    #[tokio::test]
    async fn living_object_validity_degrades_to_unknown_on_any_dataplane_query_failure() {
        // Every projection query is independently fallible; a failure must
        // downgrade the answer to "unknown" with a `projection_query_failed`
        // marker rather than bubbling a 500 out of the validity endpoint.
        for stage in [
            FailStage::State,
            FailStage::RelationsOut,
            FailStage::RelationsIn,
            FailStage::Dependents,
            FailStage::Pressure,
        ] {
            let mut state = pro_replay_state();
            state.http_dataplane = FakeReplayDataplane::fails_at(stage).shared();
            let capsule = capsule_with("tenant-a", "ans_1", vec![evidence_with_artifact("f_1", 5)], Vec::new());
            let value = living_object_validity(&state, &capsule).await;
            assert_eq!(value["status"], "unknown", "stage {stage:?}");
            assert_eq!(value["current_answer_stale"], false, "stage {stage:?}");
            assert_eq!(value["drift_categories"], json!(["projection_query_failed"]));
            let artifact = &value["artifacts"][0];
            assert_eq!(artifact["living_state"], Value::Null);
            assert!(artifact["error"].as_str().is_some_and(|err| err.contains("Internal")));
        }
    }

    #[tokio::test]
    async fn living_object_validity_reports_unprojected_artifact_as_unknown() {
        let mut state = pro_replay_state();
        state.http_dataplane = FakeReplayDataplane::enabled().shared();
        let capsule = capsule_with("tenant-a", "ans_1", vec![evidence_with_artifact("f_1", 5)], Vec::new());
        let value = living_object_validity(&state, &capsule).await;
        assert_eq!(value["status"], "unknown");
        assert_eq!(value["drift_categories"], json!(["living_object_not_projected"]));
        assert_eq!(
            value["projection_tables_checked"],
            json!([
                "artifact_living_state",
                "artifact_relations",
                "artifact_dependents",
                "pressure_events"
            ])
        );
    }

    // ------------------------------------------------------- small json helpers

    #[test]
    fn living_status_drift_category_covers_every_status() {
        assert_eq!(
            living_status_drift_category(LivingStatusV1::Stale),
            Some("living_state_stale")
        );
        assert_eq!(
            living_status_drift_category(LivingStatusV1::Contested),
            Some("living_state_contested")
        );
        assert_eq!(
            living_status_drift_category(LivingStatusV1::Superseded),
            Some("living_state_superseded")
        );
        assert_eq!(
            living_status_drift_category(LivingStatusV1::Deprecated),
            Some("living_state_deprecated")
        );
        // Active and Dormant are healthy states — they must NOT report drift.
        assert_eq!(living_status_drift_category(LivingStatusV1::Active), None);
        assert_eq!(living_status_drift_category(LivingStatusV1::Dormant), None);
    }

    #[test]
    fn living_artifact_json_reports_current_when_state_exists_and_nothing_drifted() {
        let row = LivingStateRowV1 {
            living_status: LivingStatusV1::Active,
            confidence_q16: 65535,
            last_validated_at_micros: 1,
            next_review_at_micros: 2,
            pressure_level: 3,
            pressure_reasons_mask: 4,
            trunk_tier: 5,
            relations_out_count: 6,
            relations_in_count: 7,
            dependents_count: 8,
            updated_at_micros: 9,
        };
        let value = living_artifact_json(5, Some(&row), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        assert_eq!(value["status"], "current");
        assert_eq!(value["drift_categories"], json!([]));
        let state = &value["living_state"];
        assert_eq!(state["living_status"], "active");
        assert_eq!(state["pressure_level"], 3);
        assert_eq!(state["trunk_tier"], 5);
        assert_eq!(state["dependents_count"], 8);
        assert_eq!(state["updated_at_micros"], 9);
    }

    #[test]
    fn relation_and_dependent_type_names_fall_back_to_unknown() {
        assert_eq!(relation_type_name(RelationTypeV1::DependsOn.to_u8()), "depends_on");
        assert_eq!(relation_type_name(250), "unknown(250)");
        assert_eq!(dependent_type_name(3), "artifact");
        assert_eq!(dependent_type_name(250), "unknown(250)");
    }

    #[test]
    fn hex_bytes_is_lowercase_and_zero_padded() {
        assert_eq!(hex_bytes(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_bytes(&[]), "");
    }

    #[test]
    fn local_json_helpers_round_trip_their_fields() {
        let relation = local_relation_json(
            "out",
            1,
            2,
            RelationTypeV1::Duplicates.to_u8(),
            &RelationEdgeV1 {
                confidence_q16: 65535,
                evidence_ref_hash16: [0x12; 16],
                created_at_micros: 10,
                updated_at_micros: 11,
            },
        );
        assert_eq!(relation["relation_type"], "duplicates");
        assert_eq!(relation["created_at_micros"], 10);

        let dependent = local_dependent_json(
            1,
            uuid::Uuid::from_u128(4),
            &DependentEdgeV1 {
                last_seen_at_micros: 12,
                usage_weight_q16: 0,
            },
        );
        assert_eq!(dependent["dependent_type"], "mises");
        assert_eq!(dependent["dependent_id"], uuid::Uuid::from_u128(4).to_string());
        assert_eq!(dependent["last_seen_at_micros"], 12);

        let pressure = local_pressure_json(
            uuid::Uuid::from_u128(5),
            &PressureEventRowV1 {
                pressure_code_id: 1,
                severity: 2,
                observed_at_micros: 3,
                acknowledged_at_micros: 4,
                resolved_at_micros: 5,
                receipt_id: None,
            },
        );
        assert_eq!(pressure["severity"], 2);
        assert_eq!(pressure["resolved_at_micros"], 5);
        assert_eq!(pressure["receipt_id"], Value::Null);
    }

    #[test]
    fn dataplane_json_helpers_round_trip_their_fields() {
        let relation = dataplane_relation_json(
            "in",
            ProjectionRelationRowV1 {
                src_artifact_id: 1,
                dst_artifact_id: 2,
                relation_type: RelationTypeV1::Elaborates.to_u8(),
                confidence_q16: 0,
                evidence_ref_hash16: [0xcd; 16],
                created_at_micros: 1,
                updated_at_micros: 2,
            },
        );
        assert_eq!(relation["direction"], "in");
        assert_eq!(relation["relation_type"], "elaborates");
        assert_eq!(relation["evidence_ref_hash16"], "cd".repeat(16));

        let dependent = dataplane_dependent_json(ProjectionDependentRowV1 {
            dependent_type: 0,
            dependent_id: "ans-9".to_string(),
            last_seen_at_micros: 4,
            usage_weight_q16: 65535,
        });
        assert_eq!(dependent["dependent_type"], "answer");
        assert_eq!(dependent["dependent_id"], "ans-9");

        let pressure = dataplane_pressure_json(ProjectionPressureEventRowV1 {
            event_id: uuid::Uuid::from_u128(6),
            pressure_code_id: 7,
            severity: 8,
            observed_at_micros: 9,
            acknowledged_at_micros: 10,
            resolved_at_micros: 0,
            receipt_id: Some(uuid::Uuid::from_u128(7)),
        });
        assert_eq!(pressure["pressure_code_id"], 7);
        assert_eq!(pressure["receipt_id"], uuid::Uuid::from_u128(7).to_string());
    }

    #[test]
    fn projection_query_failed_artifact_is_shaped_like_an_empty_artifact() {
        let value = projection_query_failed_artifact(5, HttpDataplaneError::Disabled);
        assert_eq!(value["artifact_id"], 5);
        assert_eq!(value["status"], "unknown");
        assert_eq!(value["drift_categories"], json!(["projection_query_failed"]));
        assert_eq!(value["error"], "Disabled");
        assert_eq!(value["relations_out"], json!([]));
        assert_eq!(value["pressure_events"], json!([]));
    }

    // ----------------------------------------------------- drift aggregation

    #[test]
    fn drift_categories_merges_dedupes_and_sorts_every_source() {
        let evidence = vec![
            json!({ "drift_category": "fact_changed" }),
            json!({ "drift_category": "fact_changed" }),
            json!({ "drift_category": Value::Null }),
        ];
        let categories = drift_categories(
            &evidence,
            &json!({ "status": "changed" }),
            &json!({ "status": "retained_for_replay" }),
            &json!({ "drift_categories": ["pressure_open"] }),
        );
        assert_eq!(
            categories,
            vec![
                "fact_changed".to_string(),
                "pressure_open".to_string(),
                "projection_module_retained_for_replay".to_string(),
                "semantic_profile_changed".to_string(),
            ]
        );
    }

    #[test]
    fn drift_categories_maps_each_status_variant() {
        assert_eq!(
            drift_categories(
                &[],
                &json!({ "status": "not_configured" }),
                &json!({ "status": "unavailable" }),
                &json!({}),
            ),
            vec![
                "projection_module_unavailable".to_string(),
                "semantic_profile_not_configured".to_string()
            ]
        );
        assert_eq!(
            drift_categories(
                &[],
                &json!({ "status": "current" }),
                &json!({ "status": "deprecated" }),
                &json!({ "drift_categories": [] }),
            ),
            vec!["projection_module_deprecated".to_string()]
        );
        assert!(drift_categories(
            &[],
            &json!({ "status": "not_recorded" }),
            &json!({ "status": "current" }),
            &json!({ "drift_categories": [] }),
        )
        .is_empty());
    }

    // ---------------------------------------------------------------- export

    fn zip_entries(bytes: &[u8]) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).expect("valid zip");
        let mut out = std::collections::BTreeMap::new();
        for index in 0..archive.len() {
            let mut file = archive.by_index(index).expect("zip entry");
            let name = file.name().to_string();
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).expect("read zip entry");
            out.insert(name, buf);
        }
        out
    }

    fn export_opts(format: ExportFormatV1, redaction: ExportRedactionV1) -> ReceiptExportOptionsV1 {
        ReceiptExportOptionsV1 {
            format,
            redaction,
            include: vec![ReceiptExportIncludeV1::Body, ReceiptExportIncludeV1::Sig],
        }
    }

    fn exportable_capsule() -> AnswerReplayCapsule {
        let mut evidence = evidence_ref("f_1");
        evidence.text = Some("sensitive evidence body".to_string());
        capsule_with("tenant-a", "ans_1", vec![evidence], Vec::new())
    }

    #[tokio::test]
    async fn export_answer_capsule_zip_contains_the_full_bundle() {
        let state = pro_replay_state();
        let capsule = exportable_capsule();
        let resp = export_answer_capsule(
            &state,
            &capsule,
            export_opts(ExportFormatV1::Zip, ExportRedactionV1::None),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/zip");
        assert_eq!(
            resp.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=\"answer-replay-tenant-a-ans_1.zip\""
        );
        let entries = zip_entries(&body_bytes(resp).await);
        assert_eq!(
            entries.keys().cloned().collect::<Vec<_>>(),
            vec![
                "answer/capsule.json".to_string(),
                "answer/evidence.jsonl".to_string(),
                "answer/projection_refs.json".to_string(),
                "answer/rendered_answer.txt".to_string(),
                "answer/source_receipts.json".to_string(),
                "manifest.json".to_string(),
                "raw_frames/README.json".to_string(),
            ]
        );
        assert_eq!(entries["answer/rendered_answer.txt"], b"the stored answer".to_vec());

        let manifest: Value = serde_json::from_slice(&entries["manifest.json"]).expect("manifest json");
        assert_eq!(manifest["export_schema"], ANSWER_REPLAY_EXPORT_SCHEMA);
        assert_eq!(manifest["tenant_id"], "tenant-a");
        assert_eq!(manifest["capsule_hash"], capsule.capsule_hash);
        assert_eq!(manifest["format"], "zip");
        assert_eq!(manifest["redaction"], "none");
        assert_eq!(manifest["include"], json!(["body", "sig"]));
        assert_eq!(manifest["historical_replay"]["agent_required"], false);
        assert_eq!(manifest["historical_replay"]["llm_required"], false);
        // The manifest hashes every file but cannot hash itself.
        let listed = manifest["included_files"].as_array().expect("included files");
        assert_eq!(listed.len(), entries.len() - 1);
        assert!(listed.iter().all(|file| file["path"] != "manifest.json"));
        for file in listed {
            let path = file["path"].as_str().expect("path");
            let bytes = &entries[path];
            assert_eq!(file["blake3"], blake3::hash(bytes).to_hex().to_string(), "{path}");
            assert_eq!(file["size"], bytes.len() as u64, "{path}");
        }
    }

    #[tokio::test]
    async fn export_answer_capsule_metadata_only_strips_answer_and_evidence_text() {
        // `metadata_only` is the redaction customers rely on to share a replay
        // bundle without shipping the answer body or the evidence prose.
        let state = pro_replay_state();
        let capsule = exportable_capsule();
        let resp = export_answer_capsule(
            &state,
            &capsule,
            export_opts(ExportFormatV1::Zip, ExportRedactionV1::MetadataOnly),
        );
        let bytes = body_bytes(resp).await;
        let entries = zip_entries(&bytes);
        assert!(
            !entries.contains_key("answer/rendered_answer.txt"),
            "metadata-only export must omit the rendered answer file"
        );
        let exported: Value = serde_json::from_slice(&entries["answer/capsule.json"]).expect("capsule json");
        assert_eq!(exported["stored_answer"], Value::Null);
        assert_eq!(exported["rendered_answer"], "");
        assert!(exported["evidence"][0].get("text").is_none());
        // Belt and braces: the plaintext must not survive anywhere in the archive
        // (entries are stored uncompressed).
        for (path, blob) in &entries {
            let text = String::from_utf8_lossy(blob);
            assert!(!text.contains("the stored answer"), "answer text leaked in {path}");
            assert!(
                !text.contains("sensitive evidence body"),
                "evidence text leaked in {path}"
            );
        }
        // Metadata that makes the bundle auditable is still present.
        assert_eq!(exported["capsule_hash"], capsule.capsule_hash);
        assert_eq!(exported["answer_hash"], capsule.answer_hash);
    }

    #[tokio::test]
    async fn export_answer_capsule_tar_zst_uses_the_matching_content_type_and_extension() {
        let state = pro_replay_state();
        let resp = export_answer_capsule(
            &state,
            &exportable_capsule(),
            export_opts(ExportFormatV1::TarZst, ExportRedactionV1::TenantSafe),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/zstd");
        assert_eq!(
            resp.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=\"answer-replay-tenant-a-ans_1.tar.zst\""
        );
        let bytes = body_bytes(resp).await;
        // zstd magic number — proves the archive really was zstd-framed.
        assert_eq!(&bytes[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
    }

    #[tokio::test]
    async fn export_answer_capsule_sanitizes_hostile_tenant_and_answer_ids() {
        // tenant_id and answer_id are caller-controlled and land in a
        // Content-Disposition header; path separators and CRLF must not survive.
        let state = pro_replay_state();
        let capsule = capsule_with("../tenant a", "ans\r\n1", vec![evidence_ref("f_1")], Vec::new());
        let resp = export_answer_capsule(
            &state,
            &capsule,
            export_opts(ExportFormatV1::Zip, ExportRedactionV1::None),
        );
        let disposition = resp.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .expect("ascii disposition")
            .to_string();
        assert_eq!(
            disposition,
            "attachment; filename=\"answer-replay-..-tenant-a-ans--1.zip\""
        );
        assert!(!disposition.contains('\r') && !disposition.contains('\n'));
        assert!(!disposition.contains('/'));
    }

    #[tokio::test]
    async fn export_answer_capsule_if_present_is_none_until_a_capsule_is_stored() {
        let state = pro_replay_state();
        assert!(export_answer_capsule_if_present(
            &state,
            "tenant-a",
            "ans_1",
            "default",
            ReceiptExportOptionsV1::default(),
        )
        .await
        .is_none());

        let capsule = capsule_with("tenant-a", "ans_1", vec![evidence_ref("f_1")], Vec::new());
        store_answer_capsule(&state, &capsule).await.expect("store capsule");
        let resp = export_answer_capsule_if_present(
            &state,
            "tenant-a",
            "ans_1",
            "default",
            ReceiptExportOptionsV1::default(),
        )
        .await
        .expect("export present");
        assert_eq!(resp.status(), StatusCode::OK);

        // A different tenant hash must not be able to export the same capsule.
        assert!(export_answer_capsule_if_present(
            &state,
            "tenant-a",
            "ans_1",
            "other-tenant-hash",
            ReceiptExportOptionsV1::default(),
        )
        .await
        .is_none());
    }

    #[test]
    fn build_evidence_jsonl_emits_one_newline_terminated_object_per_ref() {
        let bytes = build_evidence_jsonl(&[evidence_ref("f_1"), evidence_ref("f_2")]).expect("jsonl");
        let text = String::from_utf8(bytes).expect("utf8");
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert!(text.ends_with('\n'));
        for line in lines {
            let value: Value = serde_json::from_str(line).expect("line is one json object");
            assert!(value["record_id"].as_str().is_some_and(|id| id.starts_with("f_")));
        }
        assert_eq!(build_evidence_jsonl(&[]).expect("empty jsonl"), Vec::<u8>::new());
    }

    #[test]
    fn filename_sanitizer_keeps_safe_subset() {
        assert_eq!(sanitize_filename_part("tenant::a/b"), "tenant--a-b");
        assert_eq!(sanitize_filename_part("a-b_c.1"), "a-b_c.1");
        // An input with nothing safe left must not produce an empty filename.
        assert_eq!(sanitize_filename_part("///"), "---");
        assert_eq!(sanitize_filename_part(""), "unknown");
    }
}
