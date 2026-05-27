// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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

pub(super) async fn get_answer_replay(
    State(state): State<AppState>,
    Path(answer_id): Path<String>,
    Query(q): Query<ReplayQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = require_answer_replay(&state, &headers, &q.tenant_id) {
        return response;
    }
    let Some(capsule) = load_answer_capsule(&state, &q.tenant_id, &answer_id).await else {
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

pub(super) async fn get_answer_replay_validity(
    State(state): State<AppState>,
    Path(answer_id): Path<String>,
    Query(q): Query<ReplayQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = require_answer_replay(&state, &headers, &q.tenant_id) {
        return response;
    }
    let Some(capsule) = load_answer_capsule(&state, &q.tenant_id, &answer_id).await else {
        return problem_response(StatusCode::NOT_FOUND, "answer replay capsule not found");
    };

    let (evidence_status, semantic_profile_status) = {
        let store = state.fact_store.read().await;
        (
            evidence_validity(&store, &capsule),
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

pub(super) async fn store_answer_capsule(state: &AppState, capsule: &AnswerReplayCapsule) -> std::io::Result<()> {
    let mut fact = StoreFact {
        entity: answer_capsule_entity(&capsule.tenant_id, &capsule.answer_id),
        key: "capsule".to_string(),
        value: serde_json::to_string(capsule).map_err(std::io::Error::other)?,
        source_receipt: capsule.source_receipts.last().cloned(),
        confidence: 1.0,
        private: true,
    horizon_class: None,
    };
    crate::fact_privacy::enforce(&state.privacy_policy, &mut fact);
    state.fact_store.write().await.try_store(fact)?;
    Ok(())
}

pub(super) async fn load_answer_capsule(
    state: &AppState,
    tenant_id: &str,
    answer_id: &str,
) -> Option<AnswerReplayCapsule> {
    let store = state.fact_store.read().await;
    load_answer_capsule_from_store(&store, tenant_id, answer_id)
}

pub(super) async fn export_answer_capsule_if_present(
    state: &AppState,
    tenant_id: &str,
    answer_id: &str,
    opts: ReceiptExportOptionsV1,
) -> Option<Response> {
    let capsule = load_answer_capsule(state, tenant_id, answer_id).await?;
    Some(export_answer_capsule(state, &capsule, opts))
}

fn load_answer_capsule_from_store(store: &FactStore, tenant_id: &str, answer_id: &str) -> Option<AnswerReplayCapsule> {
    let entity = answer_capsule_entity(tenant_id, answer_id);
    store
        .get_by_entity(&entity)
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

fn evidence_validity(store: &FactStore, capsule: &AnswerReplayCapsule) -> Vec<Value> {
    capsule
        .evidence
        .iter()
        .map(|evidence| evidence_ref_validity(store, evidence))
        .collect()
}

fn evidence_ref_validity(store: &FactStore, evidence: &ReplayEvidenceRef) -> Value {
    let Some(fact) = store.get(&evidence.record_id) else {
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
    let latest = latest_fact_for_entity_key(store, fact);
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
        "supersession_chain": supersession_chain_for_entity_key(store, fact),
    })
}

fn latest_fact_for_entity_key<'a>(store: &'a FactStore, fact: &Fact) -> Option<&'a Fact> {
    store
        .get_by_entity(&fact.entity)
        .into_iter()
        .filter(|candidate| candidate.key == fact.key)
        .max_by_key(|candidate| candidate.version)
}

fn supersession_chain_for_entity_key(store: &FactStore, fact: &Fact) -> Vec<Value> {
    let mut chain = store
        .get_by_entity(&fact.entity)
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
    #[allow(clippy::unwrap_used)] // Static content types and sanitized filenames are valid header values.
    {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, opts.format.content_type().parse().unwrap());
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\"").parse().unwrap(),
        );
    }
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

fn sanitize_filename_part(value: &str) -> String {
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
mod tests {
    use super::*;
    use corecrux_memory::replay::{BuildAnswerReplayCapsule, ProjectionReplayRef};

    #[test]
    fn filename_sanitizer_keeps_safe_subset() {
        assert_eq!(sanitize_filename_part("tenant::a/b"), "tenant--a-b");
    }

    #[test]
    fn evidence_validity_marks_superseded_fact() {
        let mut store = FactStore::new();
        let first = store.store(StoreFact {
            entity: "tenant-a::doc".to_string(),
            key: "content".to_string(),
            value: "old answer context".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        horizon_class: None,
        });
        store.store(StoreFact {
            entity: "tenant-a::doc".to_string(),
            key: "content".to_string(),
            value: "new answer context".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        horizon_class: None,
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

        let status = evidence_validity(&store, &capsule);
        assert_eq!(status[0]["status"], "superseded");
    }
}
