// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Governance-tier incident reconstruction over existing local evidence lanes.
//!
//! Cases are private facts under `__incident__::<case_id>`. The case captures
//! an immutable, time-ordered reconstruction; export embeds that JSON plus
//! concrete `VerificationReportV1` values in the existing signed audit-bundle
//! event stream, so the unmodified offline audit verifier covers both.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use axum::body::Body;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use corecrux_memory::fact_store::{Fact, FactQuery, StoreFact};
use corecrux_receipts::{
    build_bundle_v1, resolve_audit_export_signing_key, AuditBundleKeyClassV1, AuditBundleScopeV1, AuditEventV1,
    AuditReceiptRefV1, BuildBundleInputV1, VerificationIntegrityV1, VerificationReportV1, VerificationSigInfoV1,
    VerificationTraceChecksV1,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{http_scope_context, problem_response, require_http_any_scope_for_tenant, AppState};
use crate::agentgraph_kinds::PUNCHCARD_KIND;

pub(super) const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_INCIDENTS";
pub(super) const INCIDENT_ENTITY_PREFIX: &str = "__incident__";
const INCIDENT_CASE_KEY: &str = "case";
const MAX_SELECTORS: usize = 100;
const MAX_REASONING_EVENTS: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum AssuranceClass {
    VerifiableRecord,
    MediatedEvidence,
    SelfReported,
}

impl AssuranceClass {
    fn as_str(&self) -> &'static str {
        match self {
            Self::VerifiableRecord => "verifiable_record",
            Self::MediatedEvidence => "mediated_evidence",
            Self::SelfReported => "self_reported",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(super) enum IncidentSourceLane {
    ReasoningTimeline,
    EntityTimeline,
    Observations,
    MediationReceipts,
    CoordinationAnnounces,
    CoordinationLeases,
}

impl IncidentSourceLane {
    fn as_str(&self) -> &'static str {
        match self {
            Self::ReasoningTimeline => "reasoning_timeline",
            Self::EntityTimeline => "entity_timeline",
            Self::Observations => "observations",
            Self::MediationReceipts => "mediation_receipts",
            Self::CoordinationAnnounces => "coordination_announces",
            Self::CoordinationLeases => "coordination_leases",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct IncidentWindow {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

impl IncidentWindow {
    fn contains(&self, timestamp: DateTime<Utc>) -> bool {
        timestamp >= self.from && timestamp < self.to
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct IncidentActor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct IncidentEvent {
    pub event_id: String,
    pub source_lane: IncidentSourceLane,
    pub timestamp: DateTime<Utc>,
    pub actor: IncidentActor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_or_record_id: Option<String>,
    pub assurance_class: AssuranceClass,
    pub payload: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct IncidentCostTotals {
    pub reports_joined: usize,
    pub assistant_turns: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_tokens: u64,
    pub measured_context_total: u64,
    pub join_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct IncidentCase {
    pub schema: String,
    pub id: String,
    pub tenant_id: String,
    pub title: String,
    pub window: IncidentWindow,
    #[serde(default)]
    pub session_ids: Vec<String>,
    #[serde(default)]
    pub agent_ids: Vec<String>,
    #[serde(default)]
    pub entities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub events: Vec<IncidentEvent>,
    pub event_counts_by_lane: BTreeMap<String, usize>,
    pub event_counts_by_assurance: BTreeMap<String, usize>,
    pub cost_totals: IncidentCostTotals,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct CreateIncidentBody {
    pub tenant_id: String,
    pub title: String,
    pub window: IncidentWindow,
    #[serde(default)]
    pub session_ids: Vec<String>,
    #[serde(default)]
    pub agent_ids: Vec<String>,
    #[serde(default)]
    pub entities: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct ListIncidentsQuery {
    pub tenant_id: String,
}

fn feature_enabled() -> bool {
    std::env::var(FEATURE_FLAG_ENV)
        .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"))
        .unwrap_or(false)
}

fn disabled_response() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        format!("incident reconstruction disabled (set {FEATURE_FLAG_ENV}=1)"),
    )
}

fn validate_create(body: &CreateIncidentBody) -> Result<(), String> {
    if body.tenant_id.trim().is_empty() {
        return Err("tenant_id is required".to_string());
    }
    if body.title.trim().is_empty() {
        return Err("title is required".to_string());
    }
    if body.window.from >= body.window.to {
        return Err("window.from must be earlier than window.to".to_string());
    }
    if [body.session_ids.len(), body.agent_ids.len(), body.entities.len()]
        .into_iter()
        .any(|count| count > MAX_SELECTORS)
    {
        return Err(format!("selector lists are capped at {MAX_SELECTORS} entries"));
    }
    Ok(())
}

fn valid_case_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn event_id(parts: &[&str]) -> String {
    let joined = parts.join("\u{1f}");
    let short: String = blake3::hash(joined.as_bytes()).to_hex().chars().take(24).collect();
    format!("ie_{short}")
}

fn parse_value(value: &str) -> Value {
    serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_string()))
}

fn inferred_session(haystack: &str, session_ids: &[String]) -> Option<String> {
    session_ids
        .iter()
        .find(|session| haystack.contains(session.as_str()))
        .cloned()
}

fn selector_match(haystack: &str, selectors: &[String]) -> bool {
    selectors.is_empty() || selectors.iter().any(|selector| haystack.contains(selector))
}

fn reasoning_events(
    store: &corecrux_memory::FactStore,
    tenant_hash: &str,
    tenant_id: &str,
    window: &IncidentWindow,
    session_ids: &[String],
    agent_ids: &[String],
) -> Vec<IncidentEvent> {
    let timeline = super::workbench::timeline_events(store, tenant_id, MAX_REASONING_EVENTS);
    let fact_ids: HashSet<&str> = timeline
        .iter()
        .filter_map(|event| event.get("fact_id").and_then(Value::as_str))
        .collect();
    store
        .all_facts_for_tenant(tenant_hash)
        .filter(|fact| fact_ids.contains(fact.fact_id.as_str()) && !fact.deleted && window.contains(fact.stored_at))
        .filter_map(|fact| {
            let haystack = format!("{}\n{}\n{}", fact.entity, fact.key, fact.value);
            if !selector_match(&haystack, session_ids) {
                return None;
            }
            if !agent_ids.is_empty()
                && !fact.actor.as_ref().is_some_and(|actor| agent_ids.contains(actor))
                && !selector_match(&haystack, agent_ids)
            {
                return None;
            }
            Some(IncidentEvent {
                event_id: event_id(&["reasoning", &fact.fact_id]),
                source_lane: IncidentSourceLane::ReasoningTimeline,
                timestamp: fact.stored_at,
                actor: IncidentActor {
                    passport_id: fact.actor.clone(),
                    session_id: inferred_session(&haystack, session_ids),
                },
                receipt_or_record_id: fact.source_receipt.clone().or_else(|| Some(fact.fact_id.clone())),
                assurance_class: AssuranceClass::VerifiableRecord,
                payload: json!({
                    "kind": "reasoning_timeline",
                    "fact_id": fact.fact_id,
                    "entity": fact.entity,
                    "key": fact.key,
                    "value": parse_value(&fact.value),
                    "source_receipt": fact.source_receipt,
                }),
            })
        })
        .collect()
}

fn observation_events(
    records: Vec<super::observations::ObservationRecordV1>,
    window: &IncidentWindow,
    session_ids: &[String],
    agent_ids: &[String],
) -> Vec<IncidentEvent> {
    records
        .into_iter()
        .filter(|record| window.contains(record.ts))
        .filter(|record| selector_match(&record.session_id, session_ids))
        .filter(|record| agent_ids.is_empty() || agent_ids.contains(&record.principal))
        .filter_map(|record| {
            let mediated = record.kind == "tool_mediation"
                || record.provider == "crux-gateway"
                || record.session_id.starts_with("mediation::");
            let source_lane = if mediated {
                IncidentSourceLane::MediationReceipts
            } else {
                IncidentSourceLane::Observations
            };
            let assurance_class = if mediated {
                AssuranceClass::MediatedEvidence
            } else {
                AssuranceClass::SelfReported
            };
            let record_json = serde_json::to_value(&record).ok()?;
            let session_id = record
                .session_id
                .strip_prefix("mediation::")
                .unwrap_or(record.session_id.as_str())
                .to_string();
            Some(IncidentEvent {
                event_id: event_id(&[source_lane.as_str(), &record.observation_id]),
                source_lane,
                timestamp: record.ts,
                actor: IncidentActor {
                    passport_id: Some(record.principal.clone()),
                    session_id: Some(session_id),
                },
                receipt_or_record_id: Some(record.observation_id.clone()),
                assurance_class,
                payload: json!({ "record": record_json }),
            })
        })
        .collect()
}

fn coordination_events(
    facts: &[Fact],
    bindings: &HashMap<String, crate::session_bindings::SessionBinding>,
    tenant_id: &str,
    window: &IncidentWindow,
    session_ids: &[String],
    agent_ids: &[String],
) -> Vec<IncidentEvent> {
    facts
        .iter()
        .filter(|fact| fact.entity.starts_with("__coord__::") && fact.key == crate::coord::INTENT_KEY && !fact.deleted)
        .filter_map(|fact| {
            let intent = serde_json::from_str::<crate::coord::CoordIntent>(&fact.value).ok()?;
            let timestamp = DateTime::from_timestamp_millis(intent.announced_at_unix_ms as i64)?;
            if !window.contains(timestamp)
                || (!session_ids.is_empty() && !session_ids.contains(&intent.session_id_hex))
                || (!agent_ids.is_empty() && !agent_ids.contains(&intent.passport_id))
            {
                return None;
            }
            let binding_tenant = bindings
                .get(&intent.session_id_hex)
                .map(|binding| binding.tenant_id.as_str());
            if binding_tenant.is_some_and(|bound| bound != tenant_id)
                || (binding_tenant.is_none() && tenant_id != "default")
            {
                return None;
            }
            Some(IncidentEvent {
                event_id: event_id(&["coord-announce", &fact.fact_id]),
                source_lane: IncidentSourceLane::CoordinationAnnounces,
                timestamp,
                actor: IncidentActor {
                    passport_id: Some(intent.passport_id.clone()),
                    session_id: Some(intent.session_id_hex.clone()),
                },
                receipt_or_record_id: Some(fact.fact_id.clone()),
                assurance_class: AssuranceClass::VerifiableRecord,
                payload: json!({ "fact_id": fact.fact_id, "intent": intent }),
            })
        })
        .collect()
}

async fn coordination_lease_events(
    state: &AppState,
    tenant_id: &str,
    window: &IncidentWindow,
    agent_ids: &[String],
) -> Vec<IncidentEvent> {
    let revisions = {
        let store = state.entity_store.read().await;
        let ids: Vec<String> = store
            .list(&corecrux_memory::EntityQuery {
                kind: Some(PUNCHCARD_KIND.to_string()),
                limit: None,
                include_deleted: true,
            })
            .into_iter()
            .map(|record| record.id.clone())
            .collect();
        ids.into_iter()
            .flat_map(|id| {
                store
                    .history(PUNCHCARD_KIND, &id)
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    };
    revisions
        .into_iter()
        .filter_map(|record| {
            let payload_tenant = record
                .payload
                .get("tenant_id")
                .and_then(Value::as_str)
                .unwrap_or("default");
            if payload_tenant != tenant_id {
                return None;
            }
            let actor = record
                .payload
                .get("holder_passport")
                .and_then(Value::as_str)
                .unwrap_or(&record.actor)
                .to_string();
            if !agent_ids.is_empty() && !agent_ids.contains(&actor) {
                return None;
            }
            let released = record.payload.get("released_at_unix_ms").and_then(Value::as_i64);
            let acquired = record.payload.get("acquired_at_unix_ms").and_then(Value::as_i64);
            let timestamp = DateTime::from_timestamp_millis(released.or(acquired)?)?;
            if !window.contains(timestamp) {
                return None;
            }
            let receipt_id = if released.is_some() {
                record.payload.get("receipt_release")
            } else {
                record.payload.get("receipt_acquire")
            }
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| Some(record.id.clone()));
            Some(IncidentEvent {
                event_id: event_id(&["coord-lease", &record.id, &record.version.to_string()]),
                source_lane: IncidentSourceLane::CoordinationLeases,
                timestamp,
                actor: IncidentActor {
                    passport_id: Some(actor),
                    session_id: None,
                },
                receipt_or_record_id: receipt_id,
                assurance_class: AssuranceClass::VerifiableRecord,
                payload: json!({
                    "record_id": record.id,
                    "version": record.version,
                    "payload": record.payload,
                }),
            })
        })
        .collect()
}

async fn entity_timeline_events(
    state: &AppState,
    tenant_id: &str,
    entities: &[String],
    window: &IncidentWindow,
) -> Vec<IncidentEvent> {
    if !state.http_dataplane.enabled() {
        return Vec::new();
    }
    let mut events = Vec::new();
    for selector in entities {
        let (entity_type, predicate) = selector.split_once('|').unwrap_or((selector.as_str(), ""));
        let rows = match state
            .http_dataplane
            .entity_timeline(tenant_id, entity_type, predicate)
            .await
        {
            Ok(rows) => rows,
            Err(_) => continue,
        };
        for (name, value, micros) in rows {
            let Some(timestamp) = DateTime::from_timestamp_micros(micros) else {
                continue;
            };
            if !window.contains(timestamp) {
                continue;
            }
            events.push(IncidentEvent {
                event_id: event_id(&["entity", selector, &name, &micros.to_string()]),
                source_lane: IncidentSourceLane::EntityTimeline,
                timestamp,
                actor: IncidentActor::default(),
                receipt_or_record_id: None,
                assurance_class: AssuranceClass::VerifiableRecord,
                payload: json!({
                    "selector": selector,
                    "entity_name": name,
                    "object_value": parse_value(&value),
                }),
            });
        }
    }
    events
}

async fn incident_cost_totals(tenant_id: &str, session_ids: &[String], window: &IncidentWindow) -> IncidentCostTotals {
    let reports = crate::cost::global().lock().await.reports_for_tenant(tenant_id);
    let mut totals = IncidentCostTotals {
        join_method: "case_totals_only; cost reports are session aggregates and have no per-event index".to_string(),
        ..IncidentCostTotals::default()
    };
    for stored in reports {
        if !session_ids.is_empty() && !session_ids.contains(&stored.session_id) {
            continue;
        }
        let starts_before_end = stored
            .report
            .started_at
            .as_deref()
            .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
            .is_none_or(|dt| dt.with_timezone(&Utc) < window.to);
        let ends_after_start = stored
            .report
            .ended_at
            .as_deref()
            .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
            .is_none_or(|dt| dt.with_timezone(&Utc) >= window.from);
        if !starts_before_end || !ends_after_start {
            continue;
        }
        totals.reports_joined += 1;
        totals.assistant_turns = totals
            .assistant_turns
            .saturating_add(stored.report.headline.assistant_turns);
        totals.input_tokens = totals.input_tokens.saturating_add(stored.report.measured.input);
        totals.output_tokens = totals.output_tokens.saturating_add(stored.report.measured.output);
        totals.cache_read_tokens = totals
            .cache_read_tokens
            .saturating_add(stored.report.measured.cache_read);
        totals.cache_creation_tokens = totals
            .cache_creation_tokens
            .saturating_add(stored.report.measured.cache_creation);
        totals.measured_context_total = totals
            .measured_context_total
            .saturating_add(stored.report.headline.measured_context_total);
    }
    totals
}

async fn assemble_case(
    state: &AppState,
    body: CreateIncidentBody,
    created_by: String,
    tenant_hash: &str,
) -> Result<IncidentCase, String> {
    validate_create(&body)?;
    let (mut events, coord_facts, bindings) = {
        let store = state.fact_store.read().await;
        let reasoning = reasoning_events(
            &store,
            tenant_hash,
            &body.tenant_id,
            &body.window,
            &body.session_ids,
            &body.agent_ids,
        );
        let facts = store.all_facts_for_tenant(tenant_hash).cloned().collect::<Vec<_>>();
        let bindings = crate::session_bindings::list_bindings(&store)
            .into_iter()
            .map(|binding| (binding.session_id_hex.clone(), binding))
            .collect::<HashMap<_, _>>();
        (reasoning, facts, bindings)
    };
    let observations = super::observations::read_all_observations(&state.data_dir)
        .map_err(|error| format!("read observations: {error}"))?;
    events.extend(observation_events(
        observations,
        &body.window,
        &body.session_ids,
        &body.agent_ids,
    ));
    events.extend(coordination_events(
        &coord_facts,
        &bindings,
        &body.tenant_id,
        &body.window,
        &body.session_ids,
        &body.agent_ids,
    ));
    events.extend(coordination_lease_events(state, &body.tenant_id, &body.window, &body.agent_ids).await);
    events.extend(entity_timeline_events(state, &body.tenant_id, &body.entities, &body.window).await);
    events.sort_by(|a, b| {
        a.timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.source_lane.cmp(&b.source_lane))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });

    let mut event_counts_by_lane = BTreeMap::new();
    let mut event_counts_by_assurance = BTreeMap::new();
    for event in &events {
        *event_counts_by_lane
            .entry(event.source_lane.as_str().to_string())
            .or_insert(0) += 1;
        *event_counts_by_assurance
            .entry(event.assurance_class.as_str().to_string())
            .or_insert(0) += 1;
    }
    let cost_totals = incident_cost_totals(&body.tenant_id, &body.session_ids, &body.window).await;
    Ok(IncidentCase {
        schema: "crux.incident.case.v1".to_string(),
        id: format!("inc_{}", uuid::Uuid::new_v4().simple()),
        tenant_id: body.tenant_id,
        title: body.title,
        window: body.window,
        session_ids: body.session_ids,
        agent_ids: body.agent_ids,
        entities: body.entities,
        notes: body.notes,
        created_at: Utc::now(),
        created_by,
        events,
        event_counts_by_lane,
        event_counts_by_assurance,
        cost_totals,
    })
}

fn latest_case_fact(store: &corecrux_memory::FactStore, id: &str) -> Option<(Fact, IncidentCase)> {
    let entity = format!("{INCIDENT_ENTITY_PREFIX}::{id}");
    let fact = store
        .query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            query: None,
            entity: Some(entity),
            entity_prefix: None,
            top_k: 16,
            token_budget: None,
        })
        .facts
        .into_iter()
        .filter(|fact| fact.key == INCIDENT_CASE_KEY && !fact.deleted)
        .max_by_key(|fact| fact.version)?;
    let case = serde_json::from_str::<IncidentCase>(&fact.value).ok()?;
    Some((fact, case))
}

fn list_case_records(store: &corecrux_memory::FactStore, tenant_id: &str) -> Vec<IncidentCase> {
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(format!("{INCIDENT_ENTITY_PREFIX}::")),
        top_k: 10_000,
        token_budget: None,
    });
    let mut cases = crate::fact_helpers::dedup_latest(result.facts)
        .into_iter()
        .filter(|fact| fact.key == INCIDENT_CASE_KEY && !fact.deleted)
        .filter_map(|fact| serde_json::from_str::<IncidentCase>(&fact.value).ok())
        .filter(|case| case.tenant_id == tenant_id)
        .collect::<Vec<_>>();
    cases.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| a.id.cmp(&b.id)));
    cases
}

fn observation_verification_report(
    state: &AppState,
    record: &super::observations::ObservationRecordV1,
    tenant_id: &str,
    verified_at: DateTime<Utc>,
) -> VerificationReportV1 {
    let body_bytes = super::observations::canonical_body_bytes(record).unwrap_or_default();
    let recomputed = blake3::hash(&body_bytes);
    let receipt_hash = record
        .receipt
        .body_hash
        .strip_prefix("blake3:")
        .unwrap_or(record.receipt.body_hash.as_str());
    let payload_hash_matches = recomputed.to_hex().as_str() == receipt_hash;
    let signature_valid = hex::decode(&state.passport_public_key_hex)
        .ok()
        .filter(|bytes| bytes.len() == 32)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        .zip(
            hex::decode(&record.receipt.signature)
                .ok()
                .filter(|bytes| bytes.len() == 64)
                .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
                .map(|bytes| Signature::from_bytes(&bytes)),
        )
        .is_some_and(|(key, signature)| key.verify_strict(recomputed.as_bytes(), &signature).is_ok());
    let (error_code, error_message) = if !payload_hash_matches {
        ("BODY_HASH_MISMATCH", Some("observation body hash mismatch".to_string()))
    } else if !signature_valid {
        ("SIG_INVALID", Some("observation signature invalid".to_string()))
    } else {
        ("OK", None)
    };
    VerificationReportV1 {
        schema: "cuecrux.receipt.verify.v1".to_string(),
        receipt_id: record.observation_id.clone(),
        tenant_id: tenant_id.to_string(),
        payload_hash_hex: receipt_hash.to_string(),
        signature: VerificationSigInfoV1 {
            alg: record.receipt.alg.clone(),
            key_id: Some(record.receipt.signed_by.clone()),
        },
        integrity: VerificationIntegrityV1 {
            payload_hash_matches,
            canonical_bytes_parse_ok: !body_bytes.is_empty(),
        },
        trace_checks: VerificationTraceChecksV1::default(),
        trace_summary: None,
        signature_valid,
        pubkey_fingerprint: Some(record.receipt.signed_by.clone()),
        error_code: error_code.to_string(),
        error_message,
        verified_at: verified_at.to_rfc3339(),
        verifier_build: format!("{}@{}", state.build.version, state.build.commit),
    }
}

async fn verification_reports_for_case(state: &AppState, case: &IncidentCase) -> Vec<VerificationReportV1> {
    let now = Utc::now();
    let mut reports = Vec::new();
    let mut covered = BTreeSet::new();
    for event in &case.events {
        let Some(record_value) = event.payload.get("record") else {
            continue;
        };
        let Ok(record) = serde_json::from_value::<super::observations::ObservationRecordV1>(record_value.clone())
        else {
            continue;
        };
        covered.insert(record.observation_id.clone());
        reports.push(observation_verification_report(state, &record, &case.tenant_id, now));
    }
    if state.http_dataplane.enabled() {
        let mut receipt_ids = case
            .events
            .iter()
            .filter_map(referenced_receipt_id)
            .collect::<BTreeSet<_>>();
        receipt_ids.retain(|receipt_id| !covered.contains(receipt_id));
        for receipt_id in receipt_ids {
            if let Ok(Some(report)) = state
                .http_dataplane
                .verify_receipt_stream(&case.tenant_id, &receipt_id, None)
                .await
            {
                reports.push(report);
            }
        }
    }
    reports.sort_by(|a, b| a.receipt_id.cmp(&b.receipt_id));
    reports
}

fn referenced_receipt_id(event: &IncidentEvent) -> Option<String> {
    match event.source_lane {
        IncidentSourceLane::ReasoningTimeline => event
            .payload
            .get("source_receipt")
            .and_then(Value::as_str)
            .map(str::to_string),
        IncidentSourceLane::Observations | IncidentSourceLane::MediationReceipts => event.receipt_or_record_id.clone(),
        IncidentSourceLane::CoordinationLeases => {
            let payload = event.payload.get("payload")?;
            payload
                .get("receipt_release")
                .or_else(|| payload.get("receipt_acquire"))
                .and_then(Value::as_str)
                .map(str::to_string)
        }
        IncidentSourceLane::EntityTimeline | IncidentSourceLane::CoordinationAnnounces => None,
    }
}

async fn build_incident_bundle(
    state: &AppState,
    case_fact: &Fact,
    case: &IncidentCase,
) -> Result<(Vec<u8>, AuditBundleKeyClassV1, String), String> {
    let now = Utc::now();
    let case_json = serde_json::to_string(case).map_err(|error| format!("serialise case: {error}"))?;
    let mut events = vec![AuditEventV1 {
        fact_id: case_fact.fact_id.clone(),
        entity: case_fact.entity.clone(),
        key: case_fact.key.clone(),
        value: case_json.clone(),
        source_receipt: case_fact.source_receipt.clone(),
        confidence: case_fact.confidence,
        stored_at: case_fact.stored_at.to_rfc3339(),
        tokens: case_json.len().div_ceil(4),
        deleted: false,
        version: case_fact.version,
        supersedes: case_fact.supersedes.clone(),
    }];
    let reports = verification_reports_for_case(state, case).await;
    for report in &reports {
        let report_json =
            serde_json::to_string(report).map_err(|error| format!("serialise verification report: {error}"))?;
        events.push(AuditEventV1 {
            fact_id: format!("incident-report::{}::{}", case.id, report.receipt_id),
            entity: case_fact.entity.clone(),
            key: "verification_report".to_string(),
            value: report_json.clone(),
            source_receipt: Some(report.receipt_id.clone()),
            confidence: 1.0,
            stored_at: now.to_rfc3339(),
            tokens: report_json.len().div_ceil(4),
            deleted: false,
            version: 1,
            supersedes: None,
        });
    }
    events.sort_by(|a, b| a.stored_at.cmp(&b.stored_at).then_with(|| a.fact_id.cmp(&b.fact_id)));

    let mut ref_pairs = BTreeSet::new();
    for event in &case.events {
        if let Some(receipt_id) = referenced_receipt_id(event) {
            ref_pairs.insert((event.event_id.clone(), receipt_id));
        }
    }
    let receipt_refs = ref_pairs
        .into_iter()
        .map(|(fact_id, receipt_id)| AuditReceiptRefV1 { fact_id, receipt_id })
        .collect();
    let resolved = resolve_audit_export_signing_key(Some(&state.data_dir))
        .map_err(|error| format!("resolve audit export signing key: {error}"))?;
    let key_class = resolved.key_class;
    let bundle_id = format!("incident-bundle-{}", case.id);
    let built = build_bundle_v1(BuildBundleInputV1 {
        bundle_id: bundle_id.clone(),
        since_rfc3339: case.window.from.to_rfc3339(),
        until_rfc3339: case.window.to.to_rfc3339(),
        generated_at_rfc3339: now.to_rfc3339(),
        scope: AuditBundleScopeV1 {
            entity_prefix: Some(case_fact.entity.clone()),
            include_reserved: true,
            caller: Some(case.created_by.clone()),
        },
        events,
        receipt_refs,
        witness_proofs: corecrux_receipts::read_witnessed_proofs_jsonl(&state.data_dir.join("witness_proofs.jsonl")),
        signing_key: &resolved.signing_key,
        signer_key_id: resolved.signer_key_id,
        key_class,
    })
    .map_err(|error| format!("build incident audit bundle: {error}"))?;
    let mut bytes = Vec::new();
    built
        .write_tar_zst(&mut bytes)
        .map_err(|error| format!("write incident audit bundle: {error}"))?;
    Ok((bytes, key_class, bundle_id))
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_incident(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateIncidentBody>,
) -> Response {
    if !feature_enabled() {
        return disabled_response();
    }
    if let Err(error) = validate_create(&body) {
        return problem_response(StatusCode::BAD_REQUEST, error);
    }
    if let Err(problem) =
        require_http_any_scope_for_tenant(&state.auth, &headers, &["facts:write", "admin:write"], &body.tenant_id)
    {
        return problem.into_response();
    }
    let ctx = match http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };
    let tenant_hash = super::facts::tenant_hash_for_read_context(&ctx);
    let created_by = ctx.passport_id.unwrap_or_else(|| state.passport_fpr.clone());
    let case = match assemble_case(&state, body, created_by.clone(), &tenant_hash).await {
        Ok(case) => case,
        Err(error) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    let value = match serde_json::to_string(&case) {
        Ok(value) => value,
        Err(error) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };
    let mut fact = StoreFact {
        tenant_hash: case.tenant_id.clone(),
        entity: format!("{INCIDENT_ENTITY_PREFIX}::{}", case.id),
        key: INCIDENT_CASE_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: Some(corecrux_memory::HorizonClass::None),
        actor: Some(created_by),
    };
    crate::fact_privacy::enforce(&state.privacy_policy, &mut fact);
    let stored = state.fact_store.write().await.store(fact);
    (
        StatusCode::CREATED,
        Json(json!({ "case": case, "case_record_id": stored.fact_id })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn list_incidents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListIncidentsQuery>,
) -> Response {
    if !feature_enabled() {
        return disabled_response();
    }
    if query.tenant_id.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id is required");
    }
    if let Err(problem) =
        require_http_any_scope_for_tenant(&state.auth, &headers, &["query:read", "admin:read"], &query.tenant_id)
    {
        return problem.into_response();
    }
    let cases = {
        let store = state.fact_store.read().await;
        list_case_records(&store, &query.tenant_id)
    };
    Json(json!({
        "schema": "crux.incident.case_list.v1",
        "tenant_id": query.tenant_id,
        "count": cases.len(),
        "cases": cases,
    }))
    .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_incident(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if !feature_enabled() {
        return disabled_response();
    }
    if !valid_case_id(&id) {
        return problem_response(StatusCode::BAD_REQUEST, "invalid incident id");
    }
    let found = {
        let store = state.fact_store.read().await;
        latest_case_fact(&store, &id)
    };
    let Some((fact, case)) = found else {
        return problem_response(StatusCode::NOT_FOUND, format!("incident {id} not found"));
    };
    if let Err(problem) =
        require_http_any_scope_for_tenant(&state.auth, &headers, &["query:read", "admin:read"], &case.tenant_id)
    {
        return problem.into_response();
    }
    Json(json!({ "case": case, "case_record_id": fact.fact_id })).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn export_incident(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if !feature_enabled() {
        return disabled_response();
    }
    if !valid_case_id(&id) {
        return problem_response(StatusCode::BAD_REQUEST, "invalid incident id");
    }
    let found = {
        let store = state.fact_store.read().await;
        latest_case_fact(&store, &id)
    };
    let Some((fact, case)) = found else {
        return problem_response(StatusCode::NOT_FOUND, format!("incident {id} not found"));
    };
    if let Err(problem) = require_http_any_scope_for_tenant(
        &state.auth,
        &headers,
        &["query:read", "exports:read", "admin:read"],
        &case.tenant_id,
    ) {
        return problem.into_response();
    }
    let (bytes, key_class, bundle_id) = match build_incident_bundle(&state, &fact, &case).await {
        Ok(result) => result,
        Err(error) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    let key_class = match key_class {
        AuditBundleKeyClassV1::Persistent => "persistent",
        AuditBundleKeyClassV1::Env => "env",
        AuditBundleKeyClassV1::Ephemeral => "ephemeral",
    };
    let disposition = format!("attachment; filename=\"{bundle_id}.tar.zst\"");
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/zstd"));
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        response.headers_mut().insert(header::CONTENT_DISPOSITION, value);
    }
    response
        .headers_mut()
        .insert("x-crux-audit-key-class", HeaderValue::from_static(key_class));
    response
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::http::observations::{ObservationRecordV1, ReceiptEnvelopeV1};
    use crate::http::tests::test_app_state;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn signed_observation(
        signing_key: &SigningKey,
        id: &str,
        session: &str,
        principal: &str,
        kind: &str,
        provider: &str,
        ts: DateTime<Utc>,
    ) -> ObservationRecordV1 {
        let mut record = ObservationRecordV1 {
            observation_id: id.to_string(),
            session_id: session.to_string(),
            ts,
            client_ts: None,
            provider: provider.to_string(),
            principal: principal.to_string(),
            kind: kind.to_string(),
            payload: json!({"seed": id}),
            seq: Some(0),
            prev_hash: None,
            receipt: ReceiptEnvelopeV1 {
                alg: "ed25519".to_string(),
                signed_by: "p_seed".to_string(),
                body_hash: String::new(),
                signature: String::new(),
            },
        };
        let body = super::super::observations::canonical_body_bytes(&record).expect("canonical body");
        let hash = blake3::hash(&body);
        record.receipt.body_hash = format!("blake3:{}", hash.to_hex());
        record.receipt.signature = hex::encode(signing_key.sign(hash.as_bytes()).to_bytes());
        record
    }

    fn write_observations(state: &AppState, session: &str, records: &[ObservationRecordV1]) {
        let path = super::super::observations::observation_file_path(&state.data_dir, session);
        std::fs::create_dir_all(path.parent().expect("observation parent")).expect("mkdir observations");
        let mut text = records
            .iter()
            .map(|record| serde_json::to_string(record).expect("serialise observation"))
            .collect::<Vec<_>>()
            .join("\n");
        text.push('\n');
        std::fs::write(path, text).expect("write observations");
    }

    #[tokio::test]
    async fn seeded_incident_merges_orders_classifies_and_exports_offline() {
        let mut state = test_app_state(1);
        let signing_key = SigningKey::from_bytes(&[0x5a; 32]);
        state.passport_public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let now = Utc::now();
        let from = now - chrono::Duration::minutes(10);
        let to = now + chrono::Duration::minutes(10);
        let first = signed_observation(
            &signing_key,
            "obs-s1",
            "s1",
            "p_seed",
            "tool_use",
            "codex-cli",
            from + chrono::Duration::minutes(1),
        );
        let second = signed_observation(
            &signing_key,
            "obs-s2",
            "s2",
            "p_seed",
            "model_response",
            "openai",
            from + chrono::Duration::minutes(2),
        );
        let mediated = signed_observation(
            &signing_key,
            "med-s2",
            "mediation::s2",
            "p_seed",
            "tool_mediation",
            "crux-gateway",
            from + chrono::Duration::minutes(3),
        );
        write_observations(&state, "s1", &[first]);
        write_observations(&state, "s2", &[second]);
        write_observations(&state, "mediation::s2", &[mediated]);
        {
            let mut store = state.fact_store.write().await;
            for (session, receipt) in [("s1", "r-reason-1"), ("s2", "r-reason-2")] {
                store.store(StoreFact {
                    tenant_hash: "tenant-a".to_string(),
                    entity: format!("__workbench__::tenant-a::command_ledger::{session}"),
                    key: "command_ledger".to_string(),
                    value: json!({"session_id": session, "command": "seed"}).to_string(),
                    source_receipt: Some(receipt.to_string()),
                    confidence: 1.0,
                    private: true,
                    horizon_class: None,
                    actor: Some("p_seed".to_string()),
                });
            }
        }
        let body = CreateIncidentBody {
            tenant_id: "tenant-a".to_string(),
            title: "Seeded incident".to_string(),
            window: IncidentWindow { from, to },
            session_ids: vec!["s1".to_string(), "s2".to_string()],
            agent_ids: vec!["p_seed".to_string()],
            entities: Vec::new(),
            notes: Some("fixture".to_string()),
        };
        let case = assemble_case(&state, body, "p_seed".to_string(), "tenant-a")
            .await
            .expect("assemble case");
        assert!(case
            .events
            .windows(2)
            .all(|pair| pair[0].timestamp <= pair[1].timestamp));
        assert_eq!(case.event_counts_by_lane.get("observations"), Some(&2));
        assert_eq!(case.event_counts_by_lane.get("mediation_receipts"), Some(&1));
        assert_eq!(case.event_counts_by_lane.get("reasoning_timeline"), Some(&2));
        assert_eq!(case.event_counts_by_assurance.get("self_reported"), Some(&2));
        assert_eq!(case.event_counts_by_assurance.get("mediated_evidence"), Some(&1));
        assert_eq!(case.event_counts_by_assurance.get("verifiable_record"), Some(&2));
        let verification_reports = verification_reports_for_case(&state, &case).await;
        assert_eq!(verification_reports.len(), 3);
        assert!(verification_reports.iter().all(|report| report.signature_valid));
        assert!(verification_reports
            .iter()
            .all(|report| report.schema == "cuecrux.receipt.verify.v1"));

        let value = serde_json::to_string(&case).expect("case json");
        let mut sf = StoreFact {
            tenant_hash: case.tenant_id.clone(),
            entity: format!("{INCIDENT_ENTITY_PREFIX}::{}", case.id),
            key: INCIDENT_CASE_KEY.to_string(),
            value,
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: Some(corecrux_memory::HorizonClass::None),
            actor: Some("p_seed".to_string()),
        };
        crate::fact_privacy::enforce(&state.privacy_policy, &mut sf);
        let stored = state.fact_store.write().await.store(sf);
        assert!(stored.private, "incident cases must be born private");
        let (bytes, _, _) = build_incident_bundle(&state, &stored, &case)
            .await
            .expect("export bundle");
        let report = corecrux_receipts::verify_bundle_v1(&bytes).expect("offline verify");
        assert!(report.ok, "incident audit bundle must verify offline: {report:?}");
        assert!(report.fact_count >= 4, "case + three observation verification reports");
        assert!(report.receipt_count >= 5, "reasoning and observation receipt refs");
    }

    #[test]
    fn disabled_by_default_and_id_validation() {
        std::env::remove_var(FEATURE_FLAG_ENV);
        assert!(!feature_enabled());
        assert!(valid_case_id("inc_abcd-1234"));
        assert!(!valid_case_id("../escape"));
        assert!(!valid_case_id("bad\nheader"));
    }
}
