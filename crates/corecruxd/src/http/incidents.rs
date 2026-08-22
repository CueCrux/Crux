// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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

use super::{
    http_scope_context, problem_response, require_http_any_scope, require_http_any_scope_for_tenant, AppState,
};
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
    /// Cost reports excluded because their window bounds could not be parsed.
    ///
    /// D-28: an unparsable timestamp used to take the same branch as an absent
    /// one, so a broken report overlapped every window and was folded into the
    /// totals unannounced. Non-zero here means the totals are incomplete.
    #[serde(default)]
    pub reports_skipped_unparsable_window: usize,
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
            // D-28: an announce whose session has no tenant binding used to
            // fall through to whichever caller asked for the `default` tenant
            // — an unknown owner served as if it were owned. An unbound
            // announce belongs to no tenant and is served to none.
            let binding_tenant = bindings
                .get(&intent.session_id_hex)
                .map(|binding| binding.tenant_id.as_str());
            if binding_tenant.is_none_or(|bound| bound != tenant_id) {
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
        // D-28: an UNPARSABLE timestamp took the same `is_none_or` branch as
        // an ABSENT one, so a malformed report overlapped every window and was
        // silently folded into the totals. Absent is legitimate (the report
        // simply has no bound); unparsable is a broken report and is counted
        // out loud instead.
        let parse_bound = |raw: Option<&str>| match raw {
            None => Ok(None),
            Some(raw) => DateTime::parse_from_rfc3339(raw)
                .map(|dt| Some(dt.with_timezone(&Utc)))
                .map_err(|_| ()),
        };
        let (Ok(started), Ok(ended)) = (
            parse_bound(stored.report.started_at.as_deref()),
            parse_bound(stored.report.ended_at.as_deref()),
        ) else {
            totals.reports_skipped_unparsable_window += 1;
            continue;
        };
        let starts_before_end = started.is_none_or(|dt| dt < window.to);
        let ends_after_start = ended.is_none_or(|dt| dt >= window.from);
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
        binding: Default::default(),
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
    // D-28: validation used to run BEFORE authentication, so an
    // unauthenticated caller could probe the body schema by the shape of the
    // 400 it got back. Authenticate first; a caller with no credential learns
    // nothing about what the endpoint accepts.
    if let Err(problem) =
        require_http_any_scope_for_tenant(&state.auth, &headers, &["facts:write", "admin:write"], &body.tenant_id)
    {
        return problem.into_response();
    }
    if let Err(error) = validate_create(&body) {
        return problem_response(StatusCode::BAD_REQUEST, error);
    }
    let ctx = match http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };
    let tenant_hash = match super::facts::tenant_hash_for_requested_context(&ctx, &body.tenant_id) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
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
    // D-27: the lookup used to run BEFORE any scope check, so an
    // unauthenticated caller got 404 for an absent case and 401 for a present
    // one — an existence oracle over every case id. Require the read scope
    // first, tenant-agnostically; the tenant-bound check still follows once
    // the owning tenant is known.
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["query:read", "exports:read", "admin:read"]) {
        return problem.into_response();
    }
    let found = {
        let store = state.fact_store.read().await;
        latest_case_fact(&store, &id)
    };
    let Some((fact, case)) = found else {
        return problem_response(StatusCode::NOT_FOUND, format!("incident {id} not found"));
    };
    // D-27, second half: a caller authorised for SOME tenant could still tell
    // another tenant's existing case (403) from an absent one (404). A case the
    // caller may not read is, to that caller, indistinguishable from one that
    // does not exist — so report it as absent rather than forbidden.
    if require_http_any_scope_for_tenant(&state.auth, &headers, &["query:read", "admin:read"], &case.tenant_id).is_err()
    {
        return problem_response(StatusCode::NOT_FOUND, format!("incident {id} not found"));
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
    // D-27: the lookup used to run BEFORE any scope check, so an
    // unauthenticated caller got 404 for an absent case and 401 for a present
    // one — an existence oracle over every case id. Require the read scope
    // first, tenant-agnostically; the tenant-bound check still follows once
    // the owning tenant is known.
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["query:read", "exports:read", "admin:read"]) {
        return problem.into_response();
    }
    let found = {
        let store = state.fact_store.read().await;
        latest_case_fact(&store, &id)
    };
    let Some((fact, case)) = found else {
        return problem_response(StatusCode::NOT_FOUND, format!("incident {id} not found"));
    };
    // D-27, second half: same as `get_incident` — a case this caller may not
    // read is reported absent, not forbidden, so 403-vs-404 stops being an
    // existence oracle for a caller authorised on a different tenant.
    if require_http_any_scope_for_tenant(
        &state.auth,
        &headers,
        &["query:read", "exports:read", "admin:read"],
        &case.tenant_id,
    )
    .is_err()
    {
        return problem_response(StatusCode::NOT_FOUND, format!("incident {id} not found"));
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
    use crate::auth::AuthMode;
    use crate::http::observations::{ObservationRecordV1, ReceiptEnvelopeV1};
    use crate::http::tests::{dev_scope_headers, test_app_state, test_app_state_with_auth};
    use ed25519_dalek::{Signer as _, SigningKey};

    /// Sets `CORECRUXD_FEATURE_INCIDENTS=1` for the lifetime of the guard and
    /// clears it on drop. Every test holding one must be `#[serial]` — the flag
    /// is process-global.
    struct FeatureFlag;

    impl FeatureFlag {
        fn on() -> Self {
            std::env::set_var(FEATURE_FLAG_ENV, "1");
            Self
        }
    }

    impl Drop for FeatureFlag {
        fn drop(&mut self) {
            std::env::remove_var(FEATURE_FLAG_ENV);
        }
    }

    async fn body_json(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    fn window_now() -> IncidentWindow {
        let now = Utc::now();
        IncidentWindow {
            from: now - chrono::Duration::hours(1),
            to: now + chrono::Duration::hours(1),
        }
    }

    fn create_body(tenant: &str, title: &str) -> CreateIncidentBody {
        CreateIncidentBody {
            tenant_id: tenant.to_string(),
            title: title.to_string(),
            window: window_now(),
            session_ids: Vec::new(),
            agent_ids: Vec::new(),
            entities: Vec::new(),
            notes: None,
        }
    }

    /// Create a case through the handler and return its id.
    async fn create_case(state: &AppState, tenant: &str, title: &str) -> String {
        let response = post_incident(State(state.clone()), HeaderMap::new(), Json(create_body(tenant, title))).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        body_json(response).await["case"]["id"]
            .as_str()
            .expect("case id")
            .to_string()
    }

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
    #[serial_test::serial]
    fn disabled_by_default_and_id_validation() {
        std::env::remove_var(FEATURE_FLAG_ENV);
        assert!(!feature_enabled());
        assert!(valid_case_id("inc_abcd-1234"));
        assert!(!valid_case_id("../escape"));
        assert!(!valid_case_id("bad\nheader"));
    }

    // ── Feature flag ──────────────────────────────────────────────────────

    /// The flag is an allow-list of truthy spellings; anything else — including
    /// plausible-looking values like `enabled` or `2` — must leave the surface
    /// off. A governance-tier lane must not switch on by accident.
    #[test]
    #[serial_test::serial]
    fn feature_flag_accepts_only_known_truthy_spellings() {
        for truthy in ["1", "true", "TRUE", "  On  ", "yes", "YES"] {
            std::env::set_var(FEATURE_FLAG_ENV, truthy);
            assert!(feature_enabled(), "{truthy:?} must enable the lane");
        }
        for falsy in ["", " ", "0", "off", "no", "false", "enabled", "2", "1 1"] {
            std::env::set_var(FEATURE_FLAG_ENV, falsy);
            assert!(!feature_enabled(), "{falsy:?} must NOT enable the lane");
        }
        std::env::remove_var(FEATURE_FLAG_ENV);
        assert!(!feature_enabled(), "absent env var means off");
    }

    /// With the flag off every route must 404 (invisible, not half-alive) —
    /// including for a request that would otherwise be rejected as unauthorised
    /// or malformed, so the surface leaks nothing about its existence.
    #[tokio::test]
    #[serial_test::serial]
    async fn all_handlers_return_404_when_feature_disabled() {
        std::env::remove_var(FEATURE_FLAG_ENV);
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);

        let post = post_incident(
            State(state.clone()),
            HeaderMap::new(),
            Json(create_body("", "")), // invalid body AND no auth headers
        )
        .await;
        assert_eq!(post.status(), StatusCode::NOT_FOUND);

        let list = list_incidents(
            State(state.clone()),
            HeaderMap::new(),
            Query(ListIncidentsQuery {
                tenant_id: "tenant-a".to_string(),
            }),
        )
        .await;
        assert_eq!(list.status(), StatusCode::NOT_FOUND);

        let get = get_incident(
            State(state.clone()),
            HeaderMap::new(),
            AxumPath("../escape".to_string()),
        )
        .await;
        assert_eq!(get.status(), StatusCode::NOT_FOUND);

        let export = export_incident(State(state), HeaderMap::new(), AxumPath("inc_x".to_string())).await;
        assert_eq!(export.status(), StatusCode::NOT_FOUND);
    }

    // ── Request validation ────────────────────────────────────────────────

    #[test]
    fn validate_create_rejects_blank_selectors_and_inverted_windows() {
        let ok = create_body("tenant-a", "title");
        validate_create(&ok).expect("valid body");

        let mut blank_tenant = create_body("   ", "title");
        blank_tenant.tenant_id = "   ".to_string();
        assert_eq!(
            validate_create(&blank_tenant).unwrap_err(),
            "tenant_id is required",
            "whitespace-only tenant is not a tenant"
        );

        let blank_title = create_body("tenant-a", "\t\n ");
        assert_eq!(validate_create(&blank_title).unwrap_err(), "title is required");

        let now = Utc::now();
        let mut inverted = create_body("tenant-a", "title");
        inverted.window = IncidentWindow {
            from: now + chrono::Duration::hours(1),
            to: now,
        };
        assert!(validate_create(&inverted).unwrap_err().contains("earlier than"));

        let mut empty_window = create_body("tenant-a", "title");
        empty_window.window = IncidentWindow { from: now, to: now };
        assert!(
            validate_create(&empty_window).is_err(),
            "a zero-width window selects nothing and must be rejected"
        );
    }

    /// Selector lists are the fan-out knob on a scan over every fact in the
    /// tenant; the cap must hold on each list independently.
    #[test]
    fn validate_create_caps_each_selector_list_independently() {
        let over = |n: usize| (0..n).map(|i| format!("s{i}")).collect::<Vec<_>>();

        let mut at_cap = create_body("tenant-a", "title");
        at_cap.session_ids = over(MAX_SELECTORS);
        at_cap.agent_ids = over(MAX_SELECTORS);
        at_cap.entities = over(MAX_SELECTORS);
        validate_create(&at_cap).expect("exactly at the cap is allowed");

        for field in 0..3 {
            let mut body = create_body("tenant-a", "title");
            match field {
                0 => body.session_ids = over(MAX_SELECTORS + 1),
                1 => body.agent_ids = over(MAX_SELECTORS + 1),
                _ => body.entities = over(MAX_SELECTORS + 1),
            }
            let err = validate_create(&body).unwrap_err();
            assert!(err.contains("capped at 100"), "field {field}: {err}");
        }
    }

    /// `valid_case_id` guards a value that lands in a `Content-Disposition`
    /// header and a fact entity — path traversal, header injection, and
    /// over-long ids must all be refused.
    #[test]
    fn valid_case_id_boundaries() {
        assert!(!valid_case_id(""));
        assert!(valid_case_id(&"a".repeat(128)));
        assert!(!valid_case_id(&"a".repeat(129)));
        assert!(valid_case_id("inc_ABC-123_x"));
        assert!(!valid_case_id("inc.1"));
        assert!(!valid_case_id("inc/1"));
        assert!(!valid_case_id("inc 1"));
        assert!(!valid_case_id("inc\r\nX-Evil: 1"));
        assert!(!valid_case_id("inc\u{e9}"));
    }

    // ── Pure helpers ──────────────────────────────────────────────────────

    /// Event ids are content-addressed; the `\u{1f}` separator must keep
    /// differently-grouped parts from colliding onto one id.
    #[test]
    fn event_id_is_deterministic_and_separator_safe() {
        assert_eq!(event_id(&["reasoning", "f1"]), event_id(&["reasoning", "f1"]));
        assert_ne!(event_id(&["reasoning", "f1"]), event_id(&["reasoning", "f2"]));
        assert_ne!(event_id(&["a", "bc"]), event_id(&["ab", "c"]));
        let id = event_id(&["x"]);
        assert!(id.starts_with("ie_"));
        assert_eq!(id.len(), 3 + 24);
    }

    /// Fact values are opaque strings; non-JSON must be preserved verbatim as a
    /// JSON string rather than being dropped from the reconstruction.
    #[test]
    fn parse_value_falls_back_to_a_json_string() {
        assert_eq!(parse_value(r#"{"a":1}"#), json!({"a": 1}));
        assert_eq!(parse_value("not json at all"), Value::String("not json at all".into()));
        assert_eq!(parse_value(""), Value::String(String::new()));
        assert_eq!(parse_value("42"), json!(42), "bare JSON scalars still parse");
    }

    /// PINS CURRENT BEHAVIOUR (absent-signal-reads-as-pass): an empty selector
    /// list means "no filter", so every candidate matches. A caller that meant
    /// to narrow the case but sent an empty list gets everything, not nothing.
    #[test]
    fn selector_match_treats_an_empty_list_as_match_all() {
        assert!(selector_match("anything", &[]));
        assert!(selector_match("", &[]));
        assert!(selector_match("abc-session-1-xyz", &["session-1".to_string()]));
        assert!(!selector_match("abc", &["session-1".to_string()]));
        assert!(
            selector_match("abc", &["nope".to_string(), "ab".to_string()]),
            "any-of semantics"
        );
    }

    #[test]
    fn inferred_session_returns_the_first_contained_id() {
        let ids = vec!["s1".to_string(), "s2".to_string()];
        assert_eq!(inferred_session("payload for s2 and s1", &ids).as_deref(), Some("s1"));
        assert_eq!(inferred_session("payload for s2", &ids).as_deref(), Some("s2"));
        assert!(inferred_session("nothing here", &ids).is_none());
        assert!(inferred_session("anything", &[]).is_none());
    }

    /// The window is half-open `[from, to)` — an event exactly on `to` belongs
    /// to the next window, so adjacent cases never double-count it.
    #[test]
    fn incident_window_is_half_open() {
        let from = DateTime::from_timestamp_millis(1_000).expect("from");
        let to = DateTime::from_timestamp_millis(2_000).expect("to");
        let window = IncidentWindow { from, to };
        assert!(window.contains(from));
        assert!(window.contains(DateTime::from_timestamp_millis(1_999).expect("mid")));
        assert!(!window.contains(to), "upper bound is exclusive");
        assert!(!window.contains(DateTime::from_timestamp_millis(999).expect("before")));
    }

    /// The wire strings are consumed by the console and the exported bundle;
    /// `as_str` and the serde representation must not drift apart.
    #[test]
    fn lane_and_assurance_wire_names_match_serde() {
        let lanes = [
            (IncidentSourceLane::ReasoningTimeline, "reasoning_timeline"),
            (IncidentSourceLane::EntityTimeline, "entity_timeline"),
            (IncidentSourceLane::Observations, "observations"),
            (IncidentSourceLane::MediationReceipts, "mediation_receipts"),
            (IncidentSourceLane::CoordinationAnnounces, "coordination_announces"),
            (IncidentSourceLane::CoordinationLeases, "coordination_leases"),
        ];
        for (lane, name) in lanes {
            assert_eq!(lane.as_str(), name);
            assert_eq!(serde_json::to_value(&lane).expect("encode"), json!(name));
        }
        for (class, name) in [
            (AssuranceClass::VerifiableRecord, "verifiable_record"),
            (AssuranceClass::MediatedEvidence, "mediated_evidence"),
            (AssuranceClass::SelfReported, "self_reported"),
        ] {
            assert_eq!(class.as_str(), name);
            assert_eq!(serde_json::to_value(&class).expect("encode"), json!(name));
        }
    }

    /// Same-timestamp events are ordered by lane then event id, so a case is
    /// byte-reproducible across runs. The lane order is the declaration order.
    #[test]
    fn source_lane_ordering_is_declaration_order() {
        let mut lanes = vec![
            IncidentSourceLane::CoordinationLeases,
            IncidentSourceLane::Observations,
            IncidentSourceLane::ReasoningTimeline,
            IncidentSourceLane::EntityTimeline,
        ];
        lanes.sort();
        assert_eq!(
            lanes,
            vec![
                IncidentSourceLane::ReasoningTimeline,
                IncidentSourceLane::EntityTimeline,
                IncidentSourceLane::Observations,
                IncidentSourceLane::CoordinationLeases,
            ]
        );
    }

    fn event_with(lane: IncidentSourceLane, receipt: Option<&str>, payload: Value) -> IncidentEvent {
        IncidentEvent {
            event_id: "ie_test".to_string(),
            source_lane: lane,
            timestamp: Utc::now(),
            actor: IncidentActor::default(),
            receipt_or_record_id: receipt.map(str::to_string),
            assurance_class: AssuranceClass::VerifiableRecord,
            payload,
        }
    }

    /// Each lane carries its receipt reference in a different place; the bundle
    /// export's `receipt_refs` depends on getting all six right.
    #[test]
    fn referenced_receipt_id_reads_the_right_field_per_lane() {
        assert_eq!(
            referenced_receipt_id(&event_with(
                IncidentSourceLane::ReasoningTimeline,
                Some("ignored"),
                json!({"source_receipt": "r-1"})
            ))
            .as_deref(),
            Some("r-1")
        );
        assert!(referenced_receipt_id(&event_with(
            IncidentSourceLane::ReasoningTimeline,
            Some("ignored"),
            json!({"source_receipt": Value::Null})
        ))
        .is_none());

        for lane in [IncidentSourceLane::Observations, IncidentSourceLane::MediationReceipts] {
            assert_eq!(
                referenced_receipt_id(&event_with(lane, Some("obs-1"), json!({}))).as_deref(),
                Some("obs-1")
            );
        }

        // Leases prefer the release receipt over the acquire receipt.
        assert_eq!(
            referenced_receipt_id(&event_with(
                IncidentSourceLane::CoordinationLeases,
                None,
                json!({"payload": {"receipt_acquire": "acq", "receipt_release": "rel"}})
            ))
            .as_deref(),
            Some("rel")
        );
        assert_eq!(
            referenced_receipt_id(&event_with(
                IncidentSourceLane::CoordinationLeases,
                None,
                json!({"payload": {"receipt_acquire": "acq"}})
            ))
            .as_deref(),
            Some("acq")
        );
        assert!(referenced_receipt_id(&event_with(
            IncidentSourceLane::CoordinationLeases,
            Some("record-id"),
            json!({"no_payload": true})
        ))
        .is_none());

        // These two lanes have no verifiable receipt at all.
        for lane in [
            IncidentSourceLane::EntityTimeline,
            IncidentSourceLane::CoordinationAnnounces,
        ] {
            assert!(referenced_receipt_id(&event_with(
                lane,
                Some("x"),
                json!({"payload": {"receipt_release": "r"}})
            ))
            .is_none());
        }
    }

    // ── Observation lane classification ───────────────────────────────────

    fn plain_observation(id: &str, session: &str, principal: &str, kind: &str, provider: &str) -> ObservationRecordV1 {
        ObservationRecordV1 {
            observation_id: id.to_string(),
            session_id: session.to_string(),
            ts: Utc::now(),
            client_ts: None,
            provider: provider.to_string(),
            principal: principal.to_string(),
            kind: kind.to_string(),
            payload: json!({}),
            seq: Some(0),
            prev_hash: None,
            receipt: ReceiptEnvelopeV1 {
                alg: "ed25519".to_string(),
                signed_by: "p_seed".to_string(),
                body_hash: String::new(),
                signature: String::new(),
            },
        }
    }

    /// Mediation is asserted by any ONE of three independent signals. Getting
    /// this wrong downgrades mediated evidence to self-reported (or the
    /// reverse), which is the whole assurance distinction.
    #[test]
    fn observation_events_detect_mediation_from_any_single_signal() {
        let window = window_now();
        let by_kind = plain_observation("a", "s1", "p", "tool_mediation", "codex-cli");
        let by_provider = plain_observation("b", "s1", "p", "tool_use", "crux-gateway");
        let by_session = plain_observation("c", "mediation::s1", "p", "tool_use", "codex-cli");
        let neither = plain_observation("d", "s1", "p", "tool_use", "codex-cli");

        let events = observation_events(vec![by_kind, by_provider, by_session, neither], &window, &[], &[]);
        assert_eq!(events.len(), 4);
        let lane_of = |id: &str| {
            events
                .iter()
                .find(|e| e.receipt_or_record_id.as_deref() == Some(id))
                .map(|e| (e.source_lane.clone(), e.assurance_class.clone()))
                .expect("event present")
        };
        for id in ["a", "b", "c"] {
            assert_eq!(
                lane_of(id),
                (IncidentSourceLane::MediationReceipts, AssuranceClass::MediatedEvidence),
                "observation {id} must classify as mediated"
            );
        }
        assert_eq!(
            lane_of("d"),
            (IncidentSourceLane::Observations, AssuranceClass::SelfReported)
        );

        // The `mediation::` transport prefix is stripped from the reported
        // session so the case joins against the real session id.
        let stripped = events
            .iter()
            .find(|e| e.receipt_or_record_id.as_deref() == Some("c"))
            .expect("event c");
        assert_eq!(stripped.actor.session_id.as_deref(), Some("s1"));
    }

    #[test]
    fn observation_events_filter_by_window_session_and_agent() {
        let now = Utc::now();
        let window = IncidentWindow {
            from: now - chrono::Duration::minutes(5),
            to: now + chrono::Duration::minutes(5),
        };
        let mut too_old = plain_observation("old", "s1", "p1", "tool_use", "cli");
        too_old.ts = now - chrono::Duration::hours(1);
        let mut on_upper_bound = plain_observation("edge", "s1", "p1", "tool_use", "cli");
        on_upper_bound.ts = window.to;
        let wrong_session = plain_observation("sess", "s9", "p1", "tool_use", "cli");
        let wrong_agent = plain_observation("agent", "s1", "p9", "tool_use", "cli");
        let keeper = plain_observation("keep", "s1", "p1", "tool_use", "cli");

        let events = observation_events(
            vec![too_old, on_upper_bound, wrong_session, wrong_agent, keeper],
            &window,
            &["s1".to_string()],
            &["p1".to_string()],
        );
        let ids: Vec<&str> = events
            .iter()
            .filter_map(|e| e.receipt_or_record_id.as_deref())
            .collect();
        assert_eq!(ids, vec!["keep"]);
    }

    // ── Coordination lanes ────────────────────────────────────────────────

    fn coord_intent(session: &str, passport: &str, at_ms: u64) -> crate::coord::CoordIntent {
        crate::coord::CoordIntent {
            project_id: "proj".to_string(),
            session_id_hex: session.to_string(),
            passport_id: passport.to_string(),
            execplan_slug: Some("plan-x".to_string()),
            milestone: Some("M1".to_string()),
            deploy_target: None,
            worktree: None,
            paths: Vec::new(),
            note: None,
            announced_at_unix_ms: at_ms,
            expires_at_unix_ms: at_ms + 60_000,
        }
    }

    fn binding(session: &str, tenant: &str) -> crate::session_bindings::SessionBinding {
        crate::session_bindings::SessionBinding {
            session_id_hex: session.to_string(),
            project_id: Some("proj".to_string()),
            tenant_id: tenant.to_string(),
            passport_id: "p1".to_string(),
            passport_category: "work".to_string(),
            agent_work_gate: false,
            bound_at_unix_ms: 0,
        }
    }

    fn coord_facts_for(intents: &[crate::coord::CoordIntent]) -> Vec<Fact> {
        let mut store = corecrux_memory::FactStore::new();
        for intent in intents {
            crate::coord::write_intent(&mut store, intent).expect("write intent");
        }
        store.all_facts_for_tenant("default").cloned().collect()
    }

    /// Tenant isolation on the coordination lane: an announce whose session is
    /// bound to another tenant must never land in this tenant's case.
    #[test]
    fn coordination_events_exclude_announces_bound_to_another_tenant() {
        let at = 1_700_000_000_000u64;
        let window = IncidentWindow {
            from: DateTime::from_timestamp_millis(at as i64 - 1_000).expect("from"),
            to: DateTime::from_timestamp_millis(at as i64 + 1_000).expect("to"),
        };
        let facts = coord_facts_for(&[coord_intent("mine", "p1", at), coord_intent("theirs", "p1", at)]);
        let mut bindings = HashMap::new();
        bindings.insert("mine".to_string(), binding("mine", "tenant-a"));
        bindings.insert("theirs".to_string(), binding("theirs", "tenant-b"));

        let events = coordination_events(&facts, &bindings, "tenant-a", &window, &[], &[]);
        assert_eq!(events.len(), 1, "only the tenant-a announce is included");
        assert_eq!(events[0].actor.session_id.as_deref(), Some("mine"));
        assert_eq!(events[0].source_lane, IncidentSourceLane::CoordinationAnnounces);
        assert_eq!(events[0].assurance_class, AssuranceClass::VerifiableRecord);
    }

    /// D-28 (inverted pin): an announce from a session with NO binding used
    /// to fall through to the `default` tenant — an unknown owner served as if
    /// it were owned. An unbound announce belongs to no tenant and is served
    /// to none.
    #[test]
    fn unbound_coordination_announces_belong_to_no_tenant() {
        let at = 1_700_000_000_000u64;
        let window = IncidentWindow {
            from: DateTime::from_timestamp_millis(at as i64 - 1_000).expect("from"),
            to: DateTime::from_timestamp_millis(at as i64 + 1_000).expect("to"),
        };
        let facts = coord_facts_for(&[coord_intent("unbound", "p1", at)]);
        let bindings = HashMap::new();

        assert!(
            coordination_events(&facts, &bindings, "default", &window, &[], &[]).is_empty(),
            "an unbound announce is not the default tenant's"
        );
        assert!(
            coordination_events(&facts, &bindings, "tenant-a", &window, &[], &[]).is_empty(),
            "nor any named tenant's"
        );
    }

    #[test]
    fn coordination_events_filter_by_window_session_and_agent() {
        let at = 1_700_000_000_000u64;
        let window = IncidentWindow {
            from: DateTime::from_timestamp_millis(at as i64 - 1_000).expect("from"),
            to: DateTime::from_timestamp_millis(at as i64 + 1_000).expect("to"),
        };
        let facts = coord_facts_for(&[
            coord_intent("s1", "p1", at),
            coord_intent("s2", "p2", at),
            coord_intent("s3", "p1", at - 10_000_000),
        ]);
        let mut bindings = HashMap::new();
        for session in ["s1", "s2", "s3"] {
            bindings.insert(session.to_string(), binding(session, "tenant-a"));
        }

        let sessions = coordination_events(
            &facts,
            &bindings,
            "tenant-a",
            &window,
            &["s1".to_string()],
            &["p1".to_string()],
        );
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].actor.session_id.as_deref(), Some("s1"));

        let by_agent = coordination_events(&facts, &bindings, "tenant-a", &window, &[], &["p2".to_string()]);
        assert_eq!(by_agent.len(), 1);
        assert_eq!(by_agent[0].actor.passport_id.as_deref(), Some("p2"));

        // s3 announced outside the window.
        let all = coordination_events(&facts, &bindings, "tenant-a", &window, &[], &[]);
        assert_eq!(all.len(), 2, "the out-of-window announce is dropped");
    }

    /// Facts that are not coordination intents (or are tombstoned) must not be
    /// mined for the coordination lane.
    #[test]
    fn coordination_events_ignore_non_intent_facts() {
        let mut store = corecrux_memory::FactStore::new();
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__coord__::proj::sX".to_string(),
            key: "not_intent".to_string(),
            value: "{}".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "other::thing".to_string(),
            key: crate::coord::INTENT_KEY.to_string(),
            value: "{}".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let facts: Vec<Fact> = store.all_facts_for_tenant("default").cloned().collect();
        let window = window_now();
        assert!(coordination_events(&facts, &HashMap::new(), "default", &window, &[], &[]).is_empty());
    }

    // ── Verification reports ──────────────────────────────────────────────

    /// A tampered observation body must be reported as `BODY_HASH_MISMATCH`
    /// rather than being silently included as verified evidence.
    #[tokio::test]
    async fn verification_report_flags_a_tampered_observation_body() {
        let mut state = test_app_state(1);
        let signing_key = SigningKey::from_bytes(&[0x5a; 32]);
        state.passport_public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let mut record = signed_observation(&signing_key, "obs-1", "s1", "p_seed", "tool_use", "cli", Utc::now());
        record.payload = json!({"tampered": true});

        let report = observation_verification_report(&state, &record, "tenant-a", Utc::now());
        assert!(!report.integrity.payload_hash_matches);
        assert!(!report.signature_valid);
        assert_eq!(report.error_code, "BODY_HASH_MISMATCH");
        assert_eq!(report.tenant_id, "tenant-a");
        assert_eq!(report.receipt_id, "obs-1");
        assert!(report.integrity.canonical_bytes_parse_ok);
    }

    /// A body that hashes correctly but is signed by a different key must be
    /// reported as `SIG_INVALID` — the hash check alone is not a signature.
    #[tokio::test]
    async fn verification_report_flags_a_foreign_signature() {
        let mut state = test_app_state(1);
        let attacker = SigningKey::from_bytes(&[0x11; 32]);
        let daemon = SigningKey::from_bytes(&[0x22; 32]);
        state.passport_public_key_hex = hex::encode(daemon.verifying_key().to_bytes());
        let record = signed_observation(&attacker, "obs-2", "s1", "p_seed", "tool_use", "cli", Utc::now());

        let report = observation_verification_report(&state, &record, "tenant-a", Utc::now());
        assert!(report.integrity.payload_hash_matches, "the body hash still matches");
        assert!(!report.signature_valid);
        assert_eq!(report.error_code, "SIG_INVALID");
    }

    /// A malformed daemon public key must fail the signature check closed, not
    /// skip it.
    #[tokio::test]
    async fn verification_report_fails_closed_on_an_unusable_daemon_key() {
        let mut state = test_app_state(1);
        let signing_key = SigningKey::from_bytes(&[0x5a; 32]);
        let record = signed_observation(&signing_key, "obs-3", "s1", "p_seed", "tool_use", "cli", Utc::now());
        state.passport_public_key_hex = "not-hex".to_string();
        let report = observation_verification_report(&state, &record, "tenant-a", Utc::now());
        assert!(!report.signature_valid);
        assert_eq!(report.error_code, "SIG_INVALID");

        state.passport_public_key_hex = "aabb".to_string(); // right hex, wrong length
        let report = observation_verification_report(&state, &record, "tenant-a", Utc::now());
        assert!(!report.signature_valid);
        assert_eq!(report.error_code, "SIG_INVALID");
    }

    /// Events carrying no `record` payload (coordination, entity timeline) must
    /// be skipped rather than producing a bogus verification report.
    #[tokio::test]
    async fn verification_reports_skip_events_without_an_observation_record() {
        let state = test_app_state(1);
        let case = IncidentCase {
            schema: "crux.incident.case.v1".to_string(),
            id: "inc_test".to_string(),
            tenant_id: "tenant-a".to_string(),
            title: "t".to_string(),
            window: window_now(),
            session_ids: Vec::new(),
            agent_ids: Vec::new(),
            entities: Vec::new(),
            notes: None,
            created_at: Utc::now(),
            created_by: "p_test".to_string(),
            events: vec![
                event_with(IncidentSourceLane::CoordinationAnnounces, None, json!({"intent": {}})),
                event_with(
                    IncidentSourceLane::Observations,
                    Some("x"),
                    json!({"record": {"not": "an observation"}}),
                ),
            ],
            event_counts_by_lane: BTreeMap::new(),
            event_counts_by_assurance: BTreeMap::new(),
            cost_totals: IncidentCostTotals::default(),
        };
        assert!(verification_reports_for_case(&state, &case).await.is_empty());
    }

    // ── Case storage helpers ──────────────────────────────────────────────

    fn store_case(store: &mut corecrux_memory::FactStore, case: &IncidentCase) -> Fact {
        store.store(StoreFact {
            tenant_hash: case.tenant_id.clone(),
            entity: format!("{INCIDENT_ENTITY_PREFIX}::{}", case.id),
            key: INCIDENT_CASE_KEY.to_string(),
            value: serde_json::to_string(case).expect("serialise case"),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: Some(corecrux_memory::HorizonClass::None),
            actor: Some(case.created_by.clone()),
        })
    }

    fn bare_case(id: &str, tenant: &str, title: &str, created_at: DateTime<Utc>) -> IncidentCase {
        IncidentCase {
            schema: "crux.incident.case.v1".to_string(),
            id: id.to_string(),
            tenant_id: tenant.to_string(),
            title: title.to_string(),
            window: window_now(),
            session_ids: Vec::new(),
            agent_ids: Vec::new(),
            entities: Vec::new(),
            notes: None,
            created_at,
            created_by: "p_test".to_string(),
            events: Vec::new(),
            event_counts_by_lane: BTreeMap::new(),
            event_counts_by_assurance: BTreeMap::new(),
            cost_totals: IncidentCostTotals::default(),
        }
    }

    /// A re-stored case supersedes the previous version; the reader must return
    /// the newest, not whichever the query happened to rank first.
    #[test]
    fn latest_case_fact_returns_the_highest_version() {
        let mut store = corecrux_memory::FactStore::new();
        let mut case = bare_case("inc_v", "tenant-a", "v1", Utc::now());
        store_case(&mut store, &case);
        case.title = "v2".to_string();
        store_case(&mut store, &case);

        let (fact, loaded) = latest_case_fact(&store, "inc_v").expect("found");
        assert_eq!(loaded.title, "v2");
        assert_eq!(fact.version, 2);
        assert!(latest_case_fact(&store, "inc_missing").is_none());
    }

    /// A case fact whose value no longer deserialises (schema drift) must read
    /// as "not found" rather than panicking the handler.
    #[test]
    fn latest_case_fact_returns_none_for_an_undeserialisable_value() {
        let mut store = corecrux_memory::FactStore::new();
        store.store(StoreFact {
            tenant_hash: "tenant-a".to_string(),
            entity: format!("{INCIDENT_ENTITY_PREFIX}::inc_broken"),
            key: INCIDENT_CASE_KEY.to_string(),
            value: "{\"schema\":\"crux.incident.case.v1\"}".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
        assert!(latest_case_fact(&store, "inc_broken").is_none());
    }

    /// The list is tenant-scoped and newest-first; a second tenant's cases must
    /// never appear even though all cases share one entity prefix.
    #[test]
    fn list_case_records_scopes_by_tenant_and_sorts_newest_first() {
        let mut store = corecrux_memory::FactStore::new();
        let base = Utc::now();
        store_case(&mut store, &bare_case("inc_old", "tenant-a", "old", base));
        store_case(
            &mut store,
            &bare_case("inc_new", "tenant-a", "new", base + chrono::Duration::minutes(5)),
        );
        store_case(&mut store, &bare_case("inc_other", "tenant-b", "other", base));

        let cases = list_case_records(&store, "tenant-a");
        let ids: Vec<&str> = cases.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["inc_new", "inc_old"], "newest first, tenant-scoped");
        assert_eq!(list_case_records(&store, "tenant-b").len(), 1);
        assert!(list_case_records(&store, "tenant-nobody").is_empty());
    }

    /// A re-stored case must appear once (latest version), not twice.
    #[test]
    fn list_case_records_dedups_superseded_versions() {
        let mut store = corecrux_memory::FactStore::new();
        let mut case = bare_case("inc_dup", "tenant-a", "v1", Utc::now());
        store_case(&mut store, &case);
        case.title = "v2".to_string();
        store_case(&mut store, &case);

        let cases = list_case_records(&store, "tenant-a");
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].title, "v2");
    }

    // ── Cost join ─────────────────────────────────────────────────────────

    fn cost_report(session: &str, started: Option<&str>, ended: Option<&str>) -> crux_cost::CostReport {
        serde_json::from_value(json!({
            "schema": "cuecrux.cost.report.v1",
            "session_id": session,
            "source": format!("{session}.jsonl"),
            "started_at": started,
            "ended_at": ended,
            "headline": {
                "assistant_turns": 2,
                "tasks": 1,
                "segments": 1,
                "context_tokens_per_turn": 50,
                "cache_read_to_output_ratio": 1.0,
                "measured_context_total": 100,
                "prefix_pct": 0.0,
            },
            "measured": { "input": 10, "output": 20, "cache_read": 30, "cache_creation": 40 },
            "buckets": [],
            "top_blocks": [],
            "levers": [],
        }))
        .expect("cost report fixture")
    }

    /// Cost totals are additive across the joined sessions and carry the
    /// honesty note explaining they are case-level, not per-event.
    #[tokio::test]
    async fn incident_cost_totals_sum_the_sessions_in_window() {
        let tenant = format!("cost-sum-{}", uuid::Uuid::new_v4().simple());
        let now = Utc::now();
        let window = IncidentWindow {
            from: now - chrono::Duration::hours(1),
            to: now + chrono::Duration::hours(1),
        };
        {
            let mut store = crate::cost::global().lock().await;
            store.put(
                tenant.clone(),
                "s1".to_string(),
                "p".to_string(),
                cost_report(
                    "s1",
                    Some(&now.to_rfc3339()),
                    Some(&(now + chrono::Duration::minutes(1)).to_rfc3339()),
                ),
            );
            store.put(
                tenant.clone(),
                "s2".to_string(),
                "p".to_string(),
                cost_report(
                    "s2",
                    Some(&now.to_rfc3339()),
                    Some(&(now + chrono::Duration::minutes(1)).to_rfc3339()),
                ),
            );
        }
        let totals = incident_cost_totals(&tenant, &[], &window).await;
        assert_eq!(totals.reports_joined, 2);
        assert_eq!(totals.assistant_turns, 4);
        assert_eq!(totals.input_tokens, 20);
        assert_eq!(totals.output_tokens, 40);
        assert_eq!(totals.cache_read_tokens, 60);
        assert_eq!(totals.cache_creation_tokens, 80);
        assert_eq!(totals.measured_context_total, 200);
        assert!(totals.join_method.contains("case_totals_only"));

        // Session selector narrows the join.
        let one = incident_cost_totals(&tenant, &["s1".to_string()], &window).await;
        assert_eq!(one.reports_joined, 1);
        assert_eq!(one.assistant_turns, 2);
    }

    /// A session whose active window does not overlap the incident window must
    /// be excluded on both edges.
    #[tokio::test]
    async fn incident_cost_totals_exclude_non_overlapping_sessions() {
        let tenant = format!("cost-window-{}", uuid::Uuid::new_v4().simple());
        let now = Utc::now();
        let window = IncidentWindow {
            from: now - chrono::Duration::hours(1),
            to: now + chrono::Duration::hours(1),
        };
        {
            let mut store = crate::cost::global().lock().await;
            store.put(
                tenant.clone(),
                "before".to_string(),
                "p".to_string(),
                cost_report(
                    "before",
                    Some(&(now - chrono::Duration::days(2)).to_rfc3339()),
                    Some(&(now - chrono::Duration::days(2)).to_rfc3339()),
                ),
            );
            store.put(
                tenant.clone(),
                "after".to_string(),
                "p".to_string(),
                cost_report(
                    "after",
                    Some(&(now + chrono::Duration::days(2)).to_rfc3339()),
                    Some(&(now + chrono::Duration::days(2)).to_rfc3339()),
                ),
            );
        }
        let totals = incident_cost_totals(&tenant, &[], &window).await;
        assert_eq!(totals.reports_joined, 0);
        assert_eq!(totals.measured_context_total, 0);
    }

    /// PINS CURRENT BEHAVIOUR (absent-signal-reads-as-pass): a report with no
    /// parseable `started_at`/`ended_at` is treated as overlapping EVERY
    /// window, so its tokens are joined into any incident for that tenant.
    #[tokio::test]
    async fn incident_cost_totals_join_reports_with_unparsable_timestamps() {
        let tenant = format!("cost-null-ts-{}", uuid::Uuid::new_v4().simple());
        let now = Utc::now();
        let window = IncidentWindow {
            from: now - chrono::Duration::minutes(1),
            to: now + chrono::Duration::minutes(1),
        };
        {
            let mut store = crate::cost::global().lock().await;
            store.put(
                tenant.clone(),
                "no-ts".to_string(),
                "p".to_string(),
                cost_report("no-ts", None, None),
            );
            store.put(
                tenant.clone(),
                "bad-ts".to_string(),
                "p".to_string(),
                cost_report("bad-ts", Some("not-a-timestamp"), Some("also-not")),
            );
        }
        let totals = incident_cost_totals(&tenant, &[], &window).await;
        // D-28 (inverted pin): an ABSENT bound is legitimate — the report
        // simply has none — and still joins. An UNPARSABLE one is a broken
        // report; it used to take the same branch and overlap every window
        // silently. It is now counted out loud instead.
        assert_eq!(totals.reports_joined, 1, "only the report with no bounds joins");
        assert_eq!(
            totals.reports_skipped_unparsable_window, 1,
            "and the malformed one is reported, not folded in"
        );
    }

    // ── Handlers ──────────────────────────────────────────────────────────

    /// End-to-end over the three read paths: a created case is retrievable by
    /// id and appears exactly once in its tenant's list.
    #[tokio::test]
    #[serial_test::serial]
    async fn create_then_get_and_list_round_trip() {
        let _flag = FeatureFlag::on();
        let state = test_app_state(16);
        let id = create_case(&state, "tenant-a", "Roundtrip").await;
        assert!(id.starts_with("inc_"), "case ids are prefixed: {id}");

        let got = get_incident(State(state.clone()), HeaderMap::new(), AxumPath(id.clone())).await;
        assert_eq!(got.status(), StatusCode::OK);
        let body = body_json(got).await;
        assert_eq!(body["case"]["id"], json!(id));
        assert_eq!(body["case"]["title"], json!("Roundtrip"));
        assert_eq!(body["case"]["schema"], json!("crux.incident.case.v1"));
        assert!(body["case_record_id"].is_string());

        let listed = list_incidents(
            State(state),
            HeaderMap::new(),
            Query(ListIncidentsQuery {
                tenant_id: "tenant-a".to_string(),
            }),
        )
        .await;
        assert_eq!(listed.status(), StatusCode::OK);
        let body = body_json(listed).await;
        assert_eq!(body["schema"], json!("crux.incident.case_list.v1"));
        assert_eq!(body["count"], json!(1));
        assert_eq!(body["cases"][0]["id"], json!(id));
    }

    /// Two tenants sharing one daemon must not see each other's cases through
    /// the list endpoint.
    #[tokio::test]
    #[serial_test::serial]
    async fn list_incidents_isolates_tenants() {
        let _flag = FeatureFlag::on();
        let state = test_app_state(16);
        let a = create_case(&state, "tenant-a", "A case").await;
        let b = create_case(&state, "tenant-b", "B case").await;
        assert_ne!(a, b);

        for (tenant, expected) in [("tenant-a", &a), ("tenant-b", &b)] {
            let response = list_incidents(
                State(state.clone()),
                HeaderMap::new(),
                Query(ListIncidentsQuery {
                    tenant_id: tenant.to_string(),
                }),
            )
            .await;
            let body = body_json(response).await;
            assert_eq!(body["count"], json!(1), "{tenant} must see exactly its own case");
            assert_eq!(body["cases"][0]["id"], json!(expected));
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn list_incidents_rejects_a_blank_tenant() {
        let _flag = FeatureFlag::on();
        let state = test_app_state(16);
        let response = list_incidents(
            State(state),
            HeaderMap::new(),
            Query(ListIncidentsQuery {
                tenant_id: "   ".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn get_and_export_reject_a_malformed_case_id() {
        let _flag = FeatureFlag::on();
        let state = test_app_state(16);
        for id in ["../escape", "", "inc\r\nX: 1"] {
            let got = get_incident(State(state.clone()), HeaderMap::new(), AxumPath(id.to_string())).await;
            assert_eq!(got.status(), StatusCode::BAD_REQUEST, "get {id:?}");
            let exported = export_incident(State(state.clone()), HeaderMap::new(), AxumPath(id.to_string())).await;
            assert_eq!(exported.status(), StatusCode::BAD_REQUEST, "export {id:?}");
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn get_and_export_404_for_an_unknown_case() {
        let _flag = FeatureFlag::on();
        let state = test_app_state(16);
        let got = get_incident(State(state.clone()), HeaderMap::new(), AxumPath("inc_nope".to_string())).await;
        assert_eq!(got.status(), StatusCode::NOT_FOUND);
        let exported = export_incident(State(state), HeaderMap::new(), AxumPath("inc_nope".to_string())).await;
        assert_eq!(exported.status(), StatusCode::NOT_FOUND);
    }

    // ── Auth ──────────────────────────────────────────────────────────────

    /// 401 for no credential, 403 for a valid credential lacking the scope —
    /// the two must not collapse into one status.
    #[tokio::test]
    #[serial_test::serial]
    async fn post_incident_separates_unauthenticated_from_unauthorised() {
        let _flag = FeatureFlag::on();
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);

        let anonymous = post_incident(
            State(state.clone()),
            HeaderMap::new(),
            Json(create_body("tenant-a", "t")),
        )
        .await;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

        let wrong_scope = post_incident(
            State(state.clone()),
            dev_scope_headers("query:read"),
            Json(create_body("tenant-a", "t")),
        )
        .await;
        assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);

        for scope in ["facts:write", "admin:write"] {
            let allowed = post_incident(
                State(state.clone()),
                dev_scope_headers(scope),
                Json(create_body("tenant-a", "t")),
            )
            .await;
            assert_eq!(allowed.status(), StatusCode::CREATED, "scope {scope}");
        }
    }

    /// D-28 (inverted pin): body validation used to run BEFORE the auth
    /// check, so an unauthenticated caller could probe the body schema by the
    /// shape of the 400 it got back.
    #[tokio::test]
    #[serial_test::serial]
    async fn post_incident_authenticates_before_validating_the_body() {
        let _flag = FeatureFlag::on();
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let response = post_incident(State(state.clone()), HeaderMap::new(), Json(create_body("", "t"))).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "a caller with no credential learns nothing about what the endpoint accepts"
        );

        // Control: an authenticated caller still gets the validation error.
        let validated = post_incident(
            State(state),
            dev_scope_headers("facts:write"),
            Json(create_body("", "t")),
        )
        .await;
        assert_eq!(validated.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn list_incidents_requires_a_read_scope() {
        let _flag = FeatureFlag::on();
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let query = || {
            Query(ListIncidentsQuery {
                tenant_id: "tenant-a".to_string(),
            })
        };

        let anonymous = list_incidents(State(state.clone()), HeaderMap::new(), query()).await;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

        let write_only = list_incidents(State(state.clone()), dev_scope_headers("facts:write"), query()).await;
        assert_eq!(
            write_only.status(),
            StatusCode::FORBIDDEN,
            "a write scope must not grant reads"
        );

        for scope in ["query:read", "admin:read"] {
            let allowed = list_incidents(State(state.clone()), dev_scope_headers(scope), query()).await;
            assert_eq!(allowed.status(), StatusCode::OK, "scope {scope}");
        }
    }

    /// PINS CURRENT BEHAVIOUR: `get_incident` resolves the case BEFORE the
    /// D-27 (inverted pin): the lookup used to run BEFORE any scope check, so
    /// an unauthenticated caller could distinguish an unknown id (404) from an
    /// existing one (401) — a case-id enumeration oracle. The read scope is
    /// now required first, tenant-agnostically.
    /// D-27, second half: a caller who IS authenticated, but scoped to a
    /// different tenant, could still tell an existing case (403) from an absent
    /// one (404). To that caller the two are the same thing, so both report
    /// 404. Needs `jwt_hs256` — `dev_scopes` grants `TenantAllow::Any`, so a
    /// tenant restriction is not expressible there.
    #[tokio::test]
    #[serial_test::serial]
    async fn get_incident_hides_another_tenants_case_behind_404() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        const TEST_HS256_SECRET: &str = "0123456789abcdef0123456789abcdef";

        let _flag = FeatureFlag::on();
        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");

        let state = super::tests::test_app_state_with_auth(16, crate::auth::AuthMode::JwtHs256);
        let id = {
            let mut store = state.fact_store.write().await;
            let case = bare_case("inc_other", "tenant-b", "t", Utc::now());
            store_case(&mut store, &case);
            case.id
        };

        let bearer_for = |tenant: &str| {
            let claims = serde_json::json!({
                "exp": (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600),
                "iss": "corecrux-test",
                "aud": "corecrux",
                "scope": "query:read",
                "tenant_id": tenant,
            });
            let token = encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
            )
            .expect("jwt");
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {token}").parse().expect("header"),
            );
            headers
        };

        // Authenticated, but scoped to tenant-a only.
        let outsider = bearer_for("tenant-a");
        let existing = get_incident(State(state.clone()), outsider.clone(), AxumPath(id.clone())).await;
        let absent = get_incident(State(state.clone()), outsider, AxumPath("inc_absent".to_string())).await;
        assert_eq!(existing.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            existing.status(),
            absent.status(),
            "another tenant's case is indistinguishable from one that does not exist"
        );

        // Control: the owning tenant still reads it.
        let owner = get_incident(State(state), bearer_for("tenant-b"), AxumPath(id)).await;
        assert_eq!(owner.status(), StatusCode::OK);

        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
        std::env::remove_var("CORECRUXD_JWT_ISS");
        std::env::remove_var("CORECRUXD_JWT_AUD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn get_incident_does_not_reveal_existence_before_authenticating() {
        let _flag = FeatureFlag::on();
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let id = {
            let mut store = state.fact_store.write().await;
            let case = bare_case("inc_exists", "tenant-a", "t", Utc::now());
            store_case(&mut store, &case);
            case.id
        };

        let unknown = get_incident(
            State(state.clone()),
            HeaderMap::new(),
            AxumPath("inc_absent".to_string()),
        )
        .await;
        let existing = get_incident(State(state.clone()), HeaderMap::new(), AxumPath(id.clone())).await;
        assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            existing.status(),
            unknown.status(),
            "an absent id and an existing one are indistinguishable without a credential"
        );

        let authorised = get_incident(
            State(state.clone()),
            dev_scope_headers("query:read"),
            AxumPath(id.clone()),
        )
        .await;
        assert_eq!(authorised.status(), StatusCode::OK);

        let wrong_scope = get_incident(State(state), dev_scope_headers("facts:write"), AxumPath(id)).await;
        assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);
    }

    // ── Export ────────────────────────────────────────────────────────────

    /// The export must be a download-shaped response carrying the key class,
    /// and its body must verify with the unmodified offline audit verifier.
    #[tokio::test]
    #[serial_test::serial]
    async fn export_incident_returns_an_offline_verifiable_bundle() {
        let _flag = FeatureFlag::on();
        let state = test_app_state(16);
        let id = create_case(&state, "tenant-a", "Exportable").await;

        let response = export_incident(State(state), HeaderMap::new(), AxumPath(id.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers().clone();
        assert_eq!(
            headers.get(header::CONTENT_TYPE).expect("content-type"),
            "application/zstd"
        );
        let disposition = headers
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .expect("content-disposition");
        assert_eq!(
            disposition,
            format!("attachment; filename=\"incident-bundle-{id}.tar.zst\"")
        );
        assert!(headers.get("x-crux-audit-key-class").is_some(), "key class advertised");

        let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
            .await
            .expect("read bundle");
        let report = corecrux_receipts::verify_bundle_v1(&bytes).expect("offline verify");
        assert!(report.ok, "exported bundle must verify offline: {report:?}");
        assert!(report.fact_count >= 1, "the case itself is in the event stream");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn export_incident_requires_a_read_or_export_scope() {
        let _flag = FeatureFlag::on();
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let id = {
            let mut store = state.fact_store.write().await;
            let case = bare_case("inc_export_auth", "tenant-a", "t", Utc::now());
            store_case(&mut store, &case);
            case.id
        };

        let anonymous = export_incident(State(state.clone()), HeaderMap::new(), AxumPath(id.clone())).await;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

        let wrong_scope = export_incident(
            State(state.clone()),
            dev_scope_headers("facts:write"),
            AxumPath(id.clone()),
        )
        .await;
        assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);

        for scope in ["query:read", "exports:read", "admin:read"] {
            let allowed = export_incident(State(state.clone()), dev_scope_headers(scope), AxumPath(id.clone())).await;
            assert_eq!(allowed.status(), StatusCode::OK, "scope {scope}");
        }
    }
}
