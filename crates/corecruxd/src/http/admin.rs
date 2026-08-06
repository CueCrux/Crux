// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! HTTP handlers for `/v1/admin/*` routes — shard map, restart, valves, force-seal, ops-log, admin-actions.

use super::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AdminActionStatus {
    Submitted,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct AdminActionRecord {
    #[serde(rename = "actionId")]
    pub(crate) action_id: String,
    #[serde(rename = "actionType")]
    pub(crate) action_type: String,
    pub(crate) status: AdminActionStatus,
    #[serde(rename = "submittedAtUnixMs")]
    pub(crate) submitted_at_unix_ms: u64,
    #[serde(rename = "startedAtUnixMs", skip_serializing_if = "Option::is_none")]
    pub(crate) started_at_unix_ms: Option<u64>,
    #[serde(rename = "finishedAtUnixMs", skip_serializing_if = "Option::is_none")]
    pub(crate) finished_at_unix_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) params: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    #[serde(skip)]
    pub(crate) auth_context: Option<EvidenceAuthContextV1>,
    #[serde(skip)]
    pub(crate) request_context: Option<EvidenceRequestContextV1>,
    /// Passport bound by the admin auth layer. Never populated from request JSON.
    #[serde(skip)]
    pub(crate) authenticated_passport: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PostAdminActionRequest {
    #[serde(rename = "actionId")]
    pub(super) action_id: Option<String>,
    #[serde(rename = "actionType")]
    pub(super) action_type: String,
    pub(super) actor: Option<String>,
    pub(super) reason: Option<String>,
    pub(super) params: Option<serde_json::Value>,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct PostAdminActionResponse {
    pub(super) accepted: bool,
    pub(super) action: AdminActionRecord,
}

pub(super) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

pub(super) fn is_known_admin_action(ty: &str) -> bool {
    matches!(
        ty,
        "verify-store"
            | "scrub-now"
            | "snapshot-verify"
            | "projection-rebuild"
            | "parity-pack"
            | "runtime-knob-update"
            | "force-seal"
            | "compact-facts"
    )
}

fn is_safe_admin_action_id(action_id: &str) -> bool {
    !action_id.is_empty()
        && action_id.len() <= 128
        && action_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub(super) fn read_param_str<'a>(params: Option<&'a serde_json::Value>, key: &str) -> Option<&'a str> {
    params
        .and_then(|v| v.get(key))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
}

pub(super) fn read_param_bool(params: Option<&serde_json::Value>, key: &str) -> Option<bool> {
    params.and_then(|v| v.get(key)).and_then(|v| {
        if let Some(b) = v.as_bool() {
            Some(b)
        } else if let Some(s) = v.as_str() {
            match s.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "y" => Some(true),
                "0" | "false" | "no" | "n" => Some(false),
                _ => None,
            }
        } else {
            None
        }
    })
}

pub(super) fn read_param_u64(params: Option<&serde_json::Value>, key: &str) -> Option<u64> {
    params.and_then(|v| v.get(key)).and_then(|v| {
        if let Some(n) = v.as_u64() {
            Some(n)
        } else {
            v.as_str().and_then(|s| s.parse::<u64>().ok())
        }
    })
}

pub(super) fn read_param_u32(params: Option<&serde_json::Value>, key: &str) -> Option<u32> {
    read_param_u64(params, key).and_then(|v| u32::try_from(v).ok())
}

pub(super) fn read_param_f64(params: Option<&serde_json::Value>, key: &str) -> Option<f64> {
    params.and_then(|v| v.get(key)).and_then(|v| {
        if let Some(n) = v.as_f64() {
            Some(n)
        } else {
            v.as_str().and_then(|s| s.parse::<f64>().ok())
        }
    })
}

pub(super) fn parse_tenant_throttle_rules(value: &serde_json::Value) -> Result<Vec<control::TenantThrottleV1>, String> {
    let rules: Vec<control::TenantThrottleV1> = serde_json::from_value(value.clone())
        .map_err(|e| format!("tenantThrottleRules must be an array of tenant throttle objects: {e}"))?;
    for rule in &rules {
        if rule.tenant_id.trim().is_empty() {
            return Err("tenantThrottleRules entries require non-empty tenantId".to_string());
        }
    }
    Ok(rules)
}

pub(super) fn admin_action_error(detail: impl Into<String>) -> String {
    detail.into()
}

pub(super) fn parse_knowledge_authority_mode(value: &str) -> Option<KnowledgeAuthorityModeV1> {
    match value.trim() {
        "knowledge_shadow" | "shadow" => Some(KnowledgeAuthorityModeV1::Shadow),
        "knowledge_dual_write" | "dual_write" => Some(KnowledgeAuthorityModeV1::DualWrite),
        "knowledge_shadow_read" | "shadow_read" => Some(KnowledgeAuthorityModeV1::ShadowRead),
        "knowledge_authoritative" | "authoritative" => Some(KnowledgeAuthorityModeV1::Authoritative),
        _ => None,
    }
}

pub(super) fn parse_knowledge_rollout_stage(value: &str) -> Option<KnowledgeRolloutStageV1> {
    match value.trim() {
        "internal_shadow" | "shadow" => Some(KnowledgeRolloutStageV1::InternalShadow),
        "tenant_validation" => Some(KnowledgeRolloutStageV1::TenantValidation),
        "internal_authority" => Some(KnowledgeRolloutStageV1::InternalAuthority),
        "limited_production_authority" => Some(KnowledgeRolloutStageV1::LimitedProductionAuthority),
        "full_production_authority" => Some(KnowledgeRolloutStageV1::FullProductionAuthority),
        _ => None,
    }
}

pub(super) fn parse_knowledge_parity_status(value: &str) -> Option<KnowledgeParityStatusV1> {
    match value.trim() {
        "unknown" => Some(KnowledgeParityStatusV1::Unknown),
        "pass" => Some(KnowledgeParityStatusV1::Pass),
        "warn" => Some(KnowledgeParityStatusV1::Warn),
        "fail" => Some(KnowledgeParityStatusV1::Fail),
        _ => None,
    }
}

#[derive(Debug)]
pub(super) struct AdminActionExecutionResult {
    pub(super) result: serde_json::Value,
    pub(super) mutation_event_id: Option<String>,
}

pub(super) fn trace_id_from_traceparent(traceparent: Option<&str>) -> Option<String> {
    let traceparent = traceparent?;
    let mut parts = traceparent.split('-');
    let _version = parts.next()?;
    let trace_id = parts.next()?;
    if trace_id.len() == 32 && trace_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(trace_id.to_string())
    } else {
        None
    }
}

pub(super) fn evidence_request_context_from_headers(headers: &HeaderMap) -> EvidenceRequestContextV1 {
    let correlation = CorrelationIds::from_headers(headers);
    EvidenceRequestContextV1 {
        request_id: correlation.request_id,
        trace_id: trace_id_from_traceparent(correlation.traceparent.as_deref()),
        traceparent: correlation.traceparent,
    }
}

pub(super) fn evidence_node_context(state: &AppState) -> EvidenceNodeContextV1 {
    EvidenceNodeContextV1 {
        node_id: state.node_id.clone(),
        build: state.build.clone(),
        http_listen_addr: None,
        grpc_listen_addr: None,
    }
}

pub(super) fn submitted_event_id(action_id: &str) -> String {
    format!("{EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1}:{action_id}")
}

pub(super) fn finished_event_id(action_id: &str, status: &str) -> String {
    format!("{EVT_CONTROL_ADMIN_ACTION_FINISHED_V1}:{action_id}:{status}")
}

pub(super) fn mutation_event_id(action_id: &str, control_after_hash: &str) -> String {
    let hash_prefix = control_after_hash.get(0..16).unwrap_or(control_after_hash);
    format!("{EVT_CONTROL_STATE_MUTATION_V1}:{action_id}:{hash_prefix}")
}

pub(super) fn checkpoint_id(action_id: &str, control_hash: &str) -> String {
    let hash_prefix = control_hash.get(0..16).unwrap_or(control_hash);
    format!("checkpoint:{action_id}:{hash_prefix}")
}

pub(super) fn checkpoint_event_id(checkpoint_id: &str) -> String {
    format!("{EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1}:{checkpoint_id}")
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn append_control_evidence_event<T: serde::Serialize>(
    state: &AppState,
    event_type: &str,
    event_id: String,
    payload: &T,
) -> Result<bool, String> {
    let Some(pool) = state.dataplane_pool.clone() else {
        tracing::warn!(
            event_type = %event_type,
            event_id = %event_id,
            "control evidence skipped because dataplane is disabled"
        );
        return Ok(false);
    };

    let payload_bytes =
        serde_json::to_vec(payload).map_err(|e| format!("failed to serialize control evidence payload: {e}"))?;
    let event = AppendEvent {
        event_id,
        occurred_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        event_type: event_type.to_string(),
        content_type: CONTROL_EVIDENCE_CONTENT_TYPE_V1.to_string(),
        payload: payload_bytes,
    };
    let (_decision, store) = pool
        .store_for_stream("system", "corecrux", "control", None)
        .await
        .map_err(|e| format!("failed to route control evidence append: {e}"))?;
    let store = store.read().await;
    let _ = store
        .append_batch("system", "corecrux", "control", 0, None, &[event])
        .await
        .map_err(|e| format!("failed to append control evidence event: {e}"))?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)] // Evidence event builder — fields map 1:1 to the event schema
pub(super) fn build_admin_action_submitted_event(
    state: &AppState,
    action_id: &str,
    action_type: &str,
    submitted_at_unix_ms: u64,
    actor: Option<String>,
    reason: Option<String>,
    params: Option<serde_json::Value>,
    auth_context: EvidenceAuthContextV1,
    request_context: EvidenceRequestContextV1,
) -> ControlAdminActionSubmittedV1 {
    ControlAdminActionSubmittedV1 {
        schema: EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1.to_string(),
        action_id: action_id.to_string(),
        action_type: action_type.to_string(),
        submitted_at_unix_ms,
        actor,
        reason,
        params,
        auth: auth_context,
        request: request_context,
        node: evidence_node_context(state),
    }
}

#[allow(clippy::too_many_arguments)] // Evidence event builder — fields map 1:1 to the event schema
pub(super) fn build_control_mutation_event(
    state: &AppState,
    action_id: &str,
    mutation_type: &str,
    actor: &str,
    reason: &str,
    auth_context: EvidenceAuthContextV1,
    request_context: EvidenceRequestContextV1,
    before: &control::ControlV1,
    after: &control::ControlV1,
    result: serde_json::Value,
) -> ControlStateMutationV1 {
    ControlStateMutationV1 {
        schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
        action_id: action_id.to_string(),
        mutation_type: mutation_type.to_string(),
        applied_at_unix_ms: now_unix_ms(),
        actor: actor.to_string(),
        reason: reason.to_string(),
        auth: auth_context,
        request: request_context,
        node: evidence_node_context(state),
        control_before: control::control_state_digest_v1(before),
        control_after: control::control_state_digest_v1(after),
        valve_changes: control::valve_changes_v1(before, after),
        knowledge_authority_change: control::knowledge_authority_change_v1(before, after),
        result: Some(result),
    }
}

#[allow(clippy::too_many_arguments)] // Evidence event builder — fields map 1:1 to the event schema
pub(super) fn build_admin_action_finished_event(
    state: &AppState,
    action_id: &str,
    action_type: &str,
    status: &str,
    started_at_unix_ms: Option<u64>,
    finished_at_unix_ms: u64,
    mutation_event_id: Option<String>,
    result: Option<serde_json::Value>,
    error: Option<String>,
) -> ControlAdminActionFinishedV1 {
    ControlAdminActionFinishedV1 {
        schema: EVT_CONTROL_ADMIN_ACTION_FINISHED_V1.to_string(),
        action_id: action_id.to_string(),
        action_type: action_type.to_string(),
        status: status.to_string(),
        started_at_unix_ms,
        finished_at_unix_ms,
        mutation_event_id,
        result,
        error,
        node: evidence_node_context(state),
    }
}

pub(super) fn build_control_checkpoint_materialized_event(
    state: &AppState,
    checkpoint_id: &str,
    control_state: &control::ControlV1,
) -> ControlCheckpointMaterializedV1 {
    let checkpoint_bytes = control::checkpoint_control_bytes_v1(control_state);
    ControlCheckpointMaterializedV1 {
        schema: EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1.to_string(),
        checkpoint_id: checkpoint_id.to_string(),
        materialized_at_unix_ms: now_unix_ms(),
        node: evidence_node_context(state),
        control_state: control::control_state_digest_v1(control_state),
        checkpoint_format: "control.json.pretty.v1".to_string(),
        checkpoint_blake3: blake3::hash(&checkpoint_bytes).to_hex().to_string(),
        checkpoint_size_bytes: checkpoint_bytes.len() as u64,
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn append_control_checkpoint_materialized_event(
    state: &AppState,
    action_id: &str,
    control_state: &control::ControlV1,
) -> Result<(), String> {
    let control_hash = control::control_hash_blake3_hex(control_state);
    let checkpoint_id = checkpoint_id(action_id, &control_hash);
    let payload = build_control_checkpoint_materialized_event(state, &checkpoint_id, control_state);
    append_control_evidence_event(
        state,
        EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1,
        checkpoint_event_id(&checkpoint_id),
        &payload,
    )
    .await?;
    Ok(())
}

pub(super) fn append_control_event_warning(action_id: &str, event_type: &str, err: &str) {
    tracing::warn!(
        action_id = %action_id,
        event_type = %event_type,
        error = %err,
        "failed to append control evidence event"
    );
}

pub(super) fn sync_control_metrics(metrics: &Metrics, control: &control::ControlV1) {
    metrics.set_valve_pause_ingest(control.valves.pause_ingest.enabled);
    metrics.set_valve_pause_compaction(control.valves.pause_compaction.enabled);
    metrics.set_valve_throttle(control.valves.throttle.enabled);
    metrics.set_valve_read_only(control.valves.read_only.enabled);
    metrics.set_valve_emergency_brake(control.valves.emergency_brake.enabled);

    metrics.set_valve_state("pause_ingest", control.valves.pause_ingest.enabled);
    metrics.set_valve_state("pause_compaction", control.valves.pause_compaction.enabled);
    metrics.set_valve_state("throttle", control.valves.throttle.enabled);
    metrics.set_valve_state("read_only", control.valves.read_only.enabled);
    metrics.set_valve_state("emergency_brake", control.valves.emergency_brake.enabled);
    metrics.sync_knowledge_authority(&control.knowledge_authority);
    metrics.set_throttle_ratio(1.0);
}

/// P4/M6 erasure receipt — a **typed** payload carrying counts + a bounded
/// reason-CODE + an opaque operation id ONLY. Deliberately excludes:
/// - the operator's free-text `reason` (unbounded, caller-controlled → could
///   carry PII/erased values; it stays in the local tracing log, never signed);
/// - `facts_retained` (full-store live count → leaks store cardinality); we
///   keep only `facts_dropped` (== erased count) + `retention_marked`.
///
/// Redaction is guaranteed by construction: no field can hold fact content.
#[derive(serde::Serialize)]
struct ErasureReceiptV1<'a> {
    schema: &'a str,
    op: &'a str,
    /// Bounded set: `gdpr_full_tenant_erasure` | `retention_sweep` | `operator_compaction`.
    reason_code: &'a str,
    /// Opaque, server-generated admin-action id — not operator text.
    action_id: &'a str,
    facts_dropped: usize,
    retention_marked: usize,
    retention_days: Option<u32>,
    /// `completed` | `failed` (partial: retention marks applied, compaction failed).
    compaction: &'a str,
    recorded_at: String,
}

fn build_erasure_receipt<'a>(
    facts_dropped: usize,
    retention_marked: usize,
    retention_days: Option<u32>,
    reason_code: &'a str,
    action_id: &'a str,
    compaction: &'a str,
) -> ErasureReceiptV1<'a> {
    ErasureReceiptV1 {
        schema: "crux.erasure_receipt.v1",
        op: "compact_facts",
        reason_code,
        action_id,
        facts_dropped,
        retention_marked,
        retention_days,
        compaction,
        recorded_at: chrono::Utc::now().to_rfc3339(),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn execute_admin_action(
    state: &AppState,
    action_id: &str,
    action_type: &str,
    params: Option<&serde_json::Value>,
    auth_context: Option<&EvidenceAuthContextV1>,
    request_context: Option<&EvidenceRequestContextV1>,
    authenticated_passport: Option<&str>,
) -> Result<AdminActionExecutionResult, String> {
    match action_type {
        "verify-store" => {
            let started = std::time::Instant::now();
            let scope = read_param_str(params, "scope").unwrap_or("recent");
            let mode = read_param_str(params, "mode").unwrap_or("sampled");
            let full = read_param_bool(params, "full")
                .unwrap_or_else(|| mode.eq_ignore_ascii_case("full") || scope.eq_ignore_ascii_case("all"));
            let sample_rate = read_param_f64(params, "sampleRate")
                .or_else(|| read_param_f64(params, "sample_rate"))
                .unwrap_or(if full { 1.0 } else { 0.25 })
                .clamp(0.0, 1.0);
            let budget_bytes = read_param_u64(params, "budgetBytes")
                .or_else(|| read_param_u64(params, "budget_bytes"))
                .unwrap_or(8 * 1024 * 1024) as usize;
            let pool = state
                .dataplane_pool
                .as_ref()
                .ok_or_else(|| admin_action_error("dataplane disabled"))?;
            let summary = pool
                .verify_store_integrity_all(full, sample_rate, budget_bytes, false)
                .await;
            if !summary.ok {
                *state.corruption_detected.write().await = true;
            }
            let mut op_log = StructuredOpLog::new(
                if summary.ok { "info" } else { "warn" },
                "verify_store",
                if summary.ok { "ok" } else { "fail" },
                started.elapsed().as_millis() as u64,
            );
            if !summary.ok {
                op_log.error_code = Some(ErrorCode::SegmentCorrupt.as_str().to_string());
            }
            tracing::info!(
                ts = %op_log.ts,
                level = %op_log.level,
                op = %op_log.op,
                outcome = %op_log.outcome,
                took_ms = op_log.took_ms,
                error_code = ?op_log.error_code,
                "admin verify-store completed"
            );
            Ok(AdminActionExecutionResult {
                result: serde_json::json!({
                "ok": summary.ok,
                "scope": scope,
                "mode": if full { "full" } else { "sampled" },
                "sampleRate": sample_rate,
                "summary": summary
                }),
                mutation_event_id: None,
            })
        }
        "scrub-now" => {
            let started = std::time::Instant::now();
            let scope = read_param_str(params, "scope").map_or_else(|| state.scrub_scope.clone(), ToOwned::to_owned);
            let mode = read_param_str(params, "mode").map_or_else(|| state.scrub_mode.clone(), ToOwned::to_owned);
            let full = read_param_bool(params, "full")
                .unwrap_or_else(|| mode.eq_ignore_ascii_case("full") || scope.eq_ignore_ascii_case("all"));
            let sample_rate = read_param_f64(params, "sampleRate")
                .or_else(|| read_param_f64(params, "sample_rate"))
                .unwrap_or(state.scrub_sample_rate)
                .clamp(0.0, 1.0);
            let budget_bytes = read_param_u64(params, "budgetBytes")
                .or_else(|| read_param_u64(params, "budget_bytes"))
                .unwrap_or(8 * 1024 * 1024) as usize;
            let pool = state
                .dataplane_pool
                .as_ref()
                .ok_or_else(|| admin_action_error("dataplane disabled"))?;
            let summary = pool
                .verify_store_integrity_all(full, sample_rate, budget_bytes, true)
                .await;
            if !summary.ok {
                *state.corruption_detected.write().await = true;
            }
            let mut op_log = StructuredOpLog::new(
                if summary.ok { "info" } else { "warn" },
                "scrub",
                if summary.ok { "ok" } else { "fail" },
                started.elapsed().as_millis() as u64,
            );
            if !summary.ok {
                op_log.error_code = Some(ErrorCode::SegmentCorrupt.as_str().to_string());
            }
            tracing::info!(
                ts = %op_log.ts,
                level = %op_log.level,
                op = %op_log.op,
                outcome = %op_log.outcome,
                took_ms = op_log.took_ms,
                error_code = ?op_log.error_code,
                "admin scrub-now completed"
            );
            Ok(AdminActionExecutionResult {
                result: serde_json::json!({
                "ok": summary.ok,
                "scope": scope,
                "mode": if full { "full" } else { "sampled" },
                "sampleRate": sample_rate,
                "summary": summary
                }),
                mutation_event_id: None,
            })
        }
        "snapshot-verify" => {
            let started = std::time::Instant::now();
            let pool = state
                .dataplane_pool
                .as_ref()
                .ok_or_else(|| admin_action_error("dataplane disabled"))?;
            let issues = pool.projection_snapshot_issues().await;
            let mut op_log = StructuredOpLog::new(
                if issues.is_empty() { "info" } else { "warn" },
                "snapshot_verify",
                if issues.is_empty() { "ok" } else { "fail" },
                started.elapsed().as_millis() as u64,
            );
            if !issues.is_empty() {
                op_log.error_code = Some(ErrorCode::InvalidToc.as_str().to_string());
            }
            tracing::info!(
                ts = %op_log.ts,
                level = %op_log.level,
                op = %op_log.op,
                outcome = %op_log.outcome,
                took_ms = op_log.took_ms,
                error_code = ?op_log.error_code,
                issue_count = issues.len(),
                "admin snapshot-verify completed"
            );
            Ok(AdminActionExecutionResult {
                result: serde_json::json!({
                "ok": issues.is_empty(),
                "issueCount": issues.len(),
                "issues": issues
                }),
                mutation_event_id: None,
            })
        }
        "projection-rebuild" => {
            let max_frames = read_param_u64(params, "maxFrames")
                .or_else(|| read_param_u64(params, "max_frames"))
                .unwrap_or(2048)
                .clamp(1, 65_536) as u32;
            let pool = state
                .dataplane_pool
                .as_ref()
                .ok_or_else(|| admin_action_error("dataplane disabled"))?;
            pool.tick_projections_all(max_frames).await;
            Ok(AdminActionExecutionResult {
                result: serde_json::json!({
                "ok": true,
                "maxFrames": max_frames
                }),
                mutation_event_id: None,
            })
        }
        "runtime-knob-update" => {
            let actor = read_param_str(params, "actor")
                .map_or_else(|| "admin-action-runtime-knob-update".to_string(), ToOwned::to_owned);
            let reason = read_param_str(params, "reason")
                .map_or_else(|| "runtime knob update action".to_string(), ToOwned::to_owned);
            let now = control::now_unix_ns();

            let mut control_state = state.control.write().await;
            let before = control_state.clone();
            let mut changed = false;

            let throttle_enabled =
                read_param_bool(params, "throttleEnabled").or_else(|| read_param_bool(params, "enabled"));
            if let Some(enabled) = throttle_enabled {
                control_state.valves.throttle.set(enabled, &actor, &reason, now);
                changed = true;
            }

            let events_per_sec = read_param_u64(params, "throttleEventsPerSec")
                .or_else(|| read_param_u64(params, "eventsPerSec"))
                .or(control_state.valves.throttle.events_per_sec);
            let bytes_per_sec = read_param_u64(params, "throttleBytesPerSec")
                .or_else(|| read_param_u64(params, "bytesPerSec"))
                .or(control_state.valves.throttle.bytes_per_sec);
            let max_in_flight = read_param_u64(params, "throttleMaxInFlight")
                .or_else(|| read_param_u64(params, "maxInFlight"))
                .and_then(|v| u32::try_from(v).ok())
                .or(control_state.valves.throttle.max_in_flight);
            if events_per_sec != control_state.valves.throttle.events_per_sec
                || bytes_per_sec != control_state.valves.throttle.bytes_per_sec
                || max_in_flight != control_state.valves.throttle.max_in_flight
            {
                control_state
                    .valves
                    .throttle
                    .set_throttle_params(events_per_sec, bytes_per_sec, max_in_flight);
                changed = true;
            }

            let retry_after_ms = read_param_u64(params, "throttleRetryAfterMs")
                .or_else(|| read_param_u64(params, "retryAfterMs"))
                .and_then(|v| u32::try_from(v).ok());
            if retry_after_ms.is_some() {
                control_state.valves.throttle.set_retry_after_ms(retry_after_ms);
                changed = true;
            }

            if let Some(raw_rules) = params
                .and_then(|value| value.get("tenantThrottleRules"))
                .or_else(|| params.and_then(|value| value.get("tenant_throttle_rules")))
            {
                let parsed = parse_tenant_throttle_rules(raw_rules).map_err(admin_action_error)?;
                if control_state.tenant_throttles != parsed {
                    control_state.tenant_throttles = parsed;
                    changed = true;
                }
            }

            let mut knowledge_authority_changed = false;

            if let Some(mode) = read_param_str(params, "knowledgeAuthorityMode")
                .or_else(|| read_param_str(params, "knowledge_authority_mode"))
            {
                let parsed = parse_knowledge_authority_mode(mode)
                    .ok_or_else(|| admin_action_error(format!("invalid knowledgeAuthorityMode '{mode}'")))?;
                if control_state.knowledge_authority.mode != parsed {
                    control_state.knowledge_authority.mode = parsed;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(stage) = read_param_str(params, "knowledgeAuthorityRolloutStage")
                .or_else(|| read_param_str(params, "knowledge_authority_rollout_stage"))
            {
                let parsed = parse_knowledge_rollout_stage(stage)
                    .ok_or_else(|| admin_action_error(format!("invalid knowledgeAuthorityRolloutStage '{stage}'")))?;
                if control_state.knowledge_authority.rollout_stage != parsed {
                    control_state.knowledge_authority.rollout_stage = parsed;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(value) = read_param_u64(params, "knowledgeMaxMismatchCount")
                .or_else(|| read_param_u64(params, "knowledge_max_mismatch_count"))
            {
                if control_state.knowledge_authority.parity_thresholds.max_mismatch_count != value {
                    control_state.knowledge_authority.parity_thresholds.max_mismatch_count = value;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(value) = read_param_u64(params, "knowledgeMaxCursorMissingCount")
                .or_else(|| read_param_u64(params, "knowledge_max_cursor_missing_count"))
            {
                if control_state
                    .knowledge_authority
                    .parity_thresholds
                    .max_cursor_missing_count
                    != value
                {
                    control_state
                        .knowledge_authority
                        .parity_thresholds
                        .max_cursor_missing_count = value;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(value) = read_param_u32(params, "knowledgeMinPassRatioBps")
                .or_else(|| read_param_u32(params, "knowledge_min_pass_ratio_bps"))
            {
                if control_state.knowledge_authority.parity_thresholds.min_pass_ratio_bps != value {
                    control_state.knowledge_authority.parity_thresholds.min_pass_ratio_bps = value;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(value) = read_param_u64(params, "knowledgeMaxProjectionLagMs")
                .or_else(|| read_param_u64(params, "knowledge_max_projection_lag_ms"))
            {
                if control_state.knowledge_authority.lag_thresholds.max_projection_lag_ms != value {
                    control_state.knowledge_authority.lag_thresholds.max_projection_lag_ms = value;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(value) = read_param_u64(params, "knowledgeMaxCursorAgeMs")
                .or_else(|| read_param_u64(params, "knowledge_max_cursor_age_ms"))
            {
                if control_state.knowledge_authority.lag_thresholds.max_cursor_age_ms != value {
                    control_state.knowledge_authority.lag_thresholds.max_cursor_age_ms = value;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(value) = read_param_bool(params, "knowledgeRollbackTriggered")
                .or_else(|| read_param_bool(params, "knowledge_rollback_triggered"))
            {
                if control_state.knowledge_authority.rollback_triggered != value {
                    control_state.knowledge_authority.rollback_triggered = value;
                    knowledge_authority_changed = true;
                }
            }

            if read_param_bool(params, "knowledgeClearParityOutcome")
                .or_else(|| read_param_bool(params, "knowledge_clear_parity_outcome"))
                .unwrap_or(false)
            {
                if control_state.knowledge_authority.last_parity_outcome.is_some() {
                    control_state.knowledge_authority.last_parity_outcome = None;
                    knowledge_authority_changed = true;
                }
            } else {
                let parity_status = read_param_str(params, "knowledgeLastParityStatus")
                    .or_else(|| read_param_str(params, "knowledge_last_parity_status"))
                    .map(|value| {
                        parse_knowledge_parity_status(value)
                            .ok_or_else(|| admin_action_error(format!("invalid knowledgeLastParityStatus '{value}'")))
                    })
                    .transpose()?;
                let parity_checked_at = read_param_u64(params, "knowledgeLastParityCheckedAtUnixMs")
                    .or_else(|| read_param_u64(params, "knowledge_last_parity_checked_at_unix_ms"));
                let parity_mismatch = read_param_u64(params, "knowledgeLastParityMismatchCount")
                    .or_else(|| read_param_u64(params, "knowledge_last_parity_mismatch_count"));
                let parity_cursor_missing = read_param_u64(params, "knowledgeLastParityCursorMissingCount")
                    .or_else(|| read_param_u64(params, "knowledge_last_parity_cursor_missing_count"));
                let parity_pass_ratio = read_param_u32(params, "knowledgeLastParityPassRatioBps")
                    .or_else(|| read_param_u32(params, "knowledge_last_parity_pass_ratio_bps"));
                let parity_lag = read_param_u64(params, "knowledgeLastParityLagMs")
                    .or_else(|| read_param_u64(params, "knowledge_last_parity_lag_ms"));
                let parity_detail = read_param_str(params, "knowledgeLastParityDetail")
                    .or_else(|| read_param_str(params, "knowledge_last_parity_detail"))
                    .map(|value| value.trim().to_string());

                if parity_status.is_some()
                    || parity_checked_at.is_some()
                    || parity_mismatch.is_some()
                    || parity_cursor_missing.is_some()
                    || parity_pass_ratio.is_some()
                    || parity_lag.is_some()
                    || parity_detail.is_some()
                {
                    let mut outcome = control_state.knowledge_authority.last_parity_outcome.clone().unwrap_or(
                        KnowledgeParityOutcomeV1 {
                            status: KnowledgeParityStatusV1::Unknown,
                            checked_at_unix_ms: now_unix_ms(),
                            mismatch_count: 0,
                            cursor_missing_count: 0,
                            pass_ratio_bps: 0,
                            projection_lag_ms: 0,
                            detail: None,
                        },
                    );
                    if let Some(value) = parity_status {
                        outcome.status = value;
                    }
                    if let Some(value) = parity_checked_at {
                        outcome.checked_at_unix_ms = value;
                    }
                    if let Some(value) = parity_mismatch {
                        outcome.mismatch_count = value;
                    }
                    if let Some(value) = parity_cursor_missing {
                        outcome.cursor_missing_count = value;
                    }
                    if let Some(value) = parity_pass_ratio {
                        outcome.pass_ratio_bps = value;
                    }
                    if let Some(value) = parity_lag {
                        outcome.projection_lag_ms = value;
                    }
                    if let Some(value) = parity_detail {
                        outcome.detail = if value.is_empty() { None } else { Some(value) };
                    }
                    if control_state.knowledge_authority.last_parity_outcome.as_ref() != Some(&outcome) {
                        control_state.knowledge_authority.last_parity_outcome = Some(outcome);
                        knowledge_authority_changed = true;
                    }
                }
            }

            if knowledge_authority_changed {
                control_state.knowledge_authority.actor.clone_from(&actor);
                control_state.knowledge_authority.reason.clone_from(&reason);
                control_state.knowledge_authority.updated_at_unix_ns = now;
                changed = true;
            }

            let result = serde_json::json!({
                "ok": true,
                "changed": changed,
                "throttle": {
                    "enabled": control_state.valves.throttle.enabled,
                    "eventsPerSec": control_state.valves.throttle.events_per_sec,
                    "bytesPerSec": control_state.valves.throttle.bytes_per_sec,
                    "maxInFlight": control_state.valves.throttle.max_in_flight,
                    "retryAfterMs": control_state.valves.throttle.retry_after_ms
                },
                "tenantThrottles": control_state.tenant_throttles,
                "knowledgeAuthority": control_state.knowledge_authority
            });

            let mut mutation_event_id_out = None;
            if changed {
                control_state.updated_at_unix_ns = now;
                let after = control_state.clone();
                control::write_control_atomic(&state.control_path, &after).map_err(|e| {
                    *control_state = before.clone();
                    admin_action_error(format!("failed to persist CONTROL.json: {e}"))
                })?;

                let auth_context = auth_context.cloned().unwrap_or(EvidenceAuthContextV1 {
                    mode: state.auth.mode().as_str().to_string(),
                    subject: None,
                    tenant_binding: None,
                    scopes: Vec::new(),
                });
                let request_context = request_context.cloned().unwrap_or_default();
                let next_mutation_event_id = mutation_event_id(action_id, &control::control_hash_blake3_hex(&after));
                let mutation_event = build_control_mutation_event(
                    state,
                    action_id,
                    "runtime_knob_update",
                    &actor,
                    &reason,
                    auth_context,
                    request_context,
                    &before,
                    &after,
                    result.clone(),
                );
                if let Err(err) = append_control_evidence_event(
                    state,
                    EVT_CONTROL_STATE_MUTATION_V1,
                    next_mutation_event_id.clone(),
                    &mutation_event,
                )
                .await
                {
                    *control_state = before.clone();
                    let rollback_err = control::write_control_atomic(&state.control_path, &before).err();
                    let detail = match rollback_err {
                        Some(rollback_err) => {
                            format!("failed to append control evidence event: {err}; rollback failed: {rollback_err}")
                        }
                        None => format!("failed to append control evidence event: {err}"),
                    };
                    return Err(admin_action_error(detail));
                }
                mutation_event_id_out = Some(next_mutation_event_id);
                if let Err(err) = append_control_checkpoint_materialized_event(state, action_id, &after).await {
                    append_control_event_warning(action_id, EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1, &err);
                }
                sync_control_metrics(&state.metrics, &control_state);
            }

            Ok(AdminActionExecutionResult {
                result,
                mutation_event_id: mutation_event_id_out,
            })
        }
        "force-seal" => {
            // Track W / G1: enqueue each freshly-sealed chain head for
            // witnessing. The background submit task drains the queue; enqueue
            // is idempotent and a no-op when witnessing is disabled.
            fn enqueue_sealed_head(
                store: &mut crate::witness_proofs::WitnessProofStore,
                seal: &corecrux_storage::SealResultV1,
            ) {
                if !seal.sealed {
                    return;
                }
                let Some(material) = &seal.seal_receipt else {
                    return;
                };
                let head_hex = hex::encode(material.material_hash());
                if let Err(err) = store.enqueue(head_hex, seal.segment_seq) {
                    tracing::warn!(?err, "witness: failed to enqueue sealed head");
                }
            }

            if !state.admin_force_seal_enabled {
                return Err(admin_action_error(
                    "force-seal is disabled (set CORECRUXD_ADMIN_FORCE_SEAL=1)",
                ));
            }
            let reason = read_param_str(params, "reason")
                .ok_or_else(|| admin_action_error("reason is required for force-seal"))?
                .to_string();
            let wait_proj = read_param_bool(params, "waitForProjection")
                .or_else(|| read_param_bool(params, "wait_for_projection"))
                .unwrap_or(false);
            let max_frames = read_param_u64(params, "maxFrames")
                .or_else(|| read_param_u64(params, "max_frames"))
                .unwrap_or(4096)
                .clamp(1, 65_536) as u32;

            let pool = state
                .dataplane_pool
                .as_ref()
                .ok_or_else(|| admin_action_error("dataplane disabled"))?;

            let started = std::time::Instant::now();

            if wait_proj {
                let results = pool.force_seal_all_and_tick(max_frames).await;
                if state.witness.witness_enabled {
                    let mut store = state.witness_proofs.write().await;
                    for (_, r) in &results {
                        if let Ok(res) = r {
                            enqueue_sealed_head(&mut store, &res.seal_result);
                        }
                    }
                }
                let wait_ms = started.elapsed().as_millis() as u64;
                let shards: Vec<serde_json::Value> = results
                    .into_iter()
                    .map(|(label, r)| match r {
                        Ok(res) => serde_json::json!({
                            "shardId": label,
                            "sealed": res.seal_result.sealed,
                            "segmentSeq": res.seal_result.segment_seq,
                            "frameCount": res.seal_result.frame_count,
                            "cursorBefore": res.cursor_before,
                            "cursorAfter": res.cursor_after,
                            "projectionFramesProcessed": res.projection_frames_processed,
                        }),
                        Err(err) => serde_json::json!({
                            "shardId": label,
                            "error": err,
                        }),
                    })
                    .collect();
                tracing::info!(
                    action_id = %action_id,
                    reason = %reason,
                    wait_proj = wait_proj,
                    wait_ms,
                    shard_count = shards.len(),
                    "admin force-seal completed"
                );
                Ok(AdminActionExecutionResult {
                    result: serde_json::json!({
                        "ok": true,
                        "reason": reason,
                        "waitForProjection": wait_proj,
                        "waitMs": wait_ms,
                        "shards": shards,
                    }),
                    mutation_event_id: None,
                })
            } else {
                let results = pool.force_seal_all().await;
                if state.witness.witness_enabled {
                    let mut store = state.witness_proofs.write().await;
                    for (_, r) in &results {
                        if let Ok(seal) = r {
                            enqueue_sealed_head(&mut store, seal);
                        }
                    }
                }
                let wait_ms = started.elapsed().as_millis() as u64;
                let shards: Vec<serde_json::Value> = results
                    .into_iter()
                    .map(|(label, r)| match r {
                        Ok(seal) => serde_json::json!({
                            "shardId": label,
                            "sealed": seal.sealed,
                            "segmentSeq": seal.segment_seq,
                            "frameCount": seal.frame_count,
                        }),
                        Err(err) => serde_json::json!({
                            "shardId": label,
                            "error": err,
                        }),
                    })
                    .collect();
                tracing::info!(
                    action_id = %action_id,
                    reason = %reason,
                    wait_proj = wait_proj,
                    wait_ms,
                    shard_count = shards.len(),
                    "admin force-seal completed"
                );
                Ok(AdminActionExecutionResult {
                    result: serde_json::json!({
                        "ok": true,
                        "reason": reason,
                        "waitForProjection": false,
                        "waitMs": wait_ms,
                        "shards": shards,
                    }),
                    mutation_event_id: None,
                })
            }
        }
        "compact-facts" => {
            // Launch-gate 5.1 (GDPR erasure): hard-delete the content of
            // soft-deleted facts from the on-disk `facts.jsonl` journal. This is
            // a destructive, deliberately-invoked operation — gated behind an
            // explicit `reason` exactly like `force-seal`.
            let reason = read_param_str(params, "reason")
                .ok_or_else(|| admin_action_error("reason is required for compact-facts"))?
                .to_string();

            // Optional retention sweep (W2.E2). Only runs when the operator
            // passes `applyRetention: true` AND `CORECRUXD_RETENTION_DAYS` is
            // set — retention never deletes implicitly.
            let apply_retention = read_param_bool(params, "applyRetention")
                .or_else(|| read_param_bool(params, "apply_retention"))
                .unwrap_or(false);
            // Legal holds block ordinary hard deletion. GDPR/RTBF remains the
            // higher-priority full-tenant primitive, but the override must be
            // explicit (never inferred from free-text reason) and produces a
            // durable signed `legal_hold_overridden` observation receipt.
            let gdpr_full_tenant_erasure = read_param_bool(params, "gdprFullTenantErasure")
                .or_else(|| read_param_bool(params, "gdpr_full_tenant_erasure"))
                .unwrap_or(false);

            let started = std::time::Instant::now();
            let mut retention_marked: Vec<String> = Vec::new();
            let mut retention_days_used: Option<u32> = None;

            // Attribution is security-sensitive: request params may describe an
            // operator, but only the passport bound at authentication is allowed
            // to become an erasure receipt's actor.
            let actor = authenticated_passport
                .map(str::to_string)
                .or_else(|| auth_context.and_then(|context| context.subject.clone()))
                .unwrap_or_else(|| state.passport_fpr.clone());
            // Bounded reason-CODE for the signed receipt (never the free-text reason).
            let reason_code = if gdpr_full_tenant_erasure {
                "gdpr_full_tenant_erasure"
            } else if apply_retention {
                "retention_sweep"
            } else {
                "operator_compaction"
            };

            // Mark-then-compact under a single write lock so the on-disk journal
            // reflects exactly the marks we just made.
            let (report, legal_hold_override_receipt) = {
                let mut store = state.fact_store.write().await;
                let covered = store.deleted_facts_covered_by_legal_holds();
                if !covered.is_empty() && !gdpr_full_tenant_erasure {
                    let hold_ids: std::collections::BTreeSet<&str> = covered
                        .iter()
                        .flat_map(|(_, ids)| ids.iter().map(String::as_str))
                        .collect();
                    return Err(admin_action_error(format!(
                        "hard erasure blocked by active legal hold(s): {}; set gdprFullTenantErasure=true with tenantId only for a full-tenant GDPR erasure",
                        hold_ids.into_iter().collect::<Vec<_>>().join(",")
                    )));
                }
                if apply_retention {
                    match state.retention_days {
                        Some(days) => {
                            let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
                            retention_marked = store.mark_retention_eligible(cutoff);
                            retention_days_used = Some(days);
                        }
                        None => {
                            return Err(admin_action_error(
                                "applyRetention requested but CORECRUXD_RETENTION_DAYS is unset",
                            ));
                        }
                    }
                }
                if covered.is_empty() {
                    match store.compact_journal() {
                        Ok(report) => (report, None),
                        Err(e) => {
                            // The retention soft-deletes (if any) already
                            // happened; don't lose their audit record just
                            // because the follow-on compaction failed. Emit a
                            // partial (compaction=failed) erasure receipt, then
                            // propagate the error.
                            drop(store);
                            super::observations::mint_governance_receipt(
                                state,
                                "__governance__::erasure",
                                &actor,
                                "erasure.compact_facts",
                                &build_erasure_receipt(
                                    0,
                                    retention_marked.len(),
                                    retention_days_used,
                                    reason_code,
                                    action_id,
                                    "failed",
                                ),
                            );
                            return Err(admin_action_error(format!("journal compaction failed: {e}")));
                        }
                    }
                } else {
                    let tenant_id = read_param_str(params, "tenantId")
                        .or_else(|| read_param_str(params, "tenant_id"))
                        .ok_or_else(|| {
                            admin_action_error("tenantId is required when gdprFullTenantErasure overrides a legal hold")
                        })?;
                    let active_holds = store.active_legal_holds();
                    let mut hold_ids: Vec<String> = covered.iter().flat_map(|(_, ids)| ids.iter().cloned()).collect();
                    hold_ids.sort();
                    hold_ids.dedup();
                    let outside_tenant = active_holds
                        .iter()
                        .any(|hold| hold_ids.contains(&hold.hold_id) && hold.tenant_id != tenant_id);
                    if outside_tenant {
                        return Err(admin_action_error(
                            "full-tenant GDPR override cannot cover legal holds belonging to another tenant",
                        ));
                    }
                    let mut fact_ids: Vec<String> = covered.iter().map(|(fact_id, _)| fact_id.clone()).collect();
                    fact_ids.sort();
                    fact_ids.dedup();
                    let override_material = store
                        .record_legal_hold_override(tenant_id, hold_ids, fact_ids, &reason, &actor)
                        .map_err(|err| {
                            admin_action_error(format!("legal-hold override receipt persistence failed: {err}"))
                        })?;
                    drop(store);

                    let receipt_body = super::observations::PostObservationBody {
                        kind: "legal_hold_overridden".to_string(),
                        provider: "corecruxd".to_string(),
                        client_ts: None,
                        payload: serde_json::to_value(&override_material).map_err(|err| {
                            admin_action_error(format!("legal-hold override receipt encode failed: {err}"))
                        })?,
                    };
                    let (signed_receipt, _) = super::observations::append_one_durable(
                        state,
                        "__governance__::legal-holds",
                        &actor,
                        receipt_body,
                        None,
                    )
                    .map_err(|(_, detail)| {
                        admin_action_error(format!("legal-hold override receipt signing failed: {detail}"))
                    })?;

                    let store = state.fact_store.write().await;
                    let report = store
                        .compact_journal_after_legal_hold_override_receipt(&override_material)
                        .map_err(|e| admin_action_error(format!("journal compaction failed: {e}")))?;
                    (report, Some(signed_receipt))
                }
            };

            // P4/M6: signed CROWN erasure receipt — minted on BOTH the ordinary
            // and the legal-hold-override paths (the override's
            // `legal_hold_overridden` receipt is separate authorization
            // evidence; this count-only governance receipt always accompanies
            // it). Records counts + reason-code + opaque action_id ONLY — never
            // erased content or operator free-text. `None` ⇒ receipt PENDING
            // (loud audit debt, never a silent OK); the erasure itself already
            // succeeded and is not rolled back.
            let erasure_receipt_id = super::observations::mint_governance_receipt(
                state,
                "__governance__::erasure",
                &actor,
                "erasure.compact_facts",
                &build_erasure_receipt(
                    report.facts_dropped,
                    retention_marked.len(),
                    retention_days_used,
                    reason_code,
                    action_id,
                    "completed",
                ),
            );
            let receipt_status = if erasure_receipt_id.is_some() {
                "recorded"
            } else {
                "pending"
            };

            let took_ms = started.elapsed().as_millis() as u64;

            // Erasure receipt / audit-trail log line (T.4): records WHAT was
            // removed and WHY, so the compaction is replayable from logs.
            tracing::info!(
                action_id = %action_id,
                op = "erasure.compact_facts",
                reason = %reason,
                facts_dropped = report.facts_dropped,
                facts_retained = report.facts_retained,
                tombstones_kept = report.tombstones_kept,
                retention_marked = retention_marked.len(),
                retention_days = ?retention_days_used,
                legal_hold_overridden = legal_hold_override_receipt.is_some(),
                took_ms,
                "erasure: fact-journal compaction removed deleted content"
            );

            Ok(AdminActionExecutionResult {
                result: serde_json::json!({
                    "ok": true,
                    "reason": reason,
                    "factsDropped": report.facts_dropped,
                    "factsRetained": report.facts_retained,
                    "tombstonesKept": report.tombstones_kept,
                    "retentionMarked": retention_marked.len(),
                    "retentionDays": retention_days_used,
                    "legalHoldOverridden": legal_hold_override_receipt.is_some(),
                    "legalHoldOverrideReceiptRecordId": legal_hold_override_receipt.as_ref().map(|receipt| &receipt.observation_id),
                    "legalHoldOverrideReceipt": legal_hold_override_receipt.as_ref().map(|receipt| &receipt.receipt),
                    "erasureReceiptRecordId": erasure_receipt_id,
                    "receiptStatus": receipt_status,
                    "tookMs": took_ms,
                }),
                mutation_event_id: None,
            })
        }
        "parity-pack" => Err(admin_action_error(
            "parity-pack action is not implemented in corecruxd; run corecruxctl parity-pack",
        )),
        other => Err(admin_action_error(format!("unknown actionType '{other}'"))),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn run_admin_action(state: AppState, action_id: String) {
    let started_at_ms = now_unix_ms();
    let (action_type, params, auth_context, request_context, authenticated_passport) = {
        let mut actions = state.admin_actions.write().await;
        let Some(rec) = actions.get_mut(&action_id) else {
            return;
        };
        if rec.status != AdminActionStatus::Submitted {
            return;
        }
        rec.status = AdminActionStatus::Running;
        rec.started_at_unix_ms = Some(started_at_ms);
        (
            rec.action_type.clone(),
            rec.params.clone(),
            rec.auth_context.clone(),
            rec.request_context.clone(),
            rec.authenticated_passport.clone(),
        )
    };

    let mut start_log = StructuredOpLog::new("info", "admin_action", "start", 0);
    start_log.request_id = Some(action_id.clone());
    tracing::info!(
        ts = %start_log.ts,
        level = %start_log.level,
        op = %start_log.op,
        outcome = %start_log.outcome,
        took_ms = start_log.took_ms,
        request_id = %action_id,
        action_id = %action_id,
        action_type = %action_type,
        "admin action started"
    );

    let timeout = Duration::from_secs(state.action_timeout_secs.max(1));
    let outcome = tokio::time::timeout(
        timeout,
        execute_admin_action(
            &state,
            &action_id,
            &action_type,
            params.as_ref(),
            auth_context.as_ref(),
            request_context.as_ref(),
            authenticated_passport.as_deref(),
        ),
    )
    .await;
    let finished_at = now_unix_ms();
    let took_ms = finished_at.saturating_sub(started_at_ms);

    let mut actions = state.admin_actions.write().await;
    if let Some(rec) = actions.get_mut(&action_id) {
        let finished_payload = match outcome {
            Ok(Ok(execution)) => {
                rec.status = AdminActionStatus::Succeeded;
                rec.result = Some(execution.result.clone());
                rec.error = None;
                let mut end_log = StructuredOpLog::new("info", "admin_action", "ok", took_ms);
                end_log.request_id = Some(action_id.clone());
                tracing::info!(
                    ts = %end_log.ts,
                    level = %end_log.level,
                    op = %end_log.op,
                    outcome = %end_log.outcome,
                    took_ms = end_log.took_ms,
                    request_id = %action_id,
                    action_id = %action_id,
                    action_type = %action_type,
                    "admin action succeeded"
                );
                Some(build_admin_action_finished_event(
                    &state,
                    &action_id,
                    &action_type,
                    "succeeded",
                    Some(started_at_ms),
                    finished_at,
                    execution.mutation_event_id,
                    Some(execution.result),
                    None,
                ))
            }
            Ok(Err(err)) => {
                rec.status = AdminActionStatus::Failed;
                rec.error = Some(err.clone());
                let mut end_log = StructuredOpLog::new("warn", "admin_action", "fail", took_ms);
                end_log.request_id = Some(action_id.clone());
                end_log.error_code = Some(ErrorCode::Internal.as_str().to_string());
                end_log.error_detail = Some(err.clone());
                tracing::warn!(
                    ts = %end_log.ts,
                    level = %end_log.level,
                    op = %end_log.op,
                    outcome = %end_log.outcome,
                    took_ms = end_log.took_ms,
                    request_id = %action_id,
                    error_code = %end_log.error_code.clone().unwrap_or_default(),
                    action_id = %action_id,
                    action_type = %action_type,
                    error = %err,
                    "admin action failed"
                );
                Some(build_admin_action_finished_event(
                    &state,
                    &action_id,
                    &action_type,
                    "failed",
                    Some(started_at_ms),
                    finished_at,
                    None,
                    None,
                    Some(err),
                ))
            }
            Err(_) => {
                let msg = format!("action timed out after {}s", state.action_timeout_secs.max(1));
                rec.status = AdminActionStatus::Failed;
                rec.error = Some(msg.clone());
                let mut end_log = StructuredOpLog::new("warn", "admin_action", "fail", took_ms);
                end_log.request_id = Some(action_id.clone());
                end_log.error_code = Some(ErrorCode::Timeout.as_str().to_string());
                end_log.error_detail = Some(msg.clone());
                tracing::warn!(
                    ts = %end_log.ts,
                    level = %end_log.level,
                    op = %end_log.op,
                    outcome = %end_log.outcome,
                    took_ms = end_log.took_ms,
                    request_id = %action_id,
                    error_code = %end_log.error_code.clone().unwrap_or_default(),
                    action_id = %action_id,
                    action_type = %action_type,
                    error = %msg,
                    "admin action timed out"
                );
                Some(build_admin_action_finished_event(
                    &state,
                    &action_id,
                    &action_type,
                    "failed",
                    Some(started_at_ms),
                    finished_at,
                    None,
                    None,
                    Some(msg),
                ))
            }
        };
        rec.finished_at_unix_ms = Some(finished_at);
        drop(actions);
        if let Some(finished_payload) = finished_payload {
            if let Err(err) = append_control_evidence_event(
                &state,
                EVT_CONTROL_ADMIN_ACTION_FINISHED_V1,
                finished_event_id(&action_id, &finished_payload.status),
                &finished_payload,
            )
            .await
            {
                append_control_event_warning(&action_id, EVT_CONTROL_ADMIN_ACTION_FINISHED_V1, &err);
            }
        }
    }
}

#[tracing::instrument(level = "info", skip(state, headers, req))]
pub(super) async fn post_admin_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PostAdminActionRequest>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let scope_context = match http_scope_context(&state.auth, &headers) {
        Ok(context) => context,
        Err(problem) => return problem.into_response(),
    };
    let authenticated_passport = scope_context
        .passport_id
        .clone()
        .unwrap_or_else(|| state.passport_fpr.clone());

    let action_type = req.action_type.trim();
    if action_type.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "actionType must be non-empty");
    }
    if !is_known_admin_action(action_type) {
        return problem_response(
            StatusCode::BAD_REQUEST,
            format!(
                "unknown actionType '{action_type}' (expected verify-store|scrub-now|snapshot-verify|projection-rebuild|parity-pack|runtime-knob-update|force-seal)"
            ),
        );
    }
    if action_type == "compact-facts" && scope_context.auth_enforced() && !scope_context.has_global_tenant_authority() {
        return problem_response(
            StatusCode::FORBIDDEN,
            "compact-facts requires cross-tenant operator authority",
        );
    }

    let action_id = req
        .action_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or_else(|| format!("act_{}", uuid::Uuid::new_v4()), ToOwned::to_owned);
    if !is_safe_admin_action_id(&action_id) {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "actionId must be 1..=128 ASCII chars from [A-Za-z0-9._-]",
        );
    }

    let mut actions = state.admin_actions.write().await;
    if let Some(existing) = actions.get(&action_id) {
        return (
            StatusCode::ACCEPTED,
            Json(PostAdminActionResponse {
                accepted: true,
                action: existing.clone(),
            }),
        )
            .into_response();
    }

    let pending_count = actions
        .values()
        .filter(|r| matches!(r.status, AdminActionStatus::Submitted | AdminActionStatus::Running))
        .count();
    if pending_count >= state.action_max_pending {
        return problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "operator action queue is full (pending={pending_count}, limit={})",
                state.action_max_pending
            ),
        );
    }

    let action = AdminActionRecord {
        action_id: action_id.clone(),
        action_type: action_type.to_string(),
        status: AdminActionStatus::Submitted,
        submitted_at_unix_ms: now_unix_ms(),
        started_at_unix_ms: None,
        finished_at_unix_ms: None,
        actor: req.actor.filter(|s| !s.trim().is_empty()),
        reason: req.reason.filter(|s| !s.trim().is_empty()),
        params: req.params,
        result: None,
        error: None,
        auth_context: None,
        request_context: None,
        authenticated_passport: Some(authenticated_passport),
    };

    let auth_context = match describe_http_evidence(&state.auth, &headers) {
        Ok(ok) => ok,
        Err(problem) => return problem.into_response(),
    };
    let request_context = evidence_request_context_from_headers(&headers);
    let submitted_event = build_admin_action_submitted_event(
        &state,
        &action_id,
        action_type,
        action.submitted_at_unix_ms,
        action.actor.clone(),
        action.reason.clone(),
        action.params.clone(),
        auth_context.clone(),
        request_context.clone(),
    );
    if let Err(err) = append_control_evidence_event(
        &state,
        EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1,
        submitted_event_id(&action_id),
        &submitted_event,
    )
    .await
    {
        return problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to append control evidence event: {err}"),
        );
    }

    actions.insert(action_id.clone(), action.clone());
    if let Some(rec) = actions.get_mut(&action_id) {
        rec.auth_context = Some(auth_context);
        rec.request_context = Some(request_context);
    }

    let retain_limit = state.action_max_pending.saturating_mul(8).max(256);
    if actions.len() > retain_limit {
        let mut finished: Vec<(String, u64)> = actions
            .iter()
            .filter_map(|(id, rec)| {
                if matches!(rec.status, AdminActionStatus::Succeeded | AdminActionStatus::Failed) {
                    Some((id.clone(), rec.finished_at_unix_ms.unwrap_or(0)))
                } else {
                    None
                }
            })
            .collect();
        finished.sort_by_key(|(_, ts)| *ts);
        let to_remove = actions.len().saturating_sub(retain_limit);
        for (id, _) in finished.into_iter().take(to_remove) {
            actions.remove(&id);
        }
    }
    drop(actions);

    let task_state = state.clone();
    let task_action_id = action_id.clone();
    tokio::spawn(async move {
        run_admin_action(task_state, task_action_id).await;
    });

    (
        StatusCode::ACCEPTED,
        Json(PostAdminActionResponse { accepted: true, action }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%action_id))]
pub(super) async fn get_admin_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(action_id): Path<String>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let actions = state.admin_actions.read().await;
    match actions.get(&action_id) {
        Some(action) => (StatusCode::OK, Json(action.clone())).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("action '{action_id}' not found")),
    }
}

#[tracing::instrument(level = "info", skip(state, headers))]
pub(super) async fn get_shard_map(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    #[derive(serde::Serialize)]
    struct Resp {
        #[serde(rename = "shardMap")]
        shard_map: ShardMapV1,
        #[serde(rename = "currentVersion")]
        current_version: u64,
        blake3: String,
    }

    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let routing = state.routing.read().await.clone();
    let map = routing.shard_map.clone();
    (
        StatusCode::OK,
        Json(Resp {
            shard_map: map.clone(),
            current_version: map.version,
            blake3: map.blake3,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers, _body))]
pub(super) async fn post_shard_map(
    State(state): State<AppState>,
    headers: HeaderMap,
    _body: axum::body::Bytes,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }

    problem_response(
        StatusCode::NOT_IMPLEMENTED,
        "Phase 3: shard map publishing is CLI-only (use corecruxctl shardmap publish)",
    )
}

#[tracing::instrument(level = "info", skip(state, headers))]
pub(super) async fn get_control(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let c = state.control.read().await.clone();
    (StatusCode::OK, Json(c)).into_response()
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(super) struct OpsLogQuery {
    #[serde(rename = "nodeId")]
    pub(super) node_id: Option<String>,
    pub(super) since: Option<String>,
    pub(super) until: Option<String>,
    #[serde(rename = "fromSeq")]
    pub(super) from_seq: Option<u64>,
    #[serde(rename = "maxEvents")]
    pub(super) max_events: Option<u32>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct OpsLogEvent {
    pub(super) seq: u64,
    #[serde(rename = "eventId")]
    pub(super) event_id: String,
    #[serde(rename = "eventType")]
    pub(super) event_type: String,
    #[serde(rename = "occurredAt")]
    pub(super) occurred_at: String,
    #[serde(rename = "ingestedAt")]
    pub(super) ingested_at: String,
    pub(super) payload: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct OpsLogResponse {
    #[serde(rename = "nodeId")]
    pub(super) node_id: String,
    pub(super) events: Vec<OpsLogEvent>,
}

#[tracing::instrument(level = "info", skip(state, headers))]
pub(super) async fn get_ops_log(
    State(state): State<AppState>,
    Query(query): Query<OpsLogQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::PRECONDITION_FAILED, "ops log unavailable without dataplane");
    };

    let node_id = query.node_id.unwrap_or_else(|| state.node_id.clone());
    let max_events = query.max_events.unwrap_or(256).clamp(1, 4096);
    let batch_size = max_events.min(256);
    let (_decision, store) = match pool.store_for_stream("system", "__ops__", &node_id, None).await {
        Ok(value) => value,
        Err(err) => {
            return problem_response(
                StatusCode::PRECONDITION_FAILED,
                format!("failed to route ops log stream: {err}"),
            )
        }
    };
    let store = store.read().await;

    let mut from_seq = query.from_seq.unwrap_or(0);
    let mut events = Vec::new();
    while (events.len() as u32) < max_events {
        let batch = match store
            .read_stream("system", "__ops__", &node_id, from_seq, batch_size, None)
            .await
        {
            Ok(value) => value,
            Err(err) => {
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to read ops log stream: {err}"),
                )
            }
        };
        if batch.is_empty() {
            break;
        }

        let mut exhausted = false;
        for event in batch {
            from_seq = event.seq.saturating_add(1);
            if query
                .since
                .as_deref()
                .is_some_and(|since| event.occurred_at.as_str() < since)
            {
                continue;
            }
            if query
                .until
                .as_deref()
                .is_some_and(|until| event.occurred_at.as_str() > until)
            {
                exhausted = true;
                break;
            }
            events.push(OpsLogEvent {
                seq: event.seq,
                event_id: event.event_id,
                event_type: event.event_type,
                occurred_at: event.occurred_at,
                ingested_at: event.ingested_at,
                payload: serde_json::from_slice(&event.payload).unwrap_or_else(|_| {
                    serde_json::json!({
                        "decodeError": "payload was not valid JSON"
                    })
                }),
            });
            if (events.len() as u32) >= max_events {
                exhausted = true;
                break;
            }
        }

        if exhausted {
            break;
        }
    }

    (StatusCode::OK, Json(OpsLogResponse { node_id, events })).into_response()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct SetThrottle {
    pub(super) enabled: bool,
    #[serde(rename = "retryAfterMs")]
    pub(super) retry_after_ms: Option<u32>,
    #[serde(rename = "eventsPerSec")]
    pub(super) events_per_sec: Option<u64>,
    #[serde(rename = "bytesPerSec")]
    pub(super) bytes_per_sec: Option<u64>,
    #[serde(rename = "maxInFlight")]
    pub(super) max_in_flight: Option<u32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct SetValvesReq {
    pub(super) actor: String,
    pub(super) reason: String,
    #[serde(rename = "pauseIngest")]
    pub(super) pause_ingest: Option<bool>,
    #[serde(rename = "pauseCompaction")]
    pub(super) pause_compaction: Option<bool>,
    pub(super) throttle: Option<SetThrottle>,
    #[serde(rename = "readOnly")]
    pub(super) read_only: Option<bool>,
    #[serde(rename = "emergencyBrake")]
    pub(super) emergency_brake: Option<bool>,
}

#[tracing::instrument(level = "info", skip(state, headers, req))]
pub(super) async fn post_valves(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SetValvesReq>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }

    if req.actor.trim().is_empty() || req.reason.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "actor and reason must be non-empty");
    }

    let auth_context = match describe_http_evidence(&state.auth, &headers) {
        Ok(ok) => ok,
        Err(problem) => return problem.into_response(),
    };
    let request_context = evidence_request_context_from_headers(&headers);
    let action_id = format!("valves_{}", uuid::Uuid::new_v4());
    let submitted_at_unix_ms = now_unix_ms();
    let submitted_event = build_admin_action_submitted_event(
        &state,
        &action_id,
        "set_valves",
        submitted_at_unix_ms,
        Some(req.actor.clone()),
        Some(req.reason.clone()),
        serde_json::to_value(&req).ok(),
        auth_context.clone(),
        request_context.clone(),
    );
    if let Err(err) = append_control_evidence_event(
        &state,
        EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1,
        submitted_event_id(&action_id),
        &submitted_event,
    )
    .await
    {
        return problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to append control evidence event: {err}"),
        );
    }

    let now = control::now_unix_ns();
    let mut c = state.control.write().await;
    let before = c.clone();
    let prev_emergency_brake = c.valves.emergency_brake.enabled;
    let mut changed = false;
    let mut mutation_event_id_out = None;

    if let Some(v) = req.pause_ingest {
        c.valves.pause_ingest.set(v, &req.actor, &req.reason, now);
        changed = true;
    }
    if let Some(v) = req.pause_compaction {
        c.valves.pause_compaction.set(v, &req.actor, &req.reason, now);
        changed = true;
    }
    if let Some(t) = req.throttle {
        c.valves.throttle.set(t.enabled, &req.actor, &req.reason, now);
        c.valves.throttle.set_retry_after_ms(t.retry_after_ms);
        let events_per_sec = t.events_per_sec.or(c.valves.throttle.events_per_sec);
        let bytes_per_sec = t.bytes_per_sec.or(c.valves.throttle.bytes_per_sec);
        let max_in_flight = t.max_in_flight.or(c.valves.throttle.max_in_flight);
        c.valves
            .throttle
            .set_throttle_params(events_per_sec, bytes_per_sec, max_in_flight);
        changed = true;
    }
    if let Some(v) = req.read_only {
        c.valves.read_only.set(v, &req.actor, &req.reason, now);
        changed = true;
    }
    if let Some(v) = req.emergency_brake {
        c.valves.emergency_brake.set(v, &req.actor, &req.reason, now);
        if v {
            // Emergency brake implies an immediate non-mutating posture.
            c.valves.read_only.set(true, &req.actor, &req.reason, now);
            c.valves.pause_ingest.set(true, &req.actor, &req.reason, now);
            c.valves.pause_compaction.set(true, &req.actor, &req.reason, now);
        }
        changed = true;
    }

    if changed {
        c.updated_at_unix_ns = now;
        let after = c.clone();
        if let Err(err) = control::write_control_atomic(&state.control_path, &after) {
            *c = before;
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to persist CONTROL.json: {err}"),
            );
        }

        let next_mutation_event_id = mutation_event_id(&action_id, &control::control_hash_blake3_hex(&after));
        let mutation_event = build_control_mutation_event(
            &state,
            &action_id,
            "set_valves",
            &req.actor,
            &req.reason,
            auth_context.clone(),
            request_context.clone(),
            &before,
            &after,
            serde_json::to_value(&after).unwrap_or_else(|_| serde_json::json!({ "ok": true })),
        );
        if let Err(err) = append_control_evidence_event(
            &state,
            EVT_CONTROL_STATE_MUTATION_V1,
            next_mutation_event_id.clone(),
            &mutation_event,
        )
        .await
        {
            *c = before.clone();
            let rollback_err = control::write_control_atomic(&state.control_path, &before).err();
            let detail = match rollback_err {
                Some(rollback_err) => {
                    format!("failed to append control evidence event: {err}; rollback failed: {rollback_err}")
                }
                None => format!("failed to append control evidence event: {err}"),
            };
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, detail);
        }
        mutation_event_id_out = Some(next_mutation_event_id);
        if let Err(err) = append_control_checkpoint_materialized_event(&state, &action_id, &after).await {
            append_control_event_warning(&action_id, EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1, &err);
        }

        sync_control_metrics(&state.metrics, &c);

        if !prev_emergency_brake && req.emergency_brake == Some(true) && c.valves.emergency_brake.enabled {
            state.metrics.inc_emergency_brake("admin_http");
            tracing::error!(
                actor = %req.actor,
                reason = %req.reason,
                updated_at_unix_ns = now,
                "emergency brake enabled"
            );
        }
    }

    let finished_event = build_admin_action_finished_event(
        &state,
        &action_id,
        "set_valves",
        "succeeded",
        Some(submitted_at_unix_ms),
        now_unix_ms(),
        mutation_event_id_out,
        Some(serde_json::to_value(c.clone()).unwrap_or_else(|_| serde_json::json!({}))),
        None,
    );
    if let Err(err) = append_control_evidence_event(
        &state,
        EVT_CONTROL_ADMIN_ACTION_FINISHED_V1,
        finished_event_id(&action_id, "succeeded"),
        &finished_event,
    )
    .await
    {
        append_control_event_warning(&action_id, EVT_CONTROL_ADMIN_ACTION_FINISHED_V1, &err);
    }

    (StatusCode::OK, Json(c.clone())).into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct StreamMetaReq {
    #[serde(rename = "tenantId")]
    pub(super) tenant_id: String,
    #[serde(rename = "streamType")]
    pub(super) stream_type: String,
    #[serde(rename = "streamId")]
    pub(super) stream_id: String,
    #[serde(rename = "minLiveSeq")]
    pub(super) min_live_seq: Option<u64>,
    #[serde(rename = "tombstoneSeq")]
    pub(super) tombstone_seq: Option<u64>,
    pub(super) actor: String,
    pub(super) reason: String,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ReplicationSegmentReq {
    #[serde(rename = "shardId")]
    pub(super) shard_id: String,
    pub(super) epoch: u64,
    #[serde(rename = "leaderNodeId")]
    pub(super) leader_node_id: Option<String>,
    #[serde(rename = "segmentBase64")]
    pub(super) segment_base64: String,
    #[serde(rename = "segmentHash")]
    pub(super) segment_hash: Option<String>,
}

#[tracing::instrument(level = "info", skip(state, headers, req), fields(shard_id))]
pub(super) async fn post_replication_segment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ReplicationSegmentReq>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["replication:write"]) {
        state.metrics.inc_replication_receive_total("rejected");
        return problem.into_response();
    }

    if req.shard_id.trim().is_empty() {
        state.metrics.inc_replication_receive_total("rejected");
        return problem_response(StatusCode::BAD_REQUEST, "shardId must be non-empty");
    }
    if req.segment_base64.trim().is_empty() {
        state.metrics.inc_replication_receive_total("rejected");
        return problem_response(StatusCode::BAD_REQUEST, "segmentBase64 must be non-empty");
    }

    let segment_bytes = match base64::engine::general_purpose::STANDARD.decode(&req.segment_base64) {
        Ok(v) => v,
        Err(e) => {
            state.metrics.inc_replication_receive_total("rejected");
            return problem_response(StatusCode::BAD_REQUEST, format!("segmentBase64 decode failed: {e}"));
        }
    };
    if segment_bytes.len() > 512 * 1024 * 1024 {
        state.metrics.inc_replication_receive_total("rejected");
        return problem_response(StatusCode::PAYLOAD_TOO_LARGE, "segment payload exceeds 512MiB limit");
    }
    if let Some(expected_hash) = req.segment_hash.as_ref() {
        let expected = expected_hash.trim().to_ascii_lowercase();
        if expected.len() != 64 || !expected.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
            state.metrics.inc_replication_receive_total("rejected");
            return problem_response(StatusCode::BAD_REQUEST, "segmentHash must be 64 lowercase hex chars");
        }
        let actual = hex32(blake3::hash(&segment_bytes).as_bytes());
        if actual != expected {
            state.metrics.inc_replication_receive_total("rejected");
            return problem_response(
                StatusCode::PRECONDITION_FAILED,
                serde_json::json!({
                    "code": "REPLICATION_SEGMENT_HASH_MISMATCH",
                    "expectedSegmentHash": expected,
                    "actualSegmentHash": actual
                })
                .to_string(),
            );
        }
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        state.metrics.inc_replication_receive_total("error");
        return problem_response(
            StatusCode::NOT_IMPLEMENTED,
            "replication receiver requires the proprietary edition",
        );
    };

    let (routing_epoch, owner_gpu_id, store) = match pool.store_for_replication_shard(&req.shard_id).await {
        Ok(v) => v,
        Err(err) => {
            state.metrics.inc_replication_receive_total("rejected");
            return map_store_error_http(err).into_response();
        }
    };
    if routing_epoch != req.epoch {
        state.metrics.inc_replication_receive_total("rejected");
        return problem_response(
            StatusCode::PRECONDITION_FAILED,
            serde_json::json!({
                "code": "REPLICATION_EPOCH_MISMATCH",
                "shardId": req.shard_id,
                "routingEpoch": routing_epoch,
                "requestEpoch": req.epoch
            })
            .to_string(),
        );
    }

    let store = store.read().await;
    let applied = match store
        .apply_replicated_segment(&req.shard_id, req.epoch, &segment_bytes)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            state.metrics.inc_replication_receive_total("error");
            return map_store_error_http(err).into_response();
        }
    };

    if applied.applied {
        state.metrics.inc_replication_receive_total("applied");
    } else {
        state.metrics.inc_replication_receive_total("duplicate");
    }
    state
        .metrics
        .set_replication_follower_watermark(&applied.shard_id, applied.segment_seq);
    pool.update_follower_watermark(&applied.shard_id, applied.segment_seq)
        .await;

    #[derive(serde::Serialize)]
    struct Resp<'a> {
        ok: bool,
        #[serde(rename = "leaderNodeId", skip_serializing_if = "Option::is_none")]
        leader_node_id: Option<&'a str>,
        #[serde(rename = "ownerGpuId")]
        owner_gpu_id: i32,
        result: crate::dataplane_store::ReplicationApplyResult,
    }
    (
        StatusCode::OK,
        Json(Resp {
            ok: true,
            leader_node_id: req.leader_node_id.as_deref(),
            owner_gpu_id,
            result: applied,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers, req))]
pub(super) async fn post_stream_meta(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<StreamMetaReq>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }

    if req.actor.trim().is_empty() || req.reason.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "actor and reason must be non-empty");
    }

    let decision = {
        let c = state.control.read().await.clone();
        ValveDecision::from_control(&c)
    };
    if !decision.allow_storage_writes {
        return problem_response(StatusCode::SERVICE_UNAVAILABLE, "storage writes are disabled by valves");
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(
            StatusCode::NOT_IMPLEMENTED,
            "stream-meta requires the proprietary edition",
        );
    };

    let (_rd, store) = match pool
        .store_for_stream(&req.tenant_id, &req.stream_type, &req.stream_id, None)
        .await
    {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let mut store = store.write().await;
    let res = store
        .update_stream_meta(
            &req.tenant_id,
            &req.stream_type,
            &req.stream_id,
            req.min_live_seq.unwrap_or(0),
            req.tombstone_seq.unwrap_or(0),
        )
        .await;
    match res {
        Ok((min_live_seq, tombstone_seq)) => {
            #[derive(serde::Serialize)]
            struct Resp {
                #[serde(rename = "minLiveSeq")]
                min_live_seq: u64,
                #[serde(rename = "tombstoneSeq")]
                tombstone_seq: u64,
            }
            (
                StatusCode::OK,
                Json(Resp {
                    min_live_seq,
                    tombstone_seq,
                }),
            )
                .into_response()
        }
        Err(err) => map_store_error_http(err).into_response(),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_replication_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    #[derive(serde::Serialize)]
    struct ReplicatedCommitObsResp {
        #[serde(rename = "requiredAcks")]
        required_acks: usize,
        #[serde(rename = "actualAcks")]
        actual_acks: usize,
        #[serde(rename = "ackDeficit")]
        ack_deficit: usize,
        #[serde(rename = "followerCount")]
        follower_count: usize,
        #[serde(rename = "leaderSegmentSeq")]
        leader_segment_seq: u64,
        #[serde(rename = "minFollowerAckedSegmentSeq")]
        min_follower_acked_segment_seq: u64,
        #[serde(rename = "lagSegments")]
        lag_segments: u64,
        result: String,
        #[serde(rename = "failureCount")]
        failure_count: usize,
        #[serde(rename = "failureSample", skip_serializing_if = "Option::is_none")]
        failure_sample: Option<String>,
        #[serde(rename = "observedUnixMs")]
        observed_unix_ms: u64,
    }

    #[derive(serde::Serialize)]
    struct ShardReplicationStatus {
        #[serde(rename = "shardId")]
        shard_id: String,
        epoch: u64,
        state: corecrux_types::ShardState,
        role: String,
        #[serde(rename = "leaderNodeId")]
        leader_node_id: String,
        #[serde(rename = "followerTargets")]
        follower_targets: usize,
        #[serde(rename = "topologyOk")]
        topology_ok: bool,
        #[serde(rename = "localFollowerWatermarkSegmentSeq", skip_serializing_if = "Option::is_none")]
        local_follower_watermark_segment_seq: Option<u64>,
        #[serde(rename = "replicatedCommit", skip_serializing_if = "Option::is_none")]
        replicated_commit: Option<ReplicatedCommitObsResp>,
    }

    #[derive(serde::Serialize)]
    struct Resp {
        #[serde(rename = "nodeId")]
        node_id: String,
        #[serde(rename = "commitLevel")]
        commit_level: String,
        #[serde(rename = "shardMapVersion")]
        shard_map_version: u64,
        #[serde(rename = "localLeaderShards")]
        local_leader_shards: usize,
        #[serde(rename = "topologyMissingFollowers")]
        topology_missing_followers: usize,
        #[serde(rename = "maxLagSegments")]
        max_lag_segments: u64,
        shards: Vec<ShardReplicationStatus>,
    }

    let routing = state.routing.read().await.clone();
    let (follower_watermarks, observations) = if let Some(pool) = state.dataplane_pool.as_ref() {
        (
            pool.follower_watermarks_snapshot().await,
            pool.replicated_commit_observations_snapshot().await,
        )
    } else {
        (std::collections::HashMap::new(), std::collections::HashMap::new())
    };

    let mut local_leader_shards: usize = 0;
    let mut topology_missing_followers: usize = 0;
    let mut max_lag_segments: u64 = 0;
    let mut shards = Vec::with_capacity(routing.shard_map.shards.len());
    for shard in &routing.shard_map.shards {
        let is_leader = shard.leader.node_id == state.node_id;
        let is_follower = shard
            .followers
            .as_ref()
            .is_some_and(|followers| followers.iter().any(|f| f.node_id == state.node_id));

        let role = if is_leader {
            "leader"
        } else if is_follower {
            "follower"
        } else {
            "unassigned"
        };

        let follower_targets = shard.followers.as_ref().map_or(0, |followers| {
            followers.iter().filter(|f| f.node_id != state.node_id).count()
        });
        let topology_ok = follower_targets > 0;
        if is_leader && !matches!(shard.state, corecrux_types::ShardState::Retired) {
            local_leader_shards = local_leader_shards.saturating_add(1);
            if !topology_ok {
                topology_missing_followers = topology_missing_followers.saturating_add(1);
            }
        }

        let local_follower_watermark_segment_seq = follower_watermarks.get(&shard.shard_id).copied();
        let replicated_commit = observations.get(&shard.shard_id).map(|obs| ReplicatedCommitObsResp {
            required_acks: obs.required_acks,
            actual_acks: obs.actual_acks,
            ack_deficit: obs.required_acks.saturating_sub(obs.actual_acks),
            follower_count: obs.follower_count,
            leader_segment_seq: obs.leader_segment_seq,
            min_follower_acked_segment_seq: obs.min_follower_acked_segment_seq,
            lag_segments: obs.lag_segments,
            result: obs.result.clone(),
            failure_count: obs.failure_count,
            failure_sample: obs.failure_sample.clone(),
            observed_unix_ms: obs.observed_unix_ms,
        });
        if let Some(obs) = replicated_commit.as_ref() {
            max_lag_segments = max_lag_segments.max(obs.lag_segments);
        }

        shards.push(ShardReplicationStatus {
            shard_id: shard.shard_id.clone(),
            epoch: shard.epoch,
            state: shard.state,
            role: role.to_string(),
            leader_node_id: shard.leader.node_id.clone(),
            follower_targets,
            topology_ok,
            local_follower_watermark_segment_seq,
            replicated_commit,
        });
    }

    shards.sort_by(|a, b| a.shard_id.cmp(&b.shard_id));
    (
        StatusCode::OK,
        Json(Resp {
            node_id: state.node_id.clone(),
            commit_level: state.commit_level.as_str().to_string(),
            shard_map_version: routing.current_version(),
            local_leader_shards,
            topology_missing_followers,
            max_lag_segments,
            shards,
        }),
    )
        .into_response()
}

/// `GET /v1/admin/segments/fingerprints` — CoreCrux v6 compatibility
/// posture for the local CPU-only retrieval index. The community daemon does
/// not currently enforce v6 fingerprint guard or calibration metadata, so this
/// route reports the local BM25/.ccxi state and names the missing pieces
/// explicitly instead of pretending parity.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_segment_fingerprints(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let (segment_count, total_docs, tier_stats) = {
        let index = state.retrieval_index.read().await;
        (index.segment_count(), index.total_docs(), index.tier_stats())
    };
    let semantic_profile = state.fact_store.read().await.semantic_profile();
    let semantic_profile_id = semantic_profile.as_ref().map(|profile| profile.profile_id.clone());
    let embedding_fingerprint = semantic_profile
        .as_ref()
        .map(|profile| profile.embedding_fingerprint.clone());

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": "crux.admin.segment_fingerprints.v1",
            "contract": "corecrux.retrieval.v6.fingerprinted_segments",
            "status": "partial",
            "cpu_only": true,
            "segments": {
                "count": segment_count,
                "total_docs": total_docs,
                "tier_stats": {
                    "hot_segments": tier_stats.hot_segments,
                    "hot_docs": tier_stats.hot_docs,
                    "hot_bytes": tier_stats.hot_bytes,
                    "warm_segments": tier_stats.warm_segments,
                    "warm_docs": tier_stats.warm_docs,
                    "warm_bytes": tier_stats.warm_bytes,
                    "cold_segments": tier_stats.cold_segments,
                    "hot_budget_bytes": tier_stats.hot_budget_bytes,
                }
            },
            "semantic_profile_id": semantic_profile_id,
            "semantic_profile": semantic_profile,
            "embedding_fingerprint": embedding_fingerprint,
            "fingerprint_guard": {
                "mode": "not_enforced",
                "warnings": [
                    "local daemon has no v6 segment fingerprint records yet",
                    "mixed semantic-profile retrieval must use rank fusion or rerank, not raw cosine comparison"
                ]
            },
            "calibration": {
                "available": false,
                "hash": null,
                "vector_metadata": null
            },
            "warnings": [
                "BM25 .ccxi segment stats are available, but v6 fingerprint parity is not complete",
                "semantic profile IDs are exposed only when an embedding endpoint is configured"
            ]
        })),
    )
        .into_response()
}

/// `GET /v1/admin/sharing/posture` — surface the current privacy gating
/// state: which prefixes are forced-private, share-overrides, fact counts
/// (private vs pushable), and whether remote sync is configured. Used by
/// the AX → Activity "Sharing posture" card.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_sharing_posture(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let snapshot = state.privacy_policy.snapshot();
    let store = state.fact_store.read().await;
    let total_versions = store.count();
    // Walk the latest version of every fact and bucket by privacy. The store
    // returns all versions; dedup to latest per (entity, key) so the rollup
    // reflects the *current* state, not the journal depth.
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: None,
        top_k: 200_000, // walk everything; this is read-only and rare.
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    let total = latest.len();
    let mut private_count = 0usize;
    let mut pushable_count = 0usize;
    let mut would_be_private_after_backfill = 0usize;
    let mut by_prefix: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    for fact in &latest {
        // Bucket by the first `::` segment of the entity so the UI gets a
        // tidy rollup ("__ax__", "github", "personal", etc.).
        let bucket = fact
            .entity
            .split_once("::")
            .map_or_else(|| "(no prefix)".to_string(), |(b, _)| b.to_string());
        let entry = by_prefix.entry(bucket).or_insert((0, 0));
        if fact.private {
            entry.0 += 1;
            private_count += 1;
        } else {
            entry.1 += 1;
            // Would the policy mark this private if we re-stored it?
            if state.privacy_policy.is_always_private(&fact.entity) {
                would_be_private_after_backfill += 1;
            }
            pushable_count += 1;
        }
    }
    let sync_remote_url = std::env::var("CORECRUXD_SYNC_REMOTE_URL").ok();
    let sync_configured = sync_remote_url.as_deref().is_some_and(|s| !s.trim().is_empty());
    drop(store);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "policy": snapshot,
            "facts": {
                "total_count": total,
                "total_versions_in_journal": total_versions,
                "private_count": private_count,
                "pushable_count": pushable_count,
                "would_be_private_after_backfill": would_be_private_after_backfill,
            },
            "sync": {
                "remote_url": sync_remote_url,
                "configured": sync_configured,
                "note": if sync_configured {
                    "Remote sync is configured. `private=true` facts are filtered out by sync_push."
                } else {
                    "Remote sync is unconfigured (CORECRUXD_SYNC_REMOTE_URL is not set). No remote push possible."
                },
            },
            "by_prefix": by_prefix.into_iter().map(|(p, (priv_n, push_n))|
                serde_json::json!({"prefix": p, "private": priv_n, "pushable": push_n})
            ).collect::<Vec<_>>(),
        })),
    )
        .into_response()
}

#[derive(Debug, serde::Deserialize, Default)]
pub(super) struct BackfillBody {
    /// When `true`, actually re-store matching facts with `private=true`.
    /// When `false` (default), preview-only — counts but no writes.
    #[serde(default)]
    pub confirm: bool,
}

/// `POST /v1/admin/sharing/backfill` — sweep the fact store and re-store
/// any non-private fact whose entity matches the policy as `private=true`.
/// Append-only safe: each backfill creates a new fact version; the previous
/// (non-private) version stays in the journal but the latest is private.
/// Default is preview-mode; pass `{confirm: true}` to actually write.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_sharing_backfill(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BackfillBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    // Two passes: first read-only to find candidates, then optionally write.
    let candidates: Vec<corecrux_memory::fact_store::Fact> = {
        let store = state.fact_store.read().await;
        let result = store.query(&corecrux_memory::fact_store::FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            query: None,
            entity: None,
            entity_prefix: None,
            top_k: 100_000,
            token_budget: None,
        });
        let latest = crate::fact_helpers::dedup_latest(result.facts);
        latest
            .into_iter()
            .filter(|f| !f.private && state.privacy_policy.is_always_private(&f.entity))
            .collect()
    };

    if !body.confirm {
        let by_prefix: std::collections::BTreeMap<String, usize> =
            candidates.iter().fold(Default::default(), |mut acc, f| {
                let bucket = f
                    .entity
                    .split_once("::")
                    .map_or_else(|| "(no prefix)".to_string(), |(b, _)| b.to_string());
                *acc.entry(bucket).or_insert(0) += 1;
                acc
            });
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "mode": "preview",
                "would_re_store": candidates.len(),
                "by_prefix": by_prefix.into_iter().map(|(p, n)| serde_json::json!({"prefix": p, "count": n})).collect::<Vec<_>>(),
                "note": "POST again with {\"confirm\": true} to actually re-store these facts as private. Append-only — original versions stay in the journal.",
            })),
        )
            .into_response();
    }

    // Confirmed — re-store each candidate with private=true. This bumps the
    // version for each (entity, key); the previous version stays for audit.
    let mut store = state.fact_store.write().await;
    let mut written = 0usize;
    for fact in &candidates {
        let mut sf = corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: fact.entity.clone(),
            key: fact.key.clone(),
            value: fact.value.clone(),
            source_receipt: fact.source_receipt.clone(),
            confidence: fact.confidence,
            private: true,
            horizon_class: None,
            actor: None,
        };
        crate::fact_privacy::enforce_global(&mut sf); // belt + braces — already true
        store.store(sf);
        written += 1;
    }
    drop(store);
    tracing::warn!(
        target: "corecruxd::admin",
        rewritten = written,
        "sharing-backfill confirmed: re-stored facts as private (append-only; old versions retained)"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "mode": "confirmed",
            "re_stored_count": written,
            "note": "Each fact now has a new private=true version. Previous non-private versions remain in the journal but are superseded.",
        })),
    )
        .into_response()
}

/// Restart the daemon by exiting cleanly. Container orchestrators with a
/// `restart: unless-stopped` (or `always`) policy will bring the process back
/// up; bare-metal / `cargo run` users see the daemon stop and must restart it
/// manually. We schedule the exit on a background task so the HTTP response
/// has time to flush before the process disappears.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_restart_daemon(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    tracing::warn!(target: "corecruxd::admin", "restart requested via /v1/admin/restart");
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        // Exit code 0 = clean shutdown; container restart policy decides what happens next.
        std::process::exit(0);
    });
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": "restarting",
            "note": "process will exit in ~250ms; container restart policy must bring it back up",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod compact_facts_tests {
    use super::*;
    use corecrux_memory::fact_store::{FactStore, StoreFact};

    fn store_fact(value: &str) -> StoreFact {
        StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e".into(),
            key: format!("k-{value}"),
            value: value.into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        }
    }

    #[tokio::test]
    async fn compact_facts_action_scrubs_deleted_content_from_journal() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("facts.jsonl");

        let mut state = crate::http::tests::test_app_state(4);
        // Swap in a journal-backed fact store so compaction has a file to rewrite.
        let mut fs = FactStore::with_persistence(dir.path()).unwrap();
        let deleted = fs.store(store_fact("erase-this-pii"));
        fs.store(store_fact("keep-this"));
        fs.delete("default", &deleted.fact_id);
        state.fact_store = std::sync::Arc::new(tokio::sync::RwLock::new(fs));

        // Pre-condition: deleted value is still on disk (the soft-delete leak).
        assert!(std::fs::read_to_string(&journal).unwrap().contains("erase-this-pii"));

        let params = serde_json::json!({ "reason": "gdpr-erasure-test" });
        let result = execute_admin_action(&state, "act-1", "compact-facts", Some(&params), None, None, None)
            .await
            .expect("compact-facts action succeeds");
        assert_eq!(result.result["factsDropped"], 1);
        assert_eq!(result.result["factsRetained"], 1);

        // Post-condition: deleted value gone; live value survives.
        let raw = std::fs::read_to_string(&journal).unwrap();
        assert!(!raw.contains("erase-this-pii"), "deleted value still in journal");
        assert!(raw.contains("keep-this"));
    }

    /// P4/M6 + review-fix finding 2: the erasure receipt carries a bounded
    /// reason-code + opaque action id + counts ONLY — no operator free-text, no
    /// full-store cardinality, and structurally no fact content.
    #[test]
    fn erasure_receipt_is_content_and_freetext_free() {
        let receipt = build_erasure_receipt(3, 2, Some(90), "gdpr_full_tenant_erasure", "act-xyz", "completed");
        let payload = serde_json::to_value(&receipt).unwrap();
        let s = payload.to_string();
        assert_eq!(payload["facts_dropped"], 3);
        assert_eq!(payload["retention_marked"], 2);
        assert_eq!(payload["retention_days"], 90);
        assert_eq!(payload["reason_code"], "gdpr_full_tenant_erasure");
        assert_eq!(payload["action_id"], "act-xyz");
        assert!(
            payload.get("facts_retained").is_none(),
            "store cardinality must not be exposed"
        );
        assert!(
            payload.get("reason").is_none(),
            "operator free-text reason must not be signed"
        );
        assert!(
            !s.contains("TOPSECRET_ERASED_PAYLOAD"),
            "no erased content in receipt: {s}"
        );
    }

    /// P4/M6 end-to-end: a real compact-facts erasure mints a signed CROWN
    /// receipt, and NO file under the daemon data dir (receipt included) carries
    /// the erased secret value.
    #[tokio::test]
    async fn compact_facts_mints_erasure_receipt_without_leaking_content() {
        const SECRET: &str = "TOPSECRET_ERASED_PAYLOAD_zz9";
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::http::tests::test_app_state_with_auth(4, crate::auth::AuthMode::DevScopes);
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).unwrap();
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();

        let mut fs = FactStore::with_persistence(dir.path()).unwrap();
        let deleted = fs.store(store_fact(SECRET));
        fs.store(store_fact("keep-this"));
        fs.delete("default", &deleted.fact_id);
        state.fact_store = std::sync::Arc::new(tokio::sync::RwLock::new(fs));

        let params = serde_json::json!({ "reason": "gdpr-erasure-test" });
        let result = execute_admin_action(&state, "act-r", "compact-facts", Some(&params), None, None, None)
            .await
            .expect("compact-facts action succeeds");

        // A signed erasure receipt was minted and reported as recorded.
        let receipt_id = result.result["erasureReceiptRecordId"]
            .as_str()
            .expect("erasure receipt minted");
        assert!(!receipt_id.is_empty());
        assert_eq!(result.result["receiptStatus"], "recorded");

        // Sweep the whole daemon data dir: no file (receipt or otherwise) may
        // contain the erased secret OR the operator's free-text reason.
        let mut saw_receipt = false;
        for entry in walk_files(&state.data_dir) {
            let body = std::fs::read_to_string(&entry).unwrap_or_default();
            assert!(!body.contains(SECRET), "erased secret leaked into {}", entry.display());
            assert!(
                !body.contains("gdpr-erasure-test"),
                "operator free-text reason leaked into {}",
                entry.display()
            );
            if body.contains("erasure.compact_facts") {
                saw_receipt = true;
                assert!(body.contains("\"facts_dropped\":1"), "receipt records the drop count");
                assert!(
                    body.contains("\"reason_code\":\"operator_compaction\""),
                    "bounded reason-code present"
                );
            }
        }
        assert!(saw_receipt, "erasure receipt file written under data dir");
    }

    /// Review-fix finding 5 (verifier interop): a minted erasure receipt is
    /// verifiable through the supported observation-signature path — recompute
    /// the canonical body and check the Ed25519 signature against the daemon
    /// passport public key. (Generic dataplane `receipt_verify` indexing of
    /// governance observations is a documented follow-up.)
    #[tokio::test]
    async fn erasure_receipt_verifies_through_observation_signature_path() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::http::tests::test_app_state_with_auth(4, crate::auth::AuthMode::DevScopes);
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).unwrap();
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();

        let mut fs = FactStore::with_persistence(dir.path()).unwrap();
        let d = fs.store(store_fact("verify-me-then-erase"));
        fs.delete("default", &d.fact_id);
        state.fact_store = std::sync::Arc::new(tokio::sync::RwLock::new(fs));

        let params = serde_json::json!({ "reason": "verify-test" });
        execute_admin_action(&state, "act-v", "compact-facts", Some(&params), None, None, None)
            .await
            .expect("compact-facts succeeds");

        // Read the governance erasure observation record back and verify it.
        let file = crate::http::observations::observation_file_path(&state.data_dir, "__governance__::erasure");
        let line = std::fs::read_to_string(&file)
            .unwrap()
            .lines()
            .next_back()
            .expect("one erasure record")
            .to_string();
        let record: crate::http::observations::ObservationRecordV1 = serde_json::from_str(&line).unwrap();
        assert_eq!(record.kind, "erasure.compact_facts");

        // Recompute the canonical body (receipt envelope blanked) and verify the
        // signature against the published passport public key.
        let sig_hex = record.receipt.signature.clone();
        let mut unsigned = record;
        unsigned.receipt = crate::http::observations::ReceiptEnvelopeV1 {
            alg: String::new(),
            signed_by: String::new(),
            body_hash: String::new(),
            signature: String::new(),
        };
        let body = crate::http::observations::canonical_body_bytes(&unsigned).unwrap();
        let hash = blake3::hash(&body);
        let pk = VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(hex::decode(&state.passport_public_key_hex).unwrap().as_slice()).unwrap(),
        )
        .unwrap();
        let sig = Signature::from_slice(&hex::decode(&sig_hex).unwrap()).unwrap();
        pk.verify(hash.as_bytes(), &sig)
            .expect("erasure receipt verifies against passport key");
    }

    /// Depth-first list of regular files under `root` (small test tree).
    fn walk_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(p) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&p) else { continue };
            for e in rd.flatten() {
                let path = e.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
        out
    }

    /// Review-fix finding 1/7: a mint failure is LOUD — returns None (⇒ the
    /// caller surfaces `receiptStatus: "pending"`) and increments the shared
    /// audit-debt counter. Never a silent drop.
    #[tokio::test]
    async fn governance_receipt_failure_is_counted_not_silent() {
        let mut state = crate::http::tests::test_app_state_with_auth(4, crate::auth::AuthMode::DevScopes);
        // Force a signer mismatch so minting fails deterministically.
        state.passport_fpr = "fpr:bogus-mismatch-does-not-match-key".to_string();
        let before = crate::http::observations::receipt_mint_failures();
        let out = crate::http::observations::mint_governance_receipt(
            &state,
            "__governance__::erasure",
            "actor:test",
            "erasure.compact_facts",
            &build_erasure_receipt(1, 0, None, "operator_compaction", "act-f", "completed"),
        );
        assert!(out.is_none(), "mint must fail with a bogus signer");
        assert!(
            crate::http::observations::receipt_mint_failures() > before,
            "mint failure must increment the audit-debt counter (no silent drop)"
        );
    }

    #[tokio::test]
    async fn compact_facts_action_requires_reason() {
        let state = crate::http::tests::test_app_state(4);
        let err = execute_admin_action(&state, "act-2", "compact-facts", None, None, None, None)
            .await
            .unwrap_err();
        assert!(err.contains("reason is required"));
    }

    #[tokio::test]
    async fn tenant_bound_admin_cannot_enqueue_global_fact_compaction() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        const SECRET: &str = "0123456789abcdef0123456789abcdef";
        let mut state = crate::http::tests::test_app_state(4);
        state.auth = crate::auth::Authz::test_hs256(SECRET.as_bytes(), "corecrux-test", "corecrux");
        let token = encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "exp": chrono::Utc::now().timestamp() + 3600,
                "iss": "corecrux-test",
                "aud": "corecrux",
                "scope": "admin:write",
                "tenants": ["tenant-a"],
                "passport_id": "p_tenant_a_admin",
            }),
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );

        let response = post_admin_action(
            State(state.clone()),
            headers,
            Json(PostAdminActionRequest {
                action_id: Some("act-cross-tenant-compaction".to_string()),
                action_type: "compact-facts".to_string(),
                actor: None,
                reason: Some("cross-tenant denial fixture".to_string()),
                params: Some(serde_json::json!({
                    "reason": "operator compaction",
                    "gdprFullTenantErasure": true,
                    "tenantId": "tenant-b",
                })),
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(state.admin_actions.read().await.is_empty());
    }

    #[tokio::test]
    async fn held_hard_erasure_override_is_signed_and_bound_to_authenticated_passport() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("facts.jsonl");
        let mut state = crate::http::tests::test_app_state_with_auth(4, crate::auth::AuthMode::DevScopes);
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).unwrap();
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();
        let mut fs = FactStore::with_persistence(dir.path()).unwrap();
        let held = fs.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "customer::42::profile".to_string(),
            key: "pii".to_string(),
            value: "held-sensitive-value".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let placed = fs
            .place_legal_hold(corecrux_memory::PlaceLegalHold {
                tenant_id: "default".to_string(),
                entity_prefixes: vec!["customer::42::".to_string()],
                reason: "litigation".to_string(),
                actor: Some("p_legal".to_string()),
            })
            .unwrap();
        assert!(fs.delete("default", &held.fact_id));
        state.fact_store = std::sync::Arc::new(tokio::sync::RwLock::new(fs));

        let ordinary = serde_json::json!({"reason": "ordinary hard deletion"});
        let err = execute_admin_action(&state, "act-held", "compact-facts", Some(&ordinary), None, None, None)
            .await
            .unwrap_err();
        assert!(err.contains(&placed.hold.hold_id));
        assert!(std::fs::read_to_string(&journal)
            .unwrap()
            .contains("held-sensitive-value"));

        let gdpr = serde_json::json!({
            "reason": "GDPR Article 17 full-tenant erasure",
            "gdprFullTenantErasure": true,
            "tenantId": "default",
            "actor": "p_spoofed_dpo",
        });
        let authenticated_passport = "p_authenticated_dpo";
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", HeaderValue::from_static("admin:write"));
        headers.insert(
            "x-corecrux-passport-id",
            HeaderValue::from_static(authenticated_passport),
        );
        let response = post_admin_action(
            State(state.clone()),
            headers,
            Json(PostAdminActionRequest {
                action_id: Some("act-gdpr".to_string()),
                action_type: "compact-facts".to_string(),
                actor: Some("p_spoofed_action_actor".to_string()),
                reason: Some("caller-supplied metadata".to_string()),
                params: Some(gdpr),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let action = tokio::time::timeout(std::time::Duration::from_secs(6), async {
            loop {
                let action = state.admin_actions.read().await.get("act-gdpr").cloned().unwrap();
                if matches!(&action.status, AdminActionStatus::Succeeded | AdminActionStatus::Failed) {
                    break action;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(action.status, AdminActionStatus::Succeeded, "{:?}", action.error);
        let result = action.result.unwrap();
        assert_eq!(result["legalHoldOverridden"], true);
        assert_eq!(result["legalHoldOverrideReceipt"]["alg"], "ed25519");
        assert!(result["legalHoldOverrideReceipt"]["signature"]
            .as_str()
            .is_some_and(|signature| !signature.is_empty()));
        assert!(!std::fs::read_to_string(&journal)
            .unwrap()
            .contains("held-sensitive-value"));

        let governance_log =
            super::super::observations::observation_file_path(&state.data_dir, "__governance__::legal-holds");
        let records = std::fs::read_to_string(governance_log).unwrap();
        assert!(records.contains("legal_hold_overridden"));
        assert!(records.contains(&placed.hold.hold_id));
        assert!(!records.contains("p_spoofed_dpo"));
        assert!(!records.contains("p_spoofed_action_actor"));
        let override_record: serde_json::Value = serde_json::from_str(records.lines().last().unwrap()).unwrap();
        assert_eq!(override_record["principal"], authenticated_passport);
        assert_eq!(override_record["payload"]["actor"], authenticated_passport);
    }

    #[tokio::test]
    async fn held_hard_erasure_stops_before_compaction_when_override_receipt_sync_fails() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("facts.jsonl");
        let mut state = crate::http::tests::test_app_state_with_auth(4, crate::auth::AuthMode::DevScopes);
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).unwrap();
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();
        let mut fs = FactStore::with_persistence(dir.path()).unwrap();
        let held = fs.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "customer::sync-failure::profile".to_string(),
            key: "pii".to_string(),
            value: "held-content-must-survive-sync-failure".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        fs.place_legal_hold(corecrux_memory::PlaceLegalHold {
            tenant_id: "default".to_string(),
            entity_prefixes: vec!["customer::sync-failure::".to_string()],
            reason: "litigation".to_string(),
            actor: Some("p_legal".to_string()),
        })
        .unwrap();
        assert!(fs.delete("default", &held.fact_id));
        state.fact_store = std::sync::Arc::new(tokio::sync::RwLock::new(fs));

        let override_log =
            crate::http::observations::observation_file_path(&state.data_dir, "__governance__::legal-holds");
        let sync_failure_marker = override_log.with_extension("sync-fail");
        std::fs::create_dir_all(sync_failure_marker.parent().unwrap()).unwrap();
        std::fs::write(&sync_failure_marker, b"inject sync failure").unwrap();

        let params = serde_json::json!({
            "reason": "GDPR Article 17 full-tenant erasure",
            "gdprFullTenantErasure": true,
            "tenantId": "default",
        });
        let error = execute_admin_action(
            &state,
            "act-held-sync-failure",
            "compact-facts",
            Some(&params),
            None,
            None,
            Some("p_authenticated_dpo"),
        )
        .await
        .expect_err("receipt fsync failure must abort before hard erasure");
        assert!(error.contains("sync observation"), "{error}");
        assert!(
            std::fs::read_to_string(&journal)
                .unwrap()
                .contains("held-content-must-survive-sync-failure"),
            "held plaintext must remain until the signed override receipt is crash-durable"
        );
        assert!(
            state
                .fact_store
                .read()
                .await
                .deleted_facts_covered_by_legal_holds()
                .iter()
                .any(|(fact_id, _)| fact_id == &held.fact_id),
            "failed receipt durability must leave the held tombstone eligible to block compaction"
        );
        std::fs::remove_file(sync_failure_marker).unwrap();
    }

    #[tokio::test]
    async fn apply_retention_without_config_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::http::tests::test_app_state(4);
        state.fact_store = std::sync::Arc::new(tokio::sync::RwLock::new(
            FactStore::with_persistence(dir.path()).unwrap(),
        ));
        // retention_days is None on the test state.
        let params = serde_json::json!({ "reason": "r", "applyRetention": true });
        let err = execute_admin_action(&state, "act-3", "compact-facts", Some(&params), None, None, None)
            .await
            .unwrap_err();
        assert!(err.contains("CORECRUXD_RETENTION_DAYS is unset"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod admin_read_tests {
    use super::super::tests::test_app_state;
    use super::*;

    #[tokio::test]
    async fn read_handlers_return_ok_on_default_state() {
        let s = test_app_state(16);
        assert_eq!(
            get_shard_map(State(s.clone()), HeaderMap::new())
                .await
                .into_response()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            get_control(State(s.clone()), HeaderMap::new())
                .await
                .into_response()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            get_replication_status(State(s.clone()), HeaderMap::new())
                .await
                .into_response()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            get_segment_fingerprints(State(s.clone()), HeaderMap::new())
                .await
                .into_response()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            get_sharing_posture(State(s.clone()), HeaderMap::new())
                .await
                .into_response()
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn ops_log_default_query_ok() {
        let s = test_app_state(16);
        let q = OpsLogQuery {
            node_id: None,
            since: None,
            until: None,
            from_seq: None,
            max_events: None,
        };
        let resp = get_ops_log(State(s), Query(q), HeaderMap::new()).await.into_response();
        // CE test state has no dataplane pool → ops log is precondition-failed.
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn get_admin_action_missing_is_404() {
        let s = test_app_state(16);
        let resp = get_admin_action(State(s), HeaderMap::new(), Path("nope".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use crate::auth::AuthMode;
    use crate::http::tests::{dev_scope_headers, test_app_state, test_app_state_with_auth};

    fn dev_state() -> AppState {
        test_app_state_with_auth(16, AuthMode::DevScopes)
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    // ── param readers ─────────────────────────────────────────────────────

    #[test]
    fn read_param_str_trims_and_rejects_blanks() {
        let params = serde_json::json!({ "a": "  value  ", "blank": "   ", "n": 5, "null": null });
        assert_eq!(read_param_str(Some(&params), "a"), Some("value"));
        assert_eq!(read_param_str(Some(&params), "blank"), None);
        assert_eq!(read_param_str(Some(&params), "n"), None);
        assert_eq!(read_param_str(Some(&params), "null"), None);
        assert_eq!(read_param_str(Some(&params), "absent"), None);
        assert_eq!(read_param_str(None, "a"), None);
    }

    #[test]
    fn read_param_bool_accepts_bools_and_the_documented_strings() {
        let params = serde_json::json!({
            "t": true, "f": false,
            "s1": "1", "strue": "TRUE", "syes": " yes ", "sy": "Y",
            "s0": "0", "sfalse": "False", "sno": "no", "sn": "n",
            "junk": "maybe", "num": 1, "arr": [],
        });
        let p = Some(&params);
        assert_eq!(read_param_bool(p, "t"), Some(true));
        assert_eq!(read_param_bool(p, "f"), Some(false));
        for key in ["s1", "strue", "syes", "sy"] {
            assert_eq!(read_param_bool(p, key), Some(true), "{key}");
        }
        for key in ["s0", "sfalse", "sno", "sn"] {
            assert_eq!(read_param_bool(p, key), Some(false), "{key}");
        }
        // Unparsable values must be None, never a silent `false`.
        assert_eq!(read_param_bool(p, "junk"), None);
        assert_eq!(read_param_bool(p, "num"), None);
        assert_eq!(read_param_bool(p, "arr"), None);
        assert_eq!(read_param_bool(p, "absent"), None);
        assert_eq!(read_param_bool(None, "t"), None);
    }

    #[test]
    fn read_param_u64_and_u32_reject_out_of_range_and_junk() {
        let params = serde_json::json!({
            "n": 42, "s": "43", "neg": -1, "float": 1.5, "junk": "abc", "big": "4294967296",
        });
        let p = Some(&params);
        assert_eq!(read_param_u64(p, "n"), Some(42));
        assert_eq!(read_param_u64(p, "s"), Some(43));
        assert_eq!(read_param_u64(p, "neg"), None);
        assert_eq!(read_param_u64(p, "float"), None);
        assert_eq!(read_param_u64(p, "junk"), None);
        assert_eq!(read_param_u64(p, "absent"), None);
        assert_eq!(read_param_u64(None, "n"), None);

        assert_eq!(read_param_u32(p, "n"), Some(42));
        // Above u32::MAX must narrow to None, not truncate.
        assert_eq!(read_param_u32(p, "big"), None);
    }

    #[test]
    fn read_param_f64_accepts_numbers_and_numeric_strings() {
        let params = serde_json::json!({ "f": 0.25, "s": "0.5", "junk": "x", "b": true });
        let p = Some(&params);
        assert_eq!(read_param_f64(p, "f"), Some(0.25));
        assert_eq!(read_param_f64(p, "s"), Some(0.5));
        assert_eq!(read_param_f64(p, "junk"), None);
        assert_eq!(read_param_f64(p, "b"), None);
        assert_eq!(read_param_f64(None, "f"), None);
    }

    // ── action id / type validation ───────────────────────────────────────

    #[test]
    fn is_known_admin_action_matches_the_documented_set_only() {
        for ty in [
            "verify-store",
            "scrub-now",
            "snapshot-verify",
            "projection-rebuild",
            "parity-pack",
            "runtime-knob-update",
            "force-seal",
            "compact-facts",
        ] {
            assert!(is_known_admin_action(ty), "{ty} should be known");
        }
        for ty in ["", "verify_store", "VERIFY-STORE", "restart", " force-seal "] {
            assert!(!is_known_admin_action(ty), "{ty} must not be known");
        }
    }

    #[test]
    fn is_safe_admin_action_id_rejects_path_and_control_characters() {
        assert!(is_safe_admin_action_id("act_123.a-b"));
        assert!(is_safe_admin_action_id(&"a".repeat(128)));
        assert!(!is_safe_admin_action_id(""));
        assert!(!is_safe_admin_action_id(&"a".repeat(129)));
        for bad in ["../etc/passwd", "a/b", "a b", "a\nb", "a\0b", "café", "a:b", "a%2e"] {
            assert!(!is_safe_admin_action_id(bad), "{bad:?} must be rejected");
        }
    }

    // ── knowledge-authority parsers ───────────────────────────────────────

    #[test]
    fn knowledge_authority_mode_parser_covers_every_alias() {
        for (raw, want) in [
            ("knowledge_shadow", KnowledgeAuthorityModeV1::Shadow),
            (" shadow ", KnowledgeAuthorityModeV1::Shadow),
            ("knowledge_dual_write", KnowledgeAuthorityModeV1::DualWrite),
            ("dual_write", KnowledgeAuthorityModeV1::DualWrite),
            ("knowledge_shadow_read", KnowledgeAuthorityModeV1::ShadowRead),
            ("shadow_read", KnowledgeAuthorityModeV1::ShadowRead),
            ("knowledge_authoritative", KnowledgeAuthorityModeV1::Authoritative),
            ("authoritative", KnowledgeAuthorityModeV1::Authoritative),
        ] {
            assert_eq!(parse_knowledge_authority_mode(raw), Some(want), "{raw}");
        }
        for raw in ["", "AUTHORITATIVE", "dual-write", "nonsense"] {
            assert_eq!(parse_knowledge_authority_mode(raw), None, "{raw}");
        }
    }

    #[test]
    fn knowledge_rollout_stage_parser_covers_every_alias() {
        for (raw, want) in [
            ("internal_shadow", KnowledgeRolloutStageV1::InternalShadow),
            (" shadow ", KnowledgeRolloutStageV1::InternalShadow),
            ("tenant_validation", KnowledgeRolloutStageV1::TenantValidation),
            ("internal_authority", KnowledgeRolloutStageV1::InternalAuthority),
            (
                "limited_production_authority",
                KnowledgeRolloutStageV1::LimitedProductionAuthority,
            ),
            (
                "full_production_authority",
                KnowledgeRolloutStageV1::FullProductionAuthority,
            ),
        ] {
            assert_eq!(parse_knowledge_rollout_stage(raw), Some(want), "{raw}");
        }
        assert_eq!(parse_knowledge_rollout_stage("production"), None);
    }

    #[test]
    fn knowledge_parity_status_parser_covers_every_variant() {
        for (raw, want) in [
            ("unknown", KnowledgeParityStatusV1::Unknown),
            (" pass ", KnowledgeParityStatusV1::Pass),
            ("warn", KnowledgeParityStatusV1::Warn),
            ("fail", KnowledgeParityStatusV1::Fail),
        ] {
            assert_eq!(parse_knowledge_parity_status(raw), Some(want), "{raw}");
        }
        assert_eq!(parse_knowledge_parity_status("PASS"), None);
        assert_eq!(parse_knowledge_parity_status(""), None);
    }

    #[test]
    fn parse_tenant_throttle_rules_rejects_bad_shapes_and_blank_tenants() {
        let ok = parse_tenant_throttle_rules(&serde_json::json!([
            { "tenantId": "t1", "eventsPerSec": 10 }
        ]))
        .expect("valid rules");
        assert_eq!(ok.len(), 1);

        assert!(parse_tenant_throttle_rules(&serde_json::json!([])).unwrap().is_empty());

        let err = parse_tenant_throttle_rules(&serde_json::json!({ "tenantId": "t1" })).unwrap_err();
        assert!(err.contains("must be an array"), "got {err}");

        let err = parse_tenant_throttle_rules(&serde_json::json!([{ "tenantId": "  " }])).unwrap_err();
        assert!(err.contains("non-empty tenantId"), "got {err}");
    }

    #[test]
    fn admin_action_error_passes_the_detail_through() {
        assert_eq!(admin_action_error("boom"), "boom");
        assert_eq!(admin_action_error(String::from("boom")), "boom");
    }

    // ── evidence ids + correlation ────────────────────────────────────────

    #[test]
    fn trace_id_from_traceparent_only_accepts_a_32_hex_trace_id() {
        assert_eq!(trace_id_from_traceparent(None), None);
        assert_eq!(trace_id_from_traceparent(Some("")), None);
        assert_eq!(trace_id_from_traceparent(Some("00")), None);
        assert_eq!(trace_id_from_traceparent(Some("00-short-b7ad6b7169203331-01")), None);
        assert_eq!(
            trace_id_from_traceparent(Some("00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-b7ad6b7169203331-01")),
            None
        );
        assert_eq!(
            trace_id_from_traceparent(Some("00-4bf92f3577b34da6a3ce929d0e0e4736-b7ad6b7169203331-01")),
            Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string())
        );
    }

    #[test]
    fn evidence_request_context_extracts_the_trace_id_when_present() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-b7ad6b7169203331-01"),
        );
        headers.insert("x-request-id", HeaderValue::from_static("req-1"));
        let ctx = evidence_request_context_from_headers(&headers);
        assert_eq!(ctx.trace_id.as_deref(), Some("4bf92f3577b34da6a3ce929d0e0e4736"));
        assert!(ctx.traceparent.is_some());

        let bare = evidence_request_context_from_headers(&HeaderMap::new());
        assert_eq!(bare.trace_id, None);
        assert_eq!(bare.traceparent, None);
    }

    #[test]
    fn event_id_builders_are_deterministic_and_hash_prefixed() {
        assert!(submitted_event_id("act-1").ends_with(":act-1"));
        assert!(finished_event_id("act-1", "succeeded").ends_with(":act-1:succeeded"));

        let full = "0123456789abcdef0123456789abcdef";
        assert!(mutation_event_id("act-1", full).ends_with(":act-1:0123456789abcdef"));
        // A hash shorter than the 16-char prefix must be used whole, not panic.
        assert!(mutation_event_id("act-1", "abc").ends_with(":act-1:abc"));

        assert_eq!(checkpoint_id("act-1", full), "checkpoint:act-1:0123456789abcdef");
        assert_eq!(checkpoint_id("act-1", "abc"), "checkpoint:act-1:abc");
        assert!(checkpoint_event_id("checkpoint:act-1:abc").ends_with("checkpoint:act-1:abc"));
    }

    #[test]
    fn now_unix_ms_is_a_plausible_wall_clock() {
        // Well past 2020 and inside u64 — the saturating conversion holds.
        assert!(now_unix_ms() > 1_600_000_000_000);
    }

    #[tokio::test]
    async fn evidence_node_context_carries_the_local_node_identity() {
        let state = test_app_state(16);
        let node = evidence_node_context(&state);
        assert_eq!(node.node_id, state.node_id);
        assert_eq!(node.http_listen_addr, None);
        assert_eq!(node.grpc_listen_addr, None);
    }

    // ── control evidence appenders (dataplane-disabled path) ──────────────

    #[tokio::test]
    async fn append_control_evidence_event_is_a_no_op_without_a_dataplane() {
        let state = test_app_state(16);
        let appended = append_control_evidence_event(
            &state,
            EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1,
            submitted_event_id("act-1"),
            &serde_json::json!({ "ok": true }),
        )
        .await
        .expect("no dataplane is not an error");
        assert!(!appended, "nothing can be appended without a dataplane");
    }

    #[tokio::test]
    async fn append_control_checkpoint_materialized_event_succeeds_without_a_dataplane() {
        let state = test_app_state(16);
        let control = state.control.read().await.clone();
        append_control_checkpoint_materialized_event(&state, "act-1", &control)
            .await
            .expect("checkpoint append");
        // Warning helper is a pure log call; exercise it for completeness.
        append_control_event_warning("act-1", EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1, "synthetic");
    }

    #[tokio::test]
    async fn evidence_event_builders_populate_the_schema_fields() {
        let state = test_app_state(16);
        let auth = EvidenceAuthContextV1 {
            mode: "dev_scopes".to_string(),
            subject: Some("s".to_string()),
            tenant_binding: Some("*".to_string()),
            scopes: vec!["admin:write".to_string()],
        };
        let request = evidence_request_context_from_headers(&HeaderMap::new());

        let submitted = build_admin_action_submitted_event(
            &state,
            "act-1",
            "verify-store",
            7,
            Some("actor".to_string()),
            Some("reason".to_string()),
            Some(serde_json::json!({ "scope": "all" })),
            auth.clone(),
            request.clone(),
        );
        assert_eq!(submitted.schema, EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1);
        assert_eq!(submitted.action_id, "act-1");
        assert_eq!(submitted.submitted_at_unix_ms, 7);

        let before = state.control.read().await.clone();
        let mut after = before.clone();
        after.valves.pause_ingest.set(true, "actor", "reason", 1);
        let mutation = build_control_mutation_event(
            &state,
            "act-1",
            "set_valves",
            "actor",
            "reason",
            auth,
            request,
            &before,
            &after,
            serde_json::json!({ "ok": true }),
        );
        assert_eq!(mutation.schema, EVT_CONTROL_STATE_MUTATION_V1);
        assert_eq!(mutation.mutation_type, "set_valves");
        assert!(mutation.result.is_some());

        let finished = build_admin_action_finished_event(
            &state,
            "act-1",
            "verify-store",
            "failed",
            Some(1),
            2,
            None,
            None,
            Some("boom".to_string()),
        );
        assert_eq!(finished.schema, EVT_CONTROL_ADMIN_ACTION_FINISHED_V1);
        assert_eq!(finished.status, "failed");
        assert_eq!(finished.error.as_deref(), Some("boom"));

        let checkpoint = build_control_checkpoint_materialized_event(&state, "checkpoint:act-1:abc", &after);
        assert_eq!(checkpoint.schema, EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1);
        assert_eq!(checkpoint.checkpoint_format, "control.json.pretty.v1");
        assert!(checkpoint.checkpoint_size_bytes > 0);
        assert_eq!(checkpoint.checkpoint_blake3.len(), 64);
    }

    #[tokio::test]
    async fn sync_control_metrics_mirrors_every_valve_into_prometheus() {
        let state = test_app_state(16);
        let mut control = state.control.read().await.clone();
        control.valves.pause_ingest.set(true, "a", "r", 1);
        control.valves.read_only.set(true, "a", "r", 1);
        sync_control_metrics(&state.metrics, &control);
        let rendered = state.metrics.render().unwrap();
        assert!(rendered.contains("corecrux_valve_pause_ingest 1"));
        assert!(rendered.contains("corecrux_valve_read_only 1"));
        assert!(rendered.contains("corecrux_valve_pause_compaction 0"));
        assert!(rendered.contains("corecrux_throttle_ratio 1"));
        assert!(rendered.contains("corecrux_knowledge_authority_mode"));
    }

    // ── execute_admin_action: the error arms ──────────────────────────────

    #[tokio::test]
    async fn execute_admin_action_rejects_an_unknown_action_type() {
        let state = test_app_state(16);
        let err = execute_admin_action(&state, "act-1", "not-an-action", None, None, None, None)
            .await
            .unwrap_err();
        assert!(err.contains("unknown actionType 'not-an-action'"), "got {err}");
    }

    #[tokio::test]
    async fn execute_admin_action_parity_pack_is_explicitly_unsupported() {
        let state = test_app_state(16);
        let err = execute_admin_action(&state, "act-1", "parity-pack", None, None, None, None)
            .await
            .unwrap_err();
        assert!(err.contains("not implemented in corecruxd"), "got {err}");
    }

    #[tokio::test]
    async fn dataplane_backed_actions_fail_closed_without_a_dataplane() {
        let state = test_app_state(16);
        for action in ["verify-store", "scrub-now", "snapshot-verify", "projection-rebuild"] {
            let err = execute_admin_action(&state, "act-1", action, None, None, None, None)
                .await
                .unwrap_err();
            assert!(err.contains("dataplane disabled"), "{action}: got {err}");
        }
    }

    #[tokio::test]
    async fn force_seal_is_refused_until_explicitly_enabled() {
        let state = test_app_state(16);
        let err = execute_admin_action(&state, "act-1", "force-seal", None, None, None, None)
            .await
            .unwrap_err();
        assert!(err.contains("force-seal is disabled"), "got {err}");
    }

    #[tokio::test]
    async fn force_seal_requires_a_reason_once_enabled() {
        let mut state = test_app_state(16);
        state.admin_force_seal_enabled = true;
        let err = execute_admin_action(&state, "act-1", "force-seal", None, None, None, None)
            .await
            .unwrap_err();
        assert!(err.contains("reason is required for force-seal"), "got {err}");

        // With a reason it gets as far as the (absent) dataplane, and stops.
        let params = serde_json::json!({ "reason": "operator drill" });
        let err = execute_admin_action(&state, "act-1", "force-seal", Some(&params), None, None, None)
            .await
            .unwrap_err();
        assert!(err.contains("dataplane disabled"), "got {err}");
    }

    #[tokio::test]
    async fn runtime_knob_update_with_no_params_changes_nothing() {
        let state = test_app_state(16);
        let out = execute_admin_action(&state, "act-1", "runtime-knob-update", None, None, None, None)
            .await
            .expect("no-op knob update");
        assert_eq!(out.result["changed"], false);
        assert_eq!(out.mutation_event_id, None);
    }

    #[tokio::test]
    async fn runtime_knob_update_persists_throttle_and_knowledge_authority() {
        let state = test_app_state(16);
        let params = serde_json::json!({
            "actor": "op",
            "reason": "tuning",
            "throttleEnabled": true,
            "throttleEventsPerSec": 100,
            "throttleBytesPerSec": 2048,
            "throttleMaxInFlight": 4,
            "throttleRetryAfterMs": 250,
            "knowledgeAuthorityMode": "dual_write",
            "knowledgeAuthorityRolloutStage": "tenant_validation",
            "knowledgeLastParityStatus": "warn",
            "knowledgeLastParityMismatchCount": 3,
            "knowledgeRollbackTriggered": true,
            "tenantThrottleRules": [{ "tenantId": "t1" }],
        });
        let out = execute_admin_action(&state, "act-1", "runtime-knob-update", Some(&params), None, None, None)
            .await
            .expect("knob update");
        assert_eq!(out.result["changed"], true);
        assert_eq!(out.result["throttle"]["enabled"], true);
        assert_eq!(out.result["throttle"]["eventsPerSec"], 100);
        assert!(out.mutation_event_id.is_some());

        let control = state.control.read().await;
        assert!(control.valves.throttle.enabled);
        assert_eq!(control.knowledge_authority.mode, KnowledgeAuthorityModeV1::DualWrite);
        assert!(control.knowledge_authority.rollback_triggered);
        assert_eq!(control.tenant_throttles.len(), 1);
        drop(control);

        // CONTROL.json is on disk and reloadable.
        assert!(state.control_path.exists());
    }

    #[tokio::test]
    async fn runtime_knob_update_rejects_invalid_enum_params() {
        let state = test_app_state(16);
        for (key, value, needle) in [
            ("knowledgeAuthorityMode", "bogus", "invalid knowledgeAuthorityMode"),
            (
                "knowledgeAuthorityRolloutStage",
                "bogus",
                "invalid knowledgeAuthorityRolloutStage",
            ),
            (
                "knowledgeLastParityStatus",
                "bogus",
                "invalid knowledgeLastParityStatus",
            ),
        ] {
            let params = serde_json::json!({ key: value });
            let err = execute_admin_action(&state, "act-1", "runtime-knob-update", Some(&params), None, None, None)
                .await
                .unwrap_err();
            assert!(err.contains(needle), "{key}: got {err}");
        }

        let params = serde_json::json!({ "tenantThrottleRules": [{ "tenantId": "" }] });
        let err = execute_admin_action(&state, "act-1", "runtime-knob-update", Some(&params), None, None, None)
            .await
            .unwrap_err();
        assert!(err.contains("non-empty tenantId"), "got {err}");
    }

    #[tokio::test]
    async fn runtime_knob_update_can_clear_the_parity_outcome() {
        let state = test_app_state(16);
        let set = serde_json::json!({ "knowledgeLastParityStatus": "fail" });
        execute_admin_action(&state, "act-1", "runtime-knob-update", Some(&set), None, None, None)
            .await
            .unwrap();
        assert!(state
            .control
            .read()
            .await
            .knowledge_authority
            .last_parity_outcome
            .is_some());

        let clear = serde_json::json!({ "knowledgeClearParityOutcome": true });
        let out = execute_admin_action(&state, "act-2", "runtime-knob-update", Some(&clear), None, None, None)
            .await
            .unwrap();
        assert_eq!(out.result["changed"], true);
        assert!(state
            .control
            .read()
            .await
            .knowledge_authority
            .last_parity_outcome
            .is_none());
    }

    // ── read handlers: authentication + authorisation ─────────────────────

    #[tokio::test]
    async fn admin_read_handlers_are_401_without_a_credential() {
        let s = dev_state();
        let cases: Vec<axum::response::Response> = vec![
            get_shard_map(State(s.clone()), HeaderMap::new()).await.into_response(),
            get_control(State(s.clone()), HeaderMap::new()).await.into_response(),
            get_replication_status(State(s.clone()), HeaderMap::new())
                .await
                .into_response(),
            get_segment_fingerprints(State(s.clone()), HeaderMap::new())
                .await
                .into_response(),
            get_sharing_posture(State(s.clone()), HeaderMap::new())
                .await
                .into_response(),
            get_admin_action(State(s.clone()), HeaderMap::new(), Path("act-1".to_string()))
                .await
                .into_response(),
        ];
        for resp in cases {
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn admin_read_handlers_are_403_with_the_wrong_scope() {
        let s = dev_state();
        let h = || dev_scope_headers("facts:write");
        assert_eq!(
            get_shard_map(State(s.clone()), h()).await.into_response().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            get_control(State(s.clone()), h()).await.into_response().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            get_replication_status(State(s.clone()), h())
                .await
                .into_response()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            get_segment_fingerprints(State(s.clone()), h())
                .await
                .into_response()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            get_sharing_posture(State(s.clone()), h())
                .await
                .into_response()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            get_admin_action(State(s.clone()), h(), Path("act-1".to_string()))
                .await
                .into_response()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn get_shard_map_returns_the_routing_snapshot() {
        let s = dev_state();
        let resp = get_shard_map(State(s.clone()), dev_scope_headers("admin:read"))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let expected = s.routing.read().await.shard_map.clone();
        assert_eq!(body["currentVersion"], expected.version);
        assert_eq!(body["blake3"], expected.blake3);
    }

    #[tokio::test]
    async fn get_control_returns_the_live_control_document() {
        let s = dev_state();
        s.control.write().await.valves.read_only.set(true, "op", "drill", 1);
        let resp = get_control(State(s.clone()), dev_scope_headers("admin:read"))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["valves"]["readOnly"]["enabled"], true);
    }

    #[tokio::test]
    async fn get_segment_fingerprints_reports_partial_v6_parity() {
        let s = dev_state();
        let resp = get_segment_fingerprints(State(s), dev_scope_headers("admin:read"))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["status"], "partial");
        assert_eq!(body["cpu_only"], true);
        assert_eq!(body["fingerprint_guard"]["mode"], "not_enforced");
        assert_eq!(body["calibration"]["available"], false);
    }

    #[tokio::test]
    async fn get_replication_status_reports_the_local_role_per_shard() {
        let s = dev_state();
        let resp = get_replication_status(State(s.clone()), dev_scope_headers("admin:read"))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["nodeId"], s.node_id);
        assert!(body["shards"].is_array());
        for shard in body["shards"].as_array().unwrap() {
            assert!(
                ["leader", "follower", "unassigned"].contains(&shard["role"].as_str().unwrap()),
                "unexpected role {}",
                shard["role"]
            );
        }
    }

    #[tokio::test]
    async fn get_ops_log_auth_is_checked_before_the_dataplane_precondition() {
        let s = dev_state();
        let query = || {
            Query(OpsLogQuery {
                node_id: None,
                since: None,
                until: None,
                from_seq: None,
                max_events: None,
            })
        };
        assert_eq!(
            get_ops_log(State(s.clone()), query(), HeaderMap::new())
                .await
                .into_response()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get_ops_log(State(s.clone()), query(), dev_scope_headers("facts:write"))
                .await
                .into_response()
                .status(),
            StatusCode::FORBIDDEN
        );
        // Authorised, but there is no dataplane to read from.
        assert_eq!(
            get_ops_log(State(s), query(), dev_scope_headers("admin:read"))
                .await
                .into_response()
                .status(),
            StatusCode::PRECONDITION_FAILED
        );
    }

    // ── write handlers: authorisation + validation ────────────────────────

    #[tokio::test]
    async fn post_shard_map_needs_admin_write_and_is_cli_only() {
        let s = dev_state();
        assert_eq!(
            post_shard_map(State(s.clone()), HeaderMap::new(), axum::body::Bytes::new())
                .await
                .into_response()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post_shard_map(
                State(s.clone()),
                dev_scope_headers("admin:read"),
                axum::body::Bytes::new()
            )
            .await
            .into_response()
            .status(),
            StatusCode::FORBIDDEN,
            "admin:read must not authorise a write route"
        );
        assert_eq!(
            post_shard_map(State(s), dev_scope_headers("admin:write"), axum::body::Bytes::new())
                .await
                .into_response()
                .status(),
            StatusCode::NOT_IMPLEMENTED
        );
    }

    fn valves_req(actor: &str, reason: &str) -> SetValvesReq {
        SetValvesReq {
            actor: actor.to_string(),
            reason: reason.to_string(),
            pause_ingest: None,
            pause_compaction: None,
            throttle: None,
            read_only: None,
            emergency_brake: None,
        }
    }

    #[tokio::test]
    async fn post_valves_requires_admin_write() {
        let s = dev_state();
        assert_eq!(
            post_valves(State(s.clone()), HeaderMap::new(), Json(valves_req("op", "drill")))
                .await
                .into_response()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post_valves(
                State(s),
                dev_scope_headers("admin:read"),
                Json(valves_req("op", "drill"))
            )
            .await
            .into_response()
            .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn post_valves_rejects_a_blank_actor_or_reason() {
        let s = dev_state();
        for (actor, reason) in [("", "drill"), ("op", ""), ("   ", "  ")] {
            let resp = post_valves(
                State(s.clone()),
                dev_scope_headers("admin:write"),
                Json(valves_req(actor, reason)),
            )
            .await
            .into_response();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "actor={actor:?} reason={reason:?}"
            );
        }
    }

    #[tokio::test]
    async fn post_valves_with_no_flags_persists_nothing_but_still_succeeds() {
        let s = dev_state();
        let resp = post_valves(
            State(s.clone()),
            dev_scope_headers("admin:write"),
            Json(valves_req("op", "drill")),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!s.control.read().await.valves.pause_ingest.enabled);
    }

    #[tokio::test]
    async fn post_valves_sets_each_individual_valve() {
        let s = dev_state();
        let mut req = valves_req("op", "drill");
        req.pause_ingest = Some(true);
        req.pause_compaction = Some(true);
        req.read_only = Some(true);
        req.throttle = Some(SetThrottle {
            enabled: true,
            retry_after_ms: Some(500),
            events_per_sec: Some(10),
            bytes_per_sec: Some(1024),
            max_in_flight: Some(2),
        });
        let resp = post_valves(State(s.clone()), dev_scope_headers("admin:write"), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let control = s.control.read().await;
        assert!(control.valves.pause_ingest.enabled);
        assert!(control.valves.pause_compaction.enabled);
        assert!(control.valves.read_only.enabled);
        assert!(control.valves.throttle.enabled);
        assert_eq!(control.valves.throttle.events_per_sec, Some(10));
        assert_eq!(control.valves.throttle.retry_after_ms, Some(500));
        drop(control);
        assert!(s.control_path.exists(), "CONTROL.json must be persisted");
    }

    #[tokio::test]
    async fn emergency_brake_forces_the_non_mutating_posture_and_counts_once() {
        let s = dev_state();
        let mut req = valves_req("op", "incident");
        req.emergency_brake = Some(true);
        let resp = post_valves(State(s.clone()), dev_scope_headers("admin:write"), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let control = s.control.read().await;
        assert!(control.valves.emergency_brake.enabled);
        // The brake implies read-only + both pauses, regardless of what was asked.
        assert!(control.valves.read_only.enabled);
        assert!(control.valves.pause_ingest.enabled);
        assert!(control.valves.pause_compaction.enabled);
        drop(control);

        assert!(s
            .metrics
            .render()
            .unwrap()
            .contains(r#"corecrux_emergency_brake_total{source="admin_http"} 1"#));
    }

    #[tokio::test]
    async fn post_stream_meta_validates_before_reaching_the_dataplane() {
        let s = dev_state();
        let req = |actor: &str, reason: &str| StreamMetaReq {
            tenant_id: "t1".to_string(),
            stream_type: "receipts".to_string(),
            stream_id: "s1".to_string(),
            min_live_seq: Some(1),
            tombstone_seq: Some(0),
            actor: actor.to_string(),
            reason: reason.to_string(),
        };

        assert_eq!(
            post_stream_meta(State(s.clone()), HeaderMap::new(), Json(req("op", "r")))
                .await
                .into_response()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post_stream_meta(State(s.clone()), dev_scope_headers("admin:read"), Json(req("op", "r")))
                .await
                .into_response()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post_stream_meta(State(s.clone()), dev_scope_headers("admin:write"), Json(req(" ", "r")))
                .await
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
        // Authorised + well-formed, but the CE has no dataplane.
        assert_eq!(
            post_stream_meta(State(s.clone()), dev_scope_headers("admin:write"), Json(req("op", "r")))
                .await
                .into_response()
                .status(),
            StatusCode::NOT_IMPLEMENTED
        );
    }

    #[tokio::test]
    async fn post_stream_meta_is_refused_while_writes_are_valved_off() {
        let s = dev_state();
        s.control.write().await.valves.read_only.set(true, "op", "drill", 1);
        let resp = post_stream_meta(
            State(s.clone()),
            dev_scope_headers("admin:write"),
            Json(StreamMetaReq {
                tenant_id: "t1".to_string(),
                stream_type: "receipts".to_string(),
                stream_id: "s1".to_string(),
                min_live_seq: None,
                tombstone_seq: None,
                actor: "op".to_string(),
                reason: "r".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // ── replication receiver ──────────────────────────────────────────────

    fn segment_req(shard: &str, payload: &str, hash: Option<&str>) -> ReplicationSegmentReq {
        ReplicationSegmentReq {
            shard_id: shard.to_string(),
            epoch: 1,
            leader_node_id: Some("node-b".to_string()),
            segment_base64: payload.to_string(),
            segment_hash: hash.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn post_replication_segment_requires_the_replication_write_scope() {
        let s = dev_state();
        assert_eq!(
            post_replication_segment(
                State(s.clone()),
                HeaderMap::new(),
                Json(segment_req("sh-1", "AAAA", None))
            )
            .await
            .into_response()
            .status(),
            StatusCode::UNAUTHORIZED
        );
        // admin:write is NOT replication:write.
        assert_eq!(
            post_replication_segment(
                State(s.clone()),
                dev_scope_headers("admin:write"),
                Json(segment_req("sh-1", "AAAA", None))
            )
            .await
            .into_response()
            .status(),
            StatusCode::FORBIDDEN
        );
        assert!(s
            .metrics
            .render()
            .unwrap()
            .contains(r#"corecrux_replication_receive_total{result="rejected"} 2"#));
    }

    #[tokio::test]
    async fn post_replication_segment_rejects_malformed_payloads() {
        let s = dev_state();
        let scopes = || dev_scope_headers("replication:write");

        for (req, want) in [
            (segment_req("   ", "AAAA", None), StatusCode::BAD_REQUEST),
            (segment_req("sh-1", "   ", None), StatusCode::BAD_REQUEST),
            (segment_req("sh-1", "!!!not-base64!!!", None), StatusCode::BAD_REQUEST),
            (segment_req("sh-1", "AAAA", Some("too-short")), StatusCode::BAD_REQUEST),
            (
                segment_req("sh-1", "AAAA", Some(&"z".repeat(64))),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let resp = post_replication_segment(State(s.clone()), scopes(), Json(req))
                .await
                .into_response();
            assert_eq!(resp.status(), want);
        }
    }

    #[tokio::test]
    async fn post_replication_segment_detects_a_segment_hash_mismatch() {
        let s = dev_state();
        let resp = post_replication_segment(
            State(s.clone()),
            dev_scope_headers("replication:write"),
            Json(segment_req("sh-1", "AAAA", Some(&"a".repeat(64)))),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        let body = body_json(resp).await;
        let detail = body["detail"].as_str().unwrap_or_default();
        assert!(detail.contains("REPLICATION_SEGMENT_HASH_MISMATCH"), "got {detail}");
    }

    #[tokio::test]
    async fn post_replication_segment_accepts_a_matching_hash_then_stops_at_the_dataplane() {
        let s = dev_state();
        let payload = base64::engine::general_purpose::STANDARD.encode(b"segment-bytes");
        let hash = hex32(blake3::hash(b"segment-bytes").as_bytes());
        let resp = post_replication_segment(
            State(s.clone()),
            dev_scope_headers("replication:write"),
            Json(segment_req("sh-1", &payload, Some(&hash.to_ascii_uppercase()))),
        )
        .await
        .into_response();
        // Hash matched (uppercase is normalised); the CE has no receiver.
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        assert!(s
            .metrics
            .render()
            .unwrap()
            .contains(r#"corecrux_replication_receive_total{result="error"} 1"#));
    }

    // ── sharing posture + backfill ────────────────────────────────────────

    #[tokio::test]
    async fn get_sharing_posture_buckets_facts_by_entity_prefix() {
        let s = dev_state();
        {
            let mut store = s.fact_store.write().await;
            for (entity, private) in [("github::repo", false), ("personal::note", true), ("bare", false)] {
                store.store(corecrux_memory::fact_store::StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: entity.to_string(),
                    key: "k".to_string(),
                    value: "v".to_string(),
                    source_receipt: None,
                    confidence: 1.0,
                    private,
                    horizon_class: None,
                    actor: None,
                });
            }
        }
        let resp = get_sharing_posture(State(s), dev_scope_headers("admin:read"))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["facts"]["total_count"], 3);
        // `github::` is a born-private prefix, so the store forces it private on
        // write regardless of the caller's flag — 2 private, 1 pushable.
        assert_eq!(body["facts"]["private_count"], 2);
        assert_eq!(body["facts"]["pushable_count"], 1);
        assert_eq!(
            body["facts"]["would_be_private_after_backfill"], 0,
            "born-private enforcement leaves nothing for the backfill to fix"
        );
        assert!(body["sync"]["note"].is_string());
        let prefixes: Vec<&str> = body["by_prefix"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["prefix"].as_str().unwrap())
            .collect();
        assert!(prefixes.contains(&"github"));
        assert!(prefixes.contains(&"personal"));
        assert!(
            prefixes.contains(&"(no prefix)"),
            "unprefixed entities get their own bucket"
        );
    }

    #[tokio::test]
    async fn post_sharing_backfill_needs_both_scopes() {
        let s = dev_state();
        assert_eq!(
            post_sharing_backfill(State(s.clone()), HeaderMap::new(), Json(BackfillBody::default()))
                .await
                .into_response()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        // Only one of the two required scopes.
        assert_eq!(
            post_sharing_backfill(State(s), dev_scope_headers("admin:read"), Json(BackfillBody::default()))
                .await
                .into_response()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn post_sharing_backfill_previews_before_it_writes() {
        let s = dev_state();
        let resp = post_sharing_backfill(
            State(s.clone()),
            dev_scope_headers("admin:read,facts:write"),
            Json(BackfillBody::default()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["mode"], "preview");
        assert!(body["would_re_store"].is_number());

        let resp = post_sharing_backfill(
            State(s),
            dev_scope_headers("admin:read,facts:write"),
            Json(BackfillBody { confirm: true }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["mode"], "confirmed");
        assert!(body["re_stored_count"].is_number());
    }

    // ── admin-action submission ───────────────────────────────────────────

    fn action_req(action_id: Option<&str>, action_type: &str) -> PostAdminActionRequest {
        PostAdminActionRequest {
            action_id: action_id.map(str::to_string),
            action_type: action_type.to_string(),
            actor: Some("   ".to_string()),
            reason: Some("   ".to_string()),
            params: None,
        }
    }

    #[tokio::test]
    async fn post_admin_action_requires_admin_write() {
        let s = dev_state();
        assert_eq!(
            post_admin_action(
                State(s.clone()),
                HeaderMap::new(),
                Json(action_req(None, "verify-store"))
            )
            .await
            .into_response()
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post_admin_action(
                State(s),
                dev_scope_headers("admin:read"),
                Json(action_req(None, "verify-store"))
            )
            .await
            .into_response()
            .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn post_admin_action_rejects_blank_and_unknown_action_types() {
        let s = dev_state();
        assert_eq!(
            post_admin_action(
                State(s.clone()),
                dev_scope_headers("admin:write"),
                Json(action_req(None, "   "))
            )
            .await
            .into_response()
            .status(),
            StatusCode::BAD_REQUEST
        );
        let resp = post_admin_action(
            State(s),
            dev_scope_headers("admin:write"),
            Json(action_req(None, "rm-rf")),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let detail = body_json(resp).await["detail"].as_str().unwrap_or_default().to_string();
        assert!(detail.contains("unknown actionType 'rm-rf'"), "got {detail}");
    }

    #[tokio::test]
    async fn post_admin_action_rejects_an_unsafe_action_id() {
        let s = dev_state();
        for bad in ["../escape", "a b", &"a".repeat(129)] {
            let resp = post_admin_action(
                State(s.clone()),
                dev_scope_headers("admin:write"),
                Json(action_req(Some(bad), "parity-pack")),
            )
            .await
            .into_response();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad:?}");
        }
    }

    #[tokio::test]
    async fn post_admin_action_blank_action_id_falls_back_to_a_generated_one() {
        let s = dev_state();
        let resp = post_admin_action(
            State(s.clone()),
            dev_scope_headers("admin:write"),
            Json(action_req(Some("   "), "parity-pack")),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body = body_json(resp).await;
        let id = body["action"]["actionId"].as_str().unwrap();
        assert!(id.starts_with("act_"), "got {id}");
        // Blank actor/reason are dropped rather than stored as whitespace.
        assert!(body["action"].get("actor").is_none());
        assert!(body["action"].get("reason").is_none());
    }

    #[tokio::test]
    async fn post_admin_action_is_idempotent_on_a_repeated_action_id() {
        let s = dev_state();
        let first = post_admin_action(
            State(s.clone()),
            dev_scope_headers("admin:write"),
            Json(action_req(Some("act-dup"), "parity-pack")),
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::ACCEPTED);

        let second = post_admin_action(
            State(s.clone()),
            dev_scope_headers("admin:write"),
            Json(action_req(Some("act-dup"), "parity-pack")),
        )
        .await
        .into_response();
        assert_eq!(second.status(), StatusCode::ACCEPTED);
        assert_eq!(body_json(second).await["action"]["actionId"], "act-dup");
        assert_eq!(s.admin_actions.read().await.len(), 1, "no duplicate record");
    }

    #[tokio::test]
    async fn post_admin_action_sheds_load_when_the_queue_is_full() {
        // action_max_pending = 0 → nothing may be queued.
        let s = test_app_state_with_auth(0, AuthMode::DevScopes);
        let resp = post_admin_action(
            State(s),
            dev_scope_headers("admin:write"),
            Json(action_req(Some("act-1"), "parity-pack")),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let detail = body_json(resp).await["detail"].as_str().unwrap_or_default().to_string();
        assert!(detail.contains("queue is full"), "got {detail}");
    }

    #[tokio::test]
    async fn submitted_action_runs_and_records_its_failure() {
        let s = dev_state();
        let resp = post_admin_action(
            State(s.clone()),
            dev_scope_headers("admin:write"),
            Json(action_req(Some("act-run"), "parity-pack")),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let action = tokio::time::timeout(std::time::Duration::from_secs(6), async {
            loop {
                let action = s.admin_actions.read().await.get("act-run").cloned().unwrap();
                if matches!(action.status, AdminActionStatus::Succeeded | AdminActionStatus::Failed) {
                    break action;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(action.status, AdminActionStatus::Failed);
        assert!(action.error.unwrap().contains("not implemented in corecruxd"));
        assert!(action.started_at_unix_ms.is_some());
        assert!(action.finished_at_unix_ms.is_some());

        // …and it is then readable through the GET route.
        let resp = get_admin_action(State(s), dev_scope_headers("admin:read"), Path("act-run".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["status"], "failed");
    }

    #[tokio::test]
    async fn run_admin_action_is_a_no_op_for_unknown_or_already_running_ids() {
        let s = dev_state();
        // Unknown id: must return without panicking or inserting anything.
        run_admin_action(s.clone(), "never-submitted".to_string()).await;
        assert!(s.admin_actions.read().await.is_empty());

        // Already-terminal record: the guard leaves it untouched.
        s.admin_actions.write().await.insert(
            "act-done".to_string(),
            AdminActionRecord {
                action_id: "act-done".to_string(),
                action_type: "parity-pack".to_string(),
                status: AdminActionStatus::Succeeded,
                submitted_at_unix_ms: 1,
                started_at_unix_ms: Some(1),
                finished_at_unix_ms: Some(2),
                actor: None,
                reason: None,
                params: None,
                result: None,
                error: None,
                auth_context: None,
                request_context: None,
                authenticated_passport: None,
            },
        );
        run_admin_action(s.clone(), "act-done".to_string()).await;
        let rec = s.admin_actions.read().await.get("act-done").cloned().unwrap();
        assert_eq!(rec.status, AdminActionStatus::Succeeded);
        assert_eq!(rec.finished_at_unix_ms, Some(2));
    }

    #[tokio::test]
    async fn admin_action_record_round_trips_through_json_without_the_bound_passport() {
        let record = AdminActionRecord {
            action_id: "act-1".to_string(),
            action_type: "verify-store".to_string(),
            status: AdminActionStatus::Running,
            submitted_at_unix_ms: 1,
            started_at_unix_ms: Some(2),
            finished_at_unix_ms: None,
            actor: Some("op".to_string()),
            reason: Some("r".to_string()),
            params: None,
            result: None,
            error: None,
            auth_context: None,
            request_context: None,
            authenticated_passport: Some("p_secret_binding".to_string()),
        };
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["status"], "running");
        assert_eq!(json["submittedAtUnixMs"], 1);
        assert_eq!(json["startedAtUnixMs"], 2);
        assert!(json.get("finishedAtUnixMs").is_none());
        // The auth-layer-bound passport is `serde(skip)` — never wire-visible.
        assert!(
            !json.to_string().contains("p_secret_binding"),
            "authenticated passport must not be serialised"
        );

        let back: AdminActionRecord = serde_json::from_value(json).unwrap();
        assert_eq!(back.status, AdminActionStatus::Running);
        assert_eq!(back.authenticated_passport, None);
    }
}
