// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
    )
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

pub(super) async fn execute_admin_action(
    state: &AppState,
    action_id: &str,
    action_type: &str,
    params: Option<&serde_json::Value>,
    auth_context: Option<&EvidenceAuthContextV1>,
    request_context: Option<&EvidenceRequestContextV1>,
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
            let actor = read_param_str(params, "actor").map_or_else(|| "admin-action-runtime-knob-update".to_string(), ToOwned::to_owned);
            let reason = read_param_str(params, "reason").map_or_else(|| "runtime knob update action".to_string(), ToOwned::to_owned);
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
                control_state.knowledge_authority.actor = actor.clone();
                control_state.knowledge_authority.reason = reason.clone();
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
        "parity-pack" => Err(admin_action_error(
            "parity-pack action is not implemented in corecruxd; run corecruxctl parity-pack",
        )),
        other => Err(admin_action_error(format!("unknown actionType '{other}'"))),
    }
}

pub(super) async fn run_admin_action(state: AppState, action_id: String) {
    let started_at_ms = now_unix_ms();
    let (action_type, params, auth_context, request_context) = {
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

    let action_id = req
        .action_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty()).map_or_else(|| format!("act_{}", uuid::Uuid::new_v4()), ToOwned::to_owned);
    if action_id.len() > 128 {
        return problem_response(StatusCode::BAD_REQUEST, "actionId must be <= 128 characters");
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

        let follower_targets = shard
            .followers
            .as_ref()
            .map_or(0, |followers| followers.iter().filter(|f| f.node_id != state.node_id).count());
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
