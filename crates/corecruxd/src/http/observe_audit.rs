// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `/v1/observe/*` — agent audit-chain surface (observe plan).
//!
//! Mounted via `Router::merge` so the Wave-2 observe plan can flesh out the
//! handlers without touching `http/mod.rs`. Gated by `CORECRUXD_OBSERVE`
//! (default OFF): when off, every route returns a `501` problem.
//!
//! Surfaces (one milestone each, all reading/writing the `agent_trace_node`
//! substrate kind registered in `crate::agentgraph_kinds`):
//!
//! - **M2 capture.** `POST /v1/observe/sessions/{id}/steps` opens a step
//!   (`status = running`, monotonic `seq` per session) and
//!   `PATCH /v1/observe/sessions/{id}/steps/{node_id}` closes it (appends
//!   `outputs`, sets `receipt_id`/`ts_end`/`status`). Each open/close emits a
//!   [`CruxEvent::AuditStep`] so the SSE stream (M4) fires live.
//! - **M4 reconstruction.** `GET /v1/observe/sessions/{id}/audit` reads every
//!   `agent_trace_node` for the session, orders by `seq`, and returns a
//!   [`SessionAudit`].
//! - **M5 verify + export.** `GET /v1/observe/sessions/{id}/audit/export`
//!   emits an EU-AI-Act bundle (steps + their receipts, each carrying a
//!   best-effort dataplane verification).
//! - **M6 conformance.** `GET /v1/observe/sessions/{id}/audit/conformance`
//!   asserts `receipt_chain_ok` / `is_attributed` / `enrich_ok` across the
//!   session and enumerates every failure (none silent).

use std::borrow::Cow;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::agentgraph_kinds::{observe_enabled, AGENT_TRACE_NODE_KIND};
use corecrux_memory::events::CruxEvent;
use corecrux_memory::EntityQuery;
use crux_observe::redact::{RedactMode, Redactor};
use crux_observe_api::{
    AuditStep, NodeKind, RiskClass, SessionAudit, StepStatus, TraceInput, TraceNode, TraceOutput, CONTRACT_VERSION,
};

use super::{
    problem_response, require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, Path, Response, State,
    StatusCode,
};

// ── Wire bodies ───────────────────────────────────────────────────────────

/// Body for `POST /v1/observe/sessions/{id}/steps` (open a step).
///
/// The caller supplies the *opening* facts; the daemon assigns the monotonic
/// `seq` and stamps `status = running`. `node_id` is optional — when absent
/// the daemon mints a stable id from `session_id` + `seq` so the capture hook
/// (which has no ulid generator) can stay dependency-light.
#[derive(Debug, Deserialize)]
pub(super) struct OpenStepBody {
    /// Optional caller-supplied id; minted when absent.
    #[serde(default)]
    pub node_id: Option<String>,
    /// Tree edge to the parent node (`None` for a session-root child).
    #[serde(default)]
    pub parent_id: Option<String>,
    /// Node position in the trace tree; defaults to [`NodeKind::Step`].
    #[serde(default = "default_step_kind")]
    pub kind: NodeKind,
    /// Human-facing label, e.g. `Step 2 · write reconciler`.
    pub label: String,
    /// Passport that performed the step (Art. 13). Required + non-empty (T.3).
    pub actor: String,
    /// Risk class; defaults to [`RiskClass::Low`].
    #[serde(default = "default_low_risk")]
    pub risk_class: RiskClass,
    /// RFC-3339 start timestamp.
    pub ts_start: String,
    /// What the model saw (Art. 12 input record).
    #[serde(default)]
    pub inputs: Vec<TraceInput>,
    /// `/v1/actions/enrich` consequence prediction (Art. 15) — high-risk only.
    #[serde(default)]
    pub enrich_ref: Option<String>,
    /// Inputs/reasoning may be PII; defaults `true` (Art. 10 / T.1).
    #[serde(default = "default_true")]
    pub private: bool,
}

/// Body for `PATCH /v1/observe/sessions/{id}/steps/{node_id}` (close a step).
///
/// Every field is optional so a close can patch only what it knows: a
/// best-effort PostToolUse close supplies `outputs` + `status`; the
/// PreCompact reasoning pass (M3) supplies only `reasoning_ref`.
#[derive(Debug, Deserialize, Default)]
pub(super) struct CloseStepBody {
    /// Commands / edits the step executed (appended to any existing outputs).
    #[serde(default)]
    pub outputs: Vec<TraceOutput>,
    /// Step-level CROWN receipt id (Art. 12 / T.4).
    #[serde(default)]
    pub receipt_id: Option<String>,
    /// Receipt to back-fill onto every mutating output that lacks its own.
    #[serde(default)]
    pub mutation_receipt_id: Option<String>,
    /// RFC-3339 end timestamp.
    #[serde(default)]
    pub ts_end: Option<String>,
    /// Terminal status; absent leaves the step `running`.
    #[serde(default)]
    pub status: Option<StepStatus>,
    /// Pointer to the step's reasoning — `fact:…` / `blob:…` (R1). Captured by
    /// the PreCompact reasoning pass (M3). Rejected on an unknown scheme by the
    /// `ReasoningRef` deserialiser, so it can never hold raw chain-of-thought.
    #[serde(default)]
    pub reasoning_ref: Option<crux_observe_api::ReasoningRef>,
    /// `/v1/actions/enrich` consequence prediction (Art. 15) — high-risk only.
    #[serde(default)]
    pub enrich_ref: Option<String>,
}

fn default_step_kind() -> NodeKind {
    NodeKind::Step
}

fn default_low_risk() -> RiskClass {
    RiskClass::Low
}

fn default_true() -> bool {
    true
}

// ── Routes ──────────────────────────────────────────────────────────────────

/// Routes for the observe audit-chain surface. Merged into the main router.
pub fn routes() -> axum::Router<AppState> {
    use axum::routing::{get, patch, post};
    axum::Router::new()
        .route("/v1/observe/sessions/{id}/steps", post(open_step))
        .route("/v1/observe/sessions/{id}/steps/{node_id}", patch(close_step))
        .route("/v1/observe/sessions/{id}/audit", get(get_session_audit))
        .route("/v1/observe/sessions/{id}/audit/export", get(get_session_audit_export))
        .route(
            "/v1/observe/sessions/{id}/audit/conformance",
            get(get_session_audit_conformance),
        )
}

// ── Shared helpers ────────────────────────────────────────────────────────

/// 501 problem returned by every route when `CORECRUXD_OBSERVE` is off.
fn observe_disabled() -> Response {
    problem_response(
        StatusCode::NOT_IMPLEMENTED,
        "observe surface disabled (set CORECRUXD_OBSERVE=1)",
    )
}

/// Read scopes guarding every observe read route.
const READ_SCOPES: &[&str] = &["facts:read", "admin:read"];
/// Write scopes guarding the capture (open/close) routes.
const WRITE_SCOPES: &[&str] = &["facts:write", "admin:write"];

/// Deserialise an `agent_trace_node` entity payload into a [`TraceNode`].
/// Returns `None` (and logs) on a malformed row so one bad node never poisons
/// the whole reconstruction.
fn node_from_payload(payload: &Value) -> Option<TraceNode> {
    match serde_json::from_value::<TraceNode>(payload.clone()) {
        Ok(node) => Some(node),
        Err(err) => {
            tracing::warn!("observe: skipping malformed agent_trace_node payload: {err}");
            None
        }
    }
}

/// Collect every live `agent_trace_node` for `session_id`, ordered by `seq`
/// then `node_id` (stable tie-break). Reads under the entity-store read lock.
async fn session_nodes(state: &AppState, session_id: &str) -> Vec<TraceNode> {
    let store = state.entity_store.read().await;
    let query = EntityQuery {
        kind: Some(AGENT_TRACE_NODE_KIND.to_string()),
        limit: None,
        include_deleted: false,
    };
    let mut nodes: Vec<TraceNode> = store
        .list(&query)
        .into_iter()
        .filter_map(|rec| node_from_payload(&rec.payload))
        .filter(|n| n.session_id == session_id)
        .collect();
    nodes.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.node_id.cmp(&b.node_id)));
    nodes
}

/// Next monotonic `seq` for `session_id` — `max(existing) + 1`, or `1` when the
/// session has no nodes yet. Caller holds no lock; this takes the read lock.
async fn next_seq(state: &AppState, session_id: &str) -> u64 {
    session_nodes(state, session_id)
        .await
        .iter()
        .map(|n| n.seq)
        .max()
        .map_or(1, |m| m.saturating_add(1))
}

/// Persist a [`TraceNode`] to the `agent_trace_node` substrate kind and emit
/// the `AuditStep` SSE event. Returns the stored payload value on success.
async fn upsert_node(state: &AppState, node: &TraceNode, actor: &str) -> Result<Value, Response> {
    let payload = serde_json::to_value(node)
        .map_err(|e| problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("encode trace node: {e}")))?;
    let registry = state.kind_registry.read().await;
    let registry_opt = registry.is_registered(AGENT_TRACE_NODE_KIND).then_some(&*registry);
    let mut store = state.entity_store.write().await;
    let rec = store
        .upsert(AGENT_TRACE_NODE_KIND, &node.node_id, payload, actor, registry_opt)
        .map_err(|e| problem_response(StatusCode::BAD_REQUEST, e.to_string()))?;
    // Drop the write lock before emitting so subscribers can re-read.
    drop(store);
    drop(registry);
    state.event_bus.emit(CruxEvent::AuditStep {
        node_id: node.node_id.clone(),
        session_id: node.session_id.clone(),
        seq: node.seq,
    });
    Ok(rec.payload)
}

// ── M2: capture (open + close) ──────────────────────────────────────────────

// ── Redact-then-sign (M2) ─────────────────────────────────────────────────
//
// The observe ingest lane folds `inputs[]` / `outputs[]` into an Ed25519-signed,
// append-only hash chain. A secret signed into that chain cannot be retracted
// without breaking it (T.4-adjacent), so we mask secret patterns in each `ref`
// value **before** the node is built — redact-then-sign, never sign-then-regret.

/// Redaction mode for the observe lane. Fails safe toward redaction: default
/// `On` (mask before signing), decoupled from the log-sink `CORECRUXD_REDACT`
/// default (`Audit`). Lane-scoped override: `CORECRUXD_OBSERVE_REDACT =
/// off | audit | on` (anything else, or unset, ⇒ `On`).
fn observe_redact_mode() -> RedactMode {
    match std::env::var("CORECRUXD_OBSERVE_REDACT") {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "off" => RedactMode::Off,
            "audit" => RedactMode::Audit,
            _ => RedactMode::On,
        },
        Err(_) => RedactMode::On,
    }
}

/// Mask secret patterns in each input `ref`, in place (no-op in `Audit`/`Off`).
fn redact_input_refs(redactor: &Redactor, inputs: &mut [TraceInput]) {
    for input in inputs {
        if let Cow::Owned(masked) = redactor.redact_value(&input.reference) {
            input.reference = masked;
        }
    }
}

/// Mask secret patterns in each output `ref`, in place (no-op in `Audit`/`Off`).
fn redact_output_refs(redactor: &Redactor, outputs: &mut [TraceOutput]) {
    for output in outputs {
        if let Cow::Owned(masked) = redactor.redact_value(&output.reference) {
            output.reference = masked;
        }
    }
}

/// `POST /v1/observe/sessions/{id}/steps` — open a step.
///
/// Mints the monotonic `seq`, stamps `status = running`, and persists a new
/// `agent_trace_node`. The body supplies the opening facts (label, actor,
/// inputs, …); the response is the stored node.
pub(super) async fn open_step(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(mut body): Json<OpenStepBody>,
) -> Response {
    if !observe_enabled() {
        return observe_disabled();
    }
    if let Err(p) = require_http_any_scope(&state.auth, &headers, WRITE_SCOPES) {
        return p.into_response();
    }
    if body.actor.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "actor (passport) is required (T.3)");
    }
    if body.label.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "label is required");
    }

    // Redact-then-sign (M2): mask secrets in input refs before the node is
    // built and folded into the signed chain.
    redact_input_refs(&Redactor::with_mode(observe_redact_mode()), &mut body.inputs);

    let seq = next_seq(&state, &session_id).await;
    let node_id = body
        .node_id
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("trace_{session_id}_{seq}"));

    let node = TraceNode {
        contract_version: CONTRACT_VERSION,
        node_id,
        session_id,
        parent_id: body.parent_id,
        seq,
        kind: body.kind,
        label: body.label,
        actor: body.actor,
        risk_class: body.risk_class,
        ts_start: body.ts_start,
        ts_end: None,
        tokens: None,
        status: StepStatus::Running,
        inputs: body.inputs,
        reasoning_ref: None,
        outputs: vec![],
        receipt_id: None,
        enrich_ref: body.enrich_ref,
        private: body.private,
    };

    let actor = node.actor.clone();
    match upsert_node(&state, &node, &actor).await {
        Ok(payload) => (StatusCode::CREATED, Json(json!({ "node": payload }))).into_response(),
        Err(resp) => resp,
    }
}

/// `PATCH /v1/observe/sessions/{id}/steps/{node_id}` — close a step.
///
/// Appends `outputs`, sets `receipt_id` / `ts_end` / `status`, and optionally
/// records the `reasoning_ref` (M3). Back-fills `mutation_receipt_id` onto
/// mutating outputs that didn't carry their own, and stamps the step-level
/// `receipt_id` from `mutation_receipt_id` when none was supplied — so a
/// close that names one receipt yields a chain that passes `receipt_chain_ok`.
pub(super) async fn close_step(
    State(state): State<AppState>,
    Path((session_id, node_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<CloseStepBody>,
) -> Response {
    if !observe_enabled() {
        return observe_disabled();
    }
    if let Err(p) = require_http_any_scope(&state.auth, &headers, WRITE_SCOPES) {
        return p.into_response();
    }

    // Load the open node.
    let mut node = {
        let store = state.entity_store.read().await;
        match store
            .get(AGENT_TRACE_NODE_KIND, &node_id)
            .and_then(|r| node_from_payload(&r.payload))
        {
            Some(n) => n,
            None => {
                return problem_response(
                    StatusCode::NOT_FOUND,
                    format!("trace node {node_id} not found for session {session_id}"),
                )
            }
        }
    };
    if node.session_id != session_id {
        return problem_response(
            StatusCode::BAD_REQUEST,
            format!(
                "trace node {node_id} belongs to session {}, not {session_id}",
                node.session_id
            ),
        );
    }

    apply_close(&mut node, body);

    let actor = node.actor.clone();
    match upsert_node(&state, &node, &actor).await {
        Ok(payload) => (StatusCode::OK, Json(json!({ "node": payload }))).into_response(),
        Err(resp) => resp,
    }
}

/// Mutate `node` in place from a [`CloseStepBody`]. Pure (no IO) so the close
/// semantics are unit-testable without a daemon.
fn apply_close(node: &mut TraceNode, mut body: CloseStepBody) {
    // Redact-then-sign (M2): mask secrets in output refs before they are
    // appended to the node and re-folded into the signed chain.
    redact_output_refs(&Redactor::with_mode(observe_redact_mode()), &mut body.outputs);
    // Append outputs, back-filling a step receipt onto any mutating output
    // that lacks its own.
    for mut out in body.outputs {
        if out.is_mutation() && out.mutation_receipt_id.is_none() {
            out.mutation_receipt_id = body.mutation_receipt_id.clone().or_else(|| body.receipt_id.clone());
        }
        node.outputs.push(out);
    }
    if let Some(rid) = body.receipt_id {
        node.receipt_id = Some(rid);
    } else if node.receipt_id.is_none() {
        // No explicit step receipt: promote one so a single-receipt close still
        // satisfies the M6 chain check. Prefer the body's `mutation_receipt_id`,
        // else lift the first receipt any mutating output already carries.
        node.receipt_id = body.mutation_receipt_id.clone().or_else(|| {
            node.outputs
                .iter()
                .filter(|o| o.is_mutation())
                .find_map(|o| o.mutation_receipt_id.clone())
        });
    }
    if let Some(ts) = body.ts_end {
        node.ts_end = Some(ts);
    }
    if let Some(status) = body.status {
        node.status = status;
    }
    if let Some(r) = body.reasoning_ref {
        node.reasoning_ref = Some(r);
    }
    if let Some(e) = body.enrich_ref {
        node.enrich_ref = Some(e);
    }
}

// ── M4: reconstruction ──────────────────────────────────────────────────────

/// `GET /v1/observe/sessions/{id}/audit` — return the ordered audit chain for
/// one session, reconstructed from the `agent_trace_node` substrate.
pub(super) async fn get_session_audit(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !observe_enabled() {
        return observe_disabled();
    }
    if let Err(p) = require_http_any_scope(&state.auth, &headers, READ_SCOPES) {
        return p.into_response();
    }
    let steps: Vec<AuditStep> = session_nodes(&state, &id)
        .await
        .iter()
        .map(TraceNode::to_audit_step)
        .collect();
    let audit = SessionAudit {
        session_id: id,
        contract_version: CONTRACT_VERSION,
        steps,
    };
    (StatusCode::OK, Json(audit)).into_response()
}

// ── M5: verify + export ───────────────────────────────────────────────────

/// One receipt's verification line inside the export bundle.
#[derive(Debug, serde::Serialize)]
struct ReceiptVerification {
    /// The node whose chain this receipt belongs to.
    node_id: String,
    /// The receipt id (step-level or per-output).
    receipt_id: String,
    /// `true` only when the dataplane returned a verification report whose
    /// `ok`/`verified` flag is true. Absent dataplane → `false` with a reason.
    verified: bool,
    /// Why verification did/didn't happen (`"dataplane disabled"`, an error,
    /// or the report's own verdict).
    reason: String,
}

/// `GET /v1/observe/sessions/{id}/audit/export` — an EU-AI-Act conformance
/// bundle: the ordered steps, every receipt referenced by the chain, and a
/// best-effort dataplane verification per receipt.
///
/// Verification is best-effort: on a CPU-only node the dataplane is disabled,
/// so each receipt is reported `verified: false, reason: "dataplane disabled"`
/// rather than failing the export. The bundle's `conformance` block carries
/// the contract-level gate (`receipt_chain_ok` etc.) which does not require a
/// live dataplane.
pub(super) async fn get_session_audit_export(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !observe_enabled() {
        return observe_disabled();
    }
    if let Err(p) = require_http_any_scope(&state.auth, &headers, READ_SCOPES) {
        return p.into_response();
    }

    let nodes = session_nodes(&state, &id).await;
    let steps: Vec<AuditStep> = nodes.iter().map(TraceNode::to_audit_step).collect();

    // Every receipt the chain references, deduped, in chain order.
    let mut receipt_refs: Vec<(String, String)> = Vec::new(); // (node_id, receipt_id)
    for node in &nodes {
        if let Some(rid) = &node.receipt_id {
            receipt_refs.push((node.node_id.clone(), rid.clone()));
        }
        for out in &node.outputs {
            if let Some(rid) = &out.mutation_receipt_id {
                receipt_refs.push((node.node_id.clone(), rid.clone()));
            }
        }
    }
    receipt_refs.dedup();

    let dataplane_enabled = state.http_dataplane.enabled();
    let mut verifications: Vec<ReceiptVerification> = Vec::with_capacity(receipt_refs.len());
    for (node_id, receipt_id) in receipt_refs {
        let (verified, reason) = verify_one_receipt(&state, dataplane_enabled, &id, &receipt_id).await;
        verifications.push(ReceiptVerification {
            node_id,
            receipt_id,
            verified,
            reason,
        });
    }

    let report = conformance_report(&nodes);
    let bundle = json!({
        "schema": "crux.observe.audit_export.v1",
        "session_id": id,
        "contract_version": CONTRACT_VERSION,
        "ai_act_articles": ["9", "10", "12", "13", "15"],
        "steps": steps,
        "receipts": verifications,
        "dataplane_verification_available": dataplane_enabled,
        "conformance": report,
    });
    (StatusCode::OK, Json(bundle)).into_response()
}

/// Verify one receipt through the dataplane (the same call `receipts.rs` uses).
/// Returns `(verified, reason)`. Never errors out the export.
async fn verify_one_receipt(
    state: &AppState,
    dataplane_enabled: bool,
    tenant_id: &str,
    receipt_id: &str,
) -> (bool, String) {
    if !dataplane_enabled {
        return (false, "dataplane disabled".to_string());
    }
    match state
        .http_dataplane
        .verify_receipt_stream(tenant_id, receipt_id, None)
        .await
    {
        Ok(Some(report)) => match serde_json::to_value(&report) {
            Ok(v) => {
                let ok = v
                    .get("ok")
                    .and_then(Value::as_bool)
                    .or_else(|| v.get("verified").and_then(Value::as_bool))
                    .unwrap_or(false);
                (
                    ok,
                    if ok {
                        "verified by dataplane".into()
                    } else {
                        "dataplane report not ok".into()
                    },
                )
            }
            Err(e) => (false, format!("verification report encode failed: {e}")),
        },
        Ok(None) => (false, "receipt body not found".to_string()),
        Err(e) => (false, format!("dataplane verify error: {e:?}")),
    }
}

// ── M6: conformance ───────────────────────────────────────────────────────

/// Per-node conformance failure (enumerated, never silent).
#[derive(Debug, serde::Serialize, PartialEq, Eq)]
struct ConformanceFailure {
    node_id: String,
    seq: u64,
    /// One of `receipt_chain`, `attribution`, `enrich`.
    check: &'static str,
    detail: String,
}

/// Aggregate conformance verdict for a session.
#[derive(Debug, serde::Serialize, PartialEq, Eq)]
struct ConformanceReport {
    session_id: String,
    contract_version: u32,
    steps_total: usize,
    /// `true` only when every step passes all three contract gates.
    ok: bool,
    receipt_chain_ok: bool,
    attribution_ok: bool,
    enrich_ok: bool,
    failures: Vec<ConformanceFailure>,
}

/// Build the [`ConformanceReport`] for a set of nodes. Pure (no IO / no env)
/// so the M6 gate is unit-testable.
fn conformance_report(nodes: &[TraceNode]) -> ConformanceReport {
    let mut failures: Vec<ConformanceFailure> = Vec::new();
    for node in nodes {
        if !node.receipt_chain_ok() {
            failures.push(ConformanceFailure {
                node_id: node.node_id.clone(),
                seq: node.seq,
                check: "receipt_chain",
                detail: "mutation step missing a step or per-output CROWN receipt (R2 / Art. 12)".into(),
            });
        }
        if !node.is_attributed() {
            failures.push(ConformanceFailure {
                node_id: node.node_id.clone(),
                seq: node.seq,
                check: "attribution",
                detail: "node has a blank passport actor (T.3 / Art. 13)".into(),
            });
        }
        if !node.enrich_ok() {
            failures.push(ConformanceFailure {
                node_id: node.node_id.clone(),
                seq: node.seq,
                check: "enrich",
                detail: "high-risk node missing an enrich_ref (Art. 15)".into(),
            });
        }
    }
    let receipt_chain_ok = !failures.iter().any(|f| f.check == "receipt_chain");
    let attribution_ok = !failures.iter().any(|f| f.check == "attribution");
    let enrich_ok = !failures.iter().any(|f| f.check == "enrich");
    let session_id = nodes.first().map(|n| n.session_id.clone()).unwrap_or_default();
    ConformanceReport {
        session_id,
        contract_version: CONTRACT_VERSION,
        steps_total: nodes.len(),
        ok: failures.is_empty(),
        receipt_chain_ok,
        attribution_ok,
        enrich_ok,
        failures,
    }
}

/// `GET /v1/observe/sessions/{id}/audit/conformance` — assert the three M6
/// gates across the session, enumerating every failure.
pub(super) async fn get_session_audit_conformance(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !observe_enabled() {
        return observe_disabled();
    }
    if let Err(p) = require_http_any_scope(&state.auth, &headers, READ_SCOPES) {
        return p.into_response();
    }
    let nodes = session_nodes(&state, &id).await;
    let mut report = conformance_report(&nodes);
    // session_id from the path is authoritative even for an empty session.
    report.session_id = id;
    (StatusCode::OK, Json(report)).into_response()
}

// ── Tests ────────────────────────────────────────────────────────────────

// Handler tests toggle the process-global `CORECRUXD_OBSERVE` env var, so they
// serialise through a module mutex. Pure-logic tests (`apply_close`,
// `conformance_report`) need no env and run unguarded. Tests assert against
// hand-written values; expect/unwrap are panic-by-design here.
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::tests::test_app_state;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::Router;
    use crux_observe_api::{OutputKind, ReasoningRef};
    use std::sync::Mutex;
    use tower::ServiceExt;

    /// Serialises env-mutating handler tests (CORECRUXD_OBSERVE is process-global).
    static OBSERVE_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn router(state: AppState) -> Router {
        routes().with_state(state)
    }

    async fn json_body(resp: Response) -> Value {
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn mk_mutation_output(receipt: Option<&str>) -> TraceOutput {
        TraceOutput {
            kind: OutputKind::Write,
            reference: "src/x.rs".into(),
            added: Some(10),
            removed: Some(0),
            exit_code: None,
            mutation_receipt_id: receipt.map(String::from),
        }
    }

    fn running_node(node_id: &str, seq: u64) -> TraceNode {
        TraceNode {
            contract_version: CONTRACT_VERSION,
            node_id: node_id.into(),
            session_id: "s1".into(),
            parent_id: None,
            seq,
            kind: NodeKind::Step,
            label: "step".into(),
            actor: "ce:1:local".into(),
            risk_class: RiskClass::Low,
            ts_start: "2026-05-29T00:00:00Z".into(),
            ts_end: None,
            tokens: None,
            status: StepStatus::Running,
            inputs: vec![],
            reasoning_ref: None,
            outputs: vec![],
            receipt_id: None,
            enrich_ref: None,
            private: true,
        }
    }

    // ── Pure logic: apply_close ──────────────────────────────────────────

    #[test]
    fn apply_close_backfills_step_receipt_from_output() {
        let mut node = running_node("n1", 1);
        let body = CloseStepBody {
            outputs: vec![mk_mutation_output(Some("crn_1"))],
            ts_end: Some("2026-05-29T00:01:00Z".into()),
            status: Some(StepStatus::Ok),
            ..Default::default()
        };
        apply_close(&mut node, body);
        assert_eq!(node.status, StepStatus::Ok);
        assert_eq!(node.ts_end.as_deref(), Some("2026-05-29T00:01:00Z"));
        // A single per-output receipt is promoted to the step level so the
        // chain passes.
        assert_eq!(node.receipt_id.as_deref(), Some("crn_1"));
        assert!(node.is_mutation_step());
        assert!(node.receipt_chain_ok(), "single-receipt close yields a complete chain");
    }

    #[test]
    fn apply_close_backfills_output_receipt_from_mutation_receipt_id() {
        let mut node = running_node("n1", 1);
        let body = CloseStepBody {
            outputs: vec![mk_mutation_output(None)],
            mutation_receipt_id: Some("crn_2".into()),
            status: Some(StepStatus::Ok),
            ..Default::default()
        };
        apply_close(&mut node, body);
        assert_eq!(node.outputs[0].mutation_receipt_id.as_deref(), Some("crn_2"));
        assert_eq!(node.receipt_id.as_deref(), Some("crn_2"));
        assert!(node.receipt_chain_ok());
    }

    #[test]
    fn apply_close_records_reasoning_ref_only() {
        // The M3 reasoning pass patches only the reasoning_ref, leaving the
        // step otherwise untouched.
        let mut node = running_node("n1", 1);
        node.status = StepStatus::Ok;
        let body = CloseStepBody {
            reasoning_ref: Some(ReasoningRef::Blob("reasoning/n1.txt".into())),
            ..Default::default()
        };
        apply_close(&mut node, body);
        assert_eq!(node.reasoning_ref, Some(ReasoningRef::Blob("reasoning/n1.txt".into())));
        assert_eq!(node.status, StepStatus::Ok, "reasoning patch leaves status alone");
        assert!(node.outputs.is_empty());
    }

    // ── Pure logic: conformance_report ────────────────────────────────────

    #[test]
    fn conformance_passes_on_clean_chain() {
        let mut ok = running_node("n1", 1);
        ok.status = StepStatus::Ok;
        ok.outputs = vec![mk_mutation_output(Some("crn_1"))];
        ok.receipt_id = Some("crn_1".into());
        let report = conformance_report(&[ok]);
        assert!(report.ok);
        assert!(report.receipt_chain_ok && report.attribution_ok && report.enrich_ok);
        assert!(report.failures.is_empty());
        assert_eq!(report.steps_total, 1);
    }

    #[test]
    fn conformance_enumerates_each_failure_kind() {
        // Node missing its receipt → receipt_chain failure.
        let mut a = running_node("a", 1);
        a.outputs = vec![mk_mutation_output(None)];
        // Node with blank actor → attribution failure.
        let mut b = running_node("b", 2);
        b.actor = "   ".into();
        // High-risk node without enrich_ref → enrich failure.
        let mut c = running_node("c", 3);
        c.risk_class = RiskClass::High;

        let report = conformance_report(&[a, b, c]);
        assert!(!report.ok);
        assert!(!report.receipt_chain_ok);
        assert!(!report.attribution_ok);
        assert!(!report.enrich_ok);
        let checks: Vec<&str> = report.failures.iter().map(|f| f.check).collect();
        assert!(checks.contains(&"receipt_chain"));
        assert!(checks.contains(&"attribution"));
        assert!(checks.contains(&"enrich"));
        // receipt_chain failure (node a) carries the receipt-bearing node missing
        // its receipt — the per-output one is also absent → two failures? No: the
        // chain check is a single per-node gate, so exactly one receipt_chain
        // failure for node a.
        assert_eq!(report.failures.iter().filter(|f| f.check == "receipt_chain").count(), 1);
    }

    // ── Redact-then-sign (M2) ────────────────────────────────────────────

    const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

    #[test]
    fn redact_input_refs_masks_secret_when_on() {
        let mut inputs = vec![TraceInput::query(format!("grep for {AWS_KEY} in repo"), 1, 100)];
        redact_input_refs(&Redactor::with_mode(RedactMode::On), &mut inputs);
        assert!(
            !inputs[0].reference.contains(AWS_KEY),
            "secret must be masked before signing: {}",
            inputs[0].reference
        );
        assert!(inputs[0].reference.contains("REDACTED"));
    }

    #[test]
    fn redact_input_refs_passthrough_when_off() {
        let original = format!("grep for {AWS_KEY} in repo");
        let mut inputs = vec![TraceInput::query(original.clone(), 1, 100)];
        redact_input_refs(&Redactor::with_mode(RedactMode::Off), &mut inputs);
        assert_eq!(inputs[0].reference, original, "Off mode must not alter the value");
    }

    #[test]
    fn redact_input_refs_counts_but_keeps_value_in_audit() {
        // Audit = count-don't-alter: the value is unchanged so attribution
        // survives, but the hit is tallied (no masking).
        let original = format!("grep for {AWS_KEY} in repo");
        let mut inputs = vec![TraceInput::query(original.clone(), 1, 100)];
        redact_input_refs(&Redactor::with_mode(RedactMode::Audit), &mut inputs);
        assert_eq!(inputs[0].reference, original);
    }

    #[test]
    fn redact_output_refs_masks_secret_when_on() {
        let mut outputs = vec![TraceOutput {
            kind: OutputKind::Bash,
            reference: format!("aws configure set secret {AWS_KEY}"),
            added: None,
            removed: None,
            exit_code: Some(0),
            mutation_receipt_id: None,
        }];
        redact_output_refs(&Redactor::with_mode(RedactMode::On), &mut outputs);
        assert!(!outputs[0].reference.contains(AWS_KEY));
        assert!(outputs[0].reference.contains("REDACTED"));
    }

    #[test]
    fn apply_close_redacts_output_secret_before_chaining() {
        let _guard = OBSERVE_ENV_LOCK.lock().unwrap();
        std::env::set_var("CORECRUXD_OBSERVE_REDACT", "on");
        let mut node = running_node("n1", 1);
        let body = CloseStepBody {
            outputs: vec![TraceOutput {
                kind: OutputKind::Bash,
                reference: format!("curl -sS https://x/ && echo {AWS_KEY}"),
                added: None,
                removed: None,
                exit_code: Some(0),
                mutation_receipt_id: None,
            }],
            status: Some(StepStatus::Ok),
            ..Default::default()
        };
        apply_close(&mut node, body);
        std::env::remove_var("CORECRUXD_OBSERVE_REDACT");
        let stored = &node.outputs[0].reference;
        assert!(!stored.contains(AWS_KEY), "secret welded into node: {stored}");
        assert!(stored.contains("REDACTED"));
        // Redaction rewrites the ref before the node is (re)chained; a Bash
        // output is not a mutation, so the chain stays internally consistent.
        assert!(
            node.receipt_chain_ok(),
            "chain must still verify after redact-then-sign"
        );
    }

    #[test]
    #[serial_test::serial]
    fn observe_redact_mode_defaults_on_and_parses_overrides() {
        let _guard = OBSERVE_ENV_LOCK.lock().unwrap();
        std::env::remove_var("CORECRUXD_OBSERVE_REDACT");
        assert_eq!(
            observe_redact_mode(),
            RedactMode::On,
            "observe lane fails safe toward redaction"
        );
        std::env::set_var("CORECRUXD_OBSERVE_REDACT", "off");
        assert_eq!(observe_redact_mode(), RedactMode::Off);
        std::env::set_var("CORECRUXD_OBSERVE_REDACT", "audit");
        assert_eq!(observe_redact_mode(), RedactMode::Audit);
        std::env::set_var("CORECRUXD_OBSERVE_REDACT", "garbage");
        assert_eq!(observe_redact_mode(), RedactMode::On, "unknown values fail safe to On");
        std::env::remove_var("CORECRUXD_OBSERVE_REDACT");
    }

    // ── Handler: gating ───────────────────────────────────────────────────

    #[tokio::test]
    async fn audit_501_when_observe_disabled() {
        let _guard = OBSERVE_ENV_LOCK.lock().unwrap();
        std::env::remove_var("CORECRUXD_OBSERVE");
        let state = test_app_state(1);
        let resp = router(state)
            .oneshot(
                Request::builder()
                    .uri("/v1/observe/sessions/s1/audit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── Handler: open → reconstruct → close → reconstruct round-trip ──────

    #[tokio::test]
    async fn open_close_reconstruct_roundtrip() {
        let _guard = OBSERVE_ENV_LOCK.lock().unwrap();
        std::env::set_var("CORECRUXD_OBSERVE", "1");
        let state = test_app_state(1);
        crate::agentgraph_kinds::bootstrap(&mut *state.kind_registry.write().await).expect("bootstrap kinds");
        let app = router(state);

        // Open a step.
        let open_body = json!({
            "label": "Step 1 · write x",
            "actor": "ce:1:local",
            "risk_class": "medium",
            "ts_start": "2026-05-29T00:00:00Z",
            "inputs": [{ "type": "read", "ref": "src/x.rs", "lines": 12 }]
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/observe/sessions/sess-A/steps")
                    .header("content-type", "application/json")
                    .body(Body::from(open_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = json_body(resp).await;
        let node_id = body["node"]["node_id"].as_str().unwrap().to_string();
        assert_eq!(body["node"]["seq"], 1);
        assert_eq!(body["node"]["status"], "running");

        // Reconstruct → one running step.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/observe/sessions/sess-A/audit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let audit = json_body(resp).await;
        assert_eq!(audit["steps"].as_array().unwrap().len(), 1);
        assert_eq!(audit["steps"][0]["status"], "running");
        assert_eq!(audit["contract_version"], CONTRACT_VERSION);

        // Close the step with a mutation output + receipt.
        let close_body = json!({
            "outputs": [{ "type": "write", "ref": "src/x.rs", "added": 40, "removed": 0 }],
            "mutation_receipt_id": "crn_abc",
            "ts_end": "2026-05-29T00:01:00Z",
            "status": "ok"
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/v1/observe/sessions/sess-A/steps/{node_id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(close_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Reconstruct → step is ok and carries the receipt chain.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/observe/sessions/sess-A/audit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let audit = json_body(resp).await;
        assert_eq!(audit["steps"][0]["status"], "ok");
        assert_eq!(audit["steps"][0]["receipt_id"], "crn_abc");
        assert_eq!(audit["steps"][0]["outputs"][0]["mutation_receipt_id"], "crn_abc");

        // Conformance → clean.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/observe/sessions/sess-A/audit/conformance")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let conf = json_body(resp).await;
        assert_eq!(conf["ok"], true);
        assert_eq!(conf["steps_total"], 1);

        // Export → bundle with one receipt, dataplane unavailable on CPU node.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/observe/sessions/sess-A/audit/export")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bundle = json_body(resp).await;
        assert_eq!(bundle["schema"], "crux.observe.audit_export.v1");
        assert_eq!(bundle["receipts"].as_array().unwrap().len(), 1);
        assert_eq!(bundle["dataplane_verification_available"], false);
        assert_eq!(bundle["receipts"][0]["verified"], false);
        assert_eq!(bundle["receipts"][0]["reason"], "dataplane disabled");

        std::env::remove_var("CORECRUXD_OBSERVE");
    }

    #[tokio::test]
    async fn seq_is_monotonic_per_session() {
        let _guard = OBSERVE_ENV_LOCK.lock().unwrap();
        std::env::set_var("CORECRUXD_OBSERVE", "1");
        let state = test_app_state(1);
        crate::agentgraph_kinds::bootstrap(&mut *state.kind_registry.write().await).expect("bootstrap kinds");
        let app = router(state);

        let mut seqs = Vec::new();
        for i in 0..3 {
            let body =
                json!({ "label": format!("step {i}"), "actor": "ce:1:local", "ts_start": "2026-05-29T00:00:00Z" });
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/observe/sessions/sess-B/steps")
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let v = json_body(resp).await;
            seqs.push(v["node"]["seq"].as_u64().unwrap());
        }
        assert_eq!(seqs, vec![1, 2, 3], "seq must be monotonic per session");
        std::env::remove_var("CORECRUXD_OBSERVE");
    }

    #[tokio::test]
    async fn open_rejects_blank_actor() {
        let _guard = OBSERVE_ENV_LOCK.lock().unwrap();
        std::env::set_var("CORECRUXD_OBSERVE", "1");
        let state = test_app_state(1);
        crate::agentgraph_kinds::bootstrap(&mut *state.kind_registry.write().await).expect("bootstrap kinds");
        let app = router(state);
        let body = json!({ "label": "x", "actor": "  ", "ts_start": "2026-05-29T00:00:00Z" });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/observe/sessions/s/steps")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        std::env::remove_var("CORECRUXD_OBSERVE");
    }

    #[tokio::test]
    async fn close_unknown_node_is_404() {
        let _guard = OBSERVE_ENV_LOCK.lock().unwrap();
        std::env::set_var("CORECRUXD_OBSERVE", "1");
        let state = test_app_state(1);
        crate::agentgraph_kinds::bootstrap(&mut *state.kind_registry.write().await).expect("bootstrap kinds");
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/v1/observe/sessions/s/steps/nope")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        std::env::remove_var("CORECRUXD_OBSERVE");
    }
}
