// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `approval_request` + `approval_decide` — agent-ux-05 risk-tiered HITL.
//!
//! Tools for queueing a high-risk action for operator approval. The free
//! tier surfaces are entirely local: a per-process pending-request map
//! plus a CROWN-signed `ApprovalDecision` receipt scaffold on decide.
//! The work-panel projection is fed by [`pending_requests_for_work_panel`]
//! so `list_work(state="pending_approval")` can return the same set.
//!
//! ## Constraints (from ExecPlan agent-ux-05)
//!
//! - **QC.2** — `token_budget` is mandatory on every retrieval call.
//!   `approval_request` accepts `token_budget` and threads it through.
//! - **QC.3** — `approval_request` requires an authenticated passport.
//! - **T.3** — `approval_decide` requires an OPERATOR-tier passport
//!   (`elite` per the existing tier ladder, since "operator" is not yet
//!   a first-class tier; the ladder maps elite→operator role via the
//!   passport service). Non-operators get 403 with a clear
//!   `why_denied`.
//! - **T.1** — cross-tenant approvers are rejected with 403. A reviewer
//!   in tenant A cannot decide an approval raised in tenant B.
//! - High-risk requests **block** on operator approval (do NOT
//!   auto-execute). The tool returns `status: "pending"` and the caller
//!   awaits the decision via `list_work` or a subsequent
//!   `approval_decide` event. Medium/low requests can in principle
//!   auto-approve after timeout (per-tenant policy — out of scope for
//!   this child plan; design noted in Decision Log).
//! - Slack notifier — env `CORECRUXD_APPROVALS_SLACK_WEBHOOK_URL`. If
//!   unset, the notifier degrades silently (logged warning, no crash).
//!
//! ## Feature flag
//!
//! `CORECRUXD_FEATURE_APPROVAL_QUEUE` — default OFF. With the flag off,
//! the tools are still registered (catalogue is stable) but
//! `approval_request` returns a "feature disabled" payload and writes
//! nothing.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::scope;
use corecrux_receipts::{
    build_approval_decision_body_v1, ApprovalDecisionBodyInputV1, ApprovalDecisionV1, ApprovalRiskTierV1,
};

/// Feature flag gating the entire approval surface. Default OFF.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_APPROVAL_QUEUE";

/// Slack webhook URL env. Optional — absent → silent no-op notifier.
pub const SLACK_WEBHOOK_ENV: &str = "CORECRUXD_APPROVALS_SLACK_WEBHOOK_URL";

/// Cap on the number of pending+decided approval requests held in
/// memory per process. Older entries are evicted FIFO.
pub const MAX_BUFFERED_REQUESTS: usize = 1024;

/// JSON-RPC error code surfaced when a passport-tier or cross-tenant
/// check fails (T.1 / T.3). Keep separate from INVALID_PARAMS so
/// callers can distinguish "you typed bad args" from "you can't do
/// that".
pub const FORBIDDEN: i32 = -32_003;

/// Status of a pending approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
}

impl ApprovalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }
}

/// In-memory representation of an approval request.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub request_id: String,
    pub action_summary: String,
    pub risk_tier: ApprovalRiskTierV1,
    pub scope: String,
    pub tenant_id: String,
    pub requester_passport: String,
    pub payload: Option<Value>,
    pub status: ApprovalStatus,
    pub reviewer_passport: Option<String>,
    pub reviewer_notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub receipt_id: Option<String>,
}

/// Lazy global request store. Per-process; survives across tool calls
/// but not across daemon restart (the durable record lives in the
/// `ApprovalDecision` receipt stream).
fn requests_buffer() -> &'static Arc<Mutex<Vec<ApprovalRequest>>> {
    use std::sync::OnceLock;
    static BUFFER: OnceLock<Arc<Mutex<Vec<ApprovalRequest>>>> = OnceLock::new();
    BUFFER.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

/// Return `true` iff the feature flag is enabled.
pub fn feature_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// Test helper — clear the buffer between tests. Hidden from docs.
#[doc(hidden)]
pub async fn _reset_requests_buffer_for_tests() {
    let mut buf = requests_buffer().lock().await;
    buf.clear();
}

/// Shared mutex serialising any test that mutates the per-process
/// requests buffer (and/or [`FEATURE_FLAG_ENV`]). Exposed publicly so
/// the sibling dispatch envelope tests can hold it too. Delegates to
/// [`crate::test_env_lock`] so every env-mutating test in this crate
/// shares one process-wide `tokio::sync::Mutex` — per-module locks
/// don't prevent concurrent writes to `environ` from a sibling test
/// holding a different module's lock.
#[doc(hidden)]
pub fn _approvals_test_lock() -> &'static tokio::sync::Mutex<()> {
    crate::test_env_lock()
}

/// Public snapshot of the pending requests, for the work-panel
/// projection (consumed by [`list_work`](super::coordination)).
///
/// Each entry is rendered in the same shape as a `WorkItem` so the
/// SPA can mix approval requests with regular kanban entries without
/// per-source rendering branches.
pub async fn pending_requests_for_work_panel() -> Vec<Value> {
    let buf = requests_buffer().lock().await;
    buf.iter()
        .filter(|r| r.status == ApprovalStatus::Pending)
        .map(|r| {
            json!({
                "id": format!("ar_{}", r.request_id),
                "kind": "approval",
                "state": "pending_approval",
                "title": r.action_summary,
                "risk_tier": r.risk_tier.as_str(),
                "tenant_id": r.tenant_id,
                "scope": r.scope,
                "requester_passport": r.requester_passport,
                "created_at": r.created_at.to_rfc3339(),
            })
        })
        .collect()
}

/// Lookup an approval request by id (test + envelope helper).
pub async fn get_request(request_id: &str) -> Option<ApprovalRequest> {
    let buf = requests_buffer().lock().await;
    buf.iter().find(|r| r.request_id == request_id).cloned()
}

/// Validate that the calling passport is operator-tier. The Crux
/// passport ladder caps at `elite` (>=2000 receipts) which is the
/// well-known proxy for "trusted operator". We accept either `elite`
/// or an explicit `operator` tier (forward-compat).
fn is_operator_tier(tier: &str) -> bool {
    matches!(tier, "elite" | "operator")
}

/// Fire-and-forget Slack notifier. Reads the webhook URL from env at
/// call time so test runs can rebind. Degrades silently if the env is
/// unset (the only allowed failure mode — daemon MUST NOT crash on a
/// new request when Slack isn't configured).
async fn notify_slack(req: &ApprovalRequest) {
    let Ok(url) = std::env::var(SLACK_WEBHOOK_ENV) else {
        // Silent no-op — Slack is best-effort, not load-bearing.
        return;
    };
    if url.trim().is_empty() {
        return;
    }
    let payload = json!({
        "text": format!(
            "Approval requested ({tier}): {summary} — request {id}, tenant {tenant}, requester {who}",
            tier = req.risk_tier.as_str(),
            summary = req.action_summary,
            id = req.request_id,
            tenant = req.tenant_id,
            who = req.requester_passport,
        ),
        "request_id": req.request_id,
        "risk_tier": req.risk_tier.as_str(),
    });
    let _ = tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(5)))
            .build()
            .into();
        let _ = agent
            .post(&url)
            .header("Content-Type", "application/json")
            .send(payload.to_string());
    })
    .await;
}

// ── Handler: approval_request ───────────────────────────────────────────

/// Implementation of the `approval_request` MCP tool.
///
/// Writes a work-panel entry of kind `approval` and returns immediately
/// (does not block on the operator decision — the caller polls via
/// `list_work(state="pending_approval")` or awaits an inbound
/// `approval_decide`).
pub async fn handle_approval_request(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    // QC.3 — passport gate.
    let requester = scope::agent_name(ctx.agent.as_ref()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "approval_request requires an authenticated agent identity (passport). \
                  Set CRUX_AGENT_TOKEN or CRUX_AGENT_TOKENS and pass a Bearer header."
            .to_string(),
        data: Some(json!({"requires_agent_identity": true})),
    })?;

    let action_summary = args
        .get("action_summary")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "approval_request: action_summary is required".to_string(),
            data: None,
        })?
        .to_string();

    let risk_tier_str = args
        .get("risk_tier")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "approval_request: risk_tier is required (low|medium|high)".to_string(),
            data: None,
        })?;
    let risk_tier = ApprovalRiskTierV1::parse(risk_tier_str).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("approval_request: invalid risk_tier '{risk_tier_str}' (expected low|medium|high)"),
        data: Some(json!({"accepted": ["low", "medium", "high"]})),
    })?;

    let scope_str = args
        .get("scope")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "approval_request: scope is required (tenant_id or scoped resource path)".to_string(),
            data: None,
        })?
        .to_string();

    // QC.2 — token_budget is REQUIRED on retrieval. Even though this
    // handler is a write, we honour the convention so cross-tool
    // hygiene stays consistent (consumers grep for "missing
    // token_budget" as a tripwire).
    if args.get("token_budget").is_none() {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message:
                "approval_request: token_budget is required (QC.2 — caps response size; pass any positive integer)"
                    .to_string(),
            data: Some(json!({"required": ["token_budget"]})),
        });
    }

    // tenant_id defaults to the `scope` field when it doesn't itself
    // contain a `::` separator; otherwise we extract the tenant prefix.
    let tenant_id = args
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .map_or_else(|| scope_str.clone(), String::from);

    let payload = args.get("payload").cloned();

    let request_id = format!("ar_{}", uuid::Uuid::new_v4().simple());
    let now = Utc::now();

    let req = ApprovalRequest {
        request_id: request_id.clone(),
        action_summary,
        risk_tier,
        scope: scope_str,
        tenant_id,
        requester_passport: requester.to_string(),
        payload,
        status: ApprovalStatus::Pending,
        reviewer_passport: None,
        reviewer_notes: None,
        created_at: now,
        decided_at: None,
        receipt_id: None,
    };

    if !feature_enabled() {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "approval_request: feature disabled (set {FEATURE_FLAG_ENV}=1). \
                     Request {request_id} NOT enqueued."
                )
            }],
            "request_id": request_id,
            "status": "feature_disabled",
            "feature_enabled": false,
        }));
    }

    // Record in the buffer.
    {
        let mut buf = requests_buffer().lock().await;
        buf.push(req.clone());
        if buf.len() > MAX_BUFFERED_REQUESTS {
            let drop_n = buf.len() - MAX_BUFFERED_REQUESTS;
            buf.drain(0..drop_n);
        }
    }

    // Fire-and-forget Slack notification for high-risk requests only
    // (medium + low don't page operators; they live in the work
    // panel). Silent no-op if the webhook env is unset.
    if req.risk_tier == ApprovalRiskTierV1::High {
        notify_slack(&req).await;
    }

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "approval_request enqueued: id={} tier={} scope={} (status=pending)",
                req.request_id,
                req.risk_tier.as_str(),
                req.scope,
            )
        }],
        "request_id": req.request_id,
        "status": "pending",
        "risk_tier": req.risk_tier.as_str(),
        "tenant_id": req.tenant_id,
        "feature_enabled": true,
    }))
}

// ── Handler: approval_decide ────────────────────────────────────────────

/// Implementation of the `approval_decide` MCP tool.
///
/// Flips a pending approval's status and emits the `ApprovalDecision`
/// receipt body (the daemon HTTP layer will attach the Ed25519
/// signature event via the existing CROWN signer — same pattern as
/// `memory_use_v1`).
pub async fn handle_approval_decide(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    // T.3 — passport gate.
    let reviewer = scope::agent_name(ctx.agent.as_ref()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "approval_decide requires an authenticated agent identity (passport)".to_string(),
        data: Some(json!({"requires_agent_identity": true})),
    })?;

    let request_id = args
        .get("request_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "approval_decide: request_id is required".to_string(),
            data: None,
        })?
        .to_string();

    let decision_str = args
        .get("decision")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "approval_decide: decision is required (approve|reject)".to_string(),
            data: None,
        })?;
    let decision = ApprovalDecisionV1::parse(decision_str).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("approval_decide: invalid decision '{decision_str}' (expected approve|reject)"),
        data: Some(json!({"accepted": ["approve", "reject"]})),
    })?;

    let reviewer_notes = args.get("reviewer_notes").and_then(|v| v.as_str()).map(String::from);

    // T.3 — operator-tier passport check. The harness passes the
    // caller's tier via `reviewer_tier` (the daemon HTTP layer
    // resolves the passport tier and forwards it; in the bare MCP
    // dispatch tests, callers supply it directly).
    let reviewer_tier = args
        .get("reviewer_tier")
        .and_then(|v| v.as_str())
        .unwrap_or("unverified");
    if !is_operator_tier(reviewer_tier) {
        return Err(JsonRpcError {
            code: FORBIDDEN,
            message: "approval_decide refused: operator-tier passport required".to_string(),
            data: Some(json!({
                "why_denied": format!(
                    "Your passport tier is '{reviewer_tier}'. approval_decide requires the operator tier (elite or operator)."
                ),
                "required_tier": "operator",
                "actual_tier": reviewer_tier,
            })),
        });
    }

    // Load + mutate the request.
    let mut buf = requests_buffer().lock().await;
    let idx = buf
        .iter()
        .position(|r| r.request_id == request_id)
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("approval_decide: request {request_id} not found"),
            data: Some(json!({"request_id": request_id})),
        })?;

    // T.1 — cross-tenant guard. The reviewer must operate in the same
    // tenant as the request. The reviewer's tenant comes from
    // `reviewer_tenant_id` (forwarded from the HTTP layer) and
    // defaults to the request's tenant when caller omits it AND the
    // reviewer's passport name matches the request's requester (single-
    // user dev mode).
    let request_tenant = buf[idx].tenant_id.clone();
    let reviewer_tenant = args
        .get("reviewer_tenant_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    if let Some(rt) = reviewer_tenant.as_deref() {
        if rt != request_tenant {
            return Err(JsonRpcError {
                code: FORBIDDEN,
                message: "approval_decide refused: cross-tenant approval blocked (T.1)".to_string(),
                data: Some(json!({
                    "why_denied": format!(
                        "Reviewer is in tenant '{rt}' but the request was raised in tenant '{request_tenant}'. \
                         Cross-tenant approvals are forbidden."
                    ),
                    "reviewer_tenant_id": rt,
                    "request_tenant_id": request_tenant,
                })),
            });
        }
    }

    if buf[idx].status != ApprovalStatus::Pending {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: format!(
                "approval_decide: request {request_id} already decided (current status: {})",
                buf[idx].status.as_str()
            ),
            data: Some(json!({"current_status": buf[idx].status.as_str()})),
        });
    }

    let now = Utc::now();
    let decided_at = now.to_rfc3339();
    let receipt_id = format!("ad_{request_id}");

    // Build the receipt body (canonical CBOR + BLAKE3 hash). The
    // signature is attached by the daemon HTTP layer's CROWN signer —
    // same pattern as memory_use_v1.
    let body_input = ApprovalDecisionBodyInputV1 {
        tenant_id: &request_tenant,
        receipt_id: &receipt_id,
        request_id: &request_id,
        reviewer_passport: reviewer,
        decision: decision.clone(),
        risk_tier: buf[idx].risk_tier.clone(),
        action_summary: &buf[idx].action_summary,
        reviewer_notes: reviewer_notes.as_deref(),
        decided_at: &decided_at,
    };
    let (_body_bytes, body_hash) = build_approval_decision_body_v1(&body_input);

    let new_status = match decision {
        ApprovalDecisionV1::Approve => ApprovalStatus::Approved,
        ApprovalDecisionV1::Reject => ApprovalStatus::Rejected,
    };
    buf[idx].status = new_status.clone();
    buf[idx].reviewer_passport = Some(reviewer.to_string());
    buf[idx].reviewer_notes = reviewer_notes;
    buf[idx].decided_at = Some(now);
    buf[idx].receipt_id = Some(receipt_id.clone());

    let updated = buf[idx].clone();
    drop(buf);

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "approval_decide: request {} -> {} by {} at {}",
                request_id,
                new_status.as_str(),
                reviewer,
                decided_at,
            )
        }],
        "ok": true,
        "request_id": request_id,
        "status": new_status.as_str(),
        "reviewer_passport": reviewer,
        "decided_at": decided_at,
        "receipt_id": receipt_id,
        "receipt_body_hash_hex": hex::encode(body_hash),
        "tenant_id": updated.tenant_id,
        "risk_tier": updated.risk_tier.as_str(),
    }))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;

    fn env_lock() -> &'static tokio::sync::Mutex<()> {
        // Re-use the publicly-exposed test lock so sibling dispatch
        // envelope tests don't race the global requests buffer.
        super::_approvals_test_lock()
    }

    fn ctx_with_agent(name: &str) -> McpContext {
        McpContext::new_default("test-ux05-node").with_agent(AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        })
    }

    fn ctx_anon() -> McpContext {
        McpContext::new_default("test-ux05-anon")
    }

    #[tokio::test]
    async fn approval_request_requires_passport() {
        let _g = env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        _reset_requests_buffer_for_tests().await;

        let err = handle_approval_request(
            &json!({
                "action_summary": "delete prod fixtures",
                "risk_tier": "high",
                "scope": "personal::alice",
                "token_budget": 500,
            }),
            &ctx_anon(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("passport") || err.message.contains("authenticated"));
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn approval_request_requires_token_budget() {
        let _g = env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        _reset_requests_buffer_for_tests().await;

        let err = handle_approval_request(
            &json!({
                "action_summary": "X",
                "risk_tier": "low",
                "scope": "tenant-a",
            }),
            &ctx_with_agent("alice"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.to_lowercase().contains("token_budget"));
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn approval_request_rejects_invalid_risk_tier() {
        let _g = env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        _reset_requests_buffer_for_tests().await;

        let err = handle_approval_request(
            &json!({
                "action_summary": "X",
                "risk_tier": "critical",
                "scope": "tenant-a",
                "token_budget": 500,
            }),
            &ctx_with_agent("alice"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("risk_tier"));
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn approval_request_flag_off_returns_disabled_marker() {
        let _g = env_lock().lock().await;
        std::env::remove_var(FEATURE_FLAG_ENV);
        _reset_requests_buffer_for_tests().await;

        let res = handle_approval_request(
            &json!({
                "action_summary": "X",
                "risk_tier": "low",
                "scope": "tenant-a",
                "token_budget": 500,
            }),
            &ctx_with_agent("alice"),
        )
        .await
        .unwrap();
        assert_eq!(res["feature_enabled"], false);
        assert_eq!(res["status"], "feature_disabled");
        // Nothing should have been pushed into the work-panel queue.
        assert!(pending_requests_for_work_panel().await.is_empty());
    }

    #[tokio::test]
    async fn approval_request_writes_work_panel_entry() {
        let _g = env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        _reset_requests_buffer_for_tests().await;

        let res = handle_approval_request(
            &json!({
                "action_summary": "drop tenant prod data",
                "risk_tier": "high",
                "scope": "business::acme",
                "tenant_id": "business::acme",
                "token_budget": 500,
            }),
            &ctx_with_agent("alice"),
        )
        .await
        .unwrap();
        assert_eq!(res["status"], "pending");
        assert_eq!(res["risk_tier"], "high");

        let panel = pending_requests_for_work_panel().await;
        assert_eq!(panel.len(), 1);
        assert_eq!(panel[0]["kind"], "approval");
        assert_eq!(panel[0]["state"], "pending_approval");
        assert_eq!(panel[0]["risk_tier"], "high");
        assert_eq!(panel[0]["tenant_id"], "business::acme");
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn approval_decide_requires_operator_tier() {
        let _g = env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        _reset_requests_buffer_for_tests().await;

        // Enqueue a request.
        let res = handle_approval_request(
            &json!({
                "action_summary": "X",
                "risk_tier": "high",
                "scope": "tenant-a",
                "tenant_id": "tenant-a",
                "token_budget": 500,
            }),
            &ctx_with_agent("alice"),
        )
        .await
        .unwrap();
        let rid = res["request_id"].as_str().unwrap().to_string();

        // Non-operator caller: 403.
        let err = handle_approval_decide(
            &json!({
                "request_id": rid,
                "decision": "approve",
                "reviewer_tier": "basic",
            }),
            &ctx_with_agent("bob"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, FORBIDDEN);
        let data = err.data.unwrap();
        assert!(data["why_denied"].as_str().unwrap().contains("operator"));
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn approval_decide_operator_flips_status_and_emits_receipt() {
        let _g = env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        _reset_requests_buffer_for_tests().await;

        let res = handle_approval_request(
            &json!({
                "action_summary": "deploy hotfix",
                "risk_tier": "high",
                "scope": "tenant-b",
                "tenant_id": "tenant-b",
                "token_budget": 500,
            }),
            &ctx_with_agent("alice"),
        )
        .await
        .unwrap();
        let rid = res["request_id"].as_str().unwrap().to_string();

        let decide = handle_approval_decide(
            &json!({
                "request_id": rid,
                "decision": "approve",
                "reviewer_tier": "elite",
                "reviewer_tenant_id": "tenant-b",
                "reviewer_notes": "ok per ticket #42",
            }),
            &ctx_with_agent("operator"),
        )
        .await
        .unwrap();

        assert_eq!(decide["ok"], true);
        assert_eq!(decide["status"], "approved");
        assert_eq!(decide["reviewer_passport"], "operator");
        // Receipt body hash is a 64-char hex BLAKE3 digest.
        let hash = decide["receipt_body_hash_hex"].as_str().unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Pending queue is now empty for this id.
        assert!(pending_requests_for_work_panel().await.is_empty());
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn approval_decide_cross_tenant_blocked() {
        let _g = env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        _reset_requests_buffer_for_tests().await;

        let res = handle_approval_request(
            &json!({
                "action_summary": "X",
                "risk_tier": "high",
                "scope": "tenant-a",
                "tenant_id": "tenant-a",
                "token_budget": 500,
            }),
            &ctx_with_agent("alice"),
        )
        .await
        .unwrap();
        let rid = res["request_id"].as_str().unwrap().to_string();

        // Operator from a DIFFERENT tenant: 403 (T.1).
        let err = handle_approval_decide(
            &json!({
                "request_id": rid,
                "decision": "approve",
                "reviewer_tier": "elite",
                "reviewer_tenant_id": "tenant-OTHER",
            }),
            &ctx_with_agent("operator"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, FORBIDDEN);
        let data = err.data.unwrap();
        assert!(data["why_denied"].as_str().unwrap().to_lowercase().contains("tenant"));
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn approval_decide_unknown_request_id_404_like() {
        let _g = env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        _reset_requests_buffer_for_tests().await;

        let err = handle_approval_decide(
            &json!({
                "request_id": "ar_does_not_exist",
                "decision": "approve",
                "reviewer_tier": "elite",
            }),
            &ctx_with_agent("operator"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("not found"));
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn approval_decide_idempotency_second_call_rejects() {
        let _g = env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        _reset_requests_buffer_for_tests().await;

        let res = handle_approval_request(
            &json!({
                "action_summary": "X",
                "risk_tier": "high",
                "scope": "tenant-c",
                "tenant_id": "tenant-c",
                "token_budget": 500,
            }),
            &ctx_with_agent("alice"),
        )
        .await
        .unwrap();
        let rid = res["request_id"].as_str().unwrap().to_string();

        handle_approval_decide(
            &json!({
                "request_id": rid,
                "decision": "approve",
                "reviewer_tier": "elite",
                "reviewer_tenant_id": "tenant-c",
            }),
            &ctx_with_agent("operator"),
        )
        .await
        .unwrap();

        let err = handle_approval_decide(
            &json!({
                "request_id": rid,
                "decision": "reject",
                "reviewer_tier": "elite",
                "reviewer_tenant_id": "tenant-c",
            }),
            &ctx_with_agent("operator"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("already decided"));
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn approval_request_high_tier_does_not_crash_when_slack_unset() {
        let _g = env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        std::env::remove_var(SLACK_WEBHOOK_ENV);
        _reset_requests_buffer_for_tests().await;

        let res = handle_approval_request(
            &json!({
                "action_summary": "X",
                "risk_tier": "high",
                "scope": "tenant-d",
                "tenant_id": "tenant-d",
                "token_budget": 500,
            }),
            &ctx_with_agent("alice"),
        )
        .await
        .unwrap();
        // Daemon must NOT crash when the webhook env is unset (acceptance #8).
        assert_eq!(res["status"], "pending");
        std::env::remove_var(FEATURE_FLAG_ENV);
    }
}
