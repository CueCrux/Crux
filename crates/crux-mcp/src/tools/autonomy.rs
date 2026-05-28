// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `autonomy_contract` — visible per-passport capability map.
//!
//! Master ExecPlan: `agent-ux-best-in-class-master-2026-05-27`,
//! child plan #10 — `agent-ux-10-visible-autonomy-contract-2026-05-27`.
//!
//! ## What this is
//!
//! A read-only metadata tool that enumerates every tool in the MCP
//! catalogue and, for the calling passport+token, returns whether the
//! tool is allowed, what scope it is bound to, and the cost class.
//!
//! The render is deliberately *passport-attributed*: the contract
//! reflects ONLY the calling passport's capabilities. It cannot
//! enumerate a different passport's matrix.
//!
//! ## Feature flag
//!
//! Gated by `CORECRUXD_FEATURE_AUTONOMY_CONTRACT=1`. Default OFF.
//!
//! ## Not envelope-wrapped
//!
//! `autonomy_contract` is metadata-only (it does not consult memories
//! or receipts); it deliberately does NOT opt into
//! [`crate::tools::tool_emits_envelope`]. A sibling dispatch test
//! (`envelope_omits_for_autonomy_contract`) protects this invariant.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::JsonRpcError;
use crux_router::{CallContext, RcxRouter, RouterDecision, RouterMode};

/// Environment variable that gates `autonomy_contract` emission. Default off.
///
/// Treat any value other than `"0"`, `"false"`, `"off"`, or empty as enabled.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_AUTONOMY_CONTRACT";

/// Return true if the feature flag is on.
pub fn autonomy_contract_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let trimmed = v.trim().to_ascii_lowercase();
            !matches!(trimmed.as_str(), "" | "0" | "false" | "off")
        }
        Err(_) => false,
    }
}

/// Public-facing description for the MCP `tools/list` catalogue.
pub const AUTONOMY_CONTRACT_DESCRIPTION: &str = concat!(
    "Return the calling passport's autonomy contract: a per-tool matrix of {allowed, scope, ",
    "cost_credits, why_denied?} reflecting the current RCX capability token. Metadata-only — does ",
    "not read memories. Reserved-prefix tools are marked `allowed:false` with `why_denied:",
    "\"reserved-prefix tool\"` for non-operator callers. Gated by ",
    "CORECRUXD_FEATURE_AUTONOMY_CONTRACT=1 (default off). Passport-attributed: the response ",
    "reflects ONLY the calling passport's capabilities; you cannot enumerate someone else's. ",
    "Pass `token_budget` (QC.2) to cap response size."
);

/// Tool input JSON-Schema.
pub fn tool_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "token_budget": {
                "type": "integer",
                "minimum": 1,
                "description": "Mandatory cap on the response size (QC.2). Approximate; ignored when 0."
            }
        },
        "additionalProperties": false,
        "examples": [
            { "token_budget": 4000 },
            { "token_budget": 2000 }
        ]
    })
}

/// A single tool capability row in the per-passport autonomy contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRow {
    /// MCP tool name.
    pub name: String,
    /// Whether the calling passport+token may invoke the tool.
    pub allowed: bool,
    /// Capability string the router decision was made against
    /// (e.g. `crux-mcp.store_fact`, `corecrux.query.local`).
    pub scope: String,
    /// Backend the tool would be dispatched to (`local`, hosted backend id, …).
    pub backend_id: String,
    /// Router mode that would apply if the tool were called now
    /// (`local`, `hosted`, `degraded-local`, `degraded-queued`, `refused`).
    pub mode: String,
    /// Approximate credit cost class for the call. 0 for local/no-cost tools.
    pub cost_credits: u64,
    /// Plain-English reason the call would be refused (None when allowed).
    /// Examples: `"reserved-prefix tool"`, `"denied:capability_not_permitted"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why_denied: Option<String>,
}

/// Reserved tool-name prefixes that are operator/agent-only and must be
/// rendered as `allowed:false` for any caller that isn't an operator.
///
/// At present the public MCP catalogue has no `__agent::*`/`__ops::*` tool
/// names (those prefixes scope facts, not tools), but the constraint is
/// declared here so a future operator-only tool stays denied by default.
pub const RESERVED_TOOL_PREFIXES: &[&str] = &["__agent::", "__ops::", "__bootstrap__::"];

/// Return true if the tool name begins with a reserved prefix.
pub fn is_reserved_tool_name(name: &str) -> bool {
    RESERVED_TOOL_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

/// Build an autonomy-contract row for a single tool against the supplied
/// router. The router's `decide` API is the authoritative source — this
/// function only enumerates; it does NOT re-implement decision policy
/// (anti-collision rule from child plan #10).
pub fn capability_row_for(
    tool_name: &str,
    router: &RcxRouter,
    now_unix_seconds: u64,
    is_operator: bool,
) -> CapabilityRow {
    let capability = super::rcx_mcp_tool_capability(tool_name);
    let scope = capability.capability.clone();
    let backend_id = capability.backend_id.clone();

    // Reserved-prefix tools are denied for non-operator callers regardless
    // of token grant (T.1). This is metadata-only enforcement — the
    // dispatcher already refuses these tools through other paths; the
    // contract MUST mirror that posture so the user-visible map matches
    // reality.
    if is_reserved_tool_name(tool_name) && !is_operator {
        return CapabilityRow {
            name: tool_name.to_string(),
            allowed: false,
            scope,
            backend_id,
            mode: RouterMode::Refused.as_str().to_string(),
            cost_credits: 0,
            why_denied: Some("reserved-prefix tool".to_string()),
        };
    }

    let decision: RouterDecision = router.decide(
        &CallContext {
            capability: capability.capability.clone(),
            preferred_backend: Some(capability.backend_id.clone()),
            data_egress_classes: capability.data_egress_classes.clone(),
            present_attestations: Vec::new(),
            estimated_credit_cost: 0,
            backend_reachable: true,
        },
        now_unix_seconds,
    );

    let cost_credits = router
        .token()
        .backends
        .iter()
        .find(|b| b.backend_id == capability.backend_id)
        .and_then(|b| {
            b.permitted_capabilities
                .iter()
                .find(|c| c.capability == capability.capability)
        })
        .and_then(|c| c.credit_cost.as_ref().map(|cc| cc.cost))
        .unwrap_or(0);

    CapabilityRow {
        name: tool_name.to_string(),
        allowed: decision.authorised,
        scope,
        backend_id,
        mode: decision.mode.as_str().to_string(),
        cost_credits,
        why_denied: if decision.authorised {
            None
        } else {
            Some(decision.reason_code.unwrap_or_else(|| "denied".to_string()))
        },
    }
}

/// Build the full per-passport capability matrix by enumerating every tool
/// in [`super::list_tools`] and calling [`capability_row_for`].
///
/// This is the property the CI test `autonomy_contract_covers_all_tools`
/// pins down: any new tool added to the registry will appear here.
pub fn build_capability_matrix(router: &RcxRouter, now_unix_seconds: u64, is_operator: bool) -> Vec<CapabilityRow> {
    super::list_tools()
        .into_iter()
        .map(|t| capability_row_for(&t.name, router, now_unix_seconds, is_operator))
        .collect()
}

/// Approximate the encoded byte length of a serialised capability row.
/// Used to honour `token_budget` (QC.2) without serialising the full
/// matrix twice.
fn approx_row_tokens(row: &CapabilityRow) -> usize {
    // 4 chars-per-token is a conservative proxy used elsewhere in
    // crux-mcp; matches the convention in `envelope.rs`.
    let bytes = serde_json::to_string(row).map(|s| s.len()).unwrap_or(256);
    bytes.div_ceil(4)
}

/// Trim a matrix to honour `token_budget`. Always keeps at least the first
/// row (so the caller can see the format even at very low budgets) and
/// records the truncation in the response envelope.
fn apply_token_budget(rows: Vec<CapabilityRow>, token_budget: Option<u64>) -> (Vec<CapabilityRow>, usize) {
    let Some(budget) = token_budget else {
        return (rows, 0);
    };
    if budget == 0 {
        return (rows, 0);
    }
    let mut kept: Vec<CapabilityRow> = Vec::with_capacity(rows.len());
    let mut running: u64 = 0;
    let total = rows.len();
    for row in rows {
        let row_tokens = approx_row_tokens(&row) as u64;
        if !kept.is_empty() && running.saturating_add(row_tokens) > budget {
            break;
        }
        running = running.saturating_add(row_tokens);
        kept.push(row);
    }
    let truncated = total.saturating_sub(kept.len());
    (kept, truncated)
}

/// `autonomy_contract` handler.
///
/// Returns an MCP `content[0].text` JSON string with the matrix + a
/// `structuredContent` mirror for clients that prefer the typed shape.
#[allow(clippy::unused_async)] // Async required by MCP tool dispatch signature.
pub async fn handle_autonomy_contract(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !autonomy_contract_enabled() {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": "autonomy_contract is disabled. Set CORECRUXD_FEATURE_AUTONOMY_CONTRACT=1 to enable."
            }],
            "structuredContent": {
                "feature_enabled": false,
                "passport_id": null,
                "capabilities": [],
            }
        }));
    }

    // Mandatory `token_budget` per QC.2 — accept missing for cold-start
    // discovery but surface a hint when omitted.
    let token_budget: Option<u64> = args.get("token_budget").and_then(Value::as_u64).filter(|b| *b > 0);

    let Some(router) = ctx.rcx_router.as_ref() else {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": "autonomy_contract: no RCX router on this context — every tool would refuse."
            }],
            "structuredContent": {
                "feature_enabled": true,
                "passport_id": null,
                "capabilities": [],
                "note": "router_unavailable"
            }
        }));
    };

    let now_unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Operator-tier callers see reserved-prefix tools in their matrix; all
    // others see them as `allowed:false` with `why_denied: reserved-prefix
    // tool`. Operator-tier is the daemon-internal posture — public
    // callers always go through the non-operator path. We key off the
    // token's tier here since the public MCP surface has no `operator`
    // tier flag today; this is a deliberately conservative default.
    let is_operator = false;

    let token = router.token();
    let passport_id = token.subject.passport_fpr.clone();
    let tier = token.tier.as_str().to_string();

    let matrix = build_capability_matrix(router, now_unix_seconds, is_operator);
    let total_rows = matrix.len();
    let (rows, truncated) = apply_token_budget(matrix, token_budget);
    let allowed_count = rows.iter().filter(|r| r.allowed).count();
    let denied_count = rows.len().saturating_sub(allowed_count);

    let structured = json!({
        "feature_enabled": true,
        "passport_id": passport_id,
        "tier": tier,
        "token_id": token.token_id,
        "token_hash": token.token_hash_hex(),
        "capabilities": rows,
        "summary": {
            "total_tools": total_rows,
            "returned": rows.len(),
            "allowed": allowed_count,
            "denied": denied_count,
            "truncated_by_token_budget": truncated,
        }
    });

    let pretty = serde_json::to_string_pretty(&structured).unwrap_or_else(|_| "{}".to_string());

    Ok(json!({
        "content": [{
            "type": "text",
            "text": pretty,
        }],
        "structuredContent": structured,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;
    use crate::tools::list_tools;
    use crux_router::{mint_free_local_token, RcxRouter};
    use rcx_capability_token::{
        Backend, CreditCost, CreditCostUnit, CreditRefill, Credits, FallbackAction, FallbackPolicy, OverdraftPolicy,
        PermittedCapability, RcxTier, RCX_CT_SIGNATURE_LEN,
    };

    /// Serialize tests that mutate `FEATURE_FLAG_ENV` so they don't race
    /// each other across the tokio test runtime.
    fn env_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn local_only_router(passport: &str) -> RcxRouter {
        RcxRouter::new(mint_free_local_token(
            passport,
            "daemon_01HV0000000000000000000000",
            "default",
            crate::tools::rcx_local_capabilities(),
            1_776_989_600,
            1_780_143_200,
            [0x11; RCX_CT_SIGNATURE_LEN],
        ))
    }

    fn pro_hosted_router(passport: &str) -> RcxRouter {
        let mut token = mint_free_local_token(
            passport,
            "daemon_01HV0000000000000000000000",
            "default",
            crate::tools::rcx_local_capabilities(),
            1_776_989_600,
            1_780_143_200,
            [0x22; RCX_CT_SIGNATURE_LEN],
        );
        token.tier = RcxTier::Pro;
        token.credits = Credits {
            balance: Some(1_000),
            refill: CreditRefill {
                period: rcx_capability_token::RefillPeriod::Monthly,
                amount: Some(1_000),
            },
            overdraft: OverdraftPolicy::Forbid,
            overdraft_limit: None,
        };
        token.fallback = FallbackPolicy {
            on_backend_unreachable: FallbackAction::Queue,
            on_credits_exhausted: FallbackAction::Refuse,
            on_expiry: FallbackAction::Refuse,
            queue_ttl_seconds: Some(120),
        };
        token.backends.push(Backend {
            backend_id: vaultcrux_local::tool_surface::HOSTED_BACKEND_ID.to_string(),
            trust_root_kid: "vaultcrux-hosted-root-v1".to_string(),
            endpoint_url: Some("https://hosted.vaultcrux.com".to_string()),
            permitted_capabilities: vaultcrux_local::tool_surface::hosted_gated_tool_names()
                .into_iter()
                .map(|tool_name| {
                    let tool = crate::tools::rcx_mcp_tool_capability(tool_name);
                    PermittedCapability {
                        capability: tool.capability,
                        data_egress_classes: tool.data_egress_classes,
                        required_attestations: Vec::new(),
                        credit_cost: Some(CreditCost {
                            unit: CreditCostUnit::Call,
                            cost: 1,
                        }),
                    }
                })
                .collect(),
        });
        RcxRouter::new(token)
    }

    #[tokio::test]
    async fn feature_flag_default_off() {
        let _g = env_lock().lock().await;
        std::env::remove_var(FEATURE_FLAG_ENV);
        assert!(!autonomy_contract_enabled());
    }

    #[tokio::test]
    async fn feature_flag_on_recognises_truthy_values() {
        let _g = env_lock().lock().await;
        for v in ["1", "true", "TRUE", "on", "yes"] {
            std::env::set_var(FEATURE_FLAG_ENV, v);
            assert!(autonomy_contract_enabled(), "value `{v}` should enable the feature");
        }
        for v in ["", "0", "false", "off"] {
            std::env::set_var(FEATURE_FLAG_ENV, v);
            assert!(
                !autonomy_contract_enabled(),
                "value `{v}` should NOT enable the feature"
            );
        }
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[test]
    fn autonomy_contract_covers_all_tools() {
        // Property test (Acceptance #1, #4): every tool in the catalogue
        // appears in the matrix exactly once. This is the CI tripwire that
        // forces new tool additions to make their autonomy-contract status
        // explicit — if you add a new tool without thinking about its
        // matrix entry, `build_capability_matrix` will still cover it
        // because the routing capability is derived deterministically from
        // the name, but this test pins the cardinality so silent drift
        // (e.g. someone accidentally short-circuits `list_tools()`) is
        // caught.
        let router = local_only_router("p_alice0000000000000000000000000a");
        let matrix = build_capability_matrix(&router, 1_776_989_601, false);
        let catalogue = list_tools();
        assert_eq!(
            matrix.len(),
            catalogue.len(),
            "matrix length must equal the tool catalogue length"
        );
        let matrix_names: std::collections::HashSet<&str> = matrix.iter().map(|r| r.name.as_str()).collect();
        for tool in &catalogue {
            assert!(
                matrix_names.contains(tool.name.as_str()),
                "matrix missing entry for tool `{}`",
                tool.name
            );
        }
    }

    #[test]
    fn local_tier_passport_denies_hosted_tools() {
        // Acceptance #2: a local-only passport sees hosted tools as
        // `allowed:false` with a non-empty `why_denied`.
        let router = local_only_router("p_alice0000000000000000000000000a");
        let matrix = build_capability_matrix(&router, 1_776_989_601, false);

        for hosted in ["sync_pull", "sync_push", "issue_passport"] {
            let row = matrix.iter().find(|r| r.name == hosted).expect(hosted);
            assert!(!row.allowed, "{hosted} must be denied for a local-only passport");
            assert!(row.why_denied.as_deref().is_some(), "{hosted} must include why_denied");
        }

        // …and at least one local tool is allowed.
        let q = matrix.iter().find(|r| r.name == "query").unwrap();
        assert!(q.allowed, "local-tier passport should be able to call `query`");
    }

    #[test]
    fn two_passports_get_two_different_matrices() {
        // Acceptance #3: cross-passport isolation. Two different passports
        // get two different contracts. We render Alice (local-only) vs Bob
        // (Pro hosted) and assert the matrices differ — specifically, that
        // a hosted tool flips from denied to allowed.
        let alice = local_only_router("p_alice0000000000000000000000000a");
        let bob = pro_hosted_router("p_bobbbbbbbbbbbbbbbbbbbbbbbbbbbb1");

        let now = 1_776_989_601;
        let alice_matrix = build_capability_matrix(&alice, now, false);
        let bob_matrix = build_capability_matrix(&bob, now, false);

        assert_eq!(
            alice_matrix.len(),
            bob_matrix.len(),
            "matrix length should match the catalogue regardless of passport"
        );

        let alice_pull = alice_matrix.iter().find(|r| r.name == "sync_pull").unwrap();
        let bob_pull = bob_matrix.iter().find(|r| r.name == "sync_pull").unwrap();
        assert!(!alice_pull.allowed, "alice (local) cannot sync_pull");
        assert!(bob_pull.allowed, "bob (pro hosted) can sync_pull");
        assert_ne!(
            alice_pull.allowed, bob_pull.allowed,
            "the contract must reflect passport-level differences"
        );

        // Token identities differ — the contract MUST be passport-attributed.
        assert_ne!(
            alice.token().token_id,
            bob.token().token_id,
            "test setup error: tokens must differ"
        );
    }

    #[test]
    fn reserved_prefix_tools_marked_denied_for_non_operator() {
        // T.1: if any tool name ever starts with `__agent::`, `__ops::`, or
        // `__bootstrap__::`, it MUST be `allowed:false` with
        // `why_denied: "reserved-prefix tool"` for the non-operator caller.
        let router = local_only_router("p_alice0000000000000000000000000a");
        let now = 1_776_989_601;

        // Synthetic check: capability_row_for is the per-tool entry point;
        // exercise it with a synthetic reserved-prefix name to pin the
        // policy invariant (defence-in-depth — there's no public reserved-
        // prefix tool today, but if one ships, the contract stays correct).
        let row = capability_row_for("__ops::dangerous_op", &router, now, false);
        assert!(!row.allowed);
        assert_eq!(row.why_denied.as_deref(), Some("reserved-prefix tool"));
        assert_eq!(row.mode, "refused");

        // …operator caller can see it (matrix-build escape hatch).
        let op_row = capability_row_for("__ops::dangerous_op", &router, now, true);
        // operator path still goes through the router, which will refuse on
        // capability_not_permitted (because the synthetic name isn't in
        // the token), but the `why_denied` should be the router reason,
        // NOT the reserved-prefix shortcut.
        assert!(!op_row.allowed);
        assert_ne!(op_row.why_denied.as_deref(), Some("reserved-prefix tool"));
    }

    #[tokio::test]
    async fn handler_returns_disabled_payload_when_flag_off() {
        let _g = env_lock().lock().await;
        std::env::remove_var(FEATURE_FLAG_ENV);
        let ctx = McpContext::new_default("test-node").with_rcx_router(local_only_router("p_alice"));
        let resp = handle_autonomy_contract(&json!({ "token_budget": 2000 }), &ctx)
            .await
            .unwrap();
        assert_eq!(resp["structuredContent"]["feature_enabled"], false);
        let text = resp["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("disabled"));
    }

    #[tokio::test]
    async fn handler_returns_matrix_when_flag_on() {
        let _g = env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        let ctx = McpContext::new_default("test-node").with_rcx_router(local_only_router("p_alice"));
        let resp = handle_autonomy_contract(&json!({ "token_budget": 16000 }), &ctx)
            .await
            .unwrap();
        let sc = &resp["structuredContent"];
        assert_eq!(sc["feature_enabled"], true);
        let total = sc["summary"]["total_tools"].as_u64().unwrap();
        assert!(total > 60, "expected the full catalogue, got {total}");
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn handler_truncates_under_low_token_budget() {
        let _g = env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        let ctx = McpContext::new_default("test-node").with_rcx_router(local_only_router("p_alice"));
        let resp = handle_autonomy_contract(&json!({ "token_budget": 100 }), &ctx)
            .await
            .unwrap();
        let sc = &resp["structuredContent"];
        let returned = sc["summary"]["returned"].as_u64().unwrap();
        let total = sc["summary"]["total_tools"].as_u64().unwrap();
        assert!(returned < total, "token_budget=100 should truncate the matrix");
        assert!(returned >= 1, "must always return at least one row");
        std::env::remove_var(FEATURE_FLAG_ENV);
    }
}
