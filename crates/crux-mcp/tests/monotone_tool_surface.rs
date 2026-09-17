// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! M1 gate for ExecPlan `crux-prompt-cache-1h-ttl-2026-09-17`: the offered tool
//! set is monotone per MCP session.
//!
//! Claude Code caches the prompt prefix with a 1-hour TTL. A `tools/list` that
//! returns a PROPER SUBSET of what the same `Mcp-Session-Id` already saw
//! invalidates that prefix and the whole conversation is re-billed at 2x. On
//! corpus `drivew-host-claude-transcripts-2026-09` three such events rewrote
//! ~1.1M tokens; the largest single one (11 tools removed) rewrote 311,754.
//!
//! This drives the full sequence the gate names — `initialize` → `tools/list` →
//! `cuecrux_session(intent=…)` → `tools/list` → clock past
//! `INTENT_TTL_SECONDS` → `tools/list` → 50 mixed `tools/call`s → `tools/list`
//! → RCX token expiry → `tools/list` — and asserts at EVERY step that the
//! returned set is a superset of every set returned before it, that
//! `agent.tools_offered.v1.removed` is empty, and that a `list_changed` frame
//! is warranted only when the set grew.
//!
//! The clock is injected (`list_tools_json_with_mode_and_delta` takes the
//! request clock, and `surface::current_intent` reads expiry off it), so the
//! TTL edge is crossed in microseconds rather than by sleeping an hour.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crux_mcp::agent::AgentIdentity;
use crux_mcp::dispatch::{dispatch, McpContext, CAPABILITY_DENIED};
use crux_mcp::ledger::{build_tools_offered_body, offered_set_hash};
use crux_mcp::protocol::JsonRpcRequest;
use crux_mcp::tools::surface::{OfferedDelta, ToolSurfaceMode, INTENT_TTL_SECONDS};
use crux_mcp::tools::{list_tools_json_with_mode_and_delta, rcx_local_capabilities, surface, surface_session_key};
use crux_router::{mint_free_local_token, RcxRouter};
use ed25519_dalek::{Signer, SigningKey};
use rcx_capability_token::RCX_CT_SIGNATURE_LEN;
use serde_json::{json, Value};

const SESSION_ID: &str = "gate-monotone-surface-01HV000000000000000000";
const PASSPORT: &str = "p_0123456789abcdef0123456789abcdef";
/// The intent store and the trace ring are process-global and keyed by
/// passport. The gate drives an agent of its own so its declared intent and its
/// 50 calls cannot bleed into a sibling test's surface (or vice versa).
const GATE_AGENT: &str = "__gate_monotone_surface__";

/// How long the gate's RCX capability token stays valid from `t0`.
const TOKEN_LIFETIME_SECONDS: u64 = 600;

/// `t0` is the real wall clock, because `tools/call` validates the RCX token
/// against `SystemTime::now()` — only the `tools/list` clock is injectable. The
/// listing clock is then driven forward from `t0` past both the token expiry and
/// `INTENT_TTL_SECONDS`, which is what makes the hour-long TTL edge testable in
/// microseconds.
fn t0() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn rpc(method: &str, params: Value) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: method.to_string(),
        params,
    }
}

/// A context for one MCP session, carrying an RCX capability token that is
/// valid until [`TOKEN_EXPIRES_AT`]. Every listing in the gate uses the same
/// `Mcp-Session-Id`, which is what the monotone union is keyed by.
fn session_ctx(t0: u64) -> McpContext {
    let signing = SigningKey::from_bytes(&[42u8; 32]);
    let mut token = mint_free_local_token(
        PASSPORT,
        "daemon_01HV0000000000000000000000",
        "default",
        rcx_local_capabilities(),
        t0.saturating_sub(100),
        t0 + TOKEN_LIFETIME_SECONDS,
        [0x11; RCX_CT_SIGNATURE_LEN],
    );
    token.signature.sig = signing.sign(&token.token_hash()).to_bytes();
    McpContext::new_default("gate-node")
        .with_rcx_router(RcxRouter::new_with_trusted_issuer_pubkey(
            token,
            signing.verifying_key().to_bytes(),
        ))
        .with_agent(AgentIdentity {
            name: GATE_AGENT.to_string(),
            token_hash: [0u8; 32],
        })
        // `cuecrux_session` refuses before it records the intent when no daemon
        // is wired, so point it at the discard port: the intent lands, the
        // loopback fails instantly with ECONNREFUSED, and the surface signal is
        // exercised exactly as it is in production.
        .with_daemon_base_url("http://127.0.0.1:9")
        .with_mcp_session_id(SESSION_ID)
}

fn names_of(listing: &Value) -> Vec<String> {
    listing["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t["name"].as_str().map(String::from))
        .collect()
}

/// Every assertion the gate makes about one `tools/list`, applied in order.
struct SupersetLedger {
    /// Every set returned so far, oldest first.
    history: Vec<Vec<String>>,
}

impl SupersetLedger {
    fn new() -> Self {
        Self { history: Vec::new() }
    }

    /// Record one listing and assert the three M1 invariants against it.
    fn record(&mut self, step: &str, names: Vec<String>, delta: &OfferedDelta) {
        let current: HashSet<&str> = names.iter().map(String::as_str).collect();

        // (1) Superset of EVERY earlier set, not just the previous one.
        for (i, earlier) in self.history.iter().enumerate() {
            for tool in earlier {
                assert!(
                    current.contains(tool.as_str()),
                    "step `{step}`: tool `{tool}` was offered at step {i} and is missing now — \
                     a proper subset invalidates the client's cached prefix"
                );
            }
        }

        // (2) The ledger body the daemon emits must carry an empty `removed`.
        let hash = offered_set_hash(&names);
        let body = build_tools_offered_body(PASSPORT, &names, "dynamic", &hash, &delta.added, &delta.removed);
        assert_eq!(
            body["payload"]["removed"],
            json!([]),
            "step `{step}`: agent.tools_offered.v1.removed must always be empty"
        );
        assert_eq!(
            body["payload"]["count"].as_u64(),
            Some(names.len() as u64),
            "step `{step}`: ledger count must match the listing"
        );

        // (3) `grew` — the sole trigger for a `list_changed` push — is true iff
        // something was actually added.
        assert_eq!(
            delta.grew,
            !delta.added.is_empty(),
            "step `{step}`: list_changed must track actual growth"
        );
        if let Some(previous) = self.history.last() {
            let before: HashSet<&str> = previous.iter().map(String::as_str).collect();
            let genuinely_new = names.iter().any(|n| !before.contains(n.as_str()));
            assert_eq!(
                delta.grew, genuinely_new,
                "step `{step}`: `grew` must reflect the change against the previous listing"
            );
        }

        self.history.push(names);
    }

    fn last(&self) -> &[String] {
        self.history.last().map(Vec::as_slice).unwrap_or_default()
    }
}

async fn list_at(ctx: &McpContext, now: u64) -> (Vec<String>, OfferedDelta) {
    let (listing, delta) = list_tools_json_with_mode_and_delta(ctx, now, ToolSurfaceMode::Dynamic).await;
    (names_of(&listing), delta)
}

#[tokio::test(flavor = "multi_thread")]
async fn offered_tool_set_is_monotone_across_intent_ttl_traffic_and_token_expiry() {
    let t0 = t0();
    let ctx = session_ctx(t0);
    let session_key = surface_session_key(&ctx);
    assert_eq!(
        session_key,
        format!("mcp-session:{SESSION_ID}"),
        "the union must be keyed by Mcp-Session-Id, not by passport, when the transport supplies one"
    );

    let mut ledger = SupersetLedger::new();

    // ── initialize ────────────────────────────────────────────────────────
    let init = dispatch(rpc("initialize", json!({})), &ctx, None).await;
    let init_result = init.result.expect("initialize result");
    assert_eq!(
        init_result["capabilities"]["tools"]["listChanged"],
        json!(true),
        "the server advertises list_changed, so the push it sends must be worth acting on"
    );

    // ── step 1: first tools/list (cold — no intent, no traffic) ───────────
    let (first, d1) = list_at(&ctx, t0).await;
    ledger.record("initial tools/list", first.clone(), &d1);
    assert!(
        first.iter().any(|n| n == "cuecrux_session"),
        "the discovery entry point leads the floor"
    );
    assert!(d1.grew, "the first listing is all new");
    let cold_len = first.len();

    // ── step 2: declare an intent ─────────────────────────────────────────
    // `cuecrux_session` records the intent before it attempts its loopback
    // call, so the surface signal lands even with no daemon behind the test.
    let declared = dispatch(
        rpc(
            "tools/call",
            json!({"name": "cuecrux_session", "arguments": {"intent": "audit_review"}}),
        ),
        &ctx,
        None,
    )
    .await;
    assert!(
        declared.error.is_some(),
        "the loopback is deliberately unreachable here — only the recorded intent matters"
    );
    assert_eq!(
        surface::current_intent(GATE_AGENT, t0 as i64).as_deref(),
        Some("audit_review"),
        "the intent must be recorded against the caller's passport"
    );

    // ── step 3: tools/list with the intent live ───────────────────────────
    let (boosted, d3) = list_at(&ctx, t0).await;
    ledger.record("tools/list with live intent", boosted.clone(), &d3);
    assert!(
        boosted.len() > cold_len,
        "a declared intent should promote tools (got {} vs cold {cold_len})",
        boosted.len()
    );
    assert!(d3.grew, "the intent grew the set, so a list_changed push is warranted");
    let unoffered = ["github_search".to_string()];
    assert!(
        !boosted.contains(&unoffered[0]),
        "`github_search` carries no affinity for `audit_review`, so it is not offered yet"
    );
    assert!(
        surface::would_grow(&session_key, &unoffered),
        "a not-yet-offered tool would grow the union"
    );
    assert!(
        !surface::would_grow(&session_key, &boosted),
        "re-offering the same set must NOT trigger a push"
    );

    // ── step 4: advance past INTENT_TTL_SECONDS (injected clock) ──────────
    // `record_intent` stamps the wall clock, so the injected listing clock is
    // pushed a comfortable margin past the TTL rather than exactly one second —
    // otherwise the assertion races the elapsed test time.
    let expired_at = t0 + INTENT_TTL_SECONDS as u64 + 120;
    assert_eq!(
        surface::current_intent(GATE_AGENT, expired_at as i64),
        None,
        "the intent has stopped boosting"
    );
    let (after_ttl, d4) = list_at(&ctx, expired_at).await;
    ledger.record("tools/list after intent TTL expiry", after_ttl.clone(), &d4);
    assert_eq!(
        after_ttl, boosted,
        "intent expiry stops boosting — it must not take a single tool away"
    );
    assert!(!d4.grew, "nothing was added, so no list_changed push");

    // ── step 5: 50 mixed tools/call dispatches ────────────────────────────
    let mixed = [
        "sync_status",
        "get_agent_identity",
        "query_facts",
        "list_work",
        "coord_status",
        "get_gaps",
        "list_entities",
        "tool_trace_recent",
        "activity_recent",
        "list_sessions",
    ];
    for i in 0..50 {
        let tool = mixed[i % mixed.len()];
        let _ = dispatch(rpc("tools/call", json!({"name": tool, "arguments": {}})), &ctx, None).await;
    }
    let (after_traffic, d5) = list_at(&ctx, expired_at).await;
    ledger.record("tools/list after 50 mixed calls", after_traffic.clone(), &d5);
    assert!(
        after_traffic.len() >= after_ttl.len(),
        "trace boosts may promote, never demote"
    );

    // ── step 6: RCX token expiry ──────────────────────────────────────────
    // The free local token's `on_expiry` fallback is `Refuse`, so past
    // TOKEN_EXPIRES_AT the router authorises NOTHING: the pre-M1 listing for
    // this session would have been empty. The union keeps every tool listed and
    // the refusal moves to `tools/call`.
    let post_expiry_clock = t0 + TOKEN_LIFETIME_SECONDS + INTENT_TTL_SECONDS as u64 + 10;
    let (after_expiry, d6) = list_at(&ctx, post_expiry_clock).await;
    ledger.record("tools/list after RCX token expiry", after_expiry.clone(), &d6);
    assert_eq!(
        after_expiry, after_traffic,
        "an expired capability token must not remove a single advertisement"
    );
    assert!(
        after_expiry.len() > crux_mcp::tools::surface::CORE_FLOOR.len(),
        "the listing is still the full union, not a collapse to the floor"
    );
    assert!(!d6.grew, "no growth ⇒ no push");

    // ── step 7: growth is capped, never reversed ──────────────────────────
    assert!(
        ledger.last().len() <= surface::monotone_growth_cap(),
        "a dynamic session's union stays within CORE_FLOOR + 2 * DYNAMIC_TOP_N (got {})",
        ledger.last().len()
    );
}

/// The capability withdrawal that used to be expressed by removing the tool
/// from `tools/list` is now expressed at `tools/call`, with the daemon's
/// EXISTING structured refusal (`CAPABILITY_DENIED` + `denied:*` reason code +
/// signed refusal receipt) — no new error shape.
#[tokio::test(flavor = "multi_thread")]
async fn withdrawn_capability_is_refused_at_call_time_not_by_removal() {
    // A token that never carried `crux-mcp.sync_status` — the tier-change case.
    let signing = SigningKey::from_bytes(&[43u8; 32]);
    let mut narrow = mint_free_local_token(
        PASSPORT,
        "daemon_01HV0000000000000000000000",
        "default",
        vec!["crux-mcp.store_fact".to_string()],
        t0().saturating_sub(100),
        t0() + TOKEN_LIFETIME_SECONDS,
        [0x12; RCX_CT_SIGNATURE_LEN],
    );
    narrow.signature.sig = signing.sign(&narrow.token_hash()).to_bytes();
    let ctx = McpContext::new_default("gate-node")
        .with_rcx_router(RcxRouter::new_with_trusted_issuer_pubkey(
            narrow,
            signing.verifying_key().to_bytes(),
        ))
        .with_mcp_session_id("gate-monotone-refusal-tier-change");

    let resp = dispatch(rpc("tools/call", json!({"name": "sync_status"})), &ctx, None).await;
    let err = resp.error.expect("a withdrawn capability must be refused");
    assert_eq!(err.code, CAPABILITY_DENIED);
    let data = err.data.expect("structured refusal data");
    assert_eq!(
        data["reason_code"], "denied:capability_not_permitted",
        "reuse the existing refusal shape"
    );
    assert_eq!(data["stamp"]["mode"], "refused");
    assert_eq!(
        data["refusal_receipt"]["event_type"],
        "rcx.capability_token.call_refused.v1"
    );

    // The other withdrawal mode: a token that has simply expired. Same
    // envelope, the router's own `denied:token_expired` reason code. The point
    // is that neither mode is expressed by removing the advertisement.
    let mut dead = mint_free_local_token(
        PASSPORT,
        "daemon_01HV0000000000000000000000",
        "default",
        rcx_local_capabilities(),
        t0().saturating_sub(7200),
        t0().saturating_sub(3600),
        [0x13; RCX_CT_SIGNATURE_LEN],
    );
    dead.signature.sig = signing.sign(&dead.token_hash()).to_bytes();
    let expired_ctx = McpContext::new_default("gate-node")
        .with_rcx_router(RcxRouter::new_with_trusted_issuer_pubkey(
            dead,
            signing.verifying_key().to_bytes(),
        ))
        .with_mcp_session_id("gate-monotone-refusal-token-expiry");
    let resp = dispatch(rpc("tools/call", json!({"name": "sync_status"})), &expired_ctx, None).await;
    let err = resp.error.expect("an expired token must be refused at call time");
    assert_eq!(err.code, CAPABILITY_DENIED);
    let data = err.data.expect("structured refusal data");
    assert_eq!(data["reason_code"], "denied:token_expired");
    assert_eq!(
        data["refusal_receipt"]["event_type"],
        "rcx.capability_token.call_refused.v1"
    );
}

/// `list_changed` is only worth pushing when the union grew — and when it is
/// pushed, it reaches the session's SSE stream unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn list_changed_is_pushed_only_on_growth() {
    let session = "gate-monotone-list-changed";
    let registered = crux_mcp::sse::register(session, "gate-owner").expect("register SSE stream");
    let mut rx = registered.into_receiver();

    let key = format!("mcp-session:{session}");
    let ctx = McpContext::new_default("gate-node").with_mcp_session_id(session);
    assert_eq!(surface_session_key(&ctx), key);

    // First listing: everything is new, so a push is warranted.
    let (first, d1) = list_at(&ctx, t0()).await;
    assert!(d1.grew);
    assert!(crux_mcp::sse::notify_list_changed(session), "delivered to the stream");
    let frame = rx.try_recv().expect("a frame was pushed");
    assert_eq!(frame, crux_mcp::sse::TOOLS_LIST_CHANGED);

    // Re-listing with no state change: no growth, so the gate refuses the push
    // and the stream stays quiet.
    let (second, d2) = list_at(&ctx, t0()).await;
    assert_eq!(second, first, "byte-stable across two consecutive listings");
    assert!(!d2.grew);
    assert!(
        !surface::would_grow(&key, &second),
        "an unchanged surface must not trigger a list_changed push"
    );
    assert!(rx.try_recv().is_err(), "no second frame");
}
