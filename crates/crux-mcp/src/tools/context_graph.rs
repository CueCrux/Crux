// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Context-graph MCP tools — the storybook readout (Phase 3) and agent dossier
//! exchange (Phase 4).
//!
//! Thin adapters over `/v1/projects/{id}/storybook*` and
//! `/v1/projects/{id}/dossiers*`. Every handler proxies to the same corecruxd
//! route the HTTP surface serves, so the two answers cannot drift: there is
//! exactly one implementation, in `corecruxd::storybook` / `corecruxd::dossier`,
//! and both surfaces reach it through the same request path.
//!
//! ## Why these exist
//!
//! `corecruxd::dossier`'s own module docs call the dossier "the multi-session
//! drift fix … the agent-native description language". Until this module,
//! agents — which speak MCP — had no way to read or write one. The capability
//! was addressable only by something that already knew the daemon's HTTP API,
//! which is not the audience it was built for.
//!
//! ## The pairing an agent is meant to use
//!
//! - **Starting on an unfamiliar project**: `get_project_storybook` for the
//!   narrative, then `get_project_dossiers` for what other agents already
//!   worked out. Two calls instead of crawling planes, layers and source.
//! - **Resuming**: `diff_project_storybook` between the timestamp you last saw
//!   and now — what changed, not what exists.
//! - **Before trusting a shared belief**: `reconcile_project_dossiers`, which
//!   is the only surface that shows where two agents *disagree*.
//! - **Finishing**: `publish_project_dossier` so the next session starts where
//!   this one stopped.
//!
//! Every read takes a mandatory `token_budget` (the `code_intel` rule): a tool
//! whose purpose is to reduce context spend must not have a mode that returns
//! an unbounded payload, and a storybook grows with the workspace it describes.

use serde_json::{json, Value};

use super::repos::{encode_query, loopback_json};
use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};

/// Scope for the reads, matching the HTTP handlers they wrap.
const READ_SCOPE: &str = "admin:read";
/// Scope for generate/publish — the handlers additionally persist a fact.
const WRITE_SCOPE: &str = "admin:read,facts:write";

// ─────────────────────────────────────────────────────────────────────────────
// Descriptions — written for an agent choosing between tools, not for a human
// reading documentation. Each opens with the question it answers.
// ─────────────────────────────────────────────────────────────────────────────

pub fn get_storybook_description() -> &'static str {
    "Where a project actually is right now, as a narrative. Returns the saved \
     storybook readout — vision, goals, planes, which code each plane maps to, \
     workspace health and open gaps — assembled by the daemon from the project \
     graph and the latest workspace scan. Use this instead of reading a README \
     and guessing: it is generated from state, so it cannot be stale in the way \
     prose is. Pass `section` to fetch one part (e.g. `60` for gaps and alerts, \
     `50` for workspace health) and `token_budget` to cap the whole answer. \
     Returns `available_versions` so you can diff against what you last saw. Its \
     dead-code count is graded across tiers when runtime capture is on — \
     `code_dead_code` has the per-symbol verdicts behind it, and `code_path` \
     shows what a given endpoint actually executes."
}

pub fn generate_storybook_description() -> &'static str {
    "Regenerate the project's storybook readout from current daemon state and \
     save it as a new version. Deterministic — no model call. Run this after \
     landing work so the next agent (or your future self) reads the project as \
     it is now, and so `diff_project_storybook` has a new endpoint to compare \
     against. Returns a summary with stats, not the whole document."
}

pub fn diff_storybook_description() -> &'static str {
    "What changed in a project between two storybook readouts. Given two \
     timestamps from `available_versions`, returns which sections were added, \
     removed or rewritten, plus the size delta. Use this on resuming a project \
     rather than re-reading the whole readout: it answers 'what moved since I \
     was last here' in a fraction of the tokens."
}

pub fn get_dossiers_description() -> &'static str {
    "What other agents already worked out about this project, so you can skip \
     re-deriving it. A dossier is one agent's structured belief snapshot: \
     `claims` (each with confidence and evidence), `uncertainties`, \
     `contradictions` and `open_questions`. Without `dossier_id` this lists \
     every saved dossier newest-first with its author; with one, it returns \
     that dossier's full contents. Claims are dropped lowest-confidence-first \
     when `token_budget` forces a choice, so a small budget buys the things \
     their author was most sure of. A `dead_code_likely` claim carries the tiers \
     that spoke and the window they spoke over — `code_dead_code` gives the same \
     verdict per symbol with its full evidence ladder, and `code_liveness` \
     answers whether one symbol ran at all."
}

pub fn generate_dossier_description() -> &'static str {
    "Get the daemon's own deterministic belief snapshot of a project, saved as \
     a dossier. Walks the storybook, the latest workspace scan and the project \
     graph, emitting high-confidence claims for things it can prove (members, \
     stubs, file existence) and medium-confidence inferred ones (vision↔code \
     mapping, dead-code candidates), each with explicit evidence. Use it as the \
     base to layer your own findings onto before `publish_project_dossier`, \
     rather than authoring a dossier from nothing. When runtime capture is on, \
     its dead-code claims are already graded against observed execution — a \
     symbol seen running is emitted as `extractor_false_positive`, not as a \
     deletion candidate, and `based_on.trace_window` states the window that \
     grading rests on."
}

pub fn publish_dossier_description() -> &'static str {
    "Hand what you worked out to the next agent. Publishes your own dossier for \
     a project — claims with confidence and evidence, what you are unsure of, \
     contradictions you hit, and what you would investigate next. This is the \
     fix for multi-session drift: without it, everything you inferred is lost \
     when your context ends. Call it before you finish. Re-publishing under the \
     same `dossier_id` replaces; a new id keeps both, and reconciliation prefers \
     your newest."
}

pub fn reconcile_dossiers_description() -> &'static str {
    "Where the agents working on this project agree, disagree, or stand alone. \
     Groups every agent's latest claims by subject into `agreement` (several \
     concur), `disagreement` (several claim conflicting things about the same \
     subject) and `unique` (only one agent has it). Use this before acting on a \
     belief you read in someone else's dossier — a disagreement is a fact about \
     the fleet that exists nowhere else, and it is the one thing a single \
     dossier can never tell you. A `token_budget` is spent on disagreement first."
}

pub fn diff_dossiers_description() -> &'static str {
    "How an agent's beliefs about a project moved between two snapshots. Given \
     two dossier ids, returns claims added, claims removed, and claims whose \
     confidence changed. Use it to see whether a peer's later dossier retracted \
     something you were relying on, or to audit your own drift across sessions."
}

// ─────────────────────────────────────────────────────────────────────────────
// Schemas
// ─────────────────────────────────────────────────────────────────────────────

fn project_property() -> Value {
    json!({
        "type": "string",
        "description": "Project id. Call `list_projects` if you do not know it — there is no implicit default."
    })
}

/// The mandatory `token_budget`, identical on every read.
fn token_budget_property() -> Value {
    json!({
        "type": "integer",
        "minimum": 1,
        "description": "Maximum tokens the answer may occupy, measured against the serialised \
                        response. Mandatory: a storybook grows with the workspace it describes, \
                        so there is no mode that returns an unbounded payload. 500 for a glance, \
                        2000-8000 to actually read it."
    })
}

/// Assemble a schema and stamp the tier floor.
///
/// `x-crux-min-tier` is deliberately not `x-crux-tier`: that key is written by
/// `tools_to_json` from the authenticated caller's capability token and means
/// "the tier this caller holds". What a tool needs is a different fact — the
/// floor it requires — so it gets its own key and cannot be clobbered by it.
/// Everything here runs on the operator's own daemon over their own project
/// data, so the floor is `free`.
fn schema(properties: Value, required: &[&str], examples: Value) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "examples": examples,
        "x-crux-min-tier": "free"
    })
}

pub fn get_storybook_schema() -> Value {
    schema(
        json!({
            "project_id": project_property(),
            "token_budget": token_budget_property(),
            "section": {
                "type": "string",
                "description": "Comma-separated section-key prefixes. Keys are ordered: `00_front`, \
                                `10_vision`, `20_goals`, `30_planes_intro`, `30_plane_<id>`, \
                                `40_coverage`, `50_workspace_health`, `60_alerts`, `99_footer`. \
                                A prefix matches, so `60` selects alerts and `30_plane_` selects \
                                every plane. Omit for the whole readout."
            },
            "ts": {
                "type": "integer",
                "description": "Fetch a specific saved version by its unix-ms timestamp (from \
                                `available_versions`). Omit for the latest."
            }
        }),
        &["project_id", "token_budget"],
        json!([
            { "project_id": "crux-daemon", "token_budget": 4000 },
            { "project_id": "crux-daemon", "token_budget": 500, "section": "60" },
            { "project_id": "crux-daemon", "token_budget": 2000, "section": "50,60" }
        ]),
    )
}

pub fn generate_storybook_schema() -> Value {
    schema(
        json!({ "project_id": project_property() }),
        &["project_id"],
        json!([{ "project_id": "crux-daemon" }]),
    )
}

pub fn diff_storybook_schema() -> Value {
    schema(
        json!({
            "project_id": project_property(),
            "a": { "type": "integer", "description": "Earlier readout timestamp (unix ms)." },
            "b": { "type": "integer", "description": "Later readout timestamp (unix ms)." }
        }),
        &["project_id", "a", "b"],
        json!([{ "project_id": "crux-daemon", "a": 1753600000000u64, "b": 1753700000000u64 }]),
    )
}

pub fn get_dossiers_schema() -> Value {
    schema(
        json!({
            "project_id": project_property(),
            "token_budget": token_budget_property(),
            "dossier_id": {
                "type": "string",
                "description": "Fetch one dossier's full contents. Omit to list every dossier \
                                newest-first with its author and timestamp."
            }
        }),
        &["project_id", "token_budget"],
        json!([
            { "project_id": "crux-daemon", "token_budget": 800 },
            { "project_id": "crux-daemon", "token_budget": 4000, "dossier_id": "dsr_1753700000000_p_opus" }
        ]),
    )
}

pub fn generate_dossier_schema() -> Value {
    schema(
        json!({ "project_id": project_property() }),
        &["project_id"],
        json!([{ "project_id": "crux-daemon" }]),
    )
}

pub fn publish_dossier_schema() -> Value {
    schema(
        json!({
            "project_id": project_property(),
            "dossier": {
                "type": "object",
                "description": "The dossier to publish. `dossier_id` is required and `project_id` \
                                must match the outer one. `agent_passport` and \
                                `generated_at_unix_ms` are filled from your session if omitted. \
                                Start from `generate_project_dossier` rather than hand-authoring.",
                "properties": {
                    "dossier_id":  { "type": "string" },
                    "project_id":  { "type": "string" },
                    "agent_passport": { "type": "string" },
                    "generated_at_unix_ms": { "type": "integer" },
                    "based_on": {
                        "type": "object",
                        "description": "Anchors so a consumer knows which state these beliefs reflect: \
                                        storybook_ts, workspace_scan_id, plane_count, graph_node_count."
                    },
                    "claims": {
                        "type": "array",
                        "description": "Each: claim_id, kind, subject, optional object, confidence 0..1, \
                                        evidence[], optional rationale. Evidence is not decorative — a \
                                        claim without it is not reusable by the next agent.",
                        "items": { "type": "object" }
                    },
                    "uncertainties":  { "type": "array", "items": { "type": "object" } },
                    "contradictions": { "type": "array", "items": { "type": "object" } },
                    "open_questions": { "type": "array", "items": { "type": "string" } },
                    "stats": { "type": "object" }
                },
                "required": ["dossier_id", "project_id", "claims"]
            }
        }),
        &["project_id", "dossier"],
        json!([{
            "project_id": "crux-daemon",
            "dossier": {
                "dossier_id": "dsr_session_a1",
                "project_id": "crux-daemon",
                "claims": [{
                    "claim_id": "c1",
                    "kind": "implements",
                    "subject": "plane:crux:retrieval",
                    "object": "crate:corecrux-retrieval",
                    "confidence": 0.9,
                    "evidence": ["crates/corecrux-retrieval/src/lib.rs:1"]
                }],
                "uncertainties": [],
                "contradictions": [],
                "open_questions": ["is the dense lane wired on this build?"]
            }
        }]),
    )
}

pub fn reconcile_dossiers_schema() -> Value {
    schema(
        json!({
            "project_id": project_property(),
            "token_budget": token_budget_property()
        }),
        &["project_id", "token_budget"],
        json!([{ "project_id": "crux-daemon", "token_budget": 1500 }]),
    )
}

pub fn diff_dossiers_schema() -> Value {
    schema(
        json!({
            "project_id": project_property(),
            "a": { "type": "string", "description": "Earlier dossier id." },
            "b": { "type": "string", "description": "Later dossier id." }
        }),
        &["project_id", "a", "b"],
        json!([{ "project_id": "crux-daemon", "a": "dsr_older", "b": "dsr_newer" }]),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument extraction
// ─────────────────────────────────────────────────────────────────────────────

fn base_url(ctx: &McpContext, tool: &'static str) -> Result<String, JsonRpcError> {
    ctx.daemon_base_url
        .as_deref()
        .map(|s| s.trim_end_matches('/').to_string())
        .ok_or_else(|| JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!("{tool}: daemon_base_url not configured; the MCP server was not wired to corecruxd"),
            data: None,
        })
}

fn required_string(args: &Value, name: &str, tool: &'static str) -> Result<String, JsonRpcError> {
    args.get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("{tool}: missing required string '{name}'"),
            data: None,
        })
}

fn optional_string(args: &Value, name: &str) -> Option<String> {
    args.get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn required_u64(args: &Value, name: &str, tool: &'static str) -> Result<u64, JsonRpcError> {
    args.get(name).and_then(Value::as_u64).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("{tool}: missing required integer '{name}'"),
        data: None,
    })
}

/// `token_budget` is required and must be a positive integer. A caller that
/// passes 0 gets told so rather than silently receiving an empty payload.
fn required_token_budget(args: &Value, tool: &'static str) -> Result<u64, JsonRpcError> {
    let value = args
        .get("token_budget")
        .and_then(Value::as_u64)
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("{tool}: 'token_budget' is required and must be a positive integer"),
            data: None,
        })?;
    if value == 0 {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("{tool}: 'token_budget' must be greater than zero"),
            data: None,
        });
    }
    Ok(value)
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

/// Wrap a daemon payload in the MCP `tools/call` result shape.
///
/// The spec requires `result.content` at the top level, and the dispatcher's
/// guard only normalises the legacy `{payload, envelope}` form — a bare JSON
/// object passes straight through and reaches the client with no `content`
/// array at all. `storyline.rs` does the same wrapping for the same reason.
///
/// The text is the daemon's response verbatim, which is what makes the
/// HTTP-parity integration test meaningful: the agent reads exactly the bytes
/// an operator would get from the route.
fn as_mcp_content(payload: Value) -> Value {
    json!({ "content": [{ "type": "text", "text": payload.to_string() }] })
}

/// Proxy to corecruxd and wrap the reply for MCP.
async fn proxy(
    tool: &'static str,
    method: &'static str,
    url: String,
    body: Option<Value>,
    scope: &'static str,
) -> Result<Value, JsonRpcError> {
    loopback_json(tool, method, url, body, scope).await.map(as_mcp_content)
}

pub async fn handle_get_project_storybook(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    const TOOL: &str = "get_project_storybook";
    let base = base_url(ctx, TOOL)?;
    let project = required_string(args, "project_id", TOOL)?;
    let budget = required_token_budget(args, TOOL)?;

    let mut url = format!("{base}/v1/projects/{}/storybook", encode_query(&project));
    if let Some(ts) = args.get("ts").and_then(Value::as_u64) {
        url.push('/');
        url.push_str(&ts.to_string());
    }
    use std::fmt::Write as _;
    let _ = write!(url, "?token_budget={budget}");
    if let Some(section) = optional_string(args, "section") {
        let _ = write!(url, "&section={}", encode_query(&section));
    }
    proxy(TOOL, "GET", url, None, READ_SCOPE).await
}

pub async fn handle_generate_project_storybook(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    const TOOL: &str = "generate_project_storybook";
    let base = base_url(ctx, TOOL)?;
    let project = required_string(args, "project_id", TOOL)?;
    let url = format!("{base}/v1/projects/{}/storybook", encode_query(&project));
    proxy(TOOL, "POST", url, None, WRITE_SCOPE).await
}

pub async fn handle_diff_project_storybook(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    const TOOL: &str = "diff_project_storybook";
    let base = base_url(ctx, TOOL)?;
    let project = required_string(args, "project_id", TOOL)?;
    let a = required_u64(args, "a", TOOL)?;
    let b = required_u64(args, "b", TOOL)?;
    let url = format!(
        "{base}/v1/projects/{}/storybook/diff?a={a}&b={b}",
        encode_query(&project)
    );
    proxy(TOOL, "GET", url, None, READ_SCOPE).await
}

pub async fn handle_get_project_dossiers(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    const TOOL: &str = "get_project_dossiers";
    let base = base_url(ctx, TOOL)?;
    let project = required_string(args, "project_id", TOOL)?;
    let budget = required_token_budget(args, TOOL)?;

    let url = match optional_string(args, "dossier_id") {
        Some(id) => format!(
            "{base}/v1/projects/{}/dossiers/{}?token_budget={budget}",
            encode_query(&project),
            encode_query(&id)
        ),
        None => format!(
            "{base}/v1/projects/{}/dossiers?token_budget={budget}",
            encode_query(&project)
        ),
    };
    proxy(TOOL, "GET", url, None, READ_SCOPE).await
}

pub async fn handle_generate_project_dossier(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    const TOOL: &str = "generate_project_dossier";
    let base = base_url(ctx, TOOL)?;
    let project = required_string(args, "project_id", TOOL)?;
    let url = format!("{base}/v1/projects/{}/dossiers/auto", encode_query(&project));
    proxy(TOOL, "POST", url, None, WRITE_SCOPE).await
}

pub async fn handle_publish_project_dossier(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    const TOOL: &str = "publish_project_dossier";
    let base = base_url(ctx, TOOL)?;
    let project = required_string(args, "project_id", TOOL)?;
    let mut dossier = args
        .get("dossier")
        .filter(|v| v.is_object())
        .cloned()
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("{TOOL}: 'dossier' object is required"),
            data: None,
        })?;

    // Default `project_id` from the outer argument — an agent that already
    // named the project once should not have to name it twice, and the handler
    // rejects a mismatch, so this only fills a blank. Every other field is
    // `#[serde(default)]` daemon-side, and validation stays the daemon's call:
    // this is an adapter, not a second validator that could disagree with it.
    if let Some(obj) = dossier.as_object_mut() {
        obj.entry("project_id")
            .or_insert_with(|| Value::String(project.clone()));
    }

    let url = format!("{base}/v1/projects/{}/dossiers", encode_query(&project));
    proxy(TOOL, "POST", url, Some(dossier), WRITE_SCOPE).await
}

pub async fn handle_reconcile_project_dossiers(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    const TOOL: &str = "reconcile_project_dossiers";
    let base = base_url(ctx, TOOL)?;
    let project = required_string(args, "project_id", TOOL)?;
    let budget = required_token_budget(args, TOOL)?;
    let url = format!(
        "{base}/v1/projects/{}/dossiers/reconcile?token_budget={budget}",
        encode_query(&project)
    );
    proxy(TOOL, "GET", url, None, READ_SCOPE).await
}

pub async fn handle_diff_project_dossiers(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    const TOOL: &str = "diff_project_dossiers";
    let base = base_url(ctx, TOOL)?;
    let project = required_string(args, "project_id", TOOL)?;
    let a = required_string(args, "a", TOOL)?;
    let b = required_string(args, "b", TOOL)?;
    let url = format!(
        "{base}/v1/projects/{}/dossiers/diff?a={}&b={}",
        encode_query(&project),
        encode_query(&a),
        encode_query(&b)
    );
    proxy(TOOL, "GET", url, None, READ_SCOPE).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ctx() -> McpContext {
        let mut ctx = McpContext::new_default("test-node");
        // Port 1 is never listenable, so any handler that gets as far as the
        // network fails fast — these tests are about argument validation.
        ctx.daemon_base_url = Some("http://127.0.0.1:1".to_string());
        ctx
    }

    /// Every read must require a token budget. This is the invariant the whole
    /// module rests on, so it is asserted over the set rather than per tool.
    #[test]
    fn every_read_schema_requires_a_token_budget() {
        for (name, schema) in [
            ("get_project_storybook", get_storybook_schema()),
            ("get_project_dossiers", get_dossiers_schema()),
            ("reconcile_project_dossiers", reconcile_dossiers_schema()),
        ] {
            let required: Vec<&str> = schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .collect();
            assert!(
                required.contains(&"token_budget"),
                "{name} must require token_budget, got {required:?}"
            );
            assert!(
                schema["properties"]["token_budget"].is_object(),
                "{name} must document token_budget"
            );
        }
    }

    #[test]
    fn every_schema_declares_the_free_tier_floor() {
        for schema in [
            get_storybook_schema(),
            generate_storybook_schema(),
            diff_storybook_schema(),
            get_dossiers_schema(),
            generate_dossier_schema(),
            publish_dossier_schema(),
            reconcile_dossiers_schema(),
            diff_dossiers_schema(),
        ] {
            assert_eq!(schema["x-crux-min-tier"], "free");
            assert_eq!(schema["type"], "object");
            assert!(schema["examples"].as_array().is_some_and(|e| !e.is_empty()));
        }
    }

    #[test]
    fn descriptions_lead_with_the_question_each_answers() {
        assert!(get_storybook_description().contains("Where a project actually is"));
        assert!(reconcile_dossiers_description().contains("agree, disagree"));
        assert!(publish_dossier_description().contains("multi-session drift"));
        // The pairing matters more than any single tool, so the descriptions
        // must cross-reference rather than describe themselves in isolation.
        assert!(diff_storybook_description().contains("available_versions"));
        assert!(generate_dossier_description().contains("publish_project_dossier"));
    }

    #[tokio::test]
    async fn reads_reject_a_missing_or_zero_token_budget() {
        let ctx = ctx();
        let err = handle_get_project_storybook(&json!({ "project_id": "p" }), &ctx)
            .await
            .expect_err("must reject");
        assert!(err.message.contains("token_budget"), "got: {}", err.message);

        let err = handle_get_project_dossiers(&json!({ "project_id": "p", "token_budget": 0 }), &ctx)
            .await
            .expect_err("must reject");
        assert!(err.message.contains("greater than zero"), "got: {}", err.message);

        let err = handle_reconcile_project_dossiers(&json!({ "project_id": "p" }), &ctx)
            .await
            .expect_err("must reject");
        assert!(err.message.contains("token_budget"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn handlers_reject_a_missing_project_id() {
        let ctx = ctx();
        for err in [
            handle_get_project_storybook(&json!({ "token_budget": 500 }), &ctx).await,
            handle_generate_project_storybook(&json!({}), &ctx).await,
            handle_diff_project_storybook(&json!({ "a": 1, "b": 2 }), &ctx).await,
            handle_get_project_dossiers(&json!({ "token_budget": 500 }), &ctx).await,
            handle_generate_project_dossier(&json!({}), &ctx).await,
            handle_reconcile_project_dossiers(&json!({ "token_budget": 500 }), &ctx).await,
            handle_diff_project_dossiers(&json!({ "a": "x", "b": "y" }), &ctx).await,
        ] {
            let err = err.expect_err("must reject a missing project_id");
            assert!(err.message.contains("project_id"), "got: {}", err.message);
        }
    }

    #[tokio::test]
    async fn diff_storybook_requires_both_timestamps() {
        let ctx = ctx();
        let err = handle_diff_project_storybook(&json!({ "project_id": "p", "a": 1 }), &ctx)
            .await
            .expect_err("must reject");
        assert!(err.message.contains("'b'"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn publish_requires_a_dossier_object() {
        let ctx = ctx();
        let err = handle_publish_project_dossier(&json!({ "project_id": "p" }), &ctx)
            .await
            .expect_err("must reject");
        assert!(err.message.contains("'dossier' object"), "got: {}", err.message);

        // A non-object `dossier` is the same failure, not a type panic.
        let err = handle_publish_project_dossier(&json!({ "project_id": "p", "dossier": "nope" }), &ctx)
            .await
            .expect_err("must reject");
        assert!(err.message.contains("'dossier' object"), "got: {}", err.message);
    }

    #[test]
    fn results_carry_the_mcp_content_array() {
        // A bare JSON object reaches the client with no `content` array — the
        // dispatcher's normaliser only rescues the legacy wrapper shape — so a
        // tool that skips this is invisible to a spec-conforming client.
        let wrapped = as_mcp_content(json!({ "project_id": "p", "truncated": false }));
        let text = wrapped["content"][0]["text"].as_str().expect("content text");
        assert_eq!(wrapped["content"][0]["type"], "text");
        let round_tripped: Value = serde_json::from_str(text).unwrap();
        assert_eq!(round_tripped["project_id"], "p");
        assert_eq!(round_tripped["truncated"], false);
    }

    #[tokio::test]
    async fn every_handler_reports_an_unwired_daemon_rather_than_panicking() {
        let ctx = McpContext::new_default("test-node"); // no daemon_base_url
        let err = handle_get_project_storybook(&json!({ "project_id": "p", "token_budget": 500 }), &ctx)
            .await
            .expect_err("must reject");
        assert!(err.message.contains("daemon_base_url"), "got: {}", err.message);
    }
}
