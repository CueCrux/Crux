// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Runtime code-intelligence MCP tools.
//!
//! Thin adapters over `GET /v1/code-intel/*`. Every handler here proxies to the
//! same corecruxd route the HTTP surface serves, so the two answers cannot
//! drift: there is exactly one implementation, in
//! `corecruxd::code_intel`, and both surfaces reach it through the same
//! request path.
//!
//! These tools answer from **runtime evidence** — spans actually captured while
//! the code ran — joined to `file:line` via the symbol resolver. That is the
//! distinction from static navigation (LSP, rust-analyzer, grep), which can
//! only answer what *might* run.
//!
//! Naming: the `code_*` prefix keeps these distinct from `tool_trace_recent` in
//! [`super::traces`], which inspects *agent tool-call* traces and is unrelated.
//!
//! Every tool takes a mandatory `token_budget` (QC.2). A retrieval tool whose
//! whole purpose is to reduce context spend must not have a mode that returns an
//! unbounded payload.

use serde_json::{json, Value};

use super::repos::{encode_query, loopback_json, requested_tenant};
use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};

/// Scope required by all five routes, matching the HTTP handlers they wrap.
const SCOPE: &str = "admin:read";

/// corecruxd's own default when `repo_id` is omitted (see
/// `corecruxd::http::traces`). Mirrored here only so the tool descriptions can
/// state it honestly.
const DEFAULT_REPO_ID: &str = "crux";

// ─────────────────────────────────────────────────────────────────────────────
// Descriptions — written for an agent choosing between tools, not for a human
// reading documentation. Each opens with the question it answers.
// ─────────────────────────────────────────────────────────────────────────────

pub fn path_description() -> &'static str {
    "What actually executes when an entry point fires. Returns the observed call \
     path — ordered steps with file:line, depth and duration — reconstructed from \
     runtime spans, not from static call-graph inference. Use this instead of \
     grepping and reading handler files when you need to know the real path \
     through a request, including layers static analysis misses (middleware, \
     dynamic dispatch, trait objects). Answers in a few hundred tokens."
}

pub fn blast_radius_description() -> &'static str {
    "What breaks if you change this symbol. Returns the dependents that were \
     observed calling it at runtime, ranked, with file:line for each. Use this \
     before editing or deleting a symbol, in preference to grepping for callers: \
     grep finds textual references, this finds executions, so it catches dynamic \
     dispatch and misses no caller that actually ran in the observed window."
}

pub fn liveness_description() -> &'static str {
    "Did this symbol actually run, and how often, in a stated observation window. \
     Returns execution counts plus the window the answer is true for. Use this to \
     tell 'never called' apart from 'never called *while we were looking*' — the \
     window is part of the answer, so a negative is only ever as strong as the \
     traffic behind it. If you are asking because a dossier claimed the symbol \
     was dead, `get_project_dossiers` already carries the tier evidence and the \
     window that claim was graded over."
}

pub fn trace_diff_description() -> &'static str {
    "Where two executions of the same operation diverge. Given two trace ids, \
     returns the steps present in one and not the other, and the steps common to \
     both whose timing differs. Use this for 'why was this request slow' or 'why \
     did this one fail and that one succeed' — it localises the divergence \
     instead of making you read two logs side by side."
}

pub fn dead_code_description() -> &'static str {
    "Is this symbol safe to delete — or which ones are, across the repo. Pass \
     `symbol` to ask about one; omit it for the whole repo. Returns \
     one verdict per candidate with the evidence from each tier that spoke \
     (compiler lint, AST reachability, binary symbols, runtime execution) and \
     whether those tiers agree. `actionable` is true only when independent tiers \
     agree over a non-empty observation window in which the symbol's own file ran \
     — so a verdict is a claim about evidence, never a bare heuristic. Use this \
     rather than trusting a single dead-code lint. For the same verdicts folded \
     into a project-level belief snapshot alongside everything else known about \
     the project, see `get_project_dossiers`; for the human-readable roll-up, \
     `get_project_storybook` with `section=50`."
}

// ─────────────────────────────────────────────────────────────────────────────
// Schemas
// ─────────────────────────────────────────────────────────────────────────────

/// The `token_budget` property, identical on all five tools.
fn token_budget_property() -> Value {
    json!({
        "type": "integer",
        "minimum": 1,
        "description": "Maximum tokens the answer may occupy. Mandatory: these tools exist to \
                        reduce context spend, so there is no mode that returns an unbounded \
                        payload. 300 for a quick check, 500-2000 for an investigation."
    })
}

fn tenant_property() -> Value {
    json!({ "type": "string", "description": "Tenant that owns the repo registration." })
}

fn repo_property() -> Value {
    json!({
        "type": "string",
        "description": "Repo id as registered with `register_repo`. Defaults to \"crux\".",
        "default": DEFAULT_REPO_ID
    })
}

/// Assemble a schema and stamp the per-tool tier floor.
///
/// `x-crux-min-tier` is deliberately **not** `x-crux-tier`: that key is written
/// by `tools_to_json` from the *authenticated caller's* capability token and
/// means "the tier this caller holds". What a tool needs is a different fact —
/// the floor it requires — so it gets its own key and cannot be clobbered by,
/// or mistaken for, the caller's tier.
fn schema(properties: Value, required: &[&str], examples: Value) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
        "x-crux-min-tier": "free",
        "examples": examples
    })
}

pub fn path_schema() -> Value {
    schema(
        json!({
            "tenant_id": tenant_property(),
            "entry_point": {
                "type": "string",
                "description": "The span or handler name the path starts from, e.g. \
                                \"get_version\" or a route path."
            },
            "token_budget": token_budget_property()
        }),
        &["tenant_id", "entry_point", "token_budget"],
        json!([{ "tenant_id": "local", "entry_point": "get_version", "token_budget": 500 }]),
    )
}

pub fn blast_radius_schema() -> Value {
    schema(
        json!({
            "tenant_id": tenant_property(),
            "repo_id": repo_property(),
            "symbol": {
                "type": "string",
                "description": "Symbol name to assess, e.g. \"build_info\"."
            },
            "token_budget": token_budget_property()
        }),
        &["tenant_id", "symbol", "token_budget"],
        json!([{ "tenant_id": "local", "symbol": "build_info", "token_budget": 500 }]),
    )
}

pub fn liveness_schema() -> Value {
    schema(
        json!({
            "tenant_id": tenant_property(),
            "repo_id": repo_property(),
            "symbol": {
                "type": "string",
                "description": "Symbol name to check for execution, e.g. \"get_admin_version\"."
            },
            "token_budget": token_budget_property()
        }),
        &["tenant_id", "symbol", "token_budget"],
        json!([{ "tenant_id": "local", "symbol": "get_admin_version", "token_budget": 300 }]),
    )
}

pub fn trace_diff_schema() -> Value {
    schema(
        json!({
            "tenant_id": tenant_property(),
            "trace_a": { "type": "integer", "description": "First trace id, from `code_path` or GET /v1/traces." },
            "trace_b": { "type": "integer", "description": "Second trace id to compare against." },
            "token_budget": token_budget_property()
        }),
        &["tenant_id", "trace_a", "trace_b", "token_budget"],
        json!([{ "tenant_id": "local", "trace_a": 1, "trace_b": 2, "token_budget": 500 }]),
    )
}

pub fn dead_code_schema() -> Value {
    schema(
        json!({
            "tenant_id": tenant_property(),
            "repo_id": repo_property(),
            "symbol": {
                "type": "string",
                "description": "Ask about one symbol. Strongly preferred when you have one in mind: \
                                without it the answer is every candidate in the repo, and a token \
                                budget will truncate that list — possibly dropping the symbol you asked about."
            },
            "token_budget": token_budget_property()
        }),
        &["tenant_id", "token_budget"],
        json!([{ "tenant_id": "local", "symbol": "lookup_session", "token_budget": 500 }]),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument extraction
// ─────────────────────────────────────────────────────────────────────────────

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

/// `token_budget` is mandatory and must be a positive integer.
///
/// Rejected here rather than forwarded, so a caller that omits it gets an
/// actionable MCP error instead of corecruxd's deserialisation failure.
fn token_budget(args: &Value, tool: &'static str) -> Result<u64, JsonRpcError> {
    let raw = args.get("token_budget").ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("{tool}: 'token_budget' is required — these tools never return an unbounded payload"),
        data: None,
    })?;
    let value = raw.as_u64().filter(|n| *n > 0).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("{tool}: 'token_budget' must be a positive integer, got {raw}"),
        data: None,
    })?;
    Ok(value)
}

fn required_u64(args: &Value, name: &str, tool: &'static str) -> Result<u64, JsonRpcError> {
    args.get(name).and_then(Value::as_u64).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("{tool}: missing required integer '{name}'"),
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

fn base_url(ctx: &McpContext, tool: &'static str) -> Result<String, JsonRpcError> {
    ctx.daemon_base_url
        .as_deref()
        .map(|u| u.trim_end_matches('/').to_string())
        .ok_or_else(|| JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!("{tool}: daemon_base_url not configured; the MCP server was not wired to corecruxd"),
            data: None,
        })
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

pub async fn handle_code_path(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    const TOOL: &str = "code_path";
    let base = base_url(ctx, TOOL)?;
    let tenant = requested_tenant(args, ctx, TOOL)?;
    let entry_point = required_string(args, "entry_point", TOOL)?;
    let budget = token_budget(args, TOOL)?;
    let url = format!(
        "{base}/v1/code-intel/path?tenant_id={}&entry_point={}&token_budget={budget}",
        encode_query(&tenant),
        encode_query(&entry_point)
    );
    loopback_json(TOOL, "GET", url, None, SCOPE, ctx).await
}

pub async fn handle_code_blast_radius(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    const TOOL: &str = "code_blast_radius";
    let base = base_url(ctx, TOOL)?;
    let tenant = requested_tenant(args, ctx, TOOL)?;
    let symbol = required_string(args, "symbol", TOOL)?;
    let budget = token_budget(args, TOOL)?;
    let url = format!(
        "{base}/v1/code-intel/blast-radius?tenant_id={}&symbol={}&token_budget={budget}{}",
        encode_query(&tenant),
        encode_query(&symbol),
        repo_param(args)
    );
    loopback_json(TOOL, "GET", url, None, SCOPE, ctx).await
}

pub async fn handle_code_liveness(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    const TOOL: &str = "code_liveness";
    let base = base_url(ctx, TOOL)?;
    let tenant = requested_tenant(args, ctx, TOOL)?;
    let symbol = required_string(args, "symbol", TOOL)?;
    let budget = token_budget(args, TOOL)?;
    let url = format!(
        "{base}/v1/code-intel/liveness?tenant_id={}&symbol={}&token_budget={budget}{}",
        encode_query(&tenant),
        encode_query(&symbol),
        repo_param(args)
    );
    loopback_json(TOOL, "GET", url, None, SCOPE, ctx).await
}

pub async fn handle_code_trace_diff(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    const TOOL: &str = "code_trace_diff";
    let base = base_url(ctx, TOOL)?;
    let tenant = requested_tenant(args, ctx, TOOL)?;
    let trace_a = required_u64(args, "trace_a", TOOL)?;
    let trace_b = required_u64(args, "trace_b", TOOL)?;
    let budget = token_budget(args, TOOL)?;
    let url = format!(
        "{base}/v1/code-intel/trace-diff?tenant_id={}&trace_a={trace_a}&trace_b={trace_b}&token_budget={budget}",
        encode_query(&tenant)
    );
    loopback_json(TOOL, "GET", url, None, SCOPE, ctx).await
}

pub async fn handle_code_dead_code(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    const TOOL: &str = "code_dead_code";
    let base = base_url(ctx, TOOL)?;
    let tenant = requested_tenant(args, ctx, TOOL)?;
    let budget = token_budget(args, TOOL)?;
    let symbol = optional_string(args, "symbol").map_or_else(String::new, |s| format!("&symbol={}", encode_query(&s)));
    let url = format!(
        "{base}/v1/code-intel/dead-code?tenant_id={}&token_budget={budget}{}{symbol}",
        encode_query(&tenant),
        repo_param(args)
    );
    loopback_json(TOOL, "GET", url, None, SCOPE, ctx).await
}

/// `&repo_id=…`, or empty so corecruxd applies its own default.
fn repo_param(args: &Value) -> String {
    optional_string(args, "repo_id").map_or_else(String::new, |r| format!("&repo_id={}", encode_query(&r)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schemas() -> Vec<(&'static str, Value)> {
        vec![
            ("code_path", path_schema()),
            ("code_blast_radius", blast_radius_schema()),
            ("code_liveness", liveness_schema()),
            ("code_trace_diff", trace_diff_schema()),
            ("code_dead_code", dead_code_schema()),
        ]
    }

    /// QC.2: no tool here may have a mode that returns an unbounded payload.
    #[test]
    fn every_schema_requires_token_budget() {
        for (name, schema) in schemas() {
            let required: Vec<&str> = schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert!(
                required.contains(&"token_budget"),
                "{name}: token_budget must be required, got {required:?}"
            );
            assert_eq!(
                schema["properties"]["token_budget"]["type"], "integer",
                "{name}: token_budget must be an integer"
            );
            assert_eq!(
                schema["properties"]["token_budget"]["minimum"], 1,
                "{name}: token_budget must have a positive floor"
            );
        }
    }

    /// The free/paid line is declared in the artifact, not implied by absence
    /// (plan decision 2026-07-27d). `x-crux-min-tier`, never `x-crux-tier` —
    /// that key belongs to the caller's token (2026-07-27i).
    #[test]
    fn every_schema_declares_the_free_tier_floor() {
        for (name, schema) in schemas() {
            assert_eq!(schema["x-crux-min-tier"], "free", "{name}: missing tier floor");
            assert!(
                schema.get("x-crux-tier").is_none(),
                "{name}: must not claim the caller-tier key"
            );
        }
    }

    #[test]
    fn every_schema_carries_a_tenant_and_an_example() {
        for (name, schema) in schemas() {
            assert_eq!(schema["properties"]["tenant_id"]["type"], "string", "{name}");
            let examples = schema["examples"].as_array().unwrap();
            assert!(!examples.is_empty(), "{name}: needs at least one example");
            // An example that omits a required field teaches an agent to make a
            // failing call.
            for required in schema["required"].as_array().unwrap() {
                let key = required.as_str().unwrap();
                assert!(
                    examples[0].get(key).is_some(),
                    "{name}: example omits required field '{key}'"
                );
            }
        }
    }

    #[test]
    fn descriptions_are_written_for_tool_selection() {
        for (name, description) in [
            ("code_path", path_description()),
            ("code_blast_radius", blast_radius_description()),
            ("code_liveness", liveness_description()),
            ("code_trace_diff", trace_diff_description()),
            ("code_dead_code", dead_code_description()),
        ] {
            assert!(description.len() > 120, "{name}: description too thin to select on");
            let lower = description.to_lowercase();
            assert!(
                lower.contains("use this"),
                "{name}: description must say when to choose this tool over the alternative"
            );
        }
    }

    #[test]
    fn token_budget_rejects_zero_and_non_integers() {
        assert!(token_budget(&json!({ "token_budget": 0 }), "t").is_err());
        assert!(token_budget(&json!({ "token_budget": -5 }), "t").is_err());
        assert!(token_budget(&json!({ "token_budget": "500" }), "t").is_err());
        assert!(token_budget(&json!({}), "t").is_err());
        assert_eq!(token_budget(&json!({ "token_budget": 500 }), "t").unwrap(), 500);
    }

    #[test]
    fn repo_param_is_empty_when_absent_so_the_daemon_default_applies() {
        assert_eq!(repo_param(&json!({})), "");
        assert_eq!(repo_param(&json!({ "repo_id": "  " })), "");
        assert_eq!(repo_param(&json!({ "repo_id": "crux" })), "&repo_id=crux");
    }

    /// Symbol names carry `::`, `<`, `>` and spaces; an unencoded one would
    /// truncate or corrupt the query string.
    #[test]
    fn query_values_are_percent_encoded() {
        assert_eq!(encode_query("Vec<String>::new"), "Vec%3CString%3E%3A%3Anew");
        assert_eq!(encode_query("a&b=c"), "a%26b%3Dc");
    }

    #[tokio::test]
    async fn handlers_require_a_wired_daemon() {
        let ctx = McpContext::new_default("test-node");
        let args = json!({ "tenant_id": "local", "entry_point": "x", "symbol": "x", "trace_a": 1, "trace_b": 2, "token_budget": 500 });
        assert!(handle_code_path(&args, &ctx).await.is_err());
        assert!(handle_code_blast_radius(&args, &ctx).await.is_err());
        assert!(handle_code_liveness(&args, &ctx).await.is_err());
        assert!(handle_code_trace_diff(&args, &ctx).await.is_err());
        assert!(handle_code_dead_code(&args, &ctx).await.is_err());
    }
}
