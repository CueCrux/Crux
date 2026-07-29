// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl learn` — CLI wrapper over the daemon's read-only `learn` MCP
//! tool (token-efficiency M4).
//!
//! Mines the calling passport's recent tool-call traces for looping re-fetches
//! and prints the **propose-only** guardrails the daemon ranks by measured token
//! waste. This is a thin convenience surface: all the analysis lives in the
//! daemon (`crux_mcp::learn` / the `learn` MCP tool); the CLI just issues a
//! JSON-RPC `tools/call` and renders the result. Writes nothing.

use serde_json::{json, Value};

use crate::login;
use crate::machine::{agent, resolve_daemon};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// Run `corecruxctl learn`. Resolves the daemon (→ its MCP endpoint), calls the
/// `learn` tool, and prints either a human-readable ranked report or, with
/// `--json`, the raw tool result.
pub fn run_learn(
    min_repeats: Option<usize>,
    scan: Option<usize>,
    url: Option<String>,
    json_out: bool,
) -> Result<(), DynErr> {
    let http_base = resolve_daemon(url)?;
    let mcp_url = login::derive_mcp_url(&http_base)?;
    let bearer = login::resolve_fresh_bearer(&http_base)?;

    let mut arguments = serde_json::Map::new();
    if let Some(m) = min_repeats {
        arguments.insert("min_repeats".into(), json!(m));
    }
    if let Some(s) = scan {
        arguments.insert("scan".into(), json!(s));
    }
    let result = call_learn(&mcp_url, bearer.as_deref(), Value::Object(arguments))?;

    if json_out {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    print!("{}", render(&result));
    Ok(())
}

/// Issue the JSON-RPC `tools/call` for `learn` and return the tool `result`.
fn call_learn(mcp_url: &str, bearer: Option<&str>, arguments: Value) -> Result<Value, DynErr> {
    let envelope = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "learn", "arguments": arguments }
    });
    let mut req = agent()
        .post(mcp_url)
        .header("content-type", "application/json")
        .header("accept", "application/json");
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let mut resp = match req.send_json(&envelope) {
        Ok(resp) => resp,
        Err(ureq::Error::StatusCode(code)) => {
            return Err(format!("learn call failed (HTTP {code}) against {mcp_url}").into());
        }
        Err(other) => return Err(Box::new(other)),
    };
    let body: Value = resp.body_mut().read_json()?;
    if let Some(err) = body.get("error") {
        return Err(format!("mcp error: {err}").into());
    }
    body.get("result")
        .cloned()
        .ok_or_else(|| "mcp response missing `result`".into())
}

/// Render the tool `result` as a human-readable report. Pure (testable without
/// a daemon).
fn render(result: &Value) -> String {
    if result.get("feature_disabled").and_then(Value::as_bool) == Some(true) {
        return "learn: trace recording is disabled on the daemon \
                (set CORECRUXD_FEATURE_TOOL_TRACES=1)\n"
            .to_string();
    }
    let proposals = result.get("proposals").and_then(Value::as_array);
    let count = proposals.map_or(0, Vec::len);
    if count == 0 {
        return "learn: no looping re-fetches found — nothing to propose.\n".to_string();
    }
    use std::fmt::Write as _;
    let mut out = format!("learn: {count} guardrail proposal(s) (propose-only — nothing written)\n");
    for (i, p) in proposals.into_iter().flatten().enumerate() {
        let sig = p.get("signature").and_then(Value::as_str).unwrap_or("?");
        let occ = p.get("occurrences").and_then(Value::as_u64).unwrap_or(0);
        let waste = p.get("wasted_tokens").and_then(Value::as_u64).unwrap_or(0);
        let draft = p.get("draft_guardrail").and_then(Value::as_str).unwrap_or("");
        let _ = write!(out, "\n{}. [{waste} tok wasted · {occ}×] {sig}\n   ↳ {draft}\n", i + 1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_feature_disabled() {
        let r = json!({"feature_disabled": true, "proposals": [], "count": 0});
        assert!(render(&r).contains("trace recording is disabled"));
    }

    #[test]
    fn render_no_proposals() {
        let r = json!({"proposals": [], "count": 0});
        assert!(render(&r).contains("nothing to propose"));
    }

    #[test]
    fn render_ranked_proposals() {
        let r = json!({
            "count": 2,
            "proposals": [
                {"signature": "query(q=docs)", "occurrences": 6, "wasted_tokens": 250,
                 "draft_guardrail": "Cache the first result."},
                {"signature": "list_work()", "occurrences": 3, "wasted_tokens": 90,
                 "draft_guardrail": "Reuse the prior list."}
            ]
        });
        let out = render(&r);
        assert!(out.contains("2 guardrail proposal(s)"));
        assert!(out.contains("1. [250 tok wasted · 6×] query(q=docs)"));
        assert!(out.contains("Cache the first result."));
        assert!(out.contains("2. [90 tok wasted · 3×] list_work()"));
    }
}
