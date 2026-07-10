// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Features lens MCP tools (M3): `feature_file_search`,
//! `feature_coverage_report`, `feature_trigger_audit`, `feature_suggest_next`.
//!
//! Each tool reads capability entities from `ctx.entity_store` and calls into
//! the pure analytics functions in the `crux-lens-features` crate.

use corecrux_memory::EntityQuery;
use crux_lens_features::{compute_coverage_report, compute_gaps, compute_promise_coverage, CAPABILITY_KIND};
use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};

async fn load_capabilities(ctx: &McpContext) -> Vec<Value> {
    let store = ctx.entity_store.read().await;
    let q = EntityQuery {
        kind: Some(CAPABILITY_KIND.into()),
        limit: None,
        include_deleted: false,
    };
    store.list(&q).into_iter().map(|e| e.payload.clone()).collect()
}

pub async fn handle_feature_file_search(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let needle = args.get("path").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "missing or non-string 'path'".into(),
        data: Some(json!({"param":"path"})),
    })?;
    let caps = load_capabilities(ctx).await;
    let matches: Vec<&Value> = caps
        .iter()
        .filter(|c| {
            c.get("files")
                .and_then(|v| v.as_array())
                .is_some_and(|files| files.iter().any(|f| f.as_str().is_some_and(|s| s.contains(needle))))
        })
        .collect();
    let items: Vec<_> = matches
        .into_iter()
        .map(|c| {
            json!({
                "id": c.get("id"),
                "name": c.get("name"),
                "system": c.get("system"),
                "files": c.get("files"),
            })
        })
        .collect();
    Ok(json!({
        "content":[{"type":"text","text": format!("found {} capabilities touching '{}'", items.len(), needle)}],
        "capabilities": items,
        "count": items.len()
    }))
}

pub async fn handle_feature_coverage_report(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let caps = load_capabilities(ctx).await;
    let report = compute_coverage_report(&caps);
    Ok(json!({
        "content":[{"type":"text","text": format!(
            "{} capabilities, {} tested, {} audited",
            report.total_capabilities, report.total_tested, report.total_audited
        )}],
        "report": report,
    }))
}

pub async fn handle_feature_trigger_audit(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = args.get("id").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "missing or non-string 'id'".into(),
        data: Some(json!({"param":"id"})),
    })?;
    let status = args
        .get("status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "missing or non-string 'status' (audited|gap|waived|blocked)".into(),
            data: Some(json!({"param":"status"})),
        })?;
    if !matches!(status, "audited" | "gap" | "waived" | "blocked") {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "status must be one of audited|gap|waived|blocked".into(),
            data: Some(json!({"param":"status","got":status})),
        });
    }
    let auditor = args.get("auditor").and_then(|v| v.as_str()).map(String::from);
    let notes = args.get("notes").and_then(|v| v.as_str()).map(String::from);
    let actor = ctx
        .agent
        .as_ref()
        .map_or_else(|| "anonymous".into(), |a| a.name.clone());

    let mut store = ctx.entity_store.write().await;
    let current = match store.get(CAPABILITY_KIND, id) {
        Some(r) => r.payload.clone(),
        None => {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: format!("capability {id} not found"),
                data: Some(json!({"id":id})),
            })
        }
    };
    let mut payload = current;
    let now = chrono::Utc::now().to_rfc3339();
    let audit_obj = json!({
        "status": status,
        "last_audited": if status == "audited" { Some(now) } else { None },
        "auditor": auditor,
        "notes": notes,
    });
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("audit".into(), audit_obj);
    }
    let registry = ctx.kind_registry.read().await;
    let reg_opt = if registry.is_registered(CAPABILITY_KIND) {
        Some(&*registry)
    } else {
        None
    };
    let rec = store
        .upsert(CAPABILITY_KIND, id, payload, &actor, reg_opt)
        .map_err(|e| JsonRpcError {
            code: INTERNAL_ERROR,
            message: "audit upsert failed".into(),
            data: Some(json!({"error": e.to_string()})),
        })?;
    Ok(json!({
        "content":[{"type":"text","text": format!("audit recorded for {id} status={status}")}],
        "capability": rec.payload,
        "version": rec.version,
    }))
}

pub async fn handle_feature_suggest_next(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
    let caps = load_capabilities(ctx).await;
    let gaps = compute_gaps(&caps);
    let promises = compute_promise_coverage(&caps);
    let mut suggestions: Vec<Value> = Vec::new();
    for g in gaps.gaps.iter().take(limit) {
        suggestions.push(json!({
            "kind": "fix_gap",
            "capability_id": g.id,
            "system": g.system,
            "gap_type": g.r#type,
            "severity": g.severity,
            "rationale": g.detail,
        }));
    }
    let weakest = promises
        .coverage
        .iter()
        .filter(|p| p.total > 0)
        .min_by_key(|p| (p.tested * 100) / p.total.max(1));
    if let Some(p) = weakest {
        suggestions.push(json!({
            "kind": "improve_promise_tests",
            "promise": p.promise,
            "label": p.label,
            "tested": p.tested,
            "total": p.total,
            "rationale": "Promise with lowest test coverage; lift it.",
        }));
    }
    Ok(json!({
        "content":[{"type":"text","text": format!("{} suggestions", suggestions.len())}],
        "suggestions": suggestions,
        "count": suggestions.len()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;

    async fn seed(ctx: &McpContext, payloads: &[Value]) {
        let mut s = ctx.entity_store.write().await;
        for p in payloads {
            let id = p.get("id").and_then(|v| v.as_str()).unwrap();
            s.upsert(CAPABILITY_KIND, id, p.clone(), "test", None).unwrap();
        }
    }

    #[tokio::test]
    async fn file_search_finds_matches() {
        let ctx = McpContext::new_default("t");
        seed(
            &ctx,
            &[
                json!({"id":"A","name":"A","system":"X","maturity":"shipped","files":["src/foo.rs","src/bar.rs"]}),
                json!({"id":"B","name":"B","system":"X","maturity":"shipped","files":["src/baz.rs"]}),
            ],
        )
        .await;
        let res = handle_feature_file_search(&json!({"path":"foo"}), &ctx).await.unwrap();
        assert_eq!(res["count"], 1);
        assert_eq!(res["capabilities"][0]["id"], "A");
    }

    #[tokio::test]
    async fn coverage_report_runs() {
        let ctx = McpContext::new_default("t");
        seed(
            &ctx,
            &[json!({"id":"A","name":"A","system":"X","maturity":"shipped",
                      "tests":{"unit":["a.rs"]}, "audit":{"status":"audited"}})],
        )
        .await;
        let res = handle_feature_coverage_report(&json!({}), &ctx).await.unwrap();
        assert_eq!(res["report"]["total_capabilities"], 1);
        assert_eq!(res["report"]["total_tested"], 1);
    }

    #[tokio::test]
    async fn trigger_audit_updates_entity() {
        let ctx = McpContext::new_default("t");
        seed(
            &ctx,
            &[json!({"id":"A","name":"A","system":"X","maturity":"shipped",
                      "audit":{"status":"gap"}})],
        )
        .await;
        let res = handle_feature_trigger_audit(&json!({"id":"A","status":"audited","auditor":"me","notes":"ok"}), &ctx)
            .await
            .unwrap();
        assert_eq!(res["capability"]["audit"]["status"], "audited");
        assert_eq!(res["version"], 2);
    }

    #[tokio::test]
    async fn suggest_next_returns_top_gaps() {
        let ctx = McpContext::new_default("t");
        seed(
            &ctx,
            &[json!({"id":"X","name":"X","system":"S","maturity":"shipped",
                        "tests":{}, "dod":[], "audit":{"status":"gap"}})],
        )
        .await;
        let res = handle_feature_suggest_next(&json!({"limit":3}), &ctx).await.unwrap();
        assert!(res["count"].as_u64().unwrap() >= 1);
    }
}
