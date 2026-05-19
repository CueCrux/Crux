// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Substrate edge MCP tools: `edge_get`, `edge_list`, `edge_upsert`, `edge_delete`.
//!
//! Distinct from the narrow `relations.rs` HTTP module that drives the existing
//! `/v1/relations` graph projection (tenant-scoped, fixed enum, u32 IDs).
//! Substrate edges are generic string-keyed labelled edges between
//! `(kind, id)` pairs in the entity store.

use corecrux_memory::EdgeQuery;
use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, JsonRpcError> {
    args.get(key).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing or non-string '{key}'"),
        data: Some(json!({ "param": key })),
    })
}

fn actor_from_ctx(ctx: &McpContext) -> String {
    ctx.agent
        .as_ref()
        .map(|a| a.name.clone())
        .unwrap_or_else(|| "anonymous".into())
}

pub async fn handle_edge_upsert(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let from_kind = require_str(args, "from_kind")?;
    let from_id = require_str(args, "from_id")?;
    let edge_kind = require_str(args, "edge_kind")?;
    let to_kind = require_str(args, "to_kind")?;
    let to_id = require_str(args, "to_id")?;
    let payload = args.get("payload").cloned().unwrap_or(Value::Null);
    let actor = actor_from_ctx(ctx);
    let mut store = ctx.edge_store.write().await;
    let rec = store
        .upsert(from_kind, from_id, edge_kind, to_kind, to_id, payload, &actor)
        .map_err(|e| JsonRpcError {
            code: INTERNAL_ERROR,
            message: "edge upsert failed".into(),
            data: Some(json!({"error": e.to_string()})),
        })?;
    Ok(json!({
        "content": [{"type":"text","text": format!("upserted edge {} v{}", rec.edge_id, rec.version)}],
        "edge": rec
    }))
}

pub async fn handle_edge_get(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let from_kind = require_str(args, "from_kind")?;
    let from_id = require_str(args, "from_id")?;
    let edge_kind = require_str(args, "edge_kind")?;
    let to_kind = require_str(args, "to_kind")?;
    let to_id = require_str(args, "to_id")?;
    let store = ctx.edge_store.read().await;
    let rec = store.get(from_kind, from_id, edge_kind, to_kind, to_id).cloned();
    Ok(json!({
        "content": [{"type":"text","text": rec.as_ref().map(|r| format!("found {}", r.edge_id)).unwrap_or_else(|| "edge not found".into()) }],
        "edge": rec.map(serde_json::to_value).transpose().unwrap_or(None).unwrap_or(Value::Null)
    }))
}

pub async fn handle_edge_list(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let q = EdgeQuery {
        from_kind: args.get("from_kind").and_then(|v| v.as_str()).map(String::from),
        from_id: args.get("from_id").and_then(|v| v.as_str()).map(String::from),
        to_kind: args.get("to_kind").and_then(|v| v.as_str()).map(String::from),
        to_id: args.get("to_id").and_then(|v| v.as_str()).map(String::from),
        edge_kind: args.get("edge_kind").and_then(|v| v.as_str()).map(String::from),
        limit: args.get("limit").and_then(|v| v.as_u64()).map(|n| n as usize),
        include_deleted: args.get("include_deleted").and_then(|v| v.as_bool()).unwrap_or(false),
    };
    let store = ctx.edge_store.read().await;
    let items: Vec<_> = store.list(&q).into_iter().cloned().collect();
    Ok(json!({
        "content": [{"type":"text","text": format!("listed {} edges", items.len())}],
        "edges": items,
        "count": items.len()
    }))
}

pub async fn handle_edge_delete(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let from_kind = require_str(args, "from_kind")?;
    let from_id = require_str(args, "from_id")?;
    let edge_kind = require_str(args, "edge_kind")?;
    let to_kind = require_str(args, "to_kind")?;
    let to_id = require_str(args, "to_id")?;
    let actor = actor_from_ctx(ctx);
    let mut store = ctx.edge_store.write().await;
    let rec = store
        .delete(from_kind, from_id, edge_kind, to_kind, to_id, &actor)
        .map_err(|e| JsonRpcError {
            code: INTERNAL_ERROR,
            message: "edge delete failed".into(),
            data: Some(json!({"error": e.to_string()})),
        })?;
    Ok(json!({
        "content": [{"type":"text","text": format!("deleted edge {} v{}", rec.edge_id, rec.version)}],
        "edge": rec
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;

    #[tokio::test]
    async fn upsert_get_round_trip() {
        let ctx = McpContext::new_default("test-node");
        handle_edge_upsert(
            &json!({
                "from_kind":"capability","from_id":"A",
                "edge_kind":"depends_on",
                "to_kind":"capability","to_id":"B"
            }),
            &ctx,
        )
        .await
        .unwrap();
        let res = handle_edge_get(
            &json!({
                "from_kind":"capability","from_id":"A",
                "edge_kind":"depends_on",
                "to_kind":"capability","to_id":"B"
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert!(!res["edge"].is_null());
    }

    #[tokio::test]
    async fn list_filters_by_from() {
        let ctx = McpContext::new_default("test-node");
        for to in ["B", "C", "D"] {
            handle_edge_upsert(
                &json!({
                    "from_kind":"capability","from_id":"A",
                    "edge_kind":"depends_on",
                    "to_kind":"capability","to_id":to
                }),
                &ctx,
            )
            .await
            .unwrap();
        }
        handle_edge_upsert(
            &json!({
                "from_kind":"capability","from_id":"X",
                "edge_kind":"depends_on",
                "to_kind":"capability","to_id":"Y"
            }),
            &ctx,
        )
        .await
        .unwrap();
        let res = handle_edge_list(&json!({"from_kind":"capability","from_id":"A"}), &ctx)
            .await
            .unwrap();
        assert_eq!(res["count"].as_u64().unwrap(), 3);
    }
}
