// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Substrate entity MCP tools: `entity_get`, `entity_list`, `entity_upsert`,
//! `entity_delete`.
//!
//! `entity_history` is added in M2 alongside receipt integration.

use corecrux_memory::EntityQuery;
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
        .map_or_else(|| "anonymous".into(), |a| a.name.clone())
}

pub async fn handle_entity_upsert(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let kind = require_str(args, "kind")?;
    let id = require_str(args, "id")?;
    let payload = args.get("payload").cloned().ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "missing 'payload'".into(),
        data: Some(json!({"param":"payload"})),
    })?;
    let actor = actor_from_ctx(ctx);
    let registry = ctx.kind_registry.read().await;
    let registry_opt = if registry.is_registered(kind) {
        Some(&*registry)
    } else {
        None
    };
    let mut store = ctx.entity_store.write().await;
    let rec = store
        .upsert(kind, id, payload, &actor, registry_opt)
        .map_err(|e| JsonRpcError {
            code: INTERNAL_ERROR,
            message: "entity upsert failed".into(),
            data: Some(json!({"error": e.to_string()})),
        })?;
    Ok(json!({
        "content": [{
            "type":"text",
            "text": format!(
                "upserted entity {}/{} (version={})",
                rec.kind, rec.id, rec.version
            )
        }],
        "entity": rec
    }))
}

pub async fn handle_entity_get(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let kind = require_str(args, "kind")?;
    let id = require_str(args, "id")?;
    let include_deleted = args.get("include_deleted").and_then(|v| v.as_bool()).unwrap_or(false);
    let store = ctx.entity_store.read().await;
    let rec = if include_deleted {
        store.get_including_deleted(kind, id).cloned()
    } else {
        store.get(kind, id).cloned()
    };
    match rec {
        Some(r) => Ok(json!({
            "content": [{"type":"text","text": format!("found {}/{} v{}", r.kind, r.id, r.version)}],
            "entity": r
        })),
        None => Ok(json!({
            "content": [{"type":"text","text": format!("entity {kind}/{id} not found")}],
            "entity": Value::Null
        })),
    }
}

pub async fn handle_entity_list(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let q = EntityQuery {
        kind: args.get("kind").and_then(|v| v.as_str()).map(String::from),
        limit: args.get("limit").and_then(|v| v.as_u64()).map(|n| n as usize),
        include_deleted: args.get("include_deleted").and_then(|v| v.as_bool()).unwrap_or(false),
    };
    let store = ctx.entity_store.read().await;
    let items: Vec<_> = store.list(&q).into_iter().cloned().collect();
    Ok(json!({
        "content": [{"type":"text","text": format!("listed {} entities", items.len())}],
        "entities": items,
        "count": items.len()
    }))
}

pub async fn handle_entity_history(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let kind = require_str(args, "kind")?;
    let id = require_str(args, "id")?;
    let store = ctx.entity_store.read().await;
    let versions: Vec<_> = store.history(kind, id).into_iter().cloned().collect();
    Ok(json!({
        "content":[{"type":"text","text": format!("{} versions for {}/{}", versions.len(), kind, id)}],
        "versions": versions,
        "count": versions.len()
    }))
}

pub async fn handle_entity_delete(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let kind = require_str(args, "kind")?;
    let id = require_str(args, "id")?;
    let actor = actor_from_ctx(ctx);
    let mut store = ctx.entity_store.write().await;
    let rec = store.delete(kind, id, &actor).map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: "entity delete failed".into(),
        data: Some(json!({"error": e.to_string()})),
    })?;
    Ok(json!({
        "content": [{"type":"text","text": format!("deleted {}/{} v{}", rec.kind, rec.id, rec.version)}],
        "entity": rec
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;

    #[tokio::test]
    async fn upsert_then_get() {
        let ctx = McpContext::new_default("test-node");
        handle_entity_upsert(&json!({"kind":"capability","id":"X","payload":{"name":"X"}}), &ctx)
            .await
            .unwrap();
        let res = handle_entity_get(&json!({"kind":"capability","id":"X"}), &ctx)
            .await
            .unwrap();
        assert_eq!(res["entity"]["payload"]["name"], "X");
    }

    #[tokio::test]
    async fn list_filters_by_kind() {
        let ctx = McpContext::new_default("test-node");
        for i in 0..3 {
            handle_entity_upsert(&json!({"kind":"capability","id":format!("C{i}"),"payload":{}}), &ctx)
                .await
                .unwrap();
        }
        for i in 0..2 {
            handle_entity_upsert(&json!({"kind":"repo","id":format!("R{i}"),"payload":{}}), &ctx)
                .await
                .unwrap();
        }
        let res = handle_entity_list(&json!({"kind":"capability"}), &ctx).await.unwrap();
        assert_eq!(res["count"].as_u64().unwrap(), 3);
        let all = handle_entity_list(&json!({}), &ctx).await.unwrap();
        assert_eq!(all["count"].as_u64().unwrap(), 5);
    }

    #[tokio::test]
    async fn history_after_upserts_and_delete() {
        let ctx = McpContext::new_default("test-node");
        for v in 1..=3 {
            handle_entity_upsert(&json!({"kind":"capability","id":"H","payload":{"v":v}}), &ctx)
                .await
                .unwrap();
        }
        handle_entity_delete(&json!({"kind":"capability","id":"H"}), &ctx)
            .await
            .unwrap();
        let res = handle_entity_history(&json!({"kind":"capability","id":"H"}), &ctx)
            .await
            .unwrap();
        assert_eq!(res["count"].as_u64().unwrap(), 4);
        let vs = res["versions"].as_array().unwrap();
        assert_eq!(vs[0]["version"], 1);
        assert_eq!(vs.last().unwrap()["deleted"], true);
    }

    #[tokio::test]
    async fn delete_round_trip() {
        let ctx = McpContext::new_default("test-node");
        handle_entity_upsert(&json!({"kind":"capability","id":"X","payload":{}}), &ctx)
            .await
            .unwrap();
        handle_entity_delete(&json!({"kind":"capability","id":"X"}), &ctx)
            .await
            .unwrap();
        let res = handle_entity_get(&json!({"kind":"capability","id":"X"}), &ctx)
            .await
            .unwrap();
        assert!(res["entity"].is_null());
    }
}
