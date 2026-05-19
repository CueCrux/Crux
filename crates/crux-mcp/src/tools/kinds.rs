// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Substrate kind-registry MCP tools: `kind_list`, `kind_get`.
//!
//! Registrations themselves happen in-process at startup by lens crates.
//! Agents discover what kinds the daemon knows about via `kind_list`.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};

pub async fn handle_kind_list(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let reg = ctx.kind_registry.read().await;
    let kinds: Vec<_> = reg
        .list()
        .into_iter()
        .map(|r| {
            json!({
                "kind": r.kind,
                "description": r.description,
                "allowed_outgoing_edges": r.allowed_outgoing_edges,
                "allowed_incoming_edges": r.allowed_incoming_edges,
            })
        })
        .collect();
    Ok(json!({
        "content": [{"type":"text","text": format!("{} kinds registered", kinds.len())}],
        "kinds": kinds,
        "count": kinds.len()
    }))
}

pub async fn handle_kind_get(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let kind = args.get("kind").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "missing or non-string 'kind'".into(),
        data: Some(json!({"param":"kind"})),
    })?;
    let reg = ctx.kind_registry.read().await;
    match reg.get(kind) {
        Some(r) => Ok(json!({
            "content": [{"type":"text","text": format!("kind {} registered", r.kind)}],
            "registration": r
        })),
        None => Ok(json!({
            "content": [{"type":"text","text": format!("kind {kind} not registered")}],
            "registration": Value::Null
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;
    use corecrux_memory::KindRegistration;

    #[tokio::test]
    async fn list_empty() {
        let ctx = McpContext::new_default("t");
        let res = handle_kind_list(&json!({}), &ctx).await.unwrap();
        assert_eq!(res["count"].as_u64().unwrap(), 0);
    }

    #[tokio::test]
    async fn list_after_register() {
        let ctx = McpContext::new_default("t");
        ctx.kind_registry
            .write()
            .await
            .register(KindRegistration {
                kind: "capability".into(),
                json_schema: json!({"type":"object"}),
                allowed_outgoing_edges: vec!["depends_on".into()],
                allowed_incoming_edges: vec!["depends_on".into()],
                description: "Feature Registry capability".into(),
            })
            .unwrap();
        let res = handle_kind_list(&json!({}), &ctx).await.unwrap();
        assert_eq!(res["count"].as_u64().unwrap(), 1);
        let g = handle_kind_get(&json!({"kind":"capability"}), &ctx).await.unwrap();
        assert_eq!(g["registration"]["kind"], "capability");
    }
}
