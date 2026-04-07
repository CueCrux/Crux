// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Sync tool handlers: `sync_pull`, `sync_push`, `sync_status`.

use std::path::PathBuf;

use serde_json::{json, Value};

use corecrux_memory::sync::SyncClient;

use crate::dispatch::McpContext;
use crate::protocol::JsonRpcError;

/// Build a [`SyncClient`] from environment variables.
///
/// Returns `Err` with a user-facing message if the required env vars
/// (`CORECRUXD_SYNC_REMOTE_URL`, `CORECRUXD_SYNC_API_KEY`) are missing or
/// empty.
fn build_sync_client() -> Result<SyncClient, String> {
    let remote_url = std::env::var("CORECRUXD_SYNC_REMOTE_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "sync not configured: CORECRUXD_SYNC_REMOTE_URL is not set".to_string())?;

    let api_key = std::env::var("CORECRUXD_SYNC_API_KEY")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "sync not configured: CORECRUXD_SYNC_API_KEY is not set".to_string())?;

    let data_dir =
        PathBuf::from(std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v3".to_string()));

    Ok(SyncClient::new(&remote_url, &api_key, &data_dir))
}

/// Return an MCP error-content response (not a JSON-RPC error — the tool
/// executed successfully but the result is an error condition).
fn sync_error_content(msg: &str) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": msg
        }],
        "isError": true
    })
}

/// `sync_pull` — pull latest facts from the remote CoreCrux instance.
pub async fn handle_sync_pull(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let client = match build_sync_client() {
        Ok(c) => c,
        Err(msg) => return Ok(sync_error_content(&msg)),
    };

    let mut store = ctx.fact_store.write().await;
    match client.pull(&mut *store) {
        Ok(result) => {
            let cursor = client.load_cursor();
            let text = serde_json::to_string_pretty(&json!({
                "facts_pulled": result.facts_pulled,
                "cursor": result.new_cursor,
                "total_pull_count": cursor.pull_count,
            }))
            .unwrap_or_default();
            Ok(json!({
                "content": [{ "type": "text", "text": text }]
            }))
        }
        Err(e) => Ok(sync_error_content(&format!("sync pull failed: {e}"))),
    }
}

/// `sync_push` — push local facts to the remote CoreCrux instance.
///
/// Without `confirm: true`, returns a preview of what would be pushed
/// (entities, count, skipped private count). With `confirm: true`, actually
/// pushes the facts.
pub async fn handle_sync_push(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let client = match build_sync_client() {
        Ok(c) => c,
        Err(msg) => return Ok(sync_error_content(&msg)),
    };

    let confirm = args.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);

    if !confirm {
        // Preview mode — show what would be pushed without actually pushing.
        let store = ctx.fact_store.read().await;
        let preview = client.push_preview(&*store);
        let text = serde_json::to_string_pretty(&json!({
            "mode": "preview",
            "would_push": preview.pushable_count,
            "skipped_private": preview.private_count,
            "skipped_synced": preview.synced_count,
            "entities": preview.entity_summary,
            "note": "Call sync_push with confirm=true to actually push these facts."
        }))
        .unwrap_or_default();
        return Ok(json!({
            "content": [{ "type": "text", "text": text }]
        }));
    }

    let store = ctx.fact_store.read().await;
    match client.push(&*store) {
        Ok(result) => {
            let cursor = client.load_cursor();
            let text = serde_json::to_string_pretty(&json!({
                "facts_pushed": result.facts_pushed,
                "total_push_count": cursor.push_count,
            }))
            .unwrap_or_default();
            Ok(json!({
                "content": [{ "type": "text", "text": text }]
            }))
        }
        Err(e) => Ok(sync_error_content(&format!("sync push failed: {e}"))),
    }
}

/// `sync_status` — show sync configuration and last sync state.
pub async fn handle_sync_status(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let remote_url = std::env::var("CORECRUXD_SYNC_REMOTE_URL")
        .ok()
        .filter(|s| !s.is_empty());
    let configured = remote_url.is_some();

    let data_dir =
        PathBuf::from(std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v3".to_string()));

    let cursor = if configured {
        let client = SyncClient::new(remote_url.as_deref().unwrap_or(""), "", &data_dir);
        client.load_cursor()
    } else {
        corecrux_memory::sync::SyncCursor::default()
    };

    let local_fact_count = ctx.fact_store.read().await.count();

    let text = serde_json::to_string_pretty(&json!({
        "configured": configured,
        "remote_url": remote_url.unwrap_or_default(),
        "last_pull_at": cursor.last_pull_at,
        "last_push_at": cursor.last_push_at,
        "pull_count": cursor.pull_count,
        "push_count": cursor.push_count,
        "local_fact_count": local_fact_count,
    }))
    .unwrap_or_default();

    Ok(json!({
        "content": [{ "type": "text", "text": text }]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    #[tokio::test]
    async fn sync_pull_not_configured() {
        // Ensure env vars are NOT set for this test.
        std::env::remove_var("CORECRUXD_SYNC_REMOTE_URL");
        std::env::remove_var("CORECRUXD_SYNC_API_KEY");

        let ctx = test_ctx();
        let result = handle_sync_pull(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("sync not configured"));
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn sync_push_not_configured() {
        std::env::remove_var("CORECRUXD_SYNC_REMOTE_URL");
        std::env::remove_var("CORECRUXD_SYNC_API_KEY");

        let ctx = test_ctx();
        let result = handle_sync_push(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("sync not configured"));
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn sync_status_not_configured() {
        std::env::remove_var("CORECRUXD_SYNC_REMOTE_URL");

        let ctx = test_ctx();
        let result = handle_sync_status(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"configured\": false"));
    }

    #[tokio::test]
    async fn sync_status_shows_local_fact_count() {
        std::env::remove_var("CORECRUXD_SYNC_REMOTE_URL");

        let ctx = test_ctx();
        // Store a fact so count > 0
        {
            let mut store = ctx.fact_store.write().await;
            store.store(corecrux_memory::fact_store::StoreFact {
                entity: "test".to_string(),
                key: "k".to_string(),
                value: "v".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
        }

        let result = handle_sync_status(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"local_fact_count\": 1"));
    }
}
