// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Sync tool handlers: `sync_pull`, `sync_push`, `sync_status`.

use std::path::PathBuf;

use serde_json::{json, Value};

use corecrux_memory::sync::{probe_remote_health, promotion_preview, SyncClient, SyncRuntimeStatus};

use crate::dispatch::McpContext;
use crate::protocol::JsonRpcError;
use crate::tools::passport;

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

    Ok(SyncClient::new(&remote_url, &api_key, &sync_data_dir()))
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

fn sync_data_dir() -> PathBuf {
    PathBuf::from(std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string()))
}

fn sync_background_enabled() -> bool {
    std::env::var("CORECRUXD_SYNC_ENABLED")
        .ok()
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn sync_runtime_status() -> SyncRuntimeStatus {
    let remote_url = std::env::var("CORECRUXD_SYNC_REMOTE_URL")
        .ok()
        .filter(|value| !value.is_empty());
    let api_key_configured = std::env::var("CORECRUXD_SYNC_API_KEY")
        .ok()
        .is_some_and(|value| !value.is_empty());

    let status = SyncRuntimeStatus::from_settings(sync_background_enabled(), remote_url.as_deref(), api_key_configured);

    if status.remote_url.is_empty() || !status.configured {
        return status;
    }

    let probe_url = status.remote_url.clone();
    status.with_probe_result(probe_remote_health(&probe_url))
}

fn onboarding_hint(status: &SyncRuntimeStatus) -> &'static str {
    if status.degraded || status.mode == "local_only" {
        "Continue local-first. Pull onboarding guidance with get_bootstrap(topic=\"docs\", query=\"integration\") and share the human or automatic integration playbook that matches the environment."
    } else {
        "Remote sync is available. Use get_bootstrap(topic=\"docs\", query=\"automatic integration\") for system hookup steps, then verify with store_fact/query_facts or sync_pull/sync_push."
    }
}

/// `sync_pull` — pull latest facts from the remote CoreCrux instance.
///
/// Requires an agent passport with at least `basic` tier.
pub async fn handle_sync_pull(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if let Err(gate_error) = passport::require_passport_tier(ctx, "basic").await {
        return Ok(gate_error);
    }

    let client = match build_sync_client() {
        Ok(c) => c,
        Err(msg) => return Ok(sync_error_content(&msg)),
    };

    let tenant_id = _args
        .get("tenant_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let mut store = ctx.fact_store.write().await;
    let result = if let Some(tenant_id) = tenant_id {
        client.pull_tenant_mirror(&mut store, tenant_id)
    } else {
        client.pull(&mut store)
    };

    match result {
        Ok(result) => {
            let cursor = client.load_cursor();
            let text = serde_json::to_string_pretty(&json!({
                "tenant_id": tenant_id,
                "facts_pulled": result.facts_pulled,
                "cursor": result.new_cursor,
                "total_pull_count": cursor.pull_count,
                "collection_cursor_count": cursor.collection_pull_cursors.len(),
            }))
            .unwrap_or_default();
            Ok(json!({
                "content": [{ "type": "text", "text": text }]
            }))
        }
        Err(e) => Ok(sync_error_content(&format!(
            "{e}. Local fact and session storage on this node remain available."
        ))),
    }
}

/// `sync_push` — push local facts to the remote CoreCrux instance.
///
/// Requires an agent passport with at least `established` tier.
///
/// Without `confirm: true`, returns a preview of what would be pushed
/// (entities, count, skipped private count). With `confirm: true`, actually
/// pushes the facts.
pub async fn handle_sync_push(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if let Err(gate_error) = passport::require_passport_tier(ctx, "established").await {
        return Ok(gate_error);
    }

    let client = match build_sync_client() {
        Ok(c) => c,
        Err(msg) => return Ok(sync_error_content(&msg)),
    };

    let confirm = args.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);
    let tenant_id = args
        .get("tenant_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let allowlist = args
        .get("allowlist")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if let Some(tenant_id) = tenant_id {
        if !confirm {
            let store = ctx.fact_store.read().await;
            let preview = promotion_preview(&store, tenant_id, &allowlist, false);
            let text = serde_json::to_string_pretty(&json!({
                "mode": "tenant_promotion_preview",
                "tenant_id": tenant_id,
                "allowlist": preview.allowlist,
                "would_promote": preview.promote_count,
                "skipped_private": preview.skipped_private,
                "skipped_synced": preview.skipped_synced,
                "skipped_not_allowlisted": preview.skipped_not_allowlisted,
                "preview_hash": preview.preview_hash,
                "note": "Call sync_push with tenant_id, allowlist, confirm=true to promote these records."
            }))
            .unwrap_or_default();
            return Ok(json!({
                "content": [{ "type": "text", "text": text }]
            }));
        }

        let preview = {
            let store = ctx.fact_store.read().await;
            promotion_preview(&store, tenant_id, &allowlist, true)
        };
        match client.push_tenant_promotion(tenant_id, &preview.records) {
            Ok(result) => {
                let cursor = client.load_cursor();
                let text = serde_json::to_string_pretty(&json!({
                    "tenant_id": tenant_id,
                    "facts_pushed": result.facts_pushed,
                    "preview_hash": preview.preview_hash,
                    "total_push_count": cursor.push_count,
                    "collection_cursor_count": cursor.collection_push_cursors.len(),
                }))
                .unwrap_or_default();
                return Ok(json!({
                    "content": [{ "type": "text", "text": text }]
                }));
            }
            Err(e) => {
                return Ok(sync_error_content(&format!(
                    "{e}. Local fact and session storage on this node remain available."
                )))
            }
        }
    }

    if !confirm {
        // Preview mode — show what would be pushed without actually pushing.
        let store = ctx.fact_store.read().await;
        let preview = client.push_preview(&store);
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
    match client.push(&store) {
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
        Err(e) => Ok(sync_error_content(&format!(
            "{e}. Local fact and session storage on this node remain available."
        ))),
    }
}

/// `sync_status` — show sync configuration and last sync state.
pub async fn handle_sync_status(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let status = sync_runtime_status();
    let onboarding_hint = onboarding_hint(&status);

    let cursor = if status.remote_url.is_empty() {
        corecrux_memory::sync::SyncCursor::default()
    } else {
        let client = SyncClient::new(&status.remote_url, "", &sync_data_dir());
        client.load_cursor()
    };

    let local_fact_count = ctx.fact_store.read().await.count();

    let text = serde_json::to_string_pretty(&json!({
        "mode": status.mode,
        "configured": status.configured,
        "background_sync_enabled": status.background_sync_enabled,
        "remote_url": status.remote_url,
        "api_key_configured": status.api_key_configured,
        "platform_online": status.platform_online,
        "degraded": status.degraded,
        "degraded_reason": status.degraded_reason,
        "onboarding_hint": onboarding_hint,
        "last_pull_at": cursor.last_pull_at,
        "last_push_at": cursor.last_push_at,
        "pull_count": cursor.pull_count,
        "push_count": cursor.push_count,
        "collection_pull_cursor_count": cursor.collection_pull_cursors.len(),
        "collection_push_cursor_count": cursor.collection_push_cursors.len(),
        "tenant_manifest_supported": true,
        "local_fact_count": local_fact_count,
    }))
    .unwrap_or_default();

    Ok(json!({
        "content": [{ "type": "text", "text": text }]
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;
    use crate::tools::test_support::{clear_sync_env, sync_env_lock};
    use corecrux_memory::fact_store::StoreFact;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[derive(Debug)]
    struct RecordedRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    struct MockResponse {
        status: &'static str,
        content_type: &'static str,
        body: String,
    }

    impl MockResponse {
        fn json(body: serde_json::Value) -> Self {
            Self {
                status: "200 OK",
                content_type: "application/json",
                body: body.to_string(),
            }
        }
    }

    fn start_mock_server(
        responses: Vec<MockResponse>,
    ) -> (String, mpsc::Receiver<Vec<RecordedRequest>>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (tx, rx) = mpsc::channel();

        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept connection");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("set read timeout");
                let request = read_request(&mut stream).expect("read request");
                requests.push(request);

                let response_bytes = format!(
                    "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.status,
                    response.content_type,
                    response.body.len(),
                    response.body
                );
                stream.write_all(response_bytes.as_bytes()).expect("write response");
                stream.flush().expect("flush response");
            }
            tx.send(requests).expect("send recorded requests");
        });

        (format!("http://{}", addr), rx, handle)
    }

    fn read_request(stream: &mut TcpStream) -> std::io::Result<RecordedRequest> {
        let mut bytes = Vec::new();
        let header_end = loop {
            let mut chunk = [0u8; 1024];
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                break find_header_end(&bytes);
            }
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(end) = find_header_end(&bytes) {
                break Some(end);
            }
        }
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "request missing headers"))?;

        let header_text = std::str::from_utf8(&bytes[..header_end])
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        let mut lines = header_text.split("\r\n");
        let request_line = lines
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing request line"))?;
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing method"))?
            .to_string();
        let path = request_parts
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing path"))?
            .to_string();

        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
            }
        }

        let content_length = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = bytes[header_end..].to_vec();
        while body.len() < content_length {
            let mut chunk = [0u8; 1024];
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        body.truncate(content_length);

        Ok(RecordedRequest {
            method,
            path,
            headers,
            body,
        })
    }

    fn find_header_end(bytes: &[u8]) -> Option<usize> {
        bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
    }

    fn wait_for_requests(
        rx: mpsc::Receiver<Vec<RecordedRequest>>,
        handle: thread::JoinHandle<()>,
    ) -> Vec<RecordedRequest> {
        let requests = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("receive recorded requests");
        handle.join().expect("mock server join");
        requests
    }

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    /// Create an agent context with a passport at the given tier.
    /// Stores enough receipt-backed facts to reach the tier, issues passport, and refreshes it.
    async fn agent_with_tier(ctx: &McpContext, name: &str, tier: &str) -> McpContext {
        let agent_ctx = ctx.with_agent(AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        });

        let receipt_count: u64 = match tier {
            "elite" => 2000,
            "trusted" => 500,
            "established" => 100,
            "basic" => 10,
            _ => 0,
        };

        // Seed receipt-backed facts.
        {
            let mut store = ctx.fact_store.write().await;
            for i in 0..receipt_count {
                store.store(StoreFact {
                    entity: format!("__tier_seed__::{name}::{i}"),
                    key: "r".to_string(),
                    value: "v".to_string(),
                    source_receipt: Some(format!("receipt-{i}")),
                    confidence: 1.0,
                    private: false,
                horizon_class: None,
                });
            }
        }

        // Issue and refresh passport.
        crate::tools::passport::handle_issue_passport(&json!({}), &agent_ctx)
            .await
            .unwrap();
        crate::tools::passport::handle_get_passport(&json!({}), &agent_ctx)
            .await
            .unwrap();

        agent_ctx
    }

    #[tokio::test]
    async fn sync_pull_requires_passport() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();

        // No agent identity at all.
        let ctx = test_ctx();
        let result = handle_sync_pull(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("authenticated agent identity"));
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn sync_push_requires_passport() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();

        let ctx = test_ctx();
        let result = handle_sync_push(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("authenticated agent identity"));
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn sync_pull_rejected_without_basic_tier() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();

        let ctx = test_ctx();
        // Issue passport but no receipts = unverified tier.
        let agent_ctx = ctx.with_agent(AgentIdentity {
            name: "lowrep".to_string(),
            token_hash: [0u8; 32],
        });
        crate::tools::passport::handle_issue_passport(&json!({}), &agent_ctx)
            .await
            .unwrap();

        let result = handle_sync_pull(&json!({}), &agent_ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("basic tier or above"));
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn sync_push_rejected_without_established_tier() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();

        let ctx = test_ctx();
        let agent_ctx = agent_with_tier(&ctx, "basicagent", "basic").await;

        let result = handle_sync_push(&json!({}), &agent_ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("established tier or above"));
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn sync_pull_not_configured_with_passport() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();

        let ctx = test_ctx();
        let agent_ctx = agent_with_tier(&ctx, "basicpull", "basic").await;

        let result = handle_sync_pull(&json!({}), &agent_ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        // Passes passport gate, hits sync not configured.
        assert!(text.contains("sync not configured"));
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn sync_push_not_configured_with_passport() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();

        let ctx = test_ctx();
        let agent_ctx = agent_with_tier(&ctx, "estpush", "established").await;

        let result = handle_sync_push(&json!({}), &agent_ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("sync not configured"));
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn sync_status_not_configured() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();

        let ctx = test_ctx();
        let result = handle_sync_status(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"configured\": false"));
        assert!(text.contains("\"mode\": \"local_only\""));
    }

    #[tokio::test]
    async fn sync_status_shows_local_fact_count() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();

        let ctx = test_ctx();
        // Store a fact so count > 0
        {
            let mut store = ctx.fact_store.write().await;
            store.store(StoreFact {
                entity: "test".to_string(),
                key: "k".to_string(),
                value: "v".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            horizon_class: None,
            });
        }

        let result = handle_sync_status(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"local_fact_count\": 1"));
    }

    #[test]
    fn sync_data_dir_defaults_and_honors_override() {
        let _guard = sync_env_lock().blocking_lock();
        clear_sync_env();
        assert_eq!(sync_data_dir(), PathBuf::from("../CoreCruxData/v1"));

        std::env::set_var("CORECRUXD_DATA_DIR", "/tmp/crux-sync");
        assert_eq!(sync_data_dir(), PathBuf::from("/tmp/crux-sync"));
        clear_sync_env();
    }

    #[test]
    fn sync_error_content_marks_error() {
        let result = sync_error_content("boom");
        assert_eq!(result["isError"], true);
        assert_eq!(result["content"][0]["text"], "boom");
    }

    #[test]
    fn build_sync_client_requires_api_key_when_url_is_set() {
        let _guard = sync_env_lock().blocking_lock();
        clear_sync_env();
        std::env::set_var("CORECRUXD_SYNC_REMOTE_URL", "http://example.test:14800");

        match build_sync_client() {
            Ok(_) => panic!("expected missing API key error"),
            Err(err) => assert_eq!(err, "sync not configured: CORECRUXD_SYNC_API_KEY is not set"),
        }
        clear_sync_env();
    }

    #[tokio::test]
    async fn sync_status_reads_configured_cursor() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();
        let dir = tempfile::tempdir().unwrap();
        let (remote_url, rx, handle) = start_mock_server(vec![MockResponse::json(json!({"ok": true}))]);
        let client = SyncClient::new(&remote_url, "ignored", dir.path());
        client.save_cursor(&corecrux_memory::sync::SyncCursor {
            last_pull_at: Some("2026-04-08T10:11:12Z".to_string()),
            last_pull_cursor: Some("cursor-123".to_string()),
            last_push_at: Some("2026-04-08T12:13:14Z".to_string()),
            pull_count: 7,
            push_count: 3,
            collection_pull_cursors: std::collections::BTreeMap::new(),
            collection_push_cursors: std::collections::BTreeMap::new(),
        });
        std::env::set_var("CORECRUXD_SYNC_REMOTE_URL", &remote_url);
        std::env::set_var("CORECRUXD_SYNC_API_KEY", "test-key");
        std::env::set_var("CORECRUXD_DATA_DIR", dir.path());

        let ctx = test_ctx();
        let result = handle_sync_status(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"configured\": true"));
        assert!(text.contains("\"mode\": \"manual_sync\""));
        assert!(text.contains(&format!("\"remote_url\": \"{remote_url}\"")));
        assert!(text.contains("\"platform_online\": true"));
        assert!(text.contains("\"pull_count\": 7"));
        assert!(text.contains("\"push_count\": 3"));
        assert_eq!(rx.recv().unwrap().len(), 1);
        handle.join().unwrap();
        clear_sync_env();
    }

    #[tokio::test]
    async fn sync_status_reports_degraded_when_api_key_missing() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();
        std::env::set_var("CORECRUXD_SYNC_REMOTE_URL", "http://example.test:14800");

        let ctx = test_ctx();
        let result = handle_sync_status(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"mode\": \"degraded\""));
        assert!(text.contains("\"api_key_configured\": false"));
        assert!(text.contains("CORECRUXD_SYNC_API_KEY is missing"));
        clear_sync_env();
    }

    #[tokio::test]
    async fn sync_push_preview_reports_counts() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("CORECRUXD_SYNC_REMOTE_URL", "http://example.test:14800");
        std::env::set_var("CORECRUXD_SYNC_API_KEY", "test-key");
        std::env::set_var("CORECRUXD_DATA_DIR", dir.path());

        let ctx = test_ctx();
        let agent_ctx = agent_with_tier(&ctx, "pushpreview", "established").await;
        {
            let mut store = ctx.fact_store.write().await;
            store.store(StoreFact {
                entity: "deploy".to_string(),
                key: "status".to_string(),
                value: "green".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            horizon_class: None,
            });
            store.store(StoreFact {
                entity: "private:salary".to_string(),
                key: "amount".to_string(),
                value: "redacted".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            horizon_class: None,
            });
            store.store(StoreFact {
                entity: "deploy".to_string(),
                key: "source".to_string(),
                value: "remote".to_string(),
                source_receipt: Some("sync:http://example.test:14800:f_remote".to_string()),
                confidence: 1.0,
                private: false,
            horizon_class: None,
            });
        }

        let result = handle_sync_push(&json!({ "confirm": false }), &agent_ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"mode\": \"preview\""));
        // Counts include tier-seed facts + the 3 explicit ones; just check structure.
        assert!(text.contains("\"would_push\""));
        assert!(text.contains("\"skipped_private\""));
        assert!(text.contains("\"skipped_synced\""));
        clear_sync_env();
    }

    #[tokio::test]
    async fn sync_push_tenant_preview_reports_collection_counts() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("CORECRUXD_SYNC_REMOTE_URL", "http://example.test:14800");
        std::env::set_var("CORECRUXD_SYNC_API_KEY", "test-key");
        std::env::set_var("CORECRUXD_DATA_DIR", dir.path());

        let ctx = test_ctx();
        let agent_ctx = agent_with_tier(&ctx, "tenantpreview", "established").await;
        {
            let mut store = ctx.fact_store.write().await;
            store.store(StoreFact {
                entity: "business::acme::note".to_string(),
                key: "summary".to_string(),
                value: "promote".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            horizon_class: None,
            });
            store.store(StoreFact {
                entity: "business::acme::constraint::deploy".to_string(),
                key: "constraint".to_string(),
                value: "skip by allowlist".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            horizon_class: None,
            });
        }

        let result = handle_sync_push(
            &json!({
                "tenant_id": "business::acme",
                "allowlist": ["facts"]
            }),
            &agent_ctx,
        )
        .await
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"mode\": \"tenant_promotion_preview\""));
        assert!(text.contains("\"tenant_id\": \"business::acme\""));
        assert!(text.contains("\"would_promote\": 1"));
        assert!(text.contains("\"skipped_not_allowlisted\": 1"));
        assert!(text.contains("\"preview_hash\""));
        clear_sync_env();
    }

    #[tokio::test]
    async fn sync_pull_success_reports_cursor_and_total_count() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();
        let dir = tempfile::tempdir().unwrap();
        let (url, rx, handle) = start_mock_server(vec![MockResponse::json(serde_json::json!({
            "facts": [{
                "fact_id": "f_remote_sync_1",
                "entity": "deploy",
                "key": "status",
                "value": "green",
                "source_receipt": serde_json::Value::Null,
                "confidence": 1.0,
                "stored_at": "2026-04-08T10:11:12Z",
                "tokens": 1,
                "deleted": false,
                "version": 1,
                "private": false
            }],
            "next_cursor": "f_remote_sync_1",
            "has_more": false
        }))]);

        std::env::set_var("CORECRUXD_SYNC_REMOTE_URL", &url);
        std::env::set_var("CORECRUXD_SYNC_API_KEY", "test-key");
        std::env::set_var("CORECRUXD_DATA_DIR", dir.path());

        let ctx = test_ctx();
        let agent_ctx = agent_with_tier(&ctx, "pullsuccess", "basic").await;
        let pre_count = ctx.fact_store.read().await.count();

        let result = handle_sync_pull(&json!({}), &agent_ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"facts_pulled\": 1"));
        assert!(text.contains("\"cursor\": \"f_remote_sync_1\""));
        assert!(text.contains("\"total_pull_count\": 1"));
        assert_eq!(ctx.fact_store.read().await.count(), pre_count + 1);

        let requests = wait_for_requests(rx, handle);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert!(requests[0].path.starts_with("/v1/facts/export?limit=1000"));
        assert_eq!(
            requests[0].headers.get("authorization"),
            Some(&"Bearer test-key".to_string())
        );
        clear_sync_env();
    }

    #[tokio::test]
    async fn sync_push_success_reports_total_count_and_payload() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();
        let dir = tempfile::tempdir().unwrap();
        let (url, rx, handle) = start_mock_server(vec![MockResponse::json(serde_json::json!({
            "facts": []
        }))]);

        std::env::set_var("CORECRUXD_SYNC_REMOTE_URL", &url);
        std::env::set_var("CORECRUXD_SYNC_API_KEY", "test-key");
        std::env::set_var("CORECRUXD_DATA_DIR", dir.path());

        let ctx = test_ctx();
        let agent_ctx = agent_with_tier(&ctx, "pushsuccess", "established").await;
        {
            let mut store = ctx.fact_store.write().await;
            store.store(StoreFact {
                entity: "deploy".to_string(),
                key: "status".to_string(),
                value: "green".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            horizon_class: None,
            });
        }

        let result = handle_sync_push(&json!({ "confirm": true }), &agent_ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        // Push count includes tier-seed facts + the deploy fact.
        assert!(text.contains("\"facts_pushed\""));
        assert!(text.contains("\"total_push_count\""));

        let requests = wait_for_requests(rx, handle);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "PUT");
        assert_eq!(requests[0].path, "/v1/facts/bulk");
        assert_eq!(
            requests[0].headers.get("authorization"),
            Some(&"Bearer test-key".to_string())
        );

        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        let facts = body.as_array().unwrap();
        assert!(!facts.is_empty());
        clear_sync_env();
    }

    #[tokio::test]
    async fn sync_pull_and_push_report_network_errors() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("CORECRUXD_SYNC_REMOTE_URL", "http://[::1");
        std::env::set_var("CORECRUXD_SYNC_API_KEY", "test-key");
        std::env::set_var("CORECRUXD_DATA_DIR", dir.path());

        let ctx = test_ctx();
        // Need established tier for push.
        let agent_ctx = agent_with_tier(&ctx, "neterr", "established").await;

        let pull = handle_sync_pull(&json!({}), &agent_ctx).await.unwrap();
        assert_eq!(pull["isError"], true);
        assert!(pull["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("sync pull failed"));

        let push = handle_sync_push(&json!({ "confirm": true }), &agent_ctx).await.unwrap();
        assert_eq!(push["isError"], true);
        assert!(push["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("sync push failed"));
        clear_sync_env();
    }
}
