// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `engram_resolve` — MCP surface for the local engram catalog.
//!
//! Engrams are pre-execution behavioural overlays (see
//! `corecrux_memory::engrams`), previously reachable only over the daemon's
//! HTTP routes. This tool gives MCP agents the same contract in-process:
//!
//! - **manifest mode** (no `names`): returns the capability class derived
//!   from `model_id` plus the content-free engram manifest — the discovery
//!   handshake an agent runs once per session.
//! - **resolve mode** (`names: ["name@version", ...]`): returns full content
//!   for each requested engram the caller's capability class may use.
//!
//! Flag-gated OFF by default via `CORECRUXD_FEATURE_ENGRAM_MCP`.

use serde_json::{json, Value};

use crate::dispatch::{McpContext, CAPABILITY_DENIED};
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use corecrux_memory::engrams::{
    build_engram_manifest, compute_engram_set_hash, local_catalog_with_overlays, model_id_to_capability_class,
    prompt_hash, resolve_from_catalog,
};

pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_ENGRAM_MCP";

/// Returns true if the engram MCP surface is enabled.
///
/// Default-off (opt-in): an unset env var means disabled. Any value other
/// than `""`/`0`/`false`/`off` (case-insensitive) enables it.
pub fn engram_mcp_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off")
        }
        Err(_) => false,
    }
}

fn feature_disabled_error() -> JsonRpcError {
    JsonRpcError {
        code: CAPABILITY_DENIED,
        message: format!("engram MCP surface disabled (set {FEATURE_FLAG_ENV}=1 to enable; it is off by default)"),
        data: Some(json!({"flag": FEATURE_FLAG_ENV})),
    }
}

pub async fn handle_engram_resolve(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !engram_mcp_enabled() {
        return Err(feature_disabled_error());
    }
    handle_inner(args, ctx).await
}

/// Flag-free core, separated so tests can drive it without process-global
/// env-var races.
async fn handle_inner(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let names: Vec<String> = args
        .get("names")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
        .unwrap_or_default();
    if names.len() > 20 {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "names must contain at most 20 name@version entries".to_string(),
            data: None,
        });
    }
    let model_id = args.get("model_id").and_then(|v| v.as_str());
    let intent_bucket = args.get("intent_bucket").and_then(|v| v.as_str());
    let tenant_id = args.get("tenant_id").and_then(|v| v.as_str()).unwrap_or("local");
    let capability_class = model_id_to_capability_class(model_id);

    let store = ctx.fact_store.read().await;
    let mut catalog = local_catalog_with_overlays(&store);
    drop(store);
    if let Some(bucket) = intent_bucket.filter(|s| !s.trim().is_empty()) {
        catalog.retain(|e| e.intent_bucket == bucket);
    }

    let manifest = build_engram_manifest(&catalog, tenant_id, &capability_class);

    if names.is_empty() {
        let text = serde_json::to_string_pretty(&json!({
            "schema": "crux.mcp.engram_manifest.v1",
            "capability_class": capability_class,
            "engram_manifest": manifest,
        }))
        .unwrap_or_default();
        return Ok(json!({ "content": [{ "type": "text", "text": text }] }));
    }

    let outcome = resolve_from_catalog(&catalog, &names, &capability_class);
    if !outcome.missing.is_empty() {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("capability_class_mismatch_or_missing: {}", outcome.missing.join(", ")),
            data: Some(json!({"missing": outcome.missing, "capability_class": capability_class})),
        });
    }
    let resolved = outcome.resolved;
    let engram_set_hash = compute_engram_set_hash(&resolved);
    let text = serde_json::to_string_pretty(&json!({
        "schema": "crux.mcp.engrams.resolve.v1",
        "capability_class": capability_class,
        "engrams": resolved.iter().map(|e| json!({
            "name": e.name,
            "version": e.version,
            "intent_bucket": e.intent_bucket,
            "content": e.content,
            "prompt_hash": prompt_hash(&e.content),
            "applicable_why": e.applicable_why,
        })).collect::<Vec<_>>(),
        "engram_set_hash": engram_set_hash,
        "manifest_hash": manifest["manifest_hash"],
    }))
    .unwrap_or_default();
    Ok(json!({ "content": [{ "type": "text", "text": text }] }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_defaults_off() {
        // Do not set the env var anywhere in this test binary — parallel
        // tests share the process environment.
        assert!(!engram_mcp_enabled());
    }

    #[tokio::test]
    async fn manifest_mode_lists_without_content() {
        let ctx = McpContext::new_default("t");
        let out = handle_inner(&serde_json::json!({"model_id": "claude-fable-5"}), &ctx)
            .await
            .expect("manifest mode ok");
        let text = out["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"capability_class\": \"frontier\""));
        assert!(text.contains("code-minimalism"));
        // Content-free: manifest rows carry hashes, never the prompt text.
        assert!(!text.contains("crux-min:"));
    }

    #[tokio::test]
    async fn resolve_mode_returns_content() {
        let ctx = McpContext::new_default("t");
        let out = handle_inner(
            &serde_json::json!({"names": ["code-minimalism@v1"], "model_id": "claude-opus-4-8"}),
            &ctx,
        )
        .await
        .expect("resolve mode ok");
        let text = out["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("crux-min:"));
        assert!(text.contains("engram_set_hash"));
        let payload: Value = serde_json::from_str(text).expect("valid resolve payload");
        assert_eq!(payload["engrams"][0]["version"], "v1");
        assert!(payload["engrams"][0]["applicable_why"]
            .as_str()
            .is_some_and(|why| why.contains("executed no generated patch")));
    }
}
