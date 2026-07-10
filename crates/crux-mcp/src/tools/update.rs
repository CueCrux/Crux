// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Update tool handler: `update_status`.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR};

/// `update_status` — show whether this checkout is current, behind, ahead,
/// diverged, disabled, or unavailable relative to the tracked git branch.
pub async fn handle_update_status(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let mut payload = serde_json::to_value(ctx.update_status.read().await.clone()).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("failed to serialise update status: {err}"),
        data: None,
    })?;
    if let Some(object) = payload.as_object_mut() {
        object.insert(
            "upgrade_playbook_query".to_string(),
            json!("get_bootstrap(topic=\"docs\", query=\"upgrade\")"),
        );
        object.insert(
            "backup_playbook_query".to_string(),
            json!("get_bootstrap(topic=\"docs\", query=\"backup\")"),
        );
    }

    let text = serde_json::to_string_pretty(&payload).unwrap_or_default();
    Ok(json!({
        "content": [{
            "type": "text",
            "text": text
        }]
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;
    use corecrux_types::{UpdateCheckState, UpdateStatus};

    #[tokio::test]
    async fn update_status_returns_cached_state() {
        let ctx = McpContext::new_default("test-node");
        *ctx.update_status.write().await = UpdateStatus {
            enabled: true,
            state: UpdateCheckState::Behind,
            remote: "origin".to_string(),
            ref_name: "main".to_string(),
            tracking_ref: "origin/main".to_string(),
            repo_dir: Some("/tmp/repo".to_string()),
            current_commit: Some("abc123".to_string()),
            latest_commit: Some("def456".to_string()),
            ahead_by: 0,
            behind_by: 2,
            checked_at: Some("2026-04-09T12:00:00Z".to_string()),
            error: None,
            comparison_stale: false,
            upgrade_hint: "upgrade available".to_string(),
        };

        let result = handle_update_status(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"state\": \"behind\""));
        assert!(text.contains("\"repo_dir\": \"/tmp/repo\""));
        assert!(text.contains("upgrade_playbook_query"));
        assert!(text.contains("backup_playbook_query"));
    }
}
