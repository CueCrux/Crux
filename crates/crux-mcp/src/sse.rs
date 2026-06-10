// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Server→client push channel for MCP Streamable HTTP (dynamic-tool-surface M3.5).
//!
//! The base MCP transport is request/response over `POST /mcp`. This module adds
//! the optional server-initiated side: a client opens an SSE stream on
//! `GET /mcp` (`Accept: text/event-stream`) carrying its `Mcp-Session-Id`, and
//! the server can push JSON-RPC notifications on it — currently just
//! `notifications/tools/list_changed`, fired when the `dynamic` tool surface is
//! reshaped (e.g. after `cuecrux_session(intent=…)` changes the declared intent).
//!
//! Inert unless a client opts in: with no registered SSE stream for a session,
//! [`notify_list_changed`] is a no-op. Process-global, mirroring `crate::traces`
//! / `crate::tools::surface` — no `McpContext` field churn.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// The exact JSON-RPC notification an MCP client expects when the advertised
/// tool list changes (it should then re-request `tools/list`).
pub const TOOLS_LIST_CHANGED: &str = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;

fn registry() -> &'static Mutex<HashMap<String, UnboundedSender<String>>> {
    static REG: OnceLock<Mutex<HashMap<String, UnboundedSender<String>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register an SSE stream for `session_id`, returning the receiver the stream
/// drains. A prior stream for the same id is replaced (last writer wins).
pub fn register(session_id: &str) -> UnboundedReceiver<String> {
    let (tx, rx) = unbounded_channel();
    registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(session_id.to_string(), tx);
    rx
}

/// Drop the sender for `session_id` (called when its SSE stream ends).
pub fn unregister(session_id: &str) {
    registry().lock().unwrap_or_else(|p| p.into_inner()).remove(session_id);
}

/// Push `notifications/tools/list_changed` to `session_id`'s open SSE stream, if
/// one is registered. Returns `true` when delivered. A closed receiver (client
/// disconnected) is pruned lazily and returns `false`.
pub fn notify_list_changed(session_id: &str) -> bool {
    let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    let Some(tx) = reg.get(session_id) else {
        return false;
    };
    if tx.send(TOOLS_LIST_CHANGED.to_string()).is_ok() {
        true
    } else {
        reg.remove(session_id); // receiver gone — prune
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_then_notify_delivers() {
        let mut rx = register("sess-A");
        assert!(notify_list_changed("sess-A"), "delivered to a registered session");
        let msg = rx.recv().await.expect("a pushed message");
        assert!(msg.contains("notifications/tools/list_changed"));
        unregister("sess-A");
    }

    #[test]
    fn notify_unknown_session_is_noop() {
        assert!(!notify_list_changed("no-such-session-xyz"));
    }

    #[tokio::test]
    async fn unregister_stops_delivery() {
        let _rx = register("sess-B");
        unregister("sess-B");
        assert!(!notify_list_changed("sess-B"), "no delivery after unregister");
    }

    #[tokio::test]
    async fn dropped_receiver_is_pruned() {
        let rx = register("sess-C");
        drop(rx);
        assert!(!notify_list_changed("sess-C"), "closed receiver ⇒ false + pruned");
        assert!(!notify_list_changed("sess-C"), "stays pruned on the next call");
    }
}
