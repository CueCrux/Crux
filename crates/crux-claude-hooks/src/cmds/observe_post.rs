// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `PostToolUse` hook — the close half of the observe (capture) ExecPlan.
//!
//! Pairs with `observe-pre`: the PreToolUse hook OPENs an `agent_trace_node`
//! step for the tool call, this hook performs the CLOSE
//! (`PATCH /v1/observe/sessions/{id}/steps/{node_id}`) by deriving the same
//! deterministic `node_id` and appending the tool's outputs + terminal status.
//!
//! Gated by `CRUX_HOOK_OBSERVE_CAPTURE` (default OFF). Best-effort and
//! non-blocking: the daemon being unreachable / the observe surface disabled /
//! the open never having reached the daemon all degrade silently. The hook
//! emits no decision (PostToolUse cannot block) and always exits 0.

use crate::hook_input::HookInput;
use crate::observe_capture;

/// Entry point dispatched from `main.rs` for the `observe-post` subcommand.
pub fn run<R: std::io::Read>(reader: R) -> anyhow::Result<()> {
    // No stdin (manual invocation) → nothing to close.
    let Some(input) = HookInput::read_from(reader)? else {
        return Ok(());
    };
    // Fire-and-forget close; any error is swallowed inside `close`.
    observe_capture::close(&input);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_stdin_is_a_noop() {
        run(std::io::Cursor::new("")).unwrap();
    }

    #[test]
    fn close_degrades_when_daemon_unreachable() {
        // Opt in to capture but point at a closed port: the close must not
        // error out the hook.
        let _env = crate::test_support::env_guard();
        let prev_flag = std::env::var("CRUX_HOOK_OBSERVE_CAPTURE").ok();
        let prev_url = std::env::var("CRUX_HTTP_URL").ok();
        std::env::set_var("CRUX_HOOK_OBSERVE_CAPTURE", "1");
        std::env::set_var("CRUX_HTTP_URL", "http://127.0.0.1:1");

        let payload = json!({
            "session_id": "s1",
            "hook_event_name": "PostToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "/tmp/x.rs"},
            "tool_response": {"ok": true}
        })
        .to_string();
        run(std::io::Cursor::new(payload)).unwrap();

        match prev_flag {
            Some(v) => std::env::set_var("CRUX_HOOK_OBSERVE_CAPTURE", v),
            None => std::env::remove_var("CRUX_HOOK_OBSERVE_CAPTURE"),
        }
        match prev_url {
            Some(v) => std::env::set_var("CRUX_HTTP_URL", v),
            None => std::env::remove_var("CRUX_HTTP_URL"),
        }
    }
}
