// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[test]
    fn empty_stdin_is_a_noop() {
        run(std::io::Cursor::new("")).unwrap();
    }

    /// A throwaway recording HTTP server: counts every accepted connection and
    /// replies `200 {}`. Returns `(base_url, hit_counter, stop_flag,
    /// JoinHandle)`. Uses a non-blocking accept loop so the thread never wedges
    /// on a connection that never arrives — set the stop flag and join. Std-only,
    /// no new test dep.
    #[allow(clippy::type_complexity)]
    fn recording_server() -> (String, Arc<AtomicUsize>, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let hits_thread = Arc::clone(&hits);
        let stop_thread = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        hits_thread.fetch_add(1, Ordering::SeqCst);
                        let mut buf = [0u8; 1024];
                        let _ = stream.read(&mut buf);
                        let body = "{}";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::yield_now();
                    }
                    Err(_) => break,
                }
            }
        });
        (format!("http://127.0.0.1:{port}"), hits, stop, handle)
    }

    /// B4 / workspace-rule guard: the PostToolUse hook must NEVER call
    /// `store_fact` (or any MCP tool) and must ALWAYS exit 0 (fire-and-forget).
    ///
    /// We point `CRUX_MCP_URL` at a recording server and `CRUX_HTTP_URL` at
    /// another, turn capture ON, and run the hook against a file-mod payload.
    /// Assertions:
    ///   1. `run(...)` returns `Ok` — the hook always succeeds / exits 0.
    ///   2. the MCP server saw ZERO connections — no `store_fact`, no
    ///      `call_tool`; the observation lane uses HTTP `/v1/observe` only.
    ///   3. the HTTP observe server saw at least one connection — the receipted
    ///      lane IS exercised (so #2 isn't a false pass from a dead code path).
    #[test]
    fn post_tool_use_writes_no_fact_and_exits_zero() {
        let _env = crate::test_support::env_guard();
        let prev_flag = std::env::var("CRUX_HOOK_OBSERVE_CAPTURE").ok();
        let prev_http = std::env::var("CRUX_HTTP_URL").ok();
        let prev_mcp = std::env::var("CRUX_MCP_URL").ok();

        // The close path issues: a GET (read-back blake3_before) + a PATCH —
        // both over HTTP. The MCP server must stay untouched.
        let (http_url, http_hits, http_stop, http_handle) = recording_server();
        let (mcp_url, mcp_hits, mcp_stop, mcp_handle) = recording_server();

        std::env::set_var("CRUX_HOOK_OBSERVE_CAPTURE", "1");
        std::env::set_var("CRUX_HTTP_URL", &http_url);
        std::env::set_var("CRUX_MCP_URL", format!("{mcp_url}/mcp"));

        let payload = json!({
            "session_id": "s-no-fact",
            "cwd": "/tmp",
            "hook_event_name": "PostToolUse",
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/tmp/b4-x.rs",
                "old_string": "a",
                "new_string": "a\nb"
            },
            "tool_response": {"ok": true}
        })
        .to_string();

        // 1. Always exits 0 (run returns Ok).
        run(std::io::Cursor::new(payload)).unwrap();

        // Restore env before joining so a panic doesn't leak global state.
        match prev_flag {
            Some(v) => std::env::set_var("CRUX_HOOK_OBSERVE_CAPTURE", v),
            None => std::env::remove_var("CRUX_HOOK_OBSERVE_CAPTURE"),
        }
        match prev_http {
            Some(v) => std::env::set_var("CRUX_HTTP_URL", v),
            None => std::env::remove_var("CRUX_HTTP_URL"),
        }
        match prev_mcp {
            Some(v) => std::env::set_var("CRUX_MCP_URL", v),
            None => std::env::remove_var("CRUX_MCP_URL"),
        }

        // `run` is synchronous: all HTTP work completed before it returned, so
        // the counters are final. Stop + join the non-blocking accept loops.
        http_stop.store(true, Ordering::SeqCst);
        mcp_stop.store(true, Ordering::SeqCst);
        let join_deadline = Instant::now() + Duration::from_secs(2);
        for h in [http_handle, mcp_handle] {
            // The threads check the stop flag each loop iteration; join is bounded.
            while !h.is_finished() && Instant::now() < join_deadline {
                std::thread::yield_now();
            }
            let _ = h.join();
        }

        // 2. ZERO MCP calls → no store_fact / no call_tool from PostToolUse.
        assert_eq!(
            mcp_hits.load(Ordering::SeqCst),
            0,
            "PostToolUse must not call any MCP tool (store_fact is forbidden behind PostToolUse hooks)"
        );
        // 3. The receipted HTTP observe lane WAS used.
        assert!(
            http_hits.load(Ordering::SeqCst) >= 1,
            "the observe (capture) lane must write over the receipted /v1/observe HTTP path"
        );
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
