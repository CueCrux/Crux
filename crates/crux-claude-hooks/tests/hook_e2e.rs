// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! End-to-end regression test for the MCP client's auth path.
//!
//! Why this exists (2026-05-21): the `Authorization: Bearer` header was
//! missing from `call_tool_at` for ~12+ sessions, producing silent 401s
//! against the auth'd remote daemon at `100.70.12.73:14801`. The hook
//! returned no `additionalContext` but the binary exit was clean, so no
//! signal reached the operator. This test pins the contract: when a token
//! is supplied, the request MUST carry `Authorization: Bearer <token>`.
//!
//! Implementation: a stdlib `TcpListener` accepts ONE request per test,
//! returns the canned response, and surfaces the raw request bytes for
//! header assertion. Zero new dependencies; per-test ports so the suite
//! runs in parallel cleanly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use crux_claude_hooks::mcp_client::call_tool_at_with_token;

/// One-shot mock: bind a random localhost port, read one HTTP request,
/// write the canned response, return both the URL the client should hit
/// and a join handle yielding the captured raw request bytes.
fn spawn_mock(response_body: &str, status_line: &str) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
    let port = listener.local_addr().unwrap().port();
    let response = format!(
        "HTTP/1.1 {status_line}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        response_body.len(),
        response_body
    );

    let handle = thread::spawn(move || -> String {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set_read_timeout");

        // Read headers to "\r\n\r\n", then exactly Content-Length body bytes.
        // The previous heuristic (stop once headers seen && total > 200) replied
        // and closed before draining the body whenever the headers alone passed
        // 200 bytes — i.e. precisely when an Authorization header was present —
        // racing the client's in-flight request write (EINVAL on macOS arm64;
        // broke the aarch64-apple-darwin release build since v0.4.8).
        let mut buf = Vec::with_capacity(8192);
        let mut tmp = [0u8; 4096];
        let mut header_end = None;
        loop {
            match stream.read(&mut tmp) {
                Ok(0) | Err(_) => break, // EOF or timeout
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        break;
                    }
                    if buf.len() > 65536 {
                        break;
                    }
                }
            }
        }
        if let Some(he) = header_end {
            let headers = String::from_utf8_lossy(&buf[..he]).to_ascii_lowercase();
            let body_len = headers
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while buf.len() < he + body_len {
                match stream.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
        }
        let captured = String::from_utf8_lossy(&buf).to_string();
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        captured
    });

    (format!("http://127.0.0.1:{port}/mcp"), handle)
}

#[test]
fn auth_header_present_when_token_provided() {
    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}"#;
    let (url, handle) = spawn_mock(body, "200 OK");

    let r = call_tool_at_with_token(
        &url,
        "sync_status",
        serde_json::json!({}),
        Some("test-token-xyz".to_string()),
    )
    .expect("call should succeed against the mock");

    let captured = handle.join().expect("mock thread join");
    assert!(
        captured.contains("authorization: Bearer test-token-xyz")
            || captured.contains("Authorization: Bearer test-token-xyz"),
        "Authorization header missing — regression of the 2026-05-21 silent-401 bug. \
         Captured request was:\n{captured}"
    );
    assert!(
        r.get("content").is_some(),
        "Response result not parsed correctly: {r:?}"
    );
}

#[test]
fn auth_header_absent_when_token_none() {
    // Preserves the pre-auth local-daemon path: no token → no header,
    // so an unauth'd local daemon at 127.0.0.1:14801 still works.
    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#;
    let (url, handle) = spawn_mock(body, "200 OK");

    call_tool_at_with_token(&url, "sync_status", serde_json::json!({}), None)
        .expect("local-daemon call should succeed without auth header");

    let captured = handle.join().expect("mock thread join");
    assert!(
        !captured.to_lowercase().contains("authorization:"),
        "Authorization header leaked when token was None. Captured request:\n{captured}"
    );
}

#[test]
fn auth_header_absent_when_token_empty_string_in_env() {
    // Belt-and-braces: the public `call_tool_at` honours `CRUX_AGENT_TOKEN`,
    // and `mcp_token()` must treat an empty env value as `None`. Tests the
    // env path that hooks actually use in production.
    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#;
    let (url, handle) = spawn_mock(body, "200 OK");

    let prev = std::env::var("CRUX_AGENT_TOKEN").ok();
    std::env::set_var("CRUX_AGENT_TOKEN", "");
    let r = crux_claude_hooks::mcp_client::call_tool_at(&url, "sync_status", serde_json::json!({}));
    match prev {
        Some(v) => std::env::set_var("CRUX_AGENT_TOKEN", v),
        None => std::env::remove_var("CRUX_AGENT_TOKEN"),
    }
    r.expect("empty-token call should succeed");

    let captured = handle.join().expect("mock thread join");
    assert!(
        !captured.to_lowercase().contains("authorization:"),
        "Empty CRUX_AGENT_TOKEN must NOT produce an Authorization header. Captured:\n{captured}"
    );
}

#[test]
fn http_401_does_not_silently_succeed() {
    // The actual failure mode of the 2026-05-21 bug: daemon returned 401,
    // hook treated it as "no result", produced empty additionalContext.
    // The caller MUST observe an error — silent empty is the regression.
    let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unauthorized"}}"#;
    let (url, _handle) = spawn_mock(body, "401 Unauthorized");

    let result = call_tool_at_with_token(
        &url,
        "sync_status",
        serde_json::json!({}),
        Some("wrong-token".to_string()),
    );
    assert!(
        result.is_err(),
        "401 must produce Err, not Ok-with-empty — that was the silent-401 bug. Got: {result:?}"
    );
}
