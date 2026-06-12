// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxd mcp-stdio` — the daemon-bundled stdio⇄HTTP MCP bridge.
//!
//! ExecPlan `provider-integration-surfaces-2026-06-11` M5 (G3). Many MCP
//! hosts (Codex CLI, Gemini CLI, Claude Desktop) launch stdio servers; the
//! Crux daemon serves MCP over HTTP on `:14801`. This subcommand bridges the
//! two: line-delimited JSON-RPC on stdin → `POST $CRUX_MCP_URL` → response
//! line on stdout.
//!
//! Why bundled (T.5): the shim ships *inside the daemon binary*, so there is
//! nothing extra to install and **shim version == daemon version by
//! construction** — the drift class the topology doc worries about cannot
//! occur. (`@cuecrux/mcp-lite` remains the separate, curated-profile
//! alternative for tool-count-sensitive hosts.)
//!
//! Config (env-only, matching the daemon's design):
//! - `CRUX_MCP_URL`     — upstream MCP endpoint (default `http://127.0.0.1:14801/mcp`)
//! - `CRUX_AGENT_TOKEN` — bearer token forwarded as `Authorization` (optional
//!   for loopback dev daemons with auth off)
//!
//! Protocol discipline: stdout carries ONLY JSON-RPC response lines;
//! all diagnostics go to stderr. Upstream failures are answered with a
//! JSON-RPC error (id echoed) rather than killing the host's session.
//! As a belt-and-braces check the bridge also compares the `initialize`
//! response's `serverInfo.version` against its own version and warns on
//! stderr if a mismatch slips through (e.g. CRUX_MCP_URL pointed at a
//! different daemon build than the binary running the bridge).

use std::io::{BufRead, Write};

/// Default upstream when `CRUX_MCP_URL` is unset.
pub const DEFAULT_MCP_URL: &str = "http://127.0.0.1:14801/mcp";

/// JSON-RPC error code for "upstream daemon unreachable / transport failure".
const UPSTREAM_ERROR: i64 = -32000;

fn bridge_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Forward one raw JSON-RPC line to the upstream MCP endpoint. Returns the
/// response body, or a synthesized JSON-RPC error (request id echoed) when
/// the upstream is unreachable or answers non-2xx without a JSON body.
fn forward_line(agent: &ureq::Agent, url: &str, token: Option<&str>, line: &str) -> String {
    let mut req = agent.post(url).header("Content-Type", "application/json");
    if let Some(token) = token {
        req = req.header("Authorization", &format!("Bearer {token}"));
    }
    match req.send(line) {
        Ok(mut resp) => resp
            .body_mut()
            .read_to_string()
            .unwrap_or_else(|e| upstream_error_response(line, &format!("read upstream response: {e}"))),
        Err(ureq::Error::StatusCode(code)) => {
            // Auth/validation failures surface as a JSON-RPC error so the
            // host displays something actionable instead of hanging.
            upstream_error_response(line, &format!("upstream MCP endpoint answered HTTP {code}"))
        }
        Err(e) => upstream_error_response(line, &format!("upstream MCP endpoint unreachable: {e}")),
    }
}

/// Synthesize a JSON-RPC error response, echoing the request's id when the
/// line parses (a notification without id gets `id: null`, which hosts drop).
fn upstream_error_response(request_line: &str, message: &str) -> String {
    let id = serde_json::from_str::<serde_json::Value>(request_line)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": UPSTREAM_ERROR, "message": message},
    })
    .to_string()
}

/// If `line` is an `initialize` request and `response` carries
/// `serverInfo.version`, return a drift warning when it differs from this
/// binary's version. Pure (testable); the caller prints to stderr.
fn version_drift_warning(line: &str, response: &str) -> Option<String> {
    let req: serde_json::Value = serde_json::from_str(line).ok()?;
    if req.get("method").and_then(|m| m.as_str()) != Some("initialize") {
        return None;
    }
    let resp: serde_json::Value = serde_json::from_str(response).ok()?;
    let server_version = resp
        .get("result")
        .and_then(|r| r.get("serverInfo"))
        .and_then(|s| s.get("version"))
        .and_then(|v| v.as_str())?;
    if server_version == bridge_version() {
        return None;
    }
    Some(format!(
        "corecruxd mcp-stdio: version drift — bridge {} vs daemon {} (point CRUX_MCP_URL at the daemon this binary shipped with)",
        bridge_version(),
        server_version
    ))
}

/// Run the bridge until stdin closes. Returns the process exit code.
///
/// Generic over reader/writer for tests; `main` passes locked stdio.
// Intentional stderr: stdout is reserved for the JSON-RPC stream — stderr IS
// the diagnostics channel of this CLI mode (same contract as --version's
// allowed stdout).
#[allow(clippy::print_stderr)]
fn run_loop<R: BufRead, W: Write>(url: &str, token: Option<&str>, reader: R, mut out: W) -> i32 {
    let agent = ureq::Agent::new_with_defaults();
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("corecruxd mcp-stdio: stdin read error: {e}");
                return 1;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = forward_line(&agent, url, token, &line);
        if let Some(warning) = version_drift_warning(&line, &response) {
            eprintln!("{warning}");
        }
        if writeln!(out, "{response}").and_then(|()| out.flush()).is_err() {
            // Host closed our stdout — session over.
            return 0;
        }
    }
    0
}

/// Entry point for the `mcp-stdio` CLI action.
#[allow(clippy::print_stderr)] // see run_loop note: stderr is the diagnostics channel
pub fn run() -> i32 {
    let url = std::env::var("CRUX_MCP_URL").unwrap_or_else(|_| DEFAULT_MCP_URL.to_string());
    let token = std::env::var("CRUX_AGENT_TOKEN").ok().filter(|t| !t.trim().is_empty());
    eprintln!(
        "corecruxd mcp-stdio {}: bridging stdio ⇄ {url} (auth: {})",
        bridge_version(),
        if token.is_some() {
            "bearer token from CRUX_AGENT_TOKEN"
        } else {
            "none"
        },
    );
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_loop(&url, token.as_deref(), stdin.lock(), stdout.lock())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::net::TcpListener;

    /// Minimal one-shot HTTP server: answers every request with `body` and
    /// records the raw request bytes (headers included) for assertions.
    fn stub_http_server(responses: Vec<String>) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for body in responses {
                let Ok((mut sock, _)) = listener.accept() else { return };
                let mut buf = [0u8; 65536];
                let n = sock.read(&mut buf).unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes());
            }
        });
        (format!("http://{addr}/mcp"), rx)
    }

    #[test]
    fn forwards_request_with_bearer_and_returns_body() {
        let (url, rx) = stub_http_server(vec![r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_string()]);
        let agent = ureq::Agent::new_with_defaults();
        let out = forward_line(
            &agent,
            &url,
            Some("tok-secret"),
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        );
        assert!(out.contains(r#""result":{"ok":true}"#), "unexpected response: {out}");
        let seen = rx.recv().expect("request recorded");
        assert!(
            seen.contains("Authorization: Bearer tok-secret") || seen.contains("authorization: Bearer tok-secret"),
            "missing auth header: {seen}"
        );
        assert!(seen.contains(r#""method":"tools/list""#), "body not forwarded: {seen}");
    }

    #[test]
    fn unreachable_upstream_yields_jsonrpc_error_with_request_id() {
        let agent = ureq::Agent::new_with_defaults();
        // Port 9 (discard) — nothing listens on loopback in test envs.
        let out = forward_line(
            &agent,
            "http://127.0.0.1:9/mcp",
            None,
            r#"{"jsonrpc":"2.0","id":42,"method":"tools/list"}"#,
        );
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON-RPC");
        assert_eq!(v["id"], 42, "request id echoed");
        assert_eq!(v["error"]["code"], UPSTREAM_ERROR);
    }

    #[test]
    fn run_loop_bridges_lines_and_skips_blanks() {
        let (url, _rx) = stub_http_server(vec![
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_string(),
            r#"{"jsonrpc":"2.0","id":2,"result":{}}"#.to_string(),
        ]);
        let input =
            "\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"a\"}\n\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"b\"}\n";
        let mut out = Vec::new();
        let code = run_loop(&url, None, input.as_bytes(), &mut out);
        assert_eq!(code, 0);
        let lines: Vec<&str> = std::str::from_utf8(&out).unwrap().lines().collect();
        assert_eq!(lines.len(), 2, "one response line per request line");
        assert!(lines[0].contains(r#""id":1"#));
        assert!(lines[1].contains(r#""id":2"#));
    }

    #[test]
    fn version_drift_warns_only_on_mismatched_initialize() {
        let init = r#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#;
        let other = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let resp_same = format!(
            r#"{{"jsonrpc":"2.0","id":0,"result":{{"serverInfo":{{"name":"crux","version":"{}"}}}}}}"#,
            bridge_version()
        );
        let resp_drift = r#"{"jsonrpc":"2.0","id":0,"result":{"serverInfo":{"name":"crux","version":"0.0.0-other"}}}"#;
        assert!(
            version_drift_warning(init, &resp_same).is_none(),
            "same version: no warning"
        );
        let warn = version_drift_warning(init, resp_drift).expect("drift warning");
        assert!(warn.contains("0.0.0-other"));
        assert!(
            version_drift_warning(other, resp_drift).is_none(),
            "non-initialize: ignored"
        );
    }
}
