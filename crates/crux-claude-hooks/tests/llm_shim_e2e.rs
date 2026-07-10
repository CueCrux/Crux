// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! End-to-end tests for `crux-llm-shim` (G17, M4 of ExecPlan
//! `context-mediation-injection-2026-06-11`).
//!
//! A stdlib `TcpListener` plays the local model server (the pattern pinned by
//! `hook_e2e.rs` — zero new dependencies). Each test boots a real shim via
//! `llm_shim::serve` on an ephemeral port, drives it with a raw-socket
//! client, and asserts on (a) what reached the "upstream", (b) what came back
//! to the client, and (c) the receipt records in the JSONL spool.
//!
//! No local Ollama is required: the smoke contract is the OpenAI-compatible
//! wire shape, which the stub reproduces (buffered JSON + SSE streaming).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crux_claude_hooks::llm_shim::{self, BundleSource, ShimConfig};
use serde_json::Value;

const BUNDLE_MD: &str = "# Crux context bundle\n\nstable region first\n";

/// Serialise tests that touch `CRUX_LLM_SHIM` (process-global env).
fn enable_shim() {
    std::env::set_var("CRUX_LLM_SHIM", "1");
}

struct StubUpstream {
    addr: std::net::SocketAddr,
    /// Body bytes the stub received, one per handled request.
    received: mpsc::Receiver<Vec<u8>>,
}

/// One-request stub upstream. `mode` controls the response.
#[derive(Clone, Copy)]
enum StubMode {
    /// Buffered JSON completion with Content-Length.
    Json,
    /// SSE stream: three data chunks then `[DONE]`, flushed separately.
    Sse,
    /// Write half an SSE stream then drop the connection (upstream error).
    SseTruncated,
}

fn spawn_stub(mode: StubMode, requests: usize) -> StubUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for _ in 0..requests {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut content_length = 0usize;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                let trimmed = header.trim_end();
                if trimmed.is_empty() {
                    break;
                }
                if let Some(v) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();
            let _ = tx.send(body);
            match mode {
                StubMode::Json => {
                    let payload = br#"{"id":"cmpl-1","choices":[{"message":{"role":"assistant","content":"hi"}}]}"#;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    stream.write_all(head.as_bytes()).unwrap();
                    stream.write_all(payload).unwrap();
                }
                StubMode::Sse => {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
                        .unwrap();
                    for chunk in [
                        "data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n",
                        "data: {\"choices\":[{\"delta\":{\"content\":\"b\"}}]}\n\n",
                        "data: [DONE]\n\n",
                    ] {
                        stream.write_all(chunk.as_bytes()).unwrap();
                        stream.flush().unwrap();
                        thread::sleep(Duration::from_millis(10));
                    }
                }
                StubMode::SseTruncated => {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n",
                        )
                        .unwrap();
                    stream.flush().unwrap();
                    // Drop without finishing the stream.
                }
            }
        }
    });
    StubUpstream { addr, received: rx }
}

fn shim_config(upstream: std::net::SocketAddr, spool: PathBuf, with_bundle: bool) -> ShimConfig {
    ShimConfig {
        upstream: format!("http://127.0.0.1:{}", upstream.port()),
        listen: "127.0.0.1:0".into(),
        bundle: with_bundle
            .then(|| BundleSource::from_markdown(BUNDLE_MD.into(), Some("blake3:test".into()), "file:test".into())),
        session_id: "shim-e2e".into(),
        receipts_spool: spool,
        daemon_receipts: false,
    }
}

/// Raw HTTP/1.1 POST; returns (status_line, body_bytes).
fn raw_post(addr: std::net::SocketAddr, path: &str, body: &str) -> (String, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: shim\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let text_head_end = find_head_end(&response);
    let status =
        String::from_utf8_lossy(&response[..response.iter().position(|&b| b == b'\r').unwrap_or(0)]).to_string();
    (status, response[text_head_end..].to_vec())
}

fn find_head_end(bytes: &[u8]) -> usize {
    bytes.windows(4).position(|w| w == b"\r\n\r\n").map_or(0, |i| i + 4)
}

fn read_spool(path: &PathBuf) -> Vec<Value> {
    let mut records = Vec::new();
    // The end-state receipt is written after the response bytes; give the
    // handler thread a moment.
    for _ in 0..50 {
        if let Ok(text) = std::fs::read_to_string(path) {
            records = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
            if records.len() >= 2 {
                break;
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    records
}

#[test]
fn injects_bundle_and_passes_request_through() {
    enable_shim();
    let stub = spawn_stub(StubMode::Json, 1);
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("receipts.jsonl");
    let shim = llm_shim::serve(shim_config(stub.addr, spool.clone(), true)).unwrap();

    let request_body = r#"{"model":"llama3.2","temperature":0.1,"tools":[{"type":"function","function":{"name":"t"}}],"messages":[{"role":"system","content":"terse"},{"role":"user","content":"hi"}]}"#;
    let (status, body) = raw_post(shim.addr, "/v1/chat/completions", request_body);
    assert!(status.contains("200"), "got {status}");
    let response: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["id"], "cmpl-1");

    // What reached the upstream: bundle as NEW first system message, caller
    // fields value-identical.
    let upstream_body: Value =
        serde_json::from_slice(&stub.received.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
    let messages = upstream_body["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0]["role"], "system");
    assert_eq!(messages[0]["content"], BUNDLE_MD);
    assert_eq!(messages[1]["content"], "terse");
    assert_eq!(upstream_body["model"], "llama3.2");
    assert_eq!(upstream_body["temperature"], 0.1);
    assert_eq!(upstream_body["tools"][0]["function"]["name"], "t");

    // Two-sided receipt trail: context_injected + stream_completed, linked.
    let records = read_spool(&spool);
    assert_eq!(records.len(), 2, "records: {records:?}");
    assert_eq!(records[0]["kind"], "context_injected");
    assert_eq!(records[0]["stable_hash"], "blake3:test");
    assert_eq!(records[0]["bundle_version"], "context_bundle/v1");
    assert_eq!(records[1]["kind"], "stream_completed");
    assert_eq!(records[1]["stream"], false);
    assert_eq!(records[1]["model"], "llama3.2");
    assert_eq!(records[1]["injected_stable_hash"], "blake3:test");
    assert_eq!(records[1]["injected_bundle_digest"], records[0]["bundle_digest"]);
    assert!(records[1]["output_digest"].as_str().unwrap().starts_with("sha256:"));
    shim.shutdown();
}

#[test]
fn streams_sse_bytes_verbatim_and_mints_completed() {
    enable_shim();
    let stub = spawn_stub(StubMode::Sse, 1);
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("receipts.jsonl");
    let shim = llm_shim::serve(shim_config(stub.addr, spool.clone(), true)).unwrap();

    let request_body = r#"{"model":"llama3.2","stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
    let (status, body) = raw_post(shim.addr, "/v1/chat/completions", request_body);
    assert!(status.contains("200"), "got {status}");
    let text = String::from_utf8(body).unwrap();
    // Verbatim SSE passthrough, including the terminator.
    assert!(text.contains("data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}"));
    assert!(text.contains("data: [DONE]"));

    let records = read_spool(&spool);
    assert_eq!(records.len(), 2, "records: {records:?}");
    assert_eq!(records[1]["kind"], "stream_completed");
    assert_eq!(records[1]["stream"], true);
    assert!(records[1]["first_token_at"].as_str().is_some());
    shim.shutdown();
}

#[test]
fn upstream_truncation_mints_stream_aborted() {
    enable_shim();
    let stub = spawn_stub(StubMode::SseTruncated, 1);
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("receipts.jsonl");
    let shim = llm_shim::serve(shim_config(stub.addr, spool.clone(), true)).unwrap();

    let request_body = r#"{"model":"llama3.2","stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
    let (_status, body) = raw_post(shim.addr, "/v1/chat/completions", request_body);
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("\"content\":\"a\""),
        "partial bytes should still reach the client"
    );
    assert!(!text.contains("[DONE]"));

    let records = read_spool(&spool);
    assert_eq!(records.len(), 2, "records: {records:?}");
    // A dropped upstream socket surfaces as clean EOF or a read error
    // depending on the OS/TCP teardown; both end-states are acceptable for a
    // truncated stream PROVIDED the trail records the partial output digest.
    let kind = records[1]["kind"].as_str().unwrap();
    assert!(
        kind == "stream_aborted" || kind == "stream_completed",
        "unexpected kind {kind}"
    );
    assert!(records[1]["output_digest"].as_str().unwrap().starts_with("sha256:"));
    shim.shutdown();
}

#[test]
fn non_chat_paths_pass_through_unmodified_with_no_injection_receipt() {
    enable_shim();
    let stub = spawn_stub(StubMode::Json, 1);
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("receipts.jsonl");
    let shim = llm_shim::serve(shim_config(stub.addr, spool.clone(), true)).unwrap();

    let request_body = r#"{"model":"llama3.2","prompt":"complete me"}"#;
    let (status, _body) = raw_post(shim.addr, "/api/generate", request_body);
    assert!(status.contains("200"), "got {status}");

    let upstream_body = stub.received.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        upstream_body,
        request_body.as_bytes(),
        "body must pass through byte-identical"
    );

    // Only the end-state record — no context_injected for non-chat paths.
    let records = read_spool(&spool);
    assert_eq!(records.len(), 1, "records: {records:?}");
    assert_eq!(records[0]["kind"], "stream_completed");
    assert!(records[0]["injected_stable_hash"].is_null());
    shim.shutdown();
}

#[test]
fn passthrough_mode_without_bundle_never_injects() {
    enable_shim();
    let stub = spawn_stub(StubMode::Json, 1);
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("receipts.jsonl");
    let shim = llm_shim::serve(shim_config(stub.addr, spool.clone(), false)).unwrap();

    let request_body = r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
    let (status, _body) = raw_post(shim.addr, "/v1/chat/completions", request_body);
    assert!(status.contains("200"), "got {status}");
    let upstream_body = stub.received.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(upstream_body, request_body.as_bytes());

    let records = read_spool(&spool);
    assert_eq!(records.len(), 1, "records: {records:?}");
    assert_eq!(records[0]["kind"], "stream_completed");
    shim.shutdown();
}

#[test]
fn upstream_unreachable_returns_502_and_mints_aborted() {
    enable_shim();
    // Bind-then-drop to get a port nothing listens on.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("receipts.jsonl");
    let shim = llm_shim::serve(shim_config(dead, spool.clone(), true)).unwrap();

    let request_body = r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
    let (status, body) = raw_post(shim.addr, "/v1/chat/completions", request_body);
    assert!(status.contains("502"), "got {status}");
    let err: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"]["type"], "crux_llm_shim");

    let records = read_spool(&spool);
    assert_eq!(records.len(), 2, "records: {records:?}");
    assert_eq!(records[0]["kind"], "context_injected");
    assert_eq!(records[1]["kind"], "stream_aborted");
    assert_eq!(records[1]["abort_reason"], "upstream_unreachable");
    assert!(records[1]["output_digest"].is_null());
    shim.shutdown();
}

#[test]
fn chunked_request_bodies_are_refused_with_411() {
    enable_shim();
    let stub = spawn_stub(StubMode::Json, 1);
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("receipts.jsonl");
    let shim = llm_shim::serve(shim_config(stub.addr, spool, true)).unwrap();

    let mut stream = TcpStream::connect(shim.addr).unwrap();
    stream
        .write_all(b"POST /v1/chat/completions HTTP/1.1\r\nHost: shim\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 411"));
    shim.shutdown();
}

#[test]
fn serve_refuses_non_local_upstream_and_non_loopback_listen() {
    enable_shim();
    let dir = tempfile::tempdir().unwrap();
    let mut config = shim_config(
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap(),
        dir.path().join("r.jsonl"),
        false,
    );
    config.upstream = "http://api.openai.com".into();
    assert!(llm_shim::serve(config).is_err(), "cloud upstream must be refused");
}
