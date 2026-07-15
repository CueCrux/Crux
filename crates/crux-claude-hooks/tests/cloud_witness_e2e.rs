// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! End-to-end coverage for cloud witness mode.
//!
//! Raw loopback HTTP stubs stand in for the pinned providers. The tests drive
//! the real synchronous witness server, compare entity bytes exactly, inspect
//! forwarded authentication headers, and verify the spooled Ed25519 envelopes
//! against the identity reloaded from the persisted witness key.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{mpsc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;

use crux_claude_hooks::llm_shim::allowlist::CloudUpstream;
use crux_claude_hooks::llm_shim::witness::{verify_witness_envelope, WitnessKey};
use crux_claude_hooks::llm_shim::{self, CloudWitnessConfig};
use serde_json::{json, Value};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const ANTHROPIC_KEY: &str = "sk-ant-e2e-NEVER-PERSIST-2b5d6e305cab";
const OPENAI_TOKEN: &str = "Bearer sk-e2e-NEVER-PERSIST-cc119bd6e460";
const SESSION_AUTH_TOKEN: &str = "cloud-witness-session-auth-e2e-9f632b";
const GZIP_RESPONSE: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xab, 0x56, 0x2a, 0x2d, 0x4e, 0x4c, 0x4f, 0x55, 0xb2,
    0xaa, 0x56, 0x2a, 0x28, 0xca, 0xcf, 0x2d, 0x28, 0x89, 0x2f, 0xc9, 0xcf, 0x4e, 0xcd, 0x2b, 0x56, 0xb2, 0x32, 0xac,
    0xd5, 0x51, 0x4a, 0xce, 0xc8, 0xcf, 0x4c, 0x4e, 0x05, 0x72, 0xa2, 0xab, 0x95, 0xd2, 0x32, 0xf3, 0x32, 0x8b, 0x33,
    0xe2, 0x8b, 0x52, 0x13, 0x8b, 0xf3, 0xf3, 0x94, 0xac, 0x94, 0x8a, 0x4b, 0xf2, 0x0b, 0x94, 0x6a, 0x63, 0x6b, 0x01,
    0xb2, 0x84, 0xb0, 0x14, 0x42, 0x00, 0x00, 0x00,
];

static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn test_guard() -> MutexGuard<'static, ()> {
    TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn enable_cloud_witness() {
    std::env::set_var("CRUX_CLOUD_WITNESS", "1");
}

#[derive(Debug)]
struct CapturedRequest {
    request_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

struct StubUpstream {
    addr: SocketAddr,
    captured: mpsc::Receiver<CapturedRequest>,
}

struct StubDaemon {
    base_url: String,
    captured: mpsc::Receiver<Vec<CapturedRequest>>,
}

struct EnvVarGuard {
    name: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(name: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var(self.name, value),
            None => std::env::remove_var(self.name),
        }
    }
}

fn read_captured_request(stream: &TcpStream) -> CapturedRequest {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stub stream"));
    let mut request_line = String::new();
    reader.read_line(&mut request_line).expect("read request line");
    let request_line = request_line.trim_end_matches(['\r', '\n']).to_string();
    let mut headers = Vec::new();
    let mut content_length = 0_usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("read request header");
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let (name, value) = trimmed.split_once(':').expect("well-formed forwarded header");
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if name == "content-length" {
            content_length = value.parse().expect("numeric content-length");
        }
        headers.push((name, value));
    }
    let mut body = vec![0_u8; content_length];
    reader.read_exact(&mut body).expect("read forwarded request body");
    CapturedRequest {
        request_line,
        headers,
        body,
    }
}

fn spawn_buffered_stub(content_type: &'static str, response_body: Vec<u8>) -> StubUpstream {
    spawn_buffered_stub_with_headers(content_type, response_body, "")
}

fn spawn_buffered_stub_with_headers(
    content_type: &'static str,
    response_body: Vec<u8>,
    extra_response_headers: &str,
) -> StubUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("binding buffered cloud stub");
    let addr = listener.local_addr().expect("stub local address");
    let (captured_tx, captured) = mpsc::channel();
    let extra_response_headers = extra_response_headers.to_string();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept cloud witness request");
        stream.set_read_timeout(Some(IO_TIMEOUT)).expect("stub read timeout");
        let request = read_captured_request(&stream);
        captured_tx.send(request).expect("publish captured request");
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n{extra_response_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        stream.write_all(head.as_bytes()).expect("write stub response head");
        stream.write_all(&response_body).expect("write stub response body");
        stream.flush().expect("flush stub response");
    });
    StubUpstream { addr, captured }
}

fn spawn_daemon_stub(expected_requests: usize) -> StubDaemon {
    let listener = TcpListener::bind("127.0.0.1:0").expect("binding daemon receipt stub");
    let addr = listener.local_addr().expect("daemon stub local address");
    let (captured_tx, captured) = mpsc::channel();
    thread::spawn(move || {
        let mut requests = Vec::with_capacity(expected_requests);
        for sequence in 0..expected_requests {
            let (mut stream, _) = listener.accept().expect("accept daemon receipt request");
            stream
                .set_read_timeout(Some(IO_TIMEOUT))
                .expect("daemon stub read timeout");
            requests.push(read_captured_request(&stream));
            let response_body = json!({
                "receipt_id": format!("daemon-receipt-{sequence}"),
                "signature_hex": "test-signature",
                "observation_id": format!("daemon-observation-{sequence}"),
            })
            .to_string();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            );
            stream
                .write_all(head.as_bytes())
                .expect("write daemon stub response head");
            stream
                .write_all(response_body.as_bytes())
                .expect("write daemon stub response body");
            stream.flush().expect("flush daemon stub response");
        }
        captured_tx.send(requests).expect("publish daemon receipt requests");
    });
    StubDaemon {
        base_url: format!("http://{addr}"),
        captured,
    }
}

struct GatedSseStub {
    upstream: StubUpstream,
    first_sent: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
}

fn spawn_gated_sse_stub(first: Vec<u8>, rest: Vec<u8>) -> GatedSseStub {
    let listener = TcpListener::bind("127.0.0.1:0").expect("binding gated SSE cloud stub");
    let addr = listener.local_addr().expect("stub local address");
    let (captured_tx, captured) = mpsc::channel();
    let (first_sent_tx, first_sent) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept cloud witness SSE request");
        stream.set_read_timeout(Some(IO_TIMEOUT)).expect("stub read timeout");
        let request = read_captured_request(&stream);
        captured_tx.send(request).expect("publish captured request");
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
            )
            .expect("write SSE response head");
        stream.write_all(&first).expect("write first SSE event");
        stream.flush().expect("flush first SSE event");
        first_sent_tx.send(()).expect("signal first SSE event");
        release_rx
            .recv_timeout(IO_TIMEOUT)
            .expect("test releases gated SSE response");
        stream.write_all(&rest).expect("write remaining SSE events");
        stream.flush().expect("flush remaining SSE events");
    });
    GatedSseStub {
        upstream: StubUpstream { addr, captured },
        first_sent,
        release,
    }
}

fn witness_config(provider: CloudUpstream, upstream: SocketAddr, key: PathBuf, spool: PathBuf) -> CloudWitnessConfig {
    CloudWitnessConfig::new(provider, "127.0.0.1:0".into(), key, spool, false)
        .with_insecure_test_upstream(&format!("http://127.0.0.1:{}", upstream.port()))
        .expect("validated loopback test upstream")
}

fn witness_config_with_daemon_receipts(
    provider: CloudUpstream,
    upstream: SocketAddr,
    key: PathBuf,
    spool: PathBuf,
) -> CloudWitnessConfig {
    CloudWitnessConfig::new(provider, "127.0.0.1:0".into(), key, spool, true)
        .with_insecure_test_upstream(&format!("http://127.0.0.1:{}", upstream.port()))
        .expect("validated loopback test upstream")
}

fn write_post(stream: &mut TcpStream, path: &str, headers: &[(&str, &str)], body: &[u8]) {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: cloud-witness.test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).expect("write client request head");
    for (name, value) in headers {
        stream
            .write_all(format!("{name}: {value}\r\n").as_bytes())
            .expect("write client request header");
    }
    stream.write_all(b"\r\n").expect("end client request headers");
    stream.write_all(body).expect("write client request body");
    stream.flush().expect("flush client request");
}

fn read_response_head(reader: &mut impl BufRead) -> String {
    let mut status = String::new();
    reader.read_line(&mut status).expect("read response status");
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("read response header");
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
    }
    status.trim_end_matches(['\r', '\n']).to_string()
}

fn raw_post(addr: SocketAddr, path: &str, headers: &[(&str, &str)], body: &[u8]) -> (String, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).expect("connect to cloud witness");
    stream.set_read_timeout(Some(IO_TIMEOUT)).expect("client read timeout");
    write_post(&mut stream, path, headers, body);
    let mut reader = BufReader::new(stream);
    let status = read_response_head(&mut reader);
    let mut response_body = Vec::new();
    reader
        .read_to_end(&mut response_body)
        .expect("read cloud witness response");
    (status, response_body)
}

fn read_spool_until(path: &Path, minimum_records: usize) -> Vec<Value> {
    let mut latest = Vec::new();
    for _ in 0..100 {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(records) = text
                .lines()
                .map(serde_json::from_str::<Value>)
                .collect::<Result<Vec<_>, _>>()
            {
                latest = records;
                if latest.len() >= minimum_records {
                    return latest;
                }
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!(
        "timed out waiting for {minimum_records} spool records at {}; latest={latest:?}",
        path.display()
    );
}

fn record(value: &Value) -> &Value {
    value.get("record").unwrap_or(value)
}

fn envelope_by_kind<'a>(records: &'a [Value], kind: &str) -> &'a Value {
    records
        .iter()
        .find(|candidate| record(candidate).get("kind").and_then(Value::as_str) == Some(kind))
        .unwrap_or_else(|| panic!("missing {kind} in {records:?}"))
}

fn verify_signed_pair(records: &[Value], key_path: &Path) {
    let identity = WitnessKey::load_or_create(key_path)
        .expect("reload persisted witness key")
        .identity();
    for kind in ["cloud_request_witnessed", "cloud_response_witnessed"] {
        verify_witness_envelope(envelope_by_kind(records, kind), &identity)
            .unwrap_or_else(|error| panic!("verify {kind}: {error:#}"));
    }
}

fn assert_linked(records: &[Value]) {
    let request = record(envelope_by_kind(records, "cloud_request_witnessed"));
    let response = record(envelope_by_kind(records, "cloud_response_witnessed"));
    assert_eq!(response["request_receipt_id"], request["receipt_id"]);
}

fn assert_absent_from_spool(path: &Path, canaries: &[&str]) {
    let text = std::fs::read_to_string(path).expect("read witness spool");
    for canary in canaries {
        assert!(!text.contains(canary), "spool leaked canary {canary:?}: {text}");
    }
}

#[test]
fn signed_witness_pair_is_delivered_to_daemon_with_auth_without_spool_fallback() {
    let _guard = test_guard();
    enable_cloud_witness();
    let request_body = br#"{"model":"claude-sonnet-4-5","stream":false,"messages":[{"role":"user","content":"DAEMON_DELIVERY_PROMPT_SECRET_54a9"}]}"#;
    let response_body = br#"{"id":"msg_daemon_delivery","content":[{"type":"text","text":"DAEMON_DELIVERY_RESPONSE_SECRET_a41f"}],"stop_reason":"end_turn","usage":{"input_tokens":7,"output_tokens":3}}"#;
    let upstream = spawn_buffered_stub("application/json", response_body.to_vec());
    let daemon = spawn_daemon_stub(2);
    let _http_url = EnvVarGuard::set("CRUX_HTTP_URL", &daemon.base_url);
    let _agent_token = EnvVarGuard::set("CRUX_AGENT_TOKEN", "cloud-witness-daemon-e2e-token");
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("state/witness.key");
    let spool = dir.path().join("spool/receipts.jsonl");
    let shim = llm_shim::serve_cloud_witness(witness_config_with_daemon_receipts(
        CloudUpstream::Anthropic,
        upstream.addr,
        key.clone(),
        spool.clone(),
    ))
    .expect("start daemon-delivery witness");

    let (status, received_body) = raw_post(
        shim.addr,
        "/v1/messages",
        &[("x-api-key", ANTHROPIC_KEY), ("anthropic-version", "2023-06-01")],
        request_body,
    );
    assert!(status.starts_with("HTTP/1.1 200"), "unexpected status: {status}");
    assert_eq!(received_body, response_body);
    let forwarded = upstream
        .captured
        .recv_timeout(IO_TIMEOUT)
        .expect("captured daemon-delivery provider request");
    assert_eq!(forwarded.body, request_body);

    let delivered = daemon
        .captured
        .recv_timeout(IO_TIMEOUT)
        .expect("captured both daemon receipt requests");
    assert_eq!(delivered.len(), 2, "unexpected daemon requests: {delivered:?}");
    let envelopes: Vec<Value> = delivered
        .iter()
        .map(|request| {
            assert_eq!(request.request_line, "POST /v1/mediation/receipts HTTP/1.1");
            assert_eq!(
                request.header("authorization"),
                Some("Bearer cloud-witness-daemon-e2e-token")
            );
            let envelope: Value = serde_json::from_slice(&request.body).expect("signed witness envelope JSON");
            assert!(envelope.get("record").is_some_and(Value::is_object));
            assert!(envelope.get("witness").is_some_and(Value::is_object));
            assert_eq!(envelope["record"]["schema"], "cuecrux.mediation.witness.v1");
            assert_eq!(envelope["witness"]["alg"], "ed25519");
            envelope
        })
        .collect();
    assert_eq!(record(&envelopes[0])["kind"], "cloud_request_witnessed");
    assert_eq!(record(&envelopes[1])["kind"], "cloud_response_witnessed");
    assert_linked(&envelopes);
    verify_signed_pair(&envelopes, &key);

    shim.shutdown();
    thread::sleep(Duration::from_millis(50));
    assert!(
        !spool.exists(),
        "successful daemon delivery unexpectedly fell back to {}",
        spool.display()
    );
}

#[test]
fn anthropic_non_stream_is_exact_signed_linked_and_redacted() {
    let _guard = test_guard();
    enable_cloud_witness();
    let _session_auth = EnvVarGuard::set(llm_shim::CLOUD_WITNESS_SESSION_TOKEN_ENV, SESSION_AUTH_TOKEN);
    let request_body = br#"{"model":"claude-sonnet-4-5","stream":false,"tools":[{"name":"lookup_weather","description":"TOOL_DESCRIPTION_SECRET_6ee5","input_schema":{"type":"object"}}],"messages":[{"role":"user","content":"ANTHROPIC_PROMPT_SECRET_8d72"}],"metadata":{"argument":"TOOL_ARGUMENT_SECRET_d293"}}"#;
    let response_body = br#"{"id":"msg_e2e","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"ANTHROPIC_RESPONSE_SECRET_c863"}],"stop_reason":"end_turn","usage":{"input_tokens":17,"output_tokens":5}}"#;
    let stub = spawn_buffered_stub("application/json", response_body.to_vec());
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("state/witness.key");
    let spool = dir.path().join("spool/receipts.jsonl");
    let shim = llm_shim::serve_cloud_witness(witness_config(
        CloudUpstream::Anthropic,
        stub.addr,
        key.clone(),
        spool.clone(),
    ))
    .expect("start Anthropic witness");

    let (status, received_body) = raw_post(
        shim.addr,
        "/v1/messages",
        &[
            ("x-api-key", ANTHROPIC_KEY),
            ("anthropic-version", "2023-06-01"),
            ("x-crux-session-id", "session-anthropic-e2e"),
            ("x-crux-witness-auth", SESSION_AUTH_TOKEN),
            ("x-e2e-custom", "forward-me"),
            ("Connection", "x-drop"),
            ("x-drop", "hop-only-canary"),
        ],
        request_body,
    );
    assert!(status.starts_with("HTTP/1.1 200"), "unexpected status: {status}");
    assert_eq!(received_body, response_body);
    let captured = stub
        .captured
        .recv_timeout(IO_TIMEOUT)
        .expect("captured Anthropic request");
    assert_eq!(captured.request_line, "POST /v1/messages HTTP/1.1");
    assert_eq!(captured.body, request_body);
    assert_eq!(captured.header("x-api-key"), Some(ANTHROPIC_KEY));
    assert_eq!(captured.header("anthropic-version"), Some("2023-06-01"));
    assert_eq!(captured.header("x-crux-session-id"), Some("session-anthropic-e2e"));
    assert_eq!(captured.header("x-crux-witness-auth"), None);
    assert_eq!(captured.header("x-e2e-custom"), Some("forward-me"));
    assert_eq!(captured.header("x-drop"), None);

    let records = read_spool_until(&spool, 2);
    assert_eq!(records.len(), 2, "unexpected records: {records:?}");
    let request = record(envelope_by_kind(&records, "cloud_request_witnessed"));
    assert_eq!(request["provider"], "anthropic");
    assert_eq!(request["model"], "claude-sonnet-4-5");
    assert_eq!(request["tool_names"], json!(["lookup_weather"]));
    assert_eq!(request["stream"], false);
    assert_eq!(request["session_hint"], "session-anthropic-e2e");
    assert_eq!(request["request_digest"], llm_shim::sha256_hex_prefixed(request_body));
    assert_eq!(request["test_upstream"], true);
    let response = record(envelope_by_kind(&records, "cloud_response_witnessed"));
    assert_eq!(response["upstream_status"], 200);
    assert_eq!(response["output_digest"], llm_shim::sha256_hex_prefixed(response_body));
    assert_eq!(response["usage"]["input_tokens"], 17);
    assert_eq!(response["usage"]["output_tokens"], 5);
    assert_eq!(response["stop_reason"], "end_turn");
    assert_eq!(response["end_state"], "completed");
    assert!(response["first_byte_at"].as_str().is_some());
    assert!(response["ended_at"].as_str().is_some());
    assert_linked(&records);
    verify_signed_pair(&records, &key);
    assert_absent_from_spool(
        &spool,
        &[
            ANTHROPIC_KEY,
            "x-api-key",
            SESSION_AUTH_TOKEN,
            "x-crux-witness-auth",
            "ANTHROPIC_PROMPT_SECRET_8d72",
            "ANTHROPIC_RESPONSE_SECRET_c863",
            "TOOL_DESCRIPTION_SECRET_6ee5",
            "TOOL_ARGUMENT_SECRET_d293",
            "2023-06-01",
        ],
    );
    shim.shutdown();
}

#[test]
fn anthropic_sse_is_delivered_before_eof_and_hashed_exactly() {
    let _guard = test_guard();
    enable_cloud_witness();
    let request_body = br#"{"model":"claude-sonnet-4-5","stream":true,"messages":[{"role":"user","content":"SSE_PROMPT_SECRET_b770"}]}"#;
    let first = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":9,\"output_tokens\":0}}}\n\n".to_vec();
    let rest = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"SSE_RESPONSE_SECRET_7d8d\"}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":4}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_vec();
    let expected_response = [first.as_slice(), rest.as_slice()].concat();
    let stub = spawn_gated_sse_stub(first.clone(), rest);
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("state/witness.key");
    let spool = dir.path().join("receipts.jsonl");
    let shim = llm_shim::serve_cloud_witness(witness_config(
        CloudUpstream::Anthropic,
        stub.upstream.addr,
        key.clone(),
        spool.clone(),
    ))
    .expect("start Anthropic SSE witness");

    let mut client = TcpStream::connect(shim.addr).expect("connect SSE client");
    client.set_read_timeout(Some(IO_TIMEOUT)).expect("SSE client timeout");
    write_post(
        &mut client,
        "/v1/messages",
        &[("x-api-key", ANTHROPIC_KEY), ("anthropic-version", "2023-06-01")],
        request_body,
    );
    let mut reader = BufReader::new(client);
    let status = read_response_head(&mut reader);
    assert!(status.starts_with("HTTP/1.1 200"), "unexpected status: {status}");
    stub.first_sent
        .recv_timeout(IO_TIMEOUT)
        .expect("stub sent first SSE event");
    let mut received_first = vec![0_u8; first.len()];
    reader
        .read_exact(&mut received_first)
        .expect("first SSE event reaches client before upstream EOF");
    assert_eq!(received_first, first, "first event changed in transit");
    stub.release.send(()).expect("release remaining SSE events");
    let mut received_rest = Vec::new();
    reader
        .read_to_end(&mut received_rest)
        .expect("read remaining SSE events");
    let received_response = [received_first, received_rest].concat();
    assert_eq!(received_response, expected_response, "SSE entity bytes changed");
    let captured = stub
        .upstream
        .captured
        .recv_timeout(IO_TIMEOUT)
        .expect("captured Anthropic SSE request");
    assert_eq!(captured.body, request_body);
    assert_eq!(captured.header("x-api-key"), Some(ANTHROPIC_KEY));

    let records = read_spool_until(&spool, 2);
    let request = record(envelope_by_kind(&records, "cloud_request_witnessed"));
    assert_eq!(request["stream"], true);
    let response = record(envelope_by_kind(&records, "cloud_response_witnessed"));
    assert_eq!(
        response["output_digest"],
        llm_shim::sha256_hex_prefixed(&expected_response)
    );
    assert_eq!(response["usage"]["input_tokens"], 9);
    assert_eq!(response["usage"]["output_tokens"], 4);
    assert_eq!(response["stop_reason"], "end_turn");
    assert_eq!(response["end_state"], "completed");
    assert_linked(&records);
    verify_signed_pair(&records, &key);
    assert_absent_from_spool(
        &spool,
        &[ANTHROPIC_KEY, "SSE_PROMPT_SECRET_b770", "SSE_RESPONSE_SECRET_7d8d"],
    );
    shim.shutdown();
}

#[test]
fn openai_chat_is_exact_signed_linked_and_authorization_is_redacted() {
    let _guard = test_guard();
    enable_cloud_witness();
    let request_body = br#"{"model":"gpt-5.1","stream":false,"tools":[{"type":"function","function":{"name":"search_docs","description":"OPENAI_TOOL_SECRET_f12c","parameters":{"type":"object"}}}],"messages":[{"role":"user","content":"OPENAI_PROMPT_SECRET_e364"}]}"#;
    let response_body = br#"{"id":"chatcmpl_e2e","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"OPENAI_RESPONSE_SECRET_1f87"},"finish_reason":"stop"}],"usage":{"prompt_tokens":13,"completion_tokens":3,"total_tokens":16}}"#;
    let stub = spawn_buffered_stub("application/json", response_body.to_vec());
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("state/witness.key");
    let spool = dir.path().join("receipts.jsonl");
    let shim = llm_shim::serve_cloud_witness(witness_config(
        CloudUpstream::OpenAi,
        stub.addr,
        key.clone(),
        spool.clone(),
    ))
    .expect("start OpenAI witness");

    let (status, received_body) = raw_post(
        shim.addr,
        "/v1/chat/completions",
        &[("Authorization", OPENAI_TOKEN), ("OpenAI-Organization", "org-e2e")],
        request_body,
    );
    assert!(status.starts_with("HTTP/1.1 200"), "unexpected status: {status}");
    assert_eq!(received_body, response_body);
    let captured = stub.captured.recv_timeout(IO_TIMEOUT).expect("captured OpenAI request");
    assert_eq!(captured.request_line, "POST /v1/chat/completions HTTP/1.1");
    assert_eq!(captured.body, request_body);
    assert_eq!(captured.header("authorization"), Some(OPENAI_TOKEN));
    assert_eq!(captured.header("openai-organization"), Some("org-e2e"));

    let records = read_spool_until(&spool, 2);
    let request = record(envelope_by_kind(&records, "cloud_request_witnessed"));
    assert_eq!(request["provider"], "openai");
    assert_eq!(request["model"], "gpt-5.1");
    assert_eq!(request["tool_names"], json!(["search_docs"]));
    assert_eq!(request["request_digest"], llm_shim::sha256_hex_prefixed(request_body));
    let response = record(envelope_by_kind(&records, "cloud_response_witnessed"));
    assert_eq!(response["output_digest"], llm_shim::sha256_hex_prefixed(response_body));
    assert_eq!(response["usage"]["prompt_tokens"], 13);
    assert_eq!(response["usage"]["completion_tokens"], 3);
    assert_eq!(response["usage"]["total_tokens"], 16);
    assert_eq!(response["finish_reason"], "stop");
    assert_eq!(response["end_state"], "completed");
    assert_linked(&records);
    verify_signed_pair(&records, &key);
    assert_absent_from_spool(
        &spool,
        &[
            OPENAI_TOKEN,
            "Authorization",
            "authorization",
            "OPENAI_TOOL_SECRET_f12c",
            "OPENAI_PROMPT_SECRET_e364",
            "OPENAI_RESPONSE_SECRET_1f87",
        ],
    );
    shim.shutdown();
}

#[test]
fn explicitly_requested_gzip_response_remains_byte_identical() {
    let _guard = test_guard();
    enable_cloud_witness();
    let request_body = br#"{"model":"gpt-5.1","messages":[{"role":"user","content":"gzip fidelity"}]}"#;
    let stub =
        spawn_buffered_stub_with_headers("application/json", GZIP_RESPONSE.to_vec(), "Content-Encoding: gzip\r\n");
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("state/witness.key");
    let spool = dir.path().join("receipts.jsonl");
    let shim = llm_shim::serve_cloud_witness(witness_config(
        CloudUpstream::OpenAi,
        stub.addr,
        key.clone(),
        spool.clone(),
    ))
    .expect("start gzip witness");

    let (status, received_body) = raw_post(
        shim.addr,
        "/v1/chat/completions",
        &[("Authorization", OPENAI_TOKEN), ("Accept-Encoding", "gzip")],
        request_body,
    );
    assert!(status.starts_with("HTTP/1.1 200"), "unexpected status: {status}");
    assert_eq!(received_body, GZIP_RESPONSE);
    let captured = stub.captured.recv_timeout(IO_TIMEOUT).expect("captured gzip request");
    assert_eq!(captured.header("accept-encoding"), Some("gzip"));
    assert_eq!(captured.header("authorization"), Some(OPENAI_TOKEN));

    let records = read_spool_until(&spool, 2);
    let response = record(envelope_by_kind(&records, "cloud_response_witnessed"));
    assert_eq!(response["output_digest"], llm_shim::sha256_hex_prefixed(GZIP_RESPONSE));
    assert_linked(&records);
    verify_signed_pair(&records, &key);
    assert_absent_from_spool(&spool, &[OPENAI_TOKEN, "gzip fidelity"]);
    shim.shutdown();
}

#[test]
fn openai_responses_path_is_witnessed_with_direct_tool_names() {
    let _guard = test_guard();
    enable_cloud_witness();
    let request_body = br#"{"model":"gpt-5.1","tools":[{"type":"web_search","name":"web_search"}],"input":"RESPONSES_PROMPT_SECRET_21d8"}"#;
    let response_body = br#"{"id":"resp_e2e","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"RESPONSES_OUTPUT_SECRET_b3ac"}]}],"usage":{"input_tokens":6,"output_tokens":2,"total_tokens":8}}"#;
    let stub = spawn_buffered_stub("application/json", response_body.to_vec());
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("state/witness.key");
    let spool = dir.path().join("receipts.jsonl");
    let shim = llm_shim::serve_cloud_witness(witness_config(
        CloudUpstream::OpenAi,
        stub.addr,
        key.clone(),
        spool.clone(),
    ))
    .expect("start Responses API witness");

    let (status, received_body) = raw_post(
        shim.addr,
        "/v1/responses",
        &[("Authorization", OPENAI_TOKEN)],
        request_body,
    );
    assert!(status.starts_with("HTTP/1.1 200"), "unexpected status: {status}");
    assert_eq!(received_body, response_body);
    let captured = stub
        .captured
        .recv_timeout(IO_TIMEOUT)
        .expect("captured Responses API request");
    assert_eq!(captured.request_line, "POST /v1/responses HTTP/1.1");
    assert_eq!(captured.body, request_body);
    assert_eq!(captured.header("authorization"), Some(OPENAI_TOKEN));

    let records = read_spool_until(&spool, 2);
    let request = record(envelope_by_kind(&records, "cloud_request_witnessed"));
    assert_eq!(request["tool_names"], json!(["web_search"]));
    let response = record(envelope_by_kind(&records, "cloud_response_witnessed"));
    assert_eq!(response["usage"]["input_tokens"], 6);
    assert_eq!(response["usage"]["output_tokens"], 2);
    assert_eq!(response["output_digest"], llm_shim::sha256_hex_prefixed(response_body));
    assert_linked(&records);
    verify_signed_pair(&records, &key);
    assert_absent_from_spool(
        &spool,
        &[
            OPENAI_TOKEN,
            "RESPONSES_PROMPT_SECRET_21d8",
            "RESPONSES_OUTPUT_SECRET_b3ac",
        ],
    );
    shim.shutdown();
}

#[test]
fn unavailable_witness_key_degrades_but_never_blocks_provider_traffic() {
    let _guard = test_guard();
    enable_cloud_witness();
    let request_body =
        br#"{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"DEGRADED_PROMPT_SECRET_5962"}]}"#;
    let response_body = br#"{"id":"msg_degraded","content":[{"type":"text","text":"DEGRADED_RESPONSE_SECRET_43dd"}],"stop_reason":"end_turn","usage":{"input_tokens":2,"output_tokens":1}}"#;
    let stub = spawn_buffered_stub("application/json", response_body.to_vec());
    let dir = tempfile::tempdir().expect("tempdir");
    let parent_blocker = dir.path().join("not-a-directory");
    std::fs::write(&parent_blocker, b"blocks witness key parent").expect("write key parent blocker");
    let unavailable_key = parent_blocker.join("witness.key");
    let spool = dir.path().join("receipts.jsonl");
    let shim = llm_shim::serve_cloud_witness(witness_config(
        CloudUpstream::Anthropic,
        stub.addr,
        unavailable_key,
        spool.clone(),
    ))
    .expect("key failure must not prevent witness listener startup");

    let (status, received_body) = raw_post(
        shim.addr,
        "/v1/messages",
        &[("x-api-key", ANTHROPIC_KEY), ("anthropic-version", "2023-06-01")],
        request_body,
    );
    assert!(status.starts_with("HTTP/1.1 200"), "unexpected status: {status}");
    assert_eq!(received_body, response_body, "key failure changed provider response");
    let captured = stub
        .captured
        .recv_timeout(IO_TIMEOUT)
        .expect("captured degraded request");
    assert_eq!(captured.body, request_body);
    assert_eq!(captured.header("x-api-key"), Some(ANTHROPIC_KEY));

    let records = read_spool_until(&spool, 2);
    assert!(records.iter().all(|entry| record(entry)["kind"] == "witness_degraded"));
    assert!(records
        .iter()
        .all(|entry| record(entry)["reason"] == "witness_key_unavailable"));
    assert!(records.iter().all(|entry| record(entry)["test_upstream"] == true));
    assert!(records.iter().all(|entry| entry.get("witness").is_none()));
    assert_absent_from_spool(
        &spool,
        &[
            ANTHROPIC_KEY,
            "DEGRADED_PROMPT_SECRET_5962",
            "DEGRADED_RESPONSE_SECRET_43dd",
        ],
    );
    shim.shutdown();
}

#[test]
fn binary_help_advertises_cloud_witness_safety_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_crux-llm-shim"))
        .arg("--help")
        .output()
        .expect("run crux-llm-shim --help");
    assert!(output.status.success(), "--help failed: {output:?}");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 help output");
    for flag in [
        "--cloud-witness",
        "--cloud-upstream",
        "--witness-key",
        "--insecure-test-upstream",
    ] {
        assert!(stdout.contains(flag), "help omitted {flag}: {stdout}");
    }
}
