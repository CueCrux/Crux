// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Cloud witness forwarding for the pinned Anthropic and OpenAI API origins.
//!
//! Unlike local shim mode, this module never injects or reserializes request
//! content. It forwards exact request body bytes, streams response entity
//! bytes to the client while hashing them, and emits signed metadata-only
//! witness envelopes on a delivery worker that cannot stall provider traffic.

use std::io::{BufReader, Read, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::Duration;

use rand::Rng as _;
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

use super::allowlist::CloudUpstream;
use super::http::{self, Request, RequestError};
use super::witness::WitnessKey;
use super::{receipts, sha256_hex_prefixed, CloudWitnessConfig, WITNESS_RECEIPT_SCHEMA};

/// Maximum buffered non-streaming response bytes used only for optional
/// metadata parsing. All bytes are still forwarded and hashed past this cap.
const MAX_METADATA_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Maximum one SSE line retained for optional metadata parsing.
const MAX_SSE_LINE_BYTES: usize = 256 * 1024;
/// Bounded receipt backlog: sink stalls must not grow memory without limit.
const RECEIPT_QUEUE_CAPACITY: usize = 256;
/// Client request-read timeout; provider response reads remain unbounded.
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Caller header containing the session identity to attribute when authorised.
const SESSION_ID_HEADER: &str = "x-crux-session-id";
/// Listener-only credential header; never forward this secret upstream.
const SESSION_AUTH_HEADER: &str = "x-crux-witness-auth";

static RECEIPT_SEQ: AtomicU64 = AtomicU64::new(1);
static RECEIPT_INSTANCE: OnceLock<String> = OnceLock::new();

/// Prepared cloud-witness state shared by all accepted connections.
pub(crate) struct CloudWitnessRuntime {
    config: CloudWitnessConfig,
    upstream_base: String,
    test_upstream: bool,
    witness_key: Option<WitnessKey>,
    dispatcher: ReceiptDispatcher,
}

impl CloudWitnessRuntime {
    /// Validate the optional test transport, load key custody fail-soft, and
    /// start the non-blocking receipt delivery worker.
    pub(crate) fn new(config: CloudWitnessConfig) -> anyhow::Result<Self> {
        let (upstream_base, test_upstream) = match config.insecure_test_upstream() {
            Some(url) => (super::allowlist::validate_insecure_test_upstream(url)?, true),
            None => (config.provider.base_url().to_string(), false),
        };
        let witness_key = WitnessKey::load_or_create(&config.witness_key).ok();
        let dispatcher = ReceiptDispatcher::new(config.daemon_receipts, config.receipts_spool.clone());
        Ok(Self {
            config,
            upstream_base,
            test_upstream,
            witness_key,
            dispatcher,
        })
    }

    /// Return the validated public server configuration.
    pub(crate) const fn config(&self) -> &CloudWitnessConfig {
        &self.config
    }

    fn dispatch(&self, record: Value, path: &str) {
        let fallback_record = degraded_record(path, "delivery_unavailable", self.test_upstream, true);
        let queue_full_record = degraded_record(
            path,
            "receipt_queue_full",
            self.test_upstream,
            self.witness_key.is_some(),
        );
        let (job, queue_full_notice) = match self.witness_key.as_ref() {
            Some(key) => match key.sign_record(&record) {
                Ok(envelope) => (
                    DeliveryJob {
                        envelope,
                        fallback: key.sign_record(&fallback_record).ok(),
                    },
                    sign_or_plain(key, queue_full_record),
                ),
                Err(_) => (
                    DeliveryJob {
                        envelope: degraded_record(path, "signing_failed", self.test_upstream, true),
                        fallback: None,
                    },
                    queue_full_record,
                ),
            },
            None => (
                DeliveryJob {
                    envelope: degraded_record(path, "witness_key_unavailable", self.test_upstream, false),
                    fallback: None,
                },
                queue_full_record,
            ),
        };
        self.dispatcher.send(job, queue_full_notice);
    }
}

fn sign_or_plain(key: &WitnessKey, record: Value) -> Value {
    match key.sign_record(&record) {
        Ok(envelope) => envelope,
        Err(_) => record,
    }
}

struct DeliveryJob {
    envelope: Value,
    fallback: Option<Value>,
}

struct ReceiptDispatcher {
    sender: mpsc::SyncSender<DeliveryJob>,
    pending_queue_full: Arc<Mutex<Option<Value>>>,
}

impl ReceiptDispatcher {
    fn new(daemon_receipts: bool, spool: PathBuf) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<DeliveryJob>(RECEIPT_QUEUE_CAPACITY);
        let pending_queue_full = Arc::new(Mutex::new(None::<Value>));
        let worker_pending = Arc::clone(&pending_queue_full);
        let worker = std::thread::Builder::new()
            .name("crux-witness-receipts".to_string())
            .spawn(move || {
            while let Ok(job) = receiver.recv() {
                if receipts::deliver_record(daemon_receipts, &spool, &job.envelope).is_err() {
                    let fallback_delivered = job
                        .fallback
                        .as_ref()
                        .is_some_and(|fallback| receipts::deliver_record(daemon_receipts, &spool, fallback).is_ok());
                    if !fallback_delivered {
                        eprintln!(
                            "crux-llm-shim: cloud witness receipt delivery unavailable; provider traffic was not interrupted"
                        );
                    }
                }
                let pending_notice = worker_pending.lock().ok().and_then(|mut pending| pending.take());
                if pending_notice
                    .as_ref()
                    .is_some_and(|notice| receipts::deliver_record(daemon_receipts, &spool, notice).is_err())
                {
                    eprintln!(
                        "crux-llm-shim: cloud witness queue degradation could not be persisted; provider traffic was not interrupted"
                    );
                }
            }
        });
        if worker.is_err() {
            eprintln!(
                "crux-llm-shim: cloud witness receipt worker could not start; provider traffic will remain available"
            );
        }
        Self {
            sender,
            pending_queue_full,
        }
    }

    fn send(&self, job: DeliveryJob, queue_full_notice: Value) {
        match self.sender.try_send(job) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                if let Ok(mut pending) = self.pending_queue_full.lock() {
                    *pending = Some(queue_full_notice);
                }
                eprintln!("crux-llm-shim: cloud witness receipt queue full; provider traffic was not interrupted");
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                eprintln!(
                    "crux-llm-shim: cloud witness receipt worker unavailable; provider traffic was not interrupted"
                );
            }
        }
    }
}

/// Handle one cloud client connection without ever modifying body bytes.
pub(crate) fn handle_connection(stream: TcpStream, runtime: &CloudWitnessRuntime) {
    let _ = stream.set_read_timeout(Some(CLIENT_READ_TIMEOUT));
    let Ok(read_half) = stream.try_clone() else { return };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    let request = match http::read_request(&mut reader) {
        Ok(request) => request,
        Err(RequestError::BadRequest(message)) => {
            http::respond_error(&mut writer, 400, "Bad Request", &message);
            return;
        }
        Err(RequestError::LengthRequired) => {
            http::respond_error(
                &mut writer,
                411,
                "Length Required",
                "chunked request bodies are not supported by crux-llm-shim v1",
            );
            return;
        }
        Err(RequestError::TooLarge) => {
            http::respond_error(&mut writer, 413, "Payload Too Large", "request exceeds shim cap");
            return;
        }
        Err(RequestError::Io) => return,
    };
    let _ = writer.set_read_timeout(None);

    let path = request.target.split('?').next().unwrap_or("");
    if runtime.config.provider.witnesses(&request.method, path) {
        let request_receipt_id = next_receipt_id();
        let request_record = cloud_request_record(runtime, &request, path, &request_receipt_id);
        runtime.dispatch(request_record, path);
        forward(runtime, &request, path, Some(&request_receipt_id), &mut writer);
    } else {
        runtime.dispatch(passthrough_record(path, runtime.test_upstream), path);
        forward(runtime, &request, path, None, &mut writer);
    }
}

fn next_receipt_id() -> String {
    let sequence = RECEIPT_SEQ.fetch_add(1, Ordering::Relaxed);
    let instance = RECEIPT_INSTANCE.get_or_init(|| {
        let mut random = [0_u8; 16];
        rand::rng().fill_bytes(&mut random);
        hex::encode(random)
    });
    format!("wit-{instance}-{sequence}")
}

fn fresh_nonce() -> String {
    let mut nonce = [0_u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    hex::encode(nonce)
}

fn cloud_request_record(runtime: &CloudWitnessRuntime, request: &Request, path: &str, receipt_id: &str) -> Value {
    let metadata = RequestMetadata::parse(runtime.config.provider, &request.body);
    let session_hint = authenticated_session_hint(&runtime.config, &request.headers);
    json!({
        "schema": WITNESS_RECEIPT_SCHEMA,
        "kind": "cloud_request_witnessed",
        "receipt_id": receipt_id,
        "nonce": fresh_nonce(),
        "provider": runtime.config.provider.provider(),
        "path": path,
        "model": metadata.model,
        "request_digest": sha256_hex_prefixed(&request.body),
        "tool_names": metadata.tool_names,
        "stream": metadata.stream,
        "session_hint": session_hint,
        "created_at": receipts::now_rfc3339(),
        "test_upstream": runtime.test_upstream,
    })
}

fn authenticated_session_hint<'a>(config: &CloudWitnessConfig, headers: &'a [(String, String)]) -> Option<&'a str> {
    let presented = header_value(headers, SESSION_AUTH_HEADER)?;
    if !config.session_auth_token_matches(presented) {
        return None;
    }
    header_value(headers, SESSION_ID_HEADER)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
}

fn passthrough_record(path: &str, test_upstream: bool) -> Value {
    json!({
        "schema": WITNESS_RECEIPT_SCHEMA,
        "kind": "passthrough_unwitnessed",
        "path": path,
        "created_at": receipts::now_rfc3339(),
        "test_upstream": test_upstream,
    })
}

fn degraded_record(path: &str, reason: &str, test_upstream: bool, persistent_key: bool) -> Value {
    json!({
        "schema": WITNESS_RECEIPT_SCHEMA,
        "kind": "witness_degraded",
        "path": path,
        "reason": reason,
        "persistent_key": persistent_key,
        "created_at": receipts::now_rfc3339(),
        "test_upstream": test_upstream,
    })
}

#[derive(Default)]
struct RequestMetadata {
    model: Option<String>,
    tool_names: Vec<String>,
    stream: bool,
}

impl RequestMetadata {
    fn parse(provider: CloudUpstream, body: &[u8]) -> Self {
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return Self::default();
        };
        let model = value.get("model").and_then(Value::as_str).map(str::to_string);
        let stream = value.get("stream").and_then(Value::as_bool).unwrap_or(false);
        let tool_names = value
            .get("tools")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|tool| match provider {
                CloudUpstream::Anthropic => tool.get("name").and_then(Value::as_str),
                CloudUpstream::OpenAi => tool
                    .get("function")
                    .and_then(|function| function.get("name"))
                    .or_else(|| tool.get("name"))
                    .and_then(Value::as_str),
            })
            .map(str::to_string)
            .collect();
        Self {
            model,
            tool_names,
            stream,
        }
    }
}

fn forward(
    runtime: &CloudWitnessRuntime,
    request: &Request,
    path: &str,
    request_receipt_id: Option<&str>,
    writer: &mut TcpStream,
) {
    let url = format!("{}{}", runtime.upstream_base, request.target);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .https_only(!runtime.test_upstream)
        .max_redirects(0)
        .user_agent("")
        .accept("")
        .accept_encoding("")
        .build()
        .into();

    let Ok(method) = ureq::http::Method::from_bytes(request.method.as_bytes()) else {
        http::respond_error(writer, 501, "Not Implemented", "unsupported method");
        return;
    };
    let mut builder = ureq::http::Request::builder().method(method).uri(&url);
    for (name, value) in &request.headers {
        if !matches!(name.as_str(), "host" | "content-length")
            && name != SESSION_AUTH_HEADER
            && !http::header_is_hop_by_hop(name, &request.headers)
        {
            builder = builder.header(name.as_str(), value.as_str());
        }
    }
    let Ok(upstream_request) = builder.body(request.body.as_slice()) else {
        http::respond_error(writer, 400, "Bad Request", "request headers could not be forwarded");
        dispatch_terminal_response(
            runtime,
            path,
            request_receipt_id,
            None,
            None,
            ResponseEndState::UpstreamError,
        );
        return;
    };
    let Ok(mut response) = agent.run(upstream_request) else {
        http::respond_error(writer, 502, "Bad Gateway", "cloud upstream unavailable");
        dispatch_terminal_response(
            runtime,
            path,
            request_receipt_id,
            None,
            None,
            ResponseEndState::UpstreamError,
        );
        return;
    };

    let status = response.status();
    if !write_response_head(&response, writer) {
        dispatch_terminal_response(
            runtime,
            path,
            request_receipt_id,
            Some(status.as_u16()),
            Some(sha256_hex_prefixed(&[])),
            ResponseEndState::Aborted,
        );
        return;
    }

    let stream = request_receipt_id.is_some_and(|_| {
        serde_json::from_slice::<Value>(&request.body)
            .ok()
            .and_then(|value| value.get("stream").and_then(Value::as_bool))
            .unwrap_or(false)
    });
    let pump = pump_body(response.body_mut().as_reader(), writer, runtime.config.provider, stream);
    if let Some(request_id) = request_receipt_id {
        let end_state = classify_response_end_state(status, pump.upstream_read_failed, pump.client_disconnected);
        runtime.dispatch(
            cloud_response_record(
                runtime,
                CloudResponseInput {
                    path,
                    request_receipt_id: request_id,
                    upstream_status: Some(status.as_u16()),
                    output_digest: Some(pump.output_digest),
                    end_state,
                    first_byte_at: pump.first_byte_at,
                    metadata: pump.metadata,
                },
            ),
            path,
        );
    }
}

fn classify_response_end_state(
    status: ureq::http::StatusCode,
    upstream_read_failed: bool,
    client_disconnected: bool,
) -> ResponseEndState {
    if status.is_client_error() || status.is_server_error() || upstream_read_failed {
        ResponseEndState::UpstreamError
    } else if client_disconnected {
        ResponseEndState::Aborted
    } else {
        ResponseEndState::Completed
    }
}

fn dispatch_terminal_response(
    runtime: &CloudWitnessRuntime,
    path: &str,
    request_receipt_id: Option<&str>,
    upstream_status: Option<u16>,
    output_digest: Option<String>,
    end_state: ResponseEndState,
) {
    let Some(request_receipt_id) = request_receipt_id else {
        return;
    };
    runtime.dispatch(
        cloud_response_record(
            runtime,
            CloudResponseInput {
                path,
                request_receipt_id,
                upstream_status,
                output_digest,
                end_state,
                first_byte_at: None,
                metadata: ResponseMetadata::default(),
            },
        ),
        path,
    );
}

fn write_response_head(response: &ureq::http::Response<ureq::Body>, writer: &mut TcpStream) -> bool {
    let status = response.status();
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    );
    let response_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect();
    for (header_name, header_value) in &response_headers {
        if header_name == "content-length" || http::header_is_hop_by_hop(header_name, &response_headers) {
            continue;
        }
        head.push_str(header_name);
        head.push_str(": ");
        head.push_str(header_value);
        head.push_str("\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");
    writer.write_all(head.as_bytes()).is_ok()
}

struct PumpOutcome {
    first_byte_at: Option<String>,
    output_digest: String,
    client_disconnected: bool,
    upstream_read_failed: bool,
    metadata: ResponseMetadata,
}

fn pump_body(
    mut upstream_reader: impl Read,
    writer: &mut TcpStream,
    provider: CloudUpstream,
    stream: bool,
) -> PumpOutcome {
    let mut buffer = [0_u8; 8192];
    let mut hasher = Sha256::new();
    let mut first_byte_at = None;
    let mut capture = MetadataCapture::new(stream);
    let (client_disconnected, upstream_read_failed) = loop {
        match upstream_reader.read(&mut buffer) {
            Ok(0) => break (false, false),
            Ok(count) => {
                if first_byte_at.is_none() {
                    first_byte_at = Some(receipts::now_rfc3339());
                }
                hasher.update(&buffer[..count]);
                capture.observe(provider, &buffer[..count]);
                if writer.write_all(&buffer[..count]).is_err() || writer.flush().is_err() {
                    break (true, false);
                }
            }
            Err(_) => break (false, true),
        }
    };
    let _ = writer.flush();
    let digest = hasher.finalize();
    let mut output_digest = String::with_capacity(7 + digest.len() * 2);
    output_digest.push_str("sha256:");
    for byte in digest {
        let _ = std::fmt::Write::write_fmt(&mut output_digest, format_args!("{byte:02x}"));
    }
    PumpOutcome {
        first_byte_at,
        output_digest,
        client_disconnected,
        upstream_read_failed,
        metadata: capture.finish(provider),
    }
}

#[derive(Debug, Clone, Copy)]
enum ResponseEndState {
    Completed,
    Aborted,
    UpstreamError,
}

impl ResponseEndState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Aborted => "aborted",
            Self::UpstreamError => "upstream_error",
        }
    }
}

struct CloudResponseInput<'a> {
    path: &'a str,
    request_receipt_id: &'a str,
    upstream_status: Option<u16>,
    output_digest: Option<String>,
    end_state: ResponseEndState,
    first_byte_at: Option<String>,
    metadata: ResponseMetadata,
}

fn cloud_response_record(runtime: &CloudWitnessRuntime, input: CloudResponseInput<'_>) -> Value {
    let ended_at = receipts::now_rfc3339();
    json!({
        "schema": WITNESS_RECEIPT_SCHEMA,
        "kind": "cloud_response_witnessed",
        "receipt_id": next_receipt_id(),
        "nonce": fresh_nonce(),
        "request_receipt_id": input.request_receipt_id,
        "provider": runtime.config.provider.provider(),
        "path": input.path,
        "upstream_status": input.upstream_status,
        "output_digest": input.output_digest,
        "usage": input.metadata.usage.map(Value::Object),
        "stop_reason": input.metadata.stop_reason,
        "finish_reason": input.metadata.finish_reason,
        "first_byte_at": input.first_byte_at,
        "ended_at": ended_at,
        "end_state": input.end_state.as_str(),
        "created_at": ended_at,
        "test_upstream": runtime.test_upstream,
    })
}

#[derive(Default)]
struct ResponseMetadata {
    usage: Option<Map<String, Value>>,
    stop_reason: Option<String>,
    finish_reason: Option<String>,
}

impl ResponseMetadata {
    fn merge_value(&mut self, provider: CloudUpstream, value: &Value) {
        for usage in usage_candidates(value) {
            let filtered = filter_usage_tokens(usage);
            if !filtered.is_empty() {
                self.usage.get_or_insert_with(Map::new).extend(filtered);
            }
        }
        match provider {
            CloudUpstream::Anthropic => {
                if let Some(reason) = find_string(value, &["stop_reason"])
                    .or_else(|| find_string(value, &["delta", "stop_reason"]))
                    .or_else(|| find_string(value, &["message", "stop_reason"]))
                {
                    self.stop_reason = Some(reason.to_string());
                }
            }
            CloudUpstream::OpenAi => {
                let reason = value
                    .get("choices")
                    .and_then(Value::as_array)
                    .and_then(|choices| choices.first())
                    .and_then(|choice| choice.get("finish_reason"))
                    .and_then(Value::as_str)
                    .or_else(|| find_string(value, &["finish_reason"]));
                if let Some(reason) = reason {
                    self.finish_reason = Some(reason.to_string());
                }
            }
        }
    }
}

enum MetadataCapture {
    Json {
        body: Vec<u8>,
        overflowed: bool,
    },
    Sse {
        pending: Vec<u8>,
        metadata: ResponseMetadata,
    },
}

impl MetadataCapture {
    fn new(stream: bool) -> Self {
        if stream {
            Self::Sse {
                pending: Vec::new(),
                metadata: ResponseMetadata::default(),
            }
        } else {
            Self::Json {
                body: Vec::new(),
                overflowed: false,
            }
        }
    }

    fn observe(&mut self, provider: CloudUpstream, bytes: &[u8]) {
        match self {
            Self::Json { body, overflowed } => {
                if *overflowed {
                    return;
                }
                if body.len().saturating_add(bytes.len()) > MAX_METADATA_BODY_BYTES {
                    body.clear();
                    *overflowed = true;
                } else {
                    body.extend_from_slice(bytes);
                }
            }
            Self::Sse { pending, metadata } => {
                pending.extend_from_slice(bytes);
                while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
                    let line: Vec<u8> = pending.drain(..=newline).collect();
                    parse_sse_line(provider, &line, metadata);
                }
                if pending.len() > MAX_SSE_LINE_BYTES {
                    pending.clear();
                }
            }
        }
    }

    fn finish(self, provider: CloudUpstream) -> ResponseMetadata {
        match self {
            Self::Json { body, overflowed } => {
                if overflowed {
                    return ResponseMetadata::default();
                }
                let mut metadata = ResponseMetadata::default();
                if let Ok(value) = serde_json::from_slice::<Value>(&body) {
                    metadata.merge_value(provider, &value);
                }
                metadata
            }
            Self::Sse { pending, mut metadata } => {
                if !pending.is_empty() {
                    parse_sse_line(provider, &pending, &mut metadata);
                }
                metadata
            }
        }
    }
}

fn parse_sse_line(provider: CloudUpstream, line: &[u8], metadata: &mut ResponseMetadata) {
    let Ok(line) = std::str::from_utf8(line) else {
        return;
    };
    let Some(data) = line.trim_end_matches(['\r', '\n']).strip_prefix("data:") else {
        return;
    };
    let data = data.trim_start();
    if data == "[DONE]" {
        return;
    }
    if let Ok(value) = serde_json::from_str::<Value>(data) {
        metadata.merge_value(provider, &value);
        if let Some(response) = value.get("response") {
            metadata.merge_value(provider, response);
        }
    }
}

fn usage_candidates(value: &Value) -> Vec<&Map<String, Value>> {
    let mut candidates = Vec::new();
    if let Some(usage) = value.get("usage").and_then(Value::as_object) {
        candidates.push(usage);
    }
    for prefix in ["message", "response"] {
        if let Some(usage) = value
            .get(prefix)
            .and_then(|nested| nested.get("usage"))
            .and_then(Value::as_object)
        {
            candidates.push(usage);
        }
    }
    candidates
}

fn filter_usage_tokens(usage: &Map<String, Value>) -> Map<String, Value> {
    usage
        .iter()
        .filter(|(name, value)| name.contains("token") && value.is_number())
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn find_string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SessionTokenEnvGuard {
        previous: Option<std::ffi::OsString>,
    }

    impl SessionTokenEnvGuard {
        fn set(value: Option<&str>) -> Self {
            let previous = std::env::var_os(super::super::CLOUD_WITNESS_SESSION_TOKEN_ENV);
            match value {
                Some(value) => std::env::set_var(super::super::CLOUD_WITNESS_SESSION_TOKEN_ENV, value),
                None => std::env::remove_var(super::super::CLOUD_WITNESS_SESSION_TOKEN_ENV),
            }
            Self { previous }
        }
    }

    impl Drop for SessionTokenEnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(super::super::CLOUD_WITNESS_SESSION_TOKEN_ENV, value),
                None => std::env::remove_var(super::super::CLOUD_WITNESS_SESSION_TOKEN_ENV),
            }
        }
    }

    fn test_runtime() -> CloudWitnessRuntime {
        let directory = tempfile::tempdir().expect("cloud witness test directory");
        let config = CloudWitnessConfig::new(
            CloudUpstream::Anthropic,
            "127.0.0.1:0".to_string(),
            directory.path().join("witness.key"),
            directory.path().join("receipts.jsonl"),
            false,
        );
        CloudWitnessRuntime::new(config).expect("cloud witness test runtime")
    }

    fn test_request(headers: &[(&str, &str)]) -> Request {
        Request {
            method: "POST".to_string(),
            target: "/v1/messages".to_string(),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
            body: br#"{"model":"claude-test","messages":[]}"#.to_vec(),
        }
    }

    #[test]
    fn session_hint_is_withheld_without_matching_listener_auth() {
        let _env_guard = crate::test_support::env_guard();
        let unset_token = SessionTokenEnvGuard::set(None);
        let runtime = test_runtime();
        let unauthenticated = test_request(&[
            (SESSION_ID_HEADER, "session-unproven"),
            (SESSION_AUTH_HEADER, "caller-chosen"),
        ]);
        let record = cloud_request_record(&runtime, &unauthenticated, "/v1/messages", "request-1");
        assert!(record["session_hint"].is_null());
        drop(runtime);
        drop(unset_token);

        let _configured_token = SessionTokenEnvGuard::set(Some("listener-secret"));
        let runtime = test_runtime();
        let missing_auth = test_request(&[(SESSION_ID_HEADER, "session-unproven")]);
        let record = cloud_request_record(&runtime, &missing_auth, "/v1/messages", "request-2");
        assert!(record["session_hint"].is_null());
        let incorrect_auth = test_request(&[
            (SESSION_ID_HEADER, "session-unproven"),
            (SESSION_AUTH_HEADER, "wrong-secret"),
        ]);
        let record = cloud_request_record(&runtime, &incorrect_auth, "/v1/messages", "request-3");
        assert!(record["session_hint"].is_null());
    }

    #[test]
    fn session_hint_is_stamped_with_matching_listener_auth() {
        let _env_guard = crate::test_support::env_guard();
        let _configured_token = SessionTokenEnvGuard::set(Some("listener-secret"));
        let runtime = test_runtime();
        let authenticated = test_request(&[
            (SESSION_ID_HEADER, "session-proven"),
            (SESSION_AUTH_HEADER, "listener-secret"),
        ]);
        let record = cloud_request_record(&runtime, &authenticated, "/v1/messages", "request-1");
        assert_eq!(record["session_hint"], "session-proven");
    }

    #[test]
    fn witnessed_records_have_signed_distinct_nonces() {
        let runtime = test_runtime();
        let request = test_request(&[]);
        let request_record = cloud_request_record(&runtime, &request, "/v1/messages", "request-1");
        let response_record = cloud_response_record(
            &runtime,
            CloudResponseInput {
                path: "/v1/messages",
                request_receipt_id: "request-1",
                upstream_status: Some(200),
                output_digest: Some(sha256_hex_prefixed(b"response")),
                end_state: ResponseEndState::Completed,
                first_byte_at: None,
                metadata: ResponseMetadata::default(),
            },
        );
        let request_nonce = request_record["nonce"].as_str().expect("request nonce");
        let response_nonce = response_record["nonce"].as_str().expect("response nonce");
        assert_eq!(request_nonce.len(), 32);
        assert_eq!(hex::decode(request_nonce).expect("request nonce hex").len(), 16);
        assert_eq!(response_nonce.len(), 32);
        assert_eq!(hex::decode(response_nonce).expect("response nonce hex").len(), 16);
        assert_ne!(request_nonce, response_nonce);

        let key = runtime.witness_key.as_ref().expect("test witness key");
        let identity = key.identity();
        for record in [&request_record, &response_record] {
            let envelope = key.sign_record(record).expect("sign witnessed record");
            assert_eq!(envelope["record"]["nonce"], record["nonce"]);
            crate::llm_shim::witness::verify_witness_envelope(&envelope, &identity)
                .expect("nonce-bearing witness envelope verifies");
        }
    }

    #[test]
    fn request_metadata_contains_names_only() {
        let anthropic = br#"{"model":"claude-x","stream":true,"tools":[{"name":"lookup","description":"secret","input_schema":{"type":"object"}}]}"#;
        let metadata = RequestMetadata::parse(CloudUpstream::Anthropic, anthropic);
        assert_eq!(metadata.model.as_deref(), Some("claude-x"));
        assert_eq!(metadata.tool_names, ["lookup"]);
        assert!(metadata.stream);

        let openai =
            br#"{"model":"gpt-x","tools":[{"type":"function","function":{"name":"search","arguments":"secret"}}]}"#;
        let metadata = RequestMetadata::parse(CloudUpstream::OpenAi, openai);
        assert_eq!(metadata.tool_names, ["search"]);

        let responses_api = br#"{"model":"gpt-x","tools":[{"type":"web_search","name":"web_search"}]}"#;
        let metadata = RequestMetadata::parse(CloudUpstream::OpenAi, responses_api);
        assert_eq!(metadata.tool_names, ["web_search"]);
    }

    #[test]
    fn response_metadata_filters_content_and_merges_sse_usage() {
        let mut capture = MetadataCapture::new(true);
        capture.observe(
            CloudUpstream::Anthropic,
            b"data: {\"type\":\"message_start\",\"message\":{\"content\":[{\"text\":\"secret\"}],\"usage\":{\"input_tokens\":4}}}\n\n",
        );
        capture.observe(
            CloudUpstream::Anthropic,
            b"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
        );
        let metadata = capture.finish(CloudUpstream::Anthropic);
        let usage = metadata.usage.expect("usage");
        assert_eq!(usage.get("input_tokens"), Some(&json!(4)));
        assert_eq!(usage.get("output_tokens"), Some(&json!(2)));
        assert_eq!(metadata.stop_reason.as_deref(), Some("end_turn"));
        assert!(!serde_json::to_string(&usage).expect("usage json").contains("secret"));
    }

    #[test]
    fn openai_json_usage_and_finish_reason_are_parsed() {
        let mut metadata = ResponseMetadata::default();
        metadata.merge_value(
            CloudUpstream::OpenAi,
            &json!({
                "choices": [{"message": {"content": "secret"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            }),
        );
        assert_eq!(metadata.finish_reason.as_deref(), Some("stop"));
        let usage = metadata.usage.expect("usage");
        assert_eq!(usage.get("total_tokens"), Some(&json!(5)));
        assert!(!usage.contains_key("content"));
    }

    #[test]
    fn passthrough_record_contains_no_request_metadata() {
        let record = passthrough_record("/v1/models", true);
        assert_eq!(record["kind"], "passthrough_unwitnessed");
        assert_eq!(record["path"], "/v1/models");
        assert_eq!(record["test_upstream"], true);
        assert!(record.get("request_digest").is_none());
        assert!(record.get("model").is_none());
        assert!(record.get("provider").is_none());
        assert!(record.get("headers").is_none());
        assert!(record.get("nonce").is_none());
        assert!(degraded_record("/v1/models", "test", true, true).get("nonce").is_none());
    }

    #[test]
    fn response_end_states_distinguish_provider_errors_and_client_aborts() {
        assert!(matches!(
            classify_response_end_state(ureq::http::StatusCode::INTERNAL_SERVER_ERROR, false, false),
            ResponseEndState::UpstreamError
        ));
        assert!(matches!(
            classify_response_end_state(ureq::http::StatusCode::OK, true, false),
            ResponseEndState::UpstreamError
        ));
        assert!(matches!(
            classify_response_end_state(ureq::http::StatusCode::OK, false, true),
            ResponseEndState::Aborted
        ));
        assert!(matches!(
            classify_response_end_state(ureq::http::StatusCode::OK, false, false),
            ResponseEndState::Completed
        ));
    }

    #[test]
    fn full_receipt_queue_retains_one_degraded_notice_without_blocking() {
        let (sender, _receiver) = mpsc::sync_channel(0);
        let pending_queue_full = Arc::new(Mutex::new(None));
        let dispatcher = ReceiptDispatcher {
            sender,
            pending_queue_full: Arc::clone(&pending_queue_full),
        };
        dispatcher.send(
            DeliveryJob {
                envelope: json!({"record": {"kind": "cloud_request_witnessed"}}),
                fallback: None,
            },
            json!({"record": {"kind": "witness_degraded", "reason": "receipt_queue_full"}}),
        );
        let pending = pending_queue_full.lock().unwrap();
        assert_eq!(pending.as_ref().unwrap()["record"]["kind"], "witness_degraded");
        assert_eq!(pending.as_ref().unwrap()["record"]["reason"], "receipt_queue_full");
    }
}
