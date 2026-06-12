// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Minimal HTTP/1.1 proxy loop for the shim — stdlib `TcpStream` server side,
//! `ureq` upstream side. Zero new dependencies by design (the crate's e2e
//! tests already pin the stdlib-listener pattern).
//!
//! Protocol posture (experimental v1, documented in the install guide):
//! - One request per connection; every response carries `Connection: close`
//!   and is EOF-delimited (no chunked re-encoding to get wrong).
//! - Streamed upstream bodies (SSE) are pumped chunk-by-chunk with a flush
//!   per read — bytes reach the client exactly as the upstream produced them.
//! - Chunked *request* bodies are refused with `411 Length Required`.
//! - End-states: clean upstream EOF → `stream_completed`; upstream transport
//!   error → `stream_aborted (upstream_error)`; client disconnect mid-pump →
//!   `stream_aborted (client_disconnect)`; upstream unreachable → `502` +
//!   `stream_aborted (upstream_unreachable)`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest as _, Sha256};

use super::{inject, receipts, ShimConfig};

/// Cap on request head (request line + headers).
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Cap on request bodies (chat requests are small; this is a safety rail).
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
/// Read timeout while parsing the client request (a stuck client must not
/// pin a thread forever). Cleared before the upstream pump — local model
/// generations are legitimately slow.
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(30);

static RECEIPT_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_receipt_id(session_id: &str) -> String {
    let seq = RECEIPT_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("shim-{session_id}-{seq}")
}

/// Handle one client connection end-to-end. Never panics; all failure paths
/// either answer with an HTTP error or drop the connection.
pub fn handle_connection(stream: TcpStream, config: &ShimConfig) {
    let _ = stream.set_read_timeout(Some(CLIENT_READ_TIMEOUT));
    let Ok(read_half) = stream.try_clone() else { return };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;

    let request = match read_request(&mut reader) {
        Ok(r) => r,
        Err(RequestError::BadRequest(msg)) => {
            respond_error(&mut writer, 400, "Bad Request", &msg);
            return;
        }
        Err(RequestError::LengthRequired) => {
            respond_error(
                &mut writer,
                411,
                "Length Required",
                "chunked request bodies are not supported by crux-llm-shim v1",
            );
            return;
        }
        Err(RequestError::TooLarge) => {
            respond_error(&mut writer, 413, "Payload Too Large", "request exceeds shim cap");
            return;
        }
        Err(RequestError::Io) => return,
    };
    let _ = writer.set_read_timeout(None);

    let path_only = request.target.split('?').next().unwrap_or("").to_string();
    let injectable = request.method == "POST" && inject::path_is_injectable(&path_only);
    let bundle = if injectable { config.bundle.as_ref() } else { None };
    let injection = inject::inject_bundle(&request.body, bundle.map(|b| b.markdown.as_str()));

    if injection.injected {
        if let Some(bundle) = bundle {
            let id = next_receipt_id(&config.session_id);
            let record = receipts::context_injected_record(config, bundle, &id, &path_only);
            receipts::emit(config, &record);
        }
    }

    forward(config, &request, &injection, &path_only, &mut writer);
}

struct Request {
    method: String,
    target: String,
    /// (name-lowercase, value) pairs in arrival order.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

enum RequestError {
    BadRequest(String),
    LengthRequired,
    TooLarge,
    Io,
}

fn read_request(reader: &mut impl BufRead) -> Result<Request, RequestError> {
    let mut line = String::new();
    if reader.read_line(&mut line).map_err(|_| RequestError::Io)? == 0 {
        return Err(RequestError::Io);
    }
    let mut parts = line.split_whitespace();
    let (method, target) = match (parts.next(), parts.next()) {
        (Some(m), Some(t)) => (m.to_uppercase(), t.to_string()),
        _ => return Err(RequestError::BadRequest("malformed request line".into())),
    };

    let mut headers = Vec::new();
    let mut head_bytes = line.len();
    loop {
        let mut header_line = String::new();
        let n = reader.read_line(&mut header_line).map_err(|_| RequestError::Io)?;
        if n == 0 {
            return Err(RequestError::BadRequest("unexpected EOF in headers".into()));
        }
        head_bytes += n;
        if head_bytes > MAX_HEAD_BYTES {
            return Err(RequestError::TooLarge);
        }
        let trimmed = header_line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }

    if headers.iter().any(|(n, _)| n == "transfer-encoding") {
        return Err(RequestError::LengthRequired);
    }
    let content_length = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .map(|(_, v)| {
            v.parse::<usize>()
                .map_err(|_| RequestError::BadRequest("bad content-length".into()))
        })
        .transpose()?
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(RequestError::TooLarge);
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).map_err(|_| RequestError::Io)?;
    Ok(Request {
        method,
        target,
        headers,
        body,
    })
}

/// Request headers the proxy owns (everything else is forwarded verbatim).
fn header_is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "connection"
            | "content-length"
            | "transfer-encoding"
            | "accept-encoding"
            | "keep-alive"
            | "proxy-connection"
            | "upgrade"
            | "te"
            | "trailer"
    )
}

fn forward(
    config: &ShimConfig,
    request: &Request,
    injection: &inject::Injection,
    path_only: &str,
    writer: &mut TcpStream,
) {
    let url = format!("{}{}", config.upstream, request.target);
    // Pass upstream 4xx/5xx through as responses, not transport errors; no
    // global timeout — local generations are legitimately slow.
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();

    let Ok(method) = ureq::http::Method::from_bytes(request.method.as_bytes()) else {
        respond_error(writer, 501, "Not Implemented", "unsupported method");
        return;
    };
    let mut req_builder = ureq::http::Request::builder().method(method).uri(&url);
    for (name, value) in &request.headers {
        if !header_is_hop_by_hop(name) {
            req_builder = req_builder.header(name.as_str(), value.as_str());
        }
    }
    // Identity keeps pumped bytes == wire bytes (no transparent gzip decode
    // skew between upstream content-encoding headers and the body we emit).
    req_builder = req_builder.header("Accept-Encoding", "identity");
    let upstream_request = match req_builder.body(injection.body.as_slice()) {
        Ok(r) => r,
        Err(err) => {
            respond_error(writer, 400, "Bad Request", &format!("unforwardable request: {err}"));
            return;
        }
    };
    let result = agent.run(upstream_request);

    let bundle = config.bundle.as_ref().filter(|_| injection.injected);
    let mut response = match result {
        Ok(r) => r,
        Err(err) => {
            respond_error(writer, 502, "Bad Gateway", &format!("upstream unreachable: {err}"));
            let end = receipts::StreamEnd {
                end_state: receipts::EndState::Aborted,
                stream: injection.stream,
                model: injection.model.as_deref(),
                first_byte_at: None,
                output_digest: None,
                abort_reason: Some("upstream_unreachable"),
                injected_stable_hash: bundle.and_then(|b| b.stable_hash.as_deref()),
                injected_bundle_digest: bundle.map(|b| b.bundle_digest.as_str()),
            };
            let id = next_receipt_id(&config.session_id);
            receipts::emit(config, &receipts::stream_end_record(config, &end, &id, path_only));
            return;
        }
    };

    // Response head: forwarded status + headers, Connection: close,
    // EOF-delimited body (no content-length / chunked re-encoding).
    let status = response.status();
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    );
    for (name, value) in response.headers() {
        let n = name.as_str();
        if matches!(
            n,
            "content-length" | "transfer-encoding" | "connection" | "content-encoding"
        ) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            head.push_str(n);
            head.push_str(": ");
            head.push_str(v);
            head.push_str("\r\n");
        }
    }
    head.push_str("Connection: close\r\n\r\n");
    if writer.write_all(head.as_bytes()).is_err() {
        return;
    }

    let pump = pump_body(&mut response.body_mut().as_reader(), writer);
    let end = receipts::StreamEnd {
        end_state: pump.end_state,
        stream: injection.stream,
        model: injection.model.as_deref(),
        first_byte_at: pump.first_byte_at,
        output_digest: pump.output_digest,
        abort_reason: pump.abort_reason,
        injected_stable_hash: bundle.and_then(|b| b.stable_hash.as_deref()),
        injected_bundle_digest: bundle.map(|b| b.bundle_digest.as_str()),
    };
    let id = next_receipt_id(&config.session_id);
    receipts::emit(config, &receipts::stream_end_record(config, &end, &id, path_only));
}

struct PumpOutcome {
    end_state: receipts::EndState,
    abort_reason: Option<&'static str>,
    first_byte_at: Option<String>,
    /// `sha256:<hex>` of the emitted bytes; `None` when nothing was emitted.
    output_digest: Option<String>,
}

/// Pump the upstream body to the client, chunk-by-chunk with a flush per read
/// (SSE bytes reach the client exactly as produced). Clean upstream EOF →
/// completed; upstream read error → aborted(upstream_error); client write
/// failure → aborted(client_disconnect).
fn pump_body(upstream_reader: &mut impl Read, writer: &mut TcpStream) -> PumpOutcome {
    let mut buf = [0u8; 8192];
    let mut hasher = Sha256::new();
    let mut first_byte_at: Option<String> = None;
    let mut emitted_any = false;
    let (end_state, abort_reason) = loop {
        match upstream_reader.read(&mut buf) {
            Ok(0) => break (receipts::EndState::Completed, None),
            Ok(n) => {
                if first_byte_at.is_none() {
                    first_byte_at = Some(receipts::now_rfc3339());
                }
                hasher.update(&buf[..n]);
                emitted_any = true;
                if writer.write_all(&buf[..n]).is_err() || writer.flush().is_err() {
                    break (receipts::EndState::Aborted, Some("client_disconnect"));
                }
            }
            Err(_) => break (receipts::EndState::Aborted, Some("upstream_error")),
        }
    };
    let _ = writer.flush();
    let output_digest = emitted_any.then(|| {
        let digest = hasher.finalize();
        let mut out = String::with_capacity(7 + digest.len() * 2);
        out.push_str("sha256:");
        for byte in digest {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
        }
        out
    });
    PumpOutcome {
        end_state,
        abort_reason,
        first_byte_at,
        output_digest,
    }
}

fn respond_error(writer: &mut TcpStream, code: u16, reason: &str, message: &str) {
    let body = serde_json::json!({ "error": { "message": message, "type": "crux_llm_shim" } });
    let body = body.to_string();
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = writer.write_all(head.as_bytes());
    let _ = writer.write_all(body.as_bytes());
    let _ = writer.flush();
}
