// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::{validate_attach_url, ConnectionError, SecretToken, ValidatedAttachUrl};

const MAX_HEADER_BYTES: usize = 64 * 1_024;
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1_024 * 1_024;
const MAX_CONNECTIONS: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const PROXY_DRAIN_TIMEOUT: Duration = Duration::from_secs(31);

const CSP: &str = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self' data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; worker-src 'self'; manifest-src 'self'";

/// A sanitized request passed from the loopback BFF to a native HTTP adapter.
pub struct ForwardRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// A streaming response returned by a native HTTP adapter.
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Box<dyn Read + Send>,
}

impl UpstreamResponse {
    pub fn new(status: u16, headers: Vec<(String, Vec<u8>)>, body: impl Read + Send + 'static) -> Self {
        Self {
            status,
            headers,
            body: Box::new(body),
        }
    }
}

/// Native upstream execution boundary. Implementations own normal TLS
/// certificate validation and must not follow redirects automatically.
pub trait Upstream: Send + Sync + 'static {
    fn execute(&self, request: ForwardRequest) -> Result<UpstreamResponse, UpstreamError>;
}

/// An intentionally redacted upstream failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamError {
    message: &'static str,
}

impl UpstreamError {
    pub const fn sanitized(message: &'static str) -> Self {
        Self { message }
    }

    pub const fn reason(self) -> &'static str {
        self.message
    }
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for UpstreamError {}

/// Native connection state rendered by the proxy before forwarding is ready.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusPage {
    pub status: u16,
    pub title: String,
    pub profile: String,
    pub message: String,
    pub retry: Option<String>,
}

impl StatusPage {
    pub fn new(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: 503,
            title: title.into(),
            profile: String::new(),
            message: message.into(),
            retry: None,
        }
    }
}

/// Escape and render an explicit native-owned status page.
pub fn render_status_html(status: &StatusPage) -> String {
    let mut html = String::from(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>",
    );
    push_html(&mut html, &status.title);
    html.push_str("</title><style>body{margin:0;background:#10131a;color:#f4f6fb;font:16px system-ui;display:grid;min-height:100vh;place-items:center}main{max-width:42rem;padding:2.5rem}h1{font-size:1.7rem}p{line-height:1.6;color:#c4cad8}.profile{color:#8ea8ff}</style></head><body><main><h1>");
    push_html(&mut html, &status.title);
    html.push_str("</h1>");
    if !status.profile.is_empty() {
        html.push_str("<p class=\"profile\">");
        push_html(&mut html, &status.profile);
        html.push_str("</p>");
    }
    html.push_str("<p>");
    push_html(&mut html, &status.message);
    html.push_str("</p>");
    if let Some(retry) = &status.retry {
        html.push_str("<p>");
        push_html(&mut html, retry);
        html.push_str("</p>");
    }
    html.push_str("</main></body></html>");
    html
}

fn push_html(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            value => output.push(value),
        }
    }
}

struct ForwardMode {
    upstream_origin: ValidatedAttachUrl,
    upstream: Arc<dyn Upstream>,
    token: Arc<SecretToken>,
    active: Arc<AtomicBool>,
    clear_browser_state: Arc<AtomicBool>,
}

impl Clone for ForwardMode {
    fn clone(&self) -> Self {
        Self {
            upstream_origin: self.upstream_origin.clone(),
            upstream: Arc::clone(&self.upstream),
            token: Arc::clone(&self.token),
            active: Arc::clone(&self.active),
            clear_browser_state: Arc::clone(&self.clear_browser_state),
        }
    }
}

#[derive(Clone)]
enum ProxyMode {
    Status(StatusPage),
    Forward(ForwardMode),
    Stopped,
}

struct Shared {
    mode: Mutex<ProxyMode>,
    running: AtomicBool,
    active_connections: Mutex<BTreeMap<usize, TcpStream>>,
    connections_changed: Condvar,
    next_connection_id: AtomicUsize,
}

/// A bound loopback proxy which has not yet started its accept thread.
pub struct ProxyServer {
    listener: TcpListener,
    address: SocketAddr,
    shared: Arc<Shared>,
}

impl ProxyServer {
    pub fn bind() -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        Ok(Self {
            listener,
            address,
            shared: Arc::new(Shared {
                mode: Mutex::new(ProxyMode::Status(StatusPage::new(
                    "Connecting to Crux",
                    "The selected daemon is being checked.",
                ))),
                running: AtomicBool::new(true),
                active_connections: Mutex::new(BTreeMap::new()),
                connections_changed: Condvar::new(),
                next_connection_id: AtomicUsize::new(0),
            }),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.address.port())
    }

    pub fn control(&self) -> ProxyControl {
        ProxyControl {
            address: self.address,
            shared: Arc::clone(&self.shared),
        }
    }

    pub fn start(self) -> io::Result<ProxyHandle> {
        let control = self.control();
        let listener = self.listener;
        let address = self.address;
        let shared = Arc::clone(&self.shared);
        let join = thread::Builder::new()
            .name(format!("crux-proxy-{}", address.port()))
            .spawn(move || accept_loop(listener, address, shared))?;
        Ok(ProxyHandle {
            control,
            join: Some(join),
            drain_attempted: false,
        })
    }
}

/// Thread-safe control plane for a profile's proxy origin.
#[derive(Clone)]
pub struct ProxyControl {
    address: SocketAddr,
    shared: Arc<Shared>,
}

impl ProxyControl {
    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.address.port())
    }

    pub fn show_status(&self, status: StatusPage) -> Result<(), ConnectionError> {
        let mut mode = self
            .shared
            .mode
            .lock()
            .map_err(|_| ConnectionError::new("proxy state is unavailable"))?;
        if !self.shared.running.load(Ordering::Acquire) {
            return Err(ConnectionError::new("proxy has stopped"));
        }
        deactivate_forwarding(&mode);
        *mode = ProxyMode::Status(status);
        drop(mode);
        shutdown_active_connections(&self.shared);
        Ok(())
    }

    pub fn set_forward(
        &self,
        upstream_origin: &str,
        upstream: Arc<dyn Upstream>,
        token: SecretToken,
    ) -> Result<(), ConnectionError> {
        let validated = validate_attach_url(upstream_origin)?;
        let mut mode = self
            .shared
            .mode
            .lock()
            .map_err(|_| ConnectionError::new("proxy state is unavailable"))?;
        if !self.shared.running.load(Ordering::Acquire) {
            return Err(ConnectionError::new("proxy has stopped"));
        }
        *mode = ProxyMode::Forward(ForwardMode {
            upstream_origin: validated,
            upstream,
            token: Arc::new(token),
            active: Arc::new(AtomicBool::new(true)),
            clear_browser_state: Arc::new(AtomicBool::new(true)),
        });
        Ok(())
    }

    pub fn stop(&self) {
        self.shared.running.store(false, Ordering::Release);
        match self.shared.mode.lock() {
            Ok(mut mode) => {
                deactivate_forwarding(&mode);
                *mode = ProxyMode::Stopped;
            }
            Err(poisoned) => {
                let mut mode = poisoned.into_inner();
                deactivate_forwarding(&mode);
                *mode = ProxyMode::Stopped;
            }
        }
        shutdown_active_connections(&self.shared);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
    }
}

fn deactivate_forwarding(mode: &ProxyMode) {
    if let ProxyMode::Forward(forward) = mode {
        forward.active.store(false, Ordering::Release);
    }
}

fn shutdown_active_connections(shared: &Shared) {
    let connections = match shared.active_connections.lock() {
        Ok(connections) => connections,
        Err(poisoned) => poisoned.into_inner(),
    };
    for stream in connections.values() {
        let _ = stream.shutdown(Shutdown::Both);
    }
}

/// Running loopback proxy. Drop is a bounded stop/join backstop.
pub struct ProxyHandle {
    control: ProxyControl,
    join: Option<JoinHandle<()>>,
    drain_attempted: bool,
}

impl ProxyHandle {
    pub fn control(&self) -> ProxyControl {
        self.control.clone()
    }

    pub fn origin(&self) -> String {
        self.control.origin()
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        self.control.stop();
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| io::Error::other("proxy accept thread panicked"))?;
        }
        if self.drain_attempted {
            return Ok(());
        }
        self.drain_attempted = true;
        let deadline = Instant::now() + PROXY_DRAIN_TIMEOUT;
        let mut connections = match self.control.shared.active_connections.lock() {
            Ok(connections) => connections,
            Err(poisoned) => poisoned.into_inner(),
        };
        while !connections.is_empty() {
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "proxy request workers did not stop within the drain budget",
                ));
            }
            let remaining = deadline.saturating_duration_since(now);
            let waited = self
                .control
                .shared
                .connections_changed
                .wait_timeout(connections, remaining);
            match waited {
                Ok((guard, _)) => connections = guard,
                Err(poisoned) => {
                    let (guard, _) = poisoned.into_inner();
                    connections = guard;
                }
            }
        }
        Ok(())
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn accept_loop(listener: TcpListener, address: SocketAddr, shared: Arc<Shared>) {
    while shared.running.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if !peer.ip().is_loopback() {
                    continue;
                }
                if !shared.running.load(Ordering::Acquire) {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                let Ok(shutdown_stream) = stream.try_clone() else {
                    continue;
                };
                let connection_id = shared.next_connection_id.fetch_add(1, Ordering::AcqRel);
                let mut connections = match shared.active_connections.lock() {
                    Ok(connections) => connections,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if !shared.running.load(Ordering::Acquire) {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                if connections.len() >= MAX_CONNECTIONS {
                    continue;
                }
                connections.insert(connection_id, shutdown_stream);
                drop(connections);
                let worker_shared = Arc::clone(&shared);
                let spawn = thread::Builder::new()
                    .name(format!("crux-proxy-request-{}", address.port()))
                    .spawn(move || {
                        let _guard = ConnectionGuard {
                            connection_id,
                            shared: Arc::clone(&worker_shared),
                        };
                        let _ = handle_connection(stream, address, &worker_shared);
                    });
                if spawn.is_err() {
                    remove_connection(&shared, connection_id);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

struct ConnectionGuard {
    connection_id: usize,
    shared: Arc<Shared>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        remove_connection(&self.shared, self.connection_id);
    }
}

fn remove_connection(shared: &Shared, connection_id: usize) {
    match shared.active_connections.lock() {
        Ok(mut connections) => {
            connections.remove(&connection_id);
        }
        Err(poisoned) => {
            poisoned.into_inner().remove(&connection_id);
        }
    }
    shared.connections_changed.notify_all();
}

fn handle_connection(mut stream: TcpStream, address: SocketAddr, shared: &Shared) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let expected_origin = format!("http://127.0.0.1:{}", address.port());
    let expected_host = format!("127.0.0.1:{}", address.port());
    let request = match read_request(&mut stream, &expected_origin, &expected_host) {
        Ok(request) => request,
        Err(rejection) => return write_safe_error(&mut stream, rejection.status, rejection.message),
    };
    let mode = shared
        .mode
        .lock()
        .map_err(|_| io::Error::other("proxy state unavailable"))?
        .clone();
    match mode {
        ProxyMode::Status(status) => write_status(&mut stream, &status),
        ProxyMode::Forward(forward) => forward_request(&mut stream, request, &forward, &shared.running),
        ProxyMode::Stopped => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "proxy has stopped")),
    }
}

struct ParsedRequest {
    method: String,
    target: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

struct Rejection {
    status: u16,
    message: &'static str,
}

impl Rejection {
    const fn bad_request(message: &'static str) -> Self {
        Self { status: 400, message }
    }

    const fn forbidden(message: &'static str) -> Self {
        Self { status: 403, message }
    }
}

fn read_request(
    stream: &mut TcpStream,
    expected_origin: &str,
    expected_host: &str,
) -> Result<ParsedRequest, Rejection> {
    let mut received = Vec::with_capacity(4_096);
    let header_end = loop {
        if let Some(index) = find_bytes(&received, b"\r\n\r\n") {
            break index + 4;
        }
        if received.len() >= MAX_HEADER_BYTES {
            return Err(Rejection {
                status: 431,
                message: "Request headers are too large.",
            });
        }
        let mut chunk = [0_u8; 4_096];
        let count = stream
            .read(&mut chunk)
            .map_err(|_| Rejection::bad_request("Could not read the request."))?;
        if count == 0 {
            return Err(Rejection::bad_request("Request headers are incomplete."));
        }
        received.extend_from_slice(&chunk[..count]);
    };
    let header_bytes = &received[..header_end - 4];
    let header_text =
        std::str::from_utf8(header_bytes).map_err(|_| Rejection::bad_request("Request headers are not valid text."))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| Rejection::bad_request("Request line is missing."))?;
    let request_parts: Vec<_> = request_line.split(' ').collect();
    if request_parts.len() != 3 || !matches!(request_parts[2], "HTTP/1.1" | "HTTP/1.0") {
        return Err(Rejection::bad_request("Request line is invalid."));
    }
    let method = request_parts[0];
    if method.is_empty() || !method.bytes().all(is_http_token) {
        return Err(Rejection::bad_request("Request method is invalid."));
    }
    if method.eq_ignore_ascii_case("CONNECT") || method.eq_ignore_ascii_case("TRACE") {
        return Err(Rejection {
            status: 405,
            message: "This HTTP method is not allowed.",
        });
    }
    let target = request_parts[1];
    if !target.starts_with('/') || target.starts_with("//") || target.chars().any(char::is_control) {
        return Err(Rejection::bad_request("Only origin-form request targets are accepted."));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(Rejection::bad_request("Folded request headers are forbidden."));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| Rejection::bad_request("Request header is malformed."))?;
        if name.is_empty() || !name.bytes().all(is_http_token) {
            return Err(Rejection::bad_request("Request header name is invalid."));
        }
        let trimmed = value.trim_matches([' ', '\t']);
        if trimmed.chars().any(char::is_control) {
            return Err(Rejection::bad_request("Request header value is invalid."));
        }
        headers.push((name.to_ascii_lowercase(), trimmed.as_bytes().to_vec()));
    }
    validate_browser_origin(&headers, expected_origin, expected_host, method)?;
    if header_values(&headers, "transfer-encoding").next().is_some() {
        return Err(Rejection::bad_request(
            "Transfer-encoded request bodies are not accepted.",
        ));
    }
    let content_lengths: Vec<_> = header_values(&headers, "content-length").collect();
    if content_lengths.len() > 1 {
        return Err(Rejection::bad_request(
            "Request contains multiple Content-Length headers.",
        ));
    }
    let content_length = match content_lengths.first() {
        Some(value) => std::str::from_utf8(value)
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .ok_or_else(|| Rejection::bad_request("Content-Length is invalid."))?,
        None => 0,
    };
    if content_length > MAX_REQUEST_BODY_BYTES {
        return Err(Rejection {
            status: 413,
            message: "Request body is too large.",
        });
    }
    let mut body = received[header_end..].to_vec();
    if body.len() > content_length {
        body.truncate(content_length);
    }
    while body.len() < content_length {
        let remaining = content_length - body.len();
        let mut chunk = [0_u8; 8_192];
        let read_limit = remaining.min(chunk.len());
        let count = stream
            .read(&mut chunk[..read_limit])
            .map_err(|_| Rejection::bad_request("Could not read the request body."))?;
        if count == 0 {
            return Err(Rejection::bad_request("Request body is incomplete."));
        }
        body.extend_from_slice(&chunk[..count]);
    }
    Ok(ParsedRequest {
        method: method.to_ascii_uppercase(),
        target: target.to_string(),
        headers,
        body,
    })
}

fn validate_browser_origin(
    headers: &[(String, Vec<u8>)],
    expected_origin: &str,
    expected_host: &str,
    method: &str,
) -> Result<(), Rejection> {
    let hosts: Vec<_> = header_values(headers, "host").collect();
    if hosts.len() != 1 || !hosts[0].eq_ignore_ascii_case(expected_host.as_bytes()) {
        return Err(Rejection::forbidden("Request Host does not match this profile proxy."));
    }
    let fetch_sites: Vec<_> = header_values(headers, "sec-fetch-site").collect();
    let fetch_modes: Vec<_> = header_values(headers, "sec-fetch-mode").collect();
    let fetch_destinations: Vec<_> = header_values(headers, "sec-fetch-dest").collect();
    let is_profile_navigation = method == "GET"
        && fetch_sites
            .first()
            .is_some_and(|value| value.eq_ignore_ascii_case(b"same-site"))
        && fetch_modes.len() == 1
        && fetch_modes[0].eq_ignore_ascii_case(b"navigate")
        && fetch_destinations.len() == 1
        && fetch_destinations[0].eq_ignore_ascii_case(b"document");
    if fetch_sites.len() > 1
        || fetch_modes.len() > 1
        || fetch_destinations.len() > 1
        || fetch_sites.first().is_some_and(|value| {
            !value.eq_ignore_ascii_case(b"same-origin")
                && !value.eq_ignore_ascii_case(b"none")
                && !is_profile_navigation
        })
    {
        return Err(Rejection::forbidden("Cross-site requests are not allowed."));
    }
    let origins: Vec<_> = header_values(headers, "origin").collect();
    if origins.len() > 1
        || origins
            .first()
            .is_some_and(|value| !value.eq_ignore_ascii_case(expected_origin.as_bytes()))
    {
        return Err(Rejection::forbidden(
            "Request Origin does not match this profile proxy.",
        ));
    }
    let referrers: Vec<_> = header_values(headers, "referer").collect();
    if referrers.len() > 1
        || referrers.first().is_some_and(|value| {
            !is_profile_navigation
                && std::str::from_utf8(value).ok().is_none_or(|referer| {
                    referer != expected_origin && !referer.starts_with(&format!("{expected_origin}/"))
                })
        })
    {
        return Err(Rejection::forbidden(
            "Request Referer does not match this profile proxy.",
        ));
    }
    let safe_method = matches!(method, "GET" | "HEAD" | "OPTIONS");
    if !safe_method && origins.is_empty() && referrers.is_empty() && fetch_sites.is_empty() {
        return Err(Rejection::forbidden(
            "Authenticated mutations require same-origin browser evidence.",
        ));
    }
    Ok(())
}

fn forward_request(
    stream: &mut dyn Write,
    request: ParsedRequest,
    mode: &ForwardMode,
    running: &AtomicBool,
) -> io::Result<()> {
    if !forwarding_is_active(mode, running) {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "proxy has stopped"));
    }
    let forwarded = ForwardRequest {
        method: request.method.clone(),
        url: request.target,
        headers: sanitize_request_headers(request.headers, mode.token.expose_bytes()),
        body: request.body,
    };
    let response = match mode.upstream.execute(forwarded) {
        Ok(response) => response,
        Err(_) => return write_safe_error(stream, 502, "The selected daemon could not answer the request."),
    };
    if !forwarding_is_active(mode, running) {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "proxy has stopped"));
    }
    write_upstream_response(stream, response, &request.method, mode, running)
}

fn forwarding_is_active(mode: &ForwardMode, running: &AtomicBool) -> bool {
    running.load(Ordering::Acquire) && mode.active.load(Ordering::Acquire)
}

fn sanitize_request_headers(headers: Vec<(String, Vec<u8>)>, token: &[u8]) -> Vec<(String, Vec<u8>)> {
    let connection_named = connection_named_headers(&headers);
    let mut sanitized = Vec::new();
    for (name, value) in headers {
        if is_hop_by_hop(&name)
            || connection_named.iter().any(|candidate| candidate == &name)
            || matches!(
                name.as_str(),
                "authorization"
                    | "proxy-authorization"
                    | "cookie"
                    | "host"
                    | "forwarded"
                    | "origin"
                    | "referer"
                    | "content-length"
                    | "accept-encoding"
            )
            || name.starts_with("sec-fetch-")
            || name.starts_with("x-forwarded-")
        {
            continue;
        }
        sanitized.push((name, value));
    }
    sanitized.push(("accept-encoding".to_string(), b"identity".to_vec()));
    let mut bearer = Vec::with_capacity(7 + token.len());
    bearer.extend_from_slice(b"Bearer ");
    bearer.extend_from_slice(token);
    sanitized.push(("authorization".to_string(), bearer));
    sanitized
}

fn write_upstream_response(
    stream: &mut dyn Write,
    mut response: UpstreamResponse,
    method: &str,
    mode: &ForwardMode,
    running: &AtomicBool,
) -> io::Result<()> {
    if !forwarding_is_active(mode, running) {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "proxy has stopped"));
    }
    let headers = match filter_response_headers(
        response.status,
        response.headers,
        &mode.upstream_origin,
        mode.token.expose_bytes(),
    ) {
        Ok(headers) => headers,
        Err(message) => return write_safe_error(stream, 502, message),
    };
    write_status_line(stream, response.status)?;
    for (name, value) in headers {
        stream.write_all(name.as_bytes())?;
        stream.write_all(b": ")?;
        stream.write_all(&value)?;
        stream.write_all(b"\r\n")?;
    }
    write_security_headers(stream)?;
    if mode.clear_browser_state.swap(false, Ordering::AcqRel) {
        if let Err(error) = stream.write_all(b"Clear-Site-Data: \"cache\", \"cookies\", \"storage\"\r\n") {
            mode.clear_browser_state.store(true, Ordering::Release);
            return Err(error);
        }
    }
    stream.write_all(b"Connection: close\r\n\r\n")?;
    if method != "HEAD" && !matches!(response.status, 204 | 304) {
        stream_redacted(
            &mut response.body,
            stream,
            mode.token.expose_bytes(),
            &mode.active,
            running,
        )?;
    }
    stream.flush()
}

fn filter_response_headers(
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    upstream_origin: &ValidatedAttachUrl,
    token: &[u8],
) -> Result<Vec<(String, Vec<u8>)>, &'static str> {
    if !(200..=599).contains(&status) {
        return Err("The daemon returned an invalid HTTP status.");
    }
    let mut filtered = Vec::new();
    let mut locations = Vec::new();
    let mut connection_named = Vec::new();
    for (name, value) in &headers {
        if name.eq_ignore_ascii_case("connection") {
            if let Ok(raw) = std::str::from_utf8(value) {
                connection_named.extend(raw.split(',').map(|part| part.trim().to_ascii_lowercase()));
            }
        }
    }
    for (name, value) in headers {
        if !name.bytes().all(is_http_token) || value.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err("The daemon returned an invalid response header.");
        }
        if contains_bytes(name.as_bytes(), token) || contains_bytes(&value, token) {
            return Err("The daemon reflected credential material; the response was blocked.");
        }
        let lower = name.to_ascii_lowercase();
        if lower == "refresh" {
            return Err("The daemon attempted a refresh navigation; the response was blocked.");
        }
        if lower == "content-disposition"
            && std::str::from_utf8(&value)
                .ok()
                .is_some_and(|raw| raw.to_ascii_lowercase().contains("attachment"))
        {
            return Err("The daemon attempted a download; the response was blocked.");
        }
        if lower == "content-encoding" && !value.eq_ignore_ascii_case(b"identity") {
            return Err("Encoded daemon responses are not accepted by the credential broker.");
        }
        if lower == "location" {
            locations.push(value);
            continue;
        }
        if is_hop_by_hop(&lower)
            || connection_named.iter().any(|candidate| candidate == &lower)
            || matches!(
                lower.as_str(),
                "set-cookie"
                    | "set-cookie2"
                    | "alt-svc"
                    | "clear-site-data"
                    | "cross-origin-embedder-policy"
                    | "content-length"
                    | "content-security-policy"
                    | "content-security-policy-report-only"
                    | "nel"
                    | "reporting-endpoints"
                    | "report-to"
                    | "www-authenticate"
                    | "x-frame-options"
                    | "x-content-type-options"
                    | "referrer-policy"
                    | "permissions-policy"
                    | "cross-origin-opener-policy"
                    | "cross-origin-resource-policy"
                    | "access-control-allow-credentials"
            )
        {
            continue;
        }
        filtered.push((lower, value));
    }
    if is_redirect(status) {
        if locations.len() != 1 {
            return Err("The daemon returned an invalid redirect.");
        }
        let rewritten = rewrite_location(&locations[0], upstream_origin)?;
        filtered.push(("location".to_string(), rewritten));
    }
    Ok(filtered)
}

fn rewrite_location(location: &[u8], upstream_origin: &ValidatedAttachUrl) -> Result<Vec<u8>, &'static str> {
    let raw = std::str::from_utf8(location).map_err(|_| "The daemon returned an invalid redirect.")?;
    if raw.is_empty() || raw.starts_with("//") || raw.contains('\\') || raw.chars().any(char::is_control) {
        return Err("The daemon attempted an unsafe redirect; the response was blocked.");
    }
    if raw.starts_with('/') || raw.starts_with('?') || raw.starts_with('#') {
        return Ok(raw.as_bytes().to_vec());
    }
    if let Some(scheme_index) = raw.find("://") {
        let remainder = &raw[scheme_index + 3..];
        let split = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        let base = format!("{}://{}", &raw[..scheme_index], &remainder[..split]);
        let parsed = validate_attach_url(&base)
            .map_err(|_| "The daemon attempted an unsafe redirect; the response was blocked.")?;
        if parsed.scheme() != upstream_origin.scheme()
            || parsed.host() != upstream_origin.host()
            || parsed.effective_port() != upstream_origin.effective_port()
        {
            return Err("The daemon attempted a foreign redirect; the response was blocked.");
        }
        let suffix = &remainder[split..];
        return Ok(if suffix.is_empty() {
            b"/".to_vec()
        } else if suffix.starts_with('/') {
            suffix.as_bytes().to_vec()
        } else {
            format!("/{suffix}").into_bytes()
        });
    }
    if raw.split('/').next().is_some_and(|segment| segment.contains(':')) {
        return Err("The daemon attempted a non-HTTP redirect; the response was blocked.");
    }
    Ok(raw.as_bytes().to_vec())
}

fn stream_redacted(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    token: &[u8],
    active: &AtomicBool,
    running: &AtomicBool,
) -> io::Result<()> {
    let mut pending = Vec::new();
    let mut chunk = [0_u8; 8_192];
    loop {
        if !running.load(Ordering::Acquire) || !active.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "proxy has stopped"));
        }
        let count = reader.read(&mut chunk)?;
        if !running.load(Ordering::Acquire) || !active.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "proxy has stopped"));
        }
        if count == 0 {
            redact_and_write(&mut pending, writer, token, true)?;
            return Ok(());
        }
        pending.extend_from_slice(&chunk[..count]);
        redact_and_write(&mut pending, writer, token, false)?;
    }
}

fn redact_and_write(pending: &mut Vec<u8>, writer: &mut dyn Write, token: &[u8], flush_all: bool) -> io::Result<()> {
    while let Some(index) = find_bytes(pending, token) {
        writer.write_all(&pending[..index])?;
        writer.write_all(b"[REDACTED]")?;
        pending.drain(..index + token.len());
    }
    let retained = if flush_all {
        0
    } else {
        token.len().saturating_sub(1).min(pending.len())
    };
    let writable = pending.len() - retained;
    writer.write_all(&pending[..writable])?;
    pending.drain(..writable);
    Ok(())
}

fn write_status(stream: &mut dyn Write, status: &StatusPage) -> io::Result<()> {
    let body = render_status_html(status);
    write_buffered_response(stream, status.status, "text/html; charset=utf-8", body.as_bytes())
}

fn write_safe_error(stream: &mut dyn Write, status: u16, message: &'static str) -> io::Result<()> {
    let page = StatusPage {
        status,
        title: "Crux connection blocked".to_string(),
        profile: String::new(),
        message: message.to_string(),
        retry: None,
    };
    write_status(stream, &page)
}

fn write_buffered_response(stream: &mut dyn Write, status: u16, content_type: &str, body: &[u8]) -> io::Result<()> {
    write_status_line(stream, status)?;
    write!(
        stream,
        "Content-Type: {content_type}\r\nContent-Length: {}\r\n",
        body.len()
    )?;
    write_security_headers(stream)?;
    // Every native status transition is an isolation barrier. This header is
    // processed before any subsequent console script can run and reinforces
    // the host-side clear for cookies, whose scope otherwise ignores ports.
    stream.write_all(
        b"Cache-Control: no-store\r\nClear-Site-Data: \"cache\", \"cookies\", \"storage\"\r\nConnection: close\r\n\r\n",
    )?;
    stream.write_all(body)?;
    stream.flush()
}

fn write_status_line(stream: &mut dyn Write, status: u16) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {status} {}\r\n", reason_phrase(status))
}

fn write_security_headers(stream: &mut dyn Write) -> io::Result<()> {
    write!(
        stream,
        "Content-Security-Policy: {CSP}\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nPermissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()\r\nCross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\n"
    )
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Response",
    }
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 300..=303 | 305..=308)
}

fn header_values<'a>(headers: &'a [(String, Vec<u8>)], name: &'a str) -> impl Iterator<Item = &'a [u8]> {
    headers
        .iter()
        .filter(move |(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice())
}

fn connection_named_headers(headers: &[(String, Vec<u8>)]) -> Vec<String> {
    header_values(headers, "connection")
        .filter_map(|value| std::str::from_utf8(value).ok())
        .flat_map(|value| value.split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .collect()
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_http_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    find_bytes(haystack, needle).is_some()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{
        forward_request, render_status_html, validate_browser_origin, ForwardMode, ForwardRequest, ParsedRequest,
        ProxyServer, StatusPage, Upstream, UpstreamError, UpstreamResponse,
    };
    use crate::{validate_attach_url, SecretToken};

    const TOKEN: &[u8] = b"0123456789abcdef0123456789abcdef";

    struct FakeUpstream {
        calls: AtomicUsize,
        requests: Mutex<Vec<ForwardRequest>>,
        response: Mutex<Option<UpstreamResponse>>,
    }

    impl FakeUpstream {
        fn new(response: UpstreamResponse) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
                response: Mutex::new(Some(response)),
            }
        }
    }

    impl Upstream for FakeUpstream {
        fn execute(&self, request: ForwardRequest) -> Result<UpstreamResponse, UpstreamError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.requests.lock().unwrap().push(request);
            self.response
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| UpstreamError::sanitized("test response already consumed"))
        }
    }

    fn send(origin: &str, extra_headers: &str, method: &str) -> Vec<u8> {
        let authority = origin.strip_prefix("http://").unwrap();
        let mut stream = TcpStream::connect(authority).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        write!(
            stream,
            "{method} /console HTTP/1.1\r\nHost: {authority}\r\n{extra_headers}Connection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        response
    }

    fn token() -> SecretToken {
        SecretToken::from_bytes(TOKEN.to_vec()).unwrap()
    }

    fn bind_server() -> Option<ProxyServer> {
        match ProxyServer::bind() {
            Ok(server) => Some(server),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                // The Codex workspace sandbox denies AF_INET bind. CI and normal
                // developer hosts execute the same end-to-end socket path.
                None
            }
            Err(error) => panic!("could not bind proxy test server: {error}"),
        }
    }

    #[test]
    fn status_page_escapes_untrusted_profile_and_reason() {
        let status = StatusPage {
            status: 503,
            title: "Unavailable <now>".to_string(),
            profile: "<script>alert(1)</script>".to_string(),
            message: "couldn't connect & retry".to_string(),
            retry: None,
        };
        let html = render_status_html(&status);
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("couldn&#39;t connect &amp; retry"));

        let mut response = Vec::new();
        super::write_status(&mut response, &status).unwrap();
        assert!(String::from_utf8_lossy(&response).contains("Clear-Site-Data: \"cache\", \"cookies\", \"storage\""));
    }

    #[test]
    fn stopped_proxy_rejects_late_forward_state() {
        let Some(server) = bind_server() else {
            return;
        };
        let control = server.control();
        control.stop();
        let upstream = Arc::new(FakeUpstream::new(UpstreamResponse::new(
            200,
            Vec::new(),
            Cursor::new(Vec::new()),
        )));
        assert!(control
            .set_forward("https://daemon.example", upstream.clone(), token())
            .is_err());
        assert!(control.show_status(StatusPage::new("late", "late")).is_err());
        assert_eq!(upstream.calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn quiesced_forward_mode_rejects_without_contacting_upstream() {
        let upstream = Arc::new(FakeUpstream::new(UpstreamResponse::new(
            200,
            Vec::new(),
            Cursor::new(b"must not be reached".to_vec()),
        )));
        let active = Arc::new(AtomicBool::new(false));
        let mode = ForwardMode {
            upstream_origin: validate_attach_url("https://daemon.example").unwrap(),
            upstream: upstream.clone(),
            token: Arc::new(token()),
            active,
            clear_browser_state: Arc::new(AtomicBool::new(true)),
        };
        let request = ParsedRequest {
            method: "GET".to_string(),
            target: "/console".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let mut browser_response = Vec::new();
        assert!(forward_request(&mut browser_response, request, &mode, &AtomicBool::new(true)).is_err());
        assert_eq!(upstream.calls.load(Ordering::Acquire), 0);
        assert!(browser_response.is_empty());
    }

    #[test]
    fn switching_status_quiesces_the_old_proxy() {
        let upstream = Arc::new(FakeUpstream::new(UpstreamResponse::new(
            200,
            Vec::new(),
            Cursor::new(b"must not be reached".to_vec()),
        )));
        let Some(server) = bind_server() else {
            return;
        };
        let control = server.control();
        control
            .set_forward("https://daemon.example", upstream.clone(), token())
            .unwrap();
        let mut handle = server.start().unwrap();
        control
            .show_status(StatusPage::new(
                "Switching Crux profile",
                "The previous credential boundary is closed.",
            ))
            .unwrap();
        let response = send(&handle.origin(), "", "GET");
        let rendered = String::from_utf8_lossy(&response);
        assert!(rendered.starts_with("HTTP/1.1 503"));
        assert!(rendered.contains("previous credential boundary is closed"));
        assert_eq!(upstream.calls.load(Ordering::Acquire), 0);
        handle.shutdown().unwrap();
    }

    #[test]
    fn hostile_daemon_pipeline_is_covered_without_a_socket() {
        let reflected = [b"before-".as_slice(), TOKEN, b"-after".as_slice()].concat();
        let upstream = Arc::new(FakeUpstream::new(UpstreamResponse::new(
            200,
            vec![
                ("Set-Cookie".to_string(), b"profile=A".to_vec()),
                ("Alt-Svc".to_string(), b"h2=\"evil.example:443\"".to_vec()),
                ("Clear-Site-Data".to_string(), b"*".to_vec()),
                ("NEL".to_string(), br#"{"report_to":"foreign"}"#.to_vec()),
                (
                    "Report-To".to_string(),
                    br#"{"url":"https://evil.example/report"}"#.to_vec(),
                ),
                ("Proxy-Connection".to_string(), b"keep-alive".to_vec()),
                ("WWW-Authenticate".to_string(), b"Basic realm=hostile".to_vec()),
                ("Content-Type".to_string(), b"text/plain".to_vec()),
            ],
            Cursor::new(reflected),
        )));
        let mode = ForwardMode {
            upstream_origin: validate_attach_url("https://daemon.example").unwrap(),
            upstream: upstream.clone(),
            token: Arc::new(token()),
            active: Arc::new(AtomicBool::new(true)),
            clear_browser_state: Arc::new(AtomicBool::new(true)),
        };
        let request = ParsedRequest {
            method: "GET".to_string(),
            target: "/console".to_string(),
            headers: vec![
                ("host".to_string(), b"127.0.0.1:12345".to_vec()),
                ("authorization".to_string(), b"Bearer browser-secret".to_vec()),
                ("proxy-authorization".to_string(), b"Basic browser-secret".to_vec()),
                ("cookie".to_string(), b"profile=A".to_vec()),
                ("forwarded".to_string(), b"for=192.0.2.10;host=spoofed.example".to_vec()),
                ("connection".to_string(), b"x-remove".to_vec()),
                ("x-remove".to_string(), b"ambient".to_vec()),
            ],
            body: Vec::new(),
        };
        let mut browser_response = Vec::new();
        forward_request(&mut browser_response, request, &mode, &AtomicBool::new(true)).unwrap();

        assert!(!super::contains_bytes(&browser_response, TOKEN));
        let rendered = String::from_utf8_lossy(&browser_response);
        assert!(rendered.starts_with("HTTP/1.1 200"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(rendered.contains("Content-Security-Policy:"));
        assert_eq!(rendered.matches("Clear-Site-Data:").count(), 1);
        assert!(rendered.contains("Clear-Site-Data: \"cache\", \"cookies\", \"storage\""));
        assert!(!rendered.to_ascii_lowercase().contains("set-cookie"));
        for blocked in [
            "alt-svc",
            "nel:",
            "report-to",
            "proxy-connection",
            "www-authenticate",
            "evil.example",
        ] {
            assert!(!rendered.to_ascii_lowercase().contains(blocked));
        }

        let requests = upstream.requests.lock().unwrap();
        let forwarded = requests.first().unwrap();
        let authorizations: Vec<_> = forwarded
            .headers
            .iter()
            .filter(|(name, _)| name == "authorization")
            .collect();
        assert_eq!(authorizations.len(), 1);
        assert_eq!(authorizations[0].1, [b"Bearer ".as_slice(), TOKEN].concat());
        for forbidden in ["cookie", "forwarded", "proxy-authorization", "x-remove"] {
            assert!(!forwarded.headers.iter().any(|(name, _)| name == forbidden));
        }
        drop(requests);

        for location in ["https://evil.example/steal", "file:///etc/passwd"] {
            let redirecting = Arc::new(FakeUpstream::new(UpstreamResponse::new(
                301,
                vec![("Location".to_string(), location.as_bytes().to_vec())],
                Cursor::new(Vec::new()),
            )));
            let redirect_mode = ForwardMode {
                upstream_origin: validate_attach_url("https://daemon.example").unwrap(),
                upstream: redirecting,
                token: Arc::new(token()),
                active: Arc::new(AtomicBool::new(true)),
                clear_browser_state: Arc::new(AtomicBool::new(true)),
            };
            let request = ParsedRequest {
                method: "GET".to_string(),
                target: "/console".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            };
            let mut blocked = Vec::new();
            forward_request(&mut blocked, request, &redirect_mode, &AtomicBool::new(true)).unwrap();
            let blocked = String::from_utf8_lossy(&blocked);
            assert!(blocked.starts_with("HTTP/1.1 502"));
            assert!(!blocked.contains(location));
        }
    }

    #[test]
    fn proxy_injects_one_bearer_and_strips_browser_credentials() {
        let upstream = Arc::new(FakeUpstream::new(UpstreamResponse::new(
            200,
            vec![("Content-Type".to_string(), b"text/plain".to_vec())],
            Cursor::new(b"ok".to_vec()),
        )));
        let Some(server) = bind_server() else {
            return;
        };
        let control = server.control();
        control
            .set_forward("https://daemon.example", upstream.clone(), token())
            .unwrap();
        let mut handle = server.start().unwrap();
        let response = send(
            &handle.origin(),
            "Authorization: Bearer browser-secret\r\nCookie: cross=profile\r\nOrigin: ",
            "GET",
        );
        // The deliberately incomplete Origin is rejected before forwarding.
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403"));
        assert_eq!(upstream.calls.load(Ordering::Acquire), 0);

        let origin = handle.origin();
        let response = send(
            &origin,
            &format!("Origin: {origin}\r\nAuthorization: Bearer browser-secret\r\nCookie: cross=profile\r\n"),
            "GET",
        );
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
        let requests = upstream.requests.lock().unwrap();
        let request = requests.first().unwrap();
        let authorization: Vec<_> = request
            .headers
            .iter()
            .filter(|(name, _)| name == "authorization")
            .collect();
        assert_eq!(authorization.len(), 1);
        assert_eq!(authorization[0].1, [b"Bearer ".as_slice(), TOKEN].concat());
        assert!(!request.headers.iter().any(|(name, _)| name == "cookie"));
        handle.shutdown().unwrap();
    }

    #[test]
    fn hostile_headers_redirects_and_reflected_token_are_blocked_or_redacted() {
        let reflected = [b"prefix-".as_slice(), TOKEN, b"-suffix".as_slice()].concat();
        let upstream = Arc::new(FakeUpstream::new(UpstreamResponse::new(
            200,
            vec![
                ("Set-Cookie".to_string(), b"profile=A".to_vec()),
                ("Content-Type".to_string(), b"text/plain".to_vec()),
            ],
            Cursor::new(reflected),
        )));
        let Some(server) = bind_server() else {
            return;
        };
        let control = server.control();
        control
            .set_forward("https://daemon.example", upstream, token())
            .unwrap();
        let mut handle = server.start().unwrap();
        let origin = handle.origin();
        let response = send(&origin, &format!("Origin: {origin}\r\n"), "GET");
        assert!(!super::contains_bytes(&response, TOKEN));
        assert!(!String::from_utf8_lossy(&response)
            .to_ascii_lowercase()
            .contains("set-cookie"));
        assert!(String::from_utf8_lossy(&response).contains("[REDACTED]"));
        handle.shutdown().unwrap();

        for location in ["https://evil.example/steal", "file:///etc/passwd"] {
            let upstream = Arc::new(FakeUpstream::new(UpstreamResponse::new(
                301,
                vec![("Location".to_string(), location.as_bytes().to_vec())],
                Cursor::new(Vec::new()),
            )));
            let Some(server) = bind_server() else {
                return;
            };
            let control = server.control();
            control
                .set_forward("https://daemon.example", upstream, token())
                .unwrap();
            let mut handle = server.start().unwrap();
            let origin = handle.origin();
            let response = send(&origin, &format!("Origin: {origin}\r\n"), "GET");
            let rendered = String::from_utf8_lossy(&response);
            assert!(rendered.starts_with("HTTP/1.1 502"));
            assert!(!rendered.contains(location));
            handle.shutdown().unwrap();
        }
    }

    #[test]
    fn same_upstream_redirect_is_rewritten_to_proxy_relative_location() {
        let upstream = Arc::new(FakeUpstream::new(UpstreamResponse::new(
            302,
            vec![(
                "Location".to_string(),
                b"https://daemon.example/console?view=work".to_vec(),
            )],
            Cursor::new(Vec::new()),
        )));
        let Some(server) = bind_server() else {
            return;
        };
        let control = server.control();
        control
            .set_forward("https://daemon.example", upstream, token())
            .unwrap();
        let mut handle = server.start().unwrap();
        let origin = handle.origin();
        let response = send(&origin, &format!("Origin: {origin}\r\n"), "GET");
        let rendered = String::from_utf8_lossy(&response);
        assert!(rendered.starts_with("HTTP/1.1 302"));
        assert!(rendered.contains("location: /console?view=work\r\n"));
        assert!(!rendered.contains("daemon.example"));
        handle.shutdown().unwrap();
    }

    #[test]
    fn cross_profile_origin_and_unsafe_methods_never_reach_upstream() {
        let upstream = Arc::new(FakeUpstream::new(UpstreamResponse::new(
            200,
            Vec::new(),
            Cursor::new(Vec::new()),
        )));
        let Some(server) = bind_server() else {
            return;
        };
        let control = server.control();
        control
            .set_forward("https://daemon.example", upstream.clone(), token())
            .unwrap();
        let mut handle = server.start().unwrap();
        let response = send(
            &handle.origin(),
            "Origin: http://127.0.0.1:9\r\nSec-Fetch-Site: same-site\r\n",
            "POST",
        );
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403"));
        let trace = send(&handle.origin(), "", "TRACE");
        assert!(String::from_utf8_lossy(&trace).starts_with("HTTP/1.1 405"));
        assert_eq!(upstream.calls.load(Ordering::Acquire), 0);
        handle.shutdown().unwrap();
    }

    #[test]
    fn native_cross_port_document_navigation_is_narrowly_allowed() {
        let headers = vec![
            ("host".to_string(), b"127.0.0.1:49152".to_vec()),
            ("sec-fetch-site".to_string(), b"same-site".to_vec()),
            ("sec-fetch-mode".to_string(), b"navigate".to_vec()),
            ("sec-fetch-dest".to_string(), b"document".to_vec()),
            ("referer".to_string(), b"http://127.0.0.1:49151/console".to_vec()),
        ];
        assert!(validate_browser_origin(&headers, "http://127.0.0.1:49152", "127.0.0.1:49152", "GET").is_ok());
        assert!(validate_browser_origin(&headers, "http://127.0.0.1:49152", "127.0.0.1:49152", "POST").is_err());

        let mut subresource = headers;
        subresource.retain(|(name, _)| name != "sec-fetch-dest");
        subresource.push(("sec-fetch-dest".to_string(), b"script".to_vec()));
        assert!(validate_browser_origin(&subresource, "http://127.0.0.1:49152", "127.0.0.1:49152", "GET").is_err());
    }
}
