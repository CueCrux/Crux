// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Blocking `ureq` adapter for the native credential-injecting proxy.
//!
//! Connection policy validates profile URLs before requests reach this layer.
//! This adapter still accepts only absolute HTTP(S) URLs, never follows
//! redirects, never consults environment proxy settings, and uses ureq's
//! default Rustls WebPKI certificate and hostname verification. Probe requests
//! have a short hard deadline; forwarded requests have a longer hard deadline
//! so a hostile quiet stream cannot retain an old profile token indefinitely.
//! EventSource reconnects normally when that deadline closes a stream.

use std::str::FromStr;
use std::time::Duration;

use crux_shell_connection::{validate_attach_url, ForwardRequest, Upstream, UpstreamError, UpstreamResponse};
use ureq::http::{HeaderName, HeaderValue, Method, Uri};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_HEAD_TIMEOUT: Duration = Duration::from_secs(15);
const PROBE_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const FORWARD_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Production upstream transport for attach profiles.
#[derive(Clone)]
pub(crate) struct UreqUpstream {
    agent: ureq::Agent,
    origin: String,
}

impl UreqUpstream {
    pub(crate) fn for_probe(origin: &str) -> Result<Self, UpstreamError> {
        Self::with_deadline(origin, PROBE_REQUEST_TIMEOUT)
    }

    pub(crate) fn for_proxy(origin: &str) -> Result<Self, UpstreamError> {
        Self::with_deadline(origin, FORWARD_REQUEST_TIMEOUT)
    }

    fn with_deadline(origin: &str, request_deadline: Duration) -> Result<Self, UpstreamError> {
        let origin = validate_attach_url(origin)
            .map_err(|_| UpstreamError::sanitized("upstream URL is invalid"))?
            .as_str()
            .to_string();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .timeout_resolve(Some(CONNECT_TIMEOUT))
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_send_request(Some(REQUEST_HEAD_TIMEOUT))
            .timeout_send_body(Some(REQUEST_BODY_TIMEOUT))
            .timeout_recv_response(Some(RESPONSE_HEAD_TIMEOUT))
            .timeout_recv_body(Some(request_deadline))
            .timeout_global(Some(request_deadline))
            .user_agent("")
            .accept("")
            .accept_encoding("identity")
            // `TlsConfig::default` keeps SNI, certificate-chain validation,
            // and hostname validation enabled with Rustls/WebPKI. There is no
            // insecure or custom-verifier path in this adapter.
            .tls_config(ureq::tls::TlsConfig::default())
            .build()
            .into();
        Ok(Self { agent, origin })
    }
}

impl Upstream for UreqUpstream {
    fn execute(&self, request: ForwardRequest) -> Result<UpstreamResponse, UpstreamError> {
        let ForwardRequest {
            method,
            url,
            headers,
            body,
        } = request;
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| UpstreamError::sanitized("upstream request method is invalid"))?;
        let uri = validated_uri(&self.origin, &url)?;

        let mut builder = ureq::http::Request::builder().method(method).uri(uri);
        for (name, value) in &headers {
            if request_header_is_blocked(name, &headers) {
                continue;
            }
            let name = HeaderName::from_str(name)
                .map_err(|_| UpstreamError::sanitized("upstream request headers are invalid"))?;
            let value = HeaderValue::from_bytes(value)
                .map_err(|_| UpstreamError::sanitized("upstream request headers are invalid"))?;
            builder = builder.header(name, value);
        }
        // Keep the bytes seen by the connection crate identical to the
        // upstream representation. The manifest must disable ureq's gzip
        // feature (`default-features = false`, `features = ["rustls"]`).
        builder = builder.header("accept-encoding", "identity");

        let upstream_request = builder
            .body(body.as_slice())
            .map_err(|_| UpstreamError::sanitized("upstream request could not be constructed"))?;
        let response = self
            .agent
            .run(upstream_request)
            .map_err(|_| UpstreamError::sanitized("upstream request failed"))?;
        let (parts, response_body) = response.into_parts();
        let response_headers = parts
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
            .collect();

        Ok(UpstreamResponse {
            status: parts.status.as_u16(),
            headers: response_headers,
            body: Box::new(response_body.into_reader()),
        })
    }
}

fn validated_uri(origin: &str, url: &str) -> Result<Uri, UpstreamError> {
    if !url.starts_with('/')
        || url.starts_with("//")
        || url.contains('\\')
        || url.contains('#')
        || url.chars().any(char::is_control)
    {
        return Err(UpstreamError::sanitized("upstream URL is invalid"));
    }
    let absolute = format!("{origin}{url}");
    let uri = Uri::from_str(&absolute).map_err(|_| UpstreamError::sanitized("upstream URL is invalid"))?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.authority().is_none()
        || uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(UpstreamError::sanitized("upstream URL is invalid"));
    }
    Ok(uri)
}

fn request_header_is_blocked(name: &str, headers: &[(String, Vec<u8>)]) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "host"
            | "content-length"
            | "accept-encoding"
            | "cookie"
            | "connection"
            | "transfer-encoding"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "forwarded"
            | "upgrade"
            | "te"
            | "trailer"
    ) || lower.starts_with("x-forwarded-")
        || connection_nominates(&lower, headers)
}

fn connection_nominates(name: &str, headers: &[(String, Vec<u8>)]) -> bool {
    headers
        .iter()
        .filter(|(header_name, _)| header_name.eq_ignore_ascii_case("connection"))
        .filter_map(|(_, value)| std::str::from_utf8(value).ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(name))
}
