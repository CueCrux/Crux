// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::net::IpAddr;

use crate::ConnectionError;

/// A validated, origin-only attach URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAttachUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    normalized_base: String,
}

impl ValidatedAttachUrl {
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// Normalized origin without a trailing slash.
    pub fn as_str(&self) -> &str {
        &self.normalized_base
    }

    pub(crate) fn effective_port(&self) -> u16 {
        self.port.unwrap_or(if self.scheme == "https" { 443 } else { 80 })
    }
}

/// Validate the desktop attach transport contract.
///
/// Plain HTTP is accepted only for exact `localhost` or a literal IP for which
/// [`IpAddr::is_loopback`] is true. Exact `localhost` is normalized to
/// `127.0.0.1`, avoiding ambient DNS or hosts-file behavior. Non-loopback
/// origins require HTTPS and remain subject to the native client's normal
/// certificate validation.
pub fn validate_attach_url(input: &str) -> Result<ValidatedAttachUrl, ConnectionError> {
    if input.is_empty() || input.len() > 2_048 || input.chars().any(char::is_control) || input.contains('\\') {
        return Err(ConnectionError::new(
            "attach URL is empty or contains invalid characters",
        ));
    }
    if input.contains('?') || input.contains('#') {
        return Err(ConnectionError::new("attach URL must not contain a query or fragment"));
    }
    let (raw_scheme, remainder) = input
        .split_once("://")
        .ok_or_else(|| ConnectionError::new("attach URL must be an absolute HTTP or HTTPS URL"))?;
    let scheme = raw_scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(ConnectionError::new("attach URL scheme must be http or https"));
    }

    let (authority, path) = match remainder.find('/') {
        Some(index) => (&remainder[..index], &remainder[index..]),
        None => (remainder, ""),
    };
    if !path.is_empty() && path != "/" {
        return Err(ConnectionError::new("attach URL must not contain a base path"));
    }
    if authority.is_empty() || authority.contains('@') {
        return Err(ConnectionError::new(
            "attach URL must contain a host and no user information",
        ));
    }

    let (raw_host, port) = parse_authority(authority)?;
    let exact_localhost = raw_host.eq_ignore_ascii_case("localhost");
    let parsed_ip = raw_host.parse::<IpAddr>().ok();
    if !exact_localhost && parsed_ip.is_none() {
        validate_dns_name(raw_host)?;
    }
    let loopback = exact_localhost || parsed_ip.is_some_and(|address| address.is_loopback());
    if scheme == "http" && !loopback {
        return Err(ConnectionError::new(
            "plain HTTP attach URLs are allowed only for exact localhost or a loopback IP",
        ));
    }

    let host = if exact_localhost {
        "127.0.0.1".to_string()
    } else {
        raw_host.to_ascii_lowercase()
    };
    let rendered_host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let normalized_base = match port {
        Some(value) => format!("{scheme}://{rendered_host}:{value}"),
        None => format!("{scheme}://{rendered_host}"),
    };
    Ok(ValidatedAttachUrl {
        scheme,
        host,
        port,
        normalized_base,
    })
}

fn parse_authority(authority: &str) -> Result<(&str, Option<u16>), ConnectionError> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let closing = bracketed
            .find(']')
            .ok_or_else(|| ConnectionError::new("attach URL contains an invalid IPv6 host"))?;
        let host = &bracketed[..closing];
        host.parse::<IpAddr>()
            .map_err(|_| ConnectionError::new("attach URL contains an invalid IPv6 host"))?;
        let suffix = &bracketed[closing + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            let raw = suffix
                .strip_prefix(':')
                .ok_or_else(|| ConnectionError::new("attach URL authority is invalid"))?;
            Some(parse_port(raw)?)
        };
        Ok((host, port))
    } else {
        if authority.matches(':').count() > 1 {
            return Err(ConnectionError::new("IPv6 attach URL hosts must use brackets"));
        }
        match authority.rsplit_once(':') {
            Some((host, raw_port)) => {
                if host.is_empty() {
                    return Err(ConnectionError::new("attach URL host is empty"));
                }
                Ok((host, Some(parse_port(raw_port)?)))
            }
            None => Ok((authority, None)),
        }
    }
}

fn parse_port(raw: &str) -> Result<u16, ConnectionError> {
    let port = raw
        .parse::<u16>()
        .map_err(|_| ConnectionError::new("attach URL port is invalid"))?;
    if port == 0 {
        return Err(ConnectionError::new("attach URL port must not be zero"));
    }
    Ok(port)
}

fn validate_dns_name(host: &str) -> Result<(), ConnectionError> {
    if host.len() > 253 || host.ends_with('.') {
        return Err(ConnectionError::new("attach URL host is invalid"));
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ConnectionError::new("attach URL host is invalid"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_attach_url;

    #[test]
    fn accepts_loopback_http_and_normalizes_localhost() {
        let localhost = validate_attach_url("http://LOCALHOST:14800/").unwrap();
        assert_eq!(localhost.as_str(), "http://127.0.0.1:14800");
        assert_eq!(validate_attach_url("http://127.0.0.9:80").unwrap().host(), "127.0.0.9");
        assert_eq!(validate_attach_url("http://[::1]:14800").unwrap().host(), "::1");
    }

    #[test]
    fn rejects_remote_http_and_ambiguous_local_names() {
        for value in [
            "http://example.com",
            "http://192.168.1.5",
            "http://localhost.evil",
            "http://localhost.",
            "http://0.0.0.0",
        ] {
            assert!(validate_attach_url(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn accepts_remote_https_and_rejects_unsafe_url_components() {
        assert_eq!(
            validate_attach_url("https://Crux.Example:443/").unwrap().as_str(),
            "https://crux.example:443"
        );
        for value in [
            "file:///tmp/daemon",
            "https://user:secret@example.test",
            "https://example.test/base",
            "https://example.test/?token=x",
            "https://example.test/#x",
            "https://example_test",
        ] {
            assert!(validate_attach_url(value).is_err(), "accepted {value}");
        }
    }
}
