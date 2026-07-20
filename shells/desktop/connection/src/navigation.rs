// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::net::{IpAddr, Ipv6Addr};

/// A normalized HTTP(S) origin used by the native navigation allow-list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginKey {
    scheme: String,
    host: String,
    port: u16,
}

impl OriginKey {
    /// Parse the origin components of an absolute HTTP(S) URL.
    ///
    /// The desktop app passes canonical `tauri::Url::as_str()` values here.
    /// User information is rejected even when it would not affect the origin.
    pub fn parse(value: &str) -> Option<Self> {
        let parsed = ParsedHttpUrl::parse(value)?;
        Some(Self {
            scheme: parsed.scheme.to_string(),
            host: parsed.host.to_ascii_lowercase(),
            port: parsed.port,
        })
    }

    /// Return whether `value` has this exact scheme, host, and effective port.
    pub fn matches(&self, value: &str) -> bool {
        Self::parse(value).as_ref() == Some(self)
    }
}

/// The two native-owned origins that may remain inside the desktop webview.
#[derive(Debug, Default)]
pub struct OriginPolicy {
    pub active_proxy: Option<OriginKey>,
    pub bundled_sidecar: Option<OriginKey>,
}

impl OriginPolicy {
    /// Return whether `value` belongs to either currently allowed origin.
    pub fn allows(&self, value: &str) -> bool {
        self.active_proxy.as_ref().is_some_and(|origin| origin.matches(value))
            || self
                .bundled_sidecar
                .as_ref()
                .is_some_and(|origin| origin.matches(value))
    }
}

/// Pure navigation decision used after the app reads its shared origin policy.
pub fn origin_is_allowed(policy: &OriginPolicy, value: &str) -> bool {
    policy.allows(value)
}

/// Return whether a URL may enter the native external-browser approval queue.
pub fn is_public_http_link(value: &str) -> bool {
    let Some(parsed) = ParsedHttpUrl::parse(value) else {
        return false;
    };
    !parsed.host.eq_ignore_ascii_case("localhost")
        && parsed
            .host
            .parse::<IpAddr>()
            .ok()
            .is_none_or(|address| !address.is_loopback())
}

/// Reserve the generation after `current` without wrapping to an older value.
pub const fn next_generation(current: u64) -> u64 {
    current.saturating_add(1)
}

/// Return whether work captured for `candidate` still belongs to the active generation.
pub const fn generation_is_current(active: u64, candidate: u64) -> bool {
    active == candidate
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedHttpUrl<'a> {
    scheme: &'static str,
    host: &'a str,
    port: u16,
}

impl<'a> ParsedHttpUrl<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        if value.is_empty() || value.contains('\\') || value.chars().any(char::is_control) {
            return None;
        }
        let (raw_scheme, remainder) = value.split_once("://")?;
        let (scheme, default_port) = if raw_scheme.eq_ignore_ascii_case("http") {
            ("http", 80)
        } else if raw_scheme.eq_ignore_ascii_case("https") {
            ("https", 443)
        } else {
            return None;
        };
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        if authority.is_empty() || authority.contains('@') {
            return None;
        }
        let (host, port) = parse_authority(authority, default_port)?;
        Some(Self { scheme, host, port })
    }
}

fn parse_authority(authority: &str, default_port: u16) -> Option<(&str, u16)> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let closing = bracketed.find(']')?;
        let host = &bracketed[..closing];
        host.parse::<Ipv6Addr>().ok()?;
        let suffix = &bracketed[closing + 1..];
        let port = if suffix.is_empty() {
            default_port
        } else {
            parse_port(suffix.strip_prefix(':')?)?
        };
        Some((host, port))
    } else {
        if authority.contains(['[', ']']) || authority.matches(':').count() > 1 {
            return None;
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, raw_port)) => (host, parse_port(raw_port)?),
            None => (authority, default_port),
        };
        if host.is_empty()
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return None;
        }
        Some((host, port))
    }
}

fn parse_port(raw: &str) -> Option<u16> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::{
        generation_is_current, is_public_http_link, next_generation, origin_is_allowed, OriginKey, OriginPolicy,
    };

    fn policy() -> OriginPolicy {
        OriginPolicy {
            active_proxy: OriginKey::parse("http://127.0.0.1:43123"),
            bundled_sidecar: OriginKey::parse("http://127.0.0.1:14800"),
        }
    }

    #[test]
    fn allows_active_proxy_and_bundled_sidecar_origins() {
        let policy = policy();
        assert!(origin_is_allowed(&policy, "http://127.0.0.1:43123/console?view=work"));
        assert!(origin_is_allowed(&policy, "http://127.0.0.1:14800/console#/passport"));
    }

    #[test]
    fn denies_origin_lookalikes_and_component_mismatches() {
        let policy = policy();
        for value in [
            "http://127.0.0.1.evil.invalid:43123/console",
            "http://127.0.0.1:43124/console",
            "https://127.0.0.1:43123/console",
            "http://user@127.0.0.1:43123/console",
            "http://127.0.0.2:43123/console",
            "file:///console/index.html",
        ] {
            assert!(!origin_is_allowed(&policy, value), "allowed {value}");
        }
    }

    #[test]
    fn compares_effective_ports_and_host_case() {
        let policy = OriginPolicy {
            active_proxy: OriginKey::parse("https://Crux.Example"),
            bundled_sidecar: None,
        };
        assert!(policy.allows("https://crux.example:443/console"));
        assert!(!policy.allows("https://crux.example:444/console"));
        assert!(!policy.allows("http://crux.example:443/console"));
    }

    #[test]
    fn accepts_only_public_http_and_https_links() {
        for value in [
            "http://example.com/path?view=work#today",
            "https://203.0.113.7:8443/console",
            "https://localhost.evil.invalid/",
            "https://[2001:db8::1]/",
        ] {
            assert!(is_public_http_link(value), "rejected {value}");
        }
    }

    #[test]
    fn rejects_loopback_credentials_and_non_http_links() {
        for value in [
            "http://localhost/",
            "https://LOCALHOST:443/",
            "http://127.0.0.1/",
            "https://127.32.4.9/",
            "http://[::1]/",
            "https://user@example.com/",
            "https://:secret@example.com/",
            "file:///tmp/plan.md",
            "mailto:operator@example.com",
            "data:text/plain,hello",
            "ftp://example.com/plan.md",
            "not a URL",
            "https:///missing-host",
        ] {
            assert!(!is_public_http_link(value), "accepted {value}");
        }
    }

    #[test]
    fn accepts_current_generation_and_rejects_stale_generation() {
        assert!(generation_is_current(7, 7));
        assert!(!generation_is_current(8, 7));
        assert!(!generation_is_current(7, 8));
    }

    #[test]
    fn generation_advance_saturates_without_wrapping() {
        assert_eq!(next_generation(41), 42);
        assert_eq!(next_generation(u64::MAX), u64::MAX);
    }
}
