// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Upstream allowlist — the structural block on cloud-proxy scope creep.
//!
//! Normative rule (M1, `Context-Mediation-Points.md` §3): the shim proxies
//! **local** model servers only. Allowed upstream hosts:
//!
//! - the literal hostname `localhost`,
//! - loopback IPs (`127.0.0.0/8`, `::1`),
//! - RFC1918 private IPs (`10/8`, `172.16/12`, `192.168/16`).
//!
//! Everything else — public IPs, ANY other hostname (no DNS resolution, so no
//! DNS-rebinding surface), non-http schemes — is refused at startup. `https`
//! is refused too: a local model server speaks plain http, and refusing TLS
//! upstreams removes the entire middlebox temptation by construction.

use std::net::{IpAddr, Ipv4Addr};

/// Validate a shim upstream base URL. Returns the normalized base (no
/// trailing slash) or an error explaining the refusal.
pub fn validate_upstream(url: &str) -> anyhow::Result<String> {
    let (host, _port, rest) = split_http_url(url)?;
    anyhow::ensure!(
        host_is_local(&host),
        "upstream host '{host}' is not local: the shim allowlist is localhost / loopback / \
         RFC1918 literal IPs ONLY (cloud proxying is structurally blocked; see \
         Context-Mediation-Points.md §3)"
    );
    anyhow::ensure!(
        rest.is_empty() || rest == "/",
        "upstream must be a base URL without a path (got trailing '{rest}')"
    );
    Ok(url.trim_end_matches('/').to_string())
}

/// Same host rules for the local context endpoint (the daemon).
/// A path is allowed here (`/v1/context`).
pub fn validate_local_url(url: &str) -> anyhow::Result<()> {
    let (host, _port, _rest) = split_http_url(url)?;
    anyhow::ensure!(host_is_local(&host), "host '{host}' is not local");
    Ok(())
}

/// Split `http://host[:port][/path]` into (host, port, path). Refuses
/// non-http schemes. IPv6 literals in brackets are supported.
fn split_http_url(url: &str) -> anyhow::Result<(String, Option<u16>, String)> {
    let Some(after) = url.strip_prefix("http://") else {
        anyhow::bail!(
            "upstream must be plain http:// (got '{url}'); https upstreams are refused — \
             a local model server speaks http, and TLS upstreams reopen the middlebox posture"
        );
    };
    let (authority, rest) = match after.find('/') {
        Some(i) => (&after[..i], &after[i..]),
        None => (after, ""),
    };
    anyhow::ensure!(!authority.is_empty(), "missing host in '{url}'");
    anyhow::ensure!(!authority.contains('@'), "userinfo in upstream URL is not supported");
    // IPv6 literal: [::1]:port
    if let Some(stripped) = authority.strip_prefix('[') {
        let Some(end) = stripped.find(']') else {
            anyhow::bail!("unterminated IPv6 literal in '{url}'");
        };
        let host = &stripped[..end];
        let port = match stripped[end + 1..].strip_prefix(':') {
            Some(p) => Some(
                p.parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("invalid port in '{url}'"))?,
            ),
            None => None,
        };
        return Ok((host.to_string(), port, rest.to_string()));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            Some(
                p.parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("invalid port in '{url}'"))?,
            ),
        ),
        None => (authority.to_string(), None),
    };
    Ok((host, port, rest.to_string()))
}

/// True iff `host` is `localhost`, a loopback IP, or an RFC1918 IP.
/// Hostnames other than `localhost` are NOT resolved — they are refused,
/// which removes the DNS-rebinding surface entirely.
fn host_is_local(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback() || ipv4_is_rfc1918(v4),
        Ok(IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => false,
    }
}

fn ipv4_is_rfc1918(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_localhost_loopback_and_rfc1918() {
        for url in [
            "http://localhost:11434",
            "http://127.0.0.1:11434",
            "http://127.5.4.3:8080",
            "http://[::1]:11434",
            "http://10.0.0.7:8000",
            "http://172.16.0.1:8000",
            "http://172.31.255.254:8000",
            "http://192.168.1.50:11434",
            "http://localhost:11434/",
        ] {
            assert!(validate_upstream(url).is_ok(), "should allow {url}");
        }
    }

    #[test]
    fn refuses_public_hosts_hostnames_and_schemes() {
        for url in [
            "http://api.openai.com",
            "http://example.com:80",
            "http://8.8.8.8:80",
            "http://172.32.0.1:80",      // just past RFC1918 172.16/12
            "http://172.15.0.1:80",      // just before
            "http://100.70.12.73:14800", // CGNAT/tailnet is NOT RFC1918
            "https://127.0.0.1:11434",   // TLS refused even on loopback
            "ftp://127.0.0.1",
            "http://user@127.0.0.1:80",
            "http://my-local-box:11434", // non-localhost hostname: no DNS, refused
        ] {
            assert!(validate_upstream(url).is_err(), "should refuse {url}");
        }
    }

    #[test]
    fn refuses_upstream_with_path() {
        assert!(validate_upstream("http://127.0.0.1:11434/v1").is_err());
        assert!(validate_upstream("http://127.0.0.1:11434/").is_ok());
    }

    #[test]
    fn normalizes_trailing_slash() {
        let base = validate_upstream("http://127.0.0.1:11434/").unwrap();
        assert_eq!(base, "http://127.0.0.1:11434");
    }

    #[test]
    fn local_url_allows_daemon_paths() {
        assert!(validate_local_url("http://127.0.0.1:14800/v1/context").is_ok());
        assert!(validate_local_url("http://example.com/v1/context").is_err());
    }
}
