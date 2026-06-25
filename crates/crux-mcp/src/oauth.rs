// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! OAuth 2.0 resource-server metadata for the MCP endpoint.
//!
//! Makes this daemon's `/mcp` surface an OAuth 2.0 *protected resource* so
//! hosted MCP clients (claude.ai, ChatGPT) can discover the Authorization
//! Server that fronts it (the shared VaultCrux AS) and complete an
//! authorization-code + PKCE flow. Two pieces:
//!
//! - the RFC 9728 *Protected Resource Metadata* document, served at
//!   `/.well-known/oauth-protected-resource`; and
//! - the `WWW-Authenticate: Bearer resource_metadata="…"` challenge added to
//!   the `401` so a client knows where to look.
//!
//! Opt-in and per-daemon: active only when `CRUX_MCP_RESOURCE_URL` is set, so
//! daemons that don't front OAuth behave exactly as before. This is the
//! resource-server half; token *validation* (introspection) lands in a later
//! milestone. See ExecPlan `crux-mcp-oauth-for-hosted-clients-2026-06-23`
//! (M3, work item B).

use serde_json::{json, Value};

/// Default shared Authorization Server when `CRUX_MCP_AUTH_SERVER` is unset.
const DEFAULT_AUTH_SERVER: &str = "https://api.vaultcrux.com";

/// Per-daemon OAuth resource configuration, sourced from env.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceConfig {
    /// This daemon's public MCP resource URL, e.g. `https://crux.cuecrux.com/mcp`.
    pub resource_url: String,
    /// Authorization Server base URL(s) — the shared VaultCrux AS.
    pub authorization_servers: Vec<String>,
}

impl ResourceConfig {
    /// Build from env. Returns `None` when OAuth is not configured for this
    /// daemon (`CRUX_MCP_RESOURCE_URL` unset/empty) — preserving pre-OAuth
    /// behaviour for daemons that do not front a hosted-client flow.
    pub fn from_env() -> Option<Self> {
        let resource_url = std::env::var("CRUX_MCP_RESOURCE_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        let authorization_servers = std::env::var("CRUX_MCP_AUTH_SERVER")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map_or_else(|| vec![DEFAULT_AUTH_SERVER.to_string()], |s| vec![s]);
        Some(Self {
            resource_url,
            authorization_servers,
        })
    }

    /// RFC 9728 Protected Resource Metadata document.
    pub fn protected_resource_document(&self) -> Value {
        json!({
            "resource": self.resource_url,
            "authorization_servers": self.authorization_servers,
            "scopes_supported": ["mcp:read"],
            "bearer_methods_supported": ["header"],
        })
    }

    /// The `resource_metadata` URL advertised in the `WWW-Authenticate`
    /// challenge: the metadata doc lives at the resource origin's well-known
    /// path (RFC 9728 §3.1).
    pub fn resource_metadata_url(&self) -> String {
        match origin_of(&self.resource_url) {
            Some(origin) => format!("{origin}/.well-known/oauth-protected-resource"),
            None => format!(
                "{}/.well-known/oauth-protected-resource",
                self.resource_url.trim_end_matches('/')
            ),
        }
    }

    /// `WWW-Authenticate` challenge value for a `401` (RFC 9728 §5.3).
    pub fn www_authenticate_value(&self) -> String {
        format!("Bearer resource_metadata=\"{}\"", self.resource_metadata_url())
    }
}

/// Extract `scheme://host[:port]` from a URL without pulling in a URL crate.
/// The resource URL is operator-configured and well-formed; this only needs to
/// strip the path.
fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split('/').next().filter(|h| !h.is_empty())?;
    Some(format!("{scheme}://{host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ResourceConfig {
        ResourceConfig {
            resource_url: "https://crux.cuecrux.com/mcp".to_string(),
            authorization_servers: vec!["https://api.vaultcrux.com".to_string()],
        }
    }

    #[test]
    fn protected_resource_document_shape() {
        let doc = cfg().protected_resource_document();
        assert_eq!(doc["resource"], "https://crux.cuecrux.com/mcp");
        assert_eq!(doc["authorization_servers"][0], "https://api.vaultcrux.com");
        assert_eq!(doc["scopes_supported"][0], "mcp:read");
        assert_eq!(doc["bearer_methods_supported"][0], "header");
    }

    #[test]
    fn resource_metadata_url_is_origin_rooted() {
        assert_eq!(
            cfg().resource_metadata_url(),
            "https://crux.cuecrux.com/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn www_authenticate_points_at_resource_metadata() {
        assert_eq!(
            cfg().www_authenticate_value(),
            "Bearer resource_metadata=\"https://crux.cuecrux.com/.well-known/oauth-protected-resource\""
        );
    }

    #[test]
    fn origin_extraction() {
        assert_eq!(
            origin_of("https://h.example:8443/mcp/x"),
            Some("https://h.example:8443".to_string())
        );
        assert_eq!(origin_of("https://h.example"), Some("https://h.example".to_string()));
        assert_eq!(origin_of("not-a-url"), None);
    }
}
