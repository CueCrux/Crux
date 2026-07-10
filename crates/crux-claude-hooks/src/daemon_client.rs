// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Minimal synchronous HTTP client for the Crux daemon REST surface
//! (`http://127.0.0.1:14800` by default, override with `CRUX_HTTP_URL`).
//!
//! The audit-capture hooks (`observe-pre` open, `observe-post` close) write to
//! the `/v1/observe/*` routes, which have no MCP tool — Package S routed
//! capture over HTTP so the hook crate never needs a new MCP tool. Calls are
//! best-effort: a daemon-unreachable / non-2xx / disabled (`501`) response is
//! returned as an error the caller swallows, so the hook never blocks the tool
//! call.
//!
//! Auth contract mirrors [`crate::mcp_client`]: when `CRUX_AGENT_TOKEN` is set
//! and non-empty, every request carries `Authorization: Bearer <token>`; when
//! unset/empty no header is emitted (the pre-auth local-daemon path).

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::{DEFAULT_HTTP_URL, MCP_TIMEOUT_SECS};

/// Resolve the daemon HTTP base URL, honouring `CRUX_HTTP_URL`. The trailing
/// slash (if any) is trimmed so callers can append an absolute path.
pub fn http_base_url() -> String {
    let raw = std::env::var("CRUX_HTTP_URL").unwrap_or_else(|_| DEFAULT_HTTP_URL.to_string());
    raw.trim_end_matches('/').to_string()
}

/// Resolve the agent token from env. `None` (or empty) preserves the pre-auth
/// local-daemon path: no `Authorization` header is emitted.
pub fn agent_token() -> Option<String> {
    std::env::var("CRUX_AGENT_TOKEN").ok().filter(|s| !s.is_empty())
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(MCP_TIMEOUT_SECS)))
        .build()
        .into()
}

/// `POST <base><path>` with a JSON body. Returns the parsed response body on a
/// 2xx, an error otherwise. `path` is an absolute path beginning with `/`.
pub fn post_json<B: Serialize>(path: &str, body: &B) -> anyhow::Result<Value> {
    send_json("POST", path, body)
}

/// `PATCH <base><path>` with a JSON body. Returns the parsed response body on a
/// 2xx, an error otherwise.
pub fn patch_json<B: Serialize>(path: &str, body: &B) -> anyhow::Result<Value> {
    send_json("PATCH", path, body)
}

/// `GET <base><path>`. Returns the parsed response body on a 2xx, an error
/// otherwise. `path` is an absolute path beginning with `/`.
pub fn get_json(path: &str) -> anyhow::Result<Value> {
    let url = format!("{}{path}", http_base_url());
    let agent = agent();
    let mut request = agent.get(&url).header("Accept", "application/json");
    if let Some(t) = agent_token() {
        request = request.header("Authorization", &format!("Bearer {t}"));
    }
    let mut response = request.call()?;
    let parsed: Value = response.body_mut().read_json()?;
    Ok(parsed)
}

/// Lowest-level call used by [`post_json`] / [`patch_json`] and by tests that
/// point at a mock server via `CRUX_HTTP_URL`.
fn send_json<B: Serialize>(method: &str, path: &str, body: &B) -> anyhow::Result<Value> {
    let url = format!("{}{path}", http_base_url());
    let agent = agent();
    let mut request = match method {
        "POST" => agent.post(&url),
        "PATCH" => agent.patch(&url),
        other => anyhow::bail!("unsupported method {other}"),
    }
    .header("Content-Type", "application/json")
    .header("Accept", "application/json");
    if let Some(t) = agent_token() {
        request = request.header("Authorization", &format!("Bearer {t}"));
    }

    let mut response = request.send_json(body)?;
    let parsed: Value = response.body_mut().read_json()?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_base_url_defaults_and_trims_trailing_slash() {
        let _env = crate::test_support::env_guard();
        let prev = std::env::var("CRUX_HTTP_URL").ok();
        std::env::remove_var("CRUX_HTTP_URL");
        assert_eq!(http_base_url(), DEFAULT_HTTP_URL);

        std::env::set_var("CRUX_HTTP_URL", "http://example:14800/");
        assert_eq!(http_base_url(), "http://example:14800");

        match prev {
            Some(v) => std::env::set_var("CRUX_HTTP_URL", v),
            None => std::env::remove_var("CRUX_HTTP_URL"),
        }
    }

    #[test]
    fn agent_token_treats_empty_as_none() {
        let _env = crate::test_support::env_guard();
        let prev = std::env::var("CRUX_AGENT_TOKEN").ok();
        std::env::set_var("CRUX_AGENT_TOKEN", "");
        assert!(agent_token().is_none());
        std::env::set_var("CRUX_AGENT_TOKEN", "tok");
        assert_eq!(agent_token(), Some("tok".to_string()));
        match prev {
            Some(v) => std::env::set_var("CRUX_AGENT_TOKEN", v),
            None => std::env::remove_var("CRUX_AGENT_TOKEN"),
        }
    }

    #[test]
    fn post_fails_gracefully_when_daemon_unreachable() {
        let _env = crate::test_support::env_guard();
        let prev = std::env::var("CRUX_HTTP_URL").ok();
        std::env::set_var("CRUX_HTTP_URL", "http://127.0.0.1:1");
        let res = post_json("/v1/observe/sessions/s/steps", &serde_json::json!({"x": 1}));
        assert!(
            res.is_err(),
            "unreachable daemon must surface an error the caller swallows"
        );
        match prev {
            Some(v) => std::env::set_var("CRUX_HTTP_URL", v),
            None => std::env::remove_var("CRUX_HTTP_URL"),
        }
    }
}
