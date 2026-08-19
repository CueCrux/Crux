// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Pluggable text-completion providers for daemon-side enrichment.
//!
//! Enrichment is **opt-in and additive**. Every caller must work with
//! [`ProviderMode::None`] — which is the default — so the local-first,
//! free-forever path never depends on a model being configured, reachable, or
//! paid for. A provider error degrades the caller to its deterministic output;
//! it must never fail the caller outright.
//!
//! ## Two adapters, not one shim
//!
//! Anthropic and OpenAI are **different wire protocols** and each gets its own
//! adapter. Routing Claude through an OpenAI-compatible shim is explicitly
//! wrong:
//!
//! | | Anthropic | OpenAI-compatible |
//! |---|---|---|
//! | path | `/v1/messages` | `/chat/completions` |
//! | auth | `x-api-key` | `Authorization: Bearer` |
//! | version pin | `anthropic-version: 2023-06-01` | — |
//! | `max_tokens` | **required** | optional |
//! | system prompt | top-level `system` field | a `system` role message |
//! | reply text | `content[] where type == "text"` | `choices[0].message.content` |
//!
//! [`ProviderMode::Local`] reuses the OpenAI-compatible adapter because Ollama,
//! llama.cpp and vLLM all serve that shape natively — so three user-visible
//! options cost two adapters. This mirrors `crux-llm-shim`, which already
//! proxies OpenAI-compatible `chat/completions` and already defaults its
//! upstream to a local Ollama.
//!
//! ## Testability
//!
//! Building the request ([`build_wire_request`]) is separated from sending it,
//! so the wire shape — including "mode `None` produces no request at all" — is
//! asserted offline, with no network and no credentials.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Anthropic's dated API version pin. Required on every Messages API call.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Default Anthropic model.
pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-5";

pub const DEFAULT_ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";
pub const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com/v1";
/// Ollama's default OpenAI-compatible endpoint.
pub const DEFAULT_LOCAL_BASE_URL: &str = "http://localhost:11434/v1";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, thiserror::Error)]
pub enum CompletionError {
    /// The caller asked for a completion while enrichment is off. Callers treat
    /// this as "skip enrichment", never as a failure.
    #[error("completion provider is disabled")]
    Disabled,
    #[error("provider credential missing: {0}")]
    MissingCredential(&'static str),
    #[error("network error: {0}")]
    Network(String),
    #[error("provider returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("malformed provider response: {0}")]
    Malformed(String),
}

/// Which backend to use. `None` is the default everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    /// No model call. Deterministic output only — zero egress, zero credentials.
    #[default]
    None,
    Anthropic,
    OpenAi,
    /// OpenAI-compatible server on the local machine (Ollama, llama.cpp, vLLM).
    /// Same adapter as [`ProviderMode::OpenAi`]; different default base URL and
    /// no credential requirement.
    Local,
}

impl ProviderMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "none" | "off" | "disabled" | "" => Some(Self::None),
            "anthropic" | "claude" => Some(Self::Anthropic),
            "openai" => Some(Self::OpenAi),
            "local" | "ollama" | "llamacpp" | "vllm" => Some(Self::Local),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
            Self::Local => "local",
        }
    }

    /// True when this mode sends bytes off the machine. `None` sends nothing;
    /// `Local` talks to localhost. Used to keep the free-forever guarantee
    /// checkable rather than merely documented.
    pub fn egresses(self) -> bool {
        matches!(self, Self::Anthropic | Self::OpenAi)
    }

    /// Whether an API key is mandatory. A local server usually needs none.
    pub fn requires_credential(self) -> bool {
        self.egresses()
    }

    fn default_base_url(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Anthropic => DEFAULT_ANTHROPIC_BASE_URL,
            Self::OpenAi => DEFAULT_OPENAI_BASE_URL,
            Self::Local => DEFAULT_LOCAL_BASE_URL,
        }
    }
}

/// A normalized completion request. Mirrors the `BackendRequest` contract the
/// Crucible harness (`control/clawd/adapters/base.py`) already uses, so the two
/// stay conceptually aligned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionRequest {
    pub system: Option<String>,
    pub prompt: String,
    pub model: String,
    pub max_tokens: u32,
}

/// A normalized completion response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompletionResponse {
    pub text: String,
    pub stop_reason: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

/// Provider configuration, resolved from env by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    pub mode: ProviderMode,
    /// Overrides the mode's default base URL when non-empty.
    pub base_url: Option<String>,
    /// Overrides the mode's default model when non-empty.
    pub model: Option<String>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            mode: ProviderMode::None,
            base_url: None,
            model: None,
        }
    }
}

impl ProviderConfig {
    pub fn base_url(&self) -> &str {
        self.base_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| self.mode.default_base_url())
    }

    /// Resolved model. Only Anthropic carries a built-in default — for OpenAI
    /// and local servers the available model names are deployment-specific, so
    /// an unset model is a configuration error the caller surfaces rather than
    /// a default we invent.
    pub fn model(&self) -> Option<&str> {
        self.model
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or(match self.mode {
                ProviderMode::Anthropic => Some(DEFAULT_ANTHROPIC_MODEL),
                _ => None,
            })
    }
}

/// A fully-built HTTP request, before sending. Pure data so the wire shape can
/// be asserted without a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: serde_json::Value,
}

impl WireRequest {
    /// Case-insensitive header lookup, for assertions and debugging.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Build the provider-specific HTTP request.
///
/// Returns `Ok(None)` for [`ProviderMode::None`] — the caller then skips
/// enrichment without any network activity. This is the free-forever path and
/// the reason the function returns an `Option` rather than always a request.
pub fn build_wire_request(
    config: &ProviderConfig,
    req: &CompletionRequest,
    api_key: Option<&str>,
) -> Result<Option<WireRequest>, CompletionError> {
    if config.mode == ProviderMode::None {
        return Ok(None);
    }
    let key = api_key.map(str::trim).filter(|s| !s.is_empty());
    if config.mode.requires_credential() && key.is_none() {
        return Err(CompletionError::MissingCredential(match config.mode {
            ProviderMode::Anthropic => "anthropic",
            _ => "openai",
        }));
    }
    let base = config.base_url().trim_end_matches('/').to_string();

    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("user-agent".to_string(), "crux-daemon".to_string()),
    ];

    let (url, body) = match config.mode {
        ProviderMode::None => unreachable!("returned above"),
        ProviderMode::Anthropic => {
            // Messages API: x-api-key (NOT Bearer), a dated version pin, and a
            // mandatory max_tokens. The system prompt is a top-level field, not
            // a message role.
            headers.push(("x-api-key".to_string(), key.unwrap_or_default().to_string()));
            headers.push(("anthropic-version".to_string(), ANTHROPIC_VERSION.to_string()));
            let mut body = serde_json::json!({
                "model": req.model,
                "max_tokens": req.max_tokens,
                "messages": [{ "role": "user", "content": req.prompt }],
            });
            if let Some(system) = req.system.as_deref().filter(|s| !s.trim().is_empty()) {
                body["system"] = serde_json::Value::String(system.to_string());
            }
            (format!("{base}/v1/messages"), body)
        }
        ProviderMode::OpenAi | ProviderMode::Local => {
            // Chat Completions. A local server usually wants no credential at
            // all, so the Authorization header is only attached when one exists.
            if let Some(key) = key {
                headers.push(("authorization".to_string(), format!("Bearer {key}")));
            }
            let mut messages = Vec::new();
            if let Some(system) = req.system.as_deref().filter(|s| !s.trim().is_empty()) {
                messages.push(serde_json::json!({ "role": "system", "content": system }));
            }
            messages.push(serde_json::json!({ "role": "user", "content": req.prompt }));
            let body = serde_json::json!({
                "model": req.model,
                "max_tokens": req.max_tokens,
                "messages": messages,
            });
            (format!("{base}/chat/completions"), body)
        }
    };

    Ok(Some(WireRequest { url, headers, body }))
}

/// Parse a provider response body into the normalized shape.
pub fn parse_wire_response(
    mode: ProviderMode,
    body: &serde_json::Value,
) -> Result<CompletionResponse, CompletionError> {
    match mode {
        ProviderMode::None => Err(CompletionError::Disabled),
        ProviderMode::Anthropic => {
            // content is an ARRAY of blocks; concatenate every text block. A
            // response whose only block is a tool_use or thinking block yields
            // empty text, which is valid, not malformed.
            let blocks = body
                .get("content")
                .and_then(|v| v.as_array())
                .ok_or_else(|| CompletionError::Malformed("anthropic response has no `content` array".to_string()))?;
            let text = blocks
                .iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("");
            Ok(CompletionResponse {
                text,
                stop_reason: body.get("stop_reason").and_then(|v| v.as_str()).map(str::to_string),
                input_tokens: body.pointer("/usage/input_tokens").and_then(serde_json::Value::as_u64),
                output_tokens: body.pointer("/usage/output_tokens").and_then(serde_json::Value::as_u64),
            })
        }
        ProviderMode::OpenAi | ProviderMode::Local => {
            let text = body
                .pointer("/choices/0/message/content")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    CompletionError::Malformed("openai response has no `choices[0].message.content`".to_string())
                })?
                .to_string();
            Ok(CompletionResponse {
                text,
                stop_reason: body
                    .pointer("/choices/0/finish_reason")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                input_tokens: body.pointer("/usage/prompt_tokens").and_then(serde_json::Value::as_u64),
                output_tokens: body
                    .pointer("/usage/completion_tokens")
                    .and_then(serde_json::Value::as_u64),
            })
        }
    }
}

/// Execute a completion. Returns [`CompletionError::Disabled`] without touching
/// the network when the mode is `None`.
pub fn complete(
    config: &ProviderConfig,
    req: &CompletionRequest,
    api_key: Option<&str>,
) -> Result<CompletionResponse, CompletionError> {
    let Some(wire) = build_wire_request(config, req, api_key)? else {
        return Err(CompletionError::Disabled);
    };
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .build()
        .into();
    let mut http = agent.post(&wire.url);
    for (name, value) in &wire.headers {
        http = http.header(name, value);
    }
    let mut response = http
        .send_json(&wire.body)
        .map_err(|e| CompletionError::Network(e.to_string()))?;
    let status = response.status().as_u16();
    let text = response
        .body_mut()
        .read_to_string()
        .map_err(|e| CompletionError::Network(e.to_string()))?;
    if !(200..300).contains(&status) {
        return Err(CompletionError::Status {
            status,
            body: truncate(&text, 256),
        });
    }
    let parsed: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| CompletionError::Malformed(e.to_string()))?;
    parse_wire_response(config.mode, &parsed)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn req() -> CompletionRequest {
        CompletionRequest {
            system: Some("be terse".to_string()),
            prompt: "summarize the board".to_string(),
            model: "m".to_string(),
            max_tokens: 1024,
        }
    }

    fn cfg(mode: ProviderMode) -> ProviderConfig {
        ProviderConfig {
            mode,
            base_url: None,
            model: None,
        }
    }

    /// THE free-forever guarantee, asserted rather than documented: the default
    /// mode builds no request at all, so there is nothing that could egress.
    #[test]
    fn default_mode_is_none_and_builds_no_request() {
        assert_eq!(ProviderConfig::default().mode, ProviderMode::None);
        assert_eq!(ProviderMode::default(), ProviderMode::None);
        let wire = build_wire_request(&cfg(ProviderMode::None), &req(), None).expect("none mode is not an error");
        assert!(wire.is_none(), "mode None must produce no request");
    }

    #[test]
    fn none_mode_ignores_a_supplied_credential() {
        let wire = build_wire_request(&cfg(ProviderMode::None), &req(), Some("sk-live-key")).expect("still fine");
        assert!(wire.is_none(), "a stray credential must not switch enrichment on");
    }

    #[test]
    fn only_hosted_modes_egress() {
        assert!(!ProviderMode::None.egresses());
        assert!(!ProviderMode::Local.egresses(), "local talks to localhost only");
        assert!(ProviderMode::Anthropic.egresses());
        assert!(ProviderMode::OpenAi.egresses());
    }

    /// Anthropic must NOT be routed through the OpenAI shape.
    #[test]
    fn anthropic_uses_messages_api_with_x_api_key() {
        let wire = build_wire_request(&cfg(ProviderMode::Anthropic), &req(), Some("sk-ant"))
            .expect("builds")
            .expect("some request");

        assert_eq!(wire.url, "https://api.anthropic.com/v1/messages");
        assert_eq!(wire.header("x-api-key"), Some("sk-ant"));
        assert_eq!(wire.header("anthropic-version"), Some(ANTHROPIC_VERSION));
        assert!(
            wire.header("authorization").is_none(),
            "Anthropic authenticates with x-api-key, never a Bearer token"
        );
        // max_tokens is mandatory on the Messages API.
        assert_eq!(wire.body["max_tokens"], json!(1024));
        // system is a TOP-LEVEL field, not a message role.
        assert_eq!(wire.body["system"], json!("be terse"));
        assert_eq!(
            wire.body["messages"],
            json!([{"role": "user", "content": "summarize the board"}])
        );
    }

    #[test]
    fn openai_uses_chat_completions_with_bearer() {
        let wire = build_wire_request(&cfg(ProviderMode::OpenAi), &req(), Some("sk-oai"))
            .expect("builds")
            .expect("some request");

        assert_eq!(wire.url, "https://api.openai.com/v1/chat/completions");
        assert_eq!(wire.header("authorization"), Some("Bearer sk-oai"));
        assert!(
            wire.header("x-api-key").is_none(),
            "OpenAI authenticates with a Bearer token, never x-api-key"
        );
        assert!(wire.body.get("system").is_none(), "system is a message role here");
        assert_eq!(wire.body["messages"][0]["role"], json!("system"));
        assert_eq!(wire.body["messages"][1]["role"], json!("user"));
    }

    #[test]
    fn local_needs_no_credential_and_targets_localhost() {
        let wire = build_wire_request(&cfg(ProviderMode::Local), &req(), None)
            .expect("local must not require a key")
            .expect("some request");
        assert_eq!(wire.url, "http://localhost:11434/v1/chat/completions");
        assert!(wire.header("authorization").is_none());
    }

    #[test]
    fn hosted_modes_require_a_credential() {
        for mode in [ProviderMode::Anthropic, ProviderMode::OpenAi] {
            let err = build_wire_request(&cfg(mode), &req(), None).expect_err("must refuse without a key");
            assert!(matches!(err, CompletionError::MissingCredential(_)), "{mode:?}");
        }
    }

    #[test]
    fn base_url_override_wins_and_trailing_slash_is_normalised() {
        let config = ProviderConfig {
            mode: ProviderMode::Local,
            base_url: Some("http://127.0.0.1:8000/v1/".to_string()),
            model: None,
        };
        let wire = build_wire_request(&config, &req(), None)
            .expect("builds")
            .expect("some");
        assert_eq!(wire.url, "http://127.0.0.1:8000/v1/chat/completions");
    }

    #[test]
    fn anthropic_has_a_default_model_and_others_do_not() {
        assert_eq!(cfg(ProviderMode::Anthropic).model(), Some(DEFAULT_ANTHROPIC_MODEL));
        assert_eq!(cfg(ProviderMode::OpenAi).model(), None, "deployment-specific");
        assert_eq!(cfg(ProviderMode::Local).model(), None, "deployment-specific");
        let overridden = ProviderConfig {
            mode: ProviderMode::Anthropic,
            base_url: None,
            model: Some("claude-sonnet-5".to_string()),
        };
        assert_eq!(overridden.model(), Some("claude-sonnet-5"));
    }

    #[test]
    fn mode_parses_and_round_trips() {
        for (input, want) in [
            ("none", ProviderMode::None),
            ("", ProviderMode::None),
            ("claude", ProviderMode::Anthropic),
            ("Anthropic", ProviderMode::Anthropic),
            ("openai", ProviderMode::OpenAi),
            ("ollama", ProviderMode::Local),
            ("vllm", ProviderMode::Local),
        ] {
            assert_eq!(ProviderMode::parse(input), Some(want), "input {input:?}");
        }
        assert_eq!(ProviderMode::parse("gemini"), None);
        for mode in [
            ProviderMode::None,
            ProviderMode::Anthropic,
            ProviderMode::OpenAi,
            ProviderMode::Local,
        ] {
            assert_eq!(ProviderMode::parse(mode.as_str()), Some(mode));
        }
    }

    /// Anthropic text lives in a content ARRAY; concatenate every text block
    /// and ignore non-text blocks.
    #[test]
    fn parses_anthropic_content_blocks() {
        let body = json!({
            "content": [
                {"type": "thinking", "thinking": "ignored"},
                {"type": "text", "text": "hello "},
                {"type": "text", "text": "world"}
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 12, "output_tokens": 3}
        });
        let r = parse_wire_response(ProviderMode::Anthropic, &body).expect("parses");
        assert_eq!(r.text, "hello world");
        assert_eq!(r.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(r.input_tokens, Some(12));
        assert_eq!(r.output_tokens, Some(3));
    }

    #[test]
    fn parses_openai_choice() {
        let body = json!({
            "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 1}
        });
        let r = parse_wire_response(ProviderMode::OpenAi, &body).expect("parses");
        assert_eq!(r.text, "hi");
        assert_eq!(r.stop_reason.as_deref(), Some("stop"));
        assert_eq!(r.input_tokens, Some(5));
    }

    /// Cross-shape parsing must fail loudly — an OpenAI body parsed as
    /// Anthropic (or vice versa) is exactly what a one-shim design would do.
    #[test]
    fn cross_shape_parsing_is_rejected() {
        let openai = json!({"choices": [{"message": {"content": "hi"}}]});
        let anthropic = json!({"content": [{"type": "text", "text": "hi"}]});
        assert!(matches!(
            parse_wire_response(ProviderMode::Anthropic, &openai),
            Err(CompletionError::Malformed(_))
        ));
        assert!(matches!(
            parse_wire_response(ProviderMode::OpenAi, &anthropic),
            Err(CompletionError::Malformed(_))
        ));
    }

    /// `complete()` on the default mode must return Disabled without a network
    /// call — the caller treats that as "skip enrichment", not as a failure.
    #[test]
    fn complete_is_disabled_without_network_in_none_mode() {
        let err = complete(&cfg(ProviderMode::None), &req(), None).expect_err("disabled");
        assert!(matches!(err, CompletionError::Disabled));
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("abc", 10), "abc");
        // Multi-byte: must not split the character.
        let s = "aé".repeat(50);
        let t = truncate(&s, 5);
        // The ellipsis is itself 3 bytes in UTF-8, so the cap applies to the
        // retained prefix, not to the returned string.
        let kept = t.trim_end_matches('…');
        assert!(kept.len() <= 5, "prefix within the cap: {kept:?}");
        assert!(s.is_char_boundary(kept.len()), "never split a character");
        assert!(t.ends_with('…'));
    }
}
