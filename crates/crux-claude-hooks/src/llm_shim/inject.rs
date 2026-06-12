// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Bundle injection into chat-shaped request bodies.
//!
//! Injection contract (M1 spec + G21a stability rule):
//!
//! - The bundle is inserted as a NEW first message
//!   `{"role": "system", "content": "<bundle markdown>"}` at index 0 —
//!   *before* any caller-supplied system message, never merged into it.
//!   A separate, byte-identical first message is what makes the injected
//!   region a stable prompt prefix (the provider prompt-cache lever).
//! - Every other field — model, params, tools, the caller's messages —
//!   passes through byte-equivalent at the JSON value level.
//! - Only `messages`-shaped bodies are eligible (OpenAI `/v1/chat/completions`
//!   and Ollama-native `/api/chat`). Anything else passes through untouched.

use serde_json::Value;

/// Paths whose POST bodies are eligible for injection. Matched on the path
/// only (query strings stripped by the caller).
pub fn path_is_injectable(path: &str) -> bool {
    path.ends_with("/chat/completions") || path == "/api/chat"
}

/// Outcome of an injection attempt.
pub struct Injection {
    /// Body to forward upstream (modified iff `injected`).
    pub body: Vec<u8>,
    /// Whether the bundle was inserted.
    pub injected: bool,
    /// `true` iff the request asked for a streamed response.
    pub stream: bool,
    /// `model` field when present (stamped on stream receipts).
    pub model: Option<String>,
}

/// Inject `bundle_markdown` into a chat request body. Falls back to verbatim
/// passthrough when the body is not a JSON object with a `messages` array —
/// the shim must never break a request it does not understand.
pub fn inject_bundle(body: &[u8], bundle_markdown: Option<&str>) -> Injection {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    let (stream, model) = match &parsed {
        Some(v) => (
            v.get("stream").and_then(Value::as_bool).unwrap_or(false),
            v.get("model").and_then(Value::as_str).map(str::to_string),
        ),
        None => (false, None),
    };
    let Some(markdown) = bundle_markdown else {
        return Injection {
            body: body.to_vec(),
            injected: false,
            stream,
            model,
        };
    };
    let Some(mut v) = parsed else {
        return Injection {
            body: body.to_vec(),
            injected: false,
            stream,
            model,
        };
    };
    let Some(messages) = v.get_mut("messages").and_then(Value::as_array_mut) else {
        return Injection {
            body: body.to_vec(),
            injected: false,
            stream,
            model,
        };
    };
    let system = serde_json::json!({ "role": "system", "content": markdown });
    messages.insert(0, system);
    match serde_json::to_vec(&v) {
        Ok(body) => Injection {
            body,
            injected: true,
            stream,
            model,
        },
        // Re-serialization cannot realistically fail for a Value tree, but the
        // fallback keeps the never-break-a-request invariant lint-clean.
        Err(_) => Injection {
            body: body.to_vec(),
            injected: false,
            stream,
            model,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLE: &str = "# Crux context bundle\nstable region first";

    #[test]
    fn injects_as_new_first_system_message() {
        let body = serde_json::json!({
            "model": "llama3.2",
            "temperature": 0.2,
            "stream": true,
            "tools": [{"type": "function", "function": {"name": "get_weather"}}],
            "messages": [
                {"role": "system", "content": "you are terse"},
                {"role": "user", "content": "hi"}
            ]
        });
        let out = inject_bundle(&serde_json::to_vec(&body).unwrap(), Some(BUNDLE));
        assert!(out.injected);
        assert!(out.stream);
        assert_eq!(out.model.as_deref(), Some("llama3.2"));
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        let messages = v["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], BUNDLE);
        // Caller's system message is preserved, not merged.
        assert_eq!(messages[1]["content"], "you are terse");
        assert_eq!(messages[2]["role"], "user");
        // Everything else passes through value-identical.
        assert_eq!(v["model"], body["model"]);
        assert_eq!(v["temperature"], body["temperature"]);
        assert_eq!(v["tools"], body["tools"]);
    }

    #[test]
    fn injection_is_byte_stable_across_calls() {
        let body = br#"{"model":"m","messages":[{"role":"user","content":"q"}]}"#;
        let a = inject_bundle(body, Some(BUNDLE));
        let b = inject_bundle(body, Some(BUNDLE));
        assert!(a.injected && b.injected);
        assert_eq!(a.body, b.body, "same input + same bundle must produce identical bytes");
    }

    #[test]
    fn non_json_and_non_chat_bodies_pass_through() {
        let raw = b"not json at all";
        let out = inject_bundle(raw, Some(BUNDLE));
        assert!(!out.injected);
        assert_eq!(out.body, raw.to_vec());

        let no_messages = br#"{"model":"m","prompt":"complete this"}"#;
        let out = inject_bundle(no_messages, Some(BUNDLE));
        assert!(!out.injected);
        assert_eq!(out.body, no_messages.to_vec());
    }

    #[test]
    fn no_bundle_means_passthrough_but_still_reads_stream_flag() {
        let body = br#"{"model":"m","stream":true,"messages":[]}"#;
        let out = inject_bundle(body, None);
        assert!(!out.injected);
        assert!(out.stream);
        assert_eq!(out.body, body.to_vec());
    }

    #[test]
    fn injectable_paths() {
        assert!(path_is_injectable("/v1/chat/completions"));
        assert!(path_is_injectable("/chat/completions"));
        assert!(path_is_injectable("/api/chat"));
        assert!(!path_is_injectable("/api/generate"));
        assert!(!path_is_injectable("/api/tags"));
        assert!(!path_is_injectable("/v1/embeddings"));
    }
}
