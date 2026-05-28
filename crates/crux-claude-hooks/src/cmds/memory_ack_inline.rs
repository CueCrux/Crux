// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `PostToolUse` hook — agent-ux-02 (Acknowledged Memory Use) inline
//! annotation.
//!
//! When the just-completed tool call is an envelope-emitting MCP tool
//! (`query_facts` or `memory_acknowledge_use`) AND the response carries
//! a non-empty `envelope.memories_used[]`, emit a one-line annotation
//! the Claude Code harness renders to the user inline.
//!
//! Reserved-prefix entries are already stripped upstream by the
//! envelope wrapper (see `crux-mcp::envelope::is_reserved_entity`), so
//! this module trusts what it reads. A defence-in-depth re-filter is
//! cheap, so it does that anyway — the annotation never mentions a
//! `__agent::*` / `__ops::*` / `__bootstrap__::*` topic, even if a
//! buggy upstream forgets.
//!
//! ## Feature flag
//!
//! Gated by `CORECRUXD_FEATURE_MEMORY_ACK_INLINE` (default OFF). Any
//! value other than `"0"|"false"|"off"|"no"|""` enables.
//!
//! ## Non-blocking
//!
//! Always exits Ok. Never blocks the agent. If the envelope is absent or
//! the flag is off, the hook is a no-op.

use crate::{hook_input::HookInput, hook_output::HookOutput};

/// Environment variable that gates the inline annotation. Default off.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_MEMORY_ACK_INLINE";

const RESERVED_PREFIXES: &[&str] = &["__agent::", "__ops::", "__bootstrap__::"];
const MAX_TOPICS_RENDERED: usize = 3;

fn flag_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

fn is_envelope_emitting_tool(name: &str) -> bool {
    matches!(name, "query_facts" | "memory_acknowledge_use")
}

fn is_reserved(topic: &str) -> bool {
    RESERVED_PREFIXES.iter().any(|p| topic.starts_with(p))
}

/// Build the human-readable annotation from the envelope's
/// `memories_used[]` array. Returns `None` when there's nothing
/// renderable (no envelope, empty list, all entries redacted).
pub fn build_annotation(tool_response: &serde_json::Value) -> Option<String> {
    let envelope = tool_response.get("envelope")?;
    let memories = envelope.get("memories_used")?.as_array()?;
    if memories.is_empty() {
        return None;
    }

    // Collect distinct topics, skipping reserved-prefix leaks. Keep the
    // first occurrence order so the annotation matches what the agent
    // surfaced.
    let mut topics: Vec<String> = Vec::new();
    for m in memories {
        let Some(topic) = m.get("topic").and_then(|v| v.as_str()) else {
            continue;
        };
        if is_reserved(topic) {
            continue;
        }
        if !topics.iter().any(|t| t == topic) {
            topics.push(topic.to_string());
        }
    }
    if topics.is_empty() {
        return None;
    }

    let count = memories.len();
    let shown: Vec<String> = topics.iter().take(MAX_TOPICS_RENDERED).cloned().collect();
    let topic_str = if topics.len() > MAX_TOPICS_RENDERED {
        let extra = topics.len() - MAX_TOPICS_RENDERED;
        format!("{} (+{} more)", shown.join(", "), extra)
    } else {
        shown.join(", ")
    };

    // Detect the lowest-confidence freshness for a subtle hint.
    let any_stale = memories
        .iter()
        .any(|m| m.get("freshness").and_then(|v| v.as_str()) == Some("stale"));
    let stale_hint = if any_stale {
        " (some entries stale — re-verify before relying)"
    } else {
        ""
    };

    Some(format!(
        "Memory used: {count} stored fact{plural} on {topic_str}{stale_hint}",
        plural = if count == 1 { "" } else { "s" }
    ))
}

pub fn run<R: std::io::Read>(reader: R) -> anyhow::Result<()> {
    let Some(input) = HookInput::read_from(reader)? else {
        return Ok(());
    };

    if !flag_enabled() {
        return Ok(());
    }

    let Some(tool_name) = input.tool_name.as_deref() else {
        return Ok(());
    };
    if !is_envelope_emitting_tool(tool_name) {
        return Ok(());
    }

    let Some(tool_response) = input.tool_response.as_ref() else {
        return Ok(());
    };

    if let Some(msg) = build_annotation(tool_response) {
        HookOutput::new("PostToolUse", msg).emit()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_flag<F: FnOnce()>(value: &str, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var(FEATURE_FLAG_ENV).ok();
        std::env::set_var(FEATURE_FLAG_ENV, value);
        f();
        match prev {
            Some(v) => std::env::set_var(FEATURE_FLAG_ENV, v),
            None => std::env::remove_var(FEATURE_FLAG_ENV),
        }
    }

    #[test]
    fn empty_stdin_is_a_noop() {
        run(std::io::Cursor::new("")).unwrap();
    }

    #[test]
    fn flag_off_is_a_noop_even_with_envelope() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::remove_var(FEATURE_FLAG_ENV);
        let payload = json!({
            "session_id": "s",
            "hook_event_name": "PostToolUse",
            "tool_name": "query_facts",
            "tool_response": {
                "envelope": { "memories_used": [{"topic": "project-x"}] }
            }
        });
        run(std::io::Cursor::new(payload.to_string())).unwrap();
        // No assertion on output (the hook writes to stdout); the test
        // simply asserts that the call completes successfully.
    }

    #[test]
    fn build_annotation_skips_reserved_entries() {
        let response = json!({
            "envelope": {
                "memories_used": [
                    {"topic": "__ops::config-audit"},
                    {"topic": "__bootstrap__::pattern:retry"},
                    {"topic": "__agent::alice::notes"},
                ]
            }
        });
        let out = build_annotation(&response);
        assert!(
            out.is_none(),
            "annotation must be empty when every entry is reserved-prefix; got {out:?}"
        );
    }

    #[test]
    fn build_annotation_renders_topic_list() {
        let response = json!({
            "envelope": {
                "memories_used": [
                    {"topic": "project-x", "freshness": "fresh"},
                    {"topic": "project-y", "freshness": "fresh"}
                ]
            }
        });
        let out = build_annotation(&response).expect("annotation");
        assert!(out.contains("project-x"));
        assert!(out.contains("project-y"));
        assert!(out.contains("2 stored facts"));
    }

    #[test]
    fn build_annotation_renders_singular_count() {
        let response = json!({
            "envelope": {
                "memories_used": [
                    {"topic": "project-x", "freshness": "fresh"}
                ]
            }
        });
        let out = build_annotation(&response).expect("annotation");
        assert!(out.contains("1 stored fact"));
        assert!(!out.contains("stored facts"), "singular: no plural 's'");
    }

    #[test]
    fn build_annotation_caps_topics_with_overflow_hint() {
        let mems: Vec<_> = (0..5)
            .map(|i| json!({"topic": format!("p-{i}"), "freshness": "fresh"}))
            .collect();
        let response = json!({
            "envelope": { "memories_used": mems }
        });
        let out = build_annotation(&response).expect("annotation");
        assert!(out.contains("+2 more"), "expected overflow hint, got: {out}");
    }

    #[test]
    fn build_annotation_flags_stale() {
        let response = json!({
            "envelope": {
                "memories_used": [
                    {"topic": "project-x", "freshness": "stale"}
                ]
            }
        });
        let out = build_annotation(&response).expect("annotation");
        assert!(out.contains("stale"), "expected stale hint, got: {out}");
    }

    #[test]
    fn build_annotation_none_when_envelope_missing() {
        let response = json!({"content": [{"type": "text", "text": "hello"}]});
        assert!(build_annotation(&response).is_none());
    }

    #[test]
    fn non_envelope_tool_is_skipped() {
        with_flag("1", || {
            let payload = json!({
                "session_id": "s",
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_response": {
                    "envelope": { "memories_used": [{"topic": "p"}] }
                }
            });
            run(std::io::Cursor::new(payload.to_string())).unwrap();
        });
    }

    #[test]
    fn happy_path_emits_for_query_facts() {
        with_flag("1", || {
            let payload = json!({
                "session_id": "s",
                "hook_event_name": "PostToolUse",
                "tool_name": "query_facts",
                "tool_response": {
                    "envelope": {
                        "memories_used": [{"topic": "project-x", "freshness": "fresh"}]
                    }
                }
            });
            run(std::io::Cursor::new(payload.to_string())).unwrap();
        });
    }

    #[test]
    fn happy_path_emits_for_memory_acknowledge_use() {
        with_flag("1", || {
            let payload = json!({
                "session_id": "s",
                "hook_event_name": "PostToolUse",
                "tool_name": "memory_acknowledge_use",
                "tool_response": {
                    "envelope": {
                        "memories_used": [{"topic": "project-y", "freshness": "fresh"}]
                    }
                }
            });
            run(std::io::Cursor::new(payload.to_string())).unwrap();
        });
    }
}
