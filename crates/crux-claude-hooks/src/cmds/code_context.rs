// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `PreToolUse` hook (code-intelligence M5): inject per-file context.
//!
//! The MemoryHook pattern applied to code. When an agent is about to `Read` a
//! file, this hook looks up a `code:<repo>:<path>` context fact (key
//! `context`) and, if present, injects it (≤500 tokens) as `additionalContext`
//! so the agent gets the file's intent/constraints without re-deriving them
//! from the source — attacking re-derivation token burn.
//!
//! **Default-OFF** behind `CRUX_HOOK_CODE_CONTEXT` (the `hooks.code_context`
//! config key). Disabled / no-fact / unreachable-daemon → a plain `allow` with
//! no injection. The hook never blocks (always `allow`) and never errors out
//! of the tool call; the daemon lookup is local + budget-capped for latency.

use serde_json::Value;

use crate::daemon_client;
use crate::hook_input::HookInput;
use crate::hook_output::PreToolUseOutput;

/// Hard cap on injected context — ≤500 tokens ≈ 2000 chars (4 chars/token).
const MAX_CONTEXT_CHARS: usize = 2000;

/// Entry point dispatched from `main.rs` for the `code-context` subcommand.
pub fn run<R: std::io::Read>(reader: R) -> anyhow::Result<()> {
    let Some(input) = HookInput::read_from(reader)? else {
        return PreToolUseOutput::allow().emit();
    };
    decide(&input, fetch_context).emit()
}

/// True when the hook is enabled (`CRUX_HOOK_CODE_CONTEXT` truthy). Default OFF.
pub fn is_enabled() -> bool {
    matches!(
        std::env::var("CRUX_HOOK_CODE_CONTEXT").ok().as_deref(),
        Some("1" | "true" | "on" | "yes")
    )
}

/// The `file_path` of a `Read` tool call, if this is one.
pub fn read_file_path(input: &HookInput) -> Option<String> {
    if input.tool_name.as_deref() != Some("Read") {
        return None;
    }
    input.tool_input.as_ref()?.get("file_path")?.as_str().map(String::from)
}

/// Derive `(repo, rel_path, entity)` for a file. `repo` is the leaf dir of
/// `cwd`; `rel_path` is `file_path` made relative to `cwd` (forward slashes).
pub fn code_entity(cwd: &str, file_path: &str) -> (String, String, String) {
    let cwd = cwd.trim_end_matches('/');
    let repo = cwd
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("repo")
        .to_string();
    let fp = file_path.replace('\\', "/");
    let rel = fp
        .strip_prefix(cwd)
        .map_or(fp.as_str(), |s| s.trim_start_matches('/'))
        .to_string();
    let entity = format!("code:{repo}:{rel}");
    (repo, rel, entity)
}

/// A resolved context fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextFact {
    pub value: String,
    pub commit_sha: Option<String>,
    pub stored_at_ms: Option<i64>,
}

/// Fetch the `context` fact for an entity from the daemon (fail-open → None).
fn fetch_context(entity: &str) -> Option<ContextFact> {
    let path = format!("/v1/facts/entity/{}", urlencoding::encode(entity));
    let json = daemon_client::get_json(&path).ok()?;
    let facts = json.get("facts")?.as_array()?;
    // newest (highest version) `context` fact wins
    let mut best: Option<(i64, ContextFact)> = None;
    for f in facts {
        if f.get("key").and_then(Value::as_str) != Some("context") {
            continue;
        }
        if f.get("deleted").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let value = f.get("value").and_then(Value::as_str).unwrap_or("").to_string();
        if value.is_empty() {
            continue;
        }
        let version = f.get("version").and_then(Value::as_i64).unwrap_or(0);
        let cf = ContextFact {
            value,
            commit_sha: f.get("commit_sha").and_then(Value::as_str).map(String::from),
            stored_at_ms: f.get("stored_at_unix_ms").and_then(Value::as_i64),
        };
        if best.as_ref().is_none_or(|(v, _)| version > *v) {
            best = Some((version, cf));
        }
    }
    best.map(|(_, cf)| cf)
}

/// Best-effort file mtime in unix ms (for the freshness guard).
fn file_mtime_ms(file_path: &str) -> Option<i64> {
    let meta = std::fs::metadata(file_path).ok()?;
    let mtime = meta.modified().ok()?;
    let dur = mtime.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(dur.as_millis() as i64)
}

/// Build the `additionalContext` block: a header, the (truncated) context, and
/// an optional freshness note when the file was modified after the fact.
pub fn build_block(entity: &str, fact: &ContextFact, file_mtime_ms: Option<i64>) -> String {
    let mut body = fact.value.clone();
    if body.chars().count() > MAX_CONTEXT_CHARS {
        body = body.chars().take(MAX_CONTEXT_CHARS).collect::<String>();
        body.push_str("\n… (context truncated to ≤500 tokens)");
    }
    let mut out = format!("Crux file context — {entity}\n{body}");
    if let (Some(stored), Some(mtime)) = (fact.stored_at_ms, file_mtime_ms) {
        if mtime > stored {
            out.push_str("\n⚠ context may be stale — file modified since this note was written");
        }
    }
    if let Some(sha) = &fact.commit_sha {
        use std::fmt::Write as _;
        let _ = write!(out, "\n(note recorded at {sha})");
    }
    out
}

/// Resolve the hook decision. The fetcher is injected so tests don't need a
/// daemon. Always `allow`; injects context only when enabled + a fact exists.
fn decide(input: &HookInput, fetch: impl Fn(&str) -> Option<ContextFact>) -> PreToolUseOutput {
    if !is_enabled() {
        return PreToolUseOutput::allow();
    }
    let Some(file_path) = read_file_path(input) else {
        return PreToolUseOutput::allow();
    };
    let (_, _, entity) = code_entity(&input.cwd, &file_path);
    match fetch(&entity) {
        Some(fact) => {
            let block = build_block(&entity, &fact, file_mtime_ms(&file_path));
            PreToolUseOutput::allow_with_context(block)
        }
        None => PreToolUseOutput::allow(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input(tool: Option<&str>, cwd: &str, file: Option<&str>) -> HookInput {
        HookInput {
            session_id: "s1".into(),
            transcript_path: String::new(),
            cwd: cwd.into(),
            hook_event_name: "PreToolUse".into(),
            tool_name: tool.map(String::from),
            tool_input: file.map(|f| json!({ "file_path": f })),
            tool_response: None,
            trigger: None,
            source: None,
        }
    }

    fn ctx(v: &str) -> ContextFact {
        ContextFact {
            value: v.into(),
            commit_sha: Some("abc1234".into()),
            stored_at_ms: Some(1000),
        }
    }

    fn additional(out: &PreToolUseOutput) -> Option<String> {
        let v = serde_json::to_value(out).unwrap();
        v["hookSpecificOutput"]["additionalContext"].as_str().map(String::from)
    }

    fn with_enabled<T>(on: bool, f: impl FnOnce() -> T) -> T {
        // env is process-global — serialize against other env-mutating tests.
        let _guard = crate::test_support::env_guard();
        let prev = std::env::var("CRUX_HOOK_CODE_CONTEXT").ok();
        if on {
            std::env::set_var("CRUX_HOOK_CODE_CONTEXT", "1");
        } else {
            std::env::remove_var("CRUX_HOOK_CODE_CONTEXT");
        }
        let r = f();
        match prev {
            Some(p) => std::env::set_var("CRUX_HOOK_CODE_CONTEXT", p),
            None => std::env::remove_var("CRUX_HOOK_CODE_CONTEXT"),
        }
        r
    }

    #[test]
    fn entity_derivation() {
        let (repo, rel, entity) = code_entity("/srv/Crux", "/srv/Crux/crates/corecruxd/src/work.rs");
        assert_eq!(repo, "Crux");
        assert_eq!(rel, "crates/corecruxd/src/work.rs");
        assert_eq!(entity, "code:Crux:crates/corecruxd/src/work.rs");
        // relative file path is kept as-is
        let (_, rel2, _) = code_entity("/srv/Crux", "src/main.rs");
        assert_eq!(rel2, "src/main.rs");
    }

    #[test]
    fn disabled_by_default_injects_nothing() {
        with_enabled(false, || {
            let out = decide(&input(Some("Read"), "/srv/Crux", Some("/srv/Crux/a.rs")), |_| {
                Some(ctx("hi"))
            });
            assert_eq!(
                additional(&out),
                None,
                "default-OFF: no injection even with a fact present"
            );
        });
    }

    #[test]
    fn enabled_injects_context_for_read() {
        with_enabled(true, || {
            let out = decide(&input(Some("Read"), "/srv/Crux", Some("/srv/Crux/a.rs")), |e| {
                assert_eq!(e, "code:Crux:a.rs");
                Some(ctx("This module owns gate resolution."))
            });
            let a = additional(&out).expect("context injected");
            assert!(a.contains("This module owns gate resolution."));
            assert!(a.contains("code:Crux:a.rs"));
        });
    }

    #[test]
    fn non_read_tool_never_injects() {
        with_enabled(true, || {
            let out = decide(&input(Some("Bash"), "/srv/Crux", None), |_| Some(ctx("x")));
            assert_eq!(additional(&out), None);
        });
    }

    #[test]
    fn absent_fact_allows_plain() {
        with_enabled(true, || {
            let out = decide(&input(Some("Read"), "/srv/Crux", Some("/srv/Crux/a.rs")), |_| None);
            assert_eq!(additional(&out), None);
        });
    }

    #[test]
    fn context_truncated_to_500_tokens() {
        let big = "x".repeat(5000);
        let block = build_block("code:r:a.rs", &ctx(&big), None);
        assert!(block.chars().count() < MAX_CONTEXT_CHARS + 200);
        assert!(block.contains("truncated"));
    }

    #[test]
    fn freshness_note_when_file_newer_than_fact() {
        // fact stored_at 1000ms, file mtime 2000ms → stale note
        let block = build_block("code:r:a.rs", &ctx("intent"), Some(2000));
        assert!(block.contains("may be stale"));
        // file older than fact → no stale note
        let fresh = build_block("code:r:a.rs", &ctx("intent"), Some(500));
        assert!(!fresh.contains("may be stale"));
    }
}
