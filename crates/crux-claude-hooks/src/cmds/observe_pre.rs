// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `PreToolUse` hook — the coupled piece shared by the observe (capture) and
//! punchcard (enforce) ExecPlans.
//!
//! Two responsibilities on every Edit/Write/NotebookEdit:
//!
//! 1. **Punchcard enforce** — best-effort probe the daemon for a lease on the
//!    target file. Only when the daemon *clearly* reports the resource is held
//!    by another holder AND the daemon is in enforce mode do we emit a DENY.
//!    Any error / timeout / 501 / empty / ambiguous response → ALLOW
//!    (fail-open). The check endpoint is a stub today, so the steady-state is
//!    ALLOW.
//!
//! 2. **Audit capture** — fire-and-forget attempt to record the step. Errors
//!    are swallowed; this never blocks the tool call.
//!
//! The hook ALWAYS exits 0. A deny is communicated via the
//! `permissionDecision` JSON field, never via a non-zero exit code — this
//! preserves the workspace's "hooks never block via exit code" philosophy.

use serde_json::{json, Value};

use crate::hook_input::HookInput;
use crate::hook_output::PreToolUseOutput;
use crate::mcp_client;

/// Tools that mutate files and therefore require a punchcard check.
const WRITE_TOOLS: &[&str] = &["Edit", "Write", "NotebookEdit"];

/// Entry point dispatched from `main.rs` for the `observe-pre` subcommand.
pub fn run<R: std::io::Read>(reader: R) -> anyhow::Result<()> {
    // No stdin (manual invocation) → allow and return.
    let Some(input) = HookInput::read_from(reader)? else {
        return PreToolUseOutput::allow().emit();
    };

    let decision = decide(&input);

    // Audit capture is best-effort and independent of the decision: record
    // the step regardless of allow/deny, never propagate errors.
    capture_audit_step(&input);

    decision.emit()
}

/// Resolve the allow/deny decision for this hook input. Pure except for the
/// daemon probe; isolated so tests can assert the fail-open contract.
fn decide(input: &HookInput) -> PreToolUseOutput {
    let Some(tool) = input.tool_name.as_deref() else {
        return PreToolUseOutput::allow();
    };
    if !WRITE_TOOLS.contains(&tool) {
        return PreToolUseOutput::allow();
    }
    let Some(path) = input
        .tool_input
        .as_ref()
        .and_then(|v| v.get("file_path"))
        .and_then(|v| v.as_str())
    else {
        return PreToolUseOutput::allow();
    };

    match probe_punchcard(path) {
        // Daemon clearly says the lease is held by another holder → DENY.
        Some(reason) => PreToolUseOutput::deny(reason),
        // Anything else (error / 501 / empty / not-held / ambiguous) →
        // fail-open ALLOW.
        None => PreToolUseOutput::allow(),
    }
}

/// Probe the daemon for a lease conflict on `path`. Returns `Some(reason)`
/// ONLY when the daemon clearly indicates the resource is held by another
/// passport. Returns `None` on any error / timeout / 501 / empty / not-held
/// (fail-open).
fn probe_punchcard(path: &str) -> Option<String> {
    let resource = format!("file://{path}");
    let result = mcp_client::call_tool("check_punchcard", json!({ "resource": resource, "mode": "modify" }));
    match result {
        Ok(value) => interpret_check_result(&value),
        // Daemon unreachable / 501 / JSON-RPC error → fail-open.
        Err(_) => None,
    }
}

/// Interpret a `check_punchcard` MCP result. The endpoint is a stub today
/// (returns 501 / empty), so the steady-state is `None` (ALLOW). When the
/// punchcard plan ships the real check, a held-by-another lease surfaces as
/// `held_by_other: true` with `enforce: true`; we deny only on that exact,
/// unambiguous signal.
fn interpret_check_result(value: &Value) -> Option<String> {
    // MCP tool results wrap the payload in `content[].text`; the daemon may
    // also return the structured object directly. Handle both, but require
    // the unambiguous held-by-other + enforce combination.
    let structured = extract_structured(value);
    let obj = structured.as_ref().unwrap_or(value);

    let held_by_other = obj.get("held_by_other").and_then(Value::as_bool).unwrap_or(false);
    let enforce = obj.get("enforce").and_then(Value::as_bool).unwrap_or(false);
    if held_by_other && enforce {
        let holder = obj
            .get("holder_passport")
            .and_then(Value::as_str)
            .unwrap_or("another passport");
        let resource = obj.get("resource").and_then(Value::as_str).unwrap_or("this resource");
        Some(format!(
            "punchcard: {resource} is held by {holder}; acquire or wait for release before editing"
        ))
    } else {
        None
    }
}

/// If the value is an MCP `{content:[{type:"text",text:"<json>"}]}` envelope,
/// parse the inner text as JSON and return it. Otherwise `None`.
fn extract_structured(value: &Value) -> Option<Value> {
    let text = value
        .get("content")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)?;
    serde_json::from_str(text).ok()
}

/// Best-effort, fire-and-forget audit-step capture. The record-step tool is
/// a no-op-tolerant stub today; any error is swallowed so the hook never
/// blocks the tool call.
fn capture_audit_step(input: &HookInput) {
    let args = json!({
        "session_id": input.session_id,
        "tool_name": input.tool_name,
        "hook_event": "PreToolUse",
    });
    // Ignore the result entirely — capture is advisory.
    let _ = mcp_client::call_tool("record_audit_step", args);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mk_input(tool: Option<&str>, file: Option<&str>) -> HookInput {
        HookInput {
            session_id: "s1".into(),
            transcript_path: String::new(),
            cwd: String::new(),
            hook_event_name: "PreToolUse".into(),
            tool_name: tool.map(String::from),
            tool_input: file.map(|f| json!({ "file_path": f })),
            tool_response: None,
            trigger: None,
            source: None,
        }
    }

    fn decision_of(out: &PreToolUseOutput) -> String {
        let v = serde_json::to_value(out).unwrap();
        v["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn non_write_tool_allows() {
        let out = decide(&mk_input(Some("Bash"), None));
        assert_eq!(decision_of(&out), "allow");
    }

    #[test]
    fn write_tool_without_path_allows() {
        let out = decide(&mk_input(Some("Edit"), None));
        assert_eq!(decision_of(&out), "allow");
    }

    #[test]
    fn write_tool_fails_open_when_daemon_unreachable() {
        // CRUX_MCP_URL points nowhere usable in the test env, so the probe
        // errors and we must ALLOW (fail-open).
        let prev = std::env::var("CRUX_MCP_URL").ok();
        std::env::set_var("CRUX_MCP_URL", "http://127.0.0.1:1/mcp");
        let out = decide(&mk_input(Some("Edit"), Some("/tmp/x.rs")));
        match prev {
            Some(v) => std::env::set_var("CRUX_MCP_URL", v),
            None => std::env::remove_var("CRUX_MCP_URL"),
        }
        assert_eq!(decision_of(&out), "allow");
    }

    #[test]
    fn interpret_denies_only_on_held_by_other_and_enforce() {
        let held = json!({ "held_by_other": true, "enforce": true, "holder_passport": "agent:other" });
        assert!(interpret_check_result(&held).is_some());

        let advisory = json!({ "held_by_other": true, "enforce": false });
        assert!(interpret_check_result(&advisory).is_none());

        let free = json!({ "held_by_other": false, "enforce": true });
        assert!(interpret_check_result(&free).is_none());

        let empty = json!({});
        assert!(interpret_check_result(&empty).is_none());
    }

    #[test]
    fn interpret_handles_mcp_text_envelope() {
        let envelope = json!({
            "content": [{ "type": "text", "text": "{\"held_by_other\":true,\"enforce\":true}" }]
        });
        assert!(interpret_check_result(&envelope).is_some());
    }
}
