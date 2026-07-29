// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Claude Code hook output protocol. Hooks that want to inject context back
//! into the model conversation emit a JSON envelope on stdout with the
//! shape `{"hookSpecificOutput": {"hookEventName": "...", "additionalContext": "..."}}`.

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize)]
pub struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "additionalContext")]
    pub additional_context: String,
}

impl HookOutput {
    pub fn new(event_name: impl Into<String>, additional_context: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: event_name.into(),
                additional_context: additional_context.into(),
            },
        }
    }

    /// Print the envelope to stdout. Errors during serialisation are
    /// returned to the caller, which logs them to stderr but exits 0.
    pub fn emit(&self) -> anyhow::Result<()> {
        let json = serde_json::to_string(self)?;
        println!("{json}");
        Ok(())
    }
}

/// `PreToolUse` hook output. The Claude Code harness reads
/// `permissionDecision` (`allow` | `deny` | `ask`) to decide whether the
/// about-to-run tool call proceeds. The hook always exits 0 — a deny is
/// communicated via this JSON, never via a non-zero exit code.
#[derive(Debug, Serialize)]
pub struct PreToolUseOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: PreToolUseSpecificOutput,
}

#[derive(Debug, Serialize)]
pub struct PreToolUseSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
    /// Optional context injected for the agent (code-intelligence M5 — a
    /// `code:<repo>:<path>` file-context fact). Omitted when there is nothing
    /// to inject; the harness surfaces it to the agent ahead of the tool call.
    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

impl PreToolUseOutput {
    fn new(decision: &str, reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: PreToolUseSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: decision.to_string(),
                permission_decision_reason: reason.into(),
                additional_context: None,
            },
        }
    }

    /// Allow the tool call to proceed (the fail-open default).
    pub fn allow() -> Self {
        Self::new("allow", String::new())
    }

    /// Allow the tool call and inject `context` for the agent (M5 Read hook).
    pub fn allow_with_context(context: impl Into<String>) -> Self {
        let mut out = Self::new("allow", String::new());
        out.hook_specific_output.additional_context = Some(context.into());
        out
    }

    /// Deny the tool call, surfacing `reason` to the agent.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::new("deny", reason)
    }

    /// Ask the operator to decide (reserved; not emitted by the scaffold).
    pub fn ask(reason: impl Into<String>) -> Self {
        Self::new("ask", reason)
    }

    /// Print the envelope to stdout. Serialisation errors propagate to the
    /// caller, which logs them to stderr but exits 0.
    pub fn emit(&self) -> anyhow::Result<()> {
        let json = serde_json::to_string(self)?;
        println!("{json}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_shape_matches_claude_code_protocol() {
        let out = HookOutput::new("PostToolUse", "watch out");
        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": "watch out"
                }
            })
        );
    }

    #[test]
    fn pre_tool_use_allow_shape() {
        let out = PreToolUseOutput::allow();
        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "permissionDecisionReason": ""
                }
            })
        );
    }

    #[test]
    fn pre_tool_use_deny_shape() {
        let out = PreToolUseOutput::deny("file held by another passport");
        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "file held by another passport"
        );
    }
}
