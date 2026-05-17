// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
}
