// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Claude Code hook input schema. Hooks receive JSON on stdin with a
//! standard envelope plus event-specific fields. We deserialise loosely:
//! unknown fields are ignored, missing optional fields default.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use serde::Deserialize;
use serde_json::Value;

/// Common envelope received on every hook event.
#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub hook_event_name: String,

    // PostToolUse fields
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Option<Value>,
    /// PostToolUse payload from the tool. For Claude Code MCP calls this
    /// is the JSON result the tool returned; for envelope-emitting tools
    /// it carries the per-turn audit envelope under `tool_response.envelope`.
    /// agent-ux-02 M3 reads `memories_used[]` from here.
    #[serde(default)]
    pub tool_response: Option<Value>,

    // PreCompact fields
    #[serde(default)]
    pub trigger: Option<String>,

    // SessionStart fields
    #[serde(default)]
    pub source: Option<String>,
}

impl HookInput {
    /// Deserialise from a Read source (typically `stdin.lock()`).
    /// Returns `Ok(None)` on empty input so hooks can be invoked manually.
    pub fn read_from<R: std::io::Read>(mut reader: R) -> anyhow::Result<Option<Self>> {
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(trimmed)?))
    }

    /// Best-effort signature for loop detection: tool_name + a stable hash
    /// of `tool_input` rendered as canonical JSON.
    pub fn tool_signature(&self) -> Option<String> {
        let name = self.tool_name.as_ref()?;
        let input_repr = self
            .tool_input
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default())
            .unwrap_or_default();
        // Cheap stable hash via std DefaultHasher; collisions don't matter
        // because false positives in loop detection are only "warn once".
        let mut hasher = DefaultHasher::new();
        input_repr.hash(&mut hasher);
        Some(format!("{name}:{:x}", hasher.finish()))
    }

    /// Extract an `Edit`/`Write` target file path if this is a write tool.
    pub fn edited_file_path(&self) -> Option<String> {
        let name = self.tool_name.as_deref()?;
        if !matches!(name, "Edit" | "Write" | "NotebookEdit") {
            return None;
        }
        self.tool_input.as_ref()?.get("file_path")?.as_str().map(String::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_input_returns_none() {
        let out = HookInput::read_from(std::io::Cursor::new("")).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn post_tool_use_deserialises() {
        let payload = json!({
            "session_id": "abc",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"}
        });
        let input = HookInput::read_from(std::io::Cursor::new(payload.to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(input.session_id, "abc");
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
    }

    #[test]
    fn tool_signature_stable_across_identical_calls() {
        let a = HookInput {
            session_id: "s".into(),
            transcript_path: String::new(),
            cwd: String::new(),
            hook_event_name: "PostToolUse".into(),
            tool_name: Some("Bash".into()),
            tool_input: Some(json!({"command": "ls"})),
            tool_response: None,
            trigger: None,
            source: None,
        };
        let b = a.clone();
        assert_eq!(a.tool_signature(), b.tool_signature());
    }

    #[test]
    fn edited_file_path_only_for_write_tools() {
        let edit = HookInput {
            session_id: String::new(),
            transcript_path: String::new(),
            cwd: String::new(),
            hook_event_name: String::new(),
            tool_name: Some("Edit".into()),
            tool_input: Some(json!({"file_path": "/tmp/x.rs"})),
            tool_response: None,
            trigger: None,
            source: None,
        };
        assert_eq!(edit.edited_file_path().as_deref(), Some("/tmp/x.rs"));

        let bash = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(json!({"command": "ls"})),
            ..edit
        };
        assert_eq!(bash.edited_file_path(), None);
    }
}
