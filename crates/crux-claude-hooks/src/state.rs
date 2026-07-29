// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Per-session debounce / loop-detection state persisted to a small JSON file
//! under `${TMPDIR}/crux-hook-state-{session_id}.json`. All hooks share this
//! state; concurrent writes are unlikely (Claude Code serialises hook
//! invocations within a session) so a simple read-modify-write is adequate.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Max distinct edited file paths we track before warning.
pub const FILE_SCOPE_WARN_THRESHOLD: usize = 20;

/// Number of identical consecutive tool calls that triggers a loop warning.
pub const LOOP_DETECTION_THRESHOLD: usize = 3;

/// How many PostToolUse calls must pass between repeat warnings (same severity).
pub const WARNING_DEBOUNCE_CALLS: u64 = 5;

/// Bounded history depth for tool signatures.
const TOOL_HISTORY_DEPTH: usize = 8;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub call_count: u64,
    pub tool_history: Vec<String>,
    pub edited_files: Vec<String>,
    pub last_warning_at_call: u64,
    pub file_scope_warned: bool,
}

impl SessionState {
    pub fn for_session(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            ..Self::default()
        }
    }

    /// Path under `${TMPDIR:-/tmp}/crux-hook-state-{sanitised_session_id}.json`.
    pub fn state_path(session_id: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let sanitised: String = session_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .take(64)
            .collect();
        let name = if sanitised.is_empty() {
            "default"
        } else {
            sanitised.as_str()
        };
        dir.push(format!("crux-hook-state-{name}.json"));
        dir
    }

    pub fn load(session_id: &str) -> Self {
        Self::load_from(&Self::state_path(session_id), session_id)
    }

    pub fn load_from(path: &Path, session_id: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|_| Self::for_session(session_id)),
            Err(_) => Self::for_session(session_id),
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        self.save_to(&Self::state_path(&self.session_id))
    }

    pub fn save_to(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Record a new tool signature, maintaining a bounded ring buffer.
    pub fn push_tool(&mut self, sig: String) {
        self.tool_history.push(sig);
        if self.tool_history.len() > TOOL_HISTORY_DEPTH {
            let excess = self.tool_history.len() - TOOL_HISTORY_DEPTH;
            self.tool_history.drain(..excess);
        }
    }

    /// True if the last `LOOP_DETECTION_THRESHOLD` tool signatures are identical.
    pub fn detect_loop(&self) -> bool {
        if self.tool_history.len() < LOOP_DETECTION_THRESHOLD {
            return false;
        }
        let tail = &self.tool_history[self.tool_history.len() - LOOP_DETECTION_THRESHOLD..];
        tail.iter().all(|s| s == &tail[0])
    }

    /// Track an edited file path (deduped). Returns true if scope warning
    /// has *just* crossed the threshold (call site uses this to fire once).
    pub fn track_edit(&mut self, path: String) -> bool {
        if !self.edited_files.contains(&path) {
            self.edited_files.push(path);
        }
        if !self.file_scope_warned && self.edited_files.len() >= FILE_SCOPE_WARN_THRESHOLD {
            self.file_scope_warned = true;
            return true;
        }
        false
    }

    /// Decide whether a (non-critical) warning should fire now, considering
    /// the debounce window. Always returns true for critical-severity callers,
    /// which should bypass this method.
    pub fn should_warn(&mut self) -> bool {
        let since_last = self.call_count.saturating_sub(self.last_warning_at_call);
        if self.last_warning_at_call == 0 || since_last >= WARNING_DEBOUNCE_CALLS {
            self.last_warning_at_call = self.call_count;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_via_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut s = SessionState::for_session("abc");
        s.call_count = 3;
        s.push_tool("Bash:abc".into());
        s.save_to(&path).unwrap();

        let loaded = SessionState::load_from(&path, "abc");
        assert_eq!(loaded.call_count, 3);
        assert_eq!(loaded.tool_history, vec!["Bash:abc".to_string()]);
    }

    #[test]
    fn detect_loop_fires_on_three_identical_sigs() {
        let mut s = SessionState::for_session("s");
        s.push_tool("Bash:x".into());
        assert!(!s.detect_loop());
        s.push_tool("Bash:x".into());
        assert!(!s.detect_loop());
        s.push_tool("Bash:x".into());
        assert!(s.detect_loop());
    }

    #[test]
    fn detect_loop_does_not_fire_when_pattern_breaks() {
        let mut s = SessionState::for_session("s");
        s.push_tool("Bash:x".into());
        s.push_tool("Bash:y".into());
        s.push_tool("Bash:x".into());
        assert!(!s.detect_loop());
    }

    #[test]
    fn ring_buffer_bounded() {
        let mut s = SessionState::for_session("s");
        for i in 0..20 {
            s.push_tool(format!("tool:{i}"));
        }
        assert_eq!(s.tool_history.len(), TOOL_HISTORY_DEPTH);
        assert_eq!(s.tool_history.last().unwrap(), "tool:19");
    }

    #[test]
    fn track_edit_warns_once_at_threshold() {
        let mut s = SessionState::for_session("s");
        for i in 0..FILE_SCOPE_WARN_THRESHOLD - 1 {
            assert!(!s.track_edit(format!("/tmp/f{i}")));
        }
        // Threshold crossing
        assert!(s.track_edit("/tmp/threshold".into()));
        // Subsequent edits do not re-warn
        assert!(!s.track_edit("/tmp/next".into()));
    }

    #[test]
    fn debounce_blocks_repeat_warnings() {
        let mut s = SessionState::for_session("s");
        s.call_count = 1;
        assert!(s.should_warn()); // first warning at call 1
        s.call_count = 3;
        assert!(!s.should_warn()); // too soon
        s.call_count = 1 + WARNING_DEBOUNCE_CALLS;
        assert!(s.should_warn()); // window elapsed
    }

    #[test]
    fn state_path_sanitises_session_id() {
        let path = SessionState::state_path("abc/../etc/passwd");
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("crux-hook-state-"));
        assert!(!name.contains('/'));
        assert!(!name.contains(".."));
    }
}
