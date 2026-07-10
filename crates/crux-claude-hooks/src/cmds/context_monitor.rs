// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `PostToolUse` hook. Read-only operational anomaly detector.
//!
//! Watches:
//! - **Tool-call loops**: 3 consecutive identical (tool_name, tool_input) sigs.
//! - **Excessive file scope**: distinct `Edit`/`Write` file paths > 20.
//!
//! Surfaces warnings inline via `additionalContext`. Never writes facts
//! (CueCrux/CLAUDE.md §11.2: facts must be deliberate, not reflexive).
//! Never blocks: always exits 0 from the caller.

use crate::{hook_input::HookInput, hook_output::HookOutput, state::SessionState};

pub fn run<R: std::io::Read>(reader: R) -> anyhow::Result<()> {
    let Some(input) = HookInput::read_from(reader)? else {
        return Ok(());
    };

    // Disable knob — useful for noisy debugging sessions.
    if std::env::var("CRUX_HOOK_CONTEXT_MONITOR").as_deref() == Ok("off") {
        return Ok(());
    }

    let mut state = SessionState::load(&input.session_id);
    state.call_count = state.call_count.saturating_add(1);

    let mut warnings: Vec<String> = Vec::new();
    let mut critical = false;

    // Loop detection
    if let Some(sig) = input.tool_signature() {
        state.push_tool(sig.clone());
        if state.detect_loop() {
            warnings.push(format!(
                "Loop detected: {} consecutive identical `{}` calls. \
                 Step back and consider whether the approach is working.",
                crate::state::LOOP_DETECTION_THRESHOLD,
                input.tool_name.as_deref().unwrap_or("?"),
            ));
            critical = true;
        }
    }

    // File-scope warning
    if let Some(path) = input.edited_file_path() {
        if state.track_edit(path) {
            warnings.push(format!(
                "File scope alert: {} distinct files edited this session. \
                 Consider whether the change set is staying reviewable.",
                crate::state::FILE_SCOPE_WARN_THRESHOLD,
            ));
        }
    }

    // Debounce non-critical warnings; critical always fires.
    let should_emit = !warnings.is_empty() && (critical || state.should_warn());

    state.save()?;

    if should_emit {
        let msg = warnings.join("\n\n");
        HookOutput::new("PostToolUse", msg).emit()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    // Serialises tests that touch the CRUX_HOOK_CONTEXT_MONITOR env var.
    // Process-global env state means parallel `cargo test` threads can
    // otherwise race.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn input_for(tool: &str, command: &str) -> String {
        json!({
            "session_id": "test-session",
            "hook_event_name": "PostToolUse",
            "tool_name": tool,
            "tool_input": {"command": command},
        })
        .to_string()
    }

    #[test]
    fn empty_stdin_is_a_noop() {
        run(std::io::Cursor::new("")).unwrap();
    }

    #[test]
    fn three_identical_bash_calls_record_loop_in_state() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Ensure env var pollution from a parallel test cannot mute this run.
        std::env::remove_var("CRUX_HOOK_CONTEXT_MONITOR");

        let session_id = format!("test-loop-{}", std::process::id());
        let payload = json!({
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        })
        .to_string();

        let _ = std::fs::remove_file(SessionState::state_path(&session_id));

        for _ in 0..3 {
            run(std::io::Cursor::new(payload.clone())).unwrap();
        }

        let state = SessionState::load(&session_id);
        assert_eq!(state.call_count, 3);
        assert!(state.detect_loop(), "loop should be detected after 3 identical sigs");

        let _ = std::fs::remove_file(SessionState::state_path(&session_id));
    }

    #[test]
    fn disabled_via_env_var() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var("CRUX_HOOK_CONTEXT_MONITOR").ok();
        std::env::set_var("CRUX_HOOK_CONTEXT_MONITOR", "off");
        run(std::io::Cursor::new(input_for("Bash", "ls"))).unwrap();
        match prev {
            Some(v) => std::env::set_var("CRUX_HOOK_CONTEXT_MONITOR", v),
            None => std::env::remove_var("CRUX_HOOK_CONTEXT_MONITOR"),
        }
    }
}
