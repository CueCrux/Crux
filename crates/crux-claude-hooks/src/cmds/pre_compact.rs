// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `PreCompact` hook. Snapshots a minimal session-state record to the Crux
//! daemon via MCP `save_session` before the harness compacts context.
//! Best-effort: if the daemon is unreachable, we log and exit 0.

use serde_json::json;

use crate::{hook_input::HookInput, mcp_client};

pub fn run<R: std::io::Read>(reader: R) -> anyhow::Result<()> {
    let Some(input) = HookInput::read_from(reader)? else {
        return Ok(());
    };

    if std::env::var("CRUX_HOOK_PRE_COMPACT").as_deref() == Ok("off") {
        return Ok(());
    }

    let session_key = format!("hook:session:{}", input.session_id);

    let state = json!({
        "hook_event": "PreCompact",
        "trigger": input.trigger.unwrap_or_else(|| "unknown".into()),
        "cwd": input.cwd,
        "transcript_path": input.transcript_path,
        "snapshot_ts": current_timestamp(),
    });

    let args = json!({
        "session_id": session_key,
        "state": state,
    });

    // Fire and forget. Daemon-unreachable is non-fatal.
    if let Err(err) = mcp_client::call_tool("save_session", &args) {
        eprintln!("crux-hook pre-compact: save_session failed: {err}");
    }
    Ok(())
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_stdin_is_a_noop() {
        run(std::io::Cursor::new("")).unwrap();
    }

    #[test]
    fn daemon_unreachable_does_not_error() {
        // Point at a guaranteed-closed port to confirm graceful degradation.
        let prev = std::env::var("CRUX_MCP_URL").ok();
        std::env::set_var("CRUX_MCP_URL", "http://127.0.0.1:1/mcp");

        let payload = json!({
            "session_id": "test",
            "hook_event_name": "PreCompact",
            "trigger": "manual",
            "cwd": "/tmp",
            "transcript_path": "/tmp/t.jsonl",
        })
        .to_string();

        // Must return Ok even though the daemon isn't reachable.
        run(std::io::Cursor::new(payload)).unwrap();

        match prev {
            Some(v) => std::env::set_var("CRUX_MCP_URL", v),
            None => std::env::remove_var("CRUX_MCP_URL"),
        }
    }
}
