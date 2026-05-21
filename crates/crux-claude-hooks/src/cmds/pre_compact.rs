// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `PreCompact` hook. Snapshots a minimal session-state record to the Crux
//! daemon via MCP `save_session` before the harness compacts context.
//! Best-effort: if the daemon is unreachable, we log and exit 0.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

use crate::{hook_input::HookInput, mcp_client};

/// Cap on bytes read from `.agent/current-milestone` — the file is meant to
/// hold a short label like "M3" or "M5: shell-pattern constraints", not a
/// document. Anything longer is truncated for the payload.
const MILESTONE_LABEL_MAX_BYTES: usize = 256;

pub fn run<R: std::io::Read>(reader: R) -> anyhow::Result<()> {
    let Some(input) = HookInput::read_from(reader)? else {
        return Ok(());
    };

    if std::env::var("CRUX_HOOK_PRE_COMPACT").as_deref() == Ok("off") {
        return Ok(());
    }

    let session_key = format!("hook:session:{}", input.session_id);

    let cwd_path = if input.cwd.is_empty() {
        None
    } else {
        Some(PathBuf::from(&input.cwd))
    };
    let recovery = collect_recovery_anchors(cwd_path.as_deref());

    let state = json!({
        "hook_event": "PreCompact",
        "trigger": input.trigger.unwrap_or_else(|| "unknown".into()),
        "cwd": input.cwd,
        "transcript_path": input.transcript_path,
        "snapshot_ts": current_timestamp(),
        "recovery": recovery,
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

/// Best-effort anchors for mid-ExecPlan crash recovery: HEAD commit, active
/// branch, and the operator-set `.agent/current-milestone` label if any.
/// Every field is optional — git absent, repo absent, label absent all
/// degrade silently. Caller embeds the resulting object under `state.recovery`.
fn collect_recovery_anchors(cwd: Option<&Path>) -> Value {
    let mut obj = serde_json::Map::new();

    if let Some(dir) = cwd {
        if let Some(sha) = run_git(dir, &["rev-parse", "HEAD"]) {
            obj.insert("last_commit_sha".into(), Value::String(sha));
        }
        if let Some(branch) = run_git(dir, &["rev-parse", "--abbrev-ref", "HEAD"]) {
            if branch != "HEAD" {
                obj.insert("branch".into(), Value::String(branch));
            }
        }
        if let Some(label) = read_milestone_label(dir) {
            obj.insert("active_milestone".into(), Value::String(label));
        }
    }

    Value::Object(obj)
}

fn run_git(cwd: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).current_dir(cwd).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn read_milestone_label(cwd: &Path) -> Option<String> {
    let path = cwd.join(".agent/current-milestone");
    let raw = std::fs::read(&path).ok()?;
    if raw.is_empty() {
        return None;
    }
    let slice = if raw.len() > MILESTONE_LABEL_MAX_BYTES {
        &raw[..MILESTONE_LABEL_MAX_BYTES]
    } else {
        &raw[..]
    };
    let text = String::from_utf8_lossy(slice).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
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
    fn collect_recovery_anchors_none_when_cwd_absent() {
        let v = collect_recovery_anchors(None);
        assert!(v.as_object().unwrap().is_empty());
    }

    #[test]
    fn collect_recovery_anchors_reads_milestone_label() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = tmp.path().join(".agent");
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(agent.join("current-milestone"), "M3: shell_pattern\n").unwrap();

        let v = collect_recovery_anchors(Some(tmp.path()));
        // last_commit_sha may or may not be present depending on whether
        // tmpdir happens to sit inside a git repo; we only assert the
        // milestone label is captured.
        assert_eq!(
            v.get("active_milestone").and_then(|x| x.as_str()),
            Some("M3: shell_pattern")
        );
    }

    #[test]
    fn collect_recovery_anchors_skips_empty_milestone() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = tmp.path().join(".agent");
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(agent.join("current-milestone"), "   \n").unwrap();

        let v = collect_recovery_anchors(Some(tmp.path()));
        assert!(v.get("active_milestone").is_none());
    }

    #[test]
    fn collect_recovery_anchors_truncates_long_milestone() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = tmp.path().join(".agent");
        std::fs::create_dir_all(&agent).unwrap();
        let long = "x".repeat(MILESTONE_LABEL_MAX_BYTES * 2);
        std::fs::write(agent.join("current-milestone"), &long).unwrap();

        let v = collect_recovery_anchors(Some(tmp.path()));
        let label = v.get("active_milestone").and_then(|x| x.as_str()).unwrap();
        assert!(label.len() <= MILESTONE_LABEL_MAX_BYTES);
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
