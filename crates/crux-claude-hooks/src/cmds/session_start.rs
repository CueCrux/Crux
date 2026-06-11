// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `SessionStart` hook. Automates the §11.1 session-boot ritual:
//! 1. Call `sync_status({})` — note any `degraded`/`behind` state.
//! 2. If sync is healthy, call `get_bootstrap({topic: "patterns", token_budget: 500})`.
//! 3. Inject the combined result as `additionalContext`.
//!
//! Best-effort: a missing daemon yields no injected context but never blocks.

use serde_json::{json, Value};

use crate::{config_audit, hook_input::HookInput, hook_output::HookOutput, mcp_client};

const BOOTSTRAP_TOKEN_BUDGET: u64 = 500;

pub fn run<R: std::io::Read>(reader: R) -> anyhow::Result<()> {
    let _input = HookInput::read_from(reader)?;

    if std::env::var("CRUX_HOOK_SESSION_START").as_deref() == Ok("off") {
        return Ok(());
    }

    let mut sections: Vec<String> = Vec::new();

    match mcp_client::call_tool("sync_status", json!({})) {
        Ok(result) => {
            let summary = render_sync_status(&result);
            sections.push(format!("**Crux sync_status**\n{summary}"));

            if sync_is_healthy(&result) {
                let args = json!({
                    "topic": "patterns",
                    "token_budget": BOOTSTRAP_TOKEN_BUDGET,
                });
                match mcp_client::call_tool("get_bootstrap", &args) {
                    Ok(boot) => {
                        let text = extract_text(&boot);
                        if !text.is_empty() {
                            sections.push(format!("**Crux bootstrap (patterns)**\n{text}"));
                        }
                    }
                    Err(err) => {
                        eprintln!("crux-hook session-start: get_bootstrap failed: {err}");
                    }
                }
            }
        }
        Err(err) => {
            eprintln!("crux-hook session-start: sync_status failed: {err}");
            return Ok(());
        }
    }

    // Live-session coordination digest (presence-coordination plan M5):
    // who else is live on this daemon right now, their declared focus, and
    // the punchcard leases they hold. Best-effort; silent when the daemon's
    // coord plane is disabled (CORECRUXD_COORD unset → 404).
    if std::env::var("CRUX_HOOK_COORD").as_deref() != Ok("off") {
        match mcp_client::call_tool("coord_status", json!({})) {
            Ok(result) => {
                if let Some(digest) = render_coord_digest(&extract_text(&result)) {
                    sections.push(digest);
                }
            }
            Err(err) => {
                let msg = err.to_string();
                if !msg.contains("404") {
                    eprintln!("crux-hook session-start: coord_status failed: {err}");
                }
            }
        }
    }

    // Warn-only config-audit: hash known agent-config files, ask the daemon
    // which content hashes are unreviewed, surface inline. Operators clear
    // by calling `audit_config(...)` after review.
    if let Some(warning) = config_audit::session_start_warning() {
        sections.push(warning);
    }

    // Drift check against bundled profile fragments. Cheap, filesystem-only;
    // surfaces "your CLAUDE.md is out of date" without touching the daemon.
    if std::env::var("CRUX_HOOK_WIZARD_CHECK").as_deref() != Ok("off") {
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        match crux_config_wizard::drift::check_workspace(&cwd) {
            Ok(report) if report.drifted() => {
                sections.push(format!("**Crux config drift**\n{}", report.message_for_claude()));
            }
            Ok(_) => {}
            Err(err) => {
                eprintln!("crux-hook session-start: wizard drift check failed: {err}");
            }
        }
    }

    if !sections.is_empty() {
        let body = sections.join("\n\n");
        HookOutput::new("SessionStart", body).emit()?;
    }
    Ok(())
}

/// Extract `result.content[0].text` (standard MCP tool response shape),
/// falling back to the pretty-printed JSON if the shape differs.
fn extract_text(result: &Value) -> String {
    if let Some(arr) = result.get("content").and_then(|c| c.as_array()) {
        for item in arr {
            if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                return text.to_string();
            }
        }
    }
    serde_json::to_string_pretty(result).unwrap_or_default()
}

/// Render the `coord_status` payload into a compact "live sessions" digest.
/// Returns `None` when there is nothing worth injecting (no live peers and
/// nothing in flight) so quiet daemons stay quiet.
fn render_coord_digest(text: &str) -> Option<String> {
    use std::fmt::Write as _;
    let v: Value = serde_json::from_str(text).ok()?;
    let sessions = v.get("active_sessions").and_then(Value::as_array)?;
    let work = v
        .get("work_in_flight")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if sessions.is_empty() && work.is_empty() {
        return None;
    }
    let mut lines = vec![format!(
        "**Crux coord — live sessions ({}), work in flight ({})**",
        sessions.len(),
        work.len()
    )];
    for s in sessions.iter().take(6) {
        let session = s.get("session_id_hex").and_then(Value::as_str).unwrap_or("?");
        let passport = s.get("passport_id").and_then(Value::as_str).unwrap_or("?");
        let mut line = format!("- `{session}` ({passport})");
        if let Some(intent) = s.get("intent") {
            if let Some(slug) = intent.get("execplan_slug").and_then(Value::as_str) {
                let _ = write!(line, " · {slug}");
                if let Some(ms) = intent.get("milestone").and_then(Value::as_str) {
                    let _ = write!(line, " @ {ms}");
                }
            }
            if let Some(note) = intent.get("note").and_then(Value::as_str) {
                let _ = write!(line, " · {note}");
            }
            if let Some(paths) = intent.get("paths").and_then(Value::as_array) {
                let shown: Vec<&str> = paths.iter().filter_map(Value::as_str).take(3).collect();
                if !shown.is_empty() {
                    let _ = write!(line, " · paths: {}", shown.join(", "));
                }
            }
        }
        if let Some(leases) = s.get("leases").and_then(Value::as_array) {
            let held: Vec<&str> = leases
                .iter()
                .filter_map(|l| l.get("resource").and_then(Value::as_str))
                .take(3)
                .collect();
            if !held.is_empty() {
                let _ = write!(line, " · holds: {}", held.join(", "));
            }
        }
        lines.push(line);
    }
    if sessions.len() > 6 {
        lines.push(format!("- …and {} more (call coord_status)", sessions.len() - 6));
    }
    lines.push(
        "Coordinate before touching another session's paths/leases; announce your own focus with coord_announce."
            .to_string(),
    );
    Some(lines.join("\n"))
}

fn render_sync_status(result: &Value) -> String {
    let text = extract_text(result);
    // Cap to 400 chars to keep injected context tight. Bootstrap is the bulk.
    if text.len() > 400 {
        format!("{}…", &text[..400])
    } else {
        text
    }
}

/// `sync_status` is "healthy" if it does not contain `degraded` or `behind`
/// strings. Heuristic; conservative — when in doubt, skip bootstrap fetch.
fn sync_is_healthy(result: &Value) -> bool {
    let text = extract_text(result).to_lowercase();
    !text.contains("degraded") && !text.contains("behind") && !text.contains("diverged")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_stdin_is_handled() {
        // Without a daemon, this is a graceful no-op.
        let prev = std::env::var("CRUX_MCP_URL").ok();
        std::env::set_var("CRUX_MCP_URL", "http://127.0.0.1:1/mcp");
        run(std::io::Cursor::new("")).unwrap();
        match prev {
            Some(v) => std::env::set_var("CRUX_MCP_URL", v),
            None => std::env::remove_var("CRUX_MCP_URL"),
        }
    }

    #[test]
    fn extract_text_handles_mcp_shape() {
        let r = json!({
            "content": [{"type": "text", "text": "hello"}]
        });
        assert_eq!(extract_text(&r), "hello");
    }

    #[test]
    fn extract_text_falls_back_to_pretty_json() {
        let r = json!({"foo": "bar"});
        let out = extract_text(&r);
        assert!(out.contains("\"foo\""));
        assert!(out.contains("\"bar\""));
    }

    #[test]
    fn sync_healthy_when_no_degraded_markers() {
        let r = json!({"content": [{"text": "status: ok\nlocal_only: false"}]});
        assert!(sync_is_healthy(&r));
    }

    #[test]
    fn sync_unhealthy_when_degraded() {
        let r = json!({"content": [{"text": "status: degraded"}]});
        assert!(!sync_is_healthy(&r));
    }

    #[test]
    fn sync_unhealthy_when_behind() {
        let r = json!({"content": [{"text": "Sync is BEHIND remote"}]});
        assert!(!sync_is_healthy(&r));
    }

    #[test]
    fn coord_digest_quiet_when_empty() {
        let text = r#"{"now_unix_ms":1,"presence_ttl_secs":900,"active_sessions":[],"work_in_flight":[]}"#;
        assert!(render_coord_digest(text).is_none());
        assert!(render_coord_digest("not json").is_none());
    }

    #[test]
    fn coord_digest_renders_focus_and_leases() {
        let text = r#"{
            "now_unix_ms": 1,
            "presence_ttl_secs": 900,
            "active_sessions": [{
                "session_id_hex": "aaaa",
                "passport_id": "claude-work",
                "intent": {
                    "execplan_slug": "crux-agent-presence-coordination-2026-06-11",
                    "milestone": "M5",
                    "paths": ["crates/crux-claude-hooks/src"]
                },
                "leases": [{"resource": "tree://crates/crux-claude-hooks"}]
            }],
            "work_in_flight": [{"id": "w1"}]
        }"#;
        let digest = render_coord_digest(text).expect("digest");
        assert!(digest.contains("live sessions (1)"));
        assert!(digest.contains("work in flight (1)"));
        assert!(digest.contains("crux-agent-presence-coordination-2026-06-11 @ M5"));
        assert!(digest.contains("holds: tree://crates/crux-claude-hooks"));
        assert!(digest.contains("coord_announce"));
    }
}
