// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `SessionStart` hook. Automates the §11.1 session-boot ritual:
//! 1. Call `sync_status({})` — note any `degraded`/`behind` state.
//! 2. If sync is healthy, call `get_bootstrap({topic: "patterns", token_budget: 500})`.
//! 3. Inject the combined result as `additionalContext`.
//!
//! Best-effort: a missing daemon yields no injected context but never blocks.
//!
//! ## M2 — cache-aligned boot banner (Headroom *CacheAligner* analogue)
//!
//! ExecPlan: `crux-headroom-token-efficiency-learnings-2026-06-24` (milestone M2).
//!
//! The injected `additionalContext` becomes a *prefix* of the model's context.
//! Anthropic (and other) providers serve a cached prefix at ~90% off, but the
//! cache only hits while the leading bytes are **byte-identical** boot-to-boot.
//! Today the banner leads with the most *volatile* content — `sync_status`
//! (timestamps, `local_fact_count`, sync mode) and the live-session coord
//! digest — so a single changed fact count busts the whole prefix.
//!
//! We tag each section `Stable` (playbook/patterns — identical session-to-session)
//! or `Volatile` (sync state, live sessions, config hashes) and emit all stable
//! sections first, volatile last. The stable *prefix* then stays byte-identical
//! across boots; only the tail churns.
//!
//! Cache alignment shipped behind `CRUX_BANNER_CACHE_ALIGN` (CO-2, default-ON
//! 2026-06-25). The escape-hatch env flag is now **removed** (CO-5, 2026-06-30):
//! the banner is always cache-aligned (the reorder is consumer-free — nothing
//! parses the banner positionally).

use serde_json::{json, Value};

use crate::{config_audit, hook_input::HookInput, hook_output::HookOutput, mcp_client};

const BOOTSTRAP_TOKEN_BUDGET: u64 = 500;

/// Boot-banner section stability, for M2 cache alignment. `Stable` content is
/// identical session-to-session (playbook/patterns) and belongs at the front so
/// the cached prefix stays warm; `Volatile` content (timestamps, fact counts,
/// sync/coord state, config hashes) belongs at the tail.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stability {
    Stable,
    Volatile,
}

/// Order tagged banner sections for emission. When `align` is true, all
/// `Stable` sections come first (in insertion order) then all `Volatile` ones
/// (in insertion order) — a stable partition, so within-class order is
/// preserved. When false, pure insertion order ⇒ byte-identical to pre-M2.
fn order_sections(sections: Vec<(Stability, String)>, align: bool) -> Vec<String> {
    if !align {
        return sections.into_iter().map(|(_, body)| body).collect();
    }
    let mut stable = Vec::new();
    let mut volatile = Vec::new();
    for (stability, body) in sections {
        match stability {
            Stability::Stable => stable.push(body),
            Stability::Volatile => volatile.push(body),
        }
    }
    stable.into_iter().chain(volatile).collect()
}

pub fn run<R: std::io::Read>(reader: R) -> anyhow::Result<()> {
    let _input = HookInput::read_from(reader)?;

    if std::env::var("CRUX_HOOK_SESSION_START").as_deref() == Ok("off") {
        return Ok(());
    }

    // Each section is tagged with its M2 cache-alignment stability; at emit time
    // `order_sections` floats `Stable` ahead of `Volatile` (unconditional since CO-5).
    let mut sections: Vec<(Stability, String)> = Vec::new();

    // Boot observations for the wizard self-check (see the block near the end).
    // `sync_degraded` is assigned on the only path that survives the match (the
    // `Err` arm returns), so it needs no dead initialiser; `bootstrap_loaded`
    // stays false unless the playbook actually renders.
    let sync_degraded;
    let mut bootstrap_loaded = false;

    match mcp_client::call_tool("sync_status", json!({})) {
        Ok(result) => {
            sync_degraded = sync_reports_degraded(&result);
            let summary = render_sync_status(&result);
            // Volatile: timestamps, local_fact_count, sync mode all change boot-to-boot.
            sections.push((Stability::Volatile, format!("**Crux sync_status**\n{summary}")));

            if sync_is_healthy(&result) {
                let args = json!({
                    "topic": "patterns",
                    "token_budget": BOOTSTRAP_TOKEN_BUDGET,
                });
                match mcp_client::call_tool("get_bootstrap", &args) {
                    Ok(boot) => {
                        let text = extract_text(&boot);
                        if !text.is_empty() {
                            bootstrap_loaded = true;
                            // Stable: playbook/patterns — identical session-to-session.
                            sections.push((Stability::Stable, format!("**Crux bootstrap (patterns)**\n{text}")));
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
                    // Volatile: the live-session / work-in-flight list changes constantly.
                    sections.push((Stability::Volatile, digest));
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
        // Volatile: lists unreviewed content hashes, which change as configs change.
        sections.push((Stability::Volatile, warning));
    }

    // Drift check against bundled profile fragments. Cheap, filesystem-only;
    // surfaces "your CLAUDE.md is out of date" without touching the daemon.
    if std::env::var("CRUX_HOOK_WIZARD_CHECK").as_deref() != Ok("off") {
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        match crux_config_wizard::drift::check_workspace(&cwd) {
            Ok(report) if report.drifted() || report.has_warnings() => {
                // Stable: bundled-profile drift guidance — the same text until the
                // operator's CLAUDE.md or the bundled profiles change.
                sections.push((
                    Stability::Stable,
                    format!("**Crux config**\n{}", report.message_for_claude()),
                ));
            }
            Ok(_) => {}
            Err(err) => {
                eprintln!("crux-hook session-start: wizard drift check failed: {err}");
            }
        }
    }

    // Boot self-check: catch the class of failure where the daemon is healthy
    // but the banner silently loses content — a hook regression suppressing the
    // playbook, or a stale hook binary skewed from the daemon version. The policy
    // lives in the wizard (`selfcheck`), pure + unit-tested; this block only does
    // the daemon I/O (a best-effort `initialize` for the daemon version) and feeds
    // observations in. Gated by the same flag as the drift check. Reaching here
    // means `sync_status` succeeded (the `Err` arm returned early), so the daemon
    // was reachable this boot.
    if std::env::var("CRUX_HOOK_WIZARD_CHECK").as_deref() != Ok("off") {
        let hook_version = env!("CARGO_PKG_VERSION");
        let daemon_version = mcp_client::server_version();
        let obs = crux_config_wizard::selfcheck::BootObservations {
            hook_version,
            daemon_version: daemon_version.as_deref(),
            sync_reachable: true,
            sync_degraded,
            bootstrap_loaded,
        };
        if let Some(section) =
            crux_config_wizard::selfcheck::render_section(&crux_config_wizard::selfcheck::evaluate(&obs))
        {
            // Volatile: reflects live daemon/hook state, not stable playbook text.
            sections.push((Stability::Volatile, section));
        }
    }

    // CO-5: cache alignment is unconditional (the env flag was removed).
    let ordered = order_sections(sections, true);
    if !ordered.is_empty() {
        let body = ordered.join("\n\n");
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

/// Whether sync state is healthy enough to fetch the patterns bootstrap.
///
/// The real signal is the `degraded` boolean the daemon reports, not a substring
/// scan of the payload: `sync_status` *always* embeds the literal `"degraded":
/// false` and a `"degraded_reason"` field, so the old `text.contains("degraded")`
/// heuristic fired on every healthy boot and permanently suppressed the banner.
/// `local_only` is a normal steady state — the patterns playbook is still useful
/// there (the daemon's own welcome hint tells cold starts to fetch it), so mode
/// alone does not gate the fetch; only an actually-degraded daemon does.
///
/// Falls back to the conservative substring heuristic when the payload is not the
/// expected JSON object (defensive; keeps behaviour sane for stub responses).
fn sync_is_healthy(result: &Value) -> bool {
    let text = extract_text(result);
    if let Ok(v) = serde_json::from_str::<Value>(&text) {
        return !v.get("degraded").and_then(Value::as_bool).unwrap_or(false);
    }
    // Fallback: payload was not the expected JSON object (stub / plain text).
    let lower = text.to_lowercase();
    !lower.contains("degraded") && !lower.contains("behind") && !lower.contains("diverged")
}

/// The daemon's own `degraded` verdict from a `sync_status` payload — the parsed
/// boolean, defaulting to `false` when the field or JSON is absent. Distinct from
/// [`sync_is_healthy`]: this reports *what the daemon said*, used by the boot
/// self-check to tell a genuinely-degraded daemon (legitimately no playbook) from
/// a healthy one whose banner was silently suppressed (an anomaly worth warning).
fn sync_reports_degraded(result: &Value) -> bool {
    let text = extract_text(result);
    serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| v.get("degraded").and_then(Value::as_bool))
        .unwrap_or(false)
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

    /// Regression: the real `sync_status` payload is a JSON object that always
    /// carries `"degraded": false` and a `"degraded_reason"` string. The old
    /// substring heuristic matched "degraded" here and suppressed the bootstrap
    /// banner on every healthy boot. Parsing the boolean fixes it.
    #[test]
    fn sync_healthy_when_local_only_degraded_false_json() {
        let payload = r#"{
            "mode": "local_only",
            "configured": false,
            "degraded": false,
            "degraded_reason": "remote sync is not configured; continuing with the local fact and session store only"
        }"#;
        let r = json!({"content": [{"text": payload}]});
        assert!(
            sync_is_healthy(&r),
            "local_only with degraded:false must fetch the patterns bootstrap"
        );
    }

    #[test]
    fn sync_unhealthy_when_degraded_true_json() {
        let payload = r#"{"mode": "remote", "degraded": true, "degraded_reason": "remote unreachable"}"#;
        let r = json!({"content": [{"text": payload}]});
        assert!(!sync_is_healthy(&r));
    }

    #[test]
    fn coord_digest_quiet_when_empty() {
        let text = r#"{"now_unix_ms":1,"presence_ttl_secs":900,"active_sessions":[],"work_in_flight":[]}"#;
        assert!(render_coord_digest(text).is_none());
        assert!(render_coord_digest("not json").is_none());
    }

    // ---- M2 — cache-aligned boot banner ------------------------------------

    /// Two boots: identical stable content, *different* volatile content (a
    /// changed fact count / timestamp). Models the cache-align invariant.
    fn boot_sections(volatile_marker: &str) -> Vec<(Stability, String)> {
        vec![
            (
                Stability::Volatile,
                format!("**Crux sync_status**\nlocal_fact_count={volatile_marker}"),
            ),
            (
                Stability::Stable,
                "**Crux bootstrap (patterns)**\nalways do X; never do Y".to_string(),
            ),
            (
                Stability::Volatile,
                format!("**Crux coord**\nlive sessions: {volatile_marker}"),
            ),
            (
                Stability::Stable,
                "**Crux config**\nyour CLAUDE.md is current".to_string(),
            ),
        ]
    }

    #[test]
    fn order_off_is_insertion_order() {
        // Flag OFF ⇒ byte-identical to pre-M2 (pure insertion order).
        let s = boot_sections("42");
        let bodies: Vec<String> = s.iter().map(|(_, b)| b.clone()).collect();
        assert_eq!(order_sections(s, false), bodies);
    }

    #[test]
    fn order_on_floats_stable_to_front_preserving_within_class_order() {
        let ordered = order_sections(boot_sections("42"), true);
        // Stable sections first, in their original relative order…
        assert!(ordered[0].starts_with("**Crux bootstrap (patterns)**"));
        assert!(ordered[1].starts_with("**Crux config**"));
        // …then volatile, in their original relative order.
        assert!(ordered[2].starts_with("**Crux sync_status**"));
        assert!(ordered[3].starts_with("**Crux coord**"));
    }

    #[test]
    fn gate_m2_two_boot_prefix_is_byte_identical_only_tail_churns() {
        // The M2 gate: with cache-align ON, two boots whose only difference is
        // volatile content share a byte-identical prefix; the diff is the tail.
        let boot_a = order_sections(boot_sections("42"), true).join("\n\n");
        let boot_b = order_sections(boot_sections("99"), true).join("\n\n");
        assert_ne!(boot_a, boot_b, "volatile content must still differ in the tail");

        // The stable block (everything up to the first volatile section header)
        // is identical across boots.
        let prefix_end = boot_a.find("**Crux sync_status**").expect("volatile tail present");
        assert_eq!(&boot_a[..prefix_end], &boot_b[..prefix_end]);
        assert!(prefix_end > 0, "stable prefix must be non-empty");
        // And that shared prefix carries the stable playbook, not volatile state.
        assert!(boot_a[..prefix_end].contains("always do X"));
        assert!(!boot_a[..prefix_end].contains("local_fact_count"));

        // Quantify the win: the cached prefix is the run of bytes shared before
        // the first divergence. Aligned ⇒ long shared prefix (volatile is in the
        // tail); unaligned ⇒ short (volatile sync_status leads, busts it early).
        let off_a = order_sections(boot_sections("42"), false).join("\n\n");
        let off_b = order_sections(boot_sections("99"), false).join("\n\n");
        let common = |x: &str, y: &str| x.bytes().zip(y.bytes()).take_while(|(a, b)| a == b).count();
        assert!(
            common(&boot_a, &boot_b) > common(&off_a, &off_b),
            "cache-align must extend the shared prefix (aligned {} > unaligned {})",
            common(&boot_a, &boot_b),
            common(&off_a, &off_b)
        );
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
