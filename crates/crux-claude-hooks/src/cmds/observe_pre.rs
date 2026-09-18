// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `PreToolUse` hook — the coupled piece shared by the observe (capture) and
//! punchcard (enforce) ExecPlans.
//!
//! Two responsibilities on every Edit/Write/NotebookEdit or Codex
//! `apply_patch`:
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
//! 3. **Deploy-axis probe** (B3 Part 3, deferred from B1) — when the tool is a
//!    deploy action (a `Bash` command invoking the deploy script, or an
//!    explicit deploy tool), construct the `deploy://<host>/<path>` resource
//!    and probe the punchcard lease via the same `check_punchcard` path. Under
//!    enforce mode a held-by-other deploy lease DENIES; under advisory mode it
//!    ALLOWS but injects a warning for the agent; any ambiguity (not clearly a
//!    deploy, can't resolve a host, daemon error) FAILS OPEN to a plain allow.
//!    The probe's runtime correctness depends on B1's `deploy://` punchcard
//!    endpoint (sibling branch) — it compiles and is unit-testable
//!    independently because it only POSTs a resource string and interprets the
//!    same `{held_by_other, enforce}` contract the file probe already uses.
//!
//! Codex patches are target-validated before daemon access and probe every
//! normalized path in waves of at most eight requests. Those probes are not a
//! daemon-atomic snapshot: a lease can still change between the final probe
//! and tool execution. Closing that inherited TOCTOU window requires a later
//! batch/epoch API.
//!
//! The hook ALWAYS exits 0. A deny is communicated via the
//! `permissionDecision` JSON field, never via a non-zero exit code — this
//! preserves the workspace's "hooks never block via exit code" philosophy.

use std::path::Path;

use serde_json::{json, Value};

use crate::apply_patch_targets::{self, AffectedPath};
use crate::hook_input::HookInput;
use crate::hook_output::{PreToolUseDecision, PreToolUseOutput};
use crate::mcp_client;
use crate::observe_capture;

/// Tools that mutate files and therefore require a punchcard check.
const WRITE_TOOLS: &[&str] = &["Edit", "Write", "NotebookEdit"];
const CODEX_APPLY_PATCH: &str = "apply_patch";
const MAX_CONCURRENT_PROBES: usize = 8;

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
fn decide(input: &HookInput) -> PreToolUseDecision {
    let Some(tool) = input.tool_name.as_deref() else {
        return PreToolUseDecision::output(PreToolUseOutput::allow());
    };

    // Deploy-axis probe runs first: a deploy action is never an Edit/Write, so
    // the two branches are disjoint. If this isn't recognisably a deploy, the
    // probe returns a plain allow and we fall through to the write-tool path.
    if let Some(out) = deploy_probe::decide_deploy(input) {
        return PreToolUseDecision::output(out);
    }

    if tool == CODEX_APPLY_PATCH {
        return decide_apply_patch(input);
    }

    if !WRITE_TOOLS.contains(&tool) {
        return PreToolUseDecision::output(PreToolUseOutput::allow());
    }
    let Some(path) = input
        .tool_input
        .as_ref()
        .and_then(|v| v.get("file_path"))
        .and_then(|v| v.as_str())
    else {
        return PreToolUseDecision::output(PreToolUseOutput::allow());
    };

    match probe_punchcard(path) {
        // Daemon clearly says the lease is held by another holder → DENY.
        Some(reason) => PreToolUseDecision::output(PreToolUseOutput::deny(reason)),
        // Anything else (error / 501 / empty / not-held / ambiguous) →
        // fail-open ALLOW.
        None => PreToolUseDecision::output(PreToolUseOutput::allow()),
    }
}

/// Validate one canonical Codex patch, probe every normalized target, and
/// produce one whole-patch decision. Parse/normalization errors are denied
/// before daemon access. A valid conflict-free patch emits no decision; MCP
/// transport errors remain fail-open for compatibility with the existing
/// lease probe policy.
fn decide_apply_patch(input: &HookInput) -> PreToolUseDecision {
    let Some(command) = input
        .tool_input
        .as_ref()
        .and_then(|value| value.get("command"))
        .and_then(Value::as_str)
    else {
        return PreToolUseDecision::output(PreToolUseOutput::deny(
            "apply_patch denied: tool_input.command is required",
        ));
    };

    let targets = match apply_patch_targets::parse(command, &input.cwd) {
        Ok(targets) => targets,
        Err(error) => {
            return PreToolUseDecision::output(PreToolUseOutput::deny(format!("apply_patch denied: {error}")));
        }
    };

    let conflicts = probe_apply_patch_targets(&targets);
    if conflicts.is_empty() {
        PreToolUseDecision::NoDecision
    } else {
        PreToolUseDecision::output(PreToolUseOutput::deny(format!(
            "apply_patch denied by enforced punchcards: {}",
            conflicts.join("; ")
        )))
    }
}

/// Probe no more than eight paths concurrently, retaining target order in
/// diagnostics. Every wave runs even if an earlier request fails so a later
/// enforced conflict cannot be hidden by a transport error.
fn probe_apply_patch_targets(targets: &[AffectedPath]) -> Vec<String> {
    let mut conflicts = Vec::new();
    for wave in targets.chunks(MAX_CONCURRENT_PROBES) {
        let results = std::thread::scope(|scope| {
            let handles = wave
                .iter()
                .map(|target| scope.spawn(move || probe_punchcard_resource(target.path())))
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().ok().flatten())
                .collect::<Vec<_>>()
        });
        conflicts.extend(results.into_iter().flatten());
    }
    conflicts
}

/// Probe the daemon for a lease conflict on `path`. Returns `Some(reason)`
/// ONLY when the daemon clearly indicates the resource is held by another
/// passport. Returns `None` on any error / timeout / 501 / empty / not-held
/// (fail-open).
fn probe_punchcard(path: &str) -> Option<String> {
    probe_punchcard_resource(Path::new(path))
}

fn probe_punchcard_resource(path: &Path) -> Option<String> {
    let resource = format!("file://{}", path.display());
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

/// Best-effort, fire-and-forget audit-step capture: OPEN a step on the daemon
/// observe surface for this tool call (`POST /v1/observe/sessions/{id}/steps`).
/// The matching PostToolUse `observe-post` hook performs the CLOSE. Gated by
/// `CRUX_HOOK_OBSERVE_CAPTURE` (default OFF); any error / disabled surface /
/// unreachable daemon is swallowed so the hook never blocks the tool call.
fn capture_audit_step(input: &HookInput) {
    observe_capture::open(input);
}

/// Deploy-axis PreToolUse probe (B3 Part 3). Detects a deploy action, builds a
/// `deploy://<host>/<path>` punchcard resource, and probes the lease via the
/// same `check_punchcard` MCP path the file probe uses — enforcing under
/// `enforce`, warning under `advisory`, failing open on any ambiguity.
mod deploy_probe {
    use super::extract_structured;
    use crate::hook_input::HookInput;
    use crate::hook_output::PreToolUseOutput;
    use crate::mcp_client;
    use serde_json::{json, Value};

    /// Deploy-script basenames whose invocation in a `Bash` command marks the
    /// call as a deploy action. Matched as a substring so a relative or
    /// absolute path (`scripts/crux-deploy.sh`, `./deploy-train.sh`) hits.
    const DEPLOY_SCRIPTS: &[&str] = &["crux-deploy.sh", "deploy-train.sh", "cargo-deploy"];

    /// Explicit tool names that are themselves a deploy action (future deploy
    /// MCP tool). Kept alongside the Bash-script detection so both surfaces
    /// route through the same probe.
    const DEPLOY_TOOLS: &[&str] = &["crux_deploy", "deploy"];

    /// Resolve a deploy decision for this input.
    ///
    /// - `Some(deny)` — daemon clearly reports the deploy target's lease is held
    ///   by another holder AND it is in enforce mode.
    /// - `Some(allow_with_context)` — held-by-other but advisory mode: warn, do
    ///   not block.
    /// - `Some(allow)` — recognised deploy, no conflicting lease.
    /// - `None` — NOT a deploy action (or the host/resource is ambiguous): the
    ///   caller falls through to the write-tool path. This is the fail-open
    ///   branch for any ambiguity in *classification*.
    pub(super) fn decide_deploy(input: &HookInput) -> Option<PreToolUseOutput> {
        let resource = deploy_resource(input)?;
        // From here we KNOW it's a deploy. Any probe ambiguity fails open to a
        // plain allow (never None, so we don't double-dip the write path).
        Some(match probe_deploy_lease(&resource) {
            DeployVerdict::DenyEnforced(reason) => PreToolUseOutput::deny(reason),
            DeployVerdict::WarnAdvisory(reason) => PreToolUseOutput::allow_with_context(reason),
            DeployVerdict::Clear => PreToolUseOutput::allow(),
        })
    }

    /// Build the `deploy://<host>/<path>` resource for a deploy action, or
    /// `None` when the input is not recognisably a deploy. Host resolution is
    /// best-effort; an unresolved host falls back to `unknown-host` rather than
    /// dropping the probe, so an enforce-mode broad lease (`tree://deploy://…`
    /// style) can still match — but a *non*-deploy command always returns
    /// `None` (fail-open on classification).
    fn deploy_resource(input: &HookInput) -> Option<String> {
        let tool = input.tool_name.as_deref()?;
        if DEPLOY_TOOLS.contains(&tool) {
            let host = input
                .tool_input
                .as_ref()
                .and_then(|v| v.get("host"))
                .and_then(Value::as_str)
                .map_or_else(|| "unknown-host".to_string(), str::to_string);
            let path = input
                .tool_input
                .as_ref()
                .and_then(|v| v.get("path"))
                .and_then(Value::as_str)
                .unwrap_or("deploy");
            return Some(format!("deploy://{host}/{path}"));
        }
        if tool != "Bash" {
            return None;
        }
        let command = input
            .tool_input
            .as_ref()
            .and_then(|v| v.get("command"))
            .and_then(Value::as_str)?;
        let script = DEPLOY_SCRIPTS.iter().find(|s| command.contains(**s))?;
        let host = resolve_host(command);
        Some(format!("deploy://{host}/{script}"))
    }

    /// Extract a deploy target host from a deploy command. Looks, in order, for
    /// an explicit `deploy:<host>` token, a `--host <h>`/`--host=<h>` flag, or a
    /// `CRUX_SERVICE=<h>` env assignment. Falls back to `unknown-host` so the
    /// probe still runs (an enforce-mode lease keyed on the resource path can
    /// still match); classification already proved this is a deploy.
    fn resolve_host(command: &str) -> String {
        if let Some(idx) = command.find("deploy:") {
            let rest = &command[idx + "deploy:".len()..];
            let host: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
                .collect();
            if !host.is_empty() {
                return host;
            }
        }
        for (i, tok) in command.split_whitespace().enumerate() {
            if let Some(h) = tok.strip_prefix("--host=") {
                if !h.is_empty() {
                    return h.to_string();
                }
            }
            if tok == "--host" {
                if let Some(h) = command.split_whitespace().nth(i + 1) {
                    if !h.is_empty() {
                        return h.to_string();
                    }
                }
            }
            if let Some(h) = tok.strip_prefix("CRUX_SERVICE=") {
                if !h.is_empty() {
                    return h.to_string();
                }
            }
        }
        "unknown-host".to_string()
    }

    /// The three outcomes of a deploy-lease probe.
    enum DeployVerdict {
        /// Held by another holder, daemon in enforce mode → deny.
        DenyEnforced(String),
        /// Held by another holder, daemon in advisory mode → warn, allow.
        WarnAdvisory(String),
        /// No conflicting lease, or any error/ambiguity → fail open to allow.
        Clear,
    }

    /// Probe the daemon for a lease conflict on the deploy resource. Reuses the
    /// `check_punchcard` MCP tool and the `{held_by_other, enforce}` contract.
    /// Any error / timeout / 501 / empty response → `Clear` (fail-open).
    fn probe_deploy_lease(resource: &str) -> DeployVerdict {
        match mcp_client::call_tool("check_punchcard", json!({ "resource": resource, "mode": "modify" })) {
            Ok(value) => interpret_deploy_result(&value, resource),
            Err(_) => DeployVerdict::Clear,
        }
    }

    /// Interpret a `check_punchcard` result for a deploy resource. Splits on the
    /// `enforce` flag the daemon reports (it is `true` only when
    /// `CORECRUXD_PUNCHCARD=enforce`): held-by-other + enforce → deny;
    /// held-by-other + advisory → warn; anything else → clear.
    fn interpret_deploy_result(value: &Value, resource: &str) -> DeployVerdict {
        let structured = extract_structured(value);
        let obj = structured.as_ref().unwrap_or(value);
        let held_by_other = obj.get("held_by_other").and_then(Value::as_bool).unwrap_or(false);
        if !held_by_other {
            return DeployVerdict::Clear;
        }
        let enforce = obj.get("enforce").and_then(Value::as_bool).unwrap_or(false);
        let holder = obj
            .get("holder_passport")
            .and_then(Value::as_str)
            .unwrap_or("another passport");
        let res = obj.get("resource").and_then(Value::as_str).unwrap_or(resource);
        if enforce {
            DeployVerdict::DenyEnforced(format!(
                "deploy punchcard: {res} is held by {holder}; another session is deploying this target — wait for release before cutting over"
            ))
        } else {
            DeployVerdict::WarnAdvisory(format!(
                "advisory: {res} deploy lease is held by {holder}; coordinate before cutting over (CORECRUXD_PUNCHCARD=advisory, not blocking)"
            ))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;

        fn bash(command: &str) -> HookInput {
            HookInput {
                session_id: "s".into(),
                transcript_path: String::new(),
                cwd: String::new(),
                hook_event_name: "PreToolUse".into(),
                tool_name: Some("Bash".into()),
                tool_input: Some(json!({ "command": command })),
                tool_response: None,
                trigger: None,
                source: None,
            }
        }

        #[test]
        fn non_deploy_bash_is_not_classified() {
            assert!(deploy_resource(&bash("ls -la && cargo test")).is_none());
        }

        #[test]
        fn deploy_script_classified_with_explicit_host() {
            let r = deploy_resource(&bash("bash scripts/crux-deploy.sh # deploy:crux")).unwrap();
            assert_eq!(r, "deploy://crux/crux-deploy.sh");
        }

        #[test]
        fn deploy_script_host_from_flag() {
            let r = deploy_resource(&bash("./deploy-train.sh --host gpu-1")).unwrap();
            assert_eq!(r, "deploy://gpu-1/deploy-train.sh");
        }

        #[test]
        fn deploy_script_falls_back_to_unknown_host() {
            let r = deploy_resource(&bash("bash scripts/crux-deploy.sh")).unwrap();
            assert_eq!(r, "deploy://unknown-host/crux-deploy.sh");
        }

        #[test]
        fn explicit_deploy_tool_classified() {
            let input = HookInput {
                tool_name: Some("crux_deploy".into()),
                tool_input: Some(json!({ "host": "data-1", "path": "stack" })),
                ..bash("")
            };
            assert_eq!(deploy_resource(&input).unwrap(), "deploy://data-1/stack");
        }

        #[test]
        fn interpret_denies_under_enforce() {
            let held = json!({ "held_by_other": true, "enforce": true, "holder_passport": "agent:other" });
            assert!(matches!(
                interpret_deploy_result(&held, "deploy://crux/x"),
                DeployVerdict::DenyEnforced(_)
            ));
        }

        #[test]
        fn interpret_warns_under_advisory() {
            let held = json!({ "held_by_other": true, "enforce": false, "holder_passport": "agent:other" });
            assert!(matches!(
                interpret_deploy_result(&held, "deploy://crux/x"),
                DeployVerdict::WarnAdvisory(_)
            ));
        }

        #[test]
        fn interpret_clears_when_not_held_or_ambiguous() {
            let free = json!({ "held_by_other": false, "enforce": true });
            assert!(matches!(
                interpret_deploy_result(&free, "deploy://crux/x"),
                DeployVerdict::Clear
            ));
            let empty = json!({});
            assert!(matches!(
                interpret_deploy_result(&empty, "deploy://crux/x"),
                DeployVerdict::Clear
            ));
        }

        #[test]
        fn decide_deploy_fails_open_on_daemon_error() {
            // Daemon unreachable → probe errs → recognised deploy still ALLOWS.
            let _env = crate::test_support::env_guard();
            let prev = std::env::var("CRUX_MCP_URL").ok();
            std::env::set_var("CRUX_MCP_URL", "http://127.0.0.1:1/mcp");
            let out = decide_deploy(&bash("bash scripts/crux-deploy.sh # deploy:crux"));
            match prev {
                Some(v) => std::env::set_var("CRUX_MCP_URL", v),
                None => std::env::remove_var("CRUX_MCP_URL"),
            }
            let out = out.expect("recognised deploy returns a decision");
            let v = serde_json::to_value(&out).unwrap();
            assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
        }

        #[test]
        fn decide_deploy_returns_none_for_non_deploy() {
            // Not a deploy → None so the caller falls through to the write path.
            assert!(decide_deploy(&bash("echo hi")).is_none());
        }
    }
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

    fn decision_of(out: &PreToolUseDecision) -> String {
        match out {
            PreToolUseDecision::Output(output) => {
                let value = serde_json::to_value(output).unwrap();
                value["hookSpecificOutput"]["permissionDecision"]
                    .as_str()
                    .unwrap()
                    .to_string()
            }
            PreToolUseDecision::NoDecision => "no-decision".to_string(),
        }
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
        let _env = crate::test_support::env_guard();
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
    fn malformed_apply_patch_denies_before_daemon_probe() {
        let input = HookInput {
            cwd: "/tmp".into(),
            tool_name: Some(CODEX_APPLY_PATCH.into()),
            tool_input: Some(json!({"command": "not a canonical patch"})),
            ..mk_input(None, None)
        };
        assert_eq!(decision_of(&decide(&input)), "deny");
    }

    #[test]
    fn valid_apply_patch_fails_open_with_no_decision_when_daemon_unreachable() {
        let _env = crate::test_support::env_guard();
        let root = tempfile::tempdir().unwrap();
        let previous = std::env::var("CRUX_MCP_URL").ok();
        std::env::set_var("CRUX_MCP_URL", "http://127.0.0.1:1/mcp");
        let input = HookInput {
            cwd: root.path().to_string_lossy().into_owned(),
            tool_name: Some(CODEX_APPLY_PATCH.into()),
            tool_input: Some(json!({
                "command": "*** Begin Patch\n*** Add File: new.rs\n+new\n*** End Patch"
            })),
            ..mk_input(None, None)
        };
        let out = decide(&input);
        match previous {
            Some(value) => std::env::set_var("CRUX_MCP_URL", value),
            None => std::env::remove_var("CRUX_MCP_URL"),
        }
        assert_eq!(decision_of(&out), "no-decision");
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
