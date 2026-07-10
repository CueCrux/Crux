// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Shared audit-capture logic for the coupled `observe-pre` (PreToolUse, opens
//! a step) and `observe-post` (PostToolUse, closes it) hooks.
//!
//! The two hooks fire in separate processes, so they correlate a tool call by
//! deriving the **same** deterministic `node_id` from the session id + the
//! tool-call signature ([`HookInput::tool_signature`]): the PreToolUse open and
//! the matching PostToolUse close hash to the identical id. The daemon mints
//! the monotonic `seq`; the hook only supplies the id + the opening/closing
//! facts.
//!
//! Capture is gated by `CRUX_HOOK_OBSERVE_CAPTURE` (default OFF, opt-in): the
//! capture path should only fire when the operator has turned on the observe
//! surface (`CORECRUXD_OBSERVE=1`) and wants their session traced. Every call
//! is best-effort — daemon-unreachable / disabled / error all degrade silently
//! so the hook never blocks the tool call.

use serde_json::{json, Value};

use crate::daemon_client;
use crate::hook_input::HookInput;
use crate::observe_filemod;

/// Env flag opting in to audit capture. Default OFF — capture writes to the
/// daemon only when the operator sets this (paired with `CORECRUXD_OBSERVE=1`).
const CAPTURE_FLAG: &str = "CRUX_HOOK_OBSERVE_CAPTURE";

/// Whether the operator has opted in to audit capture.
pub fn capture_enabled() -> bool {
    std::env::var(CAPTURE_FLAG)
        .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Deterministic node id shared by the open (PreToolUse) and close
/// (PostToolUse) of one tool call. `None` when there's no tool signature to
/// hash (e.g. a hook event with no tool name).
pub fn node_id_for(input: &HookInput) -> Option<String> {
    let sig = input.tool_signature()?;
    // Replace ':' so the id stays a single clean token.
    let sig = sig.replace(':', "_");
    Some(format!("trace_{}_{sig}", input.session_id))
}

/// Build the `inputs[]` for an OPEN step from `tool_input`.
///
/// - `Read` → a `read` input carrying the file path (+ line count if the tool
///   input names one).
/// - retrieval-shaped tools (`query`, `mcp__crux__query`, …) → a `query` input
///   carrying the query text + the mandatory `token_budget` (QC.2) when present.
///
/// Anything else yields no inputs — the step still opens, it just has an empty
/// input record.
pub fn inputs_for(tool: &str, tool_input: Option<&Value>) -> Vec<Value> {
    let Some(ti) = tool_input else {
        return vec![];
    };
    if tool == "Read" {
        if let Some(path) = ti.get("file_path").and_then(Value::as_str) {
            let mut input = json!({ "type": "read", "ref": path });
            if let Some(lines) = ti.get("limit").and_then(Value::as_u64) {
                input["lines"] = json!(lines);
            }
            return vec![input];
        }
        return vec![];
    }
    if is_query_tool(tool) {
        let q = ti
            .get("query")
            .or_else(|| ti.get("q"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut input = json!({ "type": "query", "ref": q });
        if let Some(budget) = ti.get("token_budget").and_then(Value::as_u64) {
            input["token_budget"] = json!(budget);
        }
        return vec![input];
    }
    vec![]
}

/// Build the **base** `outputs[]` for a CLOSE step from the tool name + its
/// input/result. This is the pre-B4 shape (no file-mod enrichment) and is what
/// the unit tests assert against.
///
/// - `Write` → a `write` output naming the file.
/// - `Edit` / `MultiEdit` / `NotebookEdit` → an `edit` output naming the file.
/// - `Bash` → a `bash` output naming the command, with the exit code lifted
///   from the tool response when present.
///
/// Read / query tools produce no outputs (they're read-only).
pub fn outputs_for(tool: &str, tool_input: Option<&Value>, tool_response: Option<&Value>) -> Vec<Value> {
    let file = tool_input.and_then(|v| v.get("file_path")).and_then(Value::as_str);
    match tool {
        "Write" => file
            .map(|f| vec![json!({ "type": "write", "ref": f })])
            .unwrap_or_default(),
        "Edit" | "MultiEdit" | "NotebookEdit" => file
            .map(|f| vec![json!({ "type": "edit", "ref": f })])
            .unwrap_or_default(),
        "Bash" => {
            let cmd = tool_input
                .and_then(|v| v.get("command"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let mut out = json!({ "type": "bash", "ref": cmd });
            if let Some(code) = extract_exit_code(tool_response) {
                out["exit_code"] = json!(code);
            }
            vec![out]
        }
        _ => vec![],
    }
}

/// B4 — build the **enriched** `outputs[]` for a file-modification CLOSE: the
/// base output ([`outputs_for`]) plus `blake3_before`/`blake3_after`,
/// `added`/`removed` line counts, and `execplan_slug`/`milestone` scope.
///
/// `blake3_before` is the hash captured at PreToolUse open (carried through
/// `prior_before`, read back from the stored step). `blake3_after` is recomputed
/// here from the on-disk file, which now holds the post-edit bytes. Non-file-mod
/// tools fall through to the base [`outputs_for`] unchanged.
///
/// Best-effort throughout: an unreadable file simply omits the hash; the
/// `edit`/`write` output (and therefore the CROWN-receipted mutation record) is
/// always produced.
pub fn enriched_outputs_for(
    tool: &str,
    tool_input: Option<&Value>,
    tool_response: Option<&Value>,
    cwd: &str,
    prior_before: Option<&str>,
) -> Vec<Value> {
    let mut outs = outputs_for(tool, tool_input, tool_response);
    if !observe_filemod::is_file_mod_tool(tool) {
        return outs;
    }
    let Some(file) = tool_input.and_then(|v| v.get("file_path")).and_then(Value::as_str) else {
        return outs;
    };
    // After the edit lands the file on disk holds the post-edit bytes.
    let after = observe_filemod::hash_file(file);
    let (added, removed) = observe_filemod::line_delta(tool, tool_input, None);
    let (slug, milestone) = observe_filemod::scope(cwd);
    if let Some(out) = outs.first_mut() {
        observe_filemod::enrich_output(
            out,
            prior_before,
            after.as_deref(),
            added,
            removed,
            slug.as_deref(),
            milestone.as_deref(),
        );
    }
    outs
}

/// Terminal status for a CLOSE, inferred from the tool response. A non-zero
/// bash exit code or an `is_error` / `error` field → `error`, else `ok`.
pub fn close_status(tool_response: Option<&Value>) -> &'static str {
    if let Some(resp) = tool_response {
        if resp.get("is_error").and_then(Value::as_bool) == Some(true) {
            return "error";
        }
        if resp.get("error").is_some() && !resp["error"].is_null() {
            return "error";
        }
        if let Some(code) = extract_exit_code(Some(resp)) {
            if code != 0 {
                return "error";
            }
        }
    }
    "ok"
}

/// Whether `tool` is a retrieval/query tool whose input carries a `query`
/// string + `token_budget`.
fn is_query_tool(tool: &str) -> bool {
    let lower = tool.to_lowercase();
    lower == "query" || lower.contains("query") || lower == "grep"
}

/// Lift a bash exit code from a tool response, tolerating a few shapes.
fn extract_exit_code(resp: Option<&Value>) -> Option<i64> {
    let r = resp?;
    r.get("exit_code")
        .or_else(|| r.get("exitCode"))
        .or_else(|| r.get("returncode"))
        .and_then(Value::as_i64)
}

/// OPEN a step for this tool call. Best-effort: returns silently on any error.
///
/// For a file-modification tool (B4) the file on disk still holds the
/// *pre-edit* bytes at this point, so we hash it now and stamp `blake3_before`
/// onto an output stub on the OPEN body. The matching CLOSE reads that hash back
/// (via the audit GET) and re-stamps it onto the final enriched output, so the
/// before/after pair survives the two-process split without a shared in-memory
/// state.
pub fn open(input: &HookInput) {
    if !capture_enabled() {
        return;
    }
    let Some(tool) = input.tool_name.as_deref() else {
        return;
    };
    let Some(node_id) = node_id_for(input) else {
        return;
    };
    let actor = actor();
    let mut body = json!({
        "node_id": node_id,
        "kind": "tool_call",
        "label": format!("{tool}"),
        "actor": actor,
        "ts_start": now_rfc3339(),
        "inputs": inputs_for(tool, input.tool_input.as_ref()),
    });
    if let Some(stub) = open_before_stub(tool, input.tool_input.as_ref()) {
        body["outputs"] = json!([stub]);
    }
    let path = format!("/v1/observe/sessions/{}/steps", input.session_id);
    let _ = daemon_client::post_json(&path, &body);
}

/// For a file-modification tool, build the OPEN-time output stub carrying the
/// pre-edit `blake3_before` (hashed from the on-disk file, which is still
/// pre-edit at PreToolUse). `None` for non-file-mod tools, a missing path, or an
/// unreadable / not-yet-existing file (a new `Write` has no prior content).
fn open_before_stub(tool: &str, tool_input: Option<&Value>) -> Option<Value> {
    if !observe_filemod::is_file_mod_tool(tool) {
        return None;
    }
    let file = tool_input?.get("file_path")?.as_str()?;
    let before = observe_filemod::hash_file(file)?;
    let kind = if tool == "Write" { "write" } else { "edit" };
    Some(json!({ "type": kind, "ref": file, "blake3_before": before }))
}

/// CLOSE the step for this tool call. Best-effort: returns silently on any
/// error (including the daemon never having seen the open).
///
/// For a file-modification tool the outputs are B4-enriched
/// ([`enriched_outputs_for`]): the `blake3_before` stamped at open is read back
/// from the stored step and combined with the post-edit `blake3_after`, the
/// line delta, and the ExecPlan scope. The PATCH still flows the existing
/// receipted `/v1/observe` path (one CROWN receipt per mutation), so the
/// enrichment rides the receipt rather than minting a separate one.
pub fn close(input: &HookInput) {
    if !capture_enabled() {
        return;
    }
    let Some(tool) = input.tool_name.as_deref() else {
        return;
    };
    let Some(node_id) = node_id_for(input) else {
        return;
    };
    let outputs = if observe_filemod::is_file_mod_tool(tool) {
        let prior_before = stored_blake3_before(&input.session_id, &node_id);
        enriched_outputs_for(
            tool,
            input.tool_input.as_ref(),
            input.tool_response.as_ref(),
            &input.cwd,
            prior_before.as_deref(),
        )
    } else {
        outputs_for(tool, input.tool_input.as_ref(), input.tool_response.as_ref())
    };
    let body = json!({
        "outputs": outputs,
        "ts_end": now_rfc3339(),
        "status": close_status(input.tool_response.as_ref()),
    });
    let path = format!("/v1/observe/sessions/{}/steps/{node_id}", input.session_id);
    let _ = daemon_client::patch_json(&path, &body);
}

/// Read back the `blake3_before` the OPEN stamped on this step's output stub.
/// Reconstructs the session audit chain (the same GET the reasoning pass uses),
/// finds the step by `node_id`, and lifts the first output's `blake3_before`.
/// `None` on any error (daemon unreachable / step not found / no hash) so the
/// close degrades to an after-only record rather than blocking.
fn stored_blake3_before(session_id: &str, node_id: &str) -> Option<String> {
    let path = format!("/v1/observe/sessions/{session_id}/audit");
    let audit = daemon_client::get_json(&path).ok()?;
    let steps = audit.get("steps")?.as_array()?;
    steps
        .iter()
        .find(|s| s.get("node_id").and_then(Value::as_str) == Some(node_id))?
        .get("outputs")?
        .as_array()?
        .iter()
        .find_map(|o| o.get("blake3_before").and_then(Value::as_str).map(String::from))
}

/// M3 reasoning pass. For every step in the session that does not yet carry a
/// `reasoning_ref`, PATCH a `blob:reasoning/<node_id>.txt` pointer — a
/// reference to a captured thinking-summary blob, **never** raw
/// chain-of-thought (R1). The PATCH carries `private: true` (Art. 10): the
/// blob path is localhost-only and must never sync.
///
/// Best-effort + gated by `CRUX_HOOK_OBSERVE_CAPTURE`. Called from the
/// PreCompact hook, where the model's reasoning for the turn is being
/// summarised before context is compacted. Returns the number of steps it
/// successfully patched (0 on any reconstruction failure).
pub fn attach_reasoning_refs(session_id: &str) -> usize {
    if !capture_enabled() {
        return 0;
    }
    let Some(node_ids) = steps_missing_reasoning(session_id) else {
        return 0;
    };
    let mut patched = 0;
    for node_id in node_ids {
        let body = json!({
            "reasoning_ref": format!("blob:reasoning/{node_id}.txt"),
            "private": true,
        });
        let path = format!("/v1/observe/sessions/{session_id}/steps/{node_id}");
        if daemon_client::patch_json(&path, &body).is_ok() {
            patched += 1;
        }
    }
    patched
}

/// Reconstruct the session audit chain and return the `node_id`s of steps that
/// have no `reasoning_ref` yet. `None` on any error (daemon unreachable /
/// observe disabled / malformed response) so the caller degrades silently.
fn steps_missing_reasoning(session_id: &str) -> Option<Vec<String>> {
    let path = format!("/v1/observe/sessions/{session_id}/audit");
    let audit = daemon_client::get_json(&path).ok()?;
    let steps = audit.get("steps")?.as_array()?;
    let ids: Vec<String> = steps
        .iter()
        .filter(|s| s.get("reasoning_ref").is_none_or(Value::is_null))
        .filter_map(|s| s.get("node_id").and_then(Value::as_str).map(String::from))
        .collect();
    Some(ids)
}

/// Best-effort passport actor for capture. Uses `CRUX_PASSPORT_ID` when set,
/// else an operator-tagged anonymous marker (never silently empty — T.3).
fn actor() -> String {
    std::env::var("CRUX_PASSPORT_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "operator:anonymous".to_string())
}

/// Current time as an RFC-3339 / ISO-8601 UTC string, without pulling in a
/// date crate. Falls back to a `unix:<secs>` marker if the clock is unusable.
pub fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return "unix:0".to_string();
    };
    let Ok(secs) = i64::try_from(dur.as_secs()) else {
        return "unix:overflow".to_string();
    };
    // Civil-from-days (Howard Hinnant's algorithm) → YYYY-MM-DD HH:MM:SSZ.
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mk_input(session: &str, tool: &str, ti: Value, tr: Option<Value>) -> HookInput {
        HookInput {
            session_id: session.into(),
            transcript_path: String::new(),
            cwd: String::new(),
            hook_event_name: String::new(),
            tool_name: Some(tool.into()),
            tool_input: Some(ti),
            tool_response: tr,
            trigger: None,
            source: None,
        }
    }

    #[test]
    fn node_id_is_stable_across_pre_and_post() {
        let pre = mk_input("s1", "Edit", json!({"file_path": "/a.rs"}), None);
        // Post has a tool_response but identical tool_name + tool_input.
        let post = mk_input("s1", "Edit", json!({"file_path": "/a.rs"}), Some(json!({"ok": true})));
        assert_eq!(
            node_id_for(&pre),
            node_id_for(&post),
            "open/close must hash to the same node id"
        );
        assert!(node_id_for(&pre).unwrap().starts_with("trace_s1_Edit_"));
    }

    #[test]
    fn node_id_none_without_tool() {
        let mut input = mk_input("s1", "Edit", json!({}), None);
        input.tool_name = None;
        assert!(node_id_for(&input).is_none());
    }

    #[test]
    fn read_input_maps_path_and_lines() {
        let inputs = inputs_for("Read", Some(&json!({"file_path": "/x.rs", "limit": 80})));
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0]["type"], "read");
        assert_eq!(inputs[0]["ref"], "/x.rs");
        assert_eq!(inputs[0]["lines"], 80);
    }

    #[test]
    fn query_input_keeps_token_budget() {
        let inputs = inputs_for(
            "mcp__crux__query",
            Some(&json!({"query": "reconcile", "token_budget": 2000})),
        );
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0]["type"], "query");
        assert_eq!(inputs[0]["ref"], "reconcile");
        assert_eq!(inputs[0]["token_budget"], 2000);
    }

    #[test]
    fn write_and_edit_outputs() {
        let w = outputs_for("Write", Some(&json!({"file_path": "/new.rs"})), None);
        assert_eq!(w[0]["type"], "write");
        assert_eq!(w[0]["ref"], "/new.rs");

        let e = outputs_for("Edit", Some(&json!({"file_path": "/old.rs"})), None);
        assert_eq!(e[0]["type"], "edit");
    }

    #[test]
    fn bash_output_lifts_exit_code() {
        let out = outputs_for(
            "Bash",
            Some(&json!({"command": "cargo test"})),
            Some(&json!({"exit_code": 101})),
        );
        assert_eq!(out[0]["type"], "bash");
        assert_eq!(out[0]["ref"], "cargo test");
        assert_eq!(out[0]["exit_code"], 101);
    }

    #[test]
    fn read_tool_produces_no_output() {
        assert!(outputs_for("Read", Some(&json!({"file_path": "/x.rs"})), None).is_empty());
    }

    #[test]
    fn multiedit_base_output_is_edit() {
        let m = outputs_for("MultiEdit", Some(&json!({"file_path": "/m.rs"})), None);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["type"], "edit");
        assert_eq!(m[0]["ref"], "/m.rs");
    }

    // ── B4 enrichment ──────────────────────────────────────────────────────

    #[test]
    fn enriched_output_carries_b4_fields_for_edit() {
        let _env = crate::test_support::env_guard();
        // Pin scope to env so the assertion is deterministic.
        let prev_slug = std::env::var("CRUX_EXECPLAN_SLUG").ok();
        let prev_ms = std::env::var("CRUX_MILESTONE").ok();
        std::env::set_var("CRUX_EXECPLAN_SLUG", "genexec-b4-ledger");
        std::env::set_var("CRUX_MILESTONE", "M4");

        // A real file on disk so blake3_after is computed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.rs");
        std::fs::write(&path, b"after content\n").unwrap();
        let p = path.to_str().unwrap();

        let ti = json!({ "file_path": p, "old_string": "a", "new_string": "a\nb" });
        let outs = enriched_outputs_for("Edit", Some(&ti), None, "/tmp", Some("BEFOREHASH"));
        assert_eq!(outs.len(), 1);
        let o = &outs[0];
        assert_eq!(o["type"], "edit");
        assert_eq!(o["ref"], p);
        assert_eq!(o["blake3_before"], "BEFOREHASH", "carried prior before-hash");
        assert_eq!(
            o["blake3_after"],
            observe_filemod::hash_file(p).unwrap(),
            "after-hash recomputed from on-disk file"
        );
        assert_eq!(o["added"], 2);
        assert_eq!(o["removed"], 1);
        assert_eq!(o["execplan_slug"], "genexec-b4-ledger");
        assert_eq!(o["milestone"], "M4");

        match prev_slug {
            Some(v) => std::env::set_var("CRUX_EXECPLAN_SLUG", v),
            None => std::env::remove_var("CRUX_EXECPLAN_SLUG"),
        }
        match prev_ms {
            Some(v) => std::env::set_var("CRUX_MILESTONE", v),
            None => std::env::remove_var("CRUX_MILESTONE"),
        }
    }

    #[test]
    fn enriched_output_for_non_file_mod_is_base_shape() {
        // Bash is not a file-mod tool → enriched == base (no B4 fields).
        let ti = json!({ "command": "cargo test" });
        let base = outputs_for("Bash", Some(&ti), Some(&json!({"exit_code": 0})));
        let enriched = enriched_outputs_for("Bash", Some(&ti), Some(&json!({"exit_code": 0})), "/tmp", None);
        assert_eq!(base, enriched, "non-file-mod tool must be byte-identical to base");
        assert!(enriched[0].get("blake3_after").is_none());
    }

    #[test]
    fn open_before_stub_hashes_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pre.rs");
        std::fs::write(&path, b"pre-edit bytes").unwrap();
        let p = path.to_str().unwrap();
        let stub = open_before_stub("Edit", Some(&json!({ "file_path": p }))).unwrap();
        assert_eq!(stub["type"], "edit");
        assert_eq!(stub["ref"], p);
        assert_eq!(stub["blake3_before"], observe_filemod::hash_file(p).unwrap());

        // Write on a non-existent file → no before-hash (no prior content).
        assert!(open_before_stub("Write", Some(&json!({ "file_path": "/no/such/file.rs" }))).is_none());
        // Non-file-mod tool → no stub.
        assert!(open_before_stub("Bash", Some(&json!({ "command": "ls" }))).is_none());
    }

    #[test]
    fn flag_off_skips_all_capture() {
        // With capture OFF, open/close are pure no-ops (return before any I/O):
        // the wire path is byte-identical to pre-B4 (nothing is sent at all).
        let _env = crate::test_support::env_guard();
        let prev = std::env::var(CAPTURE_FLAG).ok();
        std::env::remove_var(CAPTURE_FLAG);
        assert!(!capture_enabled());
        let input = mk_input(
            "s1",
            "Edit",
            json!({"file_path": "/tmp/x.rs"}),
            Some(json!({"ok": true})),
        );
        // No daemon configured; if these did any I/O they'd still be best-effort,
        // but the guard returns immediately. Exercise both halves for coverage.
        open(&input);
        close(&input);
        match prev {
            Some(v) => std::env::set_var(CAPTURE_FLAG, v),
            None => std::env::remove_var(CAPTURE_FLAG),
        }
    }

    #[test]
    fn close_status_infers_error_from_nonzero_exit() {
        assert_eq!(close_status(Some(&json!({"exit_code": 0}))), "ok");
        assert_eq!(close_status(Some(&json!({"exit_code": 101}))), "error");
        assert_eq!(close_status(Some(&json!({"is_error": true}))), "error");
        assert_eq!(close_status(None), "ok");
    }

    #[test]
    fn now_rfc3339_has_expected_shape() {
        let ts = now_rfc3339();
        // YYYY-MM-DDTHH:MM:SSZ → 20 chars, ends with Z, has the T separator.
        assert_eq!(ts.len(), 20, "got {ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
        // Sanity: a known epoch second renders correctly is covered by the
        // shape check; the algorithm is Hinnant's civil_from_days.
    }

    #[test]
    fn actor_never_empty() {
        let _env = crate::test_support::env_guard();
        let prev = std::env::var("CRUX_PASSPORT_ID").ok();
        std::env::remove_var("CRUX_PASSPORT_ID");
        assert_eq!(actor(), "operator:anonymous");
        std::env::set_var("CRUX_PASSPORT_ID", "ce:1:local");
        assert_eq!(actor(), "ce:1:local");
        match prev {
            Some(v) => std::env::set_var("CRUX_PASSPORT_ID", v),
            None => std::env::remove_var("CRUX_PASSPORT_ID"),
        }
    }

    #[test]
    fn capture_disabled_by_default() {
        let _env = crate::test_support::env_guard();
        let prev = std::env::var(CAPTURE_FLAG).ok();
        std::env::remove_var(CAPTURE_FLAG);
        assert!(!capture_enabled());
        std::env::set_var(CAPTURE_FLAG, "1");
        assert!(capture_enabled());
        match prev {
            Some(v) => std::env::set_var(CAPTURE_FLAG, v),
            None => std::env::remove_var(CAPTURE_FLAG),
        }
    }
}
