// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! B4 — file-modification ledger enrichment for the observe (capture) lane.
//!
//! The observe hooks already record an `edit`/`write` output per file mutation
//! ([`crate::observe_capture::outputs_for`]). B4 hardens that output with the
//! audit fields a write-side typed-action-trace ledger needs:
//!
//! - `blake3_before` / `blake3_after` — content addresses of the file before
//!   and after the mutation, so a reader can prove *which bytes* changed (and
//!   detect an out-of-band edit between two trace steps).
//! - `added` / `removed` — line-delta of the change (these reuse the existing
//!   [`crux_observe_api::TraceOutput`] `added`/`removed` schema fields, so no
//!   shared-schema change is needed for the line count).
//! - `execplan_slug` / `milestone` — the scope the mutation belongs to, so the
//!   ledger can be sliced per ExecPlan / per milestone gate.
//!
//! ## before-hash approach
//!
//! The PreToolUse (`open`) and PostToolUse (`close`) hooks run in **separate
//! processes**, so they cannot share an in-memory hash. We exploit the fact
//! that the file on disk holds the *pre-edit* bytes at open time and the
//! *post-edit* bytes at close time:
//!
//! - **`blake3_before`** is computed at `open` by hashing the on-disk file and
//!   stamped onto the OPEN output stub, so it is persisted in the projection
//!   before the edit lands.
//! - **`blake3_after`** is computed at `close` by re-hashing the (now mutated)
//!   on-disk file.
//!
//! A missing file (new `Write`) hashes to `None` for `before` (sentinel
//! `EMPTY_HASH` is *not* used so a reader can tell "no prior file" from "empty
//! file"). All hashing is best-effort: an unreadable file yields `None` and the
//! enrichment is simply absent — the step still records the `edit`/`write`
//! output and still flows the CROWN receipt.
//!
//! Everything here is reached only when `CRUX_HOOK_OBSERVE_CAPTURE` is set
//! (checked by the caller). With the flag OFF the enrichment functions are
//! never invoked and the wire body is byte-identical to the pre-B4 output.

use serde_json::{json, Value};

/// Env var naming the active ExecPlan slug for scope-stamping observations.
const EXECPLAN_SLUG_ENV: &str = "CRUX_EXECPLAN_SLUG";
/// Env var naming the active milestone (e.g. `M4`) for scope-stamping.
const MILESTONE_ENV: &str = "CRUX_MILESTONE";
/// Pointer file (relative to the session cwd) used when the env vars are unset.
/// Line 1 = slug (or `slug @ milestone`); optional line 2 = milestone.
const ACTIVE_EXECPLAN_POINTER: &str = ".crux/active-execplan";

/// Tools whose output is a file modification the ledger enriches.
pub fn is_file_mod_tool(tool: &str) -> bool {
    matches!(tool, "Write" | "Edit" | "MultiEdit" | "NotebookEdit")
}

/// blake3 of the on-disk file at `path`, as a lowercase hex string. `None` when
/// the file does not exist or cannot be read (best-effort — never panics, never
/// blocks the hook).
pub fn hash_file(path: &str) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(blake3::hash(&bytes).to_hex().to_string())
}

/// Resolve `(execplan_slug, milestone)` for the current session. Env vars win
/// (`CRUX_EXECPLAN_SLUG` / `CRUX_MILESTONE`); otherwise fall back to the
/// `.crux/active-execplan` pointer under `cwd`. Either component may be `None`.
pub fn scope(cwd: &str) -> (Option<String>, Option<String>) {
    let env_slug = non_empty(std::env::var(EXECPLAN_SLUG_ENV).ok());
    let env_ms = non_empty(std::env::var(MILESTONE_ENV).ok());
    if env_slug.is_some() || env_ms.is_some() {
        return (env_slug, env_ms);
    }
    read_pointer(cwd)
}

/// Parse the `.crux/active-execplan` pointer relative to `cwd`. Returns
/// `(slug, milestone)`; both `None` when the pointer is absent/empty/unreadable.
fn read_pointer(cwd: &str) -> (Option<String>, Option<String>) {
    if cwd.is_empty() {
        return (None, None);
    }
    let path = std::path::Path::new(cwd).join(ACTIVE_EXECPLAN_POINTER);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return (None, None);
    };
    parse_pointer(&contents)
}

/// Parse pointer-file text. Accepts either two lines (`slug` / `milestone`) or a
/// single `slug @ milestone` line. Blank lines and `#` comments are ignored.
fn parse_pointer(contents: &str) -> (Option<String>, Option<String>) {
    let mut lines = contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'));
    let Some(first) = lines.next() else {
        return (None, None);
    };
    // `slug @ milestone` on one line.
    if let Some((slug, ms)) = first.split_once('@') {
        return (
            non_empty(Some(slug.trim().to_string())),
            non_empty(Some(ms.trim().to_string())),
        );
    }
    let slug = non_empty(Some(first.to_string()));
    let ms = non_empty(lines.next().map(str::to_string));
    (slug, ms)
}

/// Count added/removed lines for a single tool's `tool_input`, best-effort.
///
/// - `Write` → all lines of the new `content` are `added`; `removed` is the line
///   count of the pre-edit file (`before`, when readable), else `0`.
/// - `Edit` → `old_string` lines `removed`, `new_string` lines `added`.
/// - `MultiEdit` → summed across `edits[]`.
/// - anything else → `(0, 0)`.
pub fn line_delta(tool: &str, tool_input: Option<&Value>, before: Option<&str>) -> (u32, u32) {
    let Some(ti) = tool_input else {
        return (0, 0);
    };
    match tool {
        "Write" => {
            let added = ti.get("content").and_then(Value::as_str).map_or(0, count_lines);
            let removed = before.map_or(0, count_lines);
            (added, removed)
        }
        "Edit" | "NotebookEdit" => edit_delta(ti),
        "MultiEdit" => ti.get("edits").and_then(Value::as_array).map_or((0, 0), |edits| {
            edits.iter().fold((0u32, 0u32), |(a, r), e| {
                let (ea, er) = edit_delta(e);
                (a.saturating_add(ea), r.saturating_add(er))
            })
        }),
        _ => (0, 0),
    }
}

/// `(added, removed)` for one Edit-shaped object (`old_string`/`new_string`).
fn edit_delta(e: &Value) -> (u32, u32) {
    let removed = e.get("old_string").and_then(Value::as_str).map_or(0, count_lines);
    let added = e.get("new_string").and_then(Value::as_str).map_or(0, count_lines);
    (added, removed)
}

/// Lines in `s`. An empty string is 0; a non-empty string has at least one line
/// even without a trailing newline (`a` → 1, `a\nb` → 2, `a\n` → 1).
fn count_lines(s: &str) -> u32 {
    if s.is_empty() {
        return 0;
    }
    u32::try_from(s.lines().count()).unwrap_or(u32::MAX)
}

/// Stamp the B4 audit fields onto a file-modification output object built by
/// [`crate::observe_capture::outputs_for`]. `out` is the `{type, ref}` object;
/// this adds `blake3_before`/`blake3_after`/`added`/`removed` and the scope
/// fields when each is available. Absent values are simply not written, so the
/// flag-OFF / unreadable-file path stays minimal.
pub fn enrich_output(
    out: &mut Value,
    blake3_before: Option<&str>,
    blake3_after: Option<&str>,
    added: u32,
    removed: u32,
    scope_slug: Option<&str>,
    milestone: Option<&str>,
) {
    if let Some(b) = blake3_before {
        out["blake3_before"] = json!(b);
    }
    if let Some(a) = blake3_after {
        out["blake3_after"] = json!(a);
    }
    // `added`/`removed` reuse the existing TraceOutput schema fields.
    out["added"] = json!(added);
    out["removed"] = json!(removed);
    if let Some(s) = scope_slug {
        out["execplan_slug"] = json!(s);
    }
    if let Some(m) = milestone {
        out["milestone"] = json!(m);
    }
}

/// Treat `Some("")`/whitespace as `None` so an empty env var or blank pointer
/// line never produces a junk slug/milestone.
fn non_empty(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write as _;

    #[test]
    fn file_mod_tool_classification() {
        for t in ["Write", "Edit", "MultiEdit", "NotebookEdit"] {
            assert!(is_file_mod_tool(t), "{t} must be a file-mod tool");
        }
        for t in ["Bash", "Read", "Grep", "mcp__crux__query"] {
            assert!(!is_file_mod_tool(t), "{t} must not be a file-mod tool");
        }
    }

    #[test]
    fn hash_file_is_blake3_and_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.txt");
        std::fs::write(&path, b"hello world").unwrap();
        let p = path.to_str().unwrap();
        let h1 = hash_file(p).unwrap();
        let h2 = hash_file(p).unwrap();
        assert_eq!(h1, h2, "same bytes hash identically");
        // Known blake3 of "hello world".
        assert_eq!(h1, blake3::hash(b"hello world").to_hex().to_string());
        // 64 hex chars (256-bit digest).
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn hash_missing_file_is_none() {
        assert!(hash_file("/nonexistent/path/does/not/exist.xyz").is_none());
    }

    #[test]
    fn count_lines_edges() {
        assert_eq!(count_lines(""), 0);
        assert_eq!(count_lines("a"), 1);
        assert_eq!(count_lines("a\nb"), 2);
        assert_eq!(count_lines("a\n"), 1);
        assert_eq!(count_lines("a\nb\nc\n"), 3);
    }

    #[test]
    fn edit_line_delta() {
        let ti = json!({ "old_string": "one\ntwo", "new_string": "ONE\nTWO\nTHREE" });
        assert_eq!(line_delta("Edit", Some(&ti), None), (3, 2));
    }

    #[test]
    fn write_line_delta_counts_content_and_before() {
        let ti = json!({ "content": "a\nb\nc" });
        // No before → removed 0.
        assert_eq!(line_delta("Write", Some(&ti), None), (3, 0));
        // With a 2-line before → removed 2.
        assert_eq!(line_delta("Write", Some(&ti), Some("x\ny")), (3, 2));
    }

    #[test]
    fn multiedit_sums_edits() {
        let ti = json!({
            "edits": [
                { "old_string": "a", "new_string": "a\nb" },        // +2 -1
                { "old_string": "x\ny\nz", "new_string": "x" },     // +1 -3
            ]
        });
        assert_eq!(line_delta("MultiEdit", Some(&ti), None), (3, 4));
    }

    #[test]
    fn unknown_tool_zero_delta() {
        assert_eq!(line_delta("Bash", Some(&json!({ "command": "ls" })), None), (0, 0));
        assert_eq!(line_delta("Edit", None, None), (0, 0));
    }

    #[test]
    fn scope_prefers_env() {
        let _env = crate::test_support::env_guard();
        let prev_slug = std::env::var(EXECPLAN_SLUG_ENV).ok();
        let prev_ms = std::env::var(MILESTONE_ENV).ok();
        std::env::set_var(EXECPLAN_SLUG_ENV, "genexec-b4-ledger");
        std::env::set_var(MILESTONE_ENV, "M4");
        let (slug, ms) = scope("/ignored/because/env/wins");
        assert_eq!(slug.as_deref(), Some("genexec-b4-ledger"));
        assert_eq!(ms.as_deref(), Some("M4"));
        restore(EXECPLAN_SLUG_ENV, prev_slug);
        restore(MILESTONE_ENV, prev_ms);
    }

    #[test]
    fn scope_empty_env_is_none_not_blank() {
        let _env = crate::test_support::env_guard();
        let prev_slug = std::env::var(EXECPLAN_SLUG_ENV).ok();
        let prev_ms = std::env::var(MILESTONE_ENV).ok();
        std::env::set_var(EXECPLAN_SLUG_ENV, "   ");
        std::env::remove_var(MILESTONE_ENV);
        // Empty env + no pointer (cwd has none) → both None.
        let (slug, ms) = scope("/no/pointer/here");
        assert!(slug.is_none());
        assert!(ms.is_none());
        restore(EXECPLAN_SLUG_ENV, prev_slug);
        restore(MILESTONE_ENV, prev_ms);
    }

    #[test]
    fn scope_falls_back_to_pointer_file() {
        let _env = crate::test_support::env_guard();
        let prev_slug = std::env::var(EXECPLAN_SLUG_ENV).ok();
        let prev_ms = std::env::var(MILESTONE_ENV).ok();
        std::env::remove_var(EXECPLAN_SLUG_ENV);
        std::env::remove_var(MILESTONE_ENV);

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".crux")).unwrap();
        let mut f = std::fs::File::create(dir.path().join(ACTIVE_EXECPLAN_POINTER)).unwrap();
        writeln!(f, "# active plan").unwrap();
        writeln!(f, "my-slug").unwrap();
        writeln!(f, "M2").unwrap();
        let (slug, ms) = scope(dir.path().to_str().unwrap());
        assert_eq!(slug.as_deref(), Some("my-slug"));
        assert_eq!(ms.as_deref(), Some("M2"));

        restore(EXECPLAN_SLUG_ENV, prev_slug);
        restore(MILESTONE_ENV, prev_ms);
    }

    #[test]
    fn pointer_single_line_at_form() {
        let (slug, ms) = parse_pointer("my-slug @ M5\n");
        assert_eq!(slug.as_deref(), Some("my-slug"));
        assert_eq!(ms.as_deref(), Some("M5"));
    }

    #[test]
    fn pointer_slug_only() {
        let (slug, ms) = parse_pointer("only-slug\n");
        assert_eq!(slug.as_deref(), Some("only-slug"));
        assert!(ms.is_none());
    }

    #[test]
    fn enrich_output_stamps_present_fields_only() {
        let mut out = json!({ "type": "edit", "ref": "/x.rs" });
        enrich_output(&mut out, Some("BEFORE"), Some("AFTER"), 5, 2, Some("slug"), Some("M1"));
        assert_eq!(out["type"], "edit");
        assert_eq!(out["ref"], "/x.rs");
        assert_eq!(out["blake3_before"], "BEFORE");
        assert_eq!(out["blake3_after"], "AFTER");
        assert_eq!(out["added"], 5);
        assert_eq!(out["removed"], 2);
        assert_eq!(out["execplan_slug"], "slug");
        assert_eq!(out["milestone"], "M1");
    }

    #[test]
    fn enrich_output_omits_absent_hashes_and_scope() {
        let mut out = json!({ "type": "write", "ref": "/new.rs" });
        enrich_output(&mut out, None, None, 3, 0, None, None);
        // added/removed always written (they're the line count); hashes/scope
        // only when present.
        assert_eq!(out["added"], 3);
        assert_eq!(out["removed"], 0);
        assert!(out.get("blake3_before").is_none());
        assert!(out.get("blake3_after").is_none());
        assert!(out.get("execplan_slug").is_none());
        assert!(out.get("milestone").is_none());
    }

    fn restore(key: &str, prev: Option<String>) {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
}
