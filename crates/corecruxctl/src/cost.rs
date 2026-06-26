// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl session cost` — the **token-burn cost lens**.
//!
//! Parses a real Claude Code transcript for ground-truth `message.usage`,
//! attributes the carried context across sources, and prints a shareable table
//! with the headline burn number and concrete reduction levers. `--json` emits
//! the machine [`CostReport`]; `--post` ships it to the daemon's
//! `/v1/cost/report` so the console `cx-cost` page can render it.
//!
//! The analysis lives in [`crux_cost`]; this module is discovery + presentation.

use std::path::{Path, PathBuf};

use crux_cost::{CostReport, Severity};

use crate::login;
use crate::machine::{agent, resolve_daemon};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// Width of the bucket bars, in cells.
const BAR_WIDTH: usize = 16;
/// Top carried-cost blocks shown in the human table.
const TABLE_TOP_BLOCKS: usize = 5;

/// `corecruxctl session cost` entry point.
pub fn run_cost(
    file: Option<String>,
    session: Option<String>,
    json: bool,
    post: bool,
    tenant: Option<String>,
    url: Option<String>,
) -> Result<(), DynErr> {
    let path = resolve_transcript(file, session)?;
    let mut report = crux_cost::analyze_file(&path)?;
    report.generated_at = Some(now_rfc3339());

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", render_table(&report));
    }

    if post {
        post_report(&report, tenant, url)?;
    }
    Ok(())
}

// ── transcript discovery ────────────────────────────────────────────────────

pub(crate) fn resolve_transcript(file: Option<String>, session: Option<String>) -> Result<PathBuf, DynErr> {
    if let Some(f) = file {
        let p = PathBuf::from(f);
        if !p.is_file() {
            return Err(format!("transcript not found: {}", p.display()).into());
        }
        return Ok(p);
    }
    let root = claude_projects_root()?;
    if let Some(sid) = session {
        find_session_file(&root, &sid)
            .ok_or_else(|| format!("no transcript for session '{sid}' under {}", root.display()).into())
    } else {
        find_newest_jsonl(&root).ok_or_else(|| format!("no transcripts found under {}", root.display()).into())
    }
}

fn claude_projects_root() -> Result<PathBuf, DynErr> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home).join(".claude").join("projects"))
}

/// Newest `.jsonl` across all project dirs (one level under `projects/`).
fn find_newest_jsonl(root: &Path) -> Option<PathBuf> {
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for dir in subdirs(root) {
        let Ok(inner) = std::fs::read_dir(&dir) else {
            continue;
        };
        for f in inner.flatten() {
            let p = f.path();
            if !is_jsonl(&p) {
                continue;
            }
            if let Some(mt) = f.metadata().ok().and_then(|md| md.modified().ok()) {
                if newest.as_ref().is_none_or(|(t, _)| mt > *t) {
                    newest = Some((mt, p));
                }
            }
        }
    }
    newest.map(|(_, p)| p)
}

/// The transcript whose file stem matches `sid`, across all project dirs.
fn find_session_file(root: &Path, sid: &str) -> Option<PathBuf> {
    for dir in subdirs(root) {
        let candidate = dir.join(format!("{sid}.jsonl"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn subdirs(root: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect()
}

fn is_jsonl(p: &Path) -> bool {
    p.extension().and_then(|e| e.to_str()) == Some("jsonl")
}

// ── posting to the daemon ───────────────────────────────────────────────────

fn post_report(report: &CostReport, tenant: Option<String>, url: Option<String>) -> Result<(), DynErr> {
    let http_url = resolve_daemon(url)?;
    let tenant_id = tenant.unwrap_or_else(|| "default".to_owned());
    let bearer = login::resolve_fresh_bearer(&http_url)?;
    post_report_to(report, &tenant_id, &http_url, bearer.as_deref(), true)
}

/// Post one report to an already-resolved daemon + bearer. `announce` prints the
/// success line (the single-shot `--post` path); the sweep silences it and keeps
/// its own tally. Reused by [`run_cost`]'s `--post` and [`run_cost_sweep`].
fn post_report_to(
    report: &CostReport,
    tenant_id: &str,
    http_url: &str,
    bearer: Option<&str>,
    announce: bool,
) -> Result<(), DynErr> {
    let body = serde_json::json!({ "tenant_id": tenant_id, "report": report });
    let mut req = agent()
        .post(&format!("{http_url}/v1/cost/report"))
        .header("content-type", "application/json");
    match bearer {
        Some(t) => req = req.header("authorization", format!("Bearer {t}")),
        // Local dev without login: dev_scopes mode accepts a scope header.
        None => req = req.header("x-corecrux-scopes", "facts:write"),
    }
    match req.send_json(body) {
        Ok(resp) if resp.status().as_u16() < 300 => {
            if announce {
                println!("\nposted cost report for session '{}' → {http_url}", report.session_id);
            }
            Ok(())
        }
        Ok(resp) => {
            let s = resp.status().as_u16();
            if s == 404 {
                return Err(format!(
                    "cost report endpoint not found (HTTP 404) — the daemon may be older than the \
                     cost lens, or CORECRUXD_FEATURE_COST_LENS is off on {http_url}"
                )
                .into());
            }
            Err(format!(
                "cost report post failed (HTTP {s}): {}",
                resp.into_body().read_to_string().unwrap_or_default()
            )
            .into())
        }
        Err(ureq::Error::StatusCode(code)) => Err(format!("cost report post failed (HTTP {code})").into()),
        Err(other) => Err(Box::new(other)),
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ── reconcile sweep ─────────────────────────────────────────────────────────

/// `corecruxctl session cost-sweep` — the **completeness** half of the capture
/// dual-trigger (the `SessionEnd` hook is the freshness half). Walks every
/// transcript under `~/.claude/projects` and posts any whose stored cost report
/// is **missing or older than the transcript's mtime**, so a hook missed on a
/// crash never loses a session. Idempotent (latest-wins per session); a fresh
/// report is left untouched.
pub fn run_cost_sweep(
    tenant: Option<String>,
    url: Option<String>,
    dry_run: bool,
    force: bool,
    since_days: u64,
) -> Result<(), DynErr> {
    let http_url = resolve_daemon(url)?;
    let tenant_id = tenant.unwrap_or_else(|| "default".to_owned());
    let bearer = login::resolve_fresh_bearer(&http_url)?;
    let stored = fetch_stored_sessions(&http_url, &tenant_id, bearer.as_deref())?;

    let root = claude_projects_root()?;
    let now = std::time::SystemTime::now();
    // Don't backfill ancient transcripts (a hook missed a month ago isn't worth
    // re-analysing). `since_days == 0` means "no window — sweep everything".
    let cutoff = (since_days > 0).then(|| now.checked_sub(std::time::Duration::from_secs(since_days * 86_400)));

    let (mut posted, mut skipped_fresh, mut skipped_old, mut failed) = (0u64, 0u64, 0u64, 0u64);
    for (path, session_id, mtime) in walk_transcripts(&root) {
        if let Some(Some(c)) = cutoff {
            if mtime < c {
                skipped_old += 1;
                continue;
            }
        }
        if !should_post(stored.get(&session_id).copied(), mtime, force) {
            skipped_fresh += 1;
            continue;
        }
        if dry_run {
            println!("would post {session_id}  ({})", path.display());
            posted += 1;
            continue;
        }
        match analyze_and_post(&path, &tenant_id, &http_url, bearer.as_deref()) {
            Ok(()) => posted += 1,
            Err(e) => {
                failed += 1;
                eprintln!("cost-sweep: {session_id} failed: {e}");
            }
        }
    }
    let verb = if dry_run { "would post" } else { "posted" };
    println!(
        "cost-sweep → {http_url} (tenant {tenant_id}): {verb} {posted}, skipped {skipped_fresh} fresh / {skipped_old} \
         outside {since_days}d, failed {failed}"
    );
    Ok(())
}

/// Analyze one transcript and post it (stamping `generated_at` like [`run_cost`]).
fn analyze_and_post(path: &Path, tenant_id: &str, http_url: &str, bearer: Option<&str>) -> Result<(), DynErr> {
    let mut report = crux_cost::analyze_file(path)?;
    report.generated_at = Some(now_rfc3339());
    post_report_to(&report, tenant_id, http_url, bearer, false)
}

/// Pure freshness decision: post when forced, when the daemon has no stored
/// report for the session, or when the transcript was modified at/after the
/// stored report's freshness timestamp (so its content changed since the last
/// analysis). A `>=` comparison re-posts a same-second change rather than risk
/// missing it.
fn should_post(stored_fresh_at: Option<std::time::SystemTime>, mtime: std::time::SystemTime, force: bool) -> bool {
    if force {
        return true;
    }
    match stored_fresh_at {
        None => true,
        Some(g) => mtime >= g,
    }
}

/// Walk every `<session>.jsonl` under `~/.claude/projects/*/`, returning
/// `(path, session_id, mtime)`. Bad entries are skipped (fails soft).
fn walk_transcripts(root: &Path) -> Vec<(PathBuf, String, std::time::SystemTime)> {
    let mut out = Vec::new();
    for dir in subdirs(root) {
        let Ok(inner) = std::fs::read_dir(&dir) else {
            continue;
        };
        for f in inner.flatten() {
            let p = f.path();
            if !is_jsonl(&p) {
                continue;
            }
            let Some(session_id) = p.file_stem().and_then(|s| s.to_str()).map(str::to_owned) else {
                continue;
            };
            let Some(mtime) = f.metadata().ok().and_then(|m| m.modified().ok()) else {
                continue;
            };
            out.push((p, session_id, mtime));
        }
    }
    out
}

/// GET the daemon's stored cost-report session picker and reduce it to
/// `session_id → freshness timestamp` (the report's `generated_at`, falling back
/// to the daemon `received_at`). A missing/disabled lens yields an empty map so
/// the first sweep posts everything.
fn fetch_stored_sessions(
    http_url: &str,
    tenant_id: &str,
    bearer: Option<&str>,
) -> Result<std::collections::HashMap<String, std::time::SystemTime>, DynErr> {
    // token_budget is mandatory (QC.2); the picker is tiny, 2000 is ample.
    let url = format!("{http_url}/v1/cost/report?tenant_id={tenant_id}&token_budget=2000");
    let mut req = agent().get(&url).header("accept", "application/json");
    match bearer {
        Some(t) => req = req.header("authorization", format!("Bearer {t}")),
        None => req = req.header("x-corecrux-scopes", "facts:read"),
    }
    let text = match req.call() {
        Ok(resp) if resp.status().as_u16() < 300 => resp.into_body().read_to_string()?,
        // A disabled/absent lens (404) or any non-2xx → treat as "nothing stored"
        // so the sweep still posts (the post path surfaces a real failure).
        Ok(_) => return Ok(std::collections::HashMap::new()),
        Err(ureq::Error::StatusCode(_)) => return Ok(std::collections::HashMap::new()),
        Err(other) => return Err(Box::new(other)),
    };
    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    Ok(parse_stored_sessions(&parsed))
}

/// Pure: reduce a `GET /v1/cost/report` body to `session_id → freshness time`.
fn parse_stored_sessions(v: &serde_json::Value) -> std::collections::HashMap<String, std::time::SystemTime> {
    let mut map = std::collections::HashMap::new();
    let Some(sessions) = v.get("sessions").and_then(|s| s.as_array()) else {
        return map;
    };
    for s in sessions {
        let Some(id) = s.get("session_id").and_then(|x| x.as_str()) else {
            continue;
        };
        let fresh = s
            .get("generated_at")
            .and_then(|x| x.as_str())
            .or_else(|| s.get("received_at").and_then(|x| x.as_str()))
            .and_then(parse_rfc3339_systemtime);
        if let Some(t) = fresh {
            map.insert(id.to_owned(), t);
        }
    }
    map
}

/// Parse an RFC3339 timestamp into a `SystemTime`. `None` on parse failure or a
/// pre-epoch instant (never expected for session timestamps).
fn parse_rfc3339_systemtime(s: &str) -> Option<std::time::SystemTime> {
    let ms = chrono::DateTime::parse_from_rfc3339(s).ok()?.timestamp_millis();
    let ms = u64::try_from(ms).ok()?;
    Some(std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms))
}

// ── rendering ───────────────────────────────────────────────────────────────

/// Render the shareable, screenshot-worthy table. Writing into a `String` via
/// `write!` is infallible, so the `Result`s are intentionally discarded.
fn render_table(r: &CostReport) -> String {
    use std::fmt::Write as _;
    let h = &r.headline;
    let mut out = String::new();
    let sid = if r.session_id.is_empty() {
        "(unknown)"
    } else {
        &r.session_id
    };
    let _ = writeln!(out, "\n  Token burn · {}", r.source);
    out.push_str("  ─────────────────────────────────────────────────────────\n");
    let _ = writeln!(out, "  session        {sid}");
    let _ = writeln!(
        out,
        "  turns / tasks  {} / {}   ·   {} compaction segment{}",
        h.assistant_turns,
        h.tasks,
        h.segments,
        if h.segments == 1 { "" } else { "s" }
    );
    let _ = writeln!(
        out,
        "  context/turn   {} tokens re-read per model call   \u{2190} headline",
        fmt_k(h.context_tokens_per_turn)
    );
    let _ = writeln!(
        out,
        "  cache replay   {:.0}\u{d7} output   ({} read \u{b7} {} generated)",
        h.cache_read_to_output_ratio,
        fmt_k(r.measured.cache_read),
        fmt_k(r.measured.output)
    );

    if !r.buckets.is_empty() {
        out.push_str("\n  Where it goes (carried context):\n");
        for b in &r.buckets {
            let offender = block_offender(r, &b.source)
                .map(|t| format!("  ({t} biggest)"))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "    {:<16} {} {:>4.0}%  {}{}",
                b.source,
                bar(b.pct),
                b.pct,
                fmt_k(b.carried_cost),
                offender
            );
        }
    }

    if !r.top_blocks.is_empty() {
        out.push_str("\n  Biggest single blocks (carried = tokens \u{d7} re-reads):\n");
        for (i, blk) in r.top_blocks.iter().take(TABLE_TOP_BLOCKS).enumerate() {
            let _ = writeln!(
                out,
                "    {}. {:>6} {:<18} \u{d7}{:<4} {}",
                i + 1,
                fmt_k(blk.carried_cost),
                blk.source,
                blk.turns_live,
                blk.preview
            );
        }
    }

    if r.levers.is_empty() {
        out.push_str("\n  No reduction levers — this session is already lean.\n");
    } else {
        let _ = writeln!(out, "\n  What you can do to reduce burn ({}):", r.levers.len());
        for lv in &r.levers {
            let _ = writeln!(out, "    {} {}", sev_badge(lv.severity), lv.title);
            for line in wrap(&lv.detail, 66) {
                let _ = writeln!(out, "           {line}");
            }
        }
    }
    out
}

fn block_offender(r: &CostReport, coarse: &str) -> Option<String> {
    if coarse == "session_prefix" {
        return None;
    }
    r.top_blocks
        .iter()
        .find(|b| b.source.split_once(':').map(|(head, _)| head) == Some(coarse) && b.tool.is_some())
        .and_then(|b| b.tool.clone())
}

fn bar(pct: f64) -> String {
    let filled = ((pct / 100.0) * BAR_WIDTH as f64).round() as usize;
    let filled = filled.min(BAR_WIDTH);
    let mut s = String::with_capacity(BAR_WIDTH * 3);
    for _ in 0..filled {
        s.push('\u{2588}');
    }
    for _ in filled..BAR_WIDTH {
        s.push('\u{2591}');
    }
    s
}

fn sev_badge(s: Severity) -> &'static str {
    match s {
        Severity::High => "\u{25cf} HIGH",
        Severity::Medium => "\u{25cf} MED ",
        Severity::Low => "\u{25cb} LOW ",
    }
}

fn fmt_k(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.0}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Greedy word-wrap to `width` columns.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn fixture_report() -> CostReport {
        // A tiny 3-turn transcript with a big tool result, so buckets + levers populate.
        let big = "x".repeat(4000);
        let lines = [
            r#"{"type":"user","sessionId":"sess-abc","message":{"role":"user","content":"do a thing"}}"#.to_owned(),
            r#"{"type":"assistant","sessionId":"sess-abc","message":{"role":"assistant","usage":{"input_tokens":50,"output_tokens":30,"cache_read_input_tokens":50000},"content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}}]}}"#.to_owned(),
            format!(
                r#"{{"type":"user","sessionId":"sess-abc","message":{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"t1","content":"{big}"}}]}}}}"#
            ),
            r#"{"type":"assistant","sessionId":"sess-abc","message":{"role":"assistant","usage":{"input_tokens":40,"output_tokens":20,"cache_read_input_tokens":80000},"content":[{"type":"text","text":"done"}]}}"#.to_owned(),
        ];
        crux_cost::analyze_str(&lines.join("\n"), "sess-abc.jsonl")
    }

    #[test]
    fn render_table_has_all_sections() {
        let table = render_table(&fixture_report());
        assert!(table.contains("Token burn · sess-abc.jsonl"));
        assert!(table.contains("headline"));
        assert!(table.contains("Where it goes"));
        assert!(table.contains("What you can do") || table.contains("already lean"));
        assert!(table.contains("session_prefix"));
    }

    #[test]
    fn render_table_never_leaks_thinking() {
        // Build a report whose transcript has thinking, ensure the table is clean.
        let lines = [
            r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":100},"content":[{"type":"thinking","thinking":"LEAKME_secret_reasoning"},{"type":"text","text":"hi"}]}}"#.to_owned(),
            r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":100},"content":[{"type":"text","text":"bye"}]}}"#.to_owned(),
        ];
        let r = crux_cost::analyze_str(&lines.join("\n"), "s.jsonl");
        assert!(!render_table(&r).contains("LEAKME_secret_reasoning"));
    }

    #[test]
    fn json_output_roundtrips() {
        let r = fixture_report();
        let s = serde_json::to_string(&r).unwrap();
        let back: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(back["schema"], crux_cost::COST_REPORT_SCHEMA);
        assert_eq!(back["session_id"], "sess-abc");
    }

    #[test]
    fn resolve_explicit_missing_file_errors() {
        let err = resolve_transcript(Some("/no/such/transcript.jsonl".to_owned()), None).unwrap_err();
        assert!(err.to_string().contains("transcript not found"));
    }

    #[test]
    fn find_session_file_by_id() {
        let root = std::env::temp_dir().join(format!("crux-cost-{}", uuid::Uuid::new_v4()));
        let proj = root.join("-some-project");
        std::fs::create_dir_all(&proj).unwrap();
        let target = proj.join("the-session.jsonl");
        std::fs::write(&target, "{}").unwrap();
        let found = find_session_file(&root, "the-session").expect("found");
        assert_eq!(found, target);
        assert!(find_session_file(&root, "missing").is_none());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn should_post_missing_stale_fresh_and_force() {
        use std::time::{Duration, UNIX_EPOCH};
        let t0 = UNIX_EPOCH + Duration::from_secs(1_000);
        let t1 = UNIX_EPOCH + Duration::from_secs(2_000);
        // No stored report → post.
        assert!(should_post(None, t0, false));
        // Transcript newer than the stored freshness time → post (stale).
        assert!(should_post(Some(t0), t1, false));
        // Same instant → post (re-post a same-second change rather than miss it).
        assert!(should_post(Some(t1), t1, false));
        // Transcript older than the stored report → skip (fresh).
        assert!(!should_post(Some(t1), t0, false));
        // Force overrides the fresh check.
        assert!(should_post(Some(t1), t0, true));
    }

    #[test]
    fn parse_stored_sessions_maps_id_to_generated_at_then_received_at() {
        let v = serde_json::json!({
            "sessions": [
                {"session_id": "a", "generated_at": "2026-06-25T10:00:00Z", "received_at": "2026-06-25T11:00:00Z"},
                {"session_id": "b", "received_at": "2026-06-25T09:00:00Z"}, // no generated_at → falls back
                {"session_id": "c"}, // no timestamp → dropped
                {"generated_at": "2026-06-25T10:00:00Z"}, // no id → dropped
            ]
        });
        let map = parse_stored_sessions(&v);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("a"), parse_rfc3339_systemtime("2026-06-25T10:00:00Z").as_ref());
        assert_eq!(map.get("b"), parse_rfc3339_systemtime("2026-06-25T09:00:00Z").as_ref());
        assert!(!map.contains_key("c"));
    }

    #[test]
    fn parse_stored_sessions_empty_when_no_sessions_key() {
        assert!(parse_stored_sessions(&serde_json::json!({"has_report": false})).is_empty());
    }

    #[test]
    fn bar_is_fixed_width() {
        assert_eq!(bar(50.0).chars().count(), BAR_WIDTH);
        assert_eq!(bar(0.0).chars().count(), BAR_WIDTH);
        assert_eq!(bar(150.0).chars().count(), BAR_WIDTH);
    }

    #[test]
    #[serial_test::serial]
    fn run_cost_posts_report_to_daemon() {
        // Clean HOME so resolve_fresh_bearer => None (the dev scope header path).
        let home = std::env::temp_dir().join(format!("crux-cost-home-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);
        let tx = std::env::temp_dir().join(format!("cost-tx-{}.jsonl", uuid::Uuid::new_v4()));
        std::fs::write(
            &tx,
            r#"{"type":"assistant","sessionId":"smoke","message":{"role":"assistant","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":1000},"content":[{"type":"text","text":"hi"}]}}"#,
        )
        .unwrap();
        let (port, h) = crate::test_support::serve_responses(vec![(201, r#"{"stored":true}"#.to_string())]);
        run_cost(
            Some(tx.to_string_lossy().into_owned()),
            None,
            false,
            true,
            Some("t1".to_owned()),
            Some(format!("http://127.0.0.1:{port}")),
        )
        .expect("run_cost --post ok");
        let reqs = h.join().unwrap();
        let body = reqs[0].splitn(2, "\r\n\r\n").nth(1).unwrap_or("");
        assert!(
            reqs[0].contains("/v1/cost/report"),
            "request head: {}",
            reqs[0].lines().next().unwrap_or("")
        );
        assert!(body.contains("t1"), "body missing tenant: {body}");
        assert!(body.contains("crux.cost.report.v1"), "body missing schema: {body}");
        std::fs::remove_file(&tx).ok();
        std::fs::remove_dir_all(&home).ok();
    }
}
