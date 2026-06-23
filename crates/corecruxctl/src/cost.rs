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
    let body = serde_json::json!({ "tenant_id": tenant_id, "report": report });
    let mut req = agent()
        .post(&format!("{http_url}/v1/cost/report"))
        .header("content-type", "application/json");
    match &bearer {
        Some(t) => req = req.header("authorization", format!("Bearer {t}")),
        // Local dev without login: dev_scopes mode accepts a scope header.
        None => req = req.header("x-corecrux-scopes", "facts:write"),
    }
    match req.send_json(body) {
        Ok(resp) if resp.status().as_u16() < 300 => {
            println!("\nposted cost report for session '{}' → {http_url}", report.session_id);
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
