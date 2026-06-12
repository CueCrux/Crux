// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl code-health harvest` — code-intelligence harvester.
//!
//! **Ingest, don't analyze.** Every finding names the tool that produced it
//! (`cargo-check`, `machete`, `grep`, `ts-prune`/`knip`) and the `commit_sha`
//! it was measured at. We build no static analyzer of our own; we normalize
//! what compilers/linters/grep already know into a stable JSON shape that M2
//! pushes into the fact store under `entity="codehealth:<repo>"`.
//!
//! M1 scope: the tool battery + normalized JSON to stdout + fixture-driven
//! unit tests on the pure parsers. No daemon writes (that is `--push`, M2).
//!
//! The orchestration (`run_harvest`) shells out to the battery; the parsers
//! ([`parse_cargo_check`], [`parse_machete`], [`scan_markers`],
//! [`parse_ts_prune`]) are pure functions over recorded tool output so they
//! can be golden-tested without invoking the tools.

use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

/// Finding class. Stable string keys — they become fact-key prefixes in M2
/// (`dead:<file>:<line>`, `unused-dep:<crate>`, `stub:<file>:<line>`,
/// `todo:<file>:<line>`).
pub mod class {
    pub const DEAD: &str = "dead";
    pub const UNUSED_DEP: &str = "unused-dep";
    pub const STUB: &str = "stub";
    pub const TODO: &str = "todo";
}

/// One normalized code-health finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Finding class — see [`class`].
    pub class: String,
    /// Repo-relative file path (forward slashes).
    pub file: String,
    /// 1-based line; 0 when not line-scoped (e.g. an unused dependency).
    pub line: u32,
    /// Human-readable message (the tool's own text where available).
    pub message: String,
    /// Producing tool: `cargo-check`, `machete`, `grep`, `ts-prune`, `knip`.
    pub tool: String,
    /// Commit the finding was measured at (short sha).
    pub commit_sha: String,
}

/// The full harvest result — a stable envelope around the findings, suitable
/// for `--push` (M2) and golden-file diffing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Harvest {
    /// Schema tag for forward-compat.
    pub schema: String,
    /// Repo slug (the leaf dir name).
    pub repo: String,
    /// Short commit sha the harvest was measured at.
    pub commit_sha: String,
    /// Per-class counts (sorted keys for stable output).
    pub counts: std::collections::BTreeMap<String, usize>,
    /// Tools that actually ran (others were absent — recorded so a thin
    /// report is never mistaken for "clean").
    pub tools_ran: Vec<String>,
    /// Tools that were requested but not found on PATH.
    pub tools_missing: Vec<String>,
    /// All findings, deterministically sorted.
    pub findings: Vec<Finding>,
}

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// Source-marker definitions for the grep lane: (needle, class).
/// `todo!()` / `unimplemented!()` are *stubs* (compile-but-unfinished);
/// `TODO` / `FIXME` are *todo* markers; `dbg!()` is a leftover (todo class).
const MARKERS: &[(&str, &str)] = &[
    ("todo!(", class::STUB),
    ("unimplemented!(", class::STUB),
    ("unreachable!(", class::STUB),
    ("dbg!(", class::TODO),
    ("TODO", class::TODO),
    ("FIXME", class::TODO),
];

// ─────────────────────────── pure parsers ───────────────────────────

/// Parse `cargo check --message-format=json` stdout (one JSON object per
/// line) into `dead`-class findings for `dead_code` and `unused_*` lints.
///
/// Non-warning messages, build-script artifacts, and lints outside the
/// dead/unused family are ignored. Each emitted finding uses the primary
/// span (the one flagged `is_primary`, falling back to the first span).
pub fn parse_cargo_check(stdout: &str, commit_sha: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("reason").and_then(|r| r.as_str()) != Some("compiler-message") {
            continue;
        }
        let msg = match v.get("message") {
            Some(m) => m,
            None => continue,
        };
        if msg.get("level").and_then(|l| l.as_str()) != Some("warning") {
            continue;
        }
        let code = msg
            .get("code")
            .and_then(|c| c.get("code"))
            .and_then(|c| c.as_str())
            .unwrap_or("");
        if !(code == "dead_code" || code.starts_with("unused_")) {
            continue;
        }
        let spans = msg.get("spans").and_then(|s| s.as_array());
        let span = match spans.and_then(|arr| {
            arr.iter()
                .find(|s| s.get("is_primary").and_then(|p| p.as_bool()) == Some(true))
                .or_else(|| arr.first())
        }) {
            Some(s) => s,
            None => continue,
        };
        let file = span.get("file_name").and_then(|f| f.as_str()).unwrap_or("").to_string();
        let line_no = span.get("line_start").and_then(|l| l.as_u64()).unwrap_or(0) as u32;
        let text = msg.get("message").and_then(|m| m.as_str()).unwrap_or(code).to_string();
        out.push(Finding {
            class: class::DEAD.to_string(),
            file: normalize_path(&file),
            line: line_no,
            message: format!("{code}: {text}"),
            tool: "cargo-check".to_string(),
            commit_sha: commit_sha.to_string(),
        });
    }
    out
}

/// Parse `cargo machete` plain-text stdout into `unused-dep` findings.
///
/// machete prints a header line, then per-crate blocks of the form:
/// ```text
/// crate_name -- /abs/path/Cargo.toml:
///         dep_one
///         dep_two
/// ```
/// We key each finding to the manifest path; the dep name is in the message.
pub fn parse_machete(stdout: &str, commit_sha: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut current_manifest: Option<String> = None;
    for raw in stdout.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Header line: "<crate> -- <manifest>:" (ends with a colon, has " -- ").
        if let Some(idx) = trimmed.find(" -- ") {
            if trimmed.ends_with(':') {
                let manifest = trimmed[idx + 4..].trim_end_matches(':').trim();
                current_manifest = Some(normalize_path(manifest));
                continue;
            }
        }
        // A dependency line is indented (the raw line starts with whitespace)
        // and is a bare identifier under the current manifest header.
        let indented = raw.starts_with(' ') || raw.starts_with('\t');
        if indented {
            if let Some(manifest) = &current_manifest {
                let dep = trimmed;
                if is_ident(dep) {
                    out.push(Finding {
                        class: class::UNUSED_DEP.to_string(),
                        file: manifest.clone(),
                        line: 0,
                        message: format!("unused dependency: {dep}"),
                        tool: "machete".to_string(),
                        commit_sha: commit_sha.to_string(),
                    });
                }
            }
        }
    }
    out
}

/// Scan source `(repo_relative_path, content)` pairs for TODO/FIXME/stub
/// markers. Line-based substring match — the documented grep-equivalent
/// approximation (same false-positive profile as `grep -n`).
pub fn scan_markers(files: &[(String, String)], commit_sha: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (path, content) in files {
        for (i, raw_line) in content.lines().enumerate() {
            // Only flag the first matching marker per line (most specific wins:
            // MARKERS is ordered stub-macros before bare TODO/FIXME).
            for (needle, klass) in MARKERS {
                if raw_line.contains(needle) {
                    out.push(Finding {
                        class: (*klass).to_string(),
                        file: normalize_path(path),
                        line: (i + 1) as u32,
                        message: format!("{}: {}", needle.trim_end_matches('('), raw_line.trim()),
                        tool: "grep".to_string(),
                        commit_sha: commit_sha.to_string(),
                    });
                    break;
                }
            }
        }
    }
    out
}

/// Parse `ts-prune` stdout (`path:line - symbol [(comment)]`) into `dead`
/// findings, tooled `ts-prune`. Lines flagged `(used in module)` are not
/// dead exports and are skipped.
pub fn parse_ts_prune(stdout: &str, commit_sha: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.contains("(used in module)") {
            continue;
        }
        // Format: "<path>:<line> - <symbol>"
        let (loc, symbol) = match line.split_once(" - ") {
            Some(p) => p,
            None => continue,
        };
        let (file, line_no) = match loc.rsplit_once(':') {
            Some((f, n)) => (f, n.trim().parse::<u32>().unwrap_or(0)),
            None => continue,
        };
        out.push(Finding {
            class: class::DEAD.to_string(),
            file: normalize_path(file),
            line: line_no,
            message: format!("unused export: {}", symbol.trim()),
            tool: "ts-prune".to_string(),
            commit_sha: commit_sha.to_string(),
        });
    }
    out
}

// ─────────────────────────── helpers ───────────────────────────

fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Normalize a path to forward slashes and strip a leading `./`.
fn normalize_path(p: &str) -> String {
    let p = p.replace('\\', "/");
    p.strip_prefix("./").unwrap_or(&p).to_string()
}

/// Sort findings into a deterministic order for stable JSON / golden diffs.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.class
            .cmp(&b.class)
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
            .then(a.message.cmp(&b.message))
            .then(a.tool.cmp(&b.tool))
    });
}

/// Build the [`Harvest`] envelope from a finding set (counts + sort).
pub fn build_harvest(
    repo: &str,
    commit_sha: &str,
    mut findings: Vec<Finding>,
    tools_ran: Vec<String>,
    tools_missing: Vec<String>,
) -> Harvest {
    sort_findings(&mut findings);
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for f in &findings {
        *counts.entry(f.class.clone()).or_insert(0) += 1;
    }
    Harvest {
        schema: "codehealth.v1".to_string(),
        repo: repo.to_string(),
        commit_sha: commit_sha.to_string(),
        counts,
        tools_ran,
        tools_missing,
        findings,
    }
}

// ─────────────────────────── orchestration ───────────────────────────

/// Short commit sha of `repo` (`git rev-parse --short HEAD`), or `unknown`.
pub fn short_sha(repo: &Path) -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(repo)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn repo_slug(repo: &Path) -> String {
    repo.canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "repo".to_string())
}

fn tool_exists(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Walk a repo collecting `(repo_relative_path, content)` for source files we
/// grep-scan. Skips `target/`, `node_modules/`, `.git/`, and vendored trees.
fn collect_source_files(repo: &Path) -> Vec<(String, String)> {
    fn is_skipped(name: &str) -> bool {
        matches!(
            name,
            "target" | "node_modules" | ".git" | "dist" | "build" | "vendor" | ".worktrees"
        )
    }
    fn scannable(ext: &str) -> bool {
        matches!(ext, "rs" | "ts" | "tsx" | "js" | "mjs" | "cjs")
    }
    let mut out = Vec::new();
    let mut stack = vec![repo.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if !is_skipped(&name) && !name.starts_with('.') {
                    stack.push(path);
                }
                continue;
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !scannable(ext) {
                continue;
            }
            let rel = path.strip_prefix(repo).unwrap_or(&path).to_string_lossy().to_string();
            if let Ok(content) = std::fs::read_to_string(&path) {
                out.push((rel, content));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Run the full battery over `repo` and return the harvest envelope.
pub fn harvest(repo: &Path) -> Result<Harvest, DynErr> {
    if !repo.exists() {
        return Err(format!("repo does not exist: {}", repo.display()).into());
    }
    let commit_sha = short_sha(repo);
    let slug = repo_slug(repo);
    let mut findings: Vec<Finding> = Vec::new();
    let mut tools_ran: Vec<String> = Vec::new();
    let mut tools_missing: Vec<String> = Vec::new();

    let has_cargo = repo.join("Cargo.toml").exists();
    let has_package = repo.join("package.json").exists();

    // ── cargo check (dead_code + unused_*) ──
    if has_cargo && tool_exists("cargo") {
        match Command::new("cargo")
            .args(["check", "--workspace", "--message-format=json", "--quiet"])
            .current_dir(repo)
            .output()
        {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                findings.extend(parse_cargo_check(&stdout, &commit_sha));
                tools_ran.push("cargo-check".to_string());
            }
            Err(_) => tools_missing.push("cargo-check".to_string()),
        }
    } else if has_cargo {
        tools_missing.push("cargo-check".to_string());
    }

    // ── cargo machete (unused deps) ──
    if has_cargo {
        if tool_exists("cargo-machete") {
            if let Ok(o) = Command::new("cargo").args(["machete"]).current_dir(repo).output() {
                let stdout = String::from_utf8_lossy(&o.stdout);
                findings.extend(parse_machete(&stdout, &commit_sha));
                tools_ran.push("machete".to_string());
            }
        } else {
            tools_missing.push("machete".to_string());
        }
    }

    // ── grep markers (always; pure filesystem) ──
    let files = collect_source_files(repo);
    findings.extend(scan_markers(&files, &commit_sha));
    tools_ran.push("grep".to_string());

    // ── ts-prune (unused TS exports) ──
    if has_package {
        if tool_exists("ts-prune") {
            if let Ok(o) = Command::new("ts-prune").current_dir(repo).output() {
                let stdout = String::from_utf8_lossy(&o.stdout);
                findings.extend(parse_ts_prune(&stdout, &commit_sha));
                tools_ran.push("ts-prune".to_string());
            }
        } else {
            tools_missing.push("ts-prune".to_string());
        }
    }

    Ok(build_harvest(&slug, &commit_sha, findings, tools_ran, tools_missing))
}

/// CLI entry point for `corecruxctl code-health harvest`.
pub fn run_harvest(repo: &Path, format: &str) -> Result<(), DynErr> {
    let result = harvest(repo)?;
    match format {
        "text" => {
            println!("Code Health — {} @ {}", result.repo, result.commit_sha);
            println!("=========================================");
            for (klass, n) in &result.counts {
                println!("  {klass:<12} {n}");
            }
            println!("  tools ran:     {}", result.tools_ran.join(", "));
            if !result.tools_missing.is_empty() {
                println!("  tools missing: {}", result.tools_missing.join(", "));
            }
            println!();
            for f in &result.findings {
                let loc = if f.line == 0 {
                    f.file.clone()
                } else {
                    format!("{}:{}", f.file, f.line)
                };
                println!("  [{}] {} — {} ({})", f.class, loc, f.message, f.tool);
            }
        }
        _ => {
            let json = serde_json::to_string_pretty(&result)?;
            println!("{json}");
        }
    }
    Ok(())
}

// ─────────────────────── fact ingest (M2 `--push`) ───────────────────────
//
// Findings become facts under `entity="codehealth:<repo>"`. Each finding key
// is stable (`<class>:<file>:<line>`) so a re-harvest of an unchanged finding
// writes the same (entity,key) and the fact store auto-supersedes the prior
// version (version chain = history). A finding that has been *resolved* is no
// longer emitted, so it would otherwise linger as "current" — `push` diffs the
// store's current keys against the fresh harvest and `DELETE`s the resolved
// ones, then writes one `run:<date>` summary. All writes go through the daemon
// HTTP API (receipted, passport-attributed) — never raw FS.

/// Stable fact key for a finding. Line-scoped findings use
/// `<class>:<file>:<line>`; unused-dep (line 0) appends the crate name so each
/// dependency is keyed uniquely under its manifest.
pub fn fact_key(f: &Finding) -> String {
    if f.class == class::UNUSED_DEP {
        let dep = f.message.rsplit(' ').next().unwrap_or(f.message.as_str());
        format!("unused-dep:{}:{}", f.file, dep)
    } else {
        format!("{}:{}:{}", f.class, f.file, f.line)
    }
}

/// Compact JSON value stored for a finding (carries tool + sha + message so the
/// console tab can render provenance without a second lookup).
fn finding_value(f: &Finding) -> String {
    serde_json::json!({
        "class": f.class,
        "file": f.file,
        "line": f.line,
        "message": f.message,
        "tool": f.tool,
        "commit_sha": f.commit_sha,
    })
    .to_string()
}

/// Build the `/v1/facts/bulk` body for a harvest — one `volatile` fact per
/// finding under `entity`.
pub fn finding_facts(entity: &str, h: &Harvest) -> Vec<serde_json::Value> {
    h.findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "entity": entity,
                "key": fact_key(f),
                "value": finding_value(f),
                "horizon_class": "volatile",
                "confidence": 1.0,
            })
        })
        .collect()
}

/// Build the `run:<date>` summary fact (`medium` horizon — counts move daily
/// but the run record is the audit trail, not a per-finding count).
pub fn run_summary_fact(entity: &str, h: &Harvest, date: &str, resolved: usize) -> serde_json::Value {
    let value = serde_json::json!({
        "commit_sha": h.commit_sha,
        "counts": h.counts,
        "resolved": resolved,
        "total": h.findings.len(),
        "tools_ran": h.tools_ran,
        "tools_missing": h.tools_missing,
    })
    .to_string();
    serde_json::json!({
        "entity": entity,
        "key": format!("run:{date}"),
        "value": value,
        "horizon_class": "medium",
        "confidence": 1.0,
    })
}

/// True for finding-class keys (`dead:`, `unused-dep:`, `stub:`, `todo:`,
/// `dark:`). Excludes `run:<date>` summaries and any unrelated key, which the
/// reconciler must never touch.
pub fn is_finding_key(key: &str) -> bool {
    key.starts_with("dead:")
        || key.starts_with("unused-dep:")
        || key.starts_with("stub:")
        || key.starts_with("todo:")
        || key.starts_with("dark:")
}

/// The minimal write/delete set to make the store reflect exactly the current
/// finding set + a fresh `run:<date>` summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconcilePlan {
    /// Finding facts to PUT (`/v1/facts/bulk`).
    pub write: Vec<serde_json::Value>,
    /// Fact ids to DELETE (resolved findings, changed values, dup versions,
    /// and the prior same-day `run:` copies).
    pub delete: Vec<String>,
    /// Distinct finding keys already current with the same value (skipped).
    pub unchanged: usize,
    /// Distinct finding keys retired (present in store, absent from harvest).
    pub retired: usize,
}

/// Pure reconcile. `existing` = `(key, fact_id, value)` for *every* current
/// fact under the entity (the entity endpoint returns all versions). The
/// daemon's auto-version-chain does not hide superseded versions from queries,
/// so for these machine-generated volatile findings we reconcile to a
/// desired-state set: skip unchanged, delete stale/changed/duplicate, write
/// new. `run:<other-day>` keys are left untouched (audit history); `run:<date>`
/// for today is dropped so `push` can rewrite one fresh.
pub fn reconcile_plan(entity: &str, h: &Harvest, date: &str, existing: &[(String, String, String)]) -> ReconcilePlan {
    let run_key = format!("run:{date}");
    let desired: std::collections::BTreeMap<String, String> =
        h.findings.iter().map(|f| (fact_key(f), finding_value(f))).collect();

    let mut delete = Vec::new();
    let mut kept: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut retired_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for (key, id, value) in existing {
        if key == &run_key {
            delete.push(id.clone()); // drop stale same-day run copies; rewrite fresh
            continue;
        }
        if !is_finding_key(key) {
            continue; // run:<other-day> or unrelated — history, leave alone
        }
        match desired.get(key) {
            None => {
                delete.push(id.clone());
                retired_keys.insert(key.clone());
            }
            Some(want) if want == value && !kept.contains(key) => {
                kept.insert(key.clone()); // keep exactly one matching current fact
            }
            Some(_) => delete.push(id.clone()), // changed value or duplicate of a kept key
        }
    }

    let write: Vec<serde_json::Value> = desired
        .iter()
        .filter(|(key, _)| !kept.contains(key.as_str()))
        .map(|(key, value)| {
            serde_json::json!({
                "entity": entity,
                "key": key,
                "value": value,
                "horizon_class": "volatile",
                "confidence": 1.0,
            })
        })
        .collect();

    ReconcilePlan {
        write,
        delete,
        unchanged: kept.len(),
        retired: retired_keys.len(),
    }
}

/// Summary of a `--push` run, for the CLI report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PushReport {
    pub entity: String,
    pub written: usize,
    pub unchanged: usize,
    pub retired: usize,
    pub run_key: String,
}

fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .into()
}

fn with_bearer(
    mut req: ureq::RequestBuilder<ureq::typestate::WithoutBody>,
    token: Option<&str>,
) -> ureq::RequestBuilder<ureq::typestate::WithoutBody> {
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    req
}

fn with_bearer_body(
    mut req: ureq::RequestBuilder<ureq::typestate::WithBody>,
    token: Option<&str>,
) -> ureq::RequestBuilder<ureq::typestate::WithBody> {
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    req
}

/// GET every current `(key, fact_id, value)` triple for an entity (all
/// versions; the daemon's entity endpoint does not collapse the version chain).
fn fetch_entity_facts(
    agent: &ureq::Agent,
    base: &str,
    token: Option<&str>,
    entity: &str,
) -> Result<Vec<(String, String, String)>, DynErr> {
    let url = format!(
        "{}/v1/facts/entity/{}",
        base.trim_end_matches('/'),
        urlencoding::encode(entity)
    );
    let resp = with_bearer(agent.get(&url), token).call()?;
    let body = resp.into_body().read_to_string()?;
    let parsed: serde_json::Value = serde_json::from_str(&body)?;
    let mut out = Vec::new();
    if let Some(arr) = parsed.get("facts").and_then(|f| f.as_array()) {
        for f in arr {
            if f.get("deleted").and_then(|d| d.as_bool()) == Some(true) {
                continue;
            }
            let key = f.get("key").and_then(|k| k.as_str()).unwrap_or("").to_string();
            let id = f
                .get("fact_id")
                .or_else(|| f.get("id"))
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            let value = f.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if !key.is_empty() && !id.is_empty() {
                out.push((key, id, value));
            }
        }
    }
    Ok(out)
}

fn delete_fact(agent: &ureq::Agent, base: &str, token: Option<&str>, id: &str) -> Result<(), DynErr> {
    let url = format!("{}/v1/facts/{}", base.trim_end_matches('/'), urlencoding::encode(id));
    with_bearer(agent.delete(&url), token).call()?;
    Ok(())
}

fn put_json(
    agent: &ureq::Agent,
    url: &str,
    token: Option<&str>,
    body: serde_json::Value,
    what: &str,
) -> Result<(), DynErr> {
    let resp = with_bearer_body(agent.put(url), token).send_json(body)?;
    let status = resp.status().as_u16();
    if status >= 400 {
        let err_body = resp.into_body().read_to_string().unwrap_or_default();
        return Err(format!("{what} failed ({status}): {err_body}").into());
    }
    Ok(())
}

/// Harvest `repo` and reconcile the result into the daemon at `base`: delete
/// resolved/changed/duplicate finding facts, write new ones, and refresh the
/// `run:<date>` summary. Idempotent — a no-change re-harvest writes nothing but
/// the run summary.
pub fn push(repo: &Path, base: &str, token: Option<&str>, date: &str) -> Result<PushReport, DynErr> {
    let h = harvest(repo)?;
    let entity = format!("codehealth:{}", h.repo);
    let agent = http_agent();

    let existing = fetch_entity_facts(&agent, base, token, &entity)?;
    let plan = reconcile_plan(&entity, &h, date, &existing);

    for id in &plan.delete {
        delete_fact(&agent, base, token, id)?;
    }
    if !plan.write.is_empty() {
        let url = format!("{}/v1/facts/bulk", base.trim_end_matches('/'));
        put_json(&agent, &url, token, serde_json::json!(plan.write), "bulk fact write")?;
    }

    let run_key = format!("run:{date}");
    let summary = run_summary_fact(&entity, &h, date, plan.retired);
    let url = format!("{}/v1/facts", base.trim_end_matches('/'));
    put_json(&agent, &url, token, summary, "run-summary write")?;

    Ok(PushReport {
        entity,
        written: plan.write.len(),
        unchanged: plan.unchanged,
        retired: plan.retired,
        run_key,
    })
}

/// Resolve the daemon bearer token: explicit `--token-file`, then
/// `CRUX_AGENT_TOKEN`, then the conventional `anthropic.jwt` passport file.
pub(crate) fn resolve_token(token_file: Option<&Path>) -> Option<String> {
    if let Some(p) = token_file {
        if let Ok(s) = std::fs::read_to_string(p) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    if let Ok(s) = std::env::var("CRUX_AGENT_TOKEN") {
        if !s.is_empty() {
            return Some(s);
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let p = Path::new(&home).join(".config/cuecrux/crux-tokens/anthropic.jwt");
        if let Ok(s) = std::fs::read_to_string(p) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

/// CLI entry for `code-health harvest --push`.
pub fn run_push(repo: &Path, base: &str, token_file: Option<&Path>) -> Result<(), DynErr> {
    let token = resolve_token(token_file);
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let report = push(repo, base, token.as_deref(), &date)?;
    println!(
        "{}: {} written, {} unchanged, {} retired; summary {}",
        report.entity, report.written, report.unchanged, report.retired, report.run_key
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARGO_CHECK_FIXTURE: &str = include_str!("../tests/fixtures_code_health/cargo_check.jsonl");
    const MACHETE_FIXTURE: &str = include_str!("../tests/fixtures_code_health/machete.txt");
    const TS_PRUNE_FIXTURE: &str = include_str!("../tests/fixtures_code_health/ts_prune.txt");

    #[test]
    fn cargo_check_extracts_dead_and_unused() {
        let f = parse_cargo_check(CARGO_CHECK_FIXTURE, "abc1234");
        // Fixture has: one dead_code, one unused_variables, one unused_imports,
        // plus a non-warning (build-finished) and an unrelated lint to ignore.
        assert_eq!(f.len(), 3, "expected 3 dead/unused findings, got {f:?}");
        assert!(f.iter().all(|x| x.class == class::DEAD));
        assert!(f.iter().all(|x| x.tool == "cargo-check"));
        assert!(f.iter().all(|x| x.commit_sha == "abc1234"));
        let dead = f
            .iter()
            .find(|x| x.message.starts_with("dead_code"))
            .expect("dead_code present");
        assert_eq!(dead.file, "crates/corecruxd/src/work.rs");
        assert_eq!(dead.line, 412);
    }

    #[test]
    fn cargo_check_ignores_non_dead_lints_and_non_warnings() {
        // A clippy lint + an error-level message must not appear.
        let f = parse_cargo_check(CARGO_CHECK_FIXTURE, "abc1234");
        assert!(f.iter().all(|x| !x.message.contains("needless_return")));
        assert!(f.iter().all(|x| !x.message.contains("mismatched types")));
    }

    #[test]
    fn machete_extracts_unused_deps() {
        let f = parse_machete(MACHETE_FIXTURE, "abc1234");
        assert_eq!(f.len(), 3, "expected 3 unused deps, got {f:?}");
        assert!(f.iter().all(|x| x.class == class::UNUSED_DEP));
        assert!(f.iter().all(|x| x.line == 0));
        assert!(f
            .iter()
            .any(|x| x.message == "unused dependency: regex" && x.file == "crates/corecruxd/Cargo.toml"));
        assert!(f
            .iter()
            .any(|x| x.message == "unused dependency: once_cell" && x.file == "crates/corecrux-types/Cargo.toml"));
    }

    #[test]
    fn markers_classify_stub_vs_todo() {
        let files = vec![(
            "crates/x/src/lib.rs".to_string(),
            "fn a() { todo!(\"later\") }\n// TODO: rename\nfn b() { unimplemented!() }\nlet _ = dbg!(x);\n// FIXME broken\nok();\n"
                .to_string(),
        )];
        let f = scan_markers(&files, "abc1234");
        let stubs: Vec<_> = f.iter().filter(|x| x.class == class::STUB).collect();
        let todos: Vec<_> = f.iter().filter(|x| x.class == class::TODO).collect();
        assert_eq!(stubs.len(), 2, "todo!() + unimplemented!() are stubs: {f:?}");
        assert_eq!(todos.len(), 3, "TODO + dbg!() + FIXME are todos: {f:?}");
        assert!(f.iter().all(|x| x.tool == "grep"));
        // line numbers are 1-based
        assert_eq!(stubs[0].line, 1);
    }

    #[test]
    fn ts_prune_extracts_unused_exports_skips_used_in_module() {
        let f = parse_ts_prune(TS_PRUNE_FIXTURE, "abc1234");
        assert_eq!(f.len(), 2, "expected 2 unused exports, got {f:?}");
        assert!(f.iter().all(|x| x.class == class::DEAD && x.tool == "ts-prune"));
        assert!(f
            .iter()
            .any(|x| x.file == "sdks/typescript/src/client.ts" && x.line == 42));
        // the "(used in module)" line must be skipped
        assert!(f.iter().all(|x| !x.message.contains("internalHelper")));
    }

    #[test]
    fn build_harvest_is_deterministic_and_counts() {
        let findings = vec![
            Finding {
                class: class::TODO.into(),
                file: "b.rs".into(),
                line: 9,
                message: "TODO: x".into(),
                tool: "grep".into(),
                commit_sha: "s".into(),
            },
            Finding {
                class: class::DEAD.into(),
                file: "a.rs".into(),
                line: 3,
                message: "dead_code: y".into(),
                tool: "cargo-check".into(),
                commit_sha: "s".into(),
            },
            Finding {
                class: class::DEAD.into(),
                file: "a.rs".into(),
                line: 1,
                message: "dead_code: z".into(),
                tool: "cargo-check".into(),
                commit_sha: "s".into(),
            },
        ];
        let h = build_harvest(
            "corecruxd",
            "s",
            findings,
            vec!["cargo-check".into(), "grep".into()],
            vec![],
        );
        // sorted: dead a.rs:1, dead a.rs:3, todo b.rs:9
        assert_eq!(h.findings[0].line, 1);
        assert_eq!(h.findings[1].line, 3);
        assert_eq!(h.findings[2].class, class::TODO);
        assert_eq!(h.counts.get("dead"), Some(&2));
        assert_eq!(h.counts.get("todo"), Some(&1));
        assert_eq!(h.schema, "codehealth.v1");
    }

    #[test]
    fn json_envelope_round_trips() {
        let h = build_harvest("r", "s", vec![], vec!["grep".into()], vec!["machete".into()]);
        let json = serde_json::to_string(&h).expect("serialize");
        let back: Harvest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(h, back);
    }

    fn finding(class: &str, file: &str, line: u32, msg: &str) -> Finding {
        Finding {
            class: class.into(),
            file: file.into(),
            line,
            message: msg.into(),
            tool: "grep".into(),
            commit_sha: "s".into(),
        }
    }

    #[test]
    fn fact_key_is_stable_and_unique() {
        assert_eq!(fact_key(&finding(class::DEAD, "a.rs", 12, "x")), "dead:a.rs:12");
        let dep = Finding {
            class: class::UNUSED_DEP.into(),
            file: "crates/x/Cargo.toml".into(),
            line: 0,
            message: "unused dependency: regex".into(),
            tool: "machete".into(),
            commit_sha: "s".into(),
        };
        assert_eq!(fact_key(&dep), "unused-dep:crates/x/Cargo.toml:regex");
    }

    #[test]
    fn reconcile_skips_unchanged_writes_changed_retires_resolved() {
        // Harvest: dead:a.rs:1 (unchanged) + todo:c.rs:5 (new). Store also has
        // a stale dup of dead:a.rs:1, a resolved todo:b.rs:9, a run:<today> to
        // refresh, and a run:<otherday> to leave alone.
        let h = build_harvest(
            "r",
            "sha",
            vec![
                finding(class::DEAD, "a.rs", 1, "dead_code: x"),
                finding(class::TODO, "c.rs", 5, "TODO: new"),
            ],
            vec!["grep".into()],
            vec![],
        );
        let unchanged_val = finding_value(&finding(class::DEAD, "a.rs", 1, "dead_code: x"));
        let existing = vec![
            ("dead:a.rs:1".to_string(), "f_keep".to_string(), unchanged_val),
            (
                "dead:a.rs:1".to_string(),
                "f_dupstale".to_string(),
                "{\"old\":true}".to_string(),
            ),
            ("todo:b.rs:9".to_string(), "f_resolved".to_string(), "{}".to_string()),
            ("run:2026-06-12".to_string(), "f_runtoday".to_string(), "{}".to_string()),
            ("run:2026-06-01".to_string(), "f_runold".to_string(), "{}".to_string()),
        ];
        let plan = reconcile_plan("codehealth:r", &h, "2026-06-12", &existing);
        assert_eq!(plan.write.len(), 1, "only the new finding is written");
        assert_eq!(plan.write[0]["key"], "todo:c.rs:5");
        assert_eq!(plan.unchanged, 1); // dead:a.rs:1 kept via f_keep
        assert_eq!(plan.retired, 1); // todo:b.rs:9
        assert!(plan.delete.contains(&"f_dupstale".to_string()));
        assert!(plan.delete.contains(&"f_resolved".to_string()));
        assert!(plan.delete.contains(&"f_runtoday".to_string()));
        assert!(
            !plan.delete.contains(&"f_runold".to_string()),
            "other-day run is history"
        );
        assert!(!plan.delete.contains(&"f_keep".to_string()));
    }

    #[test]
    fn is_finding_key_excludes_run_and_unrelated() {
        assert!(is_finding_key("dead:a.rs:1"));
        assert!(is_finding_key("unused-dep:Cargo.toml:regex"));
        assert!(!is_finding_key("run:2026-06-12"));
        assert!(!is_finding_key("decision:foo"));
    }

    #[test]
    fn finding_facts_carry_entity_volatile_horizon_and_provenance() {
        let h = build_harvest(
            "corecruxd",
            "abc1234",
            vec![finding(class::TODO, "b.rs", 9, "TODO: x")],
            vec!["grep".into()],
            vec![],
        );
        let facts = finding_facts("codehealth:corecruxd", &h);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0]["entity"], "codehealth:corecruxd");
        assert_eq!(facts[0]["key"], "todo:b.rs:9");
        assert_eq!(facts[0]["horizon_class"], "volatile");
        // value carries tool + sha so the tab renders provenance without a 2nd lookup
        let v: serde_json::Value = serde_json::from_str(facts[0]["value"].as_str().unwrap()).unwrap();
        assert_eq!(v["tool"], "grep");
        assert_eq!(v["commit_sha"], "s"); // the finding's own measured-at sha
    }

    #[test]
    fn run_summary_is_medium_horizon_with_counts() {
        let h = build_harvest(
            "corecruxd",
            "abc1234",
            vec![finding(class::TODO, "b.rs", 9, "TODO: x")],
            vec!["grep".into()],
            vec!["machete".into()],
        );
        let s = run_summary_fact("codehealth:corecruxd", &h, "2026-06-12", 3);
        assert_eq!(s["key"], "run:2026-06-12");
        assert_eq!(s["horizon_class"], "medium");
        let v: serde_json::Value = serde_json::from_str(s["value"].as_str().unwrap()).unwrap();
        assert_eq!(v["resolved"], 3);
        assert_eq!(v["total"], 1);
        assert_eq!(v["counts"]["todo"], 1);
        assert_eq!(v["tools_missing"][0], "machete");
    }
}
