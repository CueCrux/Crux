// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! ExecPlan aggregator — read-time projection of `*.md` plan files under
//! `$CRUX_EXECPLANS_ROOT` plus per-slug facts into the same [`WorkItem`] shape
//! consumed by the kanban `/v1/work` path.
//!
//! Data-flow split:
//!
//! ```text
//! walk_execplans_root(root)         -> Vec<ExecplanFile>      (IO)
//! parse_plan(file.content)          -> ParsedPlan             (pure)
//! summarise_facts(facts_for_slug)   -> ExecplanFactSummary    (pure)
//! derive_state(file, parsed, sum, now) -> WorkItem            (pure)
//! ```
//!
//! `derive_state` is the deterministic state machine — six rules, no LLM, no
//! filesystem, no fact-store. The HTTP layer (M2) is responsible for binding
//! the IO surface; M1 ships the data-flow + unit tests.
//!
//! State derivation rules (in order; first match wins):
//!
//! 1. `parsed.status_line` contains "archived"            → `archive`
//! 2. `parsed.superseded_by` is set                       → `archive` + `superseded_by`
//! 3. `parsed.status_line` contains "complete"            → `complete`
//! 4. all declared milestones have a gate fact `status=complete` → `complete`
//! 5. highest milestone with a fact has gate `status=blocked`    → `blocked`
//! 6. any milestone/gate fact exists                      → `in_progress`
//! 7. no facts, file mtime ≤ 90 days old                  → `planned`
//! 8. no facts, file mtime > 90 days old                  → `archive`

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use chrono::{DateTime, Utc};
use corecrux_memory::fact_store::{FactQuery, FactStore};

use crate::fact_helpers::dedup_latest;
use crate::work::WorkItem;

/// Env var that resolves the plan root for the aggregator. Unset → no plans.
pub const EXECPLANS_ROOT_ENV: &str = "CRUX_EXECPLANS_ROOT";

/// Entity prefix under which ExecPlan facts are stored (per CLAUDE.md §11.4).
pub const EXECPLAN_ENTITY_PREFIX: &str = "execplan:";

/// Page size used when scanning the fact store for ExecPlan facts. 10× the
/// largest plan we've seen (≈ 50 facts) × 687 plans, capped — single-hop scan
/// avoids one DB call per slug.
const FACT_SCAN_TOP_K: usize = 8000;

/// 90 days in milliseconds. Used by the no-facts age cutoff.
pub const ARCHIVE_AGE_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// Synthetic project_id under which aggregator-derived work items live. Not a
/// real project row — `list_work` callers must accept it without project
/// validation.
pub const VIRTUAL_PROJECT_ID: &str = "execplans";

/// Passport recorded as `created_by_passport` on aggregator items. The
/// aggregator never mutates — this is purely a serialisation requirement of
/// the [`WorkItem`] shape.
pub const VIRTUAL_PASSPORT: &str = "system:execplan-aggregator";

/// Underscore-prefixed plan files are operator scratchpads
/// (e.g. `_cascade-m1-patch-...md`) and are skipped by the walker.
const SCRATCH_PREFIX: char = '_';

/// One on-disk plan file. The walker produces these; everything downstream
/// operates on the in-memory representation.
#[derive(Debug, Clone)]
pub struct ExecplanFile {
    pub slug: String,
    pub path: PathBuf,
    pub mtime_unix_ms: u64,
    pub content: String,
}

/// Pure projection of an ExecPlan markdown file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedPlan {
    pub title: String,
    pub risk_class: Option<String>,
    /// Milestone numbers declared in the `## Milestones` section (e.g. 1, 2, 3).
    pub milestones_declared: Vec<u32>,
    /// A `Status:` line if present (e.g. "Status: Archived").
    pub status_line: Option<String>,
    /// Slug captured from `Superseded by [[<slug>]]` or `Status: Superseded by <slug>`.
    pub superseded_by: Option<String>,
}

/// Rollup of facts stored under `entity = "execplan:<slug>"`. Fields cover the
/// keys produced by the §11 fact-storage convention.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecplanFactSummary {
    /// Highest milestone number for which a `milestone:M<n>` fact exists.
    pub highest_milestone_with_fact: Option<u32>,
    /// `n` → status string parsed from gate fact value `{"status": "..."}`.
    pub gate_statuses: BTreeMap<u32, String>,
    /// Most recent `stored_at` across all related facts (ms since epoch).
    pub last_fact_at_unix_ms: Option<u64>,
    /// Earliest `stored_at` across all related facts (ms since epoch).
    pub first_fact_at_unix_ms: Option<u64>,
    pub decision_count: usize,
}

impl ExecplanFactSummary {
    fn any_fact(&self) -> bool {
        self.last_fact_at_unix_ms.is_some()
    }
}

/// Parse a single plan markdown. Cheap text-level scan — no DOM, no regex
/// crate — so M1 stays dependency-light.
pub fn parse_plan(md: &str) -> ParsedPlan {
    let mut out = ParsedPlan::default();
    let mut in_milestones = false;
    let mut seen_milestone_numbers = Vec::new();

    for line in md.lines() {
        let trimmed = line.trim_start();

        if out.title.is_empty() {
            if let Some(rest) = trimmed.strip_prefix("# ") {
                out.title = rest.trim().to_string();
            }
        }

        if out.risk_class.is_none() {
            // Matches `**Risk class: medium.**`, `Risk class: high`, etc.
            // Case-insensitive prefix match, then read the next word.
            if let Some(idx) = find_ci(trimmed, "risk class:") {
                let after = &trimmed[idx + "risk class:".len()..];
                let word = after
                    .trim_start_matches([' ', '*'])
                    .split(|c: char| !c.is_ascii_alphabetic())
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if matches!(word.as_str(), "low" | "medium" | "high") {
                    out.risk_class = Some(word);
                }
            }
        }

        if out.status_line.is_none() {
            if let Some(rest) = trimmed.strip_prefix("Status:") {
                out.status_line = Some(rest.trim().to_string());
            } else if let Some(rest) = trimmed.strip_prefix("> **Status:**") {
                out.status_line = Some(rest.trim().to_string());
            }
        }

        if out.superseded_by.is_none() {
            if let Some(slug) = extract_superseded_slug(trimmed) {
                out.superseded_by = Some(slug);
            }
        }

        if trimmed.starts_with("## ") {
            let heading = trimmed.trim_start_matches("## ").trim().to_ascii_lowercase();
            in_milestones = heading == "milestones";
            continue;
        }

        if in_milestones {
            if let Some(n) = first_milestone_number(trimmed) {
                if !seen_milestone_numbers.contains(&n) {
                    seen_milestone_numbers.push(n);
                }
            }
        }
    }

    out.milestones_declared = seen_milestone_numbers;
    out
}

fn find_ci(haystack: &str, needle_lower: &str) -> Option<usize> {
    let hl = haystack.to_ascii_lowercase();
    hl.find(needle_lower)
}

/// Strip leading markdown markup so we can ask "does this line *declare*
/// X, or merely mention X mid-prose?". Removes leading whitespace, blockquote
/// arrows, bulleted / numbered list markers, bold asterisks, and an optional
/// `Status:` prefix (followed by more bold + spaces). Used by
/// [`extract_superseded_slug`] to reject prose mentions like
/// `"- See \`Status: Superseded by \[\[slug\]\]\` pattern"` while still matching
/// declarations like `"Status: Superseded by \[\[next-plan\]\]"` or
/// `"> **Status:** Superseded by \[\[next-plan\]\]"`.
fn strip_leading_markup(line: &str) -> &str {
    let mut s = line.trim_start();
    // Blockquote arrows, possibly nested or separated by whitespace.
    while let Some(rest) = s.strip_prefix('>') {
        s = rest.trim_start();
    }
    // Unordered list marker.
    if let Some(rest) = s.strip_prefix("- ").or_else(|| s.strip_prefix("* ")) {
        s = rest;
    }
    // Ordered list marker (`6. ` etc.) — drop digits then a literal ". ".
    let trimmed_digits = s.trim_start_matches(|c: char| c.is_ascii_digit());
    if trimmed_digits.len() < s.len() {
        if let Some(rest) = trimmed_digits.strip_prefix(". ") {
            s = rest;
        }
    }
    // Bold markers around the next token.
    s = s.trim_start_matches('*');
    // Optional `Status:` (case-insensitive). ASCII-only, so byte-indexing
    // into `s` after measuring against `lower` is safe.
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("status:") {
        s = s[7..].trim_start_matches([' ', '*']);
    }
    s
}

/// Match a "Superseded by …" *declaration* at the start of a line, after
/// stripping leading markdown markup. Returns the captured slug. Rejects
/// prose mentions ("(superseded by today's work)") and backtick-quoted
/// pattern examples ("`Status: Superseded by \[\[slug\]\]`") because in both
/// cases the `Superseded by` token does not appear at the line's declarative
/// prefix.
fn extract_superseded_slug(line: &str) -> Option<String> {
    let trimmed = strip_leading_markup(line);
    // Case-sensitive: real declarations idiomatically capitalise the `S`
    // (`Status: Superseded by …`, `> **Status:** Superseded by …`,
    // standalone `Superseded by …`). Lowercase continuation prose
    // (`  superseded by today's work`, `   superseded by the older one`)
    // is rejected here so it doesn't flag the parent plan as archived.
    // Caught by the two new false positives observed against the live
    // /v1/work?source=all response after the 2026-05-27 strip-markup fix.
    let after = trimmed.strip_prefix("Superseded by")?;
    let after = after.trim_start_matches([':', ' ']);
    if let Some(rest) = after.strip_prefix("[[") {
        let end = rest.find("]]")?;
        return Some(rest[..end].trim().to_string());
    }
    let token: String = after
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// Find the first `M<digits>` token in a line, returning the number.
/// Accepts: `- **M1 — title**`, `- [ ] M1 ...`, `M1: ...`, etc.
fn first_milestone_number(line: &str) -> Option<u32> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if prev_ok && (b == b'M' || b == b'm') && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            let next_ok = j >= bytes.len() || !bytes[j].is_ascii_alphabetic();
            if next_ok {
                if let Ok(n) = std::str::from_utf8(&bytes[i + 1..j]).unwrap_or("").parse::<u32>() {
                    return Some(n);
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    None
}

/// Roll up a slice of facts for a single ExecPlan slug into the shape
/// [`derive_state`] expects. Facts are tuples of `(key, value, stored_at)`.
pub fn summarise_facts(facts: &[(String, String, DateTime<Utc>)]) -> ExecplanFactSummary {
    let mut summary = ExecplanFactSummary::default();
    let mut highest = 0u32;
    let mut seen_milestone = false;
    let mut latest: i64 = 0;
    let mut earliest: i64 = i64::MAX;

    for (key, value, stored_at) in facts {
        let stored_ms = stored_at.timestamp_millis();
        if stored_ms > latest {
            latest = stored_ms;
        }
        if stored_ms < earliest {
            earliest = stored_ms;
        }

        if let Some(rest) = key.strip_prefix("milestone:M") {
            if let Ok(n) = rest.parse::<u32>() {
                seen_milestone = true;
                if n > highest {
                    highest = n;
                }
            }
        } else if let Some(rest) = key.strip_prefix("gate:M") {
            if let Ok(n) = rest.parse::<u32>() {
                let status = serde_json::from_str::<serde_json::Value>(value)
                    .ok()
                    .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(String::from))
                    .unwrap_or_default();
                summary.gate_statuses.insert(n, status);
                // Gate facts also indicate a milestone-bound observation; track them so
                // a plan with only `gate:*` facts (no `milestone:*`) still surfaces a
                // current milestone.
                seen_milestone = true;
                if n > highest {
                    highest = n;
                }
            }
        } else if key.starts_with("decision:") {
            summary.decision_count += 1;
        }
    }

    if seen_milestone {
        summary.highest_milestone_with_fact = Some(highest);
    }
    if latest > 0 {
        summary.last_fact_at_unix_ms = Some(latest as u64);
        summary.first_fact_at_unix_ms = Some(earliest as u64);
    }
    summary
}

/// Deterministic state derivation. See module docs for the rule list.
pub fn derive_state(
    file: &ExecplanFile,
    parsed: &ParsedPlan,
    facts: &ExecplanFactSummary,
    now_unix_ms: u64,
) -> WorkItem {
    let status_lc = parsed.status_line.as_deref().unwrap_or("").to_ascii_lowercase();

    // Rule 1: explicit Archived status overrides everything else.
    if status_lc.contains("archived") {
        return mk_item(file, parsed, "archive", None, parsed.superseded_by.clone(), facts);
    }

    // Rule 2: explicit supersession.
    if parsed.superseded_by.is_some() {
        return mk_item(file, parsed, "archive", None, parsed.superseded_by.clone(), facts);
    }

    // Rule 3: explicit Complete status.
    if status_lc.contains("complete") && !status_lc.contains("incomplete") {
        return mk_item(file, parsed, "complete", None, None, facts);
    }

    // Rule 4: all declared milestones gated complete.
    if !parsed.milestones_declared.is_empty()
        && parsed
            .milestones_declared
            .iter()
            .all(|n| facts.gate_statuses.get(n).is_some_and(|s| s == "complete"))
    {
        return mk_item(file, parsed, "complete", None, None, facts);
    }

    // Rule 5: blocked gate on the highest fact'd milestone.
    if let Some(cur) = facts.highest_milestone_with_fact {
        if facts.gate_statuses.get(&cur).is_some_and(|s| s == "blocked") {
            return mk_item(file, parsed, "blocked", Some(format!("M{cur}")), None, facts);
        }
    }

    // Rule 6: any fact = in_progress.
    if facts.any_fact() {
        let current = facts.highest_milestone_with_fact.map(|n| format!("M{n}"));
        return mk_item(file, parsed, "in_progress", current, None, facts);
    }

    // Rules 7 & 8: no facts → planned or archive by file age.
    let age = now_unix_ms.saturating_sub(file.mtime_unix_ms);
    let state = if age > ARCHIVE_AGE_MS { "archive" } else { "planned" };
    mk_item(file, parsed, state, None, None, facts)
}

fn mk_item(
    file: &ExecplanFile,
    parsed: &ParsedPlan,
    state: &str,
    current_milestone: Option<String>,
    superseded_by: Option<String>,
    facts: &ExecplanFactSummary,
) -> WorkItem {
    let risk = parsed.risk_class.as_deref().unwrap_or("?");
    let body = format!(
        "Risk: {} · Milestones declared: {} · Decisions logged: {}",
        risk,
        parsed.milestones_declared.len(),
        facts.decision_count
    );
    let created = facts.first_fact_at_unix_ms.unwrap_or(file.mtime_unix_ms);
    let updated = facts
        .last_fact_at_unix_ms
        .map_or(file.mtime_unix_ms, |f| f.max(file.mtime_unix_ms));
    let title = if parsed.title.is_empty() {
        file.slug.clone()
    } else {
        parsed.title.clone()
    };
    WorkItem {
        id: format!("execplan:{}", file.slug),
        project_id: VIRTUAL_PROJECT_ID.to_string(),
        state: state.to_string(),
        title,
        body,
        assignee_passport: None,
        tenant_id: None,
        linked_pr: None,
        linked_issue: None,
        blocker_reason: None,
        created_by_passport: VIRTUAL_PASSPORT.to_string(),
        created_at_unix_ms: created,
        updated_at_unix_ms: updated,
        plan_path: Some(file.path.display().to_string()),
        current_milestone,
        superseded_by,
        orchestrator_id: None,
    }
}

/// Walk a directory of `<slug>.md` plan files. Skips:
///   - non-`.md` files
///   - underscore-prefixed scratchpads (`_<slug>.md`)
///   - entries whose stem cannot be UTF-8
///
/// Returns plain `io::Error` for filesystem failures; callers can decide
/// whether to fall back to an empty list or 500.
pub fn walk_execplans_root(root: &Path) -> std::io::Result<Vec<ExecplanFile>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        if stem.starts_with(SCRATCH_PREFIX) {
            continue;
        }
        let content = std::fs::read_to_string(&path)?;
        let mtime_unix_ms = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_millis() as u64);
        out.push(ExecplanFile {
            slug: stem,
            path,
            mtime_unix_ms,
            content,
        });
    }
    Ok(out)
}

/// Resolve the plan root from the environment. Returns `None` if unset or
/// empty — callers should treat that as "execplan source not configured" and
/// return an empty list (not an error).
pub fn execplans_root_from_env() -> Option<PathBuf> {
    std::env::var(EXECPLANS_ROOT_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
}

/// Group all fact-store rows under `entity = "execplan:*"` by slug. One scan
/// instead of N per-slug queries.
fn collect_execplan_facts(store: &FactStore) -> HashMap<String, Vec<(String, String, DateTime<Utc>)>> {
    let result = store.query(&FactQuery {
        query: None,
        entity: None,
        entity_prefix: Some(EXECPLAN_ENTITY_PREFIX.to_string()),
        top_k: FACT_SCAN_TOP_K,
        token_budget: None,
    });
    let mut by_slug: HashMap<String, Vec<(String, String, DateTime<Utc>)>> = HashMap::new();
    for fact in dedup_latest(result.facts) {
        if fact.deleted {
            continue;
        }
        let Some(slug) = fact.entity.strip_prefix(EXECPLAN_ENTITY_PREFIX) else {
            continue;
        };
        by_slug
            .entry(slug.to_string())
            .or_default()
            .push((fact.key, fact.value, fact.stored_at));
    }
    by_slug
}

/// Top-level aggregator: walk `root`, join each plan with its facts, derive
/// state. The result is suitable for splicing into `/v1/work` output.
///
/// `root` missing or empty → returns `Ok(vec![])`. Filesystem errors are
/// surfaced via `io::Error` so the HTTP layer can decide on 500 vs degrade.
///
/// Sort order matches kanban (`updated_at_unix_ms` descending).
pub fn list_execplans(store: &FactStore, root: &Path, now_unix_ms: u64) -> std::io::Result<Vec<WorkItem>> {
    let files = walk_execplans_root(root)?;
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let mut facts_by_slug = collect_execplan_facts(store);
    let mut out = Vec::with_capacity(files.len());
    for file in files {
        let parsed = parse_plan(&file.content);
        let facts = facts_by_slug.remove(&file.slug).unwrap_or_default();
        let summary = summarise_facts(&facts);
        out.push(derive_state(&file, &parsed, &summary, now_unix_ms));
    }
    out.sort_by(|a, b| b.updated_at_unix_ms.cmp(&a.updated_at_unix_ms));
    Ok(out)
}

/// Stamp `orchestrator_id` on the ExecPlan-derived [`WorkItem`]s whose `id`
/// appears in `member_ids`. The kanban write path stamps `orchestrator_id`
/// when a work item is attached; ExecPlan items are read-time projections with
/// no persisted record, so the orchestrator linkage is applied here when the
/// `/v1/work?orchestrator=<id>` filter resolves an orchestrator's members.
///
/// Mutates in place; items not in `member_ids` are left untouched.
pub fn stamp_orchestrator_id(
    items: &mut [WorkItem],
    member_ids: &std::collections::HashSet<String>,
    orchestrator_id: &str,
) {
    for item in items.iter_mut() {
        if member_ids.contains(&item.id) {
            item.orchestrator_id = Some(orchestrator_id.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use corecrux_memory::fact_store::StoreFact;

    fn file(slug: &str, mtime_unix_ms: u64, content: &str) -> ExecplanFile {
        ExecplanFile {
            slug: slug.to_string(),
            path: PathBuf::from(format!("/tmp/{slug}.md")),
            mtime_unix_ms,
            content: content.to_string(),
        }
    }

    fn ts(ms: i64) -> DateTime<Utc> {
        Utc.timestamp_millis_opt(ms).unwrap()
    }

    #[test]
    fn parse_extracts_title_risk_milestones() {
        let md = "\
# Some Title\n\
\n\
## Purpose\n\
\n\
**Risk class: medium.** Body text.\n\
\n\
## Milestones\n\
\n\
- **M1 — Aggregator**\n\
- **M2 — HTTP wiring**\n\
- **M3 — MCP 401 fix**\n\
\n\
## Test plan\n\
\n\
- M99 should NOT count (not in milestones section)\n\
";
        let p = parse_plan(md);
        assert_eq!(p.title, "Some Title");
        assert_eq!(p.risk_class.as_deref(), Some("medium"));
        assert_eq!(p.milestones_declared, vec![1, 2, 3]);
        assert_eq!(p.status_line, None);
        assert_eq!(p.superseded_by, None);
    }

    #[test]
    fn parse_picks_up_status_archived() {
        let md = "# T\n\nStatus: Archived (replaced by Q3 effort)\n";
        let p = parse_plan(md);
        assert_eq!(p.status_line.as_deref(), Some("Archived (replaced by Q3 effort)"));
    }

    #[test]
    fn parse_picks_up_supersession() {
        let md = "# T\n\nStatus: Superseded by [[plan-2026-06-01]]\n";
        let p = parse_plan(md);
        assert_eq!(p.superseded_by.as_deref(), Some("plan-2026-06-01"));
    }

    #[test]
    fn parse_picks_up_bare_supersession() {
        let md = "# T\n\nSuperseded by foo-bar-baz-2026-05-19 (see decision log).\n";
        let p = parse_plan(md);
        assert_eq!(p.superseded_by.as_deref(), Some("foo-bar-baz-2026-05-19"));
    }

    #[test]
    fn parse_accepts_status_superseded_in_blockquote() {
        let md = "# T\n\n> **Status:** Superseded by [[next-plan]]\n";
        let p = parse_plan(md);
        assert_eq!(p.superseded_by.as_deref(), Some("next-plan"));
    }

    #[test]
    fn parse_accepts_list_item_supersession() {
        let md = "# T\n\n- Superseded by old-plan-2026-04-01\n";
        let p = parse_plan(md);
        assert_eq!(p.superseded_by.as_deref(), Some("old-plan-2026-04-01"));
    }

    // ── Regression tests for the 2026-05-27 false positives ──
    // Pre-fix the parser matched `superseded by` anywhere on a line, so
    // these three real-world plan bodies all triggered phantom supersessions.

    #[test]
    fn parse_ignores_backtick_quoted_pattern_in_list_item() {
        // From crux-work-panel-execplans-as-truenorth-2026-05-26 line 91 —
        // a numbered-list item that quotes the supersession *pattern* for
        // documentation. The literal slug "slug" must not be captured.
        let md = "# T\n\n6. `Status: Superseded by [[slug]]` line in plan front-matter → `archive`\n";
        let p = parse_plan(md);
        assert_eq!(p.superseded_by, None, "pattern example must not match");
    }

    #[test]
    fn parse_ignores_prose_mention_inside_list_item() {
        // From lme-s-q500-lift-handoff-2026-05-26 line 178 — a list item
        // whose prose includes "superseded by today's …".
        let md = "# T\n\n- Prior ccxev handoff (now superseded by today's LME-S work): foo.md\n";
        let p = parse_plan(md);
        assert_eq!(p.superseded_by, None, "prose mention must not match");
    }

    #[test]
    fn parse_ignores_decision_log_reference_to_superseded_by() {
        // From crux-work-panel-execplans-as-truenorth-2026-05-26 line 159 —
        // a Decision Log entry that mentions the words "Superseded by" in
        // a description of what fields the parser populates.
        let md = "# T\n\n- 2026-05-26: M1 parser scans for `Status:` line, `Superseded by`. Rationale: …\n";
        let p = parse_plan(md);
        assert_eq!(p.superseded_by, None, "decision-log mention must not match");
    }

    #[test]
    fn parse_ignores_indented_lowercase_continuation_prose() {
        // From vaultcrux-multi-predicate-enumerate-2026-04-29 line 419 —
        // a continuation line of a bullet that starts with two-space indent
        // and lowercase "superseded by per-request …". The post-strip-markup
        // matcher (post-PR #108) caught this because it was case-insensitive;
        // the case-sensitive `Superseded by` prefix rejects it now.
        let md = "# T\n\n- some bullet\n  superseded by per-request `backend: \"legacy\"` field on chunks\n";
        let p = parse_plan(md);
        assert_eq!(p.superseded_by, None, "indented lowercase prose must not match");
    }

    #[test]
    fn parse_ignores_lowercase_explicit_mention() {
        // From vaultcrux-lme-hard50-retrieval-bugs-2026-04-27 line 125 — a
        // deeply-indented bullet continuation that starts with lowercase
        // "superseded by the explicit $350K mention …".
        let md = "# T\n\n- bullet\n     superseded by the explicit $350K mention (false positive on …)\n";
        let p = parse_plan(md);
        assert_eq!(p.superseded_by, None, "lowercase prose must not match");
    }

    #[test]
    fn summarise_extracts_highest_and_gate_statuses() {
        let facts = vec![
            ("milestone:M1".to_string(), "{}".to_string(), ts(1_000)),
            ("milestone:M2".to_string(), "{}".to_string(), ts(2_000)),
            (
                "gate:M1".to_string(),
                r#"{"status":"complete","commit_sha":"abc"}"#.to_string(),
                ts(1_500),
            ),
            ("gate:M2".to_string(), r#"{"status":"blocked"}"#.to_string(), ts(2_500)),
            ("decision:rerank-backend".to_string(), "{}".to_string(), ts(500)),
        ];
        let s = summarise_facts(&facts);
        assert_eq!(s.highest_milestone_with_fact, Some(2));
        assert_eq!(s.gate_statuses.get(&1).map(String::as_str), Some("complete"));
        assert_eq!(s.gate_statuses.get(&2).map(String::as_str), Some("blocked"));
        assert_eq!(s.last_fact_at_unix_ms, Some(2500));
        assert_eq!(s.first_fact_at_unix_ms, Some(500));
        assert_eq!(s.decision_count, 1);
    }

    // ---- derive_state: 8 rules ----

    #[test]
    fn rule_7_no_facts_recent_mtime_is_planned() {
        let now: u64 = 10 * 24 * 60 * 60 * 1000; // 10 days
        let f = file("p", now - 5 * 24 * 60 * 60 * 1000, "# P\n## Milestones\n- M1\n- M2\n");
        let p = parse_plan(&f.content);
        let s = ExecplanFactSummary::default();
        let item = derive_state(&f, &p, &s, now);
        assert_eq!(item.state, "planned");
        assert_eq!(item.id, "execplan:p");
        assert_eq!(item.project_id, VIRTUAL_PROJECT_ID);
        assert_eq!(item.current_milestone, None);
    }

    #[test]
    fn rule_8_no_facts_old_mtime_is_archive() {
        let now: u64 = 365 * 24 * 60 * 60 * 1000;
        let f = file("old", now - 100 * 24 * 60 * 60 * 1000, "# Old\n");
        let p = parse_plan(&f.content);
        let item = derive_state(&f, &p, &ExecplanFactSummary::default(), now);
        assert_eq!(item.state, "archive");
        assert_eq!(item.superseded_by, None);
    }

    #[test]
    fn rule_4_all_milestones_gated_complete_is_complete() {
        let f = file("done", 1_000, "# Done\n## Milestones\n- M1\n- M2\n");
        let p = parse_plan(&f.content);
        let s = summarise_facts(&[
            ("gate:M1".to_string(), r#"{"status":"complete"}"#.to_string(), ts(2_000)),
            ("gate:M2".to_string(), r#"{"status":"complete"}"#.to_string(), ts(3_000)),
        ]);
        let item = derive_state(&f, &p, &s, 4_000);
        assert_eq!(item.state, "complete");
        assert_eq!(item.current_milestone, None);
        assert_eq!(item.updated_at_unix_ms, 3_000);
    }

    #[test]
    fn rule_5_blocked_gate_on_current_is_blocked() {
        let f = file("stuck", 1_000, "# Stuck\n## Milestones\n- M1\n- M2\n- M3\n");
        let p = parse_plan(&f.content);
        let s = summarise_facts(&[
            ("gate:M1".to_string(), r#"{"status":"complete"}"#.to_string(), ts(2_000)),
            ("gate:M2".to_string(), r#"{"status":"blocked"}"#.to_string(), ts(3_000)),
        ]);
        let item = derive_state(&f, &p, &s, 4_000);
        assert_eq!(item.state, "blocked");
        assert_eq!(item.current_milestone.as_deref(), Some("M2"));
    }

    #[test]
    fn rule_6_any_milestone_fact_is_in_progress() {
        let f = file("midway", 1_000, "# Midway\n## Milestones\n- M1\n- M2\n- M3\n");
        let p = parse_plan(&f.content);
        let s = summarise_facts(&[("milestone:M2".to_string(), "{}".to_string(), ts(2_500))]);
        let item = derive_state(&f, &p, &s, 4_000);
        assert_eq!(item.state, "in_progress");
        assert_eq!(item.current_milestone.as_deref(), Some("M2"));
    }

    #[test]
    fn rule_2_superseded_is_archive_with_pointer() {
        let f = file(
            "super",
            1_000,
            "# Super\n\nStatus: Superseded by [[next-plan]]\n## Milestones\n- M1\n",
        );
        let p = parse_plan(&f.content);
        let s = summarise_facts(&[("milestone:M1".to_string(), "{}".to_string(), ts(2_000))]);
        let item = derive_state(&f, &p, &s, 4_000);
        assert_eq!(item.state, "archive");
        assert_eq!(item.superseded_by.as_deref(), Some("next-plan"));
    }

    #[test]
    fn rule_1_status_archived_wins_over_in_progress_facts() {
        let f = file(
            "arc",
            1_000,
            "# Arc\n\nStatus: Archived 2026-05-20\n## Milestones\n- M1\n",
        );
        let p = parse_plan(&f.content);
        let s = summarise_facts(&[("milestone:M1".to_string(), "{}".to_string(), ts(2_000))]);
        let item = derive_state(&f, &p, &s, 4_000);
        assert_eq!(item.state, "archive");
    }

    #[test]
    fn rule_3_status_complete_without_all_gates() {
        let f = file(
            "dc",
            1_000,
            "# DC\n\nStatus: Complete (manually closed)\n## Milestones\n- M1\n- M2\n",
        );
        let p = parse_plan(&f.content);
        // M2 has no gate fact, but Status: Complete wins.
        let s = summarise_facts(&[("gate:M1".to_string(), r#"{"status":"complete"}"#.to_string(), ts(2_000))]);
        let item = derive_state(&f, &p, &s, 4_000);
        assert_eq!(item.state, "complete");
    }

    #[test]
    fn empty_milestones_with_in_progress_facts_uses_rule_6_not_rule_4() {
        // A plan without a Milestones section must NOT trip rule 4 (vacuous truth).
        let f = file("nodecl", 1_000, "# NoDecl\n\nFreeform body.\n");
        let p = parse_plan(&f.content);
        let s = summarise_facts(&[("milestone:M1".to_string(), "{}".to_string(), ts(2_000))]);
        let item = derive_state(&f, &p, &s, 4_000);
        assert_eq!(item.state, "in_progress");
    }

    // ---- walker ----

    #[test]
    fn walker_skips_non_md_and_underscore_files() {
        let dir = tempdir();
        std::fs::write(dir.join("good.md"), "# A\n").unwrap();
        std::fs::write(dir.join("_scratch.md"), "# Scratch\n").unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
        let mut out = walk_execplans_root(&dir).unwrap();
        out.sort_by(|a, b| a.slug.cmp(&b.slug));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].slug, "good");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn walker_missing_root_returns_empty_not_error() {
        let dir = std::env::temp_dir().join("definitely-not-there-aggregator-test");
        let out = walk_execplans_root(&dir).unwrap();
        assert!(out.is_empty());
    }

    fn tempdir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("execplan-agg-test-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ---- list_execplans integration ----

    fn store_fact(store: &mut FactStore, slug: &str, key: &str, value: &str) {
        store.store(StoreFact {
            entity: format!("execplan:{slug}"),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
    }

    #[test]
    fn list_execplans_joins_files_and_facts() {
        let dir = tempdir();

        // Plan A: planned (no facts, recent mtime by virtue of just-written).
        std::fs::write(
            dir.join("plan-alpha.md"),
            "# Plan Alpha\n\n**Risk class: low.**\n\n## Milestones\n- M1 — bootstrap\n- M2 — ship\n",
        )
        .unwrap();
        // Plan B: in_progress with facts at M2.
        std::fs::write(
            dir.join("plan-beta.md"),
            "# Plan Beta\n\n**Risk class: medium.**\n\n## Milestones\n- M1\n- M2\n- M3\n",
        )
        .unwrap();
        // Plan C: archived by Status line.
        std::fs::write(
            dir.join("plan-gamma.md"),
            "# Plan Gamma\n\nStatus: Archived 2026-04-01 (replaced by alpha)\n\n## Milestones\n- M1\n",
        )
        .unwrap();
        // Scratchpad — must be excluded.
        std::fs::write(dir.join("_scratch.md"), "# scratch\n").unwrap();

        let mut store = FactStore::new();
        store_fact(&mut store, "plan-beta", "milestone:M2", "{}");
        store_fact(
            &mut store,
            "plan-beta",
            "gate:M1",
            r#"{"status":"complete","commit_sha":"abc"}"#,
        );
        // Decision fact under a slug with NO on-disk plan — must NOT produce a row.
        store_fact(&mut store, "orphan-slug-9999", "decision:foo", r#"{"x":1}"#);

        let now_ms = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(u64::MAX);
        let items = list_execplans(&store, &dir, now_ms).expect("ok");
        assert_eq!(items.len(), 3, "scratchpad excluded, orphan slug not promoted");

        let by_slug: HashMap<String, &WorkItem> = items.iter().map(|w| (w.id.clone(), w)).collect();

        let alpha = by_slug.get("execplan:plan-alpha").expect("alpha present");
        assert_eq!(alpha.state, "planned");
        assert_eq!(alpha.current_milestone, None);
        assert_eq!(alpha.title, "Plan Alpha");
        assert!(alpha.plan_path.as_deref().unwrap_or("").ends_with("plan-alpha.md"));

        let beta = by_slug.get("execplan:plan-beta").expect("beta present");
        assert_eq!(beta.state, "in_progress");
        assert_eq!(beta.current_milestone.as_deref(), Some("M2"));

        let gamma = by_slug.get("execplan:plan-gamma").expect("gamma present");
        assert_eq!(gamma.state, "archive");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_execplans_empty_root_returns_empty() {
        let dir = std::env::temp_dir().join("never-was-aggregator");
        let store = FactStore::new();
        let items = list_execplans(&store, &dir, 1_000).expect("ok");
        assert!(items.is_empty());
    }

    #[test]
    fn list_execplans_sorts_by_updated_desc() {
        let dir = tempdir();
        std::fs::write(dir.join("old.md"), "# Old\n## Milestones\n- M1\n").unwrap();
        std::fs::write(dir.join("new.md"), "# New\n## Milestones\n- M1\n").unwrap();
        let mut store = FactStore::new();
        store_fact(&mut store, "new", "milestone:M1", "{}");
        let now_ms = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(u64::MAX);
        let items = list_execplans(&store, &dir, now_ms).expect("ok");
        assert_eq!(items.len(), 2);
        // `new` carries a fact stored_at ~now; `old` only has file mtime ~now.
        // updated_at_unix_ms = max(last_fact, mtime); the fact `stored_at` is
        // sourced from the store and is at least as recent as the mtime, so
        // `new` should sort first or tie. Assert it is not strictly less.
        assert!(items[0].updated_at_unix_ms >= items[1].updated_at_unix_ms);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
