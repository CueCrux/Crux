// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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
//! `derive_state` is the deterministic state machine — eight rules, no LLM, no
//! filesystem, no fact-store. The HTTP layer (M2) is responsible for binding
//! the IO surface; M1 ships the data-flow + unit tests.
//!
//! State derivation rules (in order; first match wins):
//!
//! 1. a recognised leading `Status:` token declares state (never trailing prose);
//!    leading non-terminal tokens (`Blocked`, `In progress`, `Planned`, and
//!    `Parked`) deliberately short-circuit before fact-derived rules because
//!    the human declaration outranks facts
//! 2. `parsed.superseded_by` is set                       → `archive` + `superseded_by`
//!    (including when the leading status is a completion token)
//! 3. `Parked` always maps to `archive`, including when milestone facts exist;
//!    this matches the 2026-07-10 corrected-audit parking of 21 plans
//! 4. all declared milestones have a gate fact `status=complete` → `complete`
//! 5. highest milestone with a fact has gate `status=blocked`    → `blocked`
//! 6. any milestone/gate fact exists                      → `in_progress`
//! 7. no facts, file mtime ≤ 90 days old                  → `planned`
//! 8. no facts, file mtime > 90 days old                  → `archive`

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use corecrux_memory::fact_store::{FactQuery, FactStore};
use serde::{Deserialize, Serialize};

use crate::fact_helpers::dedup_latest;
use crate::work::{BlockerKind, Provenance, WorkItem};

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

/// 14 days in milliseconds. An `in_progress` plan with no fact/file activity for
/// longer than this is flagged `stale` (likely finished-but-unmarked, not in
/// flight) so the board can split in_progress into active vs stale.
pub const STALE_AGE_MS: u64 = 14 * 24 * 60 * 60 * 1000;

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

/// Env var gating the A4 **drafting** board state. **Default OFF** — when set
/// (`1`/`true`/`on`/`yes`), a plan whose `Status:` line declares "Draft"
/// projects as `drafting` instead of falling through the normal rules. When
/// unset the derive path is byte-identical to before.
pub const DRAFTING_STATE_FLAG_ENV: &str = "CORECRUXD_FEATURE_DRAFTING_STATE";

/// Env var gating the A3 **next-ready milestone** computation. **Default OFF** —
/// when set, `deps:<ID>` facts are parsed and `WorkItem::next_ready_milestone`
/// is filled. When unset the field stays `None` and no deps facts are read.
pub const NEXT_READY_MILESTONE_FLAG_ENV: &str = "CORECRUXD_FEATURE_NEXT_READY_MILESTONE";

/// Truthiness parser shared by the feature flags. **Default OFF** — an empty
/// value also counts as off. Matches the activity-log / cost-lens parser so the
/// flag vocabulary is uniform across the daemon.
fn feature_flag_enabled(env_var: &str) -> bool {
    match std::env::var(env_var) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// True when the A4 drafting-state derive rule is enabled. **Default OFF**.
pub fn drafting_state_enabled() -> bool {
    feature_flag_enabled(DRAFTING_STATE_FLAG_ENV)
}

/// True when the A3 next-ready-milestone computation is enabled. **Default OFF**.
pub fn next_ready_milestone_enabled() -> bool {
    feature_flag_enabled(NEXT_READY_MILESTONE_FLAG_ENV)
}

/// Stable, total ordering key for an **alphanumeric** milestone id (`M0`, `M10`,
/// `A1`, `B5`). Milestone ids in this system are *not* `M<number>`-only — gate /
/// deps / milestone facts can be keyed `A1`, `B5`, etc.
///
/// Ordering (documented, deterministic):
///   1. by the leading non-digit **alpha prefix**, lexicographically (so all
///      `A*` sort before `B*` before `M*`),
///   2. then by the trailing **numeric suffix**, numerically (so `M2 < M10`,
///      not the lexicographic `M10 < M2`),
///   3. then by the full id string as a final tiebreak (ids with no numeric
///      suffix, or with internal structure, still order deterministically).
///
/// Returned as `(prefix, num, full)` so callers can `sort_by_key`. An id with no
/// trailing digits gets `num = u32::MAX` so it sorts after numbered siblings of
/// the same prefix; an unparseable / overflowing suffix likewise.
fn milestone_id_key(id: &str) -> (String, u32, String) {
    let digits_start = id.len() - id.chars().rev().take_while(|c| c.is_ascii_digit()).count();
    let (prefix, suffix) = id.split_at(digits_start);
    let num = if suffix.is_empty() {
        u32::MAX
    } else {
        suffix.parse::<u32>().unwrap_or(u32::MAX)
    };
    (prefix.to_string(), num, id.to_string())
}

/// Numeric value of a **bare** `M<number>` milestone id (`"M0"` → `0`,
/// `"M12"` → `12`). Returns `None` for any non-`M<number>` id (`"A1"`, `"B5"`,
/// `"M1.2"`, `"Mx"`, `""`) so only legacy numeric ids feed the back-compat maps.
fn numeric_milestone_id(id: &str) -> Option<u32> {
    let rest = id.strip_prefix('M')?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.parse::<u32>().ok()
}

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
    /// Subset of `milestones_declared` whose declaring (parent) checklist line is
    /// ticked (`- [x] **M<n> …**`). Used to derive `complete` straight from the
    /// markdown checkboxes, independent of gate facts.
    pub milestones_checked: Vec<u32>,
    /// A `Status:` line if present (e.g. "Status: Archived").
    pub status_line: Option<String>,
    /// Slug captured from `Superseded by [[<slug>]]` or `Status: Superseded by <slug>`.
    pub superseded_by: Option<String>,
    /// Slugs from `Depends on [[<slug>]]` declaration lines — plans this one
    /// builds on / is blocked by. Accumulated across lines, deduped.
    pub depends_on: Vec<String>,
    /// Slugs from `Extended by [[<slug>]]` declaration lines — plans that build
    /// on this one.
    pub extended_by: Vec<String>,
    /// Deploy-axis edge targets from `Deploys to [[deploy:<host>]]` declaration
    /// lines — the deploy targets (hosts/lanes) this plan ships to. Captured as
    /// the full `deploy:<host>` token so the projection can group plans by the
    /// exact target they queue against. Accumulated across lines, deduped.
    pub deploys_to: Vec<String>,
    /// Distinct `OD-<n>` Open-Decision ids referenced anywhere in the plan body.
    pub open_decision_refs: Vec<String>,
}

/// Rollup of facts stored under `entity = "execplan:<slug>"`. Fields cover the
/// keys produced by the §11 fact-storage convention.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecplanFactSummary {
    /// Highest milestone number for which a `milestone:M<n>` fact exists.
    /// Numeric-only — retained for the legacy `M<n>` derive rules (current
    /// milestone, blocked-on-highest). Alphanumeric ids live in the `*_by_id`
    /// maps below.
    pub highest_milestone_with_fact: Option<u32>,
    /// `n` → status string parsed from gate fact value `{"status": "..."}`.
    /// Numeric-only mirror of `gate_statuses_by_id`, kept so the existing
    /// `M<n>`-keyed rules (rule 4 all-gated, rule 5 blocked) stay byte-identical.
    pub gate_statuses: BTreeMap<u32, String>,
    /// `<milestone-id>` → gate status string, for **all** alphanumeric milestone
    /// ids (`M0`, `A1`, `B5`), not just numeric `M<n>`. Powers the A3 next-ready
    /// computation, which must reason over the full id space.
    pub gate_statuses_by_id: BTreeMap<String, String>,
    /// `<milestone-id>` → its declared `after` dependency list, parsed from
    /// `deps:<ID>` facts (value `{"after":["<id>", ...]}`). Empty when the plan
    /// declares no deps facts, or when the next-ready flag is off.
    pub deps_by_id: BTreeMap<String, Vec<String>>,
    /// Most recent `stored_at` across all related facts (ms since epoch).
    pub last_fact_at_unix_ms: Option<u64>,
    /// Earliest `stored_at` across all related facts (ms since epoch).
    pub first_fact_at_unix_ms: Option<u64>,
    pub decision_count: usize,
    /// Distinct commit SHAs pulled from `decision:*` fact values (`commit_sha`
    /// field; QC.1 guarantees decisions carry one). Insertion order, deduped.
    pub commit_shas: Vec<String>,
    /// Distinct real-principal actors that contributed facts to this plan,
    /// sorted. The "who built this" rollup surfaced in `WorkItem::provenance`.
    pub contributing_agents: Vec<String>,
    /// Owner passport, auto-derived from the actor of the most-recent fact whose
    /// actor is a real principal (not a `system:`/`__` placeholder). None when no
    /// fact carries a usable actor.
    pub owner_passport: Option<String>,
}

impl ExecplanFactSummary {
    fn any_fact(&self) -> bool {
        self.last_fact_at_unix_ms.is_some()
    }
}

/// One fact row fed to [`summarise_facts`]: `(key, value, stored_at, actor)`.
pub type ExecplanFactRow = (String, String, DateTime<Utc>, Option<String>);

/// True when an actor string names a real principal (a passport/agent), not a
/// synthetic placeholder. Filters the empty string, `system:*` (e.g. the
/// aggregator), and reserved `__…` prefixes so the auto-owner is a usable id.
fn is_principal_actor(actor: &str) -> bool {
    let a = actor.trim();
    !a.is_empty() && !a.starts_with("system:") && !a.starts_with("__")
}

/// Distinct real-principal actors across a plan's facts (see
/// [`is_principal_actor`]), sorted for deterministic output. These are the
/// agents that contributed milestone/gate/decision facts — the "who built this"
/// rollup surfaced in [`crate::work::WorkItem::provenance`].
fn contributing_agents_from_facts(facts: &[ExecplanFactRow]) -> Vec<String> {
    let mut agents: Vec<String> = facts
        .iter()
        .filter_map(|(_, _, _, actor)| actor.as_deref())
        .filter(|a| is_principal_actor(a))
        .map(|a| a.trim().to_string())
        .collect();
    agents.sort();
    agents.dedup();
    agents
}

/// Auto-derive a plan owner from its facts: the actor of the most-recent fact
/// whose actor is a real principal (see [`is_principal_actor`]). None when no
/// fact carries a usable actor.
fn owner_from_facts(facts: &[ExecplanFactRow]) -> Option<String> {
    facts
        .iter()
        .filter(|(_, _, _, actor)| actor.as_deref().is_some_and(is_principal_actor))
        .max_by_key(|(_, _, stored_at, _)| stored_at.timestamp_millis())
        .and_then(|(_, _, _, actor)| actor.clone())
}

/// Parse a single plan markdown. Cheap text-level scan — no DOM, no regex
/// crate — so M1 stays dependency-light.
pub fn parse_plan(md: &str) -> ParsedPlan {
    let mut out = ParsedPlan::default();
    let mut in_milestones = false;
    let mut in_fence = false;
    let mut seen_milestone_numbers = Vec::new();
    let mut checked_milestone_numbers = Vec::new();

    for line in md.lines() {
        let trimmed = line.trim_start();

        // Fenced code blocks (```…```) hold ASCII diagrams / pattern examples
        // that look like declarations but are not — e.g. a `Status:Draft)` line
        // inside a state-machine diagram, or a `Depends on [[slug]]` example in a
        // docs fence. Toggle the fence flag on each ``` line and skip declaration
        // detection while inside, so a plan that merely *documents* a feature is
        // not misclassified (A4 drafting false-positive fix). The fence-toggle
        // line itself is consumed (no detection runs for it).
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }

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

        for slug in extract_ref_slugs(trimmed, "Depends on") {
            if !out.depends_on.contains(&slug) {
                out.depends_on.push(slug);
            }
        }
        for slug in extract_ref_slugs(trimmed, "Extended by") {
            if !out.extended_by.contains(&slug) {
                out.extended_by.push(slug);
            }
        }
        // Deploy-axis edge: `Deploys to [[deploy:<host>]]`. Reuses the shared
        // declaration parser so it inherits the same prose-rejection discipline
        // (case-sensitive lead token, required `:`/space separator). The captured
        // token keeps its `deploy:` prefix; only well-formed `deploy:<host>`
        // targets are retained so a bare `[[some-plan]]` typo never lands on the
        // deploy axis.
        for target in extract_ref_slugs(trimmed, "Deploys to") {
            if target.starts_with("deploy:") && target.len() > "deploy:".len() && !out.deploys_to.contains(&target) {
                out.deploys_to.push(target);
            }
        }

        collect_od_refs(trimmed, &mut out.open_decision_refs);

        if trimmed.starts_with("## ") {
            let heading = trimmed.trim_start_matches("## ").trim().to_ascii_lowercase();
            in_milestones = heading == "milestones";
            continue;
        }

        if in_milestones {
            if let Some(n) = first_milestone_number(trimmed) {
                if !seen_milestone_numbers.contains(&n) {
                    // First (parent) line for this milestone number decides its
                    // checkbox rollup; later sub-bullets (`M<n>.x`) don't override.
                    seen_milestone_numbers.push(n);
                    if checkbox_state(trimmed) == Some(true) {
                        checked_milestone_numbers.push(n);
                    }
                }
            }
        }
    }

    out.milestones_declared = seen_milestone_numbers;
    out.milestones_checked = checked_milestone_numbers;
    out
}

/// Read a markdown task-list checkbox at the start of a (already left-trimmed)
/// line: `[x]`/`[X]` → `Some(true)`, `[ ]` → `Some(false)`, otherwise `None`.
/// Tolerates a leading list marker (`- `, `* `, `1. `).
fn checkbox_state(line: &str) -> Option<bool> {
    let s = line
        .trim_start_matches(['-', '*', '+', ' '])
        .trim_start_matches(|c: char| c.is_ascii_digit())
        .trim_start_matches(['.', ')', ' ']);
    let inner = s.strip_prefix('[')?.split_once(']')?.0.trim();
    match inner {
        "x" | "X" => Some(true),
        "" => Some(false),
        _ => None,
    }
}

/// Gate-fact status strings that mean "this milestone is done". The workflow
/// stores `passed`, `passed+merged`, `done`, `merged`, etc. — not just the
/// literal `complete` — so match any of these as a substring (case-insensitive),
/// excluding the negation `incomplete`.
fn is_complete_status(status: &str) -> bool {
    let s = status.to_ascii_lowercase();
    if s.contains("incomplete") {
        return false;
    }
    [
        "complete", "passed", "pass", "done", "merged", "shipped", "deployed", "landed",
    ]
    .iter()
    .any(|t| s.contains(t))
}

fn find_ci(haystack: &str, needle_lower: &str) -> Option<usize> {
    let hl = haystack.to_ascii_lowercase();
    hl.find(needle_lower)
}

/// State tags accepted at the start of a parsed `Status:` value.
///
/// Matching is ASCII-case-insensitive and requires a token boundary after the
/// tag. Text after that boundary is descriptive prose and cannot change the
/// declaration. This is deliberately separate from [`is_complete_status`]:
/// gate facts have a broad completion vocabulary, while plan headers have a
/// small, explicit grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeclaredStatus {
    Draft,
    Planned,
    InProgress,
    Blocked,
    Parked,
    Archived,
    Superseded,
    Complete,
}

fn declared_status(value: &str) -> Option<DeclaredStatus> {
    let value = strip_leading_markup(value).to_ascii_lowercase();
    [
        ("code-complete", DeclaredStatus::Complete),
        ("in_progress", DeclaredStatus::InProgress),
        ("in progress", DeclaredStatus::InProgress),
        ("superseded", DeclaredStatus::Superseded),
        ("completed", DeclaredStatus::Complete),
        ("complete", DeclaredStatus::Complete),
        ("deployed", DeclaredStatus::Complete),
        ("shipped", DeclaredStatus::Complete),
        ("landed", DeclaredStatus::Complete),
        ("merged", DeclaredStatus::Complete),
        ("done", DeclaredStatus::Complete),
        ("archived", DeclaredStatus::Archived),
        ("blocked", DeclaredStatus::Blocked),
        ("parked", DeclaredStatus::Parked),
        ("planned", DeclaredStatus::Planned),
        ("backlog", DeclaredStatus::Planned),
        ("draft", DeclaredStatus::Draft),
    ]
    .into_iter()
    .find_map(|(token, status)| {
        value.strip_prefix(token).and_then(|rest| {
            rest.chars().next().map_or(Some(status), |next| {
                (!next.is_ascii_alphanumeric() && next != '_').then_some(status)
            })
        })
    })
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

/// Extract typed plan-reference slugs from a *declaration* line, after stripping
/// leading markdown markup. `keyword` is the case-sensitive lead token
/// (`"Depends on"`, `"Extended by"`). Mirrors [`extract_superseded_slug`]'s
/// prose rejection: the keyword must sit at the line's declarative prefix and be
/// followed by a `:`/space separator, so mid-sentence prose ("…which depends on
/// the older plan…") and `Depends online`-style words never match.
///
/// Captures every `[[<slug>]]` group on the line (comma-separated targets inside
/// one group are split); if no `[[…]]` group is present, the single bare token
/// after the keyword is taken.
fn extract_ref_slugs(line: &str, keyword: &str) -> Vec<String> {
    let trimmed = strip_leading_markup(line);
    let Some(after) = trimmed.strip_prefix(keyword) else {
        return Vec::new();
    };
    // Require an explicit `:`/space separator so the keyword can't run into the
    // next word (`Depends online` must NOT yield a bare token `line`).
    let Some(after) = after.strip_prefix([':', ' ']) else {
        return Vec::new();
    };
    let after = after.trim_start_matches([':', ' ']);

    let mut slugs = Vec::new();
    if after.contains("[[") {
        let mut rest = after;
        while let Some(open) = rest.find("[[") {
            rest = &rest[open + 2..];
            let Some(close) = rest.find("]]") else { break };
            let group = &rest[..close];
            rest = &rest[close + 2..];
            for part in group.split(',') {
                let s = part.trim();
                if !s.is_empty() {
                    slugs.push(s.to_string());
                }
            }
        }
    } else {
        let token: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .collect();
        if !token.is_empty() {
            slugs.push(token);
        }
    }
    slugs
}

/// Collect distinct `OD-<n>` ids referenced in a line into `out` (first-seen
/// order preserved). Requires a non-alphanumeric boundary before `OD` and after
/// the digits, mirroring the `\bOD-\d+\b` lint convention so `FOOD-9` / `OD-3X`
/// don't match. ASCII-only, so byte indices align with the `&str`.
fn collect_od_refs(line: &str, out: &mut Vec<String>) {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        if bytes[i] == b'O'
            && bytes[i + 1] == b'D'
            && bytes[i + 2] == b'-'
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
        {
            let mut j = i + 3;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            let next_ok = j >= bytes.len() || !bytes[j].is_ascii_alphanumeric();
            if j > i + 3 && next_ok {
                let id = format!("OD-{}", &line[i + 3..j]);
                if !out.contains(&id) {
                    out.push(id);
                }
                i = j;
                continue;
            }
        }
        i += 1;
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
///
/// Milestone ids are **alphanumeric** (`M0`, `A1`, `B5`). The legacy numeric
/// maps (`highest_milestone_with_fact`, `gate_statuses`) are populated only for
/// pure `M<number>` ids — preserving the existing `M<n>` derive rules byte-for-
/// byte — while the `*_by_id` maps capture the full id space for the A3
/// next-ready computation. `deps:<ID>` facts are read only when the next-ready
/// flag is on, so the flag-off path is unchanged.
pub fn summarise_facts(facts: &[(String, String, DateTime<Utc>)]) -> ExecplanFactSummary {
    let mut summary = ExecplanFactSummary::default();
    let mut highest = 0u32;
    let mut seen_milestone = false;
    let mut latest: i64 = 0;
    let mut earliest: i64 = i64::MAX;
    let read_deps = next_ready_milestone_enabled();

    for (key, value, stored_at) in facts {
        let stored_ms = stored_at.timestamp_millis();
        if stored_ms > latest {
            latest = stored_ms;
        }
        if stored_ms < earliest {
            earliest = stored_ms;
        }

        if let Some(id) = key.strip_prefix("milestone:") {
            // Alphanumeric id (M0, A1, B5). The numeric back-compat map is fed
            // only when the id is a bare `M<number>`.
            if let Some(n) = numeric_milestone_id(id) {
                seen_milestone = true;
                if n > highest {
                    highest = n;
                }
            }
        } else if let Some(id) = key.strip_prefix("gate:") {
            let status = serde_json::from_str::<serde_json::Value>(value)
                .ok()
                .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(String::from))
                .unwrap_or_default();
            // String-keyed map covers the full alphanumeric id space (A3).
            summary.gate_statuses_by_id.insert(id.to_string(), status.clone());
            // Numeric back-compat: only bare `M<number>` ids feed the legacy
            // `M<n>`-keyed rules (rule 4 all-gated, rule 5 blocked-on-highest),
            // keeping those code paths byte-identical.
            if let Some(n) = numeric_milestone_id(id) {
                summary.gate_statuses.insert(n, status);
                // Gate facts also indicate a milestone-bound observation; track them so
                // a plan with only `gate:*` facts (no `milestone:*`) still surfaces a
                // current milestone.
                seen_milestone = true;
                if n > highest {
                    highest = n;
                }
            }
        } else if let Some(id) = key.strip_prefix("deps:").filter(|_| read_deps) {
            // `deps:<ID>` value = {"after":["<id>", ...]}. Only consulted behind
            // the next-ready flag (`read_deps`) so the default path reads no deps
            // facts and stays byte-identical.
            let after = serde_json::from_str::<serde_json::Value>(value)
                .ok()
                .and_then(|v| v.get("after").cloned())
                .and_then(|a| a.as_array().cloned())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default();
            summary.deps_by_id.insert(id.to_string(), after);
        } else if key.starts_with("decision:") {
            summary.decision_count += 1;
            // QC.1: decision facts carry a `commit_sha`. Collect distinct ones
            // (insertion order) for the provenance rollup.
            if let Some(sha) = serde_json::from_str::<serde_json::Value>(value)
                .ok()
                .and_then(|v| v.get("commit_sha").and_then(|s| s.as_str()).map(String::from))
            {
                if !sha.is_empty() && !summary.commit_shas.contains(&sha) {
                    summary.commit_shas.push(sha);
                }
            }
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

/// A3 — compute the **next-ready milestone**: the lowest-ordered milestone id
/// (per [`milestone_id_key`]) that is BOTH (a) not itself already complete (its
/// own gate status is not a completion synonym per [`is_complete_status`]) AND
/// (b) whose declared `after` dependency list is fully satisfied by milestones
/// with a passing gate — the same vocabulary the board already uses for "done".
///
/// - Returns `None` when `deps_by_id` is empty (no `deps:*` facts → no graph to
///   reason over; the brief's "next_ready is None when no deps facts exist").
/// - A milestone with no `after` entry, or an empty `after`, has no unmet
///   prerequisites — but it is still only "ready" if it isn't itself done.
/// - A dependency id with no passing gate (missing gate, or a gate whose status
///   isn't a completion synonym) is unmet, so the dependent milestone is not yet
///   ready.
/// - A milestone whose OWN gate is already passing is excluded — pointing "do
///   this next" at an already-done milestone was the A3 live-smoke bug (it
///   returned "A2" whose `gate:A2` was passed). The pointer now advances past
///   completed milestones to the next incomplete, dep-satisfied one.
///
/// Among the qualifying milestones the lowest-ordered id wins, giving a stable
/// "do this next" pointer regardless of fact insertion order. Returns `None`
/// when none qualify (every dep-satisfied milestone is already complete).
fn compute_next_ready(
    deps_by_id: &BTreeMap<String, Vec<String>>,
    gate_statuses_by_id: &BTreeMap<String, String>,
) -> Option<String> {
    if deps_by_id.is_empty() {
        return None;
    }
    let is_done = |id: &str| gate_statuses_by_id.get(id).is_some_and(|s| is_complete_status(s));
    let mut ready: Vec<&String> = deps_by_id
        .iter()
        // (a) the milestone itself must not already be complete, and
        // (b) all of its declared `after` deps must be complete.
        .filter(|(id, after)| !is_done(id) && after.iter().all(|dep| is_done(dep)))
        .map(|(id, _)| id)
        .collect();
    ready.sort_by_key(|id| milestone_id_key(id));
    ready.first().map(|id| (*id).clone())
}

/// Deterministic state derivation. See module docs for the rule list.
pub fn derive_state(
    file: &ExecplanFile,
    parsed: &ParsedPlan,
    facts: &ExecplanFactSummary,
    now_unix_ms: u64,
) -> WorkItem {
    let status_lc = parsed.status_line.as_deref().unwrap_or("").to_ascii_lowercase();
    let declared = parsed.status_line.as_deref().and_then(declared_status);

    // Rule 0 (A4, flag-gated, default OFF): `Draft` is a leading declaration
    // token. A prose trailer is allowed; words in that trailer are never parsed
    // as another state declaration.
    if drafting_state_enabled() && declared == Some(DeclaredStatus::Draft) {
        return mk_item(file, parsed, "drafting", None, None, facts);
    }

    // Rules 1–3: only the leading Status token is authoritative. In particular,
    // `Status: In progress — M0 complete` remains live.
    match declared {
        Some(DeclaredStatus::Archived | DeclaredStatus::Parked | DeclaredStatus::Superseded) => {
            return mk_item(file, parsed, "archive", None, parsed.superseded_by.clone(), facts);
        }
        Some(DeclaredStatus::Complete) => {
            // Preserve the historical supersession precedence: a completed
            // plan may also name its replacement, in which case it archives
            // and retains that graph edge.
            if parsed.superseded_by.is_some() {
                return mk_item(file, parsed, "archive", None, parsed.superseded_by.clone(), facts);
            }
            return mk_item(file, parsed, "complete", None, None, facts);
        }
        Some(DeclaredStatus::Blocked) => {
            let mut item = mk_item(file, parsed, "blocked", None, None, facts);
            item.blocker_reason = Some("ExecPlan Status declares Blocked".to_string());
            item.blocker_kind = Some(if status_lc.contains("approval") || status_lc.contains("hold") {
                BlockerKind::NeedsApproval
            } else {
                BlockerKind::NeedsInfo
            });
            return item;
        }
        Some(DeclaredStatus::InProgress) => {
            let current = facts.highest_milestone_with_fact.map(|n| format!("M{n}"));
            let mut item = mk_item(file, parsed, "in_progress", current, None, facts);
            let last_activity = facts
                .last_fact_at_unix_ms
                .unwrap_or(file.mtime_unix_ms)
                .max(file.mtime_unix_ms);
            item.stale = Some(now_unix_ms.saturating_sub(last_activity) > STALE_AGE_MS);
            return item;
        }
        Some(DeclaredStatus::Planned) => {
            return mk_item(file, parsed, "planned", None, None, facts);
        }
        Some(DeclaredStatus::Draft) | None => {}
    }

    // Rule 2 back-compat: standalone `Superseded by ...` declarations do not
    // have a Status value, but remain authoritative.
    if parsed.superseded_by.is_some() {
        return mk_item(file, parsed, "archive", None, parsed.superseded_by.clone(), facts);
    }

    // Rule 4: all declared milestones complete — via gate facts (any "done"
    // synonym, see is_complete_status) OR every milestone's markdown checkbox
    // ticked. Either signal flips the board so a finished plan stops reading as
    // in_progress.
    if !parsed.milestones_declared.is_empty() {
        let all_gated = parsed
            .milestones_declared
            .iter()
            .all(|n| facts.gate_statuses.get(n).is_some_and(|s| is_complete_status(s)));
        let all_checked = parsed
            .milestones_declared
            .iter()
            .all(|n| parsed.milestones_checked.contains(n));
        if all_gated || all_checked {
            return mk_item(file, parsed, "complete", None, None, facts);
        }
    }

    // Rule 5: blocked gate on the highest fact'd milestone.
    if let Some(cur) = facts.highest_milestone_with_fact {
        if let Some(status) = facts.gate_statuses.get(&cur) {
            let status_lc = status.to_ascii_lowercase();
            if status_lc.contains("blocked") {
                let mut item = mk_item(file, parsed, "blocked", Some(format!("M{cur}")), None, facts);
                // A gate status that names approval / a human hold is a
                // needs_approval block (M3 maps it to HUMAN_HOLD); any other
                // blocked gate reads as needs_info.
                item.blocker_kind = Some(if status_lc.contains("approval") || status_lc.contains("hold") {
                    BlockerKind::NeedsApproval
                } else {
                    BlockerKind::NeedsInfo
                });
                return item;
            }
        }
    }

    // Rule 6: any fact = in_progress — but a fact'd plan untouched beyond the
    // archive window is a finished-but-unmarked / abandoned plan that can never
    // reach `complete` on its own, so it archives like a stale no-fact plan
    // (this is the structural fix for "milestone fact, no declared milestones,
    // pinned in_progress forever"). Otherwise it stays in_progress, flagged
    // `stale` once activity lapses past STALE_AGE_MS so the board can separate
    // active from done-but-unmarked.
    if facts.any_fact() {
        let last_activity = facts
            .last_fact_at_unix_ms
            .unwrap_or(file.mtime_unix_ms)
            .max(file.mtime_unix_ms);
        let age = now_unix_ms.saturating_sub(last_activity);
        if age > ARCHIVE_AGE_MS {
            return mk_item(file, parsed, "archive", None, None, facts);
        }
        let current = facts.highest_milestone_with_fact.map(|n| format!("M{n}"));
        let mut item = mk_item(file, parsed, "in_progress", current, None, facts);
        item.stale = Some(age > STALE_AGE_MS);
        return item;
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
    let total = parsed.milestones_declared.len() as u32;
    let (milestones_done, milestones_total) = if total > 0 {
        let done = parsed
            .milestones_declared
            .iter()
            .filter(|n| {
                facts.gate_statuses.get(n).is_some_and(|s| is_complete_status(s))
                    || parsed.milestones_checked.contains(n)
            })
            .count() as u32;
        (Some(done), Some(total))
    } else {
        (None, None)
    };
    // Provenance is the fact-derived rollup; only meaningful when the plan has
    // facts. Fact-less plans (and the kanban path) leave it `None`.
    let provenance = facts.any_fact().then(|| Provenance {
        first_activity_unix_ms: facts.first_fact_at_unix_ms.unwrap_or(created),
        last_activity_unix_ms: facts.last_fact_at_unix_ms.unwrap_or(updated),
        contributing_agents: facts.contributing_agents.clone(),
        commit_shas: facts.commit_shas.clone(),
        decision_count: facts.decision_count,
    });
    // A3 (flag-gated, default OFF): the next milestone ready to start. With the
    // flag off, `deps_by_id` is never populated (`summarise_facts` skips
    // `deps:*`) so `compute_next_ready` returns `None` regardless; the extra
    // flag check makes the no-op explicit and keeps the field omitted on the
    // wire (`skip_serializing_if = "Option::is_none"`).
    let next_ready_milestone = if next_ready_milestone_enabled() {
        compute_next_ready(&facts.deps_by_id, &facts.gate_statuses_by_id)
    } else {
        None
    };
    // Canonical bytes are the raw UTF-8 file bytes read once by the walker, with no normalization.
    // BLAKE3 matches the daemon's existing file content-addressing convention.
    let plan_content_hash = blake3::hash(file.content.as_bytes()).to_hex().to_string();
    WorkItem {
        id: format!("execplan:{}", file.slug),
        project_id: VIRTUAL_PROJECT_ID.to_string(),
        state: state.to_string(),
        title,
        body,
        assignee_passport: facts.owner_passport.clone(),
        tenant_id: None,
        linked_pr: None,
        linked_issue: None,
        blocker_reason: None,
        blocker_kind: None,
        created_by_passport: VIRTUAL_PASSPORT.to_string(),
        created_at_unix_ms: created,
        updated_at_unix_ms: updated,
        plan_path: Some(file.path.display().to_string()),
        plan_content_hash: Some(plan_content_hash),
        current_milestone,
        next_ready_milestone,
        superseded_by,
        depends_on: parsed.depends_on.clone(),
        extended_by: parsed.extended_by.clone(),
        // Raw OD refs; apply_open_decisions refines these to the open subset.
        open_decisions: parsed.open_decision_refs.clone(),
        orchestrator_id: None,
        milestones_done,
        milestones_total,
        notes_count: None,
        provenance,
        stale: None,
        // Stamped read-time at the HTTP layer (needs the async cost store);
        // the pure aggregator leaves it None.
        token_burn: None,
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
fn collect_execplan_facts(store: &FactStore) -> HashMap<String, Vec<ExecplanFactRow>> {
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(EXECPLAN_ENTITY_PREFIX.to_string()),
        top_k: FACT_SCAN_TOP_K,
        token_budget: None,
    });
    let mut by_slug: HashMap<String, Vec<ExecplanFactRow>> = HashMap::new();
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
            .push((fact.key, fact.value, fact.stored_at, fact.actor));
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
    let od_registry = open_decisions_path_from_env()
        .and_then(|p| std::fs::read_to_string(&p).ok())
        .map(|s| parse_open_decisions(&s));
    let mut out = Vec::with_capacity(files.len());
    for file in files {
        let parsed = parse_plan(&file.content);
        let facts = facts_by_slug.remove(&file.slug).unwrap_or_default();
        // summarise_facts works on (key, value, stored_at); the owner is derived
        // from the 4th element (actor), which only the raw rows carry.
        let owner = owner_from_facts(&facts);
        let agents = contributing_agents_from_facts(&facts);
        let rows3: Vec<(String, String, DateTime<Utc>)> = facts.into_iter().map(|(k, v, s, _)| (k, v, s)).collect();
        let mut summary = summarise_facts(&rows3);
        summary.owner_passport = owner;
        summary.contributing_agents = agents;
        let mut item = derive_state(&file, &parsed, &summary, now_unix_ms);
        // Surface attached notes (work comments keyed by the item id).
        let n = crate::work::list_comments(store, &item.id).len() as u32;
        item.notes_count = (n > 0).then_some(n);
        out.push(item);
    }
    apply_reciprocal_refs(&mut out);
    apply_open_decisions(&mut out, od_registry.as_ref(), now_unix_ms);
    out.sort_by(|a, b| b.updated_at_unix_ms.cmp(&a.updated_at_unix_ms));
    Ok(out)
}

/// Derive reciprocal lineage edges across the walked plan set: for every
/// `A depends_on B`, ensure `B.extended_by` contains `A` (and the mirror for a
/// declared `extended_by`). Authors declare one direction; this fills the other.
/// A declared edge whose target slug has no matching plan is left one-sided —
/// the source keeps the declared edge so a client can flag it as dangling — and
/// never mints a phantom item. Each item's edge lists are sorted + deduped for
/// deterministic output.
fn apply_reciprocal_refs(items: &mut [WorkItem]) {
    // slug -> index, where slug is the id minus the `execplan:` prefix.
    let slug_to_idx: HashMap<String, usize> = items
        .iter()
        .enumerate()
        .filter_map(|(i, it)| it.id.strip_prefix(EXECPLAN_ENTITY_PREFIX).map(|s| (s.to_string(), i)))
        .collect();

    // Read pass: collect reverse edges as (target_idx, source_slug, is_extended)
    // where is_extended means "push source into target.extended_by". Deferring
    // the writes keeps the borrow checker happy.
    let mut additions: Vec<(usize, String, bool)> = Vec::new();
    for it in items.iter() {
        let Some(src) = it.id.strip_prefix(EXECPLAN_ENTITY_PREFIX) else {
            continue;
        };
        for target in &it.depends_on {
            if let Some(&j) = slug_to_idx.get(target) {
                additions.push((j, src.to_string(), true)); // target.extended_by += src
            }
        }
        for target in &it.extended_by {
            if let Some(&j) = slug_to_idx.get(target) {
                additions.push((j, src.to_string(), false)); // target.depends_on += src
            }
        }
    }

    // Write pass.
    for (j, src, is_extended) in additions {
        let edges = if is_extended {
            &mut items[j].extended_by
        } else {
            &mut items[j].depends_on
        };
        if !edges.contains(&src) {
            edges.push(src);
        }
    }

    for it in items.iter_mut() {
        it.depends_on.sort();
        it.depends_on.dedup();
        it.extended_by.sort();
        it.extended_by.dedup();
    }
}

// ── Deploy-axis projection (B3 Part 1) ───────────────────────────────────────
//
// The deploy queue is a read-time grouping over plans that declare
// `Deploys to [[deploy:<host>]]`, surfacing — per target host — which ExecPlans
// are still queued (in an executable, non-archive state) to ship there. It is a
// pure projection: it reads `WorkItem::state` (already derived) joined with the
// per-plan `deploys_to` parse, and never mutates a plan or a WorkItem. It lives
// alongside the lineage projection and shares its closure discipline; it does
// not touch `derive_state`/`mk_item`/`summarise_facts`.

/// One ExecPlan queued to deploy to a given target. Slug + the state that made
/// it eligible, so a client can render the queue without re-deriving.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployQueueEntry {
    /// Bare ExecPlan slug (the `execplan:` id minus its prefix).
    pub slug: String,
    /// Derived state at projection time — always an executable (non-archive)
    /// state for an entry that appears in the queue.
    pub state: String,
}

/// Per-deploy-target queue: every executable ExecPlan that declares
/// `Deploys to [[deploy:<host>]]` for the same `target`. `count` mirrors
/// `entries.len()` for clients that only want the headline number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployTargetQueue {
    /// The full `deploy:<host>` target token.
    pub target: String,
    /// Number of executable plans queued for this target (`== entries.len()`).
    pub count: usize,
    /// Queued plans, sorted by slug for deterministic output.
    pub entries: Vec<DeployQueueEntry>,
}

/// States that count as "queued for deploy" — i.e. still executable, not an
/// archive/superseded terminal. A plan in any of these can still ship; an
/// `archive` plan never appears in the deploy queue.
//
// `dead_code`-allowed because the deploy-queue projection API is consumed only
// by the tests in this module today; the HTTP wiring (a `/v1/work` deploy-queue
// query) is a follow-up that lives outside this file's ownership scope. Keeping
// the projection here (data-flow + tests) mirrors how `list_execplans` shipped
// its pure layer in M1 before the HTTP layer bound it in M2.
#[allow(dead_code)]
fn is_executable_state(state: &str) -> bool {
    state != "archive"
}

/// Build the per-deploy-target queue from a slice of derived ExecPlan items
/// joined with their parsed `deploys_to` edges. `plans` pairs each
/// [`WorkItem`] with the [`ParsedPlan`] it was derived from (same order is not
/// required — the join is by id/slug). Only executable (non-archive) plans
/// contribute. Output is sorted by target, entries within a target sorted by
/// slug — deterministic for clients and tests.
// See `is_executable_state` for why this projection API is `dead_code`-allowed
// pending HTTP wiring outside this file's scope.
#[allow(dead_code)]
pub fn deploy_queue_from_pairs(plans: &[(&WorkItem, &ParsedPlan)]) -> Vec<DeployTargetQueue> {
    let mut by_target: BTreeMap<String, Vec<DeployQueueEntry>> = BTreeMap::new();
    for (item, parsed) in plans {
        if !is_executable_state(&item.state) {
            continue;
        }
        let slug = item
            .id
            .strip_prefix(EXECPLAN_ENTITY_PREFIX)
            .unwrap_or(&item.id)
            .to_string();
        for target in &parsed.deploys_to {
            let entries = by_target.entry(target.clone()).or_default();
            if !entries.iter().any(|e| e.slug == slug) {
                entries.push(DeployQueueEntry {
                    slug: slug.clone(),
                    state: item.state.clone(),
                });
            }
        }
    }
    by_target
        .into_iter()
        .map(|(target, mut entries)| {
            entries.sort_by(|a, b| a.slug.cmp(&b.slug));
            DeployTargetQueue {
                target,
                count: entries.len(),
                entries,
            }
        })
        .collect()
}

/// Walk `root`, derive each plan's state (reusing the same pure pipeline as
/// [`list_execplans`]) and parse its deploy edges, then group into the
/// per-target deploy queue. Read-only; `root` missing/empty → `Ok(vec![])`.
/// This is the deploy-axis sibling of `list_execplans` — it answers "what is
/// queued to ship to `deploy:<host>`?" without adding a field to `WorkItem`.
// `dead_code`-allowed pending HTTP wiring (see `is_executable_state`).
#[allow(dead_code)]
pub fn list_deploy_queue(store: &FactStore, root: &Path, now_unix_ms: u64) -> std::io::Result<Vec<DeployTargetQueue>> {
    let files = walk_execplans_root(root)?;
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let mut facts_by_slug = collect_execplan_facts(store);
    // Hold parsed plans alongside their derived items so the pairs borrow lives
    // for the projection call.
    let mut parsed_items: Vec<(WorkItem, ParsedPlan)> = Vec::with_capacity(files.len());
    for file in files {
        let parsed = parse_plan(&file.content);
        let facts = facts_by_slug.remove(&file.slug).unwrap_or_default();
        let owner = owner_from_facts(&facts);
        let agents = contributing_agents_from_facts(&facts);
        let rows3: Vec<(String, String, DateTime<Utc>)> = facts.into_iter().map(|(k, v, s, _)| (k, v, s)).collect();
        let mut summary = summarise_facts(&rows3);
        summary.owner_passport = owner;
        summary.contributing_agents = agents;
        let item = derive_state(&file, &parsed, &summary, now_unix_ms);
        parsed_items.push((item, parsed));
    }
    let pairs: Vec<(&WorkItem, &ParsedPlan)> = parsed_items.iter().map(|(i, p)| (i, p)).collect();
    Ok(deploy_queue_from_pairs(&pairs))
}

/// Env var pointing at the Open Decisions registry markdown
/// (`docs/master-plan/tracking/open-decisions.md`). Unset → OD wiring is off and
/// `WorkItem::open_decisions` stays empty.
pub const OPEN_DECISIONS_PATH_ENV: &str = "CRUX_OPEN_DECISIONS_PATH";

/// Resolve the OD registry path from the environment. `None` (or empty) → the
/// projection leaves `open_decisions` empty.
fn open_decisions_path_from_env() -> Option<PathBuf> {
    std::env::var(OPEN_DECISIONS_PATH_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
}

/// One row of the Open Decisions registry table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenDecision {
    pub id: String,
    /// The `Decides-by` cell verbatim — a `YYYY-MM-DD` date or free text
    /// (`"M1"`, `"RCX rollout phase 2"`, `"—"`).
    pub decides_by: String,
    pub resolved: bool,
}

/// Parse the Open Decisions registry markdown table into `id → OpenDecision`.
/// Cells (after splitting a row on `|`): 1=id, 7=decides-by, 8=status. Only rows
/// whose first cell is an `OD-<n>` id are taken — header / separator / prose
/// lines are skipped.
pub fn parse_open_decisions(md: &str) -> HashMap<String, OpenDecision> {
    let mut out = HashMap::new();
    for line in md.lines() {
        let t = line.trim_start();
        if !t.starts_with("| OD-") {
            continue;
        }
        let cells: Vec<&str> = t.split('|').map(|c| c.trim()).collect();
        // 0 = before-first-pipe, 1 = id … 7 = decides-by, 8 = status.
        if cells.len() < 9 {
            continue;
        }
        let id = cells[1].to_string();
        if !id.starts_with("OD-") {
            continue;
        }
        let resolved = cells[8].to_ascii_lowercase().contains("resolved");
        out.insert(
            id.clone(),
            OpenDecision {
                id,
                decides_by: cells[7].to_string(),
                resolved,
            },
        );
    }
    out
}

/// True when `decides_by` is a `YYYY-MM-DD` date strictly before `now`. Free-text
/// decides-by values (milestone tags, "—") are never overdue.
fn od_is_overdue(decides_by: &str, now_unix_ms: u64) -> bool {
    NaiveDate::parse_from_str(decides_by.trim(), "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(23, 59, 59))
        .is_some_and(|dt| (now_unix_ms as i64) > Utc.from_utc_datetime(&dt).timestamp_millis())
}

/// Numeric part of an `OD-<n>` id, for stable sorting. Non-conforming → MAX.
fn od_num(id: &str) -> u32 {
    id.strip_prefix("OD-").and_then(|n| n.parse().ok()).unwrap_or(u32::MAX)
}

/// Cross-reference each item's referenced `OD-<n>` ids (populated raw by
/// `mk_item`) against the registry and keep only the *unresolved* ones, overdue
/// first. An **overdue** open OD soft-blocks an otherwise-active
/// (`planned`/`in_progress`) plan — flipping it to `blocked` with a
/// `blocker_reason` — because the registry carries no per-OD blocker flag, so
/// "past its decides-by date and still open" is the strongest available signal.
/// Non-overdue open ODs annotate `open_decisions` without changing state.
/// `registry == None` (path unset/unreadable) → clears `open_decisions`, since
/// without the registry we can't assert any are still open.
fn apply_open_decisions(items: &mut [WorkItem], registry: Option<&HashMap<String, OpenDecision>>, now_unix_ms: u64) {
    for item in items.iter_mut() {
        let Some(reg) = registry else {
            item.open_decisions.clear();
            continue;
        };
        // (id, decides_by, overdue) for refs that are registered AND open.
        let mut open: Vec<(String, String, bool)> = item
            .open_decisions
            .iter()
            .filter_map(|id| reg.get(id))
            .filter(|od| !od.resolved)
            .map(|od| {
                let overdue = od_is_overdue(&od.decides_by, now_unix_ms);
                (od.id.clone(), od.decides_by.clone(), overdue)
            })
            .collect();
        if open.is_empty() {
            item.open_decisions.clear();
            continue;
        }
        // Overdue first, then by numeric id.
        open.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| od_num(&a.0).cmp(&od_num(&b.0))));
        item.open_decisions = open.iter().map(|(id, _, _)| id.clone()).collect();

        // An overdue open OD soft-blocks an active plan.
        if let Some((id, decides_by, _)) = open.iter().find(|(_, _, overdue)| *overdue) {
            if item.state == "planned" || item.state == "in_progress" {
                item.state = "blocked".to_string();
                item.blocker_reason = Some(format!("Overdue open decision {id} (decides-by {decides_by})"));
                // An overdue decision is waiting on an owner's call → HUMAN_HOLD.
                item.blocker_kind = Some(BlockerKind::NeedsApproval);
            }
        }
    }
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

    /// Build a minimal ExecPlan-shaped WorkItem for reciprocal-closure tests.
    fn wi(slug: &str, depends_on: &[&str], extended_by: &[&str]) -> WorkItem {
        WorkItem {
            id: format!("execplan:{slug}"),
            project_id: VIRTUAL_PROJECT_ID.to_string(),
            state: "planned".to_string(),
            title: slug.to_string(),
            body: String::new(),
            assignee_passport: None,
            tenant_id: None,
            linked_pr: None,
            linked_issue: None,
            blocker_reason: None,
            blocker_kind: None,
            created_by_passport: VIRTUAL_PASSPORT.to_string(),
            created_at_unix_ms: 0,
            updated_at_unix_ms: 0,
            plan_path: None,
            plan_content_hash: None,
            current_milestone: None,
            next_ready_milestone: None,
            superseded_by: None,
            depends_on: depends_on.iter().map(|s| s.to_string()).collect(),
            extended_by: extended_by.iter().map(|s| s.to_string()).collect(),
            open_decisions: Vec::new(),
            orchestrator_id: None,
            milestones_done: None,
            milestones_total: None,
            notes_count: None,
            provenance: None,
            stale: None,
            token_burn: None,
        }
    }

    /// A `planned` ExecPlan item carrying raw OD references (as `mk_item` leaves
    /// them, pre-`apply_open_decisions`).
    fn wi_od(slug: &str, ods: &[&str]) -> WorkItem {
        let mut w = wi(slug, &[], &[]);
        w.open_decisions = ods.iter().map(|s| s.to_string()).collect();
        w
    }

    fn item<'a>(items: &'a [WorkItem], slug: &str) -> &'a WorkItem {
        items
            .iter()
            .find(|i| i.id == format!("execplan:{slug}"))
            .expect("item present")
    }

    // ── M1: typed plan-reference parsing ──

    #[test]
    fn parse_extracts_depends_and_extended() {
        let md = "# T\n\n> Depends on [[plan-a]]\nExtended by [[plan-b]]\n";
        let p = parse_plan(md);
        assert_eq!(p.depends_on, vec!["plan-a".to_string()]);
        assert_eq!(p.extended_by, vec!["plan-b".to_string()]);
    }

    #[test]
    fn parse_depends_multiple_targets_and_bare_form() {
        let md = "# T\n\n- Depends on [[a]] [[b]]\nDepends on bare-slug-2026-01-01 (note)\n";
        let p = parse_plan(md);
        assert_eq!(
            p.depends_on,
            vec!["a".to_string(), "b".to_string(), "bare-slug-2026-01-01".to_string()]
        );
    }

    #[test]
    fn parse_depends_comma_separated_group() {
        let md = "# T\n\nDepends on [[a, b, c]]\n";
        let p = parse_plan(md);
        assert_eq!(p.depends_on, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn parse_refs_reject_prose_mentions() {
        // lowercase mid-sentence "depends on" / "extended by" must not match.
        let md = "# T\n\n- This milestone depends on [[a]] for context.\n- The work is extended by [[b]] later.\n";
        let p = parse_plan(md);
        assert!(p.depends_on.is_empty(), "prose 'depends on' must not match");
        assert!(p.extended_by.is_empty(), "prose 'extended by' must not match");
    }

    #[test]
    fn parse_refs_reject_keyword_without_separator() {
        // "Depends online" must not yield a bare token "line".
        let md = "# T\n\nDepends online resources are great\n";
        let p = parse_plan(md);
        assert!(p.depends_on.is_empty());
    }

    #[test]
    fn parse_refs_ignore_backtick_quoted_pattern() {
        // A docs line that quotes the convention must not mint an edge.
        let md = "# T\n\n6. `Depends on [[slug]]` declares a lineage edge → projection.\n";
        let p = parse_plan(md);
        assert!(p.depends_on.is_empty(), "pattern example must not match");
    }

    // ── M1: reciprocal closure ──

    #[test]
    fn reciprocal_closure_fills_reverse_edge() {
        let mut items = vec![wi("a", &["b"], &[]), wi("b", &[], &[])];
        apply_reciprocal_refs(&mut items);
        assert_eq!(item(&items, "a").depends_on, vec!["b".to_string()]);
        assert_eq!(item(&items, "b").extended_by, vec!["a".to_string()]);
        assert!(item(&items, "b").depends_on.is_empty());
    }

    #[test]
    fn reciprocal_closure_mirrors_declared_extended_by() {
        let mut items = vec![wi("a", &[], &["b"]), wi("b", &[], &[])];
        apply_reciprocal_refs(&mut items);
        assert_eq!(item(&items, "b").depends_on, vec!["a".to_string()]);
    }

    #[test]
    fn reciprocal_closure_no_duplicate_when_both_declared() {
        let mut items = vec![wi("a", &["b"], &[]), wi("b", &[], &["a"])];
        apply_reciprocal_refs(&mut items);
        assert_eq!(
            item(&items, "b").extended_by,
            vec!["a".to_string()],
            "no duplicate reverse edge"
        );
    }

    #[test]
    fn reciprocal_closure_dangling_target_keeps_source_edge() {
        let mut items = vec![wi("a", &["ghost"], &[])];
        apply_reciprocal_refs(&mut items);
        assert_eq!(
            items[0].depends_on,
            vec!["ghost".to_string()],
            "dangling edge retained on source"
        );
        assert_eq!(items.len(), 1, "no phantom item minted for a missing target");
    }

    // ── B3 Part 1: deploy-axis lineage edge + queue projection ──

    #[test]
    fn parse_extracts_deploys_to_edge() {
        let md = "# T\n\nDeploys to [[deploy:crux]]\n";
        let p = parse_plan(md);
        assert_eq!(p.deploys_to, vec!["deploy:crux".to_string()]);
    }

    #[test]
    fn parse_deploys_to_multiple_and_comma_group() {
        let md = "# T\n\n- Deploys to [[deploy:crux]] [[deploy:gpu-1]]\nDeploys to [[deploy:data-1, deploy:crux]]\n";
        let p = parse_plan(md);
        // dedup keeps first-seen order; deploy:crux appears once.
        assert_eq!(
            p.deploys_to,
            vec![
                "deploy:crux".to_string(),
                "deploy:gpu-1".to_string(),
                "deploy:data-1".to_string(),
            ]
        );
    }

    #[test]
    fn parse_deploys_to_rejects_non_deploy_target() {
        // A bare slug or a malformed token (no host after the prefix) is not a
        // deploy target and must not land on the deploy axis.
        let md = "# T\n\nDeploys to [[some-plan-2026-01-01]]\nDeploys to [[deploy:]]\n";
        let p = parse_plan(md);
        assert!(p.deploys_to.is_empty(), "non-deploy targets rejected");
    }

    #[test]
    fn parse_deploys_to_rejects_prose_mention() {
        let md = "# T\n\n- This milestone deploys to the staging box first.\n";
        let p = parse_plan(md);
        assert!(p.deploys_to.is_empty(), "prose 'deploys to' must not match");
    }

    /// Build an ExecPlan WorkItem with an explicit state for queue tests.
    fn wi_state(slug: &str, state: &str) -> WorkItem {
        let mut it = wi(slug, &[], &[]);
        it.state = state.to_string();
        it
    }

    fn parsed_with_deploys(targets: &[&str]) -> ParsedPlan {
        ParsedPlan {
            deploys_to: targets.iter().map(|s| s.to_string()).collect(),
            ..ParsedPlan::default()
        }
    }

    #[test]
    fn deploy_queue_groups_executable_plans_by_target() {
        let a = wi_state("plan-a", "in_progress");
        let pa = parsed_with_deploys(&["deploy:crux"]);
        let b = wi_state("plan-b", "planned");
        let pb = parsed_with_deploys(&["deploy:crux", "deploy:gpu-1"]);
        let pairs = vec![(&a, &pa), (&b, &pb)];
        let q = deploy_queue_from_pairs(&pairs);
        // Sorted by target: deploy:crux then deploy:gpu-1.
        assert_eq!(q.len(), 2);
        assert_eq!(q[0].target, "deploy:crux");
        assert_eq!(q[0].count, 2);
        assert_eq!(
            q[0].entries.iter().map(|e| e.slug.as_str()).collect::<Vec<_>>(),
            vec!["plan-a", "plan-b"]
        );
        assert_eq!(q[1].target, "deploy:gpu-1");
        assert_eq!(q[1].count, 1);
        assert_eq!(q[1].entries[0].slug, "plan-b");
    }

    #[test]
    fn deploy_queue_excludes_archived_plans() {
        let a = wi_state("plan-a", "archive");
        let pa = parsed_with_deploys(&["deploy:crux"]);
        let b = wi_state("plan-b", "blocked");
        let pb = parsed_with_deploys(&["deploy:crux"]);
        let pairs = vec![(&a, &pa), (&b, &pb)];
        let q = deploy_queue_from_pairs(&pairs);
        // Only the blocked (executable) plan is queued; archived is excluded.
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].count, 1);
        assert_eq!(q[0].entries[0].slug, "plan-b");
        assert_eq!(q[0].entries[0].state, "blocked");
    }

    #[test]
    fn deploy_queue_empty_when_no_deploy_edges() {
        let a = wi_state("plan-a", "in_progress");
        let pa = ParsedPlan::default();
        let pairs = vec![(&a, &pa)];
        assert!(deploy_queue_from_pairs(&pairs).is_empty());
    }

    // ── M2: provenance rollup ──

    #[test]
    fn summarise_extracts_distinct_commit_shas_from_decisions() {
        let facts = vec![
            (
                "decision:a".to_string(),
                r#"{"commit_sha":"abc123","note":"x"}"#.to_string(),
                ts(10),
            ),
            (
                "decision:b".to_string(),
                r#"{"commit_sha":"def456"}"#.to_string(),
                ts(20),
            ),
            (
                "decision:c".to_string(),
                r#"{"commit_sha":"abc123"}"#.to_string(),
                ts(30),
            ),
            ("decision:d".to_string(), r#"{"no_sha":true}"#.to_string(), ts(40)),
            ("milestone:M1".to_string(), "{}".to_string(), ts(5)),
        ];
        let s = summarise_facts(&facts);
        // Distinct, insertion order; the sha-less decision is counted but adds none.
        assert_eq!(s.commit_shas, vec!["abc123".to_string(), "def456".to_string()]);
        assert_eq!(s.decision_count, 4);
    }

    #[test]
    fn contributing_agents_are_distinct_principals_sorted() {
        let rows: Vec<ExecplanFactRow> = vec![
            (
                "milestone:M1".to_string(),
                "{}".to_string(),
                ts(1),
                Some("agent-zed".to_string()),
            ),
            (
                "gate:M1".to_string(),
                "{}".to_string(),
                ts(2),
                Some("agent-amy".to_string()),
            ),
            (
                "decision:x".to_string(),
                "{}".to_string(),
                ts(3),
                Some("agent-zed".to_string()),
            ),
            (
                "decision:y".to_string(),
                "{}".to_string(),
                ts(4),
                Some("system:execplan-aggregator".to_string()),
            ),
            ("decision:z".to_string(), "{}".to_string(), ts(5), None),
        ];
        // Distinct + sorted; system:/None actors filtered out.
        assert_eq!(
            contributing_agents_from_facts(&rows),
            vec!["agent-amy".to_string(), "agent-zed".to_string()]
        );
    }

    #[test]
    fn provenance_present_with_facts_absent_without() {
        let f = file("p", 1_000, "# P\n\n## Milestones\n- M1\n");
        let parsed = parse_plan(&f.content);

        // No facts → no provenance (planned by age).
        let none = derive_state(&f, &parsed, &ExecplanFactSummary::default(), 2_000);
        assert!(none.provenance.is_none());

        // With facts → provenance carries the rollup.
        let sum = ExecplanFactSummary {
            highest_milestone_with_fact: Some(1),
            first_fact_at_unix_ms: Some(500),
            last_fact_at_unix_ms: Some(900),
            decision_count: 2,
            commit_shas: vec!["abc123".to_string()],
            contributing_agents: vec!["agent-amy".to_string()],
            ..Default::default()
        };
        let item = derive_state(&f, &parsed, &sum, 2_000);
        let prov = item.provenance.expect("provenance present when facts exist");
        assert_eq!(prov.first_activity_unix_ms, 500);
        assert_eq!(prov.last_activity_unix_ms, 900);
        assert_eq!(prov.contributing_agents, vec!["agent-amy".to_string()]);
        assert_eq!(prov.commit_shas, vec!["abc123".to_string()]);
        assert_eq!(prov.decision_count, 2);
    }

    // ── M3: Open Decisions registry wiring ──

    const REGISTRY: &str = "\
# Open Decisions Registry

| id | Question | Plane | Options | Owner | Opened | Decides-by | Status | Resolution |
|---|---|---|---|---|---|---|---|---|
| OD-1 | q1 | p | o | operator | 2026-06-12 | 2099-07-12 | open | — |
| OD-2 | q2 | p | o | operator | 2026-06-12 | 2000-01-01 | open | — |
| OD-3 | q3 | p | o | operator | 2026-06-12 | M1 | open | — |
| OD-9 | q9 | p | o | operator | 2026-06-12 | 2026-06-12 | resolved | done |
";

    #[test]
    fn parse_open_decisions_reads_table() {
        let reg = parse_open_decisions(REGISTRY);
        assert_eq!(reg.len(), 4);
        assert!(!reg["OD-1"].resolved);
        assert_eq!(reg["OD-1"].decides_by, "2099-07-12");
        assert!(reg["OD-9"].resolved);
    }

    #[test]
    fn parse_plan_collects_distinct_od_refs() {
        let md = "# T\n\nResolves OD-15 and tracks OD-3, OD-15 again.\nFOOD-9 must not match; OD-3X neither.\n";
        let p = parse_plan(md);
        assert_eq!(p.open_decision_refs, vec!["OD-15".to_string(), "OD-3".to_string()]);
    }

    #[test]
    fn od_overdue_only_for_past_dates() {
        let now = 1_750_000_000_000u64; // ~2025-06-15
        assert!(od_is_overdue("2000-01-01", now));
        assert!(!od_is_overdue("2099-01-01", now));
        assert!(!od_is_overdue("M1", now)); // free text never overdue
        assert!(!od_is_overdue("—", now));
    }

    #[test]
    fn apply_open_decisions_surfaces_open_drops_resolved() {
        let reg = parse_open_decisions(REGISTRY);
        let now = 1_750_000_000_000u64; // before OD-1's 2099 date
        let mut items = vec![wi_od("a", &["OD-1", "OD-9", "OD-3"])];
        apply_open_decisions(&mut items, Some(&reg), now);
        // OD-9 resolved → dropped; OD-1 + OD-3 open; neither overdue → no block.
        assert_eq!(items[0].open_decisions, vec!["OD-1".to_string(), "OD-3".to_string()]);
        assert_eq!(items[0].state, "planned");
        assert!(items[0].blocker_reason.is_none());
    }

    #[test]
    fn apply_open_decisions_overdue_blocks_active_plan() {
        let reg = parse_open_decisions(REGISTRY);
        let now = 1_750_000_000_000u64; // after OD-2's 2000-01-01
        let mut items = vec![wi_od("a", &["OD-1", "OD-2"])];
        apply_open_decisions(&mut items, Some(&reg), now);
        // OD-2 overdue → sorted first, plan flips to blocked with a reason.
        assert_eq!(items[0].open_decisions, vec!["OD-2".to_string(), "OD-1".to_string()]);
        assert_eq!(items[0].state, "blocked");
        assert!(items[0].blocker_reason.as_deref().unwrap().contains("OD-2"));
    }

    #[test]
    fn apply_open_decisions_unknown_ref_is_dropped() {
        let reg = parse_open_decisions(REGISTRY);
        let mut items = vec![wi_od("a", &["OD-999"])];
        apply_open_decisions(&mut items, Some(&reg), 1_750_000_000_000);
        assert!(items[0].open_decisions.is_empty(), "unregistered OD dropped");
    }

    #[test]
    fn apply_open_decisions_none_registry_clears() {
        let mut items = vec![wi_od("a", &["OD-1"])];
        apply_open_decisions(&mut items, None, 1_750_000_000_000);
        assert!(items[0].open_decisions.is_empty());
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
    fn rule_4_broadened_gate_vocab_is_complete() {
        // The workflow stores "passed" / "passed+merged" / "done", not the
        // literal "complete" — these must still flip the board.
        let f = file("done", 1_000, "# Done\n## Milestones\n- M1\n- M2\n");
        let p = parse_plan(&f.content);
        let s = summarise_facts(&[
            ("gate:M1".to_string(), r#"{"status":"passed"}"#.to_string(), ts(2_000)),
            (
                "gate:M2".to_string(),
                r#"{"status":"passed+merged"}"#.to_string(),
                ts(3_000),
            ),
        ]);
        assert_eq!(derive_state(&f, &p, &s, 4_000).state, "complete");
    }

    #[test]
    fn incomplete_status_does_not_count_as_complete() {
        assert!(!is_complete_status("incomplete"));
        assert!(is_complete_status("passed"));
        assert!(is_complete_status("DONE"));
        assert!(is_complete_status("passed+merged"));
    }

    #[test]
    fn rule_4_all_checkboxes_ticked_is_complete_without_facts() {
        // A plan whose `## Milestones` are all ticked reads complete even with
        // no gate facts stored.
        let md = "# Done\n## Milestones\n- [x] **M1 — a**\n  - [x] M1.1 sub\n- [x] **M2 — b**\n";
        let f = file("checked", 1_000, md);
        let p = parse_plan(&f.content);
        assert_eq!(p.milestones_declared, vec![1, 2]);
        assert_eq!(p.milestones_checked, vec![1, 2]);
        let item = derive_state(&f, &p, &ExecplanFactSummary::default(), 4_000);
        assert_eq!(item.state, "complete");
    }

    #[test]
    fn rule_4_partial_checkboxes_is_not_complete() {
        let md = "# WIP\n## Milestones\n- [x] **M1 — a**\n- [ ] **M2 — b**\n";
        let f = file("wip", 1_000, md);
        let p = parse_plan(&f.content);
        assert_eq!(p.milestones_checked, vec![1]);
        // No facts + recent mtime + not all checked → planned, not complete.
        assert_ne!(
            derive_state(&f, &p, &ExecplanFactSummary::default(), 1_500).state,
            "complete"
        );
    }

    #[test]
    fn owner_auto_derived_from_latest_principal_fact_actor() {
        let rows: Vec<ExecplanFactRow> = vec![
            (
                "gate:M1".to_string(),
                "{}".to_string(),
                ts(1_000),
                Some("alice".to_string()),
            ),
            (
                "gate:M2".to_string(),
                "{}".to_string(),
                ts(3_000),
                Some("bob".to_string()),
            ),
            // system / reserved actors are ignored even though newer.
            (
                "milestone:M3".to_string(),
                "{}".to_string(),
                ts(4_000),
                Some("system:x".to_string()),
            ),
            ("decision:y".to_string(), "{}".to_string(), ts(2_000), None),
        ];
        assert_eq!(owner_from_facts(&rows).as_deref(), Some("bob"));
        assert_eq!(owner_from_facts(&[]).as_deref(), None);
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

    // ── Board-fidelity M1: staleness flag + archive-age cap on fact'd plans ──

    #[test]
    fn rule_6_stale_flag_and_archive_age_cap() {
        const DAY: i64 = 86_400_000;
        let now: u64 = 1_000 * DAY as u64;
        let f = file("p", 1_000, "# P\n## Milestones\n- M1\n- M2\n");
        let p = parse_plan(&f.content);
        let mk = |days_ago: i64| {
            summarise_facts(&[(
                "milestone:M1".to_string(),
                "{}".to_string(),
                ts(now as i64 - days_ago * DAY),
            )])
        };
        // fresh (5d) → in_progress, not stale
        let it = derive_state(&f, &p, &mk(5), now);
        assert_eq!(it.state, "in_progress");
        assert_eq!(it.stale, Some(false));
        // lapsed (20d > 14d) → in_progress, stale
        let it = derive_state(&f, &p, &mk(20), now);
        assert_eq!(it.state, "in_progress");
        assert_eq!(it.stale, Some(true));
        // ancient (120d > 90d) → archive via the age cap, stale cleared
        let it = derive_state(&f, &p, &mk(120), now);
        assert_eq!(it.state, "archive");
        assert_eq!(it.stale, None);
    }

    #[test]
    fn no_declared_milestones_archives_when_past_cap() {
        const DAY: i64 = 86_400_000;
        let now: u64 = 1_000 * DAY as u64;
        // A fact'd doc with no `## Milestones` — can never reach `complete`.
        let f = file("handoff", 1_000, "# Handoff\n\nNo milestones section.\n");
        let p = parse_plan(&f.content);
        assert!(p.milestones_declared.is_empty());
        let mk = |days_ago: i64| {
            summarise_facts(&[(
                "milestone:M1".to_string(),
                "{}".to_string(),
                ts(now as i64 - days_ago * DAY),
            )])
        };
        // recently active → in_progress (honest: it IS being touched)
        assert_eq!(derive_state(&f, &p, &mk(3), now).state, "in_progress");
        // past the cap → archive (no path to complete; not pinned forever)
        assert_eq!(derive_state(&f, &p, &mk(100), now).state, "archive");
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
    fn complete_status_with_standalone_supersession_archives_with_pointer() {
        // Regression for workspace-scan-storyline-improvements-2026-05-03.md:
        // its completion declaration and supersession declaration are separate
        // lines, and both pieces of state must survive projection.
        let f = file(
            "workspace-scan-storyline-improvements-2026-05-03",
            1_000,
            "# Workspace scan storyline improvements\n\nStatus: Complete (all milestones shipped)\n\nSuperseded by [[workspace-scan-storyline-v2]]\n",
        );
        let p = parse_plan(&f.content);
        assert_eq!(p.superseded_by.as_deref(), Some("workspace-scan-storyline-v2"));
        let item = derive_state(&f, &p, &ExecplanFactSummary::default(), 2_000);
        assert_eq!(item.state, "archive");
        assert_eq!(item.superseded_by.as_deref(), Some("workspace-scan-storyline-v2"));
    }

    #[test]
    fn terminal_status_leads_use_exact_token_vocabulary() {
        for value in [
            "done",
            "SHIPPED to production",
            "Deployed — rollout verified",
            "landed (main)",
            "Merged: PR #42",
            "Done (M1–M5 complete; acceptance evidence recorded)",
        ] {
            let f = file("terminal", 1_000, &format!("# Terminal\n\nStatus: {value}\n"));
            let p = parse_plan(&f.content);
            assert_eq!(
                derive_state(&f, &p, &ExecplanFactSummary::default(), 2_000).state,
                "complete",
                "{value:?} must be a completion declaration"
            );
        }
    }

    #[test]
    fn milestone_range_before_complete_is_not_a_status_declaration() {
        let f = file("range", 1_000, "# Range\n\nStatus: M0–M5 complete\n");
        let p = parse_plan(&f.content);
        assert_eq!(declared_status(p.status_line.as_deref().unwrap_or("")), None);
        assert_eq!(
            derive_state(&f, &p, &ExecplanFactSummary::default(), 2_000).state,
            "planned"
        );
    }

    #[test]
    fn status_value_may_wrap_terminal_token_in_bold_markup() {
        let f = file("bold-complete", 1_000, "# Bold\n\nStatus: **Complete**\n");
        let p = parse_plan(&f.content);
        assert_eq!(p.status_line.as_deref(), Some("**Complete**"));
        assert_eq!(
            derive_state(&f, &p, &ExecplanFactSummary::default(), 2_000).state,
            "complete"
        );
    }

    #[test]
    fn status_in_progress_ignores_complete_in_trailing_prose() {
        let f = file(
            "live",
            1_000,
            "# Live\n\nStatus: In progress — M0 complete; M1 is active\n## Milestones\n- M0\n- M1\n",
        );
        let p = parse_plan(&f.content);
        let s = summarise_facts(&[("milestone:M0".to_string(), "{}".to_string(), ts(2_000))]);
        assert_eq!(derive_state(&f, &p, &s, 3_000).state, "in_progress");
    }

    #[test]
    fn complete_in_non_status_line_does_not_change_declared_state() {
        let f = file(
            "live",
            1_000,
            "# Live\n\nStatus: In progress\n\nEvidence note: COMPLETE is the expected gate token.\n",
        );
        let p = parse_plan(&f.content);
        assert_eq!(
            derive_state(&f, &p, &ExecplanFactSummary::default(), 2_000).state,
            "in_progress"
        );
    }

    #[test]
    fn superseded_prose_is_not_a_declaration_but_status_supersession_is() {
        let live = file(
            "live",
            1_000,
            "# Live\n\nStatus: In progress — superseded by is discussed in the decision log\n",
        );
        let parsed_live = parse_plan(&live.content);
        assert_eq!(parsed_live.superseded_by, None);
        assert_eq!(
            derive_state(&live, &parsed_live, &ExecplanFactSummary::default(), 2_000).state,
            "in_progress"
        );

        let replaced = file(
            "old",
            1_000,
            "# Old\n\nStatus: Superseded by [[replacement-plan]] — scope moved\n",
        );
        let parsed_replaced = parse_plan(&replaced.content);
        let item = derive_state(&replaced, &parsed_replaced, &ExecplanFactSummary::default(), 2_000);
        assert_eq!(item.state, "archive");
        assert_eq!(item.superseded_by.as_deref(), Some("replacement-plan"));
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
            tenant_hash: "default".to_string(),
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
    fn execplan_item_plan_content_hash_matches_canonical_fixture() -> Result<(), Box<dyn std::error::Error>> {
        const PLAN_BYTES: &[u8] = b"# Canonical plan\n\nStatus: Planned\n";
        let dir = tempfile::tempdir()?;
        let plan_path = dir.path().join("canonical.md");
        std::fs::write(&plan_path, PLAN_BYTES)?;

        let items = list_execplans(&FactStore::new(), dir.path(), 1_000)?;
        let [item] = items.as_slice() else {
            return Err(std::io::Error::other(format!("expected one projected plan, got {}", items.len())).into());
        };
        let fixture_bytes = std::fs::read(plan_path)?;
        let expected = blake3::hash(&fixture_bytes).to_hex().to_string();

        assert_eq!(item.plan_content_hash.as_deref(), Some(expected.as_str()));
        Ok(())
    }

    #[test]
    fn plan_content_hash_distinguishes_one_byte_and_matches_identical_copies() -> Result<(), Box<dyn std::error::Error>>
    {
        const SAME_BYTES: &[u8] = b"# Copy A\n\nStatus: Planned\n";
        const DIFFERENT_BYTES: &[u8] = b"# Copy B\n\nStatus: Planned\n";
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("same-a.md"), SAME_BYTES)?;
        std::fs::write(dir.path().join("same-b.md"), SAME_BYTES)?;
        std::fs::write(dir.path().join("different.md"), DIFFERENT_BYTES)?;

        let items = list_execplans(&FactStore::new(), dir.path(), 1_000)?;
        let hash_for = |id: &str| {
            items
                .iter()
                .find(|item| item.id == id)
                .and_then(|item| item.plan_content_hash.as_deref())
        };
        let same_expected = blake3::hash(SAME_BYTES).to_hex().to_string();
        let different_expected = blake3::hash(DIFFERENT_BYTES).to_hex().to_string();

        assert_eq!(
            SAME_BYTES.iter().zip(DIFFERENT_BYTES).filter(|(a, b)| a != b).count(),
            1,
            "the mismatch fixture must differ by exactly one byte"
        );
        assert_eq!(hash_for("execplan:same-a"), Some(same_expected.as_str()));
        assert_eq!(hash_for("execplan:same-b"), Some(same_expected.as_str()));
        assert_eq!(hash_for("execplan:different"), Some(different_expected.as_str()));
        assert_eq!(hash_for("execplan:same-a"), hash_for("execplan:same-b"));
        assert_ne!(hash_for("execplan:same-a"), hash_for("execplan:different"));
        Ok(())
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

    // ══════════════════════════════════════════════════════════════════════
    // A3 — next-ready milestone (alphanumeric ids, deps graph). Default OFF.
    // A4 — drafting board state. Default OFF.
    //
    // The two feature flags mutate process-global env vars, so the tests that
    // toggle them serialize on FLAG_GUARD to avoid racing the (parallel) rest
    // of the suite that calls `summarise_facts` / `derive_state`. The pure
    // graph/ordering helpers are tested directly (no env) where possible.
    // ══════════════════════════════════════════════════════════════════════

    use std::sync::Mutex;
    static FLAG_GUARD: Mutex<()> = Mutex::new(());

    /// RAII flag setter that restores the prior value on drop. Holds the
    /// `FLAG_GUARD` lock for the lifetime of the guard so flag-on windows never
    /// overlap across tests.
    struct FlagOn<'a> {
        _lock: std::sync::MutexGuard<'a, ()>,
        var: &'static str,
        prev: Option<String>,
    }
    impl<'a> FlagOn<'a> {
        fn set(var: &'static str) -> Self {
            let _lock = FLAG_GUARD.lock().unwrap_or_else(|e| e.into_inner());
            let prev = std::env::var(var).ok();
            std::env::set_var(var, "1");
            FlagOn { _lock, var, prev }
        }
    }
    impl Drop for FlagOn<'_> {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.var, v),
                None => std::env::remove_var(self.var),
            }
        }
    }

    fn gates(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }
    fn deps(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, after)| (k.to_string(), after.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    // ── milestone-id ordering + numeric back-compat ──

    #[test]
    fn milestone_id_key_orders_numeric_aware_then_by_prefix() {
        let mut ids = vec!["M10", "M2", "M0", "B5", "A1", "A2", "B1"];
        ids.sort_by(|a, b| milestone_id_key(a).cmp(&milestone_id_key(b)));
        // Alpha prefix first (A < B < M), then numeric suffix (M2 < M10).
        assert_eq!(ids, vec!["A1", "A2", "B1", "B5", "M0", "M2", "M10"]);
    }

    #[test]
    fn numeric_milestone_id_only_matches_bare_m_number() {
        assert_eq!(numeric_milestone_id("M0"), Some(0));
        assert_eq!(numeric_milestone_id("M12"), Some(12));
        assert_eq!(numeric_milestone_id("A1"), None);
        assert_eq!(numeric_milestone_id("B5"), None);
        assert_eq!(numeric_milestone_id("M1.2"), None);
        assert_eq!(numeric_milestone_id("Mx"), None);
        assert_eq!(numeric_milestone_id(""), None);
        assert_eq!(numeric_milestone_id("M"), None);
    }

    // ── compute_next_ready: pure graph logic (no env) ──

    #[test]
    fn next_ready_none_when_no_deps() {
        assert_eq!(compute_next_ready(&deps(&[]), &gates(&[])), None);
    }

    #[test]
    fn next_ready_picks_lowest_ready_milestone() {
        // A1 ready (no after); A2 needs A1; B1 needs A2.
        let d = deps(&[("A2", &["A1"]), ("B1", &["A2"]), ("A1", &[])]);
        // No gates yet → only A1 is ready (A2 needs A1, B1 needs A2).
        assert_eq!(compute_next_ready(&d, &gates(&[])).as_deref(), Some("A1"));
        // A1 done → A1 is EXCLUDED (its own gate is passing); A2 now has its dep
        // (A1) met and isn't itself done, so A2 is the next-ready. The pointer
        // must skip the already-complete A1 (A3 completed-exclusion fix).
        let g = gates(&[("A1", "passed")]);
        assert_eq!(compute_next_ready(&d, &g).as_deref(), Some("A2"));
    }

    #[test]
    fn next_ready_advances_as_gates_pass_alphanumeric() {
        // Linear chain over alphanumeric ids; only the deps-declared nodes are in
        // the graph. M0 (no after) → A1 (after M0) → B5 (after A1).
        let d = deps(&[("A1", &["M0"]), ("B5", &["A1"]), ("M0", &[])]);
        // Nothing passing → M0 ready (only M0 has its deps met; A1 needs M0, B5
        // needs A1).
        assert_eq!(compute_next_ready(&d, &gates(&[])).as_deref(), Some("M0"));
        // M0 passed → M0 excluded (done); A1's dep (M0) is met and A1 isn't done,
        // so A1 is next-ready.
        let g = gates(&[("M0", "complete")]);
        assert_eq!(compute_next_ready(&d, &g).as_deref(), Some("A1"));
        // M0 + A1 passed → both excluded (done); B5's dep (A1) is met and B5 isn't
        // done, so B5 is next-ready.
        let g = gates(&[("M0", "complete"), ("A1", "passed+merged")]);
        assert_eq!(compute_next_ready(&d, &g).as_deref(), Some("B5"));
        // M0 + A1 + B5 all passed → every dep-satisfied node is complete → None.
        let g = gates(&[("M0", "complete"), ("A1", "passed+merged"), ("B5", "done")]);
        assert_eq!(compute_next_ready(&d, &g), None);
    }

    #[test]
    fn next_ready_unmet_dep_is_not_ready() {
        // Only B1 in the graph, needing A1 which has no passing gate → B1 not
        // ready, and A1 isn't a graph node → nothing ready.
        let d = deps(&[("B1", &["A1"])]);
        assert_eq!(compute_next_ready(&d, &gates(&[])), None);
        // A failing/blocked gate on A1 still doesn't satisfy the dep.
        assert_eq!(compute_next_ready(&d, &gates(&[("A1", "blocked")])), None);
        // A passing gate on A1 unblocks B1.
        assert_eq!(
            compute_next_ready(&d, &gates(&[("A1", "passed")])).as_deref(),
            Some("B1")
        );
    }

    #[test]
    fn next_ready_skips_completed_lowest_milestone() {
        // Live-smoke regression: a partially-complete plan whose lowest
        // dep-satisfied milestone is ITSELF complete must skip to the next
        // incomplete dep-satisfied one — not point back at the done milestone.
        // (The smoke returned "A2" whose gate:A2 was passed.) Chain: A1 → A2 → A3.
        let d = deps(&[("A1", &[]), ("A2", &["A1"]), ("A3", &["A2"])]);
        // A1 and A2 both done → A1/A2 excluded; A3's dep (A2) met, A3 not done.
        let g = gates(&[("A1", "passed"), ("A2", "passed")]);
        assert_eq!(compute_next_ready(&d, &g).as_deref(), Some("A3"));
    }

    #[test]
    fn next_ready_none_when_all_milestones_complete() {
        // Every dep-satisfied milestone already complete → nothing left to do.
        let d = deps(&[("A1", &[]), ("A2", &["A1"])]);
        let g = gates(&[("A1", "passed"), ("A2", "done")]);
        assert_eq!(compute_next_ready(&d, &g), None);
    }

    #[test]
    fn next_ready_fresh_plan_picks_first_incomplete() {
        // A fresh plan (no passing gates) → the lowest dep-satisfied, not-yet-done
        // milestone is next. Regression for the original "fresh plan" behaviour.
        let d = deps(&[("A1", &[]), ("A2", &["A1"]), ("B1", &["A2"])]);
        assert_eq!(compute_next_ready(&d, &gates(&[])).as_deref(), Some("A1"));
    }

    // ── summarise_facts: deps parsing with ALPHANUMERIC ids (flag ON) ──

    #[test]
    fn summarise_parses_deps_and_alphanumeric_gates_when_flag_on() {
        let _flag = FlagOn::set(NEXT_READY_MILESTONE_FLAG_ENV);
        let facts = vec![
            ("milestone:A1".to_string(), "{}".to_string(), ts(1_000)),
            ("gate:A1".to_string(), r#"{"status":"passed"}"#.to_string(), ts(1_500)),
            ("gate:B5".to_string(), r#"{"status":"blocked"}"#.to_string(), ts(2_000)),
            ("deps:B5".to_string(), r#"{"after":["A1","A2"]}"#.to_string(), ts(2_500)),
            ("deps:A1".to_string(), r#"{"after":[]}"#.to_string(), ts(2_600)),
        ];
        let s = summarise_facts(&facts);
        // String-keyed gate map carries alphanumeric ids.
        assert_eq!(s.gate_statuses_by_id.get("A1").map(String::as_str), Some("passed"));
        assert_eq!(s.gate_statuses_by_id.get("B5").map(String::as_str), Some("blocked"));
        // Deps map parsed from `deps:<ID>` facts.
        assert_eq!(s.deps_by_id.get("A1"), Some(&Vec::<String>::new()));
        assert_eq!(s.deps_by_id.get("B5"), Some(&vec!["A1".to_string(), "A2".to_string()]));
        // Alphanumeric ids are NOT counted in the numeric back-compat map.
        assert!(s.gate_statuses.is_empty(), "numeric map untouched by A1/B5 gates");
        assert_eq!(s.highest_milestone_with_fact, None, "no numeric M<n> facts");
    }

    #[test]
    fn summarise_numeric_back_compat_still_populated() {
        // Mixed numeric + alphanumeric: the numeric maps see only `M<n>`.
        let _flag = FlagOn::set(NEXT_READY_MILESTONE_FLAG_ENV);
        let facts = vec![
            ("milestone:M1".to_string(), "{}".to_string(), ts(1_000)),
            ("milestone:M2".to_string(), "{}".to_string(), ts(1_100)),
            ("gate:M1".to_string(), r#"{"status":"complete"}"#.to_string(), ts(1_500)),
            ("milestone:A1".to_string(), "{}".to_string(), ts(1_600)),
        ];
        let s = summarise_facts(&facts);
        assert_eq!(s.highest_milestone_with_fact, Some(2));
        assert_eq!(s.gate_statuses.get(&1).map(String::as_str), Some("complete"));
        assert_eq!(s.gate_statuses_by_id.get("M1").map(String::as_str), Some("complete"));
    }

    #[test]
    fn summarise_skips_deps_when_flag_off() {
        // Default OFF: a `deps:*` fact must be ignored (byte-identical path).
        let _lock = FLAG_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(NEXT_READY_MILESTONE_FLAG_ENV);
        let facts = vec![("deps:A1".to_string(), r#"{"after":["M0"]}"#.to_string(), ts(1_000))];
        let s = summarise_facts(&facts);
        assert!(s.deps_by_id.is_empty(), "deps facts unread when flag off");
    }

    // ── A3 end-to-end through mk_item / derive_state (flag ON) ──

    #[test]
    fn next_ready_surfaced_on_workitem_when_flag_on() {
        let _flag = FlagOn::set(NEXT_READY_MILESTONE_FLAG_ENV);
        let f = file("p", 1_000, "# P\n## Milestones\n- M1\n");
        let p = parse_plan(&f.content);
        let facts = vec![
            ("milestone:A1".to_string(), "{}".to_string(), ts(2_000)),
            ("gate:M0".to_string(), r#"{"status":"passed"}"#.to_string(), ts(2_100)),
            ("deps:M0".to_string(), r#"{"after":[]}"#.to_string(), ts(2_200)),
            ("deps:A1".to_string(), r#"{"after":["M0"]}"#.to_string(), ts(2_300)),
        ];
        let s = summarise_facts(&facts);
        let item = derive_state(&f, &p, &s, 3_000);
        // M0 passed → A1 ready; A1 (prefix A) sorts below M0 (prefix M).
        assert_eq!(item.next_ready_milestone.as_deref(), Some("A1"));
    }

    #[test]
    fn next_ready_none_on_workitem_when_flag_off() {
        // Flag OFF: even with deps facts present in the raw rows, the field is
        // None (deps unread + assignment gated). This is the flag-off no-op.
        let _lock = FLAG_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(NEXT_READY_MILESTONE_FLAG_ENV);
        let f = file("p", 1_000, "# P\n## Milestones\n- M1\n");
        let p = parse_plan(&f.content);
        let facts = vec![
            ("deps:M0".to_string(), r#"{"after":[]}"#.to_string(), ts(2_200)),
            ("milestone:M1".to_string(), "{}".to_string(), ts(2_000)),
        ];
        let s = summarise_facts(&facts);
        let item = derive_state(&f, &p, &s, 3_000);
        assert_eq!(item.next_ready_milestone, None);
        // The legacy derive path is unchanged: a single milestone fact → in_progress.
        assert_eq!(item.state, "in_progress");
    }

    // ── A4: drafting board state (flag ON) ──

    #[test]
    fn drafting_status_derives_drafting_when_flag_on() {
        let _flag = FlagOn::set(DRAFTING_STATE_FLAG_ENV);
        let f = file("d", 1_000, "# Draft Plan\n\nStatus: Draft\n## Milestones\n- M1\n");
        let p = parse_plan(&f.content);
        assert_eq!(p.status_line.as_deref(), Some("Draft"));
        let item = derive_state(&f, &p, &ExecplanFactSummary::default(), 2_000);
        assert_eq!(item.state, "drafting");
    }

    #[test]
    fn drafting_status_case_insensitive_exact_value() {
        // Case-insensitive on the EXACT value: "DRAFT" (any case, trimmed) → draft.
        let _flag = FlagOn::set(DRAFTING_STATE_FLAG_ENV);
        let f = file("d", 1_000, "# D\n\nStatus: DRAFT\n");
        let p = parse_plan(&f.content);
        let item = derive_state(&f, &p, &ExecplanFactSummary::default(), 2_000);
        assert_eq!(item.state, "drafting");
    }

    #[test]
    fn drafting_accepts_prose_trailer_after_token() {
        let _flag = FlagOn::set(DRAFTING_STATE_FLAG_ENV);
        let f = file(
            "d",
            1_000,
            "# D\n\nStatus: Draft — awaiting operator go (audit M0 closed out)\n",
        );
        let p = parse_plan(&f.content);
        assert_eq!(
            derive_state(&f, &p, &ExecplanFactSummary::default(), 2_000).state,
            "drafting"
        );
    }

    #[test]
    fn drafting_rejects_non_token_prefixes() {
        // The declaration must start with the token and end it at a word
        // boundary; prose before it and longer words do not declare Draft.
        let _flag = FlagOn::set(DRAFTING_STATE_FLAG_ENV);
        let now: u64 = 10 * 24 * 60 * 60 * 1000;
        for value in ["in draft review", "Drafting", "redrafted"] {
            let f = file(
                "d",
                now - 5 * 24 * 60 * 60 * 1000,
                &format!("# D\n\nStatus: {value}\n## Milestones\n- M1\n"),
            );
            let p = parse_plan(&f.content);
            let item = derive_state(&f, &p, &ExecplanFactSummary::default(), now);
            assert_ne!(item.state, "drafting", "{value:?} must not derive drafting");
            assert_eq!(item.state, "planned", "{value:?} should fall through to planned");
        }
    }

    #[test]
    fn drafting_ignores_status_inside_code_fence() {
        // A `Status: Draft` (and the bare `Status:Draft)` diagram form) inside a
        // fenced ``` block is documentation, not a declaration. The fence guard in
        // parse_plan must suppress it so the plan does NOT derive drafting (A4
        // false-positive fix). The plan body has no real declarative Status line.
        let _flag = FlagOn::set(DRAFTING_STATE_FLAG_ENV);
        let now: u64 = 10 * 24 * 60 * 60 * 1000;
        let md = "# D\n\nThis plan documents the drafting feature.\n\n```text\nstate machine:\n  Status:Draft) --> appraise\n  Status: Draft\n```\n\n## Milestones\n- M1\n";
        let f = file("d", now - 5 * 24 * 60 * 60 * 1000, md);
        let p = parse_plan(&f.content);
        assert_eq!(p.status_line, None, "fenced Status line must not be captured");
        let item = derive_state(&f, &p, &ExecplanFactSummary::default(), now);
        assert_ne!(item.state, "drafting", "fenced Status:Draft must not derive drafting");
        assert_eq!(item.state, "planned");
    }

    #[test]
    fn drafting_ignores_status_in_prose_code_span() {
        // A prose line that *mentions* the pattern in a code span — e.g.
        // "- `Status: Draft` → a new state" — is not a declarative Status line
        // (it begins with a list marker, and the value carries a trailer). It must
        // not be captured as the status_line, nor derive drafting.
        let _flag = FlagOn::set(DRAFTING_STATE_FLAG_ENV);
        let now: u64 = 10 * 24 * 60 * 60 * 1000;
        let md = "# D\n\n- `Status: Draft` → a new state the board can show.\n\n## Milestones\n- M1\n";
        let f = file("d", now - 5 * 24 * 60 * 60 * 1000, md);
        let p = parse_plan(&f.content);
        assert_eq!(p.status_line, None, "code-span prose mention must not be captured");
        let item = derive_state(&f, &p, &ExecplanFactSummary::default(), now);
        assert_ne!(
            item.state, "drafting",
            "prose code-span mention must not derive drafting"
        );
        assert_eq!(item.state, "planned");
    }

    #[test]
    fn drafting_no_op_when_flag_off() {
        // Flag OFF: a `Status: Draft` plan derives via the normal rules, NOT
        // drafting. This is the flag-off byte-identical guarantee for A4.
        let _lock = FLAG_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(DRAFTING_STATE_FLAG_ENV);
        let now: u64 = 10 * 24 * 60 * 60 * 1000;
        let f = file(
            "d",
            now - 5 * 24 * 60 * 60 * 1000,
            "# D\n\nStatus: Draft\n## Milestones\n- M1\n",
        );
        let p = parse_plan(&f.content);
        let item = derive_state(&f, &p, &ExecplanFactSummary::default(), now);
        assert_ne!(item.state, "drafting", "flag off → no drafting state");
        assert_eq!(item.state, "planned");
    }

    #[test]
    fn feature_flags_default_off() {
        let _lock = FLAG_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(DRAFTING_STATE_FLAG_ENV);
        std::env::remove_var(NEXT_READY_MILESTONE_FLAG_ENV);
        assert!(!drafting_state_enabled(), "A4 flag must default OFF");
        assert!(!next_ready_milestone_enabled(), "A3 flag must default OFF");
    }
}
