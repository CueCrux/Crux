// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Recall match floor — honest misses instead of recency filler.
//!
//! ExecPlan: `crux-memory-parity-and-codex-bridge-2026-09-17`, milestone M1.
//!
//! ## The defect this closes
//!
//! Both fact-recall surfaces — MCP `query_facts`
//! ([`crate::tools::facts::handle_query_facts`]) and HTTP `GET /v1/facts`
//! (`corecruxd::http::facts::query_facts`) — admitted a candidate when **any
//! one** whitespace-split query term appeared as a substring of the entity, key
//! or value, and then ranked the survivors by effective confidence and recency.
//! Nothing in that pipeline measured *how much* of the query a fact answered, so
//! a topic search that matched nothing meaningful still returned the store's
//! most recent high-confidence facts, and the response carried no signal that it
//! had fallen back. Measured over the `drivew-host-memory-gold-v1` gold set (98
//! queries): mean query-term coverage 0.379 on the native half, and **zero**
//! honest misses in 98 queries.
//!
//! ## What this module adds
//!
//! A per-candidate relevance score in `0.0..=1.0` (query-term coverage, with
//! whole-word matches weighted above bare substring hits and entity/key hits
//! treated as whole-word), plus a **floor**. A candidate under the floor is
//! never silently substituted for a real answer:
//!
//! - nothing clears the floor ⇒ an EMPTY result set with `match: "none"` and a
//!   [`SUGGEST_NO_MATCH`] hint pointing at entity-prefix lookups (the query
//!   shape that already resolves exactly),
//! - something clears it ⇒ only the clearing rows are returned by default, each
//!   labelled [`MatchTier::Strong`] or [`MatchTier::Partial`],
//! - below-floor rows are emitted only on explicit opt-in (`include_fallback`)
//!   and are then labelled [`MatchTier::Fallback`] so a caller can tell filler
//!   from an answer.
//!
//! Entity-addressed recall (`entity` / `entity_prefix`, and free-text queries
//! shaped like an address such as `execplan:<slug>` or `gate:M2`) scores 1.00 by
//! construction and is never filtered — that shape already worked and the plan's
//! gate forbids regressing it.
//!
//! ## Rollback
//!
//! One environment variable, [`MATCH_FLOOR_ENV`] (`CORECRUXD_RECALL_MATCH_FLOOR`),
//! default **ON**. Set it to `0`/`false`/`off`/`no` and every surface reverts to
//! the pre-M1 filter-and-rank-by-recency behaviour. A numeric value in
//! `0.0..=1.0` overrides [`DEFAULT_MATCH_FLOOR`] without a rebuild.

use std::collections::BTreeSet;

/// Environment variable gating the match floor. Default **ON** (unset ⇒
/// enabled at [`DEFAULT_MATCH_FLOOR`]). Accepts a boolean-ish off switch
/// (`0`/`false`/`off`/`no`/empty) or a floor value in `0.0..=1.0`.
pub const MATCH_FLOOR_ENV: &str = "CORECRUXD_RECALL_MATCH_FLOOR";

/// Default relevance floor: a candidate must answer at least ~half the query's
/// content terms to count as a match rather than filler.
///
/// Tuned by sweep on `drivew-host-memory-gold-v1` against a 5,818-fact export of
/// the drivew-host store (see the ExecPlan's M1 gate). 0.45 is the knee: 12/12
/// out-of-domain probe topics become honest misses (0.34 let two through on two
/// incidental generic terms) while the gold set holds at native coverage 0.750 /
/// distinctive 0.603. 0.55 starts costing real recall (native 0.690, below-half
/// 7 -> 16).
pub const DEFAULT_MATCH_FLOOR: f64 = 0.45;

/// At or above this score a match is reported as `strong` rather than `partial`.
pub const STRONG_MATCH_SCORE: f64 = 0.70;

/// Hint returned with `match: "none"`. Points at the query shape that measured
/// 1.00 coverage in the M0 baseline instead of leaving the caller to retry the
/// same failing free-text search.
pub const SUGGEST_NO_MATCH: &str = "no fact cleared the match floor. Address the store instead of searching it: \
     entity=\"<prefix>:<slug>\" (e.g. execplan:my-plan) or entity_prefix=\"incident:\" resolve exactly. \
     Otherwise retry with fewer, more distinctive terms, or pass include_fallback=true to see the \
     below-floor candidates labelled as filler.";

/// Minimum length of a content-bearing query term. Shorter runs are punctuation
/// or noise for substring matching.
const MIN_TERM_LEN: usize = 3;

/// Weight for a term found only as a bare substring (e.g. `cache` inside
/// `cached_at`) rather than as a whole word. Counts, but counts for less.
const SUBSTRING_WEIGHT: f64 = 0.5;

/// English/query stopwords dropped before scoring. Keeping them would let a
/// fact match on `the` and clear any floor.
const STOPWORDS: &[&str] = &[
    "the", "and", "for", "are", "was", "were", "with", "from", "this", "that", "into", "over", "under", "about",
    "after", "before", "more", "most", "some", "such", "only", "own", "same", "too", "very", "just", "now", "which",
    "who", "whom", "these", "those", "there", "here", "where", "while", "during", "each", "few", "other", "again",
    "further", "once", "how", "what", "when", "why", "you", "its", "our", "their", "new", "use", "using", "can",
    "does", "not", "all", "any", "has", "have", "had", "been", "but", "then", "than",
];

/// Whether the floor is active and where it sits.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MatchPolicy {
    /// `false` ⇒ every surface behaves exactly as it did before M1.
    pub enabled: bool,
    /// Relevance score a candidate must reach to count as a match.
    pub floor: f64,
}

impl MatchPolicy {
    /// Read [`MATCH_FLOOR_ENV`]. Unset ⇒ enabled at [`DEFAULT_MATCH_FLOOR`].
    ///
    /// Fails **safe, not off**: an unparseable value keeps the floor on at the
    /// default rather than silently restoring the dishonest path.
    pub fn from_env() -> Self {
        match std::env::var(MATCH_FLOOR_ENV) {
            Ok(raw) => Self::parse(&raw),
            Err(_) => Self::default(),
        }
    }

    /// Parse one raw env value. Exposed for tests and for callers that read the
    /// variable themselves.
    pub fn parse(raw: &str) -> Self {
        let trimmed = raw.trim().to_ascii_lowercase();
        if matches!(trimmed.as_str(), "" | "0" | "false" | "off" | "no") {
            return Self::disabled();
        }
        // The boolean ON forms are checked BEFORE the numeric branch: `=1` is
        // the natural way to write "enabled" and must not be read as a 100%
        // floor (which would reject every result). Write `1.0` for that.
        if matches!(trimmed.as_str(), "1" | "true" | "on" | "yes") {
            return Self::default();
        }
        if let Ok(value) = trimmed.parse::<f64>() {
            if value.is_finite() && (0.0..=1.0).contains(&value) {
                return Self {
                    enabled: true,
                    floor: value,
                };
            }
        }
        Self::default()
    }

    /// The pre-M1 behaviour: no floor, no labels, no honest miss.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            floor: 0.0,
        }
    }
}

impl Default for MatchPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            floor: DEFAULT_MATCH_FLOOR,
        }
    }
}

/// How a returned row related to the query. Extends the CRC-v1 envelope's
/// existing `hydrate_tier` / `demoted` / `emitted_full` vocabulary rather than
/// introducing a parallel one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchTier {
    /// Cleared [`STRONG_MATCH_SCORE`] — most of the query is answered here.
    Strong,
    /// Cleared the floor but not [`STRONG_MATCH_SCORE`].
    Partial,
    /// Below the floor. Filler: only ever emitted on explicit opt-in, always
    /// labelled.
    Fallback,
}

impl MatchTier {
    /// Wire form (`"strong"` / `"partial"` / `"fallback"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strong => "strong",
            Self::Partial => "partial",
            Self::Fallback => "fallback",
        }
    }

    /// Classify one score under `policy`.
    pub fn classify(score: f64, policy: &MatchPolicy) -> Self {
        if score < policy.floor {
            Self::Fallback
        } else if score >= STRONG_MATCH_SCORE {
            Self::Strong
        } else {
            Self::Partial
        }
    }
}

/// The parsed query: its content terms plus, when it is shaped like an entity
/// address, the normalised address.
#[derive(Clone, Debug, Default)]
pub struct QueryShape {
    /// Distinct, lowercased, stopword-free terms of length ≥ [`MIN_TERM_LEN`].
    pub terms: Vec<String>,
    /// `Some` when the query is a single whitespace-free token containing `:`
    /// (`execplan:my-plan`, `gate:M2`, `incident:2026-09-17`), normalised to
    /// lowercase with `::` collapsed to `:`.
    pub address: Option<String>,
}

impl QueryShape {
    /// True when there is nothing to score against — an empty or all-stopword
    /// query. Such a query cannot produce an honest miss, because it asserts
    /// nothing; the caller falls back to the unfiltered listing.
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty() && self.address.is_none()
    }
}

/// Collapse `::` to `:` and lowercase — the shared normal form for comparing a
/// query address against a fact entity (the store writes both `execplan::slug`
/// and `execplan:slug` shapes).
fn normalise_address(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace("::", ":")
}

/// Split into lowercase `[a-z0-9_]` runs of length ≥ [`MIN_TERM_LEN`], dropping
/// stopwords, preserving first-seen order and de-duplicating.
fn content_terms(raw: &str) -> Vec<String> {
    let lower = raw.to_ascii_lowercase();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for run in lower.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if run.len() < MIN_TERM_LEN || STOPWORDS.contains(&run) {
            continue;
        }
        if seen.insert(run.to_string()) {
            out.push(run.to_string());
        }
    }
    out
}

/// Parse a free-text query into its scoreable shape.
pub fn analyze(query: &str) -> QueryShape {
    let trimmed = query.trim();
    let address = (!trimmed.is_empty() && !trimmed.contains(char::is_whitespace) && trimmed.contains(':'))
        .then(|| normalise_address(trimmed));
    QueryShape {
        terms: content_terms(trimmed),
        address,
    }
}

/// True when `needle` occurs in `hay` delimited by non-word characters on both
/// sides (`cache` in `prompt cache ttl`, but not in `cached`).
fn contains_word(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = hay.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = hay[from..].find(needle) {
        let start = from + rel;
        let end = start + needle.len();
        let left_ok = start == 0 || !is_word_byte(bytes[start - 1]);
        let right_ok = end == bytes.len() || !is_word_byte(bytes[end]);
        if left_ok && right_ok {
            return true;
        }
        // Advance by one byte-boundary-safe step; `needle` is ASCII-lowercased
        // by the caller, so `start + 1` is always a char boundary here.
        from = start + 1;
        if from >= hay.len() {
            break;
        }
    }
    false
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Score one candidate in `0.0..=1.0`.
///
/// - An address-shaped query (`execplan:my-plan`) that prefixes the fact's
///   entity, or equals its key, scores **1.0** — the shape the M0 baseline
///   already answered perfectly.
/// - Otherwise: the fraction of the query's content terms present in the fact,
///   where a whole-word hit counts 1.0 and a bare substring hit counts
///   [`SUBSTRING_WEIGHT`]. Entity and key hits count as whole-word (the address
///   plane is exact by nature).
/// - An empty query (no terms, no address) scores 1.0: it asserts nothing, so
///   nothing can fail to answer it.
pub fn score_fact(shape: &QueryShape, entity: &str, key: &str, value: &str) -> f64 {
    if shape.is_empty() {
        return 1.0;
    }
    let entity_lower = entity.to_ascii_lowercase();
    let key_lower = key.to_ascii_lowercase();
    if let Some(address) = &shape.address {
        let normalised_entity = normalise_address(&entity_lower);
        if normalised_entity.starts_with(address.as_str())
            || normalised_entity == *address
            || key_lower == *address
            || format!("{normalised_entity}:{key_lower}").starts_with(address.as_str())
        {
            return 1.0;
        }
    }
    if shape.terms.is_empty() {
        return 0.0;
    }
    let value_lower = value.to_ascii_lowercase();
    let address_plane = format!("{entity_lower} {key_lower}");
    let mut total = 0.0f64;
    for term in &shape.terms {
        // A whole-word hit in the value counts 1.0, and so does ANY hit in the
        // address plane: the entity/key plane is exact by nature, so a term that
        // names part of a slug is a full hit even when it is glued in by hyphens.
        if address_plane.contains(term.as_str()) || contains_word(&value_lower, term) {
            total += 1.0;
        } else if value_lower.contains(term.as_str()) {
            total += SUBSTRING_WEIGHT;
        }
    }
    (total / shape.terms.len() as f64).clamp(0.0, 1.0)
}

/// What the floor did to one result set — carried into the response so the
/// caller can tell an honest miss from an empty store.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MatchStats {
    /// The floor was active for this query (`false` ⇒ flag off, or the query
    /// was entity-addressed and therefore exempt).
    pub applied: bool,
    /// The floor in force.
    pub floor: f64,
    /// Highest score among all candidates, before the floor.
    pub best_score: f64,
    /// Candidates that matched the term filter but fell below the floor.
    pub below_floor: usize,
    /// Candidates that cleared the floor.
    pub above_floor: usize,
}

impl MatchStats {
    /// Response-level marker: `"strong"`, `"partial"`, `"none"`, or `"unscored"`
    /// when the floor was not applied (flag off / addressed recall).
    pub fn marker(&self) -> &'static str {
        if !self.applied {
            return "unscored";
        }
        if self.above_floor == 0 {
            return "none";
        }
        if self.best_score >= STRONG_MATCH_SCORE {
            "strong"
        } else {
            "partial"
        }
    }

    /// True when the floor ran and nothing cleared it — the honest miss.
    pub fn is_miss(&self) -> bool {
        self.applied && self.above_floor == 0
    }
}

/// Partition scored candidates at the floor, in place.
///
/// `scores` are paired with `items` by index. Returns the [`MatchStats`] and
/// leaves `items` sorted by descending score (stable: equal scores keep the
/// caller's incoming rank, so the pre-M1 confidence/recency order survives as
/// the tiebreak). When `keep_fallback` is false, below-floor items are removed.
pub fn apply_floor<T>(
    items: &mut Vec<T>,
    scores: &mut Vec<f64>,
    policy: &MatchPolicy,
    keep_fallback: bool,
) -> MatchStats {
    debug_assert_eq!(items.len(), scores.len());
    let mut stats = MatchStats {
        applied: policy.enabled,
        floor: policy.floor,
        ..MatchStats::default()
    };
    let mut paired: Vec<(f64, T)> = scores.drain(..).zip(items.drain(..)).collect();
    // Stable sort: equal scores keep the incoming (confidence/recency) order.
    paired.sort_by(|left, right| right.0.partial_cmp(&left.0).unwrap_or(std::cmp::Ordering::Equal));
    for (score, _) in &paired {
        stats.best_score = stats.best_score.max(*score);
        if policy.enabled && *score < policy.floor {
            stats.below_floor += 1;
        } else {
            stats.above_floor += 1;
        }
    }
    if policy.enabled && !keep_fallback {
        paired.retain(|(score, _)| *score >= policy.floor);
    }
    for (score, item) in paired {
        scores.push(score);
        items.push(item);
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_defaults_on_and_parses_off_switch() {
        assert_eq!(MatchPolicy::default().enabled, true);
        assert_eq!(MatchPolicy::default().floor, DEFAULT_MATCH_FLOOR);
        for off in ["0", "false", "OFF", " no ", ""] {
            assert!(!MatchPolicy::parse(off).enabled, "{off} must disable the floor");
        }
        for on in ["1", "true", "on", "yes"] {
            let p = MatchPolicy::parse(on);
            assert!(p.enabled, "{on} must enable the floor");
            // `=1` means ON, not "floor = 1.0" (which would reject everything).
            assert_eq!(p.floor, DEFAULT_MATCH_FLOOR, "{on} must use the default floor");
        }
    }

    #[test]
    fn policy_parses_numeric_floor_override_and_fails_safe() {
        assert_eq!(MatchPolicy::parse("0.6").floor, 0.6);
        assert!(MatchPolicy::parse("0.6").enabled);
        // Out of range / nonsense => on, at the default. Never silently off.
        for bad in ["1.5", "-0.2", "banana", "NaN"] {
            let p = MatchPolicy::parse(bad);
            assert!(p.enabled, "{bad}");
            assert_eq!(p.floor, DEFAULT_MATCH_FLOOR, "{bad}");
        }
    }

    #[test]
    fn analyze_drops_stopwords_and_short_runs() {
        let shape = analyze("how do I fix the cargo deny advisory drift");
        assert!(!shape.terms.iter().any(|t| t == "the" || t == "how"));
        assert!(shape.terms.contains(&"cargo".to_string()));
        assert!(shape.terms.contains(&"advisory".to_string()));
        assert!(shape.address.is_none());
    }

    #[test]
    fn analyze_recognises_entity_addresses() {
        for q in [
            "execplan:my-plan",
            "gate:M2",
            "incident:2026-09-17",
            "execplan::my-plan",
        ] {
            assert!(analyze(q).address.is_some(), "{q} must read as an address");
        }
        // Two words is a search, not an address.
        assert!(analyze("execplan:my-plan status").address.is_none());
    }

    #[test]
    fn entity_lookups_score_one_and_never_regress() {
        let shape = analyze("execplan:crux-memory-parity");
        assert_eq!(
            score_fact(
                &shape,
                "execplan::crux-memory-parity",
                "gate:M1",
                "{\"status\":\"green\"}"
            ),
            1.0
        );
        assert_eq!(
            score_fact(&analyze("gate:M2"), "execplan:other", "gate:M2", "done"),
            1.0
        );
        assert_eq!(
            score_fact(&analyze("incident:2026-09-17"), "incident:2026-09-17", "symptom", "x"),
            1.0
        );
    }

    #[test]
    fn score_is_query_term_coverage() {
        let shape = analyze("prompt cache ttl");
        // All three terms present as whole words => 1.0
        assert_eq!(
            score_fact(&shape, "bench:x", "k", "the prompt cache ttl is one hour"),
            1.0
        );
        // One of three => 1/3
        let one_of_three = score_fact(&shape, "bench:x", "k", "the prompt was long");
        assert!((one_of_three - 1.0 / 3.0).abs() < 1e-9, "{one_of_three}");
        // None => 0
        assert_eq!(score_fact(&shape, "bench:x", "k", "unrelated milestone gate"), 0.0);
    }

    #[test]
    fn substring_only_hits_score_below_whole_word_hits() {
        let shape = analyze("cache");
        let word = score_fact(&shape, "e", "k", "the cache is warm");
        let substring = score_fact(&shape, "e", "k", "precached blobs");
        assert_eq!(word, 1.0);
        assert_eq!(substring, SUBSTRING_WEIGHT);
        assert!(substring < word);
    }

    #[test]
    fn entity_and_key_hits_count_as_whole_words() {
        let shape = analyze("paddle funnel");
        // Both terms live in the slugged entity, glued by hyphens.
        assert_eq!(score_fact(&shape, "decision:paddle-funnel-live", "state", "n/a"), 1.0);
    }

    #[test]
    fn all_stopword_query_matches_everything_rather_than_missing() {
        // A query that asserts nothing cannot produce an honest miss.
        let shape = analyze("the and for");
        assert!(shape.is_empty());
        assert_eq!(score_fact(&shape, "e", "k", "anything at all"), 1.0);
    }

    #[test]
    fn single_matching_fact_clears_the_floor_and_is_reported_strong() {
        let policy = MatchPolicy::default();
        let shape = analyze("erasure reclaim wedge");
        let mut items = vec!["hit", "filler"];
        let mut scores = vec![
            score_fact(
                &shape,
                "incident:2026-08-25",
                "cause",
                "erasure reclaim wedge on host crux",
            ),
            score_fact(&shape, "gate:M4", "status", "green, tests passing"),
        ];
        let stats = apply_floor(&mut items, &mut scores, &policy, false);
        assert_eq!(items, vec!["hit"]);
        assert_eq!(stats.above_floor, 1);
        assert_eq!(stats.below_floor, 1);
        assert_eq!(stats.marker(), "strong");
        assert!(!stats.is_miss());
    }

    #[test]
    fn nothing_clearing_the_floor_is_an_honest_miss_not_filler() {
        let policy = MatchPolicy::default();
        let shape = analyze("prompt caching ttl ephemeral");
        let mut items = vec!["recent-gate", "recent-milestone"];
        let mut scores = vec![
            score_fact(&shape, "execplan:unrelated", "gate:M2", "status green"),
            score_fact(&shape, "execplan:other", "milestone:M1", "done"),
        ];
        let stats = apply_floor(&mut items, &mut scores, &policy, false);
        assert!(items.is_empty(), "recency filler must not be substituted");
        assert!(stats.is_miss());
        assert_eq!(stats.marker(), "none");
        assert_eq!(stats.below_floor, 2);
    }

    #[test]
    fn opt_in_fallback_keeps_rows_but_labels_them() {
        let policy = MatchPolicy::default();
        let shape = analyze("prompt caching ttl ephemeral");
        let mut items = vec!["recent-gate"];
        let mut scores = vec![score_fact(&shape, "execplan:unrelated", "gate:M2", "status green")];
        let stats = apply_floor(&mut items, &mut scores, &policy, true);
        assert_eq!(items.len(), 1, "opt-in keeps the row");
        assert_eq!(MatchTier::classify(scores[0], &policy), MatchTier::Fallback);
        assert!(stats.is_miss(), "still a miss: nothing cleared the floor");
    }

    #[test]
    fn disabled_policy_keeps_every_candidate_and_reports_unscored() {
        let policy = MatchPolicy::disabled();
        let shape = analyze("prompt caching ttl");
        let mut items = vec!["a", "b"];
        let mut scores = vec![0.0, 0.0];
        let _ = shape;
        let stats = apply_floor(&mut items, &mut scores, &policy, false);
        assert_eq!(items.len(), 2);
        assert_eq!(stats.marker(), "unscored");
        assert!(!stats.is_miss());
    }

    #[test]
    fn apply_floor_sorts_by_score_and_is_stable_on_ties() {
        let policy = MatchPolicy::default();
        // `keep_fallback` so the below-floor row stays and the ORDER is what is
        // under test, not the cut.
        let mut items = vec!["low", "tie-first", "tie-second"];
        let mut scores = vec![0.4, 0.9, 0.9];
        apply_floor(&mut items, &mut scores, &policy, true);
        assert_eq!(items, vec!["tie-first", "tie-second", "low"]);
    }

    #[test]
    fn contains_word_respects_boundaries() {
        assert!(contains_word("the cache is warm", "cache"));
        assert!(!contains_word("precached blobs", "cache"));
        assert!(contains_word("cache", "cache"));
        assert!(contains_word("a-cache-b", "cache"));
        assert!(!contains_word("", "cache"));
        assert!(!contains_word("cache", ""));
    }

    #[test]
    fn tier_classification_bands() {
        let policy = MatchPolicy::default();
        assert_eq!(MatchTier::classify(0.9, &policy), MatchTier::Strong);
        assert_eq!(MatchTier::classify(0.5, &policy), MatchTier::Partial);
        assert_eq!(MatchTier::classify(0.1, &policy), MatchTier::Fallback);
        assert_eq!(MatchTier::Strong.as_str(), "strong");
        assert_eq!(MatchTier::Fallback.as_str(), "fallback");
    }
}
