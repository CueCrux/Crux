// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Spatial projection of the ExecPlan board — the data behind the console's
//! Patchbay destination (`#/patchbay`).
//!
//! [`crate::work_execplans`] already answers *what state is this plan in*. This
//! module answers the three questions a spatial view needs on top of that:
//!
//! 1. **Which system does this plan change?** ([`plane_for`]) — so plans can be
//!    grouped into rings instead of listed.
//! 2. **Which shared services does it touch?** ([`services_for`]) — so the ring
//!    can be wired to service rails on the canvas perimeter.
//! 3. **What is it, in a sentence?** ([`purpose_blurb`]) — so a card can be read
//!    without opening the plan.
//!
//! Edges are NOT computed here. They come from `ParsedPlan::depends_on` /
//! `extended_by`, which the parser derives from explicit `Depends on [[…]]`
//! declaration lines only — a bare `[[slug]]` mention in prose is deliberately
//! not an edge, so a typo can never land on the graph. [`narrow_links`] only
//! restricts those declared edges to plans that are still open.
//!
//! Every classifier here is a pure function over `(slug, title, body)` with no
//! I/O, so the whole module is testable off a string.

/// A plane is the system a plan predominantly changes. Ordered most- to
/// least-specific: earlier entries win ties, which keeps a plan that names both
/// `wikicrux` and the generic `retrieval` on WikiCrux.
///
/// Patterns are matched case-insensitively as plain substrings. They are scored,
/// not first-match: see [`plane_for`].
const PLANES: &[(&str, &[&str])] = &[
    ("ChainCrux", &["chaincrux"]),
    ("ParaCrux/CAD", &["paracrux", "brep", "geometry kernel"]),
    ("WikiCrux", &["wikicrux"]),
    ("VaultCrux", &["vaultcrux"]),
    // NOT a bare "registry": that swallows "feature registry" and makes the
    // PlanCrux plane unreachable. `rcx` already covers rcx-registry-* slugs.
    ("RCX protocol", &["rcx", "rcxprotocol"]),
    (
        "Commerce",
        &["paddle", "billing", "pricing", "checkout", "entitlement", "monetis"],
    ),
    ("Benchmarks", &["lme", "benchmark", "recall@", "scorecrux", "auditcrux"]),
    (
        "Agents/Harness",
        &["execplan", "subagent", "orchestrat", "engram", "jobclaw", "mirrorclaw"],
    ),
    (
        "Surfaces/Web",
        &["nuxt", "frontdoor", "console", "webcrux", "landing page"],
    ),
    ("PlanCrux", &["feature registry"]),
    // "Crux daemon" MUST precede "CoreCrux/Engine": `corecrux` is a prefix of
    // `corecruxd`, so both match a daemon slug and the tie-break (earlier wins)
    // is the only thing keeping daemon plans off the engine plane.
    (
        "Crux daemon",
        &["corecruxd", "crux daemon", "receipt", "projection", "fact store"],
    ),
    (
        "CoreCrux/Engine",
        &["corecrux", "cruxengine", "turboquant", "rerank", "embedding"],
    ),
];

/// Fallback when nothing scores — the daemon is the default owner of unlabelled
/// work, and an honest "Crux daemon" beats an "Other" bucket nobody looks at.
const PLANE_FALLBACK: &str = "Crux daemon";

/// Weights. A slug hit is worth far more than a body hit: ExecPlan boilerplate
/// (CLAUDE.md excerpts, deploy checklists, related-plan links) mentions nearly
/// every system in the portfolio, so an unweighted body scan files almost
/// everything under whichever plane has the most generic vocabulary. Measured
/// on the 2026-08-06 board an unweighted scan put 58 of 63 plans on one plane.
const W_SLUG: u32 = 30;
const W_TITLE: u32 = 12;
/// Body hits are counted but capped, so a long plan cannot out-shout a slug.
const BODY_CAP: u32 = 25;

/// Shared services a plan can touch. These become the rails on the canvas edge.
/// `side` groups them into the four perimeter rails.
const SERVICES: &[(&str, &str, &[&str])] = &[
    ("Anthropic API", "top", &["anthropic", "claude-", "/v1/messages"]),
    ("OpenAI API", "top", &["openai", "gpt-4", "gpt-5"]),
    (
        "GitHub / CI",
        "top",
        &["github actions", "gh pr", "merge queue", "workflow"],
    ),
    (
        "Docker/registry",
        "top",
        &["docker", "ghcr", "container image", "compose"],
    ),
    (
        "Postgres",
        "bottom",
        &["postgres", "psql", "pgvector", "database_url", "migration"],
    ),
    ("MinIO / S3", "bottom", &["minio", "object storage", "object-storage"]),
    (
        "GPU-1 / embedders",
        "bottom",
        &["gpu-1", "embedder", "cuda", "gguf", "onnx"],
    ),
    (
        "Vault (secrets)",
        "bottom",
        &["vault:8200", "kv/cuecrux", "passport-derived"],
    ),
    (
        "OTEL/tracing",
        "bottom",
        &["otel", "opentelemetry", "tracing", "jaeger"],
    ),
    ("Tailscale/tailnet", "bottom", &["tailnet", "tailscale"]),
    (
        "Crux HTTP :14800",
        "left",
        &["14800", "/v1/work", "/v1/coord", "/readyz"],
    ),
    ("Crux MCP :14801", "left", &["14801", "mcp"]),
    ("Paddle", "right", &["paddle"]),
    ("Feature registry", "right", &["3334", "/capabilities"]),
];

/// A service needs this many mentions before it counts. One passing reference in
/// a risks section is not "this plan touches Postgres".
const SERVICE_MIN_HITS: u32 = 3;
/// Cards have room for a handful of rails; more than this is noise on the canvas.
const SERVICE_MAX: usize = 5;

/// Count non-overlapping case-insensitive occurrences of `needle` in `haystack`.
/// `haystack` must already be lowercased; every pattern table above is lowercase.
fn count_hits(haystack: &str, needle: &str) -> u32 {
    if needle.is_empty() {
        return 0;
    }
    let mut n = 0u32;
    let mut rest = haystack;
    while let Some(at) = rest.find(needle) {
        n = n.saturating_add(1);
        // Advance past this match. `needle` is ASCII in every table, so
        // `at + needle.len()` is always a char boundary.
        rest = &rest[at + needle.len()..];
    }
    n
}

/// Which system does this plan predominantly change?
///
/// Scores every plane over the slug (heavily weighted), the title, and the body
/// (capped), and returns the highest. Ties go to the earlier — more specific —
/// entry in [`PLANES`].
pub fn plane_for(slug: &str, title: &str, body: &str) -> &'static str {
    let slug_l = slug.to_ascii_lowercase();
    let title_l = title.to_ascii_lowercase();
    let body_l = body.to_ascii_lowercase();
    // Slugs and titles use `-`/`_` where a pattern uses a space
    // (`feature-registry-edge-…` vs `"feature registry"`), so match against a
    // separator-normalised copy as well as the raw one. Only slug/title are
    // normalised — body patterns like `gpt-5` need their hyphens intact.
    let slug_n = slug_l.replace(['-', '_'], " ");
    let title_n = title_l.replace(['-', '_'], " ");

    let mut best: Option<(&'static str, u32)> = None;
    for (name, pats) in PLANES {
        let mut score = 0u32;
        let mut body_hits = 0u32;
        for pat in *pats {
            if slug_l.contains(pat) || slug_n.contains(pat) {
                score = score.saturating_add(W_SLUG);
            }
            if title_l.contains(pat) || title_n.contains(pat) {
                score = score.saturating_add(W_TITLE);
            }
            body_hits = body_hits.saturating_add(count_hits(&body_l, pat));
        }
        score = score.saturating_add(body_hits.min(BODY_CAP));
        if score == 0 {
            continue;
        }
        // Strictly greater: earlier (more specific) planes hold ties.
        if best.is_none_or(|(_, b)| score > b) {
            best = Some((name, score));
        }
    }
    best.map_or(PLANE_FALLBACK, |(name, _)| name)
}

/// Shared services this plan touches, most-mentioned first, capped at
/// [`SERVICE_MAX`]. Only services clearing [`SERVICE_MIN_HITS`] are returned.
pub fn services_for(body: &str) -> Vec<&'static str> {
    let body_l = body.to_ascii_lowercase();
    let mut scored: Vec<(&'static str, u32)> = Vec::new();
    for (name, _side, pats) in SERVICES {
        let hits = pats
            .iter()
            .fold(0u32, |acc, p| acc.saturating_add(count_hits(&body_l, p)));
        if hits >= SERVICE_MIN_HITS {
            scored.push((name, hits));
        }
    }
    // Descending by hits; ties keep table order, which is the rail order.
    scored.sort_by(|a, b| b.1.cmp(&a.1));
    scored.into_iter().take(SERVICE_MAX).map(|(name, _)| name).collect()
}

/// Every known service, in rail order, as `(name, side)`. The endpoint emits
/// `side` alongside each service so the console carries no second copy of this
/// table — which is why there is no separate lookup-by-name helper here.
pub fn all_services() -> Vec<(&'static str, &'static str)> {
    SERVICES.iter().map(|(n, s, _)| (*n, *s)).collect()
}

/// Strip the markdown a one-line card blurb cannot render: emphasis, code ticks,
/// wiki-link brackets, and inline links (keeping the link text).
fn plain_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // Emphasis and code ticks are dropped outright.
            '*' | '`' | '_' => {}
            '[' => {
                // `[[slug]]` and `[text](url)` both reduce to their inner text.
                if chars.peek() == Some(&'[') {
                    chars.next();
                }
            }
            ']' => {
                if chars.peek() == Some(&']') {
                    chars.next();
                }
                // Drop a following `(…)` target if this was an inline link.
                if chars.peek() == Some(&'(') {
                    for c2 in chars.by_ref() {
                        if c2 == ')' {
                            break;
                        }
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The first sentence or two of the plan's `## Purpose` section, as plain text.
///
/// Returns `None` when the plan has no Purpose section or it holds nothing but
/// the risk-class declaration — an honest absence beats a blurb built from
/// boilerplate.
pub fn purpose_blurb(md: &str, max_chars: usize) -> Option<String> {
    let mut in_purpose = false;
    let mut in_fence = false;
    let mut buf = String::new();

    for line in md.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("## ") {
            if in_purpose {
                break; // next heading ends the section
            }
            in_purpose = rest.trim().eq_ignore_ascii_case("purpose");
            continue;
        }
        if !in_purpose || trimmed.is_empty() {
            if in_purpose && !buf.is_empty() {
                break; // first paragraph is enough
            }
            continue;
        }
        if !buf.is_empty() {
            buf.push(' ');
        }
        buf.push_str(trimmed);
    }

    let mut text = plain_text(&buf);
    // Drop a leading "Risk class: …." sentence — the card shows risk as its own
    // chip, so repeating it in the blurb wastes the only line a card has. Done
    // after flattening, so it works whether the declaration owns the line
    // (`**Risk class: high.**`) or shares it with real prose.
    if text.to_ascii_lowercase().starts_with("risk class") {
        match text.find(". ") {
            Some(at) => text = text[at + 2..].trim().to_string(),
            // Nothing follows the declaration — the plan has no usable blurb.
            None => text.clear(),
        }
    }
    if text.is_empty() {
        return None;
    }
    Some(truncate_on_word(&text, max_chars))
}

/// Trim to `max_chars` without splitting a word or a UTF-8 char, adding an
/// ellipsis when anything was dropped.
fn truncate_on_word(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let cut: String = s.chars().take(max_chars).collect();
    let keep = match cut.rfind(' ') {
        // Only fall back to a hard cut if the last space is very early.
        Some(at) if at > max_chars / 2 => &cut[..at],
        _ => cut.as_str(),
    };
    format!("{}…", keep.trim_end_matches([' ', ',', ';', ':', '(', '-']))
}

/// Restrict declared edges to plans that are still open, deduped and sorted.
///
/// `declared` is `depends_on` ∪ `extended_by` from the parser. An edge to a
/// closed or unknown plan is dropped rather than drawn as a dangling stub.
pub fn narrow_links(declared: &[String], open: &dyn Fn(&str) -> bool, self_slug: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for slug in declared {
        let s = slug.trim();
        if s.is_empty() || s == self_slug || !open(s) || out.iter().any(|k| k == s) {
            continue;
        }
        out.push(s.to_string());
    }
    out.sort();
    out
}

/// Everything the canvas needs about a plan that depends ONLY on its file
/// content — never on the fact store.
///
/// That split is the whole basis of the cache in the HTTP layer. A plan's
/// *state* and *milestone counts* come from facts, and a gate fact changes them
/// without touching the file, so caching a whole response keyed off file mtimes
/// would silently serve a stale board. Facets cannot go stale that way: if the
/// file has not changed, none of this has changed either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanFacets {
    pub plane: &'static str,
    pub services: Vec<&'static str>,
    pub blurb: Option<String>,
    pub risk: Option<String>,
    /// `depends_on` ∪ `extended_by`, before narrowing to the open set.
    pub declared: Vec<String>,
}

/// Compute every file-derived facet in one pass.
///
/// Deliberately calls the same public classifiers everything else does, rather
/// than a private fast path: the per-plan cost only lands on a cache MISS, so a
/// second code path would buy nothing and could drift from the one under test.
/// The title is taken from the parsed plan rather than from the caller, so every
/// inch of this is file-derived and the cache key `(mtime, len)` genuinely
/// covers it. (Passing the WorkItem title in would leave a scoring input outside
/// the key — the classification could then go stale without the file changing.)
pub fn facets_for(slug: &str, body: &str) -> PlanFacets {
    let parsed = crate::work_execplans::parse_plan(body);
    let mut declared = parsed.depends_on.clone();
    declared.extend(parsed.extended_by.iter().cloned());
    PlanFacets {
        plane: plane_for(slug, &parsed.title, body),
        services: services_for(body),
        blurb: purpose_blurb(body, BLURB_CHARS),
        risk: parsed.risk_class.clone(),
        declared,
    }
}

/// Longest blurb the console renders on a card before it truncates anyway.
pub const BLURB_CHARS: usize = 240;

/// One plan file, as seen by a stat — path, slug and the two fields that decide
/// whether a cached facet set is still valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStat {
    pub slug: String,
    pub path: std::path::PathBuf,
    pub mtime_unix_ms: u64,
    pub len: u64,
}

/// Enumerate the plan root WITHOUT reading any file.
///
/// Mirrors `work_execplans::walk_execplans_root`'s filtering (`.md`, no scratch
/// prefix) but stops at the metadata, so a request whose facets are all cached
/// does no file I/O beyond the directory listing.
pub fn stat_execplans_root(root: &std::path::Path) -> std::io::Result<Vec<PlanStat>> {
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
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()).map(str::to_string) else {
            continue;
        };
        if crate::work_execplans::is_scratch_slug(&stem) {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mtime_unix_ms = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_millis() as u64);
        out.push(PlanStat {
            slug: stem,
            path,
            mtime_unix_ms,
            len: meta.len(),
        });
    }
    Ok(out)
}

#[cfg(test)]
#[path = "work_graph/tests.rs"]
mod tests;
