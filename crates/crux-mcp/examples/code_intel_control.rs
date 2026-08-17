// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! M0 — the control arm: what a competent agent spends with no code-intel tools.
//!
//! ExecPlan: `crux-codemap-agent-surface-and-measured-savings-2026-07-27` (M0).
//!
//! This harness measures **only the control**. There is deliberately no
//! treatment arm here: the baseline has to stand on its own and be frozen
//! before anything is compared to it, or the comparison can be tuned after the
//! fact (plan Decision log 2026-07-27c).
//!
//! ## The strategy being modelled
//!
//! Not "read the whole repo" — that would produce a spectacular and
//! indefensible number. The control is what a competent agent actually does:
//!
//!   1. grep the workspace for the symbol,
//!   2. rank the matching files by hit count,
//!   3. read the top `K` files — a window around each hit, merged,
//!   4. stop.
//!
//! Token cost is the grep output the agent reads plus every line it reads.
//!
//! ## Why a grid rather than a number
//!
//! `K` and the window size are judgement calls, and a single tuned pair is
//! exactly the kind of baseline that collapses the first time someone tests it.
//! So the harness sweeps both and reports every cell. The **headline control is
//! the cheapest cell in the grid** — a rule fixed here, before any treatment
//! number exists, so the eventual saving is the one that survives against the
//! most favourable baseline the control could have had.
//!
//! ## Determinism
//!
//! No clock, no RNG, sorted traversal. Two runs over the same tree emit
//! byte-identical stdout; `code_intel_control_determinism.rs` asserts it.
//!
//! Run:
//!
//!     cargo run -p crux-mcp --example code_intel_control

#![allow(clippy::print_stdout, clippy::print_stderr, clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crux_mcp::token_estimate::estimate_tokens_str;
use serde_json::{json, Value};

/// The frozen corpus, compiled in so the run does not depend on the working
/// directory and cannot silently pick up an edited copy.
const CORPUS_JSON: &str = include_str!("../corpora/code-intel-questions.json");

/// How many matching lines of grep output the agent actually reads.
///
/// Fixed, not swept: every real grep tool truncates, and truncation is the
/// *cheap* direction for the control, so pinning it cannot inflate the
/// baseline. The widest probe in the corpus matches over 700 lines.
///
/// Note also that no corpus symbol is named anywhere in this file. Doing so
/// would add a reference the control arm's own grep would find, quietly
/// inflating the baseline it is trying to measure honestly.
const GREP_LINES_SHOWN: usize = 100;

/// Files read, ranked by hit count. Swept.
const FILE_CAPS: [usize; 3] = [3, 5, 10];

/// Lines read around each hit. `None` means the whole file — the behaviour of
/// an agent that just opens what grep pointed at. Swept.
const WINDOWS: [Option<usize>; 3] = [Some(40), Some(120), None];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root is two levels above the crate")
        .to_path_buf()
}

/// Every `.rs` file under `crates/`, in sorted order so the walk is stable.
fn source_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut children: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        children.sort();
        for path in children {
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// A whole-word match, the way `grep -w` / `\b` would see it.
fn word_match(line: &str, needle: &str) -> bool {
    let bytes = line.as_bytes();
    let n = needle.as_bytes();
    let boundary = |b: u8| !(b.is_ascii_alphanumeric() || b == b'_');
    let mut from = 0;
    while let Some(rel) = line[from..].find(needle) {
        let start = from + rel;
        let end = start + n.len();
        let left_ok = start == 0 || boundary(bytes[start - 1]);
        let right_ok = end == bytes.len() || boundary(bytes[end]);
        if left_ok && right_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

struct FileHits {
    rel_path: String,
    lines: Vec<String>,
    hit_lines: Vec<usize>,
}

/// Step 1 — grep. Returns per-file hits in sorted-path order.
fn grep(files: &[PathBuf], root: &Path, needle: &str) -> Vec<FileHits> {
    let mut out = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        let hit_lines: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| word_match(l, needle))
            .map(|(i, _)| i + 1)
            .collect();
        if hit_lines.is_empty() {
            continue;
        }
        out.push(FileHits {
            rel_path: path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/"),
            lines,
            hit_lines,
        });
    }
    out
}

/// What the agent sees back from the grep: `path:line:content`, truncated.
fn grep_output(hits: &[FileHits]) -> (String, usize) {
    let mut rendered = String::new();
    let mut total = 0usize;
    let mut shown = 0usize;
    for f in hits {
        for &n in &f.hit_lines {
            total += 1;
            if shown < GREP_LINES_SHOWN {
                rendered.push_str(&format!("{}:{}:{}\n", f.rel_path, n, f.lines[n - 1]));
                shown += 1;
            }
        }
    }
    if total > shown {
        rendered.push_str(&format!("... {} more matches\n", total - shown));
    }
    (rendered, total)
}

/// Merge each hit's ±`window` neighbourhood into non-overlapping ranges.
fn read_ranges(hit_lines: &[usize], line_count: usize, window: Option<usize>) -> Vec<(usize, usize)> {
    let Some(w) = window else {
        return vec![(1, line_count)];
    };
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for &n in hit_lines {
        let start = n.saturating_sub(w).max(1);
        let end = (n + w).min(line_count);
        match ranges.last_mut() {
            Some(last) if start <= last.1 + 1 => last.1 = last.1.max(end),
            _ => ranges.push((start, end)),
        }
    }
    ranges
}

struct ControlCost {
    tokens: u64,
    grep_matches: usize,
    files_read: usize,
    lines_read: usize,
}

/// Run the control strategy for one probe at one grid cell.
fn control_cost(hits: &[FileHits], file_cap: usize, window: Option<usize>) -> ControlCost {
    let (rendered, grep_matches) = grep_output(hits);
    let mut tokens = estimate_tokens_str(&rendered);

    // Rank by hit count, then by path so ties are broken deterministically.
    let mut ranked: Vec<&FileHits> = hits.iter().collect();
    ranked.sort_by(|a, b| {
        b.hit_lines
            .len()
            .cmp(&a.hit_lines.len())
            .then_with(|| a.rel_path.cmp(&b.rel_path))
    });

    let mut files_read = 0usize;
    let mut lines_read = 0usize;
    for f in ranked.into_iter().take(file_cap) {
        files_read += 1;
        for (start, end) in read_ranges(&f.hit_lines, f.lines.len(), window) {
            let slice = f.lines[start - 1..end].join("\n");
            lines_read += end - start + 1;
            tokens += estimate_tokens_str(&slice);
        }
    }

    ControlCost {
        tokens,
        grep_matches,
        files_read,
        lines_read,
    }
}

fn window_label(w: Option<usize>) -> String {
    w.map_or_else(|| "whole_file".to_string(), |n| format!("window_{n}"))
}

fn main() {
    let corpus: Value = serde_json::from_str(CORPUS_JSON).expect("corpus JSON parses");
    let corpus_name = corpus["corpus"].as_str().expect("corpus name");
    let corpus_commit = corpus["commit_sha"].as_str().expect("corpus commit");
    let questions = corpus["questions"].as_array().expect("questions array");

    let root = repo_root();
    let files = source_files(&root);

    // grep once per distinct probe — several questions share a symbol.
    let probes: Vec<String> = {
        let mut p: Vec<String> = questions
            .iter()
            .map(|q| q["probe"].as_str().expect("probe").to_string())
            .collect();
        p.sort();
        p.dedup();
        p
    };
    let hits: BTreeMap<String, Vec<FileHits>> = probes
        .into_iter()
        .map(|p| {
            let h = grep(&files, &root, &p);
            (p, h)
        })
        .collect();

    let mut records = Vec::new();
    let mut cell_totals: BTreeMap<String, u64> = BTreeMap::new();

    for q in questions {
        let id = q["id"].as_str().expect("id");
        let probe = q["probe"].as_str().expect("probe");
        let h = &hits[probe];
        let mut cells = serde_json::Map::new();
        for &cap in &FILE_CAPS {
            for &window in &WINDOWS {
                let cost = control_cost(h, cap, window);
                let key = format!("k{cap}_{}", window_label(window));
                *cell_totals.entry(key.clone()).or_default() += cost.tokens;
                cells.insert(
                    key,
                    json!({
                        "tokens": cost.tokens,
                        "files_read": cost.files_read,
                        "lines_read": cost.lines_read,
                    }),
                );
            }
        }
        let grep_matches = control_cost(h, 0, Some(0)).grep_matches;
        records.push(json!({
            "id": id,
            "kind": q["kind"],
            "probe": probe,
            "grep_matches": grep_matches,
            "files_matched": h.len(),
            "cells": Value::Object(cells),
        }));
    }

    // The headline control is the cheapest cell — fixed as a rule before any
    // treatment number exists, so the eventual saving is the one that survives
    // the most favourable baseline the control could have had.
    let (cheapest_cell, cheapest_total) = cell_totals
        .iter()
        .min_by_key(|(k, v)| (**v, (*k).clone()))
        .map(|(k, v)| (k.clone(), *v))
        .expect("grid is non-empty");

    let out = json!({
        "harness": "code_intel_control",
        "arm": "control",
        "corpus": corpus_name,
        "corpus_commit": corpus_commit,
        "questions": records.len(),
        "strategy": {
            "steps": [
                "grep the workspace for the symbol (whole-word, crates/**/*.rs)",
                format!("read the first {GREP_LINES_SHOWN} matching lines of grep output"),
                "rank matching files by hit count, ties broken by path",
                "read the top K files — a merged window around each hit",
                "stop",
            ],
            "grep_lines_shown": GREP_LINES_SHOWN,
            "file_caps": FILE_CAPS,
            "windows": WINDOWS.iter().map(|w| window_label(*w)).collect::<Vec<_>>(),
        },
        "headline_control": {
            "cell": cheapest_cell,
            "total_tokens": cheapest_total,
            "mean_tokens_per_question": cheapest_total / records.len() as u64,
            "rule": "cheapest cell in the grid, fixed at M0 before any treatment arm existed",
        },
        "cell_totals": cell_totals,
        "records": records,
    });

    println!("{}", serde_json::to_string_pretty(&out).expect("serialise"));

    eprintln!(
        "control arm — corpus {corpus_name} @ {corpus_commit}, {} questions",
        records.len()
    );
    for (cell, total) in &cell_totals {
        eprintln!("  {cell:22} total={total:7}  mean={:6}", total / records.len() as u64);
    }
    eprintln!("headline control: {cheapest_cell} — {cheapest_total} tokens over the corpus");
}
