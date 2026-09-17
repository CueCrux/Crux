// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Cache-invalidation ledger tests (M0 of `crux-prompt-cache-1h-ttl-2026-09-17`).
//!
//! The fixture is **synthetic**, hand-cut to the shape of the measured corpus:
//! no operator path, name or transcript content reaches CI. The real corpus
//! check is [`corpus_reproduces_frozen_baseline`], which is skipped unless
//! `CRUX_COST_CACHE_CORPUS` points at a transcript root.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::print_stdout)]

use crux_cost::report::{CacheClass, ToolDeltaKind};
use crux_cost::{analyze_str, CostReport};

const FIXTURE: &str = include_str!("fixtures/cache-invalidations.jsonl");

fn fixture_report() -> CostReport {
    analyze_str(FIXTURE, "cache-invalidations.jsonl")
}

/// One API response is several JSONL lines sharing a `message.id`, each
/// repeating the whole `usage` object. The fixture's first call is written
/// twice; it must be counted once.
#[test]
fn dedupes_api_calls_by_message_id() {
    let dup = r#"{"type":"assistant","sessionId":"d","message":{"role":"assistant","id":"msg_1","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":1000,"cache_creation_input_tokens":200},"content":[{"type":"text","text":"a"}]}}
{"type":"assistant","sessionId":"d","message":{"role":"assistant","id":"msg_1","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":1000,"cache_creation_input_tokens":200},"content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}}]}}
{"type":"assistant","sessionId":"d","message":{"role":"assistant","id":"msg_2","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":1000,"cache_creation_input_tokens":200},"content":[{"type":"text","text":"b"}]}}"#;
    let r = analyze_str(dup, "d.jsonl");
    assert_eq!(r.headline.assistant_turns, 2, "3 lines, 2 API calls");
    assert_eq!(r.measured.cache_read, 2_000);
    assert_eq!(r.measured.cache_creation, 400);
    assert_eq!(r.measured.output, 10);
    // The duplicate line's content blocks are still attributed — they are real
    // content, they were just not a second API call.
    assert!(r.buckets.iter().any(|b| b.source == "tool_use_args"));
}

/// Two records without ids are two calls: dedupe keys on the id, and a missing
/// id must never collapse distinct turns.
#[test]
fn records_without_message_id_are_never_deduped() {
    let no_id = r#"{"type":"assistant","sessionId":"n","message":{"role":"assistant","usage":{"input_tokens":1,"output_tokens":1,"cache_read_input_tokens":100},"content":[{"type":"text","text":"a"}]}}
{"type":"assistant","sessionId":"n","message":{"role":"assistant","usage":{"input_tokens":1,"output_tokens":1,"cache_read_input_tokens":100},"content":[{"type":"text","text":"b"}]}}"#;
    let r = analyze_str(no_id, "n.jsonl");
    assert_eq!(r.headline.assistant_turns, 2);
    assert_eq!(r.measured.cache_read, 200);
}

/// The nested `cache_creation` map splits by TTL tier; the flat total is kept.
#[test]
fn splits_the_ttl_buckets_and_keeps_the_total() {
    let r = fixture_report();
    assert_eq!(r.measured.cache_creation, 292_900, "total is unchanged");
    assert_eq!(r.headline.cache_creation_1h, 292_800);
    assert_eq!(r.headline.cache_creation_5m, 100);
    assert_eq!(
        r.headline.cache_creation_1h + r.headline.cache_creation_5m,
        r.measured.cache_creation,
        "the two tiers reconcile to the total"
    );
}

/// A record that carries only the flat `cache_creation_input_tokens` (the older
/// shape) still totals correctly, with both tiers zero rather than guessed.
#[test]
fn flat_cache_creation_shape_has_no_tier_split() {
    let flat = r#"{"type":"assistant","sessionId":"f","message":{"role":"assistant","id":"m1","usage":{"input_tokens":1,"output_tokens":1,"cache_read_input_tokens":0,"cache_creation_input_tokens":5000},"content":[{"type":"text","text":"a"}]}}"#;
    let r = analyze_str(flat, "f.jsonl");
    assert_eq!(r.measured.cache_creation, 5_000);
    assert_eq!(r.headline.cache_creation_1h, 0);
    assert_eq!(r.headline.cache_creation_5m, 0);
}

/// A compaction boundary rebuilds the context on purpose — the write that
/// follows it is not an invalidation. The fixture has exactly one such turn.
#[test]
fn compaction_windows_are_excluded() {
    let r = fixture_report();
    assert!(
        r.headline.invalidations.iter().all(|i| i.tokens != 9_000),
        "the post-compaction 9,000-token write must not be flagged"
    );
}

/// A prefix under 5,000 tokens is not worth caching; those windows are skipped.
#[test]
fn tiny_context_windows_are_excluded() {
    let r = fixture_report();
    assert!(
        r.headline.invalidations.iter().all(|i| i.tokens != 4_000),
        "the 4,000-token write after a 405-token context must not be flagged"
    );
}

/// Every classification branch, in the measured precedence order.
#[test]
fn classifies_each_branch() {
    let r = fixture_report();
    let by_tokens = |tokens: u64| {
        r.headline
            .invalidations
            .iter()
            .find(|i| i.tokens == tokens)
            .unwrap_or_else(|| panic!("no invalidation of {tokens} tokens"))
    };
    assert_eq!(by_tokens(21_000).class, CacheClass::TtlExpiry);
    assert_eq!(by_tokens(22_000).class, CacheClass::EffortChange);
    assert_eq!(by_tokens(23_000).class, CacheClass::DateChange);
    assert_eq!(by_tokens(24_000).class, CacheClass::ToolDelta);
    assert_eq!(by_tokens(25_000).class, CacheClass::McpInstructionsDelta);
    assert_eq!(by_tokens(26_000).class, CacheClass::HookBlock);
    assert_eq!(by_tokens(27_000).class, CacheClass::Unattributed);

    // The tool delta names the server whose surface churned, and says whether
    // it removed anything — add-only deltas never invalidated in the corpus.
    let td = by_tokens(24_000);
    assert_eq!(td.server.as_deref(), Some("crux"));
    assert_eq!(td.tool_delta, Some(ToolDeltaKind::WithRemovals));
}

/// An add-only `deferred_tools_delta` is recorded as such.
#[test]
fn add_only_tool_delta_is_labelled() {
    let lines = [
        r#"{"type":"assistant","sessionId":"a","timestamp":"2026-09-17T00:00:00.000Z","message":{"role":"assistant","id":"m1","usage":{"input_tokens":100,"output_tokens":5,"cache_read_input_tokens":0,"cache_creation_input_tokens":20000},"content":[{"type":"text","text":"a"}]}}"#,
        r#"{"type":"attachment","sessionId":"a","timestamp":"2026-09-17T00:00:30.000Z","attachment":{"type":"deferred_tools_delta","addedNames":["mcp__docs__read","mcp__docs__write"]}}"#,
        r#"{"type":"assistant","sessionId":"a","timestamp":"2026-09-17T00:01:00.000Z","message":{"role":"assistant","id":"m2","usage":{"input_tokens":5,"output_tokens":5,"cache_read_input_tokens":0,"cache_creation_input_tokens":21000},"content":[{"type":"text","text":"b"}]}}"#,
    ]
    .join("\n");
    let r = analyze_str(&lines, "a.jsonl");
    let inv = r.headline.invalidations.first().expect("one invalidation");
    assert_eq!(inv.class, CacheClass::ToolDelta);
    assert_eq!(inv.tool_delta, Some(ToolDeltaKind::AddOnly));
    assert_eq!(inv.server.as_deref(), Some("docs"));
}

/// The measured nuance: `hook_additional_context` fires in 17.6% of invalidating
/// windows against a 0.11% base rate, but it fires at SessionStart/resume — the
/// same moment a long idle gap expired the cache. It is a marker of a cold
/// resume, not its cause, so an idle gap must outrank it.
#[test]
fn a_hook_marker_never_outranks_an_idle_gap() {
    let lines = [
        r#"{"type":"assistant","sessionId":"h","timestamp":"2026-09-17T00:00:00.000Z","message":{"role":"assistant","id":"m1","usage":{"input_tokens":100,"output_tokens":5,"cache_read_input_tokens":0,"cache_creation_input_tokens":20000},"content":[{"type":"text","text":"a"}]}}"#,
        r#"{"type":"attachment","sessionId":"h","timestamp":"2026-09-17T02:00:00.000Z","attachment":{"type":"hook_additional_context","content":["session banner"]}}"#,
        r#"{"type":"assistant","sessionId":"h","timestamp":"2026-09-17T02:00:05.000Z","message":{"role":"assistant","id":"m2","usage":{"input_tokens":5,"output_tokens":5,"cache_read_input_tokens":0,"cache_creation_input_tokens":21000},"content":[{"type":"text","text":"b"}]}}"#,
    ]
    .join("\n");
    let r = analyze_str(&lines, "h.jsonl");
    let inv = r.headline.invalidations.first().expect("one invalidation");
    assert_eq!(inv.class, CacheClass::TtlExpiry, "the 2-hour gap is the cause");
    assert_eq!(inv.sub_bucket.as_deref(), Some("120-480m"));
}

/// TTL expiries are sub-bucketed; the fixture covers all four bands.
#[test]
fn ttl_expiries_are_sub_bucketed() {
    let r = fixture_report();
    let bucket_of = |tokens: u64| {
        r.headline
            .invalidations
            .iter()
            .find(|i| i.tokens == tokens)
            .and_then(|i| i.sub_bucket.clone())
    };
    assert_eq!(bucket_of(29_000).as_deref(), Some("60-65m"));
    assert_eq!(bucket_of(21_000).as_deref(), Some("65-120m"));
    assert_eq!(bucket_of(30_000).as_deref(), Some("120-480m"));
    assert_eq!(bucket_of(28_000).as_deref(), Some("480m+"));
    // Only TTL expiries carry a sub-bucket.
    assert!(r
        .headline
        .invalidations
        .iter()
        .all(|i| (i.class == CacheClass::TtlExpiry) == i.sub_bucket.is_some()));
}

/// The golden aggregate for the fixture corpus — the shape of the gate the real
/// corpus is held to, at a size that can live in CI.
#[test]
fn golden_fixture_aggregates() {
    let r = fixture_report();
    assert_eq!(r.headline.assistant_turns, 25, "API calls, not JSONL lines");
    assert_eq!(r.headline.invalidations.len(), 10);
    assert_eq!(r.headline.invalidation_tokens, 255_000);
    assert!(
        (r.headline.rewrite_share - 0.8706).abs() < 0.0001,
        "rewrite_share was {}",
        r.headline.rewrite_share
    );
    assert!(
        (r.headline.cache_hit_rate - 0.4594).abs() < 0.0001,
        "cache_hit_rate was {}",
        r.headline.cache_hit_rate
    );
    let named: u64 = r
        .headline
        .invalidations
        .iter()
        .filter(|i| i.class != CacheClass::Unattributed)
        .map(|i| i.tokens)
        .sum();
    assert_eq!(named, 228_000);
    // Indices address API turns, ascending, and stay in range.
    let idx: Vec<u64> = r.headline.invalidations.iter().map(|i| i.index).collect();
    assert_eq!(idx, vec![2, 4, 6, 8, 10, 12, 14, 20, 22, 24]);
}

/// `rewrite_share ≥ 0.4` fires the lever, and it names the dominant class.
#[test]
fn cache_thrash_lever_fires_and_names_the_cause() {
    let r = fixture_report();
    let lever = r
        .levers
        .iter()
        .find(|l| l.id == "cache-thrash")
        .expect("cache-thrash lever must fire at 87% rewrite share");
    assert!(lever.detail.contains("1-hour TTL"), "detail was: {}", lever.detail);
    assert!(lever.detail.contains("255000"));
}

/// Below the threshold the lever stays quiet.
#[test]
fn cache_thrash_lever_is_quiet_on_a_warm_session() {
    let warm = r#"{"type":"assistant","sessionId":"w","message":{"role":"assistant","id":"m1","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":50000,"cache_creation_input_tokens":100},"content":[{"type":"text","text":"a"}]}}
{"type":"assistant","sessionId":"w","message":{"role":"assistant","id":"m2","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":50100,"cache_creation_input_tokens":100},"content":[{"type":"text","text":"b"}]}}"#;
    let r = analyze_str(warm, "w.jsonl");
    assert_eq!(r.headline.invalidations.len(), 0);
    assert_eq!(r.headline.rewrite_share, 0.0);
    assert!(r.levers.iter().all(|l| l.id != "cache-thrash"));
}

/// A report written before the ledger existed must still deserialise: the new
/// fields are `serde(default)`, so an older client is unaffected in both
/// directions.
#[test]
fn legacy_report_without_cache_fields_still_deserialises() {
    let legacy = serde_json::json!({
        "schema": crux_cost::COST_REPORT_SCHEMA,
        "session_id": "legacy",
        "source": "legacy.jsonl",
        "headline": {
            "assistant_turns": 3, "tasks": 1, "segments": 1,
            "context_tokens_per_turn": 1000, "cache_read_to_output_ratio": 5.0,
            "measured_context_total": 3000, "prefix_pct": 50.0
        },
        "measured": {"input": 1, "output": 1, "cache_read": 1, "cache_creation": 1},
        "buckets": [], "top_blocks": [], "levers": []
    })
    .to_string();
    let r: CostReport = serde_json::from_str(&legacy).expect("legacy report must deserialise");
    assert_eq!(r.headline.cache_hit_rate, 0.0);
    assert_eq!(r.headline.rewrite_share, 0.0);
    assert!(r.headline.invalidations.is_empty());
    // And a ledger-less report round-trips without emitting an empty list.
    let back = serde_json::to_string(&r).expect("serialise");
    assert!(!back.contains("\"invalidations\""));
}

// ---------------------------------------------------------------------------
// The real-corpus gate. Opt-in: CI never reads the operator's transcripts.
// ---------------------------------------------------------------------------

/// Reproduce the frozen baseline for corpus
/// **`drivew-host-claude-transcripts-2026-09`** — the 27 most recent Claude Code
/// sessions with ≥ 5 API turns under `~/.claude/projects` on drivew-host, read
/// 2026-09-17 (`PlanCrux/.agent/research/prompt-cache-claude-code-2026-09-17/`).
///
/// Skipped unless `CRUX_COST_CACHE_CORPUS` names the transcript root, because
/// the corpus is one operator's private transcripts and does not belong in CI.
/// Run it with:
///
/// ```text
/// CRUX_COST_CACHE_CORPUS=~/.claude/projects cargo test -p crux-cost --test cache_ledger -- --ignored --nocapture
/// ```
///
/// The corpus is live (sessions keep growing), so every total is held to the
/// plan's ±1%; the event counts and the ≥ 85% attribution bar are the gate.
#[test]
#[ignore = "reads the operator's local transcripts; set CRUX_COST_CACHE_CORPUS"]
fn corpus_reproduces_frozen_baseline() {
    use std::collections::BTreeMap;

    let Ok(root) = std::env::var("CRUX_COST_CACHE_CORPUS") else {
        panic!("set CRUX_COST_CACHE_CORPUS to the transcript root");
    };
    let recent: usize = std::env::var("CRUX_COST_CACHE_CORPUS_N")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(40);

    // The corpus definition: the `recent` most recently modified transcripts,
    // of which the ones with ≥ 5 API turns are the corpus.
    let mut files: Vec<(std::time::SystemTime, std::path::PathBuf)> = Vec::new();
    for project in std::fs::read_dir(&root).expect("read corpus root").flatten() {
        let Ok(inner) = std::fs::read_dir(project.path()) else { continue };
        for entry in inner.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "jsonl") {
                let mtime = entry.metadata().and_then(|m| m.modified()).expect("mtime");
                files.push((mtime, path));
            }
        }
    }
    files.sort();
    let tail = files.split_off(files.len().saturating_sub(recent));

    let (mut sessions, mut read, mut write, mut input) = (0_u64, 0_u64, 0_u64, 0_u64);
    let (mut e5, mut e1, mut inv_tokens, mut inv_events) = (0_u64, 0_u64, 0_u64, 0_u64);
    let mut by_class: BTreeMap<&'static str, (u64, u64)> = BTreeMap::new();
    let mut by_gap: BTreeMap<&'static str, (u64, u64)> = BTreeMap::new();

    for (_, path) in &tail {
        let r = crux_cost::analyze_file(path).expect("analyze");
        if r.headline.assistant_turns < 5 {
            continue;
        }
        sessions += 1;
        read += r.measured.cache_read;
        write += r.measured.cache_creation;
        input += r.measured.input;
        e5 += r.headline.cache_creation_5m;
        e1 += r.headline.cache_creation_1h;
        inv_tokens += r.headline.invalidation_tokens;
        for i in &r.headline.invalidations {
            inv_events += 1;
            let c = by_class.entry(i.class.as_str()).or_default();
            c.0 += 1;
            c.1 += i.tokens;
            let band = match i.gap_minutes.unwrap_or(0.0) {
                g if g < 5.0 => "<5min",
                g if g < 60.0 => "5-60min",
                g if g < 65.0 => "60-65min",
                g if g < 120.0 => "65-120min",
                g if g < 480.0 => "120-480min",
                _ => ">480min",
            };
            let b = by_gap.entry(band).or_default();
            b.0 += 1;
            b.1 += i.tokens;
        }
    }

    let hit = read as f64 / (read + write + input) as f64;
    let named = inv_tokens - by_class.get("unattributed").map_or(0, |c| c.1);
    let attributed = 100.0 * named as f64 / inv_tokens as f64;
    println!("corpus drivew-host-claude-transcripts-2026-09 (live re-read)");
    println!("sessions {sessions}, hit ratio {hit:.4}");
    println!("cache_creation total {write} ; ephemeral_1h {e1} ; ephemeral_5m {e5}");
    println!("invalidations {inv_events}, tokens {inv_tokens}");
    for (band, (n, t)) in &by_gap {
        println!("  gap {band:<12} {n:3} events {t:>10}");
    }
    for (class, (n, t)) in &by_class {
        println!("  {class:<22} {n:3} events {t:>10}  ({:.1}%)", 100.0 * *t as f64 / inv_tokens as f64);
    }
    println!("attributed to a named class: {attributed:.2}%");

    // Frozen baseline (05-baseline.py, snapshots/cache-before.txt).
    let within_1pct = |got: u64, frozen: u64, what: &str| {
        let drift = 100.0 * (got as f64 - frozen as f64).abs() / frozen as f64;
        assert!(drift <= 1.0, "{what}: {got} vs frozen {frozen} — {drift:.2}% drift");
    };
    assert_eq!(sessions, 27, "corpus size");
    assert!((hit - 0.9817).abs() < 0.001, "hit ratio {hit:.4} vs frozen 0.9817");
    within_1pct(write, 61_676_021, "cache_creation total");
    within_1pct(e1, 61_312_477, "ephemeral_1h");
    within_1pct(e5, 363_544, "ephemeral_5m");
    within_1pct(inv_tokens, 37_453_910, "invalidation tokens");
    assert_eq!(inv_events, 102, "invalidation events");
    for (band, events, tokens) in [
        ("<5min", 11_u64, 2_978_405_u64),
        ("5-60min", 15, 5_489_907),
        ("60-65min", 7, 3_587_983),
        ("65-120min", 31, 10_759_299),
        ("120-480min", 21, 8_577_092),
        (">480min", 17, 6_061_224),
    ] {
        let (n, t) = by_gap.get(band).copied().unwrap_or_default();
        assert_eq!(n, events, "gap band {band} event count");
        within_1pct(t, tokens, &format!("gap band {band} tokens"));
    }
    assert!(attributed >= 85.0, "only {attributed:.2}% of rewritten tokens attributed (gate: 85%)");
}
