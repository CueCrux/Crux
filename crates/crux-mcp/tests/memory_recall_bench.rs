// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Memory recall + anti-hallucination benchmark harness.
//!
//! Adapts the LoCoMo / MemoryAgentBench / HaluMem benchmarks from the
//! Awesome-Agent-Memory survey (execplan `agent-memory-improvements-2026-06-26`,
//! M4) into a CPU-only, deterministic Rust harness so we can MEASURE — not just
//! assume — that the memory stack recalls the right facts and resists
//! stale-fact hallucination.
//!
//! It lives in `crux-mcp` because that crate is where the fact store
//! (`corecrux-memory`) and the decay policy (`corecrux-projections`) meet —
//! the same pairing the real recall path uses. The harness re-implements only
//! the public, documented ranking rule (`effective_confidence` over
//! salience-aware decay), so it tracks the production ranking without reaching
//! into private internals.
//!
//! Metrics reported (run with `--nocapture` to see them):
//!   * **recall@k** — fraction of QA probes whose expected fact is in the
//!     top-k recalled facts. LoCoMo / MemoryAgentBench style.
//!   * **stale-leak rate** — fraction of "a fact was corrected" probes where a
//!     decayed-stale prior value still outranks the fresh correction. HaluMem
//!     style; lower is better, target 0.
//!
//! These are assertions, not just prints: regressions in recall or a rise in
//! stale leakage fail CI.

use chrono::{DateTime, Duration, Utc};
use corecrux_memory::fact_store::{Fact, FactQuery, HorizonClass, StoreFact};
use corecrux_memory::FactStore;
use corecrux_projections::decay;

/// Bridge `corecrux_memory::HorizonClass` -> `corecrux_projections::decay`'s
/// independent copy via the shared lowercase wire form (the two crates keep
/// separate enums on purpose; `as_str`/`parse` is the public bridge).
fn class_of(h: HorizonClass) -> decay::HorizonClass {
    decay::HorizonClass::parse(h.as_str()).expect("horizon class wire form round-trips")
}

/// Salience-aware effective confidence — the public form of the production
/// recall ranking key (`crux-mcp::tools::facts::query_visible_facts_opts`).
fn ranking_key(fact: &Fact, now: DateTime<Utc>, policy: decay::DecayPolicy) -> f64 {
    let fresh = decay::apply_at_chrono_salient(
        class_of(fact.horizon_class),
        fact.stored_at,
        fact.reverified_at,
        fact.access_count,
        now,
        policy,
    );
    decay::effective_confidence(fact.confidence as f64, fresh)
}

/// Insert a fact with a controlled `stored_at` (the store path stamps
/// `Utc::now()`, so we go through `store_synced`, which preserves identity —
/// the documented remote-sync ingest path). Returns the fact_id.
fn insert_at(
    store: &mut FactStore,
    entity: &str,
    key: &str,
    value: &str,
    confidence: f32,
    horizon: HorizonClass,
    stored_at: DateTime<Utc>,
) -> String {
    let fact_id = format!(
        "f_bench_{}_{}",
        entity.replace([':', ' '], "_"),
        key.replace([':', ' '], "_")
    );
    let fact = Fact {
        fact_id: format!("{fact_id}_{}", stored_at.timestamp_millis()),
        entity: entity.to_string(),
        key: key.to_string(),
        value: value.to_string(),
        source_receipt: None,
        confidence,
        stored_at,
        tokens: value.split_whitespace().count().max(1),
        deleted: false,
        version: 1,
        supersedes: None,
        private: false,
        horizon_class: horizon,
        reverified_at: None,
        superseded_by: None,
        actor: None,
        valid_from: None,
        valid_to: None,
        access_count: 0,
        last_accessed_at: None,
    };
    let id = fact.fact_id.clone();
    store.store_synced(fact);
    id
}

// ── LoCoMo-style recall@k ────────────────────────────────────────────

#[test]
fn recall_at_k_over_locomo_style_fixture() {
    let mut store = FactStore::new();
    let now = Utc::now();

    // A small "long conversation" memory: facts accrued over many turns about
    // one user, plus some distractor facts about other entities.
    let knowledge: &[(&str, &str, &str)] = &[
        ("person:alice", "home_city", "Alice lives in Berlin"),
        ("person:alice", "employer", "Alice works at Visiativ"),
        ("person:alice", "pet", "Alice has a dog named Rex"),
        ("person:alice", "hobby", "Alice plays the cello"),
        ("person:alice", "allergy", "Alice is allergic to peanuts"),
        ("person:bob", "home_city", "Bob lives in Paris"),
        ("person:bob", "employer", "Bob works at Acme"),
        ("project:crux", "language", "Crux Daemon is written in Rust"),
        ("project:crux", "port", "Crux Daemon listens on port 14800"),
        (
            "project:crux",
            "store",
            "Crux stores facts in an append-only JSONL journal",
        ),
    ];
    for (entity, key, value) in knowledge {
        store.store(StoreFact {
            entity: (*entity).to_string(),
            key: (*key).to_string(),
            value: (*value).to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: Some(HorizonClass::None),
            actor: None,
        });
    }

    // QA probes: (query, substring the correct answer fact must contain).
    let probes: &[(&str, &str)] = &[
        ("where does alice live", "Berlin"),
        ("who employs alice", "Visiativ"),
        ("what pet does alice have", "Rex"),
        ("what instrument does alice play", "cello"),
        ("what is alice allergic to", "peanuts"),
        ("what language is crux written in", "Rust"),
        ("what port does crux listen on", "14800"),
    ];

    let policy = decay::DecayPolicy::default_const();
    let recall_at = |k: usize| -> f64 {
        let mut hits = 0usize;
        for (query, expected) in probes {
            let q = FactQuery {
                query: Some((*query).to_string()),
                entity: None,
                entity_prefix: None,
                top_k: k,
                token_budget: None,
            };
            let mut facts = store.query(&q).facts;
            // Re-rank by the production ranking key (decay-aware), top-k.
            facts.sort_by(|a, b| {
                ranking_key(b, now, policy)
                    .partial_cmp(&ranking_key(a, now, policy))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            facts.truncate(k);
            if facts.iter().any(|f| f.value.contains(expected)) {
                hits += 1;
            }
        }
        hits as f64 / probes.len() as f64
    };

    let r3 = recall_at(3);
    let r5 = recall_at(5);
    println!(
        "[memory-bench] recall@3 = {r3:.3}   recall@5 = {r5:.3}   (n={})",
        probes.len()
    );

    // BASELINE REGRESSION GATE — not an aspirational target. These are the
    // MEASURED numbers of today's lexical recall path (substring match +
    // confidence/decay/recency ranking, no term-frequency weighting). The gap
    // from 1.0 at k=3 is itself the finding: an entity-name term (e.g. "alice")
    // matches every fact about that entity, so without dense/BM25 relevance the
    // right fact often isn't in the top 3. That is the empirical motivation for
    // the dense-retrieval follow-up the survey points to (HippoRAG/embeddings).
    // The gate catches regressions below the established floor; tighten it as
    // retrieval improves.
    assert!(
        r3 >= 0.50,
        "recall@3 regressed below the lexical baseline: {r3:.3} < 0.50"
    );
    assert!(
        r5 >= r3,
        "recall@5 should be >= recall@3 (monotone in k): {r5:.3} < {r3:.3}"
    );
    assert!(
        r5 >= 0.70,
        "recall@5 regressed below the lexical baseline: {r5:.3} < 0.70"
    );
}

// ── HaluMem-style stale-leak rate ────────────────────────────────────

#[test]
fn stale_leak_rate_is_zero_after_correction() {
    let mut store = FactStore::new();
    let now = Utc::now();
    let policy = decay::DecayPolicy::default_const();

    // Each probe: an OLD value written long ago under a decaying horizon, then
    // a FRESH correction written just now. A correct memory ranks the fresh
    // correction above the stale prior — a "leak" is when the stale value wins.
    // (entity, key, stale_value, fresh_value, horizon, stale_age)
    let corrections: &[(&str, &str, &str, &str, HorizonClass, Duration)] = &[
        (
            "deploy:crux",
            "edge_sha",
            "abc111",
            "def222",
            HorizonClass::Volatile,
            Duration::days(5),
        ),
        (
            "tenant:acme",
            "plan",
            "free",
            "enterprise",
            HorizonClass::Medium,
            Duration::days(120),
        ),
        (
            "person:alice",
            "home_city",
            "London",
            "Berlin",
            HorizonClass::Medium,
            Duration::days(90),
        ),
        (
            "bench:lme-s",
            "baseline",
            "82.0%",
            "90.0%",
            HorizonClass::Stable,
            Duration::days(500),
        ),
    ];

    let mut leaks = 0usize;
    for (entity, key, stale_value, fresh_value, horizon, stale_age) in corrections {
        // Fresh store gets exactly the two competing facts.
        let mut s = FactStore::new();
        insert_at(&mut s, entity, key, stale_value, 1.0, *horizon, now - *stale_age);
        insert_at(&mut s, entity, key, fresh_value, 1.0, *horizon, now);

        let q = FactQuery {
            query: Some((*key).to_string()),
            entity: Some((*entity).to_string()),
            entity_prefix: None,
            top_k: 10,
            token_budget: None,
        };
        let mut facts = s.query(&q).facts;
        facts.sort_by(|a, b| {
            ranking_key(b, now, policy)
                .partial_cmp(&ranking_key(a, now, policy))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let top = facts.first().expect("two facts present");
        if top.value == *stale_value {
            eprintln!(
                "[memory-bench] STALE LEAK: {entity}/{key} -> {} (should be {fresh_value})",
                top.value
            );
            leaks += 1;
        }
    }
    let _ = &mut store; // store kept for symmetry; per-probe stores used above.

    let leak_rate = leaks as f64 / corrections.len() as f64;
    println!(
        "[memory-bench] stale-leak rate = {leak_rate:.3} ({leaks}/{})",
        corrections.len()
    );
    assert_eq!(
        leaks, 0,
        "decay ranking let {leaks} stale value(s) outrank the fresh correction"
    );
}

// ── M1 bi-temporal: as-of recall ─────────────────────────────────────

#[test]
fn bitemporal_as_of_recovers_world_state() {
    let mut store = FactStore::new();
    let jan = DateTime::parse_from_rfc3339("2026-01-15T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let jul = DateTime::parse_from_rfc3339("2026-07-15T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);

    let old = store.store(StoreFact {
        entity: "person:alice".into(),
        key: "home_city".into(),
        value: "London".into(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: Some(HorizonClass::None),
        actor: None,
    });
    let new = store.store(StoreFact {
        entity: "person:alice".into(),
        key: "home_city".into(),
        value: "Berlin".into(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: Some(HorizonClass::None),
        actor: None,
    });
    store.set_validity(
        &old.fact_id,
        Some(
            DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        ),
        Some(
            DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        ),
    );
    store.set_validity(
        &new.fact_id,
        Some(
            DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        ),
        None,
    );

    let q = FactQuery {
        query: None,
        entity: Some("person:alice".into()),
        entity_prefix: None,
        top_k: 10,
        token_budget: None,
    };
    let jan_facts = store.query_as_of(&q, jan);
    assert!(jan_facts.facts.iter().any(|f| f.value == "London"));
    assert!(jan_facts.facts.iter().all(|f| f.value != "Berlin"));

    let jul_facts = store.query_as_of(&q, jul);
    assert!(jul_facts.facts.iter().any(|f| f.value == "Berlin"));
    assert!(jul_facts.facts.iter().all(|f| f.value != "London"));
    println!("[memory-bench] bi-temporal as-of recall: OK");
}

// ── M2 salience: recalled facts resist demotion ──────────────────────

#[test]
fn salience_keeps_hot_fact_outranking_a_fresh_cold_one() {
    let now = Utc::now();
    let policy = decay::DecayPolicy::default_const();
    let mut store = FactStore::new();

    // A medium-horizon fact aged past the 35-day staleness threshold: cold, it
    // is demoted (0.5x). Hot (frequently recalled), salience keeps it Fresh so
    // it retains full confidence.
    let id = insert_at(
        &mut store,
        "tenant:acme",
        "tier",
        "enterprise",
        1.0,
        HorizonClass::Medium,
        now - Duration::days(40),
    );

    let cold_key = ranking_key(store.get(&id).unwrap(), now, policy);
    assert!(
        (cold_key - 0.5).abs() < 1e-9,
        "cold aged fact is demoted to 0.5, got {cold_key}"
    );

    // Simulate heavy recall.
    for _ in 0..1000 {
        store.record_access(&[id.as_str()]);
    }
    let hot_key = ranking_key(store.get(&id).unwrap(), now, policy);
    assert!(
        hot_key > cold_key,
        "salience should lift the recalled fact's ranking key"
    );
    assert!(
        (hot_key - 1.0).abs() < 1e-9,
        "hot fact stays Fresh -> full confidence, got {hot_key}"
    );
    println!("[memory-bench] salience: cold={cold_key:.2} hot={hot_key:.2}");
}
