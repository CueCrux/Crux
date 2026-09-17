// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! End-to-end gate for ExecPlan `crux-memory-parity-and-codex-bridge-2026-09-17`
//! M2 + M3: seed a curated tier from a harness-native memory store, render the
//! digest, and compose it into **both** `CLAUDE.md` and `AGENTS.md`.
//!
//! Each half has unit tests of its own. This file exists for the seam between
//! them — a renderer that is byte-stable in isolation is still useless if the
//! composer normalises its whitespace, and a drift check that passes on bundled
//! text says nothing about a body that comes off disk.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use corecrux_projections::native_memory::{ingest_native_memory, NativeMemoryIngestOptions};
use corecruxctl::memory::MemoryFact;
use corecruxctl::memory_distill::{
    build_catalog, render_catalog_digest, CATALOG_MIN_ENTRIES, DIGEST_FRAGMENT_PATH, DIGEST_TOKEN_BUDGET,
};
use crux_config_wizard::config::{workspace_fingerprint, AgentProfileConfig};
use crux_config_wizard::{check_workspace, compose_file, load_workspace_profiles, Target, DEFAULT_PROFILES};

/// Groups mirroring the shape of a real `MEMORY.md`: a handful of `##`
/// headings with the memories listed under them.
const GROUPS: &[&str] = &[
    "Environment traps",
    "Crux daemon / memory plane",
    "CI / merge queue",
    "Deploy runbooks",
    "Retired / archived — do NOT target",
    "Product surfaces",
];

/// Write a synthetic native memory store of `n` memories plus its index.
fn write_memory_store(root: &Path, n: usize) {
    std::fs::create_dir_all(root).unwrap();
    let mut index = String::from("# Memory Index\n");
    let mut by_group: Vec<Vec<String>> = vec![Vec::new(); GROUPS.len()];
    for i in 0..n {
        let slug = format!("synthetic-trap-{i:03}-with-a-realistically-long-slug");
        let description = format!(
            "Trap {i}: the symptom looks like a dependency regression but the cause is a shared \
             runner running out of disk, and the fix is to prune before retrying."
        );
        let body = format!(
            "---\nname: {slug}\ndescription: {description}\nmetadata:\n  type: project\n---\n\n\
             A longer body that the digest must never carry, cross-referencing \
             [[synthetic-trap-{:03}-with-a-realistically-long-slug]].\n",
            (i + 1) % n
        );
        std::fs::write(root.join(format!("{slug}.md")), body).unwrap();
        by_group[i % GROUPS.len()].push(format!("- [{slug}]({slug}.md) — trap {i} recall hook\n"));
    }
    for (idx, group) in GROUPS.iter().enumerate() {
        index.push_str(&format!("\n## {group}\n\n"));
        for row in &by_group[idx] {
            index.push_str(row);
        }
    }
    std::fs::write(root.join("MEMORY.md"), index).unwrap();
}

/// A pool of distinct technical nouns. Each synthetic incident draws five of
/// them at wide strides, so no two proposals share enough vocabulary to be
/// deduplicated. Near-identical fixtures would be collapsed by the distiller —
/// correctly — and the gate would then be measuring the fixture, not the code.
const NOUNS: &[&str] = &[
    "advisory",
    "ratchet",
    "sealer",
    "embedder",
    "passport",
    "scheduler",
    "projection",
    "mirror",
    "capability",
    "manifest",
    "envelope",
    "quorum",
    "shard",
    "segment",
    "receipt",
    "lattice",
    "runner",
    "queue",
    "partition",
    "checkpoint",
    "ledger",
    "beacon",
    "collator",
    "digest",
    "harness",
    "overlay",
    "sentinel",
    "tracker",
    "reaper",
    "planner",
    "auditor",
    "sampler",
    "warden",
    "courier",
    "notary",
    "splicer",
    "hydrator",
    "compactor",
    "dispatcher",
    "arbiter",
    "prefetcher",
    "throttle",
    "watchdog",
    "rotator",
    "shredder",
    "bundler",
    "verifier",
    "indexer",
    "resolver",
    "balancer",
    "annotator",
    "scrubber",
    "conductor",
    "marshal",
    "spooler",
    "grafter",
    "trimmer",
    "weigher",
    "hasher",
    "signer",
    "packer",
    "prober",
    "linker",
    "seeder",
];

/// One noun of the pool, suffixed with the case index so every proposal owns
/// its own vocabulary outright. Deduplication compares content-bearing terms,
/// so a fixture that merely permutes a shared pool collapses under it.
fn token(i: usize, slot: usize) -> String {
    format!("{}{i:03}", NOUNS[(i * 7 + slot * 23) % NOUNS.len()])
}

fn incident_fact(i: usize) -> MemoryFact {
    let (a, b, c, d) = (token(i, 0), token(i, 1), token(i, 2), token(i, 3));
    MemoryFact {
        fact_id: format!("f_{i:032x}"),
        entity: "incident:2026-09-17".to_string(),
        key: format!("{a}-{b}"),
        value: format!(
            r#"{{"symptom":"The {a} stalls and {b} logs nil.","cause":"{c} outran {d}.","fix_sha":"abc{i:04}"}}"#
        ),
        version: 1,
        confidence: 1.0,
        stored_at: "2026-09-17T12:00:00Z".to_string(),
        source_receipt: None,
        deleted: false,
    }
}

/// M2: the curated tier reaches the plan's floor, every entry carries a recall
/// line, and every distilled entry names the fact and date it came from.
#[test]
fn curated_tier_meets_the_m2_gate() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("memory");
    write_memory_store(&root, 84);
    let ingest = ingest_native_memory(&[root], NativeMemoryIngestOptions::default());
    assert_eq!(ingest.memories, 84);

    let facts: Vec<MemoryFact> = (0..60).map(incident_fact).collect();
    let build = build_catalog(&ingest, &facts, 20, &[], 1_700_000_000_000);

    assert_eq!(build.seeded, 84);
    assert_eq!(build.distilled, 20);
    assert!(
        build.catalog.len() >= CATALOG_MIN_ENTRIES,
        "catalog holds {} entries, under the {CATALOG_MIN_ENTRIES} floor",
        build.catalog.len()
    );
    for engram in &build.catalog {
        assert!(
            !engram.digest_description().trim().is_empty(),
            "{} has no recall line",
            engram.name
        );
        if engram.generated_class.as_deref() == Some("fact_distilled") {
            let fact_id = engram.source_fact_id.as_deref().unwrap_or_default();
            let date = engram.source_fact_date.as_deref().unwrap_or_default();
            assert!(!fact_id.is_empty(), "{} is distilled but names no fact", engram.name);
            assert_eq!(date.len(), 10, "{} carries no ISO date", engram.name);
        }
    }
    // Nothing was promoted that was not accepted: the rest stay in the review
    // queue. The queue is shorter than the input because the distiller drops
    // proposals that restate one another — which is the behaviour that keeps
    // the tier curated rather than merely large.
    assert!(!build.pending.is_empty(), "unaccepted proposals must stay pending");
}

/// M3: the digest fits the budget, is byte-identical across renders, composes
/// into both harness files, and leaves the wizard's drift check clean.
#[test]
fn digest_composes_into_both_harness_files_and_stays_stable() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("memory");
    write_memory_store(&root, 84);
    let ingest = ingest_native_memory(&[root], NativeMemoryIngestOptions::default());
    let facts: Vec<MemoryFact> = (0..60).map(incident_fact).collect();
    let build = build_catalog(&ingest, &facts, 20, &[], 1_700_000_000_000);

    let first = render_catalog_digest(&build.catalog, DIGEST_TOKEN_BUDGET);
    let second = render_catalog_digest(&build.catalog, DIGEST_TOKEN_BUDGET);
    assert_eq!(first.body, second.body, "two renders must be byte-identical");
    assert_eq!(first.manifest_hash, second.manifest_hash);
    assert!(
        first.token_estimate <= DIGEST_TOKEN_BUDGET,
        "digest is {} tokens, over budget",
        first.token_estimate
    );
    assert_eq!(first.omitted, 0);
    assert!(first.body.contains(&first.manifest_hash));

    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(workspace.join(".crux")).unwrap();
    std::fs::write(workspace.join(DIGEST_FRAGMENT_PATH), &first.body).unwrap();

    let fragments = load_workspace_profiles(&workspace).unwrap();
    let mut cfg = AgentProfileConfig::new(workspace_fingerprint(&workspace));
    for name in DEFAULT_PROFILES {
        let fragment = fragments
            .iter()
            .find(|f| &f.frontmatter.name == name)
            .expect("default profile bundled");
        cfg.enable(name, fragment.frontmatter.version);
    }
    cfg.save(&workspace).unwrap();
    let enabled: Vec<_> = fragments
        .into_iter()
        .filter(|f| cfg.profiles.contains_key(&f.frontmatter.name))
        .collect();

    for target in [Target::ClaudeMd, Target::AgentsMd] {
        compose_file(&workspace, target, &enabled, false, false).unwrap();
        let text = std::fs::read_to_string(workspace.join(target.filename())).unwrap();
        assert!(
            text.contains("BEGIN-CRUX-MANAGED:memory-digest v1"),
            "{} has no memory-digest section",
            target.filename()
        );
        assert!(
            text.contains(&first.manifest_hash),
            "{} lost the digest identity",
            target.filename()
        );
        // The index goes in; bodies never do.
        assert!(text.contains("- synthetic-trap-000-with-a-realistically-long-slug — "));
        assert!(!text.contains("A longer body that the digest must never carry"));
    }

    // The drift check has to be clean, or every session-start hook in the
    // workspace reports a false positive for as long as the digest is enabled.
    let report = check_workspace(&workspace).unwrap();
    assert!(!report.drifted(), "wizard drift check: {:?}", report.details);

    // Recomposing an unchanged digest must not rewrite either file: a rewrite
    // is prefix churn, and prefix churn is re-billed at 2x on every session.
    for target in [Target::ClaudeMd, Target::AgentsMd] {
        let again = compose_file(&workspace, target, &enabled, false, false).unwrap();
        assert!(
            !again.wrote,
            "{} was rewritten with an unchanged digest",
            target.filename()
        );
    }
}
