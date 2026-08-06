// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Tests for the Patchbay projection.
//!
//! Deliberately in `tests.rs` (gated from the parent via `#[path]`): the
//! unwrap-ratchet scan excludes files named `tests.rs`, and the corecruxd
//! baseline currently sits at its exact budget, so test-only `.unwrap()`s in a
//! counted file would red CI's Lint gate.

use super::*;

fn plan(slug: &str) -> String {
    format!("# {slug}\n\n## Purpose\n\nSomething.\n")
}

// ---- plane_for -------------------------------------------------------------

#[test]
fn slug_beats_a_body_full_of_other_systems() {
    // The failure this guards: ExecPlan boilerplate names every system in the
    // portfolio, so an unweighted body scan files nearly everything on one
    // plane. A slug hit must dominate.
    let body = "corecrux corecrux corecrux retrieval rerank embedding \
                paddle billing pricing lme benchmark console nuxt";
    assert_eq!(
        plane_for("wikicrux-agent-first-wiki-service-2026-06-11", "WikiCrux", body),
        "WikiCrux"
    );
}

#[test]
fn a_hyphenated_slug_matches_a_multi_word_pattern() {
    // Slugs separate with `-`, patterns with a space. Without normalising, every
    // multi-word pattern ("feature registry", "crux daemon") is unreachable from
    // a slug — caught against the real board, where
    // feature-registry-edge-reconciliation was filing under CoreCrux/Engine.
    assert_eq!(
        plane_for("feature-registry-edge-reconciliation-2026-08-02", "", ""),
        "PlanCrux"
    );
    assert_eq!(
        plane_for("crux-daemon-buyer-fit-buildout-2026-07-13", "", ""),
        "Crux daemon"
    );
}

#[test]
fn title_is_weighed_when_the_slug_is_silent() {
    assert_eq!(
        plane_for("m4-followups-2026-01-01", "Paddle billing rails", "some prose"),
        "Commerce"
    );
}

#[test]
fn body_alone_still_classifies() {
    let body = "wikicrux wikicrux wikicrux corpus coverage";
    assert_eq!(plane_for("misc-2026-01-01", "Misc", body), "WikiCrux");
}

#[test]
fn unlabelled_work_falls_back_to_the_daemon() {
    assert_eq!(
        plane_for("misc-2026-01-01", "Misc", "nothing familiar here"),
        "Crux daemon"
    );
}

#[test]
fn more_specific_plane_holds_a_tie() {
    // Two slug hits of equal weight; the earlier (more specific) table entry
    // must win, deterministically.
    assert_eq!(plane_for("wikicrux-corecrux-bridge-2026-01-01", "", ""), "WikiCrux");
}

#[test]
fn a_daemon_slug_does_not_land_on_the_engine_plane() {
    // `corecrux` is a prefix of `corecruxd`, so both planes match a daemon slug.
    // Without the table ordering every corecruxd plan files under the engine.
    assert_eq!(
        plane_for("corecruxd-c2pa-vault-pki-runtime-enablement-2026-05-29", "", ""),
        "Crux daemon"
    );
    // ...and a genuine engine slug still lands on the engine.
    assert_eq!(
        plane_for("corecrux-fleet-control-plane-2026-07-03", "", ""),
        "CoreCrux/Engine"
    );
}

#[test]
fn every_plane_is_reachable_from_its_own_slug() {
    // A plane nothing can ever land on is dead weight in the table.
    for (name, pats) in PLANES {
        let Some(first) = pats.first() else { continue };
        let got = plane_for(first, "", "");
        assert_eq!(got, *name, "plane {name} unreachable via its own pattern {first}");
    }
}

// ---- services_for ----------------------------------------------------------

#[test]
fn a_single_passing_mention_is_not_a_dependency() {
    assert!(services_for("we might one day use postgres").is_empty());
}

#[test]
fn repeated_mentions_count_as_a_dependency() {
    let svc = services_for("postgres migration postgres psql postgres");
    assert!(svc.iter().any(|s| s == "Postgres"), "got {svc:?}");
}

#[test]
fn services_are_capped_and_ordered_by_weight() {
    let body = "paddle paddle paddle paddle paddle \
                postgres postgres postgres \
                docker docker docker ghcr \
                otel otel opentelemetry \
                tailnet tailnet tailscale \
                minio minio object storage object-storage";
    let svc = services_for(body);
    assert!(svc.len() <= SERVICE_MAX, "not capped: {svc:?}");
    assert_eq!(svc.first().map(String::as_str), Some("Paddle"), "got {svc:?}");
}

#[test]
fn every_service_has_a_rail() {
    for (name, side) in all_services() {
        assert_eq!(service_side(name), Some(side));
        assert!(
            matches!(side, "top" | "bottom" | "left" | "right"),
            "service {name} has an unknown rail {side}"
        );
    }
}

// ---- purpose_blurb ---------------------------------------------------------

#[test]
fn blurb_takes_the_first_paragraph_of_purpose() {
    let md = "# T\n\n## Purpose\n\nMake the thing work.\nAnd keep it working.\n\n\
              Second paragraph is ignored.\n\n## Non-goals\n\nNope.\n";
    assert_eq!(
        purpose_blurb(md, 200).as_deref(),
        Some("Make the thing work. And keep it working.")
    );
}

#[test]
fn blurb_skips_the_risk_class_declaration() {
    let md = "## Purpose\n\n**Risk class: high.** Touches billing.\n";
    let got = purpose_blurb(md, 200);
    assert_eq!(got.as_deref(), Some("Touches billing."), "got {got:?}");
}

#[test]
fn blurb_strips_markdown_and_links() {
    let md = "## Purpose\n\nSee [[other-plan]] and [the doc](../x.md) for `context`.\n";
    assert_eq!(
        purpose_blurb(md, 200).as_deref(),
        Some("See other-plan and the doc for context.")
    );
}

#[test]
fn blurb_ignores_fenced_blocks() {
    let md = "## Purpose\n\n```\n## Purpose\nfake\n```\nReal text.\n";
    let got = purpose_blurb(md, 200);
    assert_eq!(got.as_deref(), Some("Real text."), "got {got:?}");
}

#[test]
fn blurb_is_absent_when_there_is_no_purpose() {
    assert!(purpose_blurb("# T\n\n## Context\n\nStuff.\n", 200).is_none());
    assert!(purpose_blurb("## Purpose\n\n**Risk class: low.**\n", 200).is_none());
}

#[test]
fn blurb_truncates_on_a_word_boundary() {
    let md = format!("## Purpose\n\n{}\n", "alpha bravo ".repeat(40));
    let Some(got) = purpose_blurb(&md, 30) else {
        panic!("expected a blurb");
    };
    assert!(got.chars().count() <= 31, "too long: {got:?}");
    assert!(got.ends_with('…'), "missing ellipsis: {got:?}");
    assert!(!got.contains("alp…"), "split mid-word: {got:?}");
}

#[test]
fn blurb_handles_multibyte_text() {
    let md = "## Purpose\n\nRé-ingest the corpus — évidemment — and keep going for a while.\n";
    let Some(got) = purpose_blurb(md, 20) else {
        panic!("expected a blurb");
    };
    assert!(got.chars().count() <= 21, "got {got:?}");
}

// ---- narrow_links ----------------------------------------------------------

#[test]
fn links_are_narrowed_to_open_plans() {
    let open = |s: &str| s == "b" || s == "c";
    let declared = vec!["a".into(), "b".into(), "c".into()];
    assert_eq!(narrow_links(&declared, &open, "self"), vec!["b", "c"]);
}

#[test]
fn links_drop_self_and_duplicates() {
    let open = |_: &str| true;
    let declared = vec!["b".into(), "b".into(), "self".into(), " ".into()];
    assert_eq!(narrow_links(&declared, &open, "self"), vec!["b"]);
}

#[test]
fn a_prose_wikilink_is_never_an_edge() {
    // The load-bearing guarantee: edges come from `Depends on [[…]]` declaration
    // lines only. A plan that merely *mentions* another plan in prose must not
    // gain an edge — otherwise a typo lands on the dependency graph. This asserts
    // the parser contract that narrow_links is fed from.
    let md = "# T\n\n## Purpose\n\nRelated work lives in [[other-plan]], see also\n\
              [[third-plan]] for background.\n\n## Milestones\n\n- [ ] M1 do it\n";
    let parsed = crate::work_execplans::parse_plan(md);
    assert!(
        parsed.depends_on.is_empty(),
        "prose mention became a dependency: {:?}",
        parsed.depends_on
    );
    assert!(parsed.extended_by.is_empty(), "prose mention became an edge");

    // ...whereas the declaration line does produce one.
    let declared = format!("{md}\nDepends on [[other-plan]]\n");
    let parsed2 = crate::work_execplans::parse_plan(&declared);
    assert_eq!(parsed2.depends_on, vec!["other-plan".to_string()]);
}

// ---- distribution guard (plan risk R2) -------------------------------------

#[test]
fn the_tagger_does_not_collapse_the_board_onto_one_plane() {
    // R2 in the ExecPlan: the first scorer put 58 of 63 plans on a single plane.
    // Feed a spread of real-shaped slugs and assert the classifier keeps them
    // apart, with no plane taking more than half.
    let slugs = [
        "crux-log-redaction-2026-06-11",
        "crux-key-escrow-and-recovery-2026-07-31",
        "corecrux-fleet-control-plane-2026-07-03",
        "corecrux-turboquant-ccxe-quant-mode",
        "commerce-paddle-billing-2026-06-11",
        "tier-packaging-and-site-reframe-2026-07-13",
        "wikicrux-link-graph-explorer-2026-07-23",
        "wikicrux-agent-first-wiki-service-2026-06-11",
        "rcx-registry-v11-adoption-trust-hardening-2026-07-19",
        "scorecrux-opus-5-2026-07-24",
        "lme-ordering-day-precision-extraction-2026-06-12",
        "vaultcrux-opslite-v8-coverage-console-2026-02-25",
        "chaincrux-zero-events-substrate-investigation-2026-05-28",
        "frontdoor-agent-ux-nuxt-feature-flag-wiring-2026-05-29",
    ];
    let mut seen: Vec<&'static str> = Vec::new();
    for s in slugs {
        seen.push(plane_for(s, "", &plan(s)));
    }
    let mut distinct: Vec<&'static str> = Vec::new();
    for p in &seen {
        if !distinct.contains(p) {
            distinct.push(p);
        }
    }
    assert!(
        distinct.len() >= 8,
        "collapsed onto {} planes: {seen:?}",
        distinct.len()
    );
    for d in distinct {
        let n = seen.iter().filter(|&&p| p == d).count();
        assert!(n * 2 <= seen.len(), "plane {d} took {n}/{} of the board", seen.len());
    }
}
