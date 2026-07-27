// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::inefficient_to_string)]

//! End-to-end test: drive the library API the same way `main.rs` does, in a
//! tempdir. Covers init → regenerate idempotency → add → remove → check.

use crux_config_wizard::{
    compose::compose_file,
    config::{workspace_fingerprint, AgentProfileConfig},
    drift::check_workspace,
    profile::load_bundled_profiles,
    Target, DEFAULT_PROFILES,
};
use tempfile::TempDir;

#[test]
fn full_init_regenerate_loop() {
    let dir = TempDir::new().unwrap();
    let workspace = dir.path();

    let bundled = load_bundled_profiles().expect("bundled profiles parse");
    assert_eq!(bundled.len(), 13, "13 bundled profiles expected");

    // init with all defaults.
    let mut cfg = AgentProfileConfig::new(workspace_fingerprint(workspace));
    for name in DEFAULT_PROFILES {
        let frag = bundled.iter().find(|f| &f.frontmatter.name == name).unwrap();
        cfg.enable(name, frag.frontmatter.version);
    }
    cfg.save(workspace).unwrap();

    let enabled: Vec<_> = bundled
        .iter()
        .filter(|f| cfg.profiles.contains_key(&f.frontmatter.name))
        .cloned()
        .collect();

    // Both targets land 10 sections: 9 shared profiles, plus exactly one of the
    // target-split pair (claude-5 → CLAUDE.md, agent-harness-parity → AGENTS.md).
    for t in [Target::ClaudeMd, Target::AgentsMd] {
        let r = compose_file(workspace, t, &enabled, false, false).unwrap();
        assert!(r.wrote);
        assert_eq!(r.managed_sections_added, 10);
    }

    // The two files must no longer be identical. CLAUDE.md omits the rules Claude
    // Code's own system prompt supplies; AGENTS.md states them for harnesses that
    // do not. A regression here silently re-introduces the duplicated-instruction
    // cost that the claude-5 / agent-harness-parity split exists to remove.
    let claude_md = std::fs::read_to_string(workspace.join("CLAUDE.md")).unwrap();
    let agents_md = std::fs::read_to_string(workspace.join("AGENTS.md")).unwrap();
    assert_ne!(claude_md, agents_md, "CLAUDE.md and AGENTS.md must diverge");
    assert!(claude_md.contains("BEGIN-CRUX-MANAGED:claude-5"));
    assert!(!claude_md.contains("BEGIN-CRUX-MANAGED:agent-harness-parity"));
    assert!(agents_md.contains("BEGIN-CRUX-MANAGED:agent-harness-parity"));
    assert!(!agents_md.contains("BEGIN-CRUX-MANAGED:claude-5"));

    // idempotency: second compose makes no change.
    for t in [Target::ClaudeMd, Target::AgentsMd] {
        let r = compose_file(workspace, t, &enabled, false, false).unwrap();
        assert!(!r.wrote, "second compose must not rewrite");
    }

    // check should report no drift.
    let report = check_workspace(workspace).unwrap();
    assert!(!report.drifted(), "no drift expected immediately after init");

    // remove a profile and re-compose.
    let mut cfg2 = AgentProfileConfig::load(workspace).unwrap();
    cfg2.disable("eu-ai-act");
    cfg2.save(workspace).unwrap();
    let enabled2: Vec<_> = bundled
        .iter()
        .filter(|f| cfg2.profiles.contains_key(&f.frontmatter.name))
        .cloned()
        .collect();
    for t in [Target::ClaudeMd, Target::AgentsMd] {
        compose_file(workspace, t, &enabled2, false, false).unwrap();
    }
    let after = std::fs::read_to_string(workspace.join("CLAUDE.md")).unwrap();
    assert!(!after.contains("BEGIN-CRUX-MANAGED:eu-ai-act"));
    assert!(after.contains("BEGIN-CRUX-MANAGED:memory-practices"));
}

#[test]
fn manual_section_survives_regenerate() {
    let dir = TempDir::new().unwrap();
    let workspace = dir.path();
    let bundled = load_bundled_profiles().unwrap();
    let two: Vec<_> = bundled
        .iter()
        .filter(|f| matches!(f.frontmatter.name.as_str(), "memory-practices" | "token-conservation"))
        .cloned()
        .collect();
    compose_file(workspace, Target::ClaudeMd, &two, false, false).unwrap();

    let path = workspace.join("CLAUDE.md");
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str("\n## My own section\n\nNotes I added by hand.\n");
    std::fs::write(&path, &text).unwrap();

    compose_file(workspace, Target::ClaudeMd, &two, false, false).unwrap();
    let after = std::fs::read_to_string(&path).unwrap();
    assert!(after.contains("## My own section"));
    assert!(after.contains("Notes I added by hand."));
}

#[test]
fn bundled_profiles_have_expected_names() {
    let bundled = load_bundled_profiles().unwrap();
    let names: Vec<_> = bundled.iter().map(|f| f.frontmatter.name.clone()).collect();
    for default in DEFAULT_PROFILES {
        assert!(
            names.contains(&default.to_string()),
            "missing default profile '{default}'"
        );
    }
}
