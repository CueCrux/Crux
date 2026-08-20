// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Profile fragment loader.
//!
//! Profile fragments are markdown files with TOML frontmatter delimited by
//! `+++`. The frontmatter declares `name`, `version`, `description`, `targets`
//! (which output files this fragment lands in), `order` (numeric sort
//! position), optional `conflicts_with` / `requires`, and `risk_class`.
//!
//! Bundled profiles ship in `crates/crux-config-wizard/profiles/` and are
//! embedded into the binary via `include_str!`. The `load_bundled_profiles()`
//! function returns the list at runtime; no filesystem read is required.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::Target;

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("profile {name}: frontmatter missing or malformed: {reason}")]
    Frontmatter { name: String, reason: String },
    #[error("profile {name}: missing required field '{field}'")]
    MissingField { name: String, field: String },
    #[error("profile {0}: TOML parse error: {1}")]
    TomlParse(String, #[source] toml::de::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileFrontmatter {
    pub name: String,
    pub version: u32,
    pub description: String,
    #[serde(default)]
    pub targets: Vec<Target>,
    #[serde(default)]
    pub order: u32,
    #[serde(default)]
    pub conflicts_with: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default = "default_risk_class")]
    pub risk_class: String,
}

fn default_risk_class() -> String {
    "low".to_string()
}

#[derive(Debug, Clone)]
pub struct ProfileFragment {
    pub frontmatter: ProfileFrontmatter,
    pub body: String,
}

impl ProfileFragment {
    /// Parse a raw fragment string (with `+++`-delimited TOML frontmatter).
    ///
    /// CRLF input parses identically to LF. `bundled_raw` resolves these
    /// fragments with `include_str!`, which bakes in whatever bytes are on disk
    /// at compile time, so a checkout under git's `core.autocrlf=true` (the
    /// Windows default) hands every fence below a `\r` it would not otherwise
    /// match. Normalising once here — rather than relying on `.gitattributes` —
    /// keeps parsing and the composed output byte-identical across platforms,
    /// and covers existing clones that an attributes file could not reach.
    pub fn parse(name_hint: &str, raw: &str) -> Result<Self, ProfileError> {
        let normalised: Cow<'_, str> = if raw.contains('\r') {
            Cow::Owned(raw.replace("\r\n", "\n"))
        } else {
            Cow::Borrowed(raw)
        };
        let trimmed = normalised.trim_start();
        let rest = trimmed.strip_prefix("+++\n").ok_or_else(|| ProfileError::Frontmatter {
            name: name_hint.to_string(),
            reason: "missing opening '+++' frontmatter fence".into(),
        })?;
        let end = rest.find("\n+++").ok_or_else(|| ProfileError::Frontmatter {
            name: name_hint.to_string(),
            reason: "missing closing '+++' frontmatter fence".into(),
        })?;
        let fm_text = &rest[..end];
        // Body starts after the closing fence and its trailing newline.
        let after = &rest[end + "\n+++".len()..];
        let body = after.trim_start_matches('\n').to_string();

        let mut fm: ProfileFrontmatter =
            toml::from_str(fm_text).map_err(|e| ProfileError::TomlParse(name_hint.to_string(), e))?;

        if fm.name.is_empty() {
            return Err(ProfileError::MissingField {
                name: name_hint.to_string(),
                field: "name".into(),
            });
        }
        if fm.targets.is_empty() {
            // Sensible default: both CLAUDE.md and AGENTS.md.
            fm.targets = vec![Target::ClaudeMd, Target::AgentsMd];
        }
        Ok(Self { frontmatter: fm, body })
    }
}

/// Bundled profile sources. Each entry is `(filename_hint, raw_contents)`.
/// `include_str!` is resolved at compile time, so the binary is
/// self-contained and works in any cwd.
fn bundled_raw() -> Vec<(&'static str, &'static str)> {
    vec![
        ("memory-practices.md", include_str!("../profiles/memory-practices.md")),
        (
            "token-conservation.md",
            include_str!("../profiles/token-conservation.md"),
        ),
        ("claude-5.md", include_str!("../profiles/claude-5.md")),
        (
            "agent-harness-parity.md",
            include_str!("../profiles/agent-harness-parity.md"),
        ),
        (
            "execplan-discipline.md",
            include_str!("../profiles/execplan-discipline.md"),
        ),
        ("code-grounding.md", include_str!("../profiles/code-grounding.md")),
        ("code-minimalism.md", include_str!("../profiles/code-minimalism.md")),
        (
            "scratchpad-survival.md",
            include_str!("../profiles/scratchpad-survival.md"),
        ),
        ("boot-banner.md", include_str!("../profiles/boot-banner.md")),
        ("pre-deploy-gate.md", include_str!("../profiles/pre-deploy-gate.md")),
        ("eu-ai-act.md", include_str!("../profiles/eu-ai-act.md")),
        ("audit-soc2.md", include_str!("../profiles/audit-soc2.md")),
        ("workspace-cuecrux.md", include_str!("../profiles/workspace-cuecrux.md")),
    ]
}

pub fn load_bundled_profiles() -> Result<Vec<ProfileFragment>, ProfileError> {
    let mut out = Vec::new();
    for (name_hint, raw) in bundled_raw() {
        out.push(ProfileFragment::parse(name_hint, raw)?);
    }
    out.sort_by_key(|f| f.frontmatter.order);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"+++
name = "sample"
version = 2
description = "a sample profile"
targets = ["claude_md"]
order = 50
risk_class = "medium"
+++

## Body

This is the body.
"#;

    /// A CRLF checkout must parse exactly as an LF one, and produce the same
    /// body bytes. `include_str!` embeds the on-disk form, so under git's
    /// `core.autocrlf=true` this is what every bundled profile actually looks
    /// like to the parser — the whole crate failed to load a single profile on
    /// Windows until the parser normalised it, while Linux-only CI stayed green.
    #[test]
    fn crlf_checkout_parses_identically_to_lf() {
        let lf = ProfileFragment::parse("sample.md", SAMPLE).unwrap();
        let crlf_src = SAMPLE.replace('\n', "\r\n");
        let crlf = ProfileFragment::parse("sample.md", &crlf_src).unwrap();

        assert_eq!(crlf.frontmatter.name, lf.frontmatter.name);
        assert_eq!(crlf.frontmatter.version, lf.frontmatter.version);
        assert_eq!(crlf.frontmatter.targets, lf.frontmatter.targets);
        assert_eq!(crlf.frontmatter.order, lf.frontmatter.order);
        // Byte-identical bodies: a composed CLAUDE.md must not depend on how
        // the repository happened to be checked out.
        assert_eq!(crlf.body, lf.body);
        assert!(
            !crlf.body.contains('\r'),
            "normalisation must not leave stray CR in the body"
        );
    }

    /// The bundled set must load on the host actually running the tests, not
    /// just on the CI platform. This is the assertion Linux-only CI could not make.
    #[test]
    fn bundled_profiles_load_on_this_platform() {
        let loaded = load_bundled_profiles().expect("every bundled profile must parse on this platform");
        assert_eq!(loaded.len(), bundled_raw().len());
        for f in &loaded {
            assert!(
                !f.body.contains('\r'),
                "profile {} kept a CR in its body",
                f.frontmatter.name
            );
        }
    }

    #[test]
    fn parse_round_trip() {
        let f = ProfileFragment::parse("sample.md", SAMPLE).unwrap();
        assert_eq!(f.frontmatter.name, "sample");
        assert_eq!(f.frontmatter.version, 2);
        assert_eq!(f.frontmatter.targets, vec![Target::ClaudeMd]);
        assert_eq!(f.frontmatter.order, 50);
        assert!(f.body.contains("## Body"));
    }

    #[test]
    fn missing_frontmatter_errors() {
        let raw = "## body only, no frontmatter\n";
        assert!(ProfileFragment::parse("x", raw).is_err());
    }

    #[test]
    fn missing_close_fence_errors() {
        let raw = "+++\nname = \"x\"\nversion = 1\ndescription = \"d\"\n\nno-close\n";
        assert!(ProfileFragment::parse("x", raw).is_err());
    }

    #[test]
    fn empty_targets_default_to_both() {
        let raw = "+++\nname = \"x\"\nversion = 1\ndescription = \"d\"\n+++\nbody\n";
        let f = ProfileFragment::parse("x", raw).unwrap();
        assert_eq!(f.frontmatter.targets, vec![Target::ClaudeMd, Target::AgentsMd]);
    }

    #[test]
    fn bundled_load_returns_all_in_order() {
        let bundled = load_bundled_profiles().unwrap();
        assert_eq!(bundled.len(), 13);
        for win in bundled.windows(2) {
            assert!(
                win[0].frontmatter.order <= win[1].frontmatter.order,
                "bundled profiles must be sorted by order"
            );
        }
    }

    #[test]
    fn code_minimalism_v2_bounds_benchmark_claims() {
        let bundled = load_bundled_profiles().unwrap();
        let profile = bundled
            .iter()
            .find(|f| f.frontmatter.name == "code-minimalism")
            .expect("code-minimalism fragment must be bundled");
        assert_eq!(profile.frontmatter.version, 2);

        let claims = format!("{}\n{}", profile.frontmatter.description, profile.body)
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(claims.contains("did not execute"));
        assert!(claims.contains("non-empty code diff"));
        assert!(claims.contains("95 returned cli result json"));
        assert!(claims.contains("timed out"));
        assert!(claims.contains("censored/provisional"));
        assert!(claims.contains("functional correctness"));
        assert!(claims.contains("causal"));
        for unsupported in [
            "no correctness regression",
            "zero correctness",
            "correctness 1.0",
            "correctness 1.00",
            "both arms correct",
            "48/48 correct",
            "all cells correct",
            "effect scales with model",
            "effect grows with model",
            "stronger models over-build",
            "matters most on the strongest",
        ] {
            assert!(!claims.contains(unsupported), "unsupported claim: {unsupported}");
        }
    }

    /// The `claude-5` profile exists to *remove* two instruction classes that cost
    /// tokens without improving results on Claude 5 generation models: re-verification
    /// prompts and fixed numeric output ceilings. Both are the kind of rule that creeps
    /// back in during a well-meaning edit, so guard them here.
    #[test]
    fn claude_5_omits_numeric_caps_and_keeps_the_no_reverify_carve_out() {
        let bundled = load_bundled_profiles().unwrap();
        let p = bundled
            .iter()
            .find(|f| f.frontmatter.name == "claude-5")
            .expect("claude-5 fragment must be bundled");

        // claude_md only. Rendering this into AGENTS.md would duplicate what Claude
        // Code's own system prompt already supplies — see `agent-harness-parity`.
        assert_eq!(p.frontmatter.targets, vec![Target::ClaudeMd]);
        assert!(
            p.frontmatter.conflicts_with.iter().any(|c| c == "token-conservation"),
            "claude-5 supersedes token-conservation and must declare the conflict"
        );

        // Match against description + body, normalised to one space-joined line, so a
        // reflow cannot silently defeat these guards. The rationale lives in the
        // description on purpose: it is *why* the profile is shaped this way, and
        // frontmatter is not rendered into CLAUDE.md, so it costs no session context.
        let claims = format!("{}\n{}", p.frontmatter.description, p.body)
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        for cap in ["500-token", "at most 10 lines", "token output max", "2,000 for design"] {
            assert!(
                !claims.contains(cap),
                "claude-5 must not carry a fixed output cap: {cap}"
            );
        }
        assert!(
            claims.contains("self-verification is already the model's default behaviour"),
            "the no-reverification rationale must stay explicit or the profile rots"
        );
        assert!(
            claims.contains("verification belongs in the main loop"),
            "subagent-verification carve-out must survive"
        );

        // The body is the part that costs context on every session. Keep it lean —
        // this profile replaces a 19-line one, and a subtraction pass that grows the
        // rendered file has failed at its own premise.
        let body_lines = p.body.lines().filter(|l| !l.trim().is_empty()).count();
        assert!(
            body_lines <= 40,
            "claude-5 body is {body_lines} non-blank lines; keep rationale in `description`"
        );
    }

    /// `agent-harness-parity` carries the rules Claude Code's harness supplies natively,
    /// for harnesses that do not. It must never render into CLAUDE.md, or it re-introduces
    /// exactly the duplication `claude-5` was written to remove.
    #[test]
    fn agent_harness_parity_is_agents_md_only_and_disjoint_from_claude_5() {
        let bundled = load_bundled_profiles().unwrap();
        let p = bundled
            .iter()
            .find(|f| f.frontmatter.name == "agent-harness-parity")
            .expect("agent-harness-parity fragment must be bundled");
        assert_eq!(p.frontmatter.targets, vec![Target::AgentsMd]);

        let body = p.body.to_lowercase();
        assert!(body.contains("single message"), "tool-batching rule must be stated");
        assert!(
            body.contains("\"x exists now\""),
            "memory-staleness rule must be stated for non-Claude harnesses"
        );

        // The two profiles must not both land in the same file.
        let claude5 = bundled
            .iter()
            .find(|f| f.frontmatter.name == "claude-5")
            .expect("claude-5 fragment must be bundled");
        for t in &p.frontmatter.targets {
            assert!(
                !claude5.frontmatter.targets.contains(t),
                "claude-5 and agent-harness-parity must not share a target"
            );
        }
    }

    /// v2 narrowed this profile to source-citation and corpus-identity. The dropped
    /// sections were re-verification instructions; re-adding them would reintroduce the
    /// over-verification this generation is prone to.
    #[test]
    fn code_grounding_v2_drops_the_reverification_sections() {
        let bundled = load_bundled_profiles().unwrap();
        let p = bundled
            .iter()
            .find(|f| f.frontmatter.name == "code-grounding")
            .expect("code-grounding fragment must be bundled");
        assert_eq!(p.frontmatter.version, 2);

        let body = p.body.to_lowercase();
        for dropped in [
            "when the result surprises you",
            "memory-versus-current-state",
            "substrate scans need budgets",
        ] {
            assert!(
                !body.contains(dropped),
                "code-grounding v2 dropped this section: {dropped}"
            );
        }
        assert!(body.contains("file:line"), "citation rule survives");
        assert!(body.contains("corpus"), "corpus-identity rule survives");
    }

    /// v2 collapsed four competing boot rituals into one, and handed the retrieval-budget
    /// and entity-prefix rules to the MCP tool schemas. Guard both.
    #[test]
    fn memory_practices_v3_declares_a_single_boot_and_pins_tool_routing() {
        let bundled = load_bundled_profiles().unwrap();
        let p = bundled
            .iter()
            .find(|f| f.frontmatter.name == "memory-practices")
            .expect("memory-practices fragment must be bundled");
        assert_eq!(p.frontmatter.version, 3);

        let body = p.body.to_lowercase();
        assert!(
            body.contains("this is the **only** boot sequence"),
            "the single-boot claim must be explicit"
        );
        assert!(
            !body.contains("is mandatory on every retrieval call"),
            "the token_budget mandate now lives in the MCP tool schemas, not here"
        );
        assert!(
            !body.contains("entity=\"execplan:"),
            "entity conventions now live in the store_fact schema, not here"
        );

        // v3: the three signals that were being misread as "the tools cannot
        // reach the daemon" must each be named, or the misreading recurs.
        for signal in ["[tier:local]", "local_only", "unreachable"] {
            assert!(
                body.contains(signal),
                "v3 must disambiguate the `{signal}` signal from tool routing"
            );
        }
        assert!(
            body.contains("fall back to raw http only on an actual failure"),
            "v3 must state the call-then-fall-back rule, not merely explain the markers"
        );
    }

    /// v2 lifted the deploy checklist into the bundled `pre-deploy-gate` skill.
    /// What stays inline is only what a deploy-triggered skill cannot deliver in
    /// time: the process-detachment triad (any long-running job, not just a
    /// deploy) and the three-place wiring rule (a coding-time gotcha that has
    /// nothing to do with deploying). Guard both directions — the moved
    /// checklist must not creep back, and those two must not drift out.
    #[test]
    fn pre_deploy_gate_v2_defers_the_checklist_to_the_skill() {
        let bundled = load_bundled_profiles().unwrap();
        let p = bundled
            .iter()
            .find(|f| f.frontmatter.name == "pre-deploy-gate")
            .expect("pre-deploy-gate fragment must be bundled");
        assert_eq!(p.frontmatter.version, 2);

        let body = p.body.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ");
        for moved in [
            "ls db/migrations/",
            "database_url",
            "df -h",
            "corecruxd-deploy-audit",
            "journalctl -u corecruxd",
            "store_fact(entity=\"incident:",
        ] {
            assert!(
                !body.contains(moved),
                "checklist item crept back into the always-loaded profile: {moved}"
            );
        }

        assert!(
            body.contains("`pre-deploy-gate` skill's checklist"),
            "the profile must name the skill, or the checklist becomes unreachable"
        );
        assert!(
            body.contains("setsid + nohup + < /dev/null + disown"),
            "the process-detachment triad fires outside a deploy and must stay inline"
        );
        assert!(
            body.contains("storage allowlist, projection registry, and load-at-startup"),
            "three-place wiring is a coding-time gotcha and must stay inline"
        );

        // The point of the move is the always-loaded cost. v1 was 34 non-blank
        // lines; a pointer that grows back past ~a dozen has undone the win.
        let body_lines = p.body.lines().filter(|l| !l.trim().is_empty()).count();
        assert!(
            body_lines <= 13,
            "pre-deploy-gate body is {body_lines} non-blank lines; detail belongs in the skill"
        );
    }

    /// v3 moved the drift guard's install/wiring detail into
    /// `docs/execplan-drift-guard.md`. The body keeps only what an agent needs
    /// mid-session; operator setup is read on demand. Guard both halves.
    #[test]
    fn execplan_discipline_v7_pins_a_runnable_workspace_green_gate_and_still_defers_setup_detail() {
        let bundled = load_bundled_profiles().unwrap();
        let p = bundled
            .iter()
            .find(|f| f.frontmatter.name == "execplan-discipline")
            .expect("execplan-discipline fragment must be bundled");
        assert_eq!(p.frontmatter.version, 7);

        let body = p.body.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ");

        // Operator-time setup detail belongs in the doc, not in every session.
        for setup in [
            ".claude/settings.json",
            ".codex/hooks.json",
            "xdg_data_home",
            "--print-only",
            "crux_execplans_root",
            "~/.local/share/crux/hooks",
        ] {
            assert!(
                !body.contains(setup),
                "execplan-discipline v3 defers setup detail to docs: {setup}"
            );
        }

        // Agent-time behaviour must survive: the hook can fire mid-session, and the
        // leading-token rule is a real semantic gotcha that is not inferable.
        // v5: the propagation step. The board is a read-time projection over the
        // daemon's replica, so a locally-committed plan is invisible to every other
        // session until it is pushed and refreshed — and an untracked plan can be
        // destroyed outright by a sibling checkout (one was, on 2026-07-31).
        assert!(
            body.contains("/v1/execplans/refresh"),
            "the gate routine must name the refresh call"
        );
        assert!(
            body.contains("untracked"),
            "commit-on-create must survive: an untracked plan is one checkout from gone"
        );
        assert!(body.contains("posttooluse"), "the agent must know the hook exists");
        assert!(body.contains("leading"), "leading-Status:-token semantics must survive");
        assert!(
            body.contains("docs/execplan-drift-guard.md"),
            "must point at the reference doc"
        );

        // v4: the pre-flight pointed at `get_gaps`, which reads retrieval-coverage
        // facts, and at the retired PlanCrux API. Pin the real endpoint and the
        // disambiguation, or agents silently pre-flight against the wrong surface.
        assert!(
            body.contains("/v1/features/capabilities/analysis/gaps"),
            "the pre-flight must name the Features-lens endpoint"
        );
        assert!(
            body.contains("get_gaps` is **not** this"),
            "the get_gaps/capability-registry distinction must be explicit"
        );

        // v6: a per-package check passes while a downstream *test* target is
        // broken. Without the workspace-green half, "I ran the steps" reads as a
        // gate result — which is how a one-field struct change reached CI unseen.
        assert!(
            body.contains("workspace-green"),
            "the milestone gate must define done as workspace-green"
        );
        // v7: the command has to be one an agent can actually run. v6 named
        // `clippy --all-targets`, which on a crate that denies unwrap/expect in
        // production while its tests use them reports thousands of pre-existing
        // errors — an unrunnable gate is worse than none, because the first
        // agent to try it learns to ignore the rule.
        assert!(
            body.contains("cargo check --workspace --all-targets`)"),
            "the gate must name the compile-all-targets sweep it can actually run"
        );
        assert!(
            body.contains("deliberate posture and not a finding"),
            "the clippy --all-targets false-positive must be called out by name"
        );
    }

    #[test]
    fn boot_banner_fragment_loads() {
        let bundled = load_bundled_profiles().unwrap();
        let bb = bundled
            .iter()
            .find(|f| f.frontmatter.name == "boot-banner")
            .expect("boot-banner fragment must be bundled");
        assert_eq!(bb.frontmatter.order, 47);
        assert_eq!(bb.frontmatter.targets, vec![Target::ClaudeMd, Target::AgentsMd]);
        assert!(bb.body.contains("crux-statusline"), "documents the statusline");
        assert!(bb.body.contains("crux-claude-banner"), "documents the agent brief");
        assert!(bb.body.contains("CRUX_BANNER_CARD"), "documents the switches");
    }

    #[test]
    fn bundled_profiles_have_non_empty_bodies() {
        let bundled = load_bundled_profiles().unwrap();
        for f in &bundled {
            assert!(
                !f.body.trim().is_empty(),
                "profile '{}' has an empty body",
                f.frontmatter.name
            );
        }
    }

    #[test]
    fn invalid_toml_in_frontmatter_errors() {
        let raw = "+++\nname = \"x\"\nversion = not_a_number\n+++\nbody\n";
        let err = ProfileFragment::parse("x", raw).unwrap_err();
        assert!(matches!(err, ProfileError::TomlParse(_, _)));
    }
}
