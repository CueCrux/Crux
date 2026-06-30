// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
    pub fn parse(name_hint: &str, raw: &str) -> Result<Self, ProfileError> {
        let trimmed = raw.trim_start();
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
        (
            "execplan-discipline.md",
            include_str!("../profiles/execplan-discipline.md"),
        ),
        ("code-grounding.md", include_str!("../profiles/code-grounding.md")),
        (
            "scratchpad-survival.md",
            include_str!("../profiles/scratchpad-survival.md"),
        ),
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
    fn bundled_load_returns_nine_in_order() {
        let bundled = load_bundled_profiles().unwrap();
        assert_eq!(bundled.len(), 9);
        for win in bundled.windows(2) {
            assert!(
                win[0].frontmatter.order <= win[1].frontmatter.order,
                "bundled profiles must be sorted by order"
            );
        }
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
