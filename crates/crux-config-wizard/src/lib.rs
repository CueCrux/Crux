// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `crux-config-wizard` — composes `CLAUDE.md` and `AGENTS.md` from
//! versioned profile fragments for Crux-aligned workspaces.
#![allow(clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::inefficient_to_string))]
//!
//! Loaded by the `crux-claude-hooks session-start` hook for drift detection,
//! and called directly via the `crux-config-wizard` binary for `init`,
//! `regenerate`, `check`, `list`, `add`, `remove`, `diff` operations.
//!
//! See `ExecPlan agent-config-wizard-2026-05-19` for the design rationale.

pub mod commands;
pub mod compose;
pub mod config;
pub mod drift;
pub mod profile;

pub use compose::{compose_file, ComposeError, ComposeReport};
pub use config::{AgentProfileConfig, ConfigError, ProfileEntry};
pub use drift::{check_workspace, DriftReport};
pub use profile::{load_bundled_profiles, ProfileError, ProfileFragment, ProfileFrontmatter};

/// Default profile set for the CueCrux workspace, per the M6 of the
/// agent-config-wizard ExecPlan. Other workspaces opt in to whichever subset
/// matches their posture.
pub const DEFAULT_PROFILES: &[&str] = &[
    "memory-practices",
    "token-conservation",
    "execplan-discipline",
    "code-grounding",
    "scratchpad-survival",
    "pre-deploy-gate",
    "eu-ai-act",
    "audit-soc2",
    "workspace-cuecrux",
];

/// Output target for a profile fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    ClaudeMd,
    AgentsMd,
}

impl Target {
    pub fn filename(self) -> &'static str {
        match self {
            Self::ClaudeMd => "CLAUDE.md",
            Self::AgentsMd => "AGENTS.md",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_filenames() {
        assert_eq!(Target::ClaudeMd.filename(), "CLAUDE.md");
        assert_eq!(Target::AgentsMd.filename(), "AGENTS.md");
    }

    #[test]
    fn default_profiles_present_and_unique() {
        assert_eq!(DEFAULT_PROFILES.len(), 9);
        let mut seen = std::collections::HashSet::new();
        for p in DEFAULT_PROFILES {
            assert!(seen.insert(*p), "duplicate default profile '{p}'");
        }
    }

    #[test]
    fn default_profiles_match_bundled() {
        let bundled = load_bundled_profiles().unwrap();
        for p in DEFAULT_PROFILES {
            assert!(
                bundled.iter().any(|f| f.frontmatter.name == *p),
                "DEFAULT_PROFILES entry '{p}' missing from bundled set"
            );
        }
    }
}
