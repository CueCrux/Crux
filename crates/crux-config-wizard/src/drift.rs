// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Workspace drift check — called by `crux-claude-hooks session-start` so
//! every Claude session sees `additionalContext` advising a regenerate when
//! `CLAUDE.md` / `AGENTS.md` versions don't match the bundled fragments.

use std::path::Path;

use crate::compose::compose_file;
use crate::config::AgentProfileConfig;
use crate::profile::load_bundled_profiles;
use crate::Target;

#[derive(Debug)]
pub struct DriftReport {
    pub drifted: bool,
    pub details: Vec<String>,
}

impl DriftReport {
    pub fn drifted(&self) -> bool {
        self.drifted
    }

    pub fn message_for_claude(&self) -> String {
        if !self.drifted {
            return String::new();
        }
        let detail = if self.details.is_empty() {
            "Run `crux-config-wizard regenerate` to refresh.".to_string()
        } else {
            format!(
                "{}\n\nRun `crux-config-wizard regenerate` to refresh.",
                self.details.join("\n")
            )
        };
        format!("[crux-config-wizard] CLAUDE.md or AGENTS.md is out of date.\n{detail}")
    }
}

/// Check the workspace at `workspace_root` for managed-section drift against
/// the bundled profile fragments. Returns drifted=false when there's no
/// config (the wizard hasn't been run yet) — that's not drift, just unset.
pub fn check_workspace(workspace_root: &Path) -> std::io::Result<DriftReport> {
    let cfg = match AgentProfileConfig::load(workspace_root) {
        Ok(c) => c,
        Err(_) => {
            return Ok(DriftReport {
                drifted: false,
                details: Vec::new(),
            });
        }
    };
    let bundled = match load_bundled_profiles() {
        Ok(b) => b,
        Err(e) => {
            return Ok(DriftReport {
                drifted: true,
                details: vec![format!("failed to load bundled profiles: {e}")],
            });
        }
    };

    let enabled: Vec<_> = bundled
        .into_iter()
        .filter(|f| cfg.profiles.contains_key(&f.frontmatter.name))
        .collect();

    let mut details = Vec::new();

    // Version mismatch between config + bundled.
    for f in &enabled {
        if let Some(entry) = cfg.profiles.get(&f.frontmatter.name) {
            if entry.version != f.frontmatter.version {
                details.push(format!(
                    "profile '{}' is at v{} in config but v{} in the crate",
                    f.frontmatter.name, entry.version, f.frontmatter.version
                ));
            }
        }
    }

    // Content drift: would regenerate change anything?
    for target in [Target::ClaudeMd, Target::AgentsMd] {
        let report = compose_file(workspace_root, target, &enabled, false, true);
        match report {
            Ok(r) if r.wrote => details.push(format!(
                "{} would be rewritten (updated={}, added={})",
                target.filename(),
                r.managed_sections_updated,
                r.managed_sections_added
            )),
            Ok(_) => {}
            Err(crate::compose::ComposeError::Drift { profile, .. }) => details.push(format!(
                "{} has manual edits inside managed section '{}'",
                target.filename(),
                profile
            )),
            Err(e) => details.push(format!("{} check failed: {e}", target.filename())),
        }
    }

    let drifted = !details.is_empty();
    Ok(DriftReport { drifted, details })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn empty_workspace_is_not_drifted() {
        let dir = TempDir::new().unwrap();
        let r = check_workspace(dir.path()).unwrap();
        assert!(!r.drifted());
        assert!(r.message_for_claude().is_empty());
    }

    #[test]
    fn drift_report_message_when_clean() {
        let r = DriftReport {
            drifted: false,
            details: Vec::new(),
        };
        assert!(r.message_for_claude().is_empty());
    }

    #[test]
    fn drift_report_message_with_details() {
        let r = DriftReport {
            drifted: true,
            details: vec!["profile 'x' is at v1 in config but v2 in the crate".into()],
        };
        let msg = r.message_for_claude();
        assert!(msg.contains("out of date"));
        assert!(msg.contains("profile 'x'"));
        assert!(msg.contains("regenerate"));
    }

    #[test]
    fn drift_report_message_no_details_falls_back_to_generic() {
        let r = DriftReport {
            drifted: true,
            details: Vec::new(),
        };
        let msg = r.message_for_claude();
        assert!(msg.contains("regenerate"));
    }
}
