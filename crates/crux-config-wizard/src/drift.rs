// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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
    /// Advisory warnings (free-span duplication, oversize composed file) that
    /// `regenerate` cannot fix — surfaced separately from drift `details`, and
    /// they do NOT set `drifted`.
    pub warnings: Vec<String>,
}

impl DriftReport {
    pub fn drifted(&self) -> bool {
        self.drifted
    }

    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Render for the boot advisory / `check` output. Two distinct blocks with
    /// distinct remediation: drift `details` → run `regenerate`; advisory
    /// `warnings` → `regenerate` will NOT fix these, edit the free spans.
    pub fn message_for_claude(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        if self.drifted {
            out.push_str("[crux-config-wizard] CLAUDE.md or AGENTS.md is out of date.\n");
            if self.details.is_empty() {
                out.push_str("Run `crux-config-wizard regenerate` to refresh.");
            } else {
                out.push_str(&self.details.join("\n"));
                out.push_str("\n\nRun `crux-config-wizard regenerate` to refresh.");
            }
        }
        if !self.warnings.is_empty() {
            if !out.is_empty() {
                out.push_str("\n\n");
            }
            write!(
                out,
                "[crux-config-wizard] advisory ({} item(s)) — `regenerate` will NOT fix these; edit the free spans:\n{}",
                self.warnings.len(),
                self.warnings.join("\n")
            )
            .expect("write to String cannot fail");
        }
        out
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
                warnings: Vec::new(),
            });
        }
    };
    let bundled = match load_bundled_profiles() {
        Ok(b) => b,
        Err(e) => {
            return Ok(DriftReport {
                drifted: true,
                details: vec![format!("failed to load bundled profiles: {e}")],
                warnings: Vec::new(),
            });
        }
    };

    let enabled: Vec<_> = bundled
        .into_iter()
        .filter(|f| cfg.profiles.contains_key(&f.frontmatter.name))
        .collect();

    let mut details = Vec::new();
    let mut warnings = Vec::new();

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
            Ok(r) => {
                if r.wrote {
                    details.push(format!(
                        "{} would be rewritten (updated={}, added={})",
                        target.filename(),
                        r.managed_sections_updated,
                        r.managed_sections_added
                    ));
                }
                // Advisory (not drift): free-span text restating a managed profile.
                for ov in &r.free_span_overlaps {
                    warnings.push(format!(
                        "{}: free-span text restates managed profile '{}' ({}/{} distinctive lines duplicated, e.g. \"{}\"). Replace the duplicated prose with a pointer to the managed section — `regenerate` cannot fix this.",
                        target.filename(),
                        ov.profile,
                        ov.matched_lines,
                        ov.distinctive_lines,
                        ov.sample
                    ));
                }
                // Advisory (not drift): composed file over its soft size budget.
                let max = match target {
                    Target::ClaudeMd => cfg.limits.claude_md_max_bytes,
                    Target::AgentsMd => cfg.limits.agents_md_max_bytes,
                };
                if r.composed_bytes > max {
                    warnings.push(format!(
                        "{} is {} B (soft budget {} B); free-span text is {} B of that. Trim free spans or split content — a large file inflates every session prefix and risks the boot load cap.",
                        target.filename(),
                        r.composed_bytes,
                        max,
                        r.free_span_bytes
                    ));
                }
            }
            Err(crate::compose::ComposeError::Drift { profile, .. }) => details.push(format!(
                "{} has manual edits inside managed section '{}'",
                target.filename(),
                profile
            )),
            Err(e) => details.push(format!("{} check failed: {e}", target.filename())),
        }
    }

    let drifted = !details.is_empty();
    Ok(DriftReport {
        drifted,
        details,
        warnings,
    })
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
            warnings: Vec::new(),
        };
        assert!(r.message_for_claude().is_empty());
    }

    #[test]
    fn drift_report_message_with_details() {
        let r = DriftReport {
            drifted: true,
            details: vec!["profile 'x' is at v1 in config but v2 in the crate".into()],
            warnings: Vec::new(),
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
            warnings: Vec::new(),
        };
        let msg = r.message_for_claude();
        assert!(msg.contains("regenerate"));
    }

    #[test]
    fn oversize_composed_file_warns_but_is_not_drift() {
        let dir = TempDir::new().unwrap();
        let bundled = load_bundled_profiles().unwrap();
        let mp = bundled
            .iter()
            .find(|f| f.frontmatter.name == "memory-practices")
            .expect("memory-practices bundled");
        let mut cfg = AgentProfileConfig::new("blake3:test".into());
        cfg.enable("memory-practices", mp.frontmatter.version);
        cfg.limits.claude_md_max_bytes = 10; // force over-budget
        cfg.limits.agents_md_max_bytes = 10_000_000; // avoid an AGENTS.md warning
        cfg.save(dir.path()).unwrap();

        let enabled: Vec<_> = bundled
            .into_iter()
            .filter(|f| cfg.profiles.contains_key(&f.frontmatter.name))
            .collect();
        for t in [Target::ClaudeMd, Target::AgentsMd] {
            compose_file(dir.path(), t, &enabled, false, false).unwrap();
        }

        let r = check_workspace(dir.path()).unwrap();
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("CLAUDE.md") && w.contains("soft budget")),
            "expected size warning, got: {:?}",
            r.warnings
        );
        assert!(!r.drifted(), "over-budget is a warning, not drift: {:?}", r.details);
    }

    #[test]
    fn warnings_only_message_is_advisory_not_drift() {
        let r = DriftReport {
            drifted: false,
            details: Vec::new(),
            warnings: vec!["CLAUDE.md: free-span text restates managed profile 'x'".into()],
        };
        assert!(!r.drifted());
        assert!(r.has_warnings());
        let msg = r.message_for_claude();
        assert!(msg.contains("advisory"), "msg: {msg}");
        assert!(msg.contains("free-span"));
        assert!(!msg.contains("out of date"));
    }
}
