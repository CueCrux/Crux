// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Boot-time self-diagnostics for the Crux hook environment.
//!
//! [`crate::drift`] catches *file* drift (CLAUDE.md/AGENTS.md vs bundled
//! fragments). This module catches *environment* drift a stale or buggy hook
//! produces at session-start — the failure class where the daemon is healthy
//! but the boot banner silently loses content.
//!
//! Motivated by a real regression (2026-07): `session_start::sync_is_healthy`
//! substring-matched `"degraded"` against a `sync_status` payload that always
//! embeds `"degraded": false`, permanently suppressing the patterns playbook.
//! The daemon was healthy, the tests were green, and the banner had been a thin
//! stub for weeks — nothing surfaced it. That is exactly what this module exists
//! to make loud, plus the stale-hook version skew (a 0.3.x hook on a 0.5.x
//! daemon) that let the buggy binary persist unnoticed.
//!
//! Intentionally **pure**: the caller (the session-start hook) performs the
//! daemon I/O and feeds observations in; [`evaluate`] returns advisory warnings.
//! This keeps the policy unit-testable with no network and lets the same rules
//! back both the boot advisory and `crux-config-wizard check`.

/// What the session-start hook observed about the daemon/hook this boot.
#[derive(Debug, Clone)]
pub struct BootObservations<'a> {
    /// Version of the running `crux-hook` binary (`CARGO_PKG_VERSION`).
    pub hook_version: &'a str,
    /// Version the daemon reports (MCP `serverInfo.version`), if it was reachable.
    pub daemon_version: Option<&'a str>,
    /// Whether `sync_status` was reachable this boot.
    pub sync_reachable: bool,
    /// Whether the daemon reported `degraded: true`.
    pub sync_degraded: bool,
    /// Whether the substantive `bootstrap (patterns)` section actually rendered.
    pub bootstrap_loaded: bool,
}

/// Parse the `major.minor` of a semver-ish string, ignoring any pre-release or
/// build suffix. Returns `None` when it does not look like `N[.N]`.
fn major_minor(v: &str) -> Option<(u64, u64)> {
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let mut it = core.split('.');
    let major = it.next()?.trim().parse().ok()?;
    let minor = it.next().unwrap_or("0").trim().parse().ok()?;
    Some((major, minor))
}

/// Evaluate boot observations into advisory warnings. Empty ⇒ environment looks
/// healthy. Never errors; unparseable inputs simply yield no warning.
pub fn evaluate(obs: &BootObservations) -> Vec<String> {
    let mut warnings = Vec::new();

    // 1. Hook↔daemon version skew. A hook trailing the daemon by a minor version
    //    or more is the enabler for silent boot-contract drift (a 0.3.x hook
    //    against a 0.5.x daemon shipped a stale banner for weeks). Patch-level
    //    differences are expected and ignored.
    if let Some(dv) = obs.daemon_version {
        if let (Some(h), Some(d)) = (major_minor(obs.hook_version), major_minor(dv)) {
            if h != d {
                warnings.push(format!(
                    "hook/daemon version skew: crux-hook {hook} vs daemon {daemon}. \
                     A stale hook silently drifts from the daemon's boot contract — \
                     reinstall/regenerate crux-hook (via corecruxctl) to match the daemon.",
                    hook = obs.hook_version,
                    daemon = dv,
                ));
            }
        }
    }

    // 2. Silent banner degradation: the daemon is reachable and NOT degraded, yet
    //    the substantive patterns playbook failed to render. This is the exact
    //    signature of the sync_is_healthy false-positive — a healthy daemon behind
    //    an empty banner. Surface it rather than shipping a silent stub.
    if obs.sync_reachable && !obs.sync_degraded && !obs.bootstrap_loaded {
        warnings.push(
            "boot banner degraded: the daemon is healthy but the `bootstrap (patterns)` \
             playbook did not load. This usually means a hook regression is suppressing it \
             (e.g. an over-eager sync-health gate). Report it and reinstall crux-hook."
                .to_string(),
        );
    }

    warnings
}

/// Render the warnings as a Markdown boot-banner section, or `None` when clean.
/// Marked `**Crux self-check**` so it reads alongside the other banner sections.
pub fn render_section(warnings: &[String]) -> Option<String> {
    if warnings.is_empty() {
        return None;
    }
    let mut out = String::from("**Crux self-check**");
    for w in warnings {
        out.push_str("\n- ");
        out.push_str(w);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy<'a>() -> BootObservations<'a> {
        BootObservations {
            hook_version: "0.5.36",
            daemon_version: Some("0.5.36"),
            sync_reachable: true,
            sync_degraded: false,
            bootstrap_loaded: true,
        }
    }

    #[test]
    fn clean_environment_yields_no_warnings() {
        assert!(evaluate(&healthy()).is_empty());
        assert!(render_section(&[]).is_none());
    }

    #[test]
    fn patch_level_skew_is_ignored() {
        let obs = BootObservations {
            hook_version: "0.5.30",
            daemon_version: Some("0.5.36"),
            ..healthy()
        };
        assert!(evaluate(&obs).is_empty(), "patch differences must not warn");
    }

    #[test]
    fn minor_version_skew_warns() {
        // The real case: a 0.3.x hook against a 0.5.x daemon.
        let obs = BootObservations {
            hook_version: "0.3.1",
            daemon_version: Some("0.5.36"),
            ..healthy()
        };
        let w = evaluate(&obs);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("version skew"));
        assert!(w[0].contains("0.3.1") && w[0].contains("0.5.36"));
    }

    #[test]
    fn major_version_skew_warns() {
        let obs = BootObservations {
            hook_version: "0.5.36",
            daemon_version: Some("1.0.0"),
            ..healthy()
        };
        assert_eq!(evaluate(&obs).len(), 1);
    }

    #[test]
    fn unreachable_daemon_suppresses_skew_check() {
        // No daemon version ⇒ cannot compare ⇒ no skew warning (and no banner
        // check, since we did not observe the daemon healthy).
        let obs = BootObservations {
            hook_version: "0.3.1",
            daemon_version: None,
            sync_reachable: false,
            sync_degraded: false,
            bootstrap_loaded: false,
        };
        assert!(evaluate(&obs).is_empty());
    }

    #[test]
    fn healthy_daemon_without_bootstrap_warns() {
        // The regression signature: reachable, not degraded, but no playbook.
        let obs = BootObservations {
            bootstrap_loaded: false,
            ..healthy()
        };
        let w = evaluate(&obs);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("boot banner degraded"));
    }

    #[test]
    fn degraded_daemon_without_bootstrap_does_not_warn() {
        // A genuinely degraded daemon legitimately has no playbook — not our anomaly.
        let obs = BootObservations {
            sync_degraded: true,
            bootstrap_loaded: false,
            ..healthy()
        };
        assert!(evaluate(&obs).is_empty());
    }

    #[test]
    fn both_anomalies_stack() {
        let obs = BootObservations {
            hook_version: "0.3.1",
            daemon_version: Some("0.5.36"),
            sync_reachable: true,
            sync_degraded: false,
            bootstrap_loaded: false,
        };
        let w = evaluate(&obs);
        assert_eq!(w.len(), 2);
        let section = render_section(&w).expect("section");
        assert!(section.starts_with("**Crux self-check**"));
        assert_eq!(section.matches("\n- ").count(), 2);
    }

    #[test]
    fn nonsemver_versions_do_not_panic_or_warn() {
        let obs = BootObservations {
            hook_version: "dev",
            daemon_version: Some("unknown"),
            ..healthy()
        };
        assert!(evaluate(&obs).is_empty());
    }
}
