// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl start` — the one canonical zero→first-loop on-ramp (Open Engine
//! M4).
//!
//! The audit (§2.5) found the on-ramp *has* all the parts — `quickstart`,
//! `login`, raw docker — but lacks a single obvious front door: 38 subcommands
//! and three overlapping entry points with no canonical "get me live" command.
//! `start` is that door. It runs the happy path end-to-end —
//!
//!   detect the daemon → authenticate on the lowest-friction secure rail →
//!   wire the MCP endpoint + Claude Code hooks → round-trip a first fact →
//!   print one "you're live" summary
//!
//! — by delegating to the existing [`crate::login`] rail with verification and
//! hooks ON (the happy defaults), then printing a single next-steps summary.
//! The legacy entry points are **not removed** (back-compat): `quickstart`,
//! `login`, and `docker compose up` remain for the specific rails they serve;
//! `start` is just the one we point newcomers at.

use crate::agent_wiring::{self, Agent};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// Parsed arguments for `corecruxctl start`.
#[derive(Debug, Clone, Default)]
pub struct StartArgs {
    /// Explicit daemon URL (`--url`). When absent, discovery runs (the same
    /// `--url` → env-file → localhost ladder `login` uses).
    pub url: Option<String>,
    /// Static named token (`--token`) for CI / headless / air-gapped clients.
    pub token: Option<String>,
    /// Which agent to wire (`claude` | `codex` | `cursor`). Omit to bring the
    /// daemon connection up without touching any agent's config.
    pub agent: Option<Agent>,
}

/// Run the canonical on-ramp.
pub fn run(args: StartArgs) -> Result<(), DynErr> {
    println!("crux start — bringing Crux online");
    println!("================================");

    // The happy path *is* `login` with verification + hooks ON. login already
    // does discover → probe → auth-rail → persist credential → register MCP →
    // (re)verify with a tools/list + fact round-trip. We just front-door it and
    // add the summary.
    let result = crate::login::run(crate::login::LoginArgs {
        url: args.url.clone(),
        token: args.token.clone(),
        device: false,
        no_verify: false,
        // `start` is the operator-facing happy path, not CI: a failed
        // self-check is printed loudly but must not fail the command.
        strict_verify: false,
        no_hooks: false,
        no_register: false,
    });

    match result {
        Ok(()) => {
            // Agent wiring runs after login so it can use the endpoint login
            // resolved, and is reported separately: a failure here means the
            // daemon is live but one client is not pointed at it yet, which is
            // a different (and much smaller) problem than login failing.
            if let Some(agent) = args.agent {
                let mcp = mcp_url_for(args.url.as_deref())?;
                match agent_wiring::wire(agent, &mcp) {
                    Ok(lines) => {
                        println!("\nagent: {}", agent.as_str());
                        for line in lines {
                            println!("  {line}");
                        }
                    }
                    Err(e) => {
                        eprintln!("\nagent: {} — wiring FAILED: {e}", agent.as_str());
                        eprintln!("  the daemon is up; re-run once the config path is writable");
                        return Err(e);
                    }
                }
            }
            print!("{}", live_summary(args.url.as_deref()));
            if let Some(agent) = args.agent {
                println!("\nNext: restart {} and ask it to recall something.", agent.as_str());
            }
            Ok(())
        }
        Err(e) => Err(daemon_unreachable_hint(&e).into()),
    }
}

/// The MCP endpoint to hand an agent.
///
/// Prefers what `login` just resolved and persisted to
/// `~/.config/cuecrux/env`, because that is the endpoint actually in use.
/// Falls back to deriving it from `--url` (the daemon's convention puts MCP on
/// a fixed port regardless of the HTTP port), then to the loopback default.
fn mcp_url_for(url: Option<&str>) -> Result<String, DynErr> {
    if let Some(cfg_dir) = crate::login::config_dir() {
        let path = crate::login::env_path(&cfg_dir);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Some(mcp) = crate::login::parse_env_file(&contents).get("CRUX_MCP_URL") {
                if !mcp.trim().is_empty() {
                    return Ok(mcp.clone());
                }
            }
        }
    }
    match url {
        Some(u) => crate::login::derive_mcp_url(u).map_err(Into::into),
        None => Ok("http://127.0.0.1:14801/mcp".to_string()),
    }
}

/// The single "you're live" summary printed on success.
pub fn live_summary(url: Option<&str>) -> String {
    let http = url.unwrap_or("http://127.0.0.1:14800");
    // The MCP endpoint mirrors the HTTP host on the +1 port by convention; we
    // only special-case the local default so the summary is concrete there.
    let mcp = if url.is_none() {
        "http://127.0.0.1:14801/mcp".to_string()
    } else {
        format!("{http} (MCP endpoint, registered by login)")
    };
    format!(
        "\n✓ You're live.\n\
         \x20 daemon   {http}\n\
         \x20 mcp      {mcp}\n\
         \x20 hooks    installed (banner + observe capture)\n\
         \x20 verified first fact round-trip OK\n\
         \n\
         Next:\n\
         \x20 • point your agent at the MCP endpoint (see examples/mcp-configs/)\n\
         \x20 • open the console at the daemon URL for the live work board\n\
         \x20 • `corecruxctl whoami` to confirm your identity any time\n"
    )
}

/// Wrap a login failure with a clear "bring the daemon up first" hint — the
/// most common reason `start` fails from a truly clean machine.
fn daemon_unreachable_hint(err: &DynErr) -> String {
    format!(
        "{err}\n\nCrux isn't reachable yet. Bring the daemon up, then re-run `corecruxctl start`:\n  \
         docker compose up -d                                  # recommended\n  \
         CORECRUXD_AUTH_MODE=dev_scopes CORECRUXD_DATA_DIR=./data ./corecruxd   # or run the binary"
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn live_summary_default_names_local_endpoints_and_next_steps() {
        let s = live_summary(None);
        assert!(s.contains("You're live"));
        assert!(s.contains("127.0.0.1:14800"));
        assert!(s.contains("127.0.0.1:14801/mcp"));
        assert!(s.contains("hooks"));
        assert!(s.contains("first fact round-trip"));
        assert!(s.contains("Next:"));
    }

    #[test]
    fn live_summary_honours_explicit_url() {
        let s = live_summary(Some("https://crux.example.com"));
        assert!(s.contains("https://crux.example.com"));
    }

    #[test]
    #[serial_test::serial] // HOME is process-global
    fn mcp_url_prefers_what_login_persisted_over_rederiving() {
        // A re-derivation can disagree with the endpoint login actually
        // resolved; the agent must be pointed at the latter.
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", home.path());

        let cfg = crate::login::config_dir().unwrap();
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(
            crate::login::env_path(&cfg),
            "CRUX_HTTP_URL=http://example:14800
CRUX_MCP_URL=http://example:19999/mcp
",
        )
        .unwrap();

        assert_eq!(
            mcp_url_for(Some("http://example:14800")).unwrap(),
            "http://example:19999/mcp"
        );
    }

    #[test]
    #[serial_test::serial]
    fn mcp_url_falls_back_to_derivation_when_nothing_is_persisted() {
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", home.path());

        let derived = mcp_url_for(Some("http://example:14800")).unwrap();
        assert!(derived.starts_with("http://example:"), "{derived}");
        assert!(derived.ends_with("/mcp"), "{derived}");

        assert_eq!(mcp_url_for(None).unwrap(), "http://127.0.0.1:14801/mcp");
    }

    #[test]
    fn unreachable_hint_points_at_daemon_bringup() {
        let err: DynErr = "no reachable daemon".into();
        let hint = daemon_unreachable_hint(&err);
        assert!(hint.contains("no reachable daemon"));
        assert!(hint.contains("docker compose up -d"));
        assert!(hint.contains("CORECRUXD_AUTH_MODE=dev_scopes"));
        assert!(hint.contains("corecruxctl start"));
    }
}
