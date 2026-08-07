// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Per-agent wiring for `corecruxctl start --agent <claude|codex|cursor>`.
//!
//! `start` already brings the daemon connection up; what differs per agent is
//! only *where the client is told about it*. Claude Code was already
//! automated — [`crate::hooks`] merges `~/.claude/settings.json` and `login`
//! writes `~/.config/cuecrux/env` — so this module adds the two that were
//! still a README to follow by hand:
//!
//! * **Codex** — installs the stdio bridge and registers `[mcp_servers.crux]`
//!   in `~/.codex/config.toml`. Deliberately stdio, not the HTTP endpoint:
//!   Codex CLI failed the daemon's streamable-HTTP handshake both natively and
//!   through `mcp-remote` (see `integrations/codex-cli/README.md`), so the
//!   bridge is the supported path rather than a preference.
//! * **Cursor** — writes the `crux` server into `~/.cursor/mcp.json`, which
//!   does speak HTTP.
//!
//! Both writes are **merges, not overwrites**: these are the user's own config
//! files and may already describe other MCP servers. Both are idempotent, so
//! re-running `start` is safe.
//!
//! No bearer material is ever written into an agent config. The token lives in
//! `~/.config/cuecrux/env` (0600) and the bridge resolves it at runtime.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// The stdio bridge, embedded so a client that installed only the binary still
/// has it. Same reasoning as the Claude hook assets living in the wizard crate.
const CODEX_STDIO_BRIDGE: &str = include_str!("../../../integrations/codex-cli/crux-mcp-stdio.py");

/// Which agent `start --agent` should wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Codex,
    Cursor,
}

impl Agent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
        }
    }

    /// Parse the `--agent` value. Unknown names list the valid ones rather
    /// than failing with a bare "invalid value".
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "claude" | "claude-code" => Ok(Self::Claude),
            "codex" | "codex-cli" => Ok(Self::Codex),
            "cursor" => Ok(Self::Cursor),
            other => Err(format!(
                "unknown agent '{other}' (expected one of: claude, codex, cursor)"
            )),
        }
    }
}

fn home() -> Result<PathBuf, DynErr> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set; cannot locate the agent config directory".into())
}

// ── Cursor ────────────────────────────────────────────────────────────────

/// Merge `{"mcpServers": {"crux": {"url": ...}}}` into `~/.cursor/mcp.json`.
///
/// Pure so the merge semantics are testable without touching a real home
/// directory: other servers survive, and re-running replaces only `crux`.
pub fn merge_cursor_config(existing: &str, mcp_url: &str) -> Result<String, DynErr> {
    let mut root: serde_json::Value = if existing.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(existing)
            .map_err(|e| format!("~/.cursor/mcp.json is not valid JSON ({e}); leaving it alone"))?
    };

    if !root.is_object() {
        return Err("~/.cursor/mcp.json is not a JSON object; leaving it alone".into());
    }

    let servers = root
        .as_object_mut()
        .and_then(|o| {
            o.entry("mcpServers")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
        })
        .ok_or("~/.cursor/mcp.json has a non-object `mcpServers`; leaving it alone")?;

    servers.insert("crux".to_string(), serde_json::json!({ "url": mcp_url }));

    Ok(format!("{}\n", serde_json::to_string_pretty(&root)?))
}

fn wire_cursor(mcp_url: &str) -> Result<Vec<String>, DynErr> {
    let path = home()?.join(".cursor").join("mcp.json");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let merged = merge_cursor_config(&existing, mcp_url)?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, merged)?;

    Ok(vec![
        format!("wrote MCP server `crux` → {}", path.display()),
        format!("  url {mcp_url}"),
        "restart Cursor to pick up the new server".to_string(),
    ])
}

// ── Codex ─────────────────────────────────────────────────────────────────

/// Register `[mcp_servers.crux]` in a `~/.codex/config.toml` document.
///
/// Pure, for the same reason as the Cursor merge. Any other `mcp_servers`
/// entry and every unrelated key survive; re-running replaces only `crux`.
///
/// The command is the stdio bridge, not the HTTP endpoint — Codex CLI failed
/// the daemon's streamable-HTTP handshake, so this is the supported path.
pub fn merge_codex_config(existing: &str, bridge_path: &str) -> Result<String, DynErr> {
    let mut doc: toml::Table = if existing.trim().is_empty() {
        toml::Table::new()
    } else {
        existing
            .parse()
            .map_err(|e| format!("~/.codex/config.toml is not valid TOML ({e}); leaving it alone"))?
    };

    let servers = doc
        .entry("mcp_servers".to_string())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let servers = servers
        .as_table_mut()
        .ok_or("~/.codex/config.toml has a non-table `mcp_servers`; leaving it alone")?;

    let mut crux = toml::Table::new();
    crux.insert("command".to_string(), toml::Value::String("bash".to_string()));
    crux.insert(
        "args".to_string(),
        toml::Value::Array(vec![
            toml::Value::String("-lc".to_string()),
            toml::Value::String(format!("exec python3 \"{bridge_path}\"")),
        ]),
    );
    servers.insert("crux".to_string(), toml::Value::Table(crux));

    Ok(toml::to_string_pretty(&doc)?)
}

fn wire_codex() -> Result<Vec<String>, DynErr> {
    let codex_dir = home()?.join(".codex");
    std::fs::create_dir_all(&codex_dir)?;

    // 1. The stdio bridge, from the copy embedded in this binary.
    let bridge = codex_dir.join("crux-mcp-stdio.py");
    write_executable(&bridge, CODEX_STDIO_BRIDGE.as_bytes())?;

    // 2. The server entry, merged into whatever config.toml already says.
    let config = codex_dir.join("config.toml");
    let existing = std::fs::read_to_string(&config).unwrap_or_default();
    // `$HOME` rather than the expanded path: config.toml is often synced
    // between machines, and the bridge command is evaluated by bash anyway.
    let merged = merge_codex_config(&existing, "$HOME/.codex/crux-mcp-stdio.py")?;
    std::fs::write(&config, merged)?;

    Ok(vec![
        format!("installed stdio bridge → {}", bridge.display()),
        format!("registered MCP server `crux` → {}", config.display()),
        "  stdio, not HTTP: Codex CLI fails the daemon's streamable-HTTP handshake".to_string(),
        "restart Codex to pick up the new server".to_string(),
    ])
}

/// Write a file 0755 where the platform supports it.
fn write_executable(path: &Path, bytes: &[u8]) -> Result<(), DynErr> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

// ── Entry point ───────────────────────────────────────────────────────────

/// Wire one agent. Returns the lines `start` prints under "agent".
///
/// Claude returns nothing to add: `login` already installed its hooks and
/// registered the endpoint, so duplicating that work here would be the second
/// implementation this milestone is meant to avoid.
pub fn wire(agent: Agent, mcp_url: &str) -> Result<Vec<String>, DynErr> {
    match agent {
        Agent::Claude => Ok(vec![
            "Claude Code hooks + MCP endpoint wired by `login` (nothing further to do)".to_string(),
            "restart Claude Code to pick up the hooks".to_string(),
        ]),
        Agent::Codex => wire_codex(),
        Agent::Cursor => wire_cursor(mcp_url),
    }
}

/// The one command a new user runs, per agent — quoted verbatim in the READMEs
/// so the docs and the binary cannot drift apart.
pub fn one_liner(agent: Agent) -> String {
    format!("corecruxctl start --agent {}", agent.as_str())
}

/// Every agent, for `--agent` help text and the README table.
pub fn all() -> [Agent; 3] {
    [Agent::Claude, Agent::Codex, Agent::Cursor]
}

/// Where each agent's config lives, for the summary and the docs.
pub fn config_targets() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("claude", "~/.claude/settings.json + ~/.config/cuecrux/env"),
        ("codex", "~/.codex/config.toml + ~/.codex/crux-mcp-stdio.py"),
        ("cursor", "~/.cursor/mcp.json"),
    ])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_agent_and_its_alias() {
        assert_eq!(Agent::parse("claude").unwrap(), Agent::Claude);
        assert_eq!(Agent::parse("claude-code").unwrap(), Agent::Claude);
        assert_eq!(Agent::parse("CODEX").unwrap(), Agent::Codex);
        assert_eq!(Agent::parse("codex-cli").unwrap(), Agent::Codex);
        assert_eq!(Agent::parse(" cursor ").unwrap(), Agent::Cursor);
    }

    #[test]
    fn unknown_agent_lists_the_valid_ones() {
        let err = Agent::parse("copilot").unwrap_err();
        assert!(err.contains("copilot"));
        assert!(err.contains("claude"));
        assert!(err.contains("codex"));
        assert!(err.contains("cursor"));
    }

    // ── Cursor merge ──

    #[test]
    fn cursor_merge_creates_the_file_from_nothing() {
        let out = merge_cursor_config("", "http://127.0.0.1:14801/mcp").unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["mcpServers"]["crux"]["url"], "http://127.0.0.1:14801/mcp");
    }

    #[test]
    fn cursor_merge_preserves_other_servers_and_other_keys() {
        // The user's file is theirs; we add one key to one map.
        let existing = r#"{
          "mcpServers": { "other": { "url": "http://elsewhere/mcp" } },
          "someUnrelatedSetting": true
        }"#;
        let out = merge_cursor_config(existing, "http://127.0.0.1:14801/mcp").unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["mcpServers"]["other"]["url"], "http://elsewhere/mcp");
        assert_eq!(v["mcpServers"]["crux"]["url"], "http://127.0.0.1:14801/mcp");
        assert_eq!(v["someUnrelatedSetting"], serde_json::Value::Bool(true));
    }

    #[test]
    fn cursor_merge_is_idempotent_and_updates_the_url() {
        let once = merge_cursor_config("", "http://a:14801/mcp").unwrap();
        let twice = merge_cursor_config(&once, "http://a:14801/mcp").unwrap();
        assert_eq!(once, twice);

        let moved = merge_cursor_config(&twice, "http://b:14801/mcp").unwrap();
        let v: serde_json::Value = serde_json::from_str(&moved).unwrap();
        assert_eq!(v["mcpServers"]["crux"]["url"], "http://b:14801/mcp");
        assert_eq!(v["mcpServers"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn cursor_merge_refuses_to_touch_a_malformed_file() {
        // Better to fail loudly than to overwrite something we cannot parse.
        let err = merge_cursor_config("{ not json", "http://x/mcp")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not valid JSON"), "{err}");
        let err = merge_cursor_config("[1,2,3]", "http://x/mcp").unwrap_err().to_string();
        assert!(err.contains("not a JSON object"), "{err}");
    }

    // ── Codex merge ──

    #[test]
    fn codex_merge_registers_the_stdio_bridge() {
        let out = merge_codex_config("", "$HOME/.codex/crux-mcp-stdio.py").unwrap();
        let doc: toml::Table = out.parse().unwrap();
        let crux = doc["mcp_servers"]["crux"].as_table().unwrap();
        assert_eq!(crux["command"].as_str().unwrap(), "bash");
        let args: Vec<&str> = crux["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        assert_eq!(args[0], "-lc");
        assert!(args[1].contains("crux-mcp-stdio.py"), "{:?}", args);
        // Explicitly NOT a url server: Codex fails the HTTP handshake.
        assert!(crux.get("url").is_none());
    }

    #[test]
    fn codex_merge_preserves_other_servers_and_unrelated_tables() {
        let existing = r#"
model = "gpt-5"

[features]
hooks = true

[mcp_servers.other]
command = "other-bridge"
"#;
        let out = merge_codex_config(existing, "$HOME/.codex/crux-mcp-stdio.py").unwrap();
        let doc: toml::Table = out.parse().unwrap();
        assert_eq!(doc["model"].as_str().unwrap(), "gpt-5");
        assert!(doc["features"]["hooks"].as_bool().unwrap());
        assert_eq!(doc["mcp_servers"]["other"]["command"].as_str().unwrap(), "other-bridge");
        assert!(doc["mcp_servers"]["crux"].is_table());
    }

    #[test]
    fn codex_merge_is_idempotent() {
        let once = merge_codex_config("", "$HOME/.codex/crux-mcp-stdio.py").unwrap();
        let twice = merge_codex_config(&once, "$HOME/.codex/crux-mcp-stdio.py").unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn codex_merge_refuses_to_touch_a_malformed_file() {
        let err = merge_codex_config("[[[not toml", "x").unwrap_err().to_string();
        assert!(err.contains("not valid TOML"), "{err}");
    }

    #[test]
    fn no_agent_config_ever_carries_a_bearer_token() {
        // The token lives in ~/.config/cuecrux/env (0600); the bridge resolves
        // it at runtime. A config file is not a secret store.
        let cursor = merge_cursor_config("", "http://127.0.0.1:14801/mcp").unwrap();
        let codex = merge_codex_config("", "$HOME/.codex/crux-mcp-stdio.py").unwrap();
        for rendered in [&cursor, &codex] {
            let lower = rendered.to_ascii_lowercase();
            assert!(!lower.contains("token"), "agent config mentions a token: {rendered}");
            assert!(
                !lower.contains("authorization"),
                "agent config carries auth: {rendered}"
            );
        }
    }

    #[test]
    fn the_embedded_bridge_is_the_real_one() {
        // include_str! silently succeeding on an empty or wrong file would
        // ship a broken one-liner.
        assert!(CODEX_STDIO_BRIDGE.contains("mcp"), "embedded bridge looks wrong");
        assert!(CODEX_STDIO_BRIDGE.len() > 500, "embedded bridge is suspiciously small");
    }

    #[test]
    fn one_liner_matches_the_documented_command_for_every_agent() {
        for agent in all() {
            assert_eq!(
                one_liner(agent),
                format!("corecruxctl start --agent {}", agent.as_str())
            );
        }
        assert_eq!(config_targets().len(), all().len());
    }
}
