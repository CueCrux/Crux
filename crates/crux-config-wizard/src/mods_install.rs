// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Claude Code mod installation: the `crux-desktop` function-hook plugin.
//!
//! A mod is a plugin folder (`.claude-plugin/plugin.json` + a hooks module)
//! that Claude Code loads from every folder listed in `CLAUDE_CODE_PLUGIN_DIRS`,
//! read from the `env` block of the user's `settings.json`. Installing it means
//! three writes:
//!
//! 1. the mod's files into `~/.claude/mods/crux-desktop/` (embedded here, so a
//!    client needs no checkout);
//! 2. `settings.json`: the folder appended to `CLAUDE_CODE_PLUGIN_DIRS`, and the
//!    mod's `server` option under `pluginConfigs` naming the MCP server it uses;
//! 3. `~/.claude.json`: a user-scope MCP server for the daemon, when none of
//!    that name exists, because the mod reaches the daemon only through MCP.
//!
//! With the mod installed it owns session continuity (the context block on the
//! first prompt, and `save_session` after every turn, before compaction and at
//! session end). The classic SessionStart banner and PreCompact save hooks then
//! step aside: [`crate::hooks_install::install`] checks [`is_installed`] and
//! leaves them out, and installing or removing the mod re-converges any Crux
//! hooks already wired in the user settings.

use std::path::{Path, PathBuf};

use crate::paths;

/// Boxed error type for the install path.
pub type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// The plugin's `name`; also its folder name and its `pluginConfigs` key.
pub const MOD_NAME: &str = "crux-desktop";

/// The MCP server name the installer registers and points the mod at.
pub const DEFAULT_MCP_SERVER: &str = "crux";

/// The loopback daemon's MCP endpoint.
pub const DEFAULT_MCP_URL: &str = "http://127.0.0.1:14801/mcp";

/// The settings `env` key Claude Code reads plugin folders from.
const PLUGIN_DIRS_ENV: &str = "CLAUDE_CODE_PLUGIN_DIRS";

/// The mod's files, relative to its folder. `.claude-plugin/types/` and
/// `tsconfig.json` are editor scaffolding `/plugin-types` writes on demand, so
/// they are not shipped.
const FILES: &[(&str, &str)] = &[
    (
        ".claude-plugin/plugin.json",
        include_str!("../assets/mods/crux-desktop/.claude-plugin/plugin.json"),
    ),
    (
        "hooks/hooks.json",
        include_str!("../assets/mods/crux-desktop/hooks/hooks.json"),
    ),
    (
        "hooks/register.tsx",
        include_str!("../assets/mods/crux-desktop/hooks/register.tsx"),
    ),
    (
        "types/index.d.ts",
        include_str!("../assets/mods/crux-desktop/types/index.d.ts"),
    ),
];

/// Where each install target lives. Built from the environment in normal use
/// and from a tempdir in tests.
#[derive(Debug, Clone)]
pub struct ModPaths {
    /// `~/.claude/mods/crux-desktop`.
    pub mod_dir: PathBuf,
    /// `~/.claude/settings.json`.
    pub settings: PathBuf,
    /// `~/.claude.json`.
    pub claude_json: PathBuf,
}

impl ModPaths {
    /// The real locations, honouring `CLAUDE_CONFIG_DIR`.
    ///
    /// # Errors
    /// When no home directory can be resolved.
    pub fn resolve() -> Result<Self, DynErr> {
        let config = paths::claude_config_dir()?;
        Ok(Self {
            mod_dir: config.join("mods").join(MOD_NAME),
            settings: config.join("settings.json"),
            claude_json: paths::claude_json_path()?,
        })
    }

    /// The layout under a given home directory (no `CLAUDE_CONFIG_DIR`).
    #[must_use]
    pub fn under_home(home: &Path) -> Self {
        let config = home.join(".claude");
        Self {
            mod_dir: config.join("mods").join(MOD_NAME),
            settings: config.join("settings.json"),
            claude_json: home.join(".claude.json"),
        }
    }
}

/// What to install beyond the mod's files.
#[derive(Debug, Clone, Default)]
pub struct ModOptions {
    /// The MCP server the mod uses. `None` keeps an existing setting, or
    /// writes [`DEFAULT_MCP_SERVER`] when there is none.
    pub server: Option<String>,
    /// The daemon MCP endpoint to register. `None` means [`DEFAULT_MCP_URL`].
    pub mcp_url: Option<String>,
    /// Bearer token for that endpoint, written as an `Authorization` header.
    /// `None` registers it without one (a loopback daemon with auth off).
    pub mcp_token: Option<String>,
    /// Skip the `~/.claude.json` MCP registration.
    pub skip_mcp: bool,
}

impl ModOptions {
    /// Fill an unset endpoint and token from what `corecruxctl login` saved:
    /// `CRUX_MCP_URL` / `CRUX_AGENT_TOKEN` in `~/.config/cuecrux/env`, with the
    /// registered MCP token file taking precedence, as the hook launcher does.
    #[must_use]
    pub fn with_saved_endpoint(mut self) -> Self {
        let Ok(home) = paths::home_dir() else {
            return self;
        };
        let cfg = home.join(".config").join("cuecrux");
        let env = std::fs::read_to_string(cfg.join("env")).unwrap_or_default();
        let get = |key: &str| {
            env.lines().find_map(|l| {
                let l = l.trim().strip_prefix("export ").unwrap_or(l.trim());
                let v = l.strip_prefix(key)?.strip_prefix('=')?;
                Some(v.trim().trim_matches(['"', '\'']).to_string()).filter(|v| !v.is_empty())
            })
        };
        if self.mcp_url.is_none() {
            self.mcp_url = get("CRUX_MCP_URL");
        }
        if self.mcp_token.is_none() {
            self.mcp_token = std::fs::read_to_string(cfg.join("crux-tokens").join("anthropic.mcp-token"))
                .ok()
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .or_else(|| get("CRUX_AGENT_TOKEN"));
        }
        self
    }
}

/// How the MCP registration went.
#[derive(Debug, Clone, PartialEq, Eq)]
enum McpOutcome {
    Added,
    Updated,
    Unchanged,
    /// A server of that name exists and points somewhere else; left alone.
    KeptOther(String),
    Skipped,
}

/// Install the mod. See the module docs for what is written.
///
/// # Errors
/// On an unresolvable home directory, an unwritable target, or a settings file
/// that is not a JSON object.
pub fn install(opts: &ModOptions) -> Result<String, DynErr> {
    let paths = ModPaths::resolve()?;
    let mut summary = install_at(&paths, opts)?;
    // The mod now owns continuity: rebuild the classic hooks without their
    // banner and PreCompact save, so nothing is injected or saved twice.
    rewire_classic_hooks(&paths, &mut summary, "banner + PreCompact save now handled by the mod");
    Ok(summary)
}

/// Re-run the classic hooks install when Crux hooks are already wired in the
/// user settings, so it re-reads who owns continuity. Never fails the caller.
fn rewire_classic_hooks(paths: &ModPaths, summary: &mut String, done: &str) {
    use std::fmt::Write as _;
    if !crate::hooks_install::crux_hooks_wired(&paths.settings) {
        return;
    }
    let _ = match crate::hooks_install::install(true, None) {
        Ok(_) => write!(summary, "\n  classic hooks re-wired: {done}"),
        Err(e) => write!(
            summary,
            "\n  warning: could not re-wire the classic hooks ({e}); run `corecruxctl hooks install --user`"
        ),
    };
}

/// [`install`] against explicit paths, without touching the classic hooks.
///
/// # Errors
/// As [`install`].
pub fn install_at(paths: &ModPaths, opts: &ModOptions) -> Result<String, DynErr> {
    use std::fmt::Write as _;
    let changed = write_files(&paths.mod_dir)?;
    let server = update_json(&paths.settings, |root| {
        merge_settings(root, &paths.mod_dir, opts.server.as_deref())
    })?;

    let mcp = if opts.skip_mcp {
        McpOutcome::Skipped
    } else {
        let url = opts.mcp_url.as_deref().unwrap_or(DEFAULT_MCP_URL);
        update_json(&paths.claude_json, |root| {
            Ok(register_mcp(root, &server, url, opts.mcp_token.as_deref()))
        })?
    };

    let mut out = format!(
        "mod {MOD_NAME} installed → {} ({})",
        paths.mod_dir.display(),
        if changed == 0 {
            "already current".to_string()
        } else {
            format!("{changed} file(s) written")
        }
    );
    let _ = write!(
        out,
        "\n  {PLUGIN_DIRS_ENV} → {}\n  mod uses MCP server \"{server}\"",
        paths.settings.display()
    );
    let _ = match mcp {
        McpOutcome::Added => write!(
            out,
            "\n  MCP server \"{server}\" registered (user scope) → {}",
            paths.claude_json.display()
        ),
        McpOutcome::Updated => write!(out, "\n  MCP server \"{server}\" credentials refreshed"),
        McpOutcome::Unchanged => write!(out, "\n  MCP server \"{server}\" already registered"),
        McpOutcome::KeptOther(url) => write!(
            out,
            "\n  note: an MCP server \"{server}\" already points at {url}; left as-is. \
             Re-run with --server <name> to register the local daemon under another name."
        ),
        McpOutcome::Skipped => write!(out, "\n  MCP registration skipped"),
    };
    for (dir, url) in project_shadows(&paths.claude_json, &server) {
        let _ = write!(
            out,
            "\n  note: project {dir} defines its own \"{server}\" server ({url}); there the mod talks to that one"
        );
    }
    out.push_str("\n  restart Claude Code (new session) to load the mod");
    Ok(out)
}

/// Remove the mod: its folder, its `CLAUDE_CODE_PLUGIN_DIRS` entry and its
/// `pluginConfigs` entry. The MCP server registration is kept (other tools may
/// use it). Classic hooks already wired get their banner and PreCompact save
/// back.
///
/// # Errors
/// On an unresolvable home directory or an unwritable target.
pub fn uninstall() -> Result<String, DynErr> {
    let paths = ModPaths::resolve()?;
    let mut summary = uninstall_at(&paths)?;
    rewire_classic_hooks(&paths, &mut summary, "banner + PreCompact save restored");
    Ok(summary)
}

/// [`uninstall`] against explicit paths, without touching the classic hooks.
///
/// # Errors
/// As [`uninstall`].
pub fn uninstall_at(paths: &ModPaths) -> Result<String, DynErr> {
    let existed = paths.mod_dir.exists();
    if existed {
        std::fs::remove_dir_all(&paths.mod_dir)?;
    }
    if paths.settings.exists() {
        update_json(&paths.settings, |root| {
            unmerge_settings(root, &paths.mod_dir);
            Ok(())
        })?;
    }
    Ok(if existed {
        format!("mod {MOD_NAME} removed from {}", paths.mod_dir.display())
    } else {
        format!("mod {MOD_NAME} was not installed; settings cleaned")
    })
}

/// Is the mod installed and on Claude Code's plugin path? The classic hooks
/// installer asks this to decide who owns continuity.
#[must_use]
pub fn is_installed() -> bool {
    ModPaths::resolve().is_ok_and(|p| is_installed_at(&p))
}

/// [`is_installed`] against explicit paths.
#[must_use]
pub fn is_installed_at(paths: &ModPaths) -> bool {
    paths.mod_dir.join(".claude-plugin").join("plugin.json").is_file()
        && read_json(&paths.settings).is_some_and(|root| plugin_dirs(&root).iter().any(|d| same_dir(d, &paths.mod_dir)))
}

/// A read-only report: files current or stale, plugin path, server option, MCP
/// registration.
///
/// # Errors
/// On an unresolvable home directory.
pub fn status() -> Result<String, DynErr> {
    Ok(status_at(&ModPaths::resolve()?))
}

/// [`status`] against explicit paths.
#[must_use]
pub fn status_at(paths: &ModPaths) -> String {
    use std::fmt::Write as _;
    let mut out = format!("mod {MOD_NAME}: {}\n", paths.mod_dir.display());
    for (rel, want) in FILES {
        let state = match std::fs::read_to_string(paths.mod_dir.join(rel)) {
            Ok(got) if got == *want => "current",
            Ok(_) => "STALE (re-run `mods install`)",
            Err(_) => "missing",
        };
        let _ = writeln!(out, "  {rel:<28} {state}");
    }
    let settings = read_json(&paths.settings);
    let on_path = settings
        .as_ref()
        .is_some_and(|root| plugin_dirs(root).iter().any(|d| same_dir(d, &paths.mod_dir)));
    let _ = writeln!(
        out,
        "  {PLUGIN_DIRS_ENV:<28} {}",
        if on_path { "includes the mod" } else { "MISSING the mod" }
    );
    let server = settings.as_ref().and_then(configured_server).unwrap_or_default();
    let _ = writeln!(
        out,
        "  server option                {}",
        if server.is_empty() {
            "(unset: tries \"crux\", then \"Crux Daemon\")".to_string()
        } else {
            format!("\"{server}\"")
        }
    );
    let name = if server.is_empty() { DEFAULT_MCP_SERVER } else { &server };
    let registered = read_json(&paths.claude_json).and_then(|root| {
        root.get("mcpServers")?
            .get(name)?
            .get("url")?
            .as_str()
            .map(str::to_owned)
    });
    let _ = write!(
        out,
        "  MCP server \"{name}\"{}{}",
        " ".repeat(16usize.saturating_sub(name.len())),
        registered.map_or("not registered at user scope".to_string(), |u| format!("→ {u}"))
    );
    out
}

// ── internals ───────────────────────────────────────────────────────────────

/// Write the embedded files, skipping any already byte-identical. Returns how
/// many were written.
fn write_files(dir: &Path) -> Result<usize, DynErr> {
    let mut written = 0;
    for (rel, body) in FILES {
        let path = dir.join(rel);
        if std::fs::read_to_string(&path).is_ok_and(|s| s == *body) {
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, body)?;
        written += 1;
    }
    Ok(written)
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    let s = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&s).ok()
}

/// Read-modify-write a JSON object file: absent or empty starts as `{}`, the
/// write is skipped when nothing changed, a changed file keeps a `.bak`, and
/// the new contents land by rename so a reader never sees half a file.
fn update_json<T>(path: &Path, edit: impl FnOnce(&mut serde_json::Value) -> Result<T, DynErr>) -> Result<T, DynErr> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut root: serde_json::Value = if existing.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(&existing).map_err(|e| format!("{}: {e}", path.display()))?
    };
    if !root.is_object() {
        return Err(format!("{} is not a JSON object", path.display()).into());
    }
    let out = edit(&mut root)?;
    let new_text = serde_json::to_string_pretty(&root)? + "\n";
    if existing.trim().is_empty() || serde_json::from_str::<serde_json::Value>(&existing).ok().as_ref() != Some(&root) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !existing.trim().is_empty() {
            std::fs::write(format!("{}.bak", path.display()), existing.as_bytes())?;
        }
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        std::fs::write(&tmp, &new_text)?;
        std::fs::rename(&tmp, path)?;
    }
    Ok(out)
}

/// The folders in `env.CLAUDE_CODE_PLUGIN_DIRS`, in order.
fn plugin_dirs(root: &serde_json::Value) -> Vec<PathBuf> {
    root.get("env")
        .and_then(|e| e.get(PLUGIN_DIRS_ENV))
        .and_then(serde_json::Value::as_str)
        .map(|s| std::env::split_paths(s).filter(|p| !p.as_os_str().is_empty()).collect())
        .unwrap_or_default()
}

/// Path equality as the OS sees it: trailing separators ignored, and case
/// ignored on Windows.
fn same_dir(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| {
        let s = p.display().to_string();
        let s = s.trim_end_matches(['/', '\\']).to_string();
        if cfg!(windows) {
            s.replace('/', "\\").to_lowercase()
        } else {
            s
        }
    };
    norm(a) == norm(b)
}

fn set_plugin_dirs(root: &mut serde_json::Value, dirs: &[PathBuf]) -> Result<(), DynErr> {
    if dirs.is_empty() {
        if let Some(env) = root.get_mut("env").and_then(serde_json::Value::as_object_mut) {
            env.remove(PLUGIN_DIRS_ENV);
            if env.is_empty() {
                root.as_object_mut().map(|o| o.remove("env"));
            }
        }
        return Ok(());
    }
    let joined = std::env::join_paths(dirs).map_err(|e| format!("cannot join plugin dirs: {e}"))?;
    if !root.get("env").is_some_and(serde_json::Value::is_object) {
        root["env"] = serde_json::json!({});
    }
    root["env"][PLUGIN_DIRS_ENV] = serde_json::Value::String(joined.to_string_lossy().into_owned());
    Ok(())
}

fn configured_server(root: &serde_json::Value) -> Option<String> {
    root.get("pluginConfigs")?
        .get(MOD_NAME)?
        .get("options")?
        .get("server")?
        .as_str()
        .map(str::to_owned)
}

/// Add the mod's folder to the plugin path and settle its `server` option.
/// Returns the server name the mod will use.
fn merge_settings(root: &mut serde_json::Value, mod_dir: &Path, server: Option<&str>) -> Result<String, DynErr> {
    let mut dirs = plugin_dirs(root);
    if !dirs.iter().any(|d| same_dir(d, mod_dir)) {
        dirs.push(mod_dir.to_path_buf());
        set_plugin_dirs(root, &dirs)?;
    }
    let server = match server.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => configured_server(root)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_MCP_SERVER.to_string()),
    };
    if !root.get("pluginConfigs").is_some_and(serde_json::Value::is_object) {
        root["pluginConfigs"] = serde_json::json!({});
    }
    if !root["pluginConfigs"]
        .get(MOD_NAME)
        .is_some_and(serde_json::Value::is_object)
    {
        root["pluginConfigs"][MOD_NAME] = serde_json::json!({});
    }
    if !root["pluginConfigs"][MOD_NAME]
        .get("options")
        .is_some_and(serde_json::Value::is_object)
    {
        root["pluginConfigs"][MOD_NAME]["options"] = serde_json::json!({});
    }
    root["pluginConfigs"][MOD_NAME]["options"]["server"] = serde_json::Value::String(server.clone());
    Ok(server)
}

fn unmerge_settings(root: &mut serde_json::Value, mod_dir: &Path) {
    let dirs: Vec<PathBuf> = plugin_dirs(root)
        .into_iter()
        .filter(|d| !same_dir(d, mod_dir))
        .collect();
    // Joining paths that came from splitting the same value cannot fail.
    let _ = set_plugin_dirs(root, &dirs);
    if let Some(configs) = root.get_mut("pluginConfigs").and_then(serde_json::Value::as_object_mut) {
        configs.remove(MOD_NAME);
        if configs.is_empty() {
            root.as_object_mut().map(|o| o.remove("pluginConfigs"));
        }
    }
}

/// Register (or refresh) the user-scope MCP server `name`. An existing entry
/// with a different URL belongs to someone else and is left alone.
fn register_mcp(root: &mut serde_json::Value, name: &str, url: &str, token: Option<&str>) -> McpOutcome {
    if !root.get("mcpServers").is_some_and(serde_json::Value::is_object) {
        root["mcpServers"] = serde_json::json!({});
    }
    let mut want = serde_json::json!({ "type": "http", "url": url });
    if let Some(t) = token.map(str::trim).filter(|t| !t.is_empty()) {
        want["headers"] = serde_json::json!({ "Authorization": format!("Bearer {t}") });
    }
    match root["mcpServers"].get(name) {
        None => {
            root["mcpServers"][name] = want;
            McpOutcome::Added
        }
        Some(existing) => {
            let existing_url = existing.get("url").and_then(serde_json::Value::as_str).unwrap_or("");
            if existing_url.trim_end_matches('/') != url.trim_end_matches('/') {
                return McpOutcome::KeptOther(if existing_url.is_empty() {
                    "a non-HTTP command".to_string()
                } else {
                    existing_url.to_string()
                });
            }
            if want.get("headers").is_some() && existing.get("headers") != want.get("headers") {
                root["mcpServers"][name]["headers"] = want["headers"].clone();
                McpOutcome::Updated
            } else {
                McpOutcome::Unchanged
            }
        }
    }
}

/// Projects in `~/.claude.json` that define their own server named `name`
/// (project scope wins over user scope there), with that server's URL.
fn project_shadows(claude_json: &Path, name: &str) -> Vec<(String, String)> {
    let Some(root) = read_json(claude_json) else {
        return Vec::new();
    };
    let user_url = root
        .get("mcpServers")
        .and_then(|s| s.get(name))
        .and_then(|s| s.get("url"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    root.get("projects")
        .and_then(serde_json::Value::as_object)
        .map(|projects| {
            projects
                .iter()
                .filter_map(|(dir, p)| {
                    let url = p.get("mcpServers")?.get(name)?.get("url")?.as_str()?;
                    (url != user_url).then(|| (dir.clone(), url.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> ModOptions {
        ModOptions::default()
    }

    fn json(path: &Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn embedded_mod_is_a_loadable_plugin() {
        let manifest: serde_json::Value = serde_json::from_str(FILES[0].1).unwrap();
        assert_eq!(
            manifest["name"], MOD_NAME,
            "folder, manifest and pluginConfigs key must agree"
        );
        assert!(
            manifest["userConfig"]["server"].is_object(),
            "the installer writes this option"
        );
        let hooks: serde_json::Value = serde_json::from_str(FILES[1].1).unwrap();
        assert_eq!(hooks["modules"][0], "./register.tsx");
        assert!(
            FILES[2].1.contains("options.server"),
            "the module reads the server option"
        );
    }

    #[test]
    fn install_writes_files_settings_and_mcp_server() {
        let home = tempfile::tempdir().unwrap();
        let p = ModPaths::under_home(home.path());
        std::fs::create_dir_all(p.settings.parent().unwrap()).unwrap();
        std::fs::write(&p.settings, r#"{"permissions":{"allow":["x"]}}"#).unwrap();

        let out = install_at(&p, &opts()).unwrap();
        assert!(out.contains("4 file(s) written"), "{out}");
        for (rel, body) in FILES {
            assert_eq!(std::fs::read_to_string(p.mod_dir.join(rel)).unwrap(), *body);
        }
        let s = json(&p.settings);
        assert_eq!(s["permissions"]["allow"][0], "x", "foreign keys preserved");
        assert_eq!(plugin_dirs(&s), vec![p.mod_dir.clone()]);
        assert_eq!(s["pluginConfigs"][MOD_NAME]["options"]["server"], DEFAULT_MCP_SERVER);
        let c = json(&p.claude_json);
        assert_eq!(c["mcpServers"]["crux"]["url"], DEFAULT_MCP_URL);
        assert_eq!(c["mcpServers"]["crux"]["type"], "http");
        assert!(c["mcpServers"]["crux"].get("headers").is_none(), "no token, no header");
        assert!(is_installed_at(&p));
    }

    #[test]
    fn install_is_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let p = ModPaths::under_home(home.path());
        install_at(&p, &opts()).unwrap();
        let settings1 = std::fs::read_to_string(&p.settings).unwrap();
        let claude1 = std::fs::read_to_string(&p.claude_json).unwrap();
        let out = install_at(&p, &opts()).unwrap();
        assert!(out.contains("already current"), "{out}");
        assert!(out.contains("already registered"), "{out}");
        assert_eq!(settings1, std::fs::read_to_string(&p.settings).unwrap());
        assert_eq!(claude1, std::fs::read_to_string(&p.claude_json).unwrap());
        assert!(
            !p.settings.with_file_name("settings.json.bak").exists(),
            "a no-op re-run writes nothing"
        );
    }

    #[test]
    fn install_appends_to_existing_plugin_dirs() {
        let home = tempfile::tempdir().unwrap();
        let p = ModPaths::under_home(home.path());
        let other = home.path().join("other-mod");
        std::fs::create_dir_all(p.settings.parent().unwrap()).unwrap();
        let mut root = serde_json::json!({});
        set_plugin_dirs(&mut root, std::slice::from_ref(&other)).unwrap();
        std::fs::write(&p.settings, root.to_string()).unwrap();

        install_at(&p, &opts()).unwrap();
        assert_eq!(plugin_dirs(&json(&p.settings)), vec![other.clone(), p.mod_dir.clone()]);

        uninstall_at(&p).unwrap();
        let s = json(&p.settings);
        assert_eq!(plugin_dirs(&s), vec![other], "only our folder is removed");
        assert!(s.get("pluginConfigs").is_none(), "our config entry is removed");
        assert!(!p.mod_dir.exists());
        assert!(!is_installed_at(&p));
    }

    #[test]
    fn uninstall_drops_empty_env_block() {
        let home = tempfile::tempdir().unwrap();
        let p = ModPaths::under_home(home.path());
        install_at(&p, &opts()).unwrap();
        uninstall_at(&p).unwrap();
        assert!(json(&p.settings).get("env").is_none());
    }

    #[test]
    fn explicit_server_wins_and_is_kept_on_rerun() {
        let home = tempfile::tempdir().unwrap();
        let p = ModPaths::under_home(home.path());
        let named = ModOptions {
            server: Some("crux-local".into()),
            ..opts()
        };
        install_at(&p, &named).unwrap();
        install_at(&p, &opts()).unwrap();
        assert_eq!(
            json(&p.settings)["pluginConfigs"][MOD_NAME]["options"]["server"],
            "crux-local"
        );
        assert_eq!(json(&p.claude_json)["mcpServers"]["crux-local"]["url"], DEFAULT_MCP_URL);
    }

    #[test]
    fn foreign_server_of_the_same_name_is_left_alone() {
        let home = tempfile::tempdir().unwrap();
        let p = ModPaths::under_home(home.path());
        std::fs::write(
            &p.claude_json,
            r#"{"mcpServers":{"crux":{"type":"http","url":"https://crux.example.com/mcp"}}}"#,
        )
        .unwrap();
        let out = install_at(&p, &opts()).unwrap();
        assert!(out.contains("already points at https://crux.example.com/mcp"), "{out}");
        assert_eq!(
            json(&p.claude_json)["mcpServers"]["crux"]["url"],
            "https://crux.example.com/mcp"
        );
    }

    #[test]
    fn token_becomes_an_authorization_header_and_refreshes() {
        let home = tempfile::tempdir().unwrap();
        let p = ModPaths::under_home(home.path());
        let with = |t: &str| ModOptions {
            mcp_token: Some(t.into()),
            ..opts()
        };
        install_at(&p, &with("one")).unwrap();
        assert_eq!(
            json(&p.claude_json)["mcpServers"]["crux"]["headers"]["Authorization"],
            "Bearer one"
        );
        let out = install_at(&p, &with("two")).unwrap();
        assert!(out.contains("credentials refreshed"), "{out}");
        assert_eq!(
            json(&p.claude_json)["mcpServers"]["crux"]["headers"]["Authorization"],
            "Bearer two"
        );
    }

    #[test]
    fn project_scoped_server_is_reported_as_a_shadow() {
        let home = tempfile::tempdir().unwrap();
        let p = ModPaths::under_home(home.path());
        std::fs::write(
            &p.claude_json,
            r#"{"projects":{"/work/x":{"mcpServers":{"crux":{"type":"http","url":"https://hosted/mcp"}}}}}"#,
        )
        .unwrap();
        let out = install_at(&p, &opts()).unwrap();
        assert!(out.contains("project /work/x defines its own \"crux\" server"), "{out}");
        assert!(
            json(&p.claude_json)["projects"]["/work/x"].is_object(),
            "projects preserved"
        );
    }

    #[test]
    fn skip_mcp_leaves_claude_json_untouched() {
        let home = tempfile::tempdir().unwrap();
        let p = ModPaths::under_home(home.path());
        install_at(
            &p,
            &ModOptions {
                skip_mcp: true,
                ..opts()
            },
        )
        .unwrap();
        assert!(!p.claude_json.exists());
    }

    #[test]
    fn status_reports_stale_files() {
        let home = tempfile::tempdir().unwrap();
        let p = ModPaths::under_home(home.path());
        install_at(&p, &opts()).unwrap();
        std::fs::write(p.mod_dir.join("hooks/register.tsx"), "// edited").unwrap();
        let s = status_at(&p);
        assert!(s.contains("hooks/register.tsx"), "{s}");
        assert!(s.contains("STALE"), "{s}");
        assert!(s.contains("includes the mod"), "{s}");
    }
}
