// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Config-audit helper for the SessionStart hook.
//!
//! Resolves the known set of agent-config files (`settings.json`, `.mcp.json`,
//! `CLAUDE.md`), computes a SHA-256 over each existing file, and asks the
//! Crux daemon's `check_config_audit` tool which paths are unaudited.
//!
//! Warn-only by design: unaudited paths are surfaced via
//! `additionalContext`, never block the session. Operators clear the warning
//! by calling `audit_config(path=..., sha256=..., auditor=...)` once they've
//! reviewed the file.

use std::io::Read;
use std::path::PathBuf;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Probe a small set of well-known config paths. Returns the hashed entries
/// for those that exist. Missing files are silently skipped (a fresh
/// workstation only has a couple of these).
pub fn collect_config_hashes() -> Vec<(PathBuf, String)> {
    let mut paths: Vec<PathBuf> = Vec::new();

    if let Some(home) = std::env::var_os("HOME") {
        let home: PathBuf = home.into();
        paths.push(home.join(".claude/settings.json"));
        paths.push(home.join(".claude/settings.local.json"));
        paths.push(home.join(".claude/.mcp.json"));
        paths.push(home.join(".claude/CLAUDE.md"));
    }

    if let Some(project) = std::env::var_os("CLAUDE_PROJECT_DIR") {
        let project: PathBuf = project.into();
        paths.push(project.join(".claude/settings.json"));
        paths.push(project.join(".claude/settings.local.json"));
        paths.push(project.join(".mcp.json"));
        paths.push(project.join("CLAUDE.md"));
    }

    let mut out: Vec<(PathBuf, String)> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for path in paths {
        if !seen.insert(path.clone()) {
            continue;
        }
        match hash_file(&path) {
            Ok(Some(hex)) => out.push((path, hex)),
            Ok(None) => {}
            Err(err) => {
                eprintln!("crux-hook config-audit: hash failed for {}: {}", path.display(), err);
            }
        }
    }
    out
}

/// Compute the SHA-256 of a file, streaming so very large files don't pin
/// memory. Returns `Ok(None)` if the file doesn't exist; `Err` only on
/// genuine I/O failure.
pub fn hash_file(path: &std::path::Path) -> std::io::Result<Option<String>> {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in &digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(Some(hex))
}

/// Ask the daemon which entries are unaudited. On any error (daemon down,
/// auth missing) returns an empty list — warn-only contract is preserved.
pub fn unaudited_via_daemon(entries: &[(PathBuf, String)]) -> Vec<(PathBuf, String)> {
    if entries.is_empty() {
        return Vec::new();
    }

    let paths_arg: Vec<Value> = entries
        .iter()
        .map(|(path, sha256)| {
            json!({
                "path": path.to_string_lossy(),
                "sha256": sha256,
            })
        })
        .collect();

    let result = match crate::mcp_client::call_tool("check_config_audit", json!({"paths": paths_arg})) {
        Ok(v) => v,
        Err(err) => {
            // `capability_not_permitted` is expected for free/local-tier tokens that
            // lack the `crux-mcp.check_config_audit` capability — fires every session
            // start. Daemon-down / network / 4xx-not-perm-related errors still print.
            let msg = err.to_string();
            if !msg.contains("capability_not_permitted") {
                eprintln!("crux-hook config-audit: check_config_audit failed: {err}");
            }
            return Vec::new();
        }
    };

    let unaudited_array = result.get("unaudited").and_then(|v| v.as_array());
    let Some(unaudited_array) = unaudited_array else {
        return Vec::new();
    };

    unaudited_array
        .iter()
        .filter_map(|entry| {
            let path = entry.get("path").and_then(|v| v.as_str())?;
            let sha = entry.get("sha256").and_then(|v| v.as_str())?;
            Some((PathBuf::from(path), sha.to_string()))
        })
        .collect()
}

/// Format a warn-only `additionalContext` block listing the unaudited paths.
/// Returns `None` if there are no unaudited entries.
pub fn format_warning(unaudited: &[(PathBuf, String)]) -> Option<String> {
    if unaudited.is_empty() {
        return None;
    }
    let mut lines = vec![
        "**Crux config-audit (warn-only)**".to_string(),
        format!(
            "{} agent-config file(s) have content hashes that no operator has audited. \
             Run `audit_config(path=..., sha256=..., auditor=...)` after reviewing each:",
            unaudited.len()
        ),
    ];
    for (path, sha) in unaudited.iter().take(8) {
        let short = sha.get(..16).unwrap_or(sha);
        lines.push(format!("  - {} (sha256={short}…)", path.display()));
    }
    if unaudited.len() > 8 {
        lines.push(format!("  … and {} more", unaudited.len() - 8));
    }
    Some(lines.join("\n"))
}

/// One-shot helper: probe paths, ask the daemon, format. Empty string if
/// nothing to report.
pub fn session_start_warning() -> Option<String> {
    if std::env::var("CRUX_HOOK_CONFIG_AUDIT").as_deref() == Ok("off") {
        return None;
    }
    let hashes = collect_config_hashes();
    let unaudited = unaudited_via_daemon(&hashes);
    format_warning(&unaudited)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hash_file_missing_returns_none() {
        let p = std::path::Path::new("/definitely/does/not/exist/anywhere");
        assert!(matches!(hash_file(p), Ok(None)));
    }

    #[test]
    fn hash_file_known_input() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"hello world").unwrap();
        drop(f);

        let hex = hash_file(&path).unwrap().unwrap();
        // Known sha256 of "hello world".
        assert_eq!(hex, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn format_warning_empty_returns_none() {
        assert!(format_warning(&[]).is_none());
    }

    #[test]
    fn format_warning_lists_paths() {
        let entries = vec![
            (PathBuf::from("/home/u/.claude/settings.json"), "a".repeat(64)),
            (PathBuf::from("/p/.mcp.json"), "b".repeat(64)),
        ];
        let text = format_warning(&entries).unwrap();
        assert!(text.contains("2 agent-config file(s)"));
        assert!(text.contains("/home/u/.claude/settings.json"));
        assert!(text.contains("/p/.mcp.json"));
        assert!(text.contains("aaaaaaaaaaaaaaaa…"));
    }

    #[test]
    fn format_warning_truncates_at_eight() {
        let entries: Vec<(PathBuf, String)> = (0..12)
            .map(|i| (PathBuf::from(format!("/p{i}")), format!("{:0>64}", i)))
            .collect();
        let text = format_warning(&entries).unwrap();
        assert!(text.contains("12 agent-config"));
        assert!(text.contains("and 4 more"));
    }

    #[test]
    fn collect_config_hashes_skips_missing() {
        // Force HOME + CLAUDE_PROJECT_DIR to a tmpdir with no agent-config
        // files; result must be empty (graceful skip, not error).
        let tmp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        let prev_cpd = std::env::var("CLAUDE_PROJECT_DIR").ok();
        std::env::set_var("HOME", tmp.path());
        std::env::set_var("CLAUDE_PROJECT_DIR", tmp.path());

        let entries = collect_config_hashes();
        assert!(entries.is_empty());

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_cpd {
            Some(v) => std::env::set_var("CLAUDE_PROJECT_DIR", v),
            None => std::env::remove_var("CLAUDE_PROJECT_DIR"),
        }
    }
}
