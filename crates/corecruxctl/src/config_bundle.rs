// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl config` — save a machine's Claude Code config to the daemon and
//! deploy it onto other machines.
//!
//! A bundle is a public fact: entity `__infra__::configs`, key `<name>`, value =
//! a JSON manifest of the captured `~/.claude` files. **Secrets are redacted**
//! (any JSON value under a secret-looking key → `"${REDACTED}"`); they are
//! re-resolved per machine via `corecruxctl login`, so the bundle is portable
//! structure (settings, MCP servers, CLAUDE.md, commands, agents), not creds.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::login;
use crate::machine::{agent, resolve_daemon};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

const CONFIGS_ENTITY: &str = "__infra__::configs";
/// Per-file cap; files larger than this are skipped (with a note).
const MAX_FILE_BYTES: usize = 256 * 1024;
/// Whole-bundle cap to keep the backing fact reasonable.
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn claude_dir() -> Result<PathBuf, DynErr> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(Path::new(&home).join(".claude"))
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Whether a JSON key looks secret-bearing.
fn key_is_secret(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "api-key",
        "authorization",
        "bearer",
        "access_key",
        "private_key",
        "credential",
        "client_secret",
    ]
    .iter()
    .any(|needle| k.contains(needle))
}

/// Whether a string *value* looks like a secret regardless of its key — catches
/// tokens hidden under innocuous keys (`url`, `args`, `env`, …). Conservative:
/// known prefixes, `Bearer …`, and long token-shaped strings (no spaces / path
/// separators, so prose and file paths are left alone).
fn value_looks_secret(s: &str) -> bool {
    let t = s.trim();
    if t.starts_with("Bearer ") || t.starts_with("bearer ") {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    for prefix in [
        "sk-",
        "sk_",
        "ghp_",
        "gho_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "aws_",
        "akia",
        "glpat-",
        "eyj",
    ] {
        if lower.starts_with(prefix) {
            return true;
        }
    }
    // Token-shaped: long, single run of base64/hex chars, no path/prose markers.
    let token_shaped = t.len() >= 40
        && !t.contains(['/', ' ', '\t', '\n', '.', ':'])
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '='));
    token_shaped
}

/// Recursively redact secrets: values under secret-looking keys, plus any string
/// value that looks like a token. Returns whether anything was redacted.
///
/// Shared with `session push` (`session_sync.rs`) so session snapshots get the
/// same best-effort masking before they land as a public fact on the shared
/// daemon. Not a security boundary — a convenience filter for common token
/// shapes; see the module docs.
pub(crate) fn redact_json(value: &mut serde_json::Value) -> bool {
    fn redact_entry(key: Option<&str>, v: &mut serde_json::Value) -> bool {
        let key_secret = key.is_some_and(key_is_secret);
        match v {
            serde_json::Value::String(s) if key_secret || value_looks_secret(s) => {
                *v = serde_json::Value::String("${REDACTED}".to_string());
                true
            }
            serde_json::Value::Number(_) if key_secret => {
                *v = serde_json::Value::String("${REDACTED}".to_string());
                true
            }
            serde_json::Value::Object(map) => {
                let mut any = false;
                for (k, child) in map.iter_mut() {
                    any |= redact_entry(Some(k), child);
                }
                any
            }
            serde_json::Value::Array(arr) => {
                let mut any = false;
                for child in arr.iter_mut() {
                    any |= redact_entry(None, child);
                }
                any
            }
            _ => false,
        }
    }
    redact_entry(None, value)
}

/// The curated set of `~/.claude` paths to capture. Top-level config files plus
/// markdown under commands/ and agents/. Hooks (binaries) + history/credentials
/// are intentionally excluded.
fn collect_files(base: &Path) -> Result<Vec<serde_json::Value>, DynErr> {
    let mut out = Vec::new();
    let mut total = 0usize;

    let add = |rel: &str, out: &mut Vec<serde_json::Value>, total: &mut usize| -> Result<(), DynErr> {
        let path = base.join(rel);
        if !path.is_file() {
            return Ok(());
        }
        let raw = std::fs::read_to_string(&path)?;
        if raw.len() > MAX_FILE_BYTES {
            println!("  skip {rel} ({} KB > cap)", raw.len() / 1024);
            return Ok(());
        }
        let is_json = Path::new(rel)
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("json"));
        let (content, redacted) = if is_json {
            match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(mut v) => {
                    let r = redact_json(&mut v);
                    (serde_json::to_string_pretty(&v)? + "\n", r)
                }
                Err(_) => (raw, false),
            }
        } else {
            (raw, false)
        };
        *total += content.len();
        if *total > MAX_BUNDLE_BYTES {
            return Err("bundle exceeds size cap (1 MB) — trim ~/.claude".into());
        }
        out.push(serde_json::json!({ "path": rel, "redacted": redacted, "content": content }));
        Ok(())
    };

    for f in ["settings.json", "settings.local.json", ".mcp.json", "CLAUDE.md"] {
        add(f, &mut out, &mut total)?;
    }
    for dir in ["commands", "agents"] {
        let d = base.join(dir);
        if d.is_dir() {
            for entry in walk_md(&d) {
                if let Ok(rel) = entry.strip_prefix(base) {
                    let rel = rel.to_string_lossy().replace('\\', "/");
                    add(&rel, &mut out, &mut total)?;
                }
            }
        }
    }
    Ok(out)
}

/// Recursively collect `*.md` files under `dir` (one level of nesting is plenty
/// for command/agent libraries; we recurse fully but only take `.md`).
fn walk_md(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            out.extend(walk_md(&p));
        } else if p
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("md"))
        {
            out.push(p);
        }
    }
    out
}

fn put_fact(http_url: &str, key: &str, value: String) -> Result<(), DynErr> {
    let bearer = login::resolve_fresh_bearer(http_url)?;
    let body = serde_json::json!({ "entity": CONFIGS_ENTITY, "key": key, "value": value, "confidence": 1.0 });
    let mut req = agent()
        .put(&format!("{http_url}/v1/facts"))
        .header("content-type", "application/json");
    if let Some(t) = &bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    match req.send_json(body) {
        Ok(resp) if resp.status().as_u16() < 300 => Ok(()),
        Ok(resp) => {
            let s = resp.status().as_u16();
            Err(format!(
                "config push failed (HTTP {s}): {}",
                resp.into_body().read_to_string().unwrap_or_default()
            )
            .into())
        }
        Err(ureq::Error::StatusCode(code)) => Err(format!("config push failed (HTTP {code})").into()),
        Err(other) => Err(Box::new(other)),
    }
}

fn get_configs(http_url: &str) -> Result<Vec<serde_json::Value>, DynErr> {
    let bearer = login::resolve_fresh_bearer(http_url)?;
    let mut req = agent()
        .get(&format!("{http_url}/v1/facts"))
        .query("entity", CONFIGS_ENTITY)
        .query("top_k", "100")
        .header("accept", "application/json");
    if let Some(t) = &bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let text = match req.call() {
        Ok(resp) => {
            let s = resp.status().as_u16();
            let b = resp.into_body().read_to_string()?;
            if s >= 300 {
                return Err(format!("config list failed (HTTP {s}): {b}").into());
            }
            b
        }
        Err(ureq::Error::StatusCode(code)) => return Err(format!("config list failed (HTTP {code})").into()),
        Err(other) => return Err(Box::new(other)),
    };
    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    Ok(parsed
        .get("facts")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default())
}

/// `corecruxctl config push <name>` — capture ~/.claude and store on the daemon.
pub fn run_push(name: String, url: Option<String>) -> Result<(), DynErr> {
    let http_url = resolve_daemon(url)?;
    let base = claude_dir()?;
    if !base.is_dir() {
        return Err(format!("{} not found — nothing to push", base.display()).into());
    }
    println!("capturing {} …", base.display());
    let files = collect_files(&base)?;
    if files.is_empty() {
        return Err("no config files found under ~/.claude".into());
    }
    let redacted_count = files
        .iter()
        .filter(|f| f["redacted"].as_bool().unwrap_or(false))
        .count();
    let bundle = serde_json::json!({
        "name": name,
        "created_at_unix_ms": now_unix_ms(),
        "source_host": hostname(),
        "files": files,
    });
    let nfiles = bundle["files"].as_array().map_or(0, |a| a.len());
    put_fact(&http_url, &name, bundle.to_string())?;
    println!("pushed config bundle '{name}' ({nfiles} files, {redacted_count} redacted) → {http_url}");
    Ok(())
}

/// `corecruxctl config list`.
pub fn run_list(url: Option<String>) -> Result<(), DynErr> {
    let http_url = resolve_daemon(url)?;
    let facts = get_configs(&http_url)?;
    if facts.is_empty() {
        println!("no config bundles on {http_url}");
        return Ok(());
    }
    println!("config bundles on {http_url}:");
    for f in facts {
        let key = f.get("key").and_then(|k| k.as_str()).unwrap_or("?");
        let b: serde_json::Value = f
            .get("value")
            .and_then(|v| v.as_str())
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(serde_json::Value::Null);
        let host = b.get("source_host").and_then(|v| v.as_str()).unwrap_or("?");
        let n = b.get("files").and_then(|v| v.as_array()).map_or(0, |a| a.len());
        println!("  {key:<24} files={n:<3} from={host}");
    }
    Ok(())
}

/// `corecruxctl config pull <name>` — restore a bundle into ~/.claude.
pub fn run_pull(name: String, url: Option<String>) -> Result<(), DynErr> {
    let http_url = resolve_daemon(url)?;
    let facts = get_configs(&http_url)?;
    let fact = facts
        .iter()
        .find(|f| f.get("key").and_then(|k| k.as_str()) == Some(name.as_str()))
        .ok_or_else(|| format!("no config bundle named '{name}' on {http_url}"))?;
    let bundle: serde_json::Value = fact
        .get("value")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str(s).ok())
        .ok_or("config bundle is malformed")?;
    let base = claude_dir()?;
    let files = bundle
        .get("files")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();
    let mut written = 0;
    let mut redacted_files = Vec::new();
    for f in &files {
        let (Some(rel), Some(content)) = (
            f.get("path").and_then(|v| v.as_str()),
            f.get("content").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let Some(target) = safe_target(&base, rel) else {
            println!("  skip unsafe path '{rel}'");
            continue;
        };
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if target.exists() {
            let _ = std::fs::copy(&target, format!("{}.bak", target.display()));
        }
        std::fs::write(&target, content)?;
        written += 1;
        if f["redacted"].as_bool().unwrap_or(false) {
            redacted_files.push(rel.to_string());
        }
    }
    println!("restored '{name}' → {} ({written} files)", base.display());
    if !redacted_files.is_empty() {
        println!("  these files had secrets redacted — re-add them or re-run `corecruxctl login`:");
        for r in &redacted_files {
            println!("    {r}");
        }
    }
    Ok(())
}

/// Resolve a bundle-relative path under `base`, rejecting absolute paths and any
/// `..` traversal. Returns `None` for unsafe input.
fn safe_target(base: &Path, rel: &str) -> Option<PathBuf> {
    let rp = Path::new(rel);
    if rp.is_absolute() {
        return None;
    }
    for comp in rp.components() {
        match comp {
            std::path::Component::Normal(_) | std::path::Component::CurDir => {}
            // ParentDir / RootDir / Prefix → reject.
            _ => return None,
        }
    }
    Some(base.join(rp))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn key_secret_detection() {
        assert!(key_is_secret("CRUX_AGENT_TOKEN"));
        assert!(key_is_secret("apiKey"));
        assert!(key_is_secret("Authorization"));
        assert!(!key_is_secret("model"));
        assert!(!key_is_secret("command"));
    }

    #[test]
    fn redact_walks_nested() {
        let mut v = serde_json::json!({
            "mcpServers": { "x": { "headers": { "Authorization": "Bearer abc" }, "command": "node" } },
            "token": "sekret",
            "list": [{ "api_key": "k" }],
            "keep": "value"
        });
        let r = redact_json(&mut v);
        assert!(r);
        assert_eq!(v["token"], "${REDACTED}");
        assert_eq!(v["mcpServers"]["x"]["headers"]["Authorization"], "${REDACTED}");
        assert_eq!(v["mcpServers"]["x"]["command"], "node");
        assert_eq!(v["list"][0]["api_key"], "${REDACTED}");
        assert_eq!(v["keep"], "value");
    }

    #[test]
    fn value_based_redaction_catches_hidden_tokens() {
        // A token under an innocuous key + in an array is redacted; prose/paths/short are not.
        assert!(value_looks_secret("ghp_0123456789ABCDEFabcdef0123456789ABCD"));
        assert!(value_looks_secret("Bearer abc.def.ghi"));
        assert!(value_looks_secret("0123456789abcdef0123456789abcdef0123456789ab")); // 44-char hex
        assert!(!value_looks_secret("claude-opus-4-8"));
        assert!(!value_looks_secret(
            "/home/myles/.local/share/crux/hooks/crux-hook-env.sh"
        ));
        assert!(!value_looks_secret("a short value with spaces"));

        let mut v = serde_json::json!({
            "args": ["--key", "ghp_0123456789ABCDEFabcdef0123456789ABCD"],
            "url": "https://example.com/path",
            "note": "just prose here"
        });
        assert!(redact_json(&mut v));
        assert_eq!(v["args"][1], "${REDACTED}");
        assert_eq!(v["args"][0], "--key");
        assert_eq!(v["url"], "https://example.com/path");
        assert_eq!(v["note"], "just prose here");
    }

    #[test]
    fn safe_target_blocks_traversal_and_absolute() {
        let base = Path::new("/home/u/.claude");
        assert_eq!(safe_target(base, "settings.json"), Some(base.join("settings.json")));
        assert_eq!(safe_target(base, "commands/x.md"), Some(base.join("commands/x.md")));
        assert!(safe_target(base, "../../../etc/passwd").is_none());
        assert!(safe_target(base, "a/../../b").is_none());
        assert!(safe_target(base, "/etc/passwd").is_none());
    }

    #[test]
    fn key_secret_negative_and_more_positives() {
        for k in [
            "client_secret",
            "PRIVATE_KEY",
            "x-bearer",
            "ACCESS_KEY_ID",
            "credential",
        ] {
            assert!(key_is_secret(k), "{k} should be secret");
        }
        for k in ["temperature", "name", "args", "command"] {
            assert!(!key_is_secret(k), "{k} should not be secret");
        }
    }

    #[test]
    fn value_secret_prefixes_and_shape_edges() {
        assert!(value_looks_secret("sk-aaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(value_looks_secret("glpat-xxxxxxxxxxxxxxxxxxxx"));
        assert!(value_looks_secret("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        // Exactly token-shaped (>=40 alnum, no separators).
        assert!(value_looks_secret(&"a".repeat(40)));
        // Just under length cutoff with separators stays clear.
        assert!(!value_looks_secret(&"a".repeat(39)));
        assert!(!value_looks_secret("https://api.example.com/v1/endpoint/path"));
    }

    #[test]
    fn redact_json_reports_no_change_on_clean_input() {
        let mut v = serde_json::json!({ "model": "opus", "nested": { "temp": 0.2 }, "list": ["a", "b"] });
        assert!(!redact_json(&mut v));
        assert_eq!(v["model"], "opus");
    }

    #[test]
    fn redact_json_redacts_numeric_under_secret_key() {
        let mut v = serde_json::json!({ "api_key": 12345 });
        assert!(redact_json(&mut v));
        assert_eq!(v["api_key"], "${REDACTED}");
    }

    #[test]
    fn walk_md_recurses_and_filters_extension() {
        let root = std::env::temp_dir().join(format!("crux-walkmd-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("a.md"), "# a").unwrap();
        std::fs::write(root.join("ignore.txt"), "x").unwrap();
        std::fs::write(root.join("sub/b.MD"), "# b").unwrap();
        let mut found: Vec<String> = walk_md(&root)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        found.sort();
        assert_eq!(found, vec!["a.md".to_string(), "b.MD".to_string()]);
        // Non-existent dir yields empty (the read_dir error path).
        assert!(walk_md(&root.join("does-not-exist")).is_empty());
    }

    #[test]
    fn collect_files_captures_curated_set_and_redacts_json() {
        let base = std::env::temp_dir().join(format!("crux-collect-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(base.join("commands")).unwrap();
        std::fs::create_dir_all(base.join("agents")).unwrap();
        std::fs::write(base.join("settings.json"), r#"{"model":"opus","token":"sekret-value"}"#).unwrap();
        std::fs::write(base.join("CLAUDE.md"), "# project rules").unwrap();
        std::fs::write(base.join("commands/do.md"), "do a thing").unwrap();
        std::fs::write(base.join("agents/helper.md"), "helper agent").unwrap();
        // Not in the curated set → ignored.
        std::fs::write(base.join("history.jsonl"), "noise").unwrap();

        let files = collect_files(&base).expect("collect ok");
        let paths: Vec<String> = files.iter().map(|f| f["path"].as_str().unwrap().to_string()).collect();
        assert!(paths.contains(&"settings.json".to_string()));
        assert!(paths.contains(&"CLAUDE.md".to_string()));
        assert!(paths.contains(&"commands/do.md".to_string()));
        assert!(paths.contains(&"agents/helper.md".to_string()));
        assert!(!paths.iter().any(|p| p.contains("history")));

        let settings = files.iter().find(|f| f["path"] == "settings.json").unwrap();
        assert_eq!(settings["redacted"], true);
        assert!(settings["content"].as_str().unwrap().contains("${REDACTED}"));
        assert!(!settings["content"].as_str().unwrap().contains("sekret-value"));

        let md = files.iter().find(|f| f["path"] == "CLAUDE.md").unwrap();
        assert_eq!(md["redacted"], false);
    }

    fn clean_home() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("crux-cfg-home-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("HOME", &dir);
        dir
    }

    #[test]
    #[serial_test::serial]
    fn run_list_empty_populated_and_error() {
        clean_home();
        // empty
        let (port, h) = crate::test_support::serve_responses(vec![(200, r#"{"facts":[]}"#.to_string())]);
        run_list(Some(format!("http://127.0.0.1:{port}"))).expect("list ok");
        h.join().ok();
        // populated
        let bundle = serde_json::json!({ "name": "n", "source_host": "host-a", "files": [{"path":"settings.json"}] });
        let body = serde_json::json!({ "facts": [{ "key": "mybundle", "value": bundle.to_string() }] }).to_string();
        let (port, h) = crate::test_support::serve_responses(vec![(200, body)]);
        run_list(Some(format!("http://127.0.0.1:{port}"))).expect("list ok");
        h.join().ok();
        // upstream error
        let (port, h) = crate::test_support::serve_responses(vec![(500, "boom".to_string())]);
        let err = run_list(Some(format!("http://127.0.0.1:{port}"))).expect_err("must fail");
        h.join().ok();
        assert!(err.to_string().contains("config list failed (HTTP 500)"));
    }

    #[test]
    #[serial_test::serial]
    fn run_pull_restores_files_and_skips_unsafe_paths() {
        let home = clean_home();
        let files = serde_json::json!([
            { "path": "settings.json", "content": "{\"model\":\"opus\"}", "redacted": true },
            { "path": "commands/do.md", "content": "do", "redacted": false },
            { "path": "../escape.txt", "content": "nope", "redacted": false },
        ]);
        let bundle = serde_json::json!({ "name": "b1", "files": files });
        let body = serde_json::json!({ "facts": [{ "key": "b1", "value": bundle.to_string() }] }).to_string();
        let (port, h) = crate::test_support::serve_responses(vec![(200, body)]);
        run_pull("b1".to_string(), Some(format!("http://127.0.0.1:{port}"))).expect("pull ok");
        h.join().ok();
        assert!(home.join(".claude/settings.json").is_file());
        assert!(home.join(".claude/commands/do.md").is_file());
        assert!(!home.join(".claude/escape.txt").exists());
        assert!(!home.join("escape.txt").exists());
    }

    #[test]
    #[serial_test::serial]
    fn run_pull_missing_and_malformed() {
        clean_home();
        // not found
        let (port, h) = crate::test_support::serve_responses(vec![(200, r#"{"facts":[]}"#.to_string())]);
        let err = run_pull("ghost".to_string(), Some(format!("http://127.0.0.1:{port}"))).expect_err("must fail");
        h.join().ok();
        assert!(err.to_string().contains("no config bundle named 'ghost'"));
        // malformed value
        let body = serde_json::json!({ "facts": [{ "key": "bad", "value": "not-json" }] }).to_string();
        let (port, h) = crate::test_support::serve_responses(vec![(200, body)]);
        let err = run_pull("bad".to_string(), Some(format!("http://127.0.0.1:{port}"))).expect_err("must fail");
        h.join().ok();
        assert!(err.to_string().contains("malformed"));
    }

    #[test]
    #[serial_test::serial]
    fn run_push_captures_and_uploads() {
        let home = clean_home();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(
            home.join(".claude/settings.json"),
            r#"{"token":"sekret","model":"opus"}"#,
        )
        .unwrap();
        let (port, h) = crate::test_support::serve_responses(vec![(200, "{}".to_string())]);
        run_push("mybundle".to_string(), Some(format!("http://127.0.0.1:{port}"))).expect("push ok");
        let reqs = h.join().unwrap();
        assert!(reqs[0].starts_with("PUT /v1/facts"));
        assert!(reqs[0].contains("__infra__::configs"));
        assert!(reqs[0].contains("${REDACTED}"));
        assert!(!reqs[0].contains("sekret"));
    }

    #[test]
    #[serial_test::serial]
    fn run_push_errors_without_claude_dir() {
        clean_home(); // HOME exists but no ~/.claude
        let err = run_push("x".to_string(), Some("http://127.0.0.1:1".to_string())).expect_err("must fail");
        assert!(err.to_string().contains("nothing to push"));
    }

    #[test]
    fn collect_files_skips_oversized_and_passes_through_bad_json() {
        let base = std::env::temp_dir().join(format!("crux-collect2-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&base).unwrap();
        // Oversized file is skipped (no panic, not included).
        std::fs::write(base.join("settings.json"), "x".repeat(MAX_FILE_BYTES + 1)).unwrap();
        // Invalid JSON under a .json name passes through verbatim, unredacted.
        std::fs::write(base.join(".mcp.json"), "{ not valid json").unwrap();
        let files = collect_files(&base).expect("collect ok");
        let paths: Vec<String> = files.iter().map(|f| f["path"].as_str().unwrap().to_string()).collect();
        assert!(
            !paths.contains(&"settings.json".to_string()),
            "oversized must be skipped"
        );
        let mcp = files.iter().find(|f| f["path"] == ".mcp.json").unwrap();
        assert_eq!(mcp["redacted"], false);
        assert!(mcp["content"].as_str().unwrap().contains("not valid json"));
    }
}
