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

/// Recursively replace values under secret-looking keys with `"${REDACTED}"`.
/// Returns whether anything was redacted.
fn redact_json(value: &mut serde_json::Value) -> bool {
    let mut redacted = false;
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if key_is_secret(k) && (v.is_string() || v.is_number()) {
                    *v = serde_json::Value::String("${REDACTED}".to_string());
                    redacted = true;
                } else {
                    redacted |= redact_json(v);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                redacted |= redact_json(v);
            }
        }
        _ => {}
    }
    redacted
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
        if rel.contains("..") {
            continue; // path-traversal guard
        }
        let target = base.join(rel);
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
}
