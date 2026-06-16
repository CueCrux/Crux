// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl session` — share session state across machines via the one
//! shared daemon.
//!
//! All machines log into the same daemon, so a session snapshot pushed from one
//! machine is readable on another. A snapshot is a public fact: entity
//! `__infra__::sessions`, key `<session-id>`, value = `{state, source_host,
//! updated_at, tokens?}`. (We use the shared fact namespace rather than the
//! per-agent `/v1/sessions/{id}/state`, which is scoped to the writing
//! passport and so isn't visible to other machines' tokens.)
//!
//! Scope note: this is **event-driven snapshot + resume**, not real-time
//! mirroring — granularity is bounded by what a client/hook pushes. A full
//! Claude Code conversation cannot be re-injected on resume; this carries a
//! structured working-set you choose to sync.

use std::io::Read as _;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::login;
use crate::machine::{agent, resolve_daemon};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

const SESSIONS_ENTITY: &str = "__infra__::sessions";

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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

fn get_sessions(http_url: &str) -> Result<Vec<serde_json::Value>, DynErr> {
    let bearer = login::resolve_fresh_bearer(http_url)?;
    let mut req = agent()
        .get(&format!("{http_url}/v1/facts"))
        .query("entity", SESSIONS_ENTITY)
        .query("top_k", "200")
        .header("accept", "application/json");
    if let Some(t) = &bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let text = match req.call() {
        Ok(resp) => {
            let s = resp.status().as_u16();
            let b = resp.into_body().read_to_string()?;
            if s >= 300 {
                return Err(format!("session list failed (HTTP {s}): {b}").into());
            }
            b
        }
        Err(ureq::Error::StatusCode(code)) => return Err(format!("session list failed (HTTP {code})").into()),
        Err(other) => return Err(Box::new(other)),
    };
    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    Ok(parsed
        .get("facts")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default())
}

/// `corecruxctl session push <id> [--file f]` — snapshot session state from a
/// file or stdin to the shared daemon.
pub fn run_push(id: String, file: Option<String>, url: Option<String>) -> Result<(), DynErr> {
    let http_url = resolve_daemon(url)?;
    let raw = match file {
        Some(p) => std::fs::read_to_string(&p)?,
        None => {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };
    // Accept JSON; fall back to wrapping a plain string.
    let state: serde_json::Value = serde_json::from_str(raw.trim()).unwrap_or(serde_json::Value::String(raw.clone()));
    let snapshot = serde_json::json!({
        "state": state,
        "source_host": hostname(),
        "updated_at_unix_ms": now_unix_ms(),
        "bytes": raw.len(),
    });
    let bearer = login::resolve_fresh_bearer(&http_url)?;
    let body =
        serde_json::json!({ "entity": SESSIONS_ENTITY, "key": id, "value": snapshot.to_string(), "confidence": 1.0 });
    let mut req = agent()
        .put(&format!("{http_url}/v1/facts"))
        .header("content-type", "application/json");
    if let Some(t) = &bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    match req.send_json(body) {
        Ok(resp) if resp.status().as_u16() < 300 => {
            println!("pushed session '{id}' snapshot ({} bytes) → {http_url}", raw.len());
            Ok(())
        }
        Ok(resp) => {
            let s = resp.status().as_u16();
            Err(format!(
                "session push failed (HTTP {s}): {}",
                resp.into_body().read_to_string().unwrap_or_default()
            )
            .into())
        }
        Err(ureq::Error::StatusCode(code)) => Err(format!("session push failed (HTTP {code})").into()),
        Err(other) => Err(Box::new(other)),
    }
}

/// `corecruxctl session pull <id>` — print the latest snapshot's state JSON.
pub fn run_pull(id: String, url: Option<String>) -> Result<(), DynErr> {
    let http_url = resolve_daemon(url)?;
    let facts = get_sessions(&http_url)?;
    let fact = facts
        .iter()
        .find(|f| f.get("key").and_then(|k| k.as_str()) == Some(id.as_str()))
        .ok_or_else(|| format!("no session snapshot '{id}' on {http_url}"))?;
    let snap: serde_json::Value = fact
        .get("value")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str(s).ok())
        .ok_or("session snapshot is malformed")?;
    let host = snap.get("source_host").and_then(|v| v.as_str()).unwrap_or("?");
    eprintln!("# session '{id}' from {host}");
    println!(
        "{}",
        serde_json::to_string_pretty(snap.get("state").unwrap_or(&serde_json::Value::Null))?
    );
    Ok(())
}

/// `corecruxctl session list` — snapshots shared across machines.
pub fn run_list(url: Option<String>) -> Result<(), DynErr> {
    let http_url = resolve_daemon(url)?;
    let facts = get_sessions(&http_url)?;
    if facts.is_empty() {
        println!("no session snapshots on {http_url}");
        return Ok(());
    }
    println!("session snapshots on {http_url}:");
    for f in facts {
        let key = f.get("key").and_then(|k| k.as_str()).unwrap_or("?");
        let snap: serde_json::Value = f
            .get("value")
            .and_then(|v| v.as_str())
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(serde_json::Value::Null);
        let host = snap.get("source_host").and_then(|v| v.as_str()).unwrap_or("?");
        let bytes = snap.get("bytes").and_then(serde_json::Value::as_u64).unwrap_or(0);
        println!("  {key:<28} from={host:<14} {bytes} bytes");
    }
    Ok(())
}
