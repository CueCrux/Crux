// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl machine` — register this machine with the daemon and list the
//! machines logged into it.
//!
//! A machine record is a public fact: entity `__infra__::machines`, key
//! `<hostname>`, value = a JSON record (hostname, tailnet IP, OS/arch, ctl
//! version, rail, hook state, last-login). It is HTTP-readable so the console's
//! IX / Infra section can enumerate machines. Reuses the `login` credential
//! store + transparent refresh for the daemon URL + bearer.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::login;

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// Reserved entity that holds one fact per machine (keyed by hostname).
pub const MACHINES_ENTITY: &str = "__infra__::machines";

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Shared HTTP agent for the infra subcommands (machine / config / session).
pub(crate) fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(3)))
        .timeout_global(Some(Duration::from_secs(15)))
        .http_status_as_error(false)
        .build()
        .into()
}

/// Best-effort hostname: `$HOSTNAME` → `/etc/hostname` → "unknown".
fn hostname() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        let h = h.trim();
        if !h.is_empty() {
            return h.to_string();
        }
    }
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let h = h.trim();
        if !h.is_empty() {
            return h.to_string();
        }
    }
    "unknown".to_string()
}

/// Best-effort tailnet IPv4 via `tailscale ip -4` (first line). `None` if absent.
fn tailnet_ip() -> Option<String> {
    let out = std::process::Command::new("tailscale")
        .args(["ip", "-4"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// True if the Crux hook launcher has been installed on this machine.
fn hooks_installed() -> bool {
    std::env::var_os("HOME").is_some_and(|h| {
        std::path::Path::new(&h)
            .join(".local/share/crux/hooks/crux-hook-env.sh")
            .is_file()
    })
}

/// Resolve which daemon to act against: explicit `--url`, else the sole daemon
/// in the credential store, else error. Shared by the infra subcommands.
pub(crate) fn resolve_daemon(url: Option<String>) -> Result<String, DynErr> {
    if let Some(u) = url {
        return Ok(login::normalize_http_base(&u)?);
    }
    let cfg_dir = login::config_dir().ok_or("HOME is not set; cannot locate ~/.config/cuecrux")?;
    let store = login::load_store(&login::credentials_path(&cfg_dir))?;
    let mut keys = store.daemons.keys();
    match (keys.next(), keys.next()) {
        (Some(only), None) => Ok(only.clone()),
        (Some(_), Some(_)) => Err("multiple daemons in the credential store — pass --url <daemon>".into()),
        (None, _) => Err("no stored daemon — run `corecruxctl login` first (or pass --url)".into()),
    }
}

/// Build this machine's record (the fact value).
fn build_record(http_url: &str) -> serde_json::Value {
    let cfg_dir = login::config_dir();
    let rail = cfg_dir
        .and_then(|d| login::load_store(&login::credentials_path(&d)).ok())
        .and_then(|s| s.daemons.get(http_url).map(|c| c.rail.clone()))
        .unwrap_or_else(|| "unknown".to_string());
    serde_json::json!({
        "hostname": hostname(),
        "tailnet_ip": tailnet_ip(),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "ctl_version": env!("CARGO_PKG_VERSION"),
        "rail": rail,
        "hooks_installed": hooks_installed(),
        "http_url": http_url,
        "last_login_unix_ms": now_unix_ms(),
    })
}

/// Register (or refresh) this machine's record on the daemon. Reusable by `login`.
/// Returns a short summary line.
pub fn register(http_url: &str) -> Result<String, DynErr> {
    let bearer = login::resolve_fresh_bearer(http_url)?;
    let record = build_record(http_url);
    let host = record["hostname"].as_str().unwrap_or("unknown").to_string();
    let body = serde_json::json!({
        "entity": MACHINES_ENTITY,
        "key": host,
        "value": record.to_string(),
        "confidence": 1.0,
    });
    let url = format!("{http_url}/v1/facts");
    let mut req = agent().put(&url).header("content-type", "application/json");
    if let Some(t) = &bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    match req.send_json(body) {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status < 300 {
                Ok(format!("registered machine '{host}' → {http_url}"))
            } else {
                let txt = resp.into_body().read_to_string().unwrap_or_default();
                Err(format!("machine register failed (HTTP {status}): {txt}").into())
            }
        }
        Err(ureq::Error::StatusCode(code)) => Err(format!("machine register failed (HTTP {code})").into()),
        Err(other) => Err(Box::new(other)),
    }
}

/// `corecruxctl machine register`.
pub fn run_register(url: Option<String>) -> Result<(), DynErr> {
    let http_url = resolve_daemon(url)?;
    println!("{}", register(&http_url)?);
    Ok(())
}

/// `corecruxctl machine list`.
pub fn run_list(url: Option<String>) -> Result<(), DynErr> {
    let http_url = resolve_daemon(url)?;
    let bearer = login::resolve_fresh_bearer(&http_url)?;
    let get_url = format!("{http_url}/v1/facts");
    let mut req = agent()
        .get(&get_url)
        .query("entity", MACHINES_ENTITY)
        .query("top_k", "100")
        .header("accept", "application/json");
    if let Some(t) = &bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let text = match req.call() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.into_body().read_to_string()?;
            if status >= 300 {
                return Err(format!("machine list failed (HTTP {status}): {body}").into());
            }
            body
        }
        Err(ureq::Error::StatusCode(code)) => return Err(format!("machine list failed (HTTP {code})").into()),
        Err(other) => return Err(Box::new(other)),
    };
    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    let facts = parsed
        .get("facts")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();
    if facts.is_empty() {
        println!("no machines registered with {http_url}");
        return Ok(());
    }
    println!("machines registered with {http_url}:");
    for f in facts {
        let key = f.get("key").and_then(|k| k.as_str()).unwrap_or("?");
        let rec: serde_json::Value = f
            .get("value")
            .and_then(|v| v.as_str())
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(serde_json::Value::Null);
        let os = rec.get("os").and_then(|v| v.as_str()).unwrap_or("?");
        let ip = rec.get("tailnet_ip").and_then(|v| v.as_str()).unwrap_or("-");
        let rail = rec.get("rail").and_then(|v| v.as_str()).unwrap_or("?");
        let hooks = rec
            .get("hooks_installed")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        println!(
            "  {key:<18} os={os:<7} ip={ip:<15} rail={rail:<12} hooks={}",
            if hooks { "yes" } else { "no" }
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn record_has_expected_shape() {
        let r = build_record("http://127.0.0.1:14800");
        assert!(r["hostname"].is_string());
        assert_eq!(r["os"], std::env::consts::OS);
        assert_eq!(r["arch"], std::env::consts::ARCH);
        assert_eq!(r["http_url"], "http://127.0.0.1:14800");
        assert!(r["hooks_installed"].is_boolean());
        assert!(r["last_login_unix_ms"].as_u64().is_some());
        assert!(r["ctl_version"].is_string());
    }

    fn clean_home() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("crux-mach-home-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("HOME", &dir);
        dir
    }

    #[test]
    fn now_unix_ms_is_nonzero() {
        assert!(now_unix_ms() > 0);
    }

    #[test]
    fn hostname_falls_back_when_env_unset() {
        // Whatever the resolution path, it must yield a non-empty string.
        assert!(!hostname().is_empty());
    }

    #[test]
    fn resolve_daemon_normalises_explicit_url() {
        // Explicit URL bypasses the credential store and is normalised.
        assert_eq!(
            resolve_daemon(Some("127.0.0.1:14800".to_string())).unwrap(),
            "http://127.0.0.1:14800"
        );
        assert_eq!(
            resolve_daemon(Some("http://host:9/".to_string())).unwrap(),
            "http://host:9"
        );
    }

    #[test]
    fn resolve_daemon_rejects_empty_url() {
        assert!(resolve_daemon(Some("   ".to_string())).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn register_succeeds_against_stub() {
        clean_home();
        let (port, h) = crate::test_support::serve_responses(vec![(200, "{}".to_string())]);
        let msg = register(&format!("http://127.0.0.1:{port}")).expect("register ok");
        let reqs = h.join().unwrap();
        assert!(msg.starts_with("registered machine "));
        assert!(reqs[0].contains("__infra__::machines"));
        assert!(reqs[0].starts_with("PUT /v1/facts"));
    }

    #[test]
    #[serial_test::serial]
    fn register_surfaces_upstream_error() {
        clean_home();
        let (port, h) = crate::test_support::serve_responses(vec![(409, "conflict".to_string())]);
        let err = register(&format!("http://127.0.0.1:{port}")).expect_err("must fail");
        h.join().ok();
        assert!(err.to_string().contains("machine register failed (HTTP 409)"));
    }

    #[test]
    #[serial_test::serial]
    fn run_register_prints_summary() {
        clean_home();
        let (port, h) = crate::test_support::serve_responses(vec![(200, "{}".to_string())]);
        run_register(Some(format!("http://127.0.0.1:{port}"))).expect("run_register ok");
        h.join().ok();
    }

    #[test]
    #[serial_test::serial]
    fn run_list_empty_and_populated() {
        clean_home();
        // Empty list.
        let (port, h) = crate::test_support::serve_responses(vec![(200, r#"{"facts":[]}"#.to_string())]);
        run_list(Some(format!("http://127.0.0.1:{port}"))).expect("list ok");
        h.join().ok();

        // Populated with a full record + a record with missing fields.
        let rec = serde_json::json!({
            "os": "linux", "tailnet_ip": "100.1.2.3", "rail": "tailscale", "hooks_installed": true
        });
        let body = serde_json::json!({
            "facts": [
                { "key": "host-a", "value": rec.to_string() },
                { "key": "host-b", "value": "not-json" },
            ]
        })
        .to_string();
        let (port, h) = crate::test_support::serve_responses(vec![(200, body)]);
        run_list(Some(format!("http://127.0.0.1:{port}"))).expect("list ok");
        h.join().ok();
    }

    #[test]
    #[serial_test::serial]
    fn run_list_surfaces_upstream_error() {
        clean_home();
        let (port, h) = crate::test_support::serve_responses(vec![(500, "boom".to_string())]);
        let err = run_list(Some(format!("http://127.0.0.1:{port}"))).expect_err("must fail");
        h.join().ok();
        assert!(err.to_string().contains("machine list failed (HTTP 500)"));
    }
}
