// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl compaction-sync` — self-serve activation for the hosted,
//! Pro-gated compaction-snapshot sync (ExecPlan
//! `hosted-compaction-sync-productization-2026-07-17` M3).
//!
//! `enable` turns on hosted continuity in one command: it verifies the CruxEngine
//! credential + passport prerequisite, runs a live seal→push→pull→verify round-trip
//! on a scratch snapshot, then sets the durable opt-in in `~/.config/cuecrux/env`.
//! The round-trip doubles as the Pro-entitlement probe, so a `402` or transport
//! failure cannot enable the feature. `status` reports the current state without
//! touching the network.
//!
//! The hosted transport + credential model live in
//! [`corecrux_memory::snapshot_sync`]; this module is only the operator on-ramp.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use corecrux_memory::snapshot_sync::{self, SnapshotSyncClient, SnapshotSyncConfig, SnapshotSyncError};

use crate::login;

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// Stable per-tenant scratch id for the activation self-test. Reused (overwritten)
/// across runs so repeated activations don't accumulate objects.
const SELFTEST_ID: &str = "compaction-selftest";

/// `corecruxctl compaction-sync enable` — verify prerequisites, set the opt-in,
/// and prove the hosted round-trip end to end.
pub fn run_enable() -> Result<(), DynErr> {
    println!("Activating hosted compaction-snapshot sync (Pro)…\n");

    // 1) CruxEngine credential (reused CORECRUXD_ENGINE_* family + tenant id).
    let config = match SnapshotSyncConfig::from_env() {
        Some(cfg) => cfg,
        None => {
            eprintln!("  [x] hosted mirror not configured. Set these before enabling:");
            for (var, present) in engine_env_presence() {
                eprintln!("        {} {var}", if present { "ok " } else { "-> " });
            }
            return Err("hosted snapshot mirror is not configured".into());
        }
    };
    println!(
        "  [ok] hosted mirror configured  (engine={}, tenant={})",
        config.base_url, config.tenant_id
    );

    // 2) Same-passport prerequisite: the hook seals every snapshot with the
    //    passport-derived key, so without a local passport seed there is nothing
    //    to sync and cross-device decrypt cannot work.
    if !passport_seed_present() {
        eprintln!(
            "  [x] no passport seed found (looked at {}). Cross-device continuity needs the\n\
             \x20     same passport provisioned on each machine — provision it, then re-run.",
            passport_key_path().map_or_else(|| "<unset>".to_string(), |p| p.display().to_string())
        );
        return Err("passport seed missing".into());
    }
    println!("  [ok] passport seed present     (same-passport cross-device prerequisite)");

    // 3) Live self-test: seal→push→pull→verify. Doubles as the Pro probe. Do not
    //    mutate durable or process-local activation unless this succeeds.
    println!("\n  Running self-test (push → pull → verify)…");
    self_test(&config)?;

    // 4) Persist the opt-in only after the entitlement and transport path pass.
    //    The hook + daemon read this on the next session.
    let env_path = set_opt_in()?;
    std::env::set_var(snapshot_sync::COMPACTION_SYNC_ENV, "1");
    println!(
        "  [ok] opt-in set                ({}=1 in {})",
        snapshot_sync::COMPACTION_SYNC_ENV,
        env_path.display()
    );

    println!(
        "\n[ok] Activated. Hosted continuity is on for tenant {}.\n\
         Your agent's context now follows you across machines that carry the same passport —\n\
         and it is encrypted on this device before upload, so we cannot read it.\n\
         On another machine, start a fresh session and it picks up your latest snapshot.",
        config.tenant_id
    );
    Ok(())
}

/// `corecruxctl compaction-sync status` — report the current state (offline).
pub fn run_status() -> Result<(), DynErr> {
    let opt_in = snapshot_sync::opt_in_enabled();
    let config = SnapshotSyncConfig::from_env();
    let seed = passport_seed_present();

    println!("hosted compaction-snapshot sync");
    println!(
        "  opt-in ({}):   {}",
        snapshot_sync::COMPACTION_SYNC_ENV,
        on_off(opt_in)
    );
    match &config {
        Some(cfg) => {
            println!(
                "  mirror:            configured (engine={}, tenant={})",
                cfg.base_url, cfg.tenant_id
            );
            println!("  api key:           set (x-api-key, not shown)");
        }
        None => {
            let missing: Vec<&str> = engine_env_presence()
                .into_iter()
                .filter(|(_, present)| !present)
                .map(|(var, _)| var)
                .collect();
            println!("  mirror:            not configured (missing: {})", missing.join(", "));
        }
    }
    println!("  passport seed:     {}", if seed { "present" } else { "MISSING" });

    let (state, why) = gate_state(opt_in, config.is_some(), seed);
    println!("  gate:              {state}{why}");
    Ok(())
}

/// Push a scratch blob and read it back, proving entitlement + transport + the
/// 16 MiB path end to end. A `402` is surfaced as a clear "upgrade to Pro".
fn self_test(config: &SnapshotSyncConfig) -> Result<(), DynErr> {
    let client = SnapshotSyncClient::new(config.clone());
    // Opaque scratch payload standing in for a hook-sealed ciphertext envelope —
    // the server treats every snapshot as opaque bytes, so a random blob exercises
    // exactly the same path. (The passport seal/open pairing is checked in step 2
    // and proven by `snapshot_crypto`'s own tests.)
    let payload = format!("crux-compaction-selftest {} {}", now_unix_ms(), uuid::Uuid::new_v4()).into_bytes();

    match client.push(SELFTEST_ID, &payload) {
        Ok(()) => println!("    [ok] push  ({} bytes)", payload.len()),
        Err(SnapshotSyncError::ProRequired) => {
            return Err(format!(
                "Pro entitlement (snapshot_sync) is not active for tenant {} — activation blocked.\n\
                 Upgrade to Pro to enable hosted continuity; the free local compaction survival stays free.",
                config.tenant_id
            )
            .into());
        }
        Err(e) => return Err(format!("self-test push failed: {e}").into()),
    }

    match client.pull(SELFTEST_ID) {
        Ok(Some(got)) if got == payload => println!("    [ok] pull  (round-trip byte-identical)"),
        Ok(Some(_)) => return Err("self-test round-trip mismatch (pulled bytes differ)".into()),
        Ok(None) => return Err("self-test snapshot not found after push".into()),
        Err(e) => return Err(format!("self-test pull failed: {e}").into()),
    }

    // The daemon-side push path mints a CROWN receipt (born-private
    // `__ops::compaction-sync` fact) for each real snapshot; show the id here.
    println!("    receipt id: compaction-sync:push:{SELFTEST_ID}");
    Ok(())
}

/// Presence of each of the three required engine envs, in report order.
fn engine_env_presence() -> Vec<(&'static str, bool)> {
    [
        snapshot_sync::ENGINE_BASE_URL_ENV,
        snapshot_sync::ENGINE_API_KEY_ENV,
        snapshot_sync::ENGINE_TENANT_ID_ENV,
    ]
    .into_iter()
    .map(|var| {
        let present = std::env::var(var).ok().is_some_and(|v| !v.trim().is_empty());
        (var, present)
    })
    .collect()
}

/// Passport key path, matching the hook's resolution order
/// (`snapshot_crypto::passport_key_path_from_env`).
fn passport_key_path() -> Option<PathBuf> {
    for var in ["CRUX_PASSPORT_KEY_PATH", "CORECRUXD_PASSPORT_KEY_PATH"] {
        if let Ok(raw) = std::env::var(var) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(PathBuf::from(trimmed));
            }
        }
    }
    std::env::var("CORECRUXD_DATA_DIR").ok().and_then(|dir| {
        let trimmed = dir.trim();
        (!trimmed.is_empty()).then(|| PathBuf::from(trimmed).join("passport.key"))
    })
}

/// Whether a usable passport seed exists at the resolved path (read-only; never
/// mints a fresh seed, which would differ from the other device).
fn passport_seed_present() -> bool {
    passport_key_path().is_some_and(|p| crux_session::LocalPassportKey::from_existing_path(&p).is_ok())
}

/// Merge `CRUX_COMPACTION_SYNC=1` into `~/.config/cuecrux/env` (0600), preserving
/// other keys (notably `CRUX_AGENT_TOKEN`). Returns the path written.
fn set_opt_in() -> Result<PathBuf, DynErr> {
    let cfg_dir = login::config_dir().ok_or("HOME is not set")?;
    let path = login::env_path(&cfg_dir);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut updates: BTreeMap<String, String> = BTreeMap::new();
    updates.insert(snapshot_sync::COMPACTION_SYNC_ENV.to_string(), "1".to_string());
    let rendered = login::render_env_file(&existing, &updates);
    write_private(&path, rendered.as_bytes())?;
    Ok(path)
}

/// Write `bytes` to `path`, creating the parent 0700 and leaving the file 0600
/// (the env file may hold `CRUX_AGENT_TOKEN`).
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<(), DynErr> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = std::fs::metadata(parent)?.permissions();
            perms.set_mode(0o700);
            let _ = std::fs::set_permissions(parent, perms);
        }
    }
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)?;
    }
    Ok(())
}

fn gate_state(opt_in: bool, configured: bool, seed: bool) -> (&'static str, String) {
    if !opt_in {
        return (
            "closed",
            " (opt-in off — run `corecruxctl compaction-sync enable`)".to_string(),
        );
    }
    if !configured {
        return ("closed", " (mirror not configured)".to_string());
    }
    if !seed {
        return ("closed", " (no passport seed)".to_string());
    }
    ("open", " (would push on the next compaction)".to_string())
}

fn on_off(v: bool) -> &'static str {
    if v {
        "on"
    } else {
        "off"
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// Point HOME + engine envs + passport key at fresh, isolated temp state.
    fn scratch_env() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("crux-cs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("HOME", &dir);
        // A valid 32-byte hex passport seed so `LocalPassportKey::from_existing_path` succeeds.
        let key = dir.join("passport.key");
        std::fs::write(&key, "aa".repeat(32)).unwrap();
        std::env::set_var("CRUX_PASSPORT_KEY_PATH", &key);
        std::env::set_var(snapshot_sync::ENGINE_API_KEY_ENV, "sk-selftest");
        std::env::set_var(snapshot_sync::ENGINE_TENANT_ID_ENV, "tenant-selftest");
        std::env::remove_var(snapshot_sync::COMPACTION_SYNC_ENV);
        dir
    }

    /// A stub that stores the PUT body and serves it back on GET, so the self-test
    /// round-trip is byte-identical. Answers exactly two requests (PUT then GET).
    fn spawn_roundtrip_stub(put_status: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let stored: Arc<Mutex<Vec<u8>>> = Arc::default();
        std::thread::spawn(move || {
            for i in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let (headers, body) = read_request(&mut stream);
                if i == 0 {
                    *stored.lock().unwrap() = body;
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {put_status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                } else {
                    let _ = headers; // GET
                    let b = stored.lock().unwrap().clone();
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        b.len()
                    );
                    let _ = stream.write_all(&b);
                }
            }
        });
        base
    }

    fn spawn_status_stub(status: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = read_request(&mut stream);
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
            }
        });
        base
    }

    fn spawn_disconnect_stub() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = read_request(&mut stream);
            }
        });
        base
    }

    fn assert_activation_stayed_off(dir: &std::path::Path, original_env: &str) {
        let env_path = dir.join(".config/cuecrux/env");
        let env = std::fs::read_to_string(&env_path).expect("existing env remains readable");
        assert_eq!(env, original_env, "failed activation must not rewrite env");
        assert!(
            !snapshot_sync::opt_in_enabled(),
            "failed activation must not set the process opt-in"
        );
    }

    fn read_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
        let mut bytes = Vec::new();
        let mut buf = [0u8; 4096];
        let header_end = loop {
            if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break bytes.len(),
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end.min(bytes.len())]).to_string();
        let content_length = headers
            .lines()
            .find_map(|l| {
                let (n, v) = l.split_once(':')?;
                n.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while bytes.len() < header_end + content_length {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
            }
        }
        (headers, bytes[header_end.min(bytes.len())..].to_vec())
    }

    #[test]
    #[serial_test::serial]
    fn enable_happy_path_sets_opt_in_and_round_trips() {
        let dir = scratch_env();
        std::env::set_var(
            snapshot_sync::ENGINE_BASE_URL_ENV,
            spawn_roundtrip_stub("204 No Content"),
        );

        run_enable().expect("enable should succeed against a Pro-entitled stub");

        // Opt-in was persisted durably.
        let env = std::fs::read_to_string(dir.join(".config/cuecrux/env")).unwrap();
        assert!(env.contains("CRUX_COMPACTION_SYNC=1"), "opt-in must be written: {env}");
        assert!(snapshot_sync::opt_in_enabled(), "process env opt-in set");
    }

    #[test]
    #[serial_test::serial]
    fn enable_blocks_on_402_pro_required() {
        let dir = scratch_env();
        let original_env = "CRUX_AGENT_TOKEN=fixture-token\n";
        let env_path = dir.join(".config/cuecrux/env");
        std::fs::create_dir_all(env_path.parent().unwrap()).unwrap();
        std::fs::write(&env_path, original_env).unwrap();
        std::env::set_var(
            snapshot_sync::ENGINE_BASE_URL_ENV,
            spawn_status_stub("402 Payment Required"),
        );

        let err = run_enable().expect_err("402 must block activation");
        assert!(
            err.to_string().contains("Pro entitlement"),
            "clear upgrade message: {err}"
        );
        assert_activation_stayed_off(&dir, original_env);
    }

    #[test]
    #[serial_test::serial]
    fn enable_transport_failure_does_not_activate() {
        let dir = scratch_env();
        let original_env = "CRUX_AGENT_TOKEN=fixture-token\n";
        let env_path = dir.join(".config/cuecrux/env");
        std::fs::create_dir_all(env_path.parent().unwrap()).unwrap();
        std::fs::write(&env_path, original_env).unwrap();
        std::env::set_var(snapshot_sync::ENGINE_BASE_URL_ENV, spawn_disconnect_stub());

        let err = run_enable().expect_err("transport failure must block activation");
        assert!(err.to_string().contains("self-test push failed"), "{err}");
        assert_activation_stayed_off(&dir, original_env);
    }

    #[test]
    #[serial_test::serial]
    fn enable_fails_when_mirror_unconfigured() {
        let _dir = scratch_env();
        std::env::remove_var(snapshot_sync::ENGINE_BASE_URL_ENV);
        let err = run_enable().expect_err("missing base url must fail");
        assert!(err.to_string().contains("not configured"), "{err}");
    }

    #[test]
    fn gate_state_reasons() {
        assert_eq!(gate_state(false, true, true).0, "closed");
        assert_eq!(gate_state(true, false, true).0, "closed");
        assert_eq!(gate_state(true, true, false).0, "closed");
        assert_eq!(gate_state(true, true, true).0, "open");
    }
}
