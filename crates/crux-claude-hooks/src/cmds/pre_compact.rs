// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `PreCompact` hook. Snapshots a minimal session-state record to the Crux
//! daemon via MCP `save_session` before the harness compacts context.
//! Best-effort: if the daemon is unreachable, we log and exit 0.
//!
//! It also runs the observe **M3 reasoning pass**: before context (and the
//! model's reasoning for the turn) is compacted away, it attaches a
//! `reasoning_ref` blob pointer to every audit step that lacks one — a
//! reference, never raw chain-of-thought (R1), written `private: true`
//! (Art. 10). Gated by `CRUX_HOOK_OBSERVE_CAPTURE`; best-effort.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

use crate::{hook_input::HookInput, mcp_client, observe_capture, snapshot_crypto};

/// Cap on bytes read from `.agent/current-milestone` — the file is meant to
/// hold a short label like "M3" or "M5: shell-pattern constraints", not a
/// document. Anything longer is truncated for the payload.
const MILESTONE_LABEL_MAX_BYTES: usize = 256;

use snapshot_crypto::SNAPSHOT_ENTITY;

pub fn run<R: std::io::Read>(reader: R) -> anyhow::Result<()> {
    let Some(input) = HookInput::read_from(reader)? else {
        return Ok(());
    };

    if std::env::var("CRUX_HOOK_PRE_COMPACT").as_deref() == Ok("off") {
        return Ok(());
    }

    let session_key = format!("hook:session:{}", input.session_id);

    let cwd_path = if input.cwd.is_empty() {
        None
    } else {
        Some(PathBuf::from(&input.cwd))
    };
    let recovery = collect_recovery_anchors(cwd_path.as_deref());

    let state = json!({
        "hook_event": "PreCompact",
        "trigger": input.trigger.unwrap_or_else(|| "unknown".into()),
        "cwd": input.cwd,
        "transcript_path": input.transcript_path,
        "snapshot_ts": current_timestamp(),
        "recovery": recovery,
    });

    // Finding 1 (crypto-review): the snapshot must never egress in plaintext.
    // `mcp_client` sends `save_session` to `CRUX_MCP_URL`, which a supported
    // login flow can point at a REMOTE hosted daemon — so a plaintext state here
    // leaks cwd/transcript/branch/milestone/recovery. Seal the state with the
    // passport-derived key so the session store holds only ciphertext, whatever
    // the endpoint; fall back to plaintext only for a verified-loopback daemon.
    save_session_sealed(&session_key, &input.session_id, &state);

    // Hosted continuity (ExecPlan hosted-compaction-sync-encrypted-2026-07-17):
    // additionally store the snapshot as a CLIENT-SIDE-ENCRYPTED, non-private
    // `session_snapshot` fact so it rides the per-tenant hosted mirror to the
    // user's other devices. The fact value is ciphertext only ("unreadable to
    // us"). The free/local path above (`save_session` + the shell preset's `.md`)
    // is untouched; free users skip this silently (no passport seed or no mirror).
    // Best-effort — never blocks or errors the hook.
    store_encrypted_snapshot(&input.session_id, &state);

    // M3 reasoning pass: attach a reasoning_ref blob pointer to every audit
    // step still missing one, before the turn's reasoning is compacted away.
    // Best-effort + gated by CRUX_HOOK_OBSERVE_CAPTURE; the helper returns 0
    // when capture is off or the daemon is unreachable.
    let patched = observe_capture::attach_reasoning_refs(&input.session_id);
    if patched > 0 {
        eprintln!("crux-hook pre-compact: attached reasoning_ref to {patched} audit step(s)");
    }
    Ok(())
}

/// Send the PreCompact session snapshot to `save_session`, sealed (Finding 1).
///
/// The state is encrypted with the passport-derived key so the daemon's session
/// store holds only ciphertext — even if `CRUX_MCP_URL` is a hosted daemon.
/// When no passport seed is available (no key to encrypt with), plaintext is
/// sent ONLY to a verified-loopback daemon; a non-loopback endpoint is skipped
/// so plaintext never egresses. Best-effort — daemon-unreachable is non-fatal.
fn save_session_sealed(session_key: &str, session_id: &str, state: &Value) {
    let state_field = match snapshot_crypto::derive_snapshot_key() {
        Some(key) => match seal_state_value(&key, session_id, state) {
            Ok(enc) => json!({ "enc": enc }),
            Err(err) => {
                // Never fall back to plaintext egress on a seal failure.
                eprintln!("crux-hook pre-compact: seal session state failed: {err}");
                return;
            }
        },
        None => {
            if endpoint_is_loopback(&mcp_client::mcp_url()) {
                // No key, but a loopback daemon is trusted: preserve the
                // free/local crash-recovery snapshot (byte-for-byte as before).
                state.clone()
            } else {
                eprintln!(
                    "crux-hook pre-compact: no passport seed and non-loopback MCP endpoint — \
                     skipping save_session to avoid plaintext egress"
                );
                return;
            }
        }
    };
    let args = json!({ "session_id": session_key, "state": state_field });
    if let Err(err) = mcp_client::call_tool("save_session", &args) {
        eprintln!("crux-hook pre-compact: save_session failed: {err}");
    }
}

/// Seal `state` for `session_id` and return the opaque base64 fact value.
fn seal_state_value(key: &[u8; 32], session_id: &str, state: &Value) -> anyhow::Result<String> {
    let plaintext = serde_json::to_vec(state)?;
    snapshot_crypto::seal(key, session_id, &plaintext)?.to_fact_value()
}

/// True only for a loopback MCP endpoint (`127.0.0.0/8`, `::1`, `localhost`).
/// Strict loopback, NOT RFC1918: a LAN / tailnet / hosted address is a remote
/// the plaintext session state must never reach. Hostnames other than
/// `localhost` are refused (not resolved) — no DNS-rebind surface.
fn endpoint_is_loopback(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(after) = authority.strip_prefix('[') {
        after.split(']').next().unwrap_or("")
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Best-effort hosted-continuity store. Silent no-op unless a passport seed is
/// readable **and** a hosted mirror is configured; never errors the hook.
///
/// Order matters for the free path: the passport-seed check is a local file stat
/// (no network), so free users with no seed skip before any extra MCP round-trip.
fn store_encrypted_snapshot(session_id: &str, state: &Value) {
    // Cheap local gate first: no passport seed ⇒ no key ⇒ nothing to encrypt/sync.
    let Some(key) = snapshot_crypto::derive_snapshot_key() else {
        return;
    };
    // Then confirm a hosted mirror is configured. Without one the fact would
    // never sync, and storing it would change the free/local behaviour.
    if !hosted_sync_active() {
        return;
    }
    let args = match build_snapshot_fact_args(session_id, state, &key) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("crux-hook pre-compact: seal snapshot failed: {err}");
            return;
        }
    };
    if let Err(err) = mcp_client::call_tool("store_fact", &args) {
        eprintln!("crux-hook pre-compact: store_fact(session_snapshot) failed: {err}");
    }
}

/// Build the `store_fact` arguments for the encrypted snapshot. Pure + testable.
///
/// The returned payload carries ONLY the sealed envelope in `value`; no snapshot
/// plaintext appears in the entity, key, value, or metadata — asserted by
/// `snapshot_fact_args_carry_ciphertext_only`.
fn build_snapshot_fact_args(session_id: &str, state: &Value, key: &[u8; 32]) -> anyhow::Result<Value> {
    let plaintext = serde_json::to_vec(state)?;
    // Bind the envelope to this session_id (the fact key it is stored under):
    // restore reconstructs the same AAD, so a value moved under a foreign key
    // fails authentication (crypto-review Finding 2).
    let envelope = snapshot_crypto::seal(key, session_id, &plaintext)?;
    Ok(json!({
        "entity": SNAPSHOT_ENTITY,
        "key": session_id,
        "value": envelope.to_fact_value()?,
        "private": false,
    }))
}

/// Whether a hosted mirror is configured, so the encrypted snapshot fact will
/// actually sync. `CRUX_COMPACTION_SYNC=1|on` forces on (opt-in / tests);
/// `0|off` forces off; otherwise the daemon's `sync_status` decides
/// (`configured`, or a non-`local_only` mode). Daemon-unreachable ⇒ not hosted.
fn hosted_sync_active() -> bool {
    match std::env::var("CRUX_COMPACTION_SYNC").as_deref() {
        Ok("1" | "on") => return true,
        Ok("0" | "off") => return false,
        _ => {}
    }
    match mcp_client::call_tool("sync_status", json!({})) {
        Ok(result) => sync_status_is_hosted(&result),
        Err(_) => false,
    }
}

/// Parse a `sync_status` MCP result: hosted = a remote mirror is `configured`
/// (or the sync mode is anything other than `local_only`). Tolerates both the
/// raw object and the MCP `{content:[{text}]}` wrapper.
fn sync_status_is_hosted(result: &Value) -> bool {
    let obj = result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|items| items.iter().find_map(|item| item.get("text").and_then(Value::as_str)))
        .and_then(|text| serde_json::from_str::<Value>(text).ok());
    let obj = obj.as_ref().unwrap_or(result);
    obj.get("configured").and_then(Value::as_bool).unwrap_or(false)
        || obj
            .get("mode")
            .and_then(Value::as_str)
            .is_some_and(|mode| mode != "local_only")
}

/// Best-effort anchors for mid-ExecPlan crash recovery: HEAD commit, active
/// branch, and the operator-set `.agent/current-milestone` label if any.
/// Every field is optional — git absent, repo absent, label absent all
/// degrade silently. Caller embeds the resulting object under `state.recovery`.
fn collect_recovery_anchors(cwd: Option<&Path>) -> Value {
    let mut obj = serde_json::Map::new();

    if let Some(dir) = cwd {
        if let Some(sha) = run_git(dir, &["rev-parse", "HEAD"]) {
            obj.insert("last_commit_sha".into(), Value::String(sha));
        }
        if let Some(branch) = run_git(dir, &["rev-parse", "--abbrev-ref", "HEAD"]) {
            if branch != "HEAD" {
                obj.insert("branch".into(), Value::String(branch));
            }
        }
        if let Some(label) = read_milestone_label(dir) {
            obj.insert("active_milestone".into(), Value::String(label));
        }
    }

    Value::Object(obj)
}

fn run_git(cwd: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).current_dir(cwd).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn read_milestone_label(cwd: &Path) -> Option<String> {
    let path = cwd.join(".agent/current-milestone");
    let raw = std::fs::read(&path).ok()?;
    if raw.is_empty() {
        return None;
    }
    let slice = if raw.len() > MILESTONE_LABEL_MAX_BYTES {
        &raw[..MILESTONE_LABEL_MAX_BYTES]
    } else {
        &raw[..]
    };
    let text = String::from_utf8_lossy(slice).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_stdin_is_a_noop() {
        run(std::io::Cursor::new("")).unwrap();
    }

    #[test]
    fn collect_recovery_anchors_none_when_cwd_absent() {
        let v = collect_recovery_anchors(None);
        assert!(v.as_object().unwrap().is_empty());
    }

    #[test]
    fn collect_recovery_anchors_reads_milestone_label() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = tmp.path().join(".agent");
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(agent.join("current-milestone"), "M3: shell_pattern\n").unwrap();

        let v = collect_recovery_anchors(Some(tmp.path()));
        // last_commit_sha may or may not be present depending on whether
        // tmpdir happens to sit inside a git repo; we only assert the
        // milestone label is captured.
        assert_eq!(
            v.get("active_milestone").and_then(|x| x.as_str()),
            Some("M3: shell_pattern")
        );
    }

    #[test]
    fn collect_recovery_anchors_skips_empty_milestone() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = tmp.path().join(".agent");
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(agent.join("current-milestone"), "   \n").unwrap();

        let v = collect_recovery_anchors(Some(tmp.path()));
        assert!(v.get("active_milestone").is_none());
    }

    #[test]
    fn collect_recovery_anchors_truncates_long_milestone() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = tmp.path().join(".agent");
        std::fs::create_dir_all(&agent).unwrap();
        let long = "x".repeat(MILESTONE_LABEL_MAX_BYTES * 2);
        std::fs::write(agent.join("current-milestone"), &long).unwrap();

        let v = collect_recovery_anchors(Some(tmp.path()));
        let label = v.get("active_milestone").and_then(|x| x.as_str()).unwrap();
        assert!(label.len() <= MILESTONE_LABEL_MAX_BYTES);
    }

    // ---- M2: encrypted snapshot fact (ExecPlan hosted-compaction-sync-...) ----

    #[test]
    fn snapshot_fact_args_carry_ciphertext_only() {
        let key = [3u8; 32];
        let state = json!({
            "hook_event": "PreCompact",
            "cwd": "/home/user/SECRET_MARKER_PROJECT",
            "transcript_path": "/tmp/SECRET_MARKER_TRANSCRIPT.jsonl",
            "recovery": {
                "branch": "feature/SECRET_MARKER_BRANCH",
                "last_commit_sha": "deadbeefSECRET_MARKER",
                "active_milestone": "M2: SECRET_MARKER_MILESTONE"
            }
        });

        let args = build_snapshot_fact_args("sess-abc-123", &state, &key).unwrap();

        // Routing fields are the non-sensitive ones the spec allows in clear.
        assert_eq!(args["entity"], SNAPSHOT_ENTITY);
        assert_eq!(args["key"], "sess-abc-123");
        assert_eq!(args["private"], false);

        // Red line: the ENTIRE synced payload (entity + key + value + metadata)
        // must not contain any plaintext snapshot substring.
        let serialized = args.to_string();
        assert!(
            !serialized.contains("SECRET_MARKER"),
            "plaintext leaked into the synced fact payload: {serialized}"
        );
        // The value must be the opaque sealed envelope, not JSON we can read.
        let value = args["value"].as_str().unwrap();
        assert!(!value.contains('{'), "value should be opaque base64, not readable JSON");

        // And with the key + the bound session_id it decrypts back to exactly
        // the original state.
        let envelope = snapshot_crypto::Envelope::from_fact_value(value).unwrap();
        let recovered = snapshot_crypto::open(&key, "sess-abc-123", &envelope).unwrap();
        let recovered_state: Value = serde_json::from_slice(&recovered).unwrap();
        assert_eq!(recovered_state, state);
    }

    /// M4 mirror-carries-ciphertext proof. The value the hosted mirror receives
    /// is the ENTIRE `store_fact` args payload; assert that no fragment of any
    /// sensitive snapshot field survives in it, and that the value is opaque
    /// (base64, not readable JSON) — then confirm it still decrypts back.
    #[test]
    fn m4_mirror_payload_is_ciphertext_only() {
        let key = [77u8; 32];
        let secrets = [
            "AKIA_FAKE_SECRET_ACCESS_KEY",
            "/home/alice/private-repo/billing.ts",
            "do not touch production database",
            "feature/customer-pii-migration",
            "commit 9f8e7d6c5b4a",
        ];
        let state = json!({
            "hook_event": "PreCompact",
            "cwd": secrets[1],
            "note": secrets[0],
            "plan": secrets[2],
            "recovery": { "branch": secrets[3], "last_commit_sha": secrets[4] },
        });

        let args = build_snapshot_fact_args("session-xyz", &state, &key).unwrap();
        // The whole serialized args object is what the mirror could read. The
        // only field carrying snapshot content is `value`; assert no secret (or
        // any 8+ char alphanumeric run of one) survives anywhere in the payload.
        // (`private`/`entity`/etc. are the args' own structural field names, not
        // snapshot content — the >=8 window skips those short collisions.)
        let synced = args.to_string();
        for secret in secrets {
            assert!(
                !synced.contains(secret),
                "plaintext `{secret}` leaked into synced payload"
            );
            for word in secret.split(|c: char| !c.is_alphanumeric()).filter(|w| w.len() >= 8) {
                assert!(!synced.contains(word), "fragment `{word}` leaked into synced payload");
            }
        }
        // The value must be opaque: base64, NOT readable JSON.
        let value = args["value"].as_str().unwrap();
        assert!(
            !value.contains('{') && !value.contains(':'),
            "value must be opaque base64"
        );
        // Round-trip proves it is genuine ciphertext of the exact state, not a redaction.
        let env = snapshot_crypto::Envelope::from_fact_value(value).unwrap();
        let recovered: Value =
            serde_json::from_slice(&snapshot_crypto::open(&key, "session-xyz", &env).unwrap()).unwrap();
        assert_eq!(recovered, state);
    }

    #[test]
    fn hosted_sync_active_respects_env_override() {
        let _env = crate::test_support::env_guard();
        let prev = std::env::var("CRUX_COMPACTION_SYNC").ok();
        std::env::set_var("CRUX_COMPACTION_SYNC", "1");
        assert!(hosted_sync_active(), "explicit on must be honoured without a daemon");
        std::env::set_var("CRUX_COMPACTION_SYNC", "off");
        assert!(!hosted_sync_active(), "explicit off must skip");
        match prev {
            Some(v) => std::env::set_var("CRUX_COMPACTION_SYNC", v),
            None => std::env::remove_var("CRUX_COMPACTION_SYNC"),
        }
    }

    #[test]
    fn sync_status_hosted_detection() {
        // local_only, not configured ⇒ free path (no hosted store).
        let local = json!({"content": [{"text": "{\"mode\":\"local_only\",\"configured\":false}"}]});
        assert!(!sync_status_is_hosted(&local));
        // configured mirror ⇒ hosted.
        let hosted = json!({"content": [{"text": "{\"mode\":\"cloud_mirror\",\"configured\":true}"}]});
        assert!(sync_status_is_hosted(&hosted));
        // raw object (no MCP wrapper) also parsed.
        assert!(sync_status_is_hosted(
            &json!({"mode": "background_sync", "configured": true})
        ));
        assert!(!sync_status_is_hosted(
            &json!({"mode": "local_only", "configured": false})
        ));
    }

    #[test]
    fn store_encrypted_snapshot_skips_without_passport_seed() {
        // No CRUX_PASSPORT_KEY_PATH / CORECRUXD_* env ⇒ derive_snapshot_key None
        // ⇒ silent no-op even with sync forced on. Must not panic or error.
        let _env = crate::test_support::env_guard();
        let prev_sync = std::env::var("CRUX_COMPACTION_SYNC").ok();
        let prev_kp = std::env::var("CRUX_PASSPORT_KEY_PATH").ok();
        let prev_dd = std::env::var("CORECRUXD_DATA_DIR").ok();
        let prev_pk = std::env::var("CORECRUXD_PASSPORT_KEY_PATH").ok();
        std::env::set_var("CRUX_COMPACTION_SYNC", "1");
        std::env::remove_var("CRUX_PASSPORT_KEY_PATH");
        std::env::remove_var("CORECRUXD_DATA_DIR");
        std::env::remove_var("CORECRUXD_PASSPORT_KEY_PATH");

        store_encrypted_snapshot("sess", &json!({"cwd": "/x"}));

        for (k, v) in [
            ("CRUX_COMPACTION_SYNC", prev_sync),
            ("CRUX_PASSPORT_KEY_PATH", prev_kp),
            ("CORECRUXD_DATA_DIR", prev_dd),
            ("CORECRUXD_PASSPORT_KEY_PATH", prev_pk),
        ] {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }

    #[test]
    fn endpoint_is_loopback_is_strict() {
        // Loopback endpoints may receive plaintext state (no key case).
        assert!(endpoint_is_loopback("http://127.0.0.1:14801/mcp"));
        assert!(endpoint_is_loopback("http://localhost:14801/mcp"));
        assert!(endpoint_is_loopback("http://[::1]:14801/mcp"));
        assert!(endpoint_is_loopback("http://127.5.4.3/mcp"));
        // Remotes — CGNAT tailnet, RFC1918 LAN, and public — are NOT loopback.
        assert!(!endpoint_is_loopback("http://100.70.12.73:14801/mcp"));
        assert!(!endpoint_is_loopback("http://10.0.0.5:14801/mcp"));
        assert!(!endpoint_is_loopback("http://192.168.1.9/mcp"));
        assert!(!endpoint_is_loopback("http://evil.example.com/mcp"));
        assert!(!endpoint_is_loopback("http://user@127.0.0.1@evil.com/mcp"));
    }

    #[test]
    fn daemon_unreachable_does_not_error() {
        // Point at a guaranteed-closed port to confirm graceful degradation.
        let _env = crate::test_support::env_guard();
        let prev = std::env::var("CRUX_MCP_URL").ok();
        std::env::set_var("CRUX_MCP_URL", "http://127.0.0.1:1/mcp");

        let payload = json!({
            "session_id": "test",
            "hook_event_name": "PreCompact",
            "trigger": "manual",
            "cwd": "/tmp",
            "transcript_path": "/tmp/t.jsonl",
        })
        .to_string();

        // Must return Ok even though the daemon isn't reachable.
        run(std::io::Cursor::new(payload)).unwrap();

        match prev {
            Some(v) => std::env::set_var("CRUX_MCP_URL", v),
            None => std::env::remove_var("CRUX_MCP_URL"),
        }
    }
}
