// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Plaintext-egress regression test for the PreCompact hook (crypto-review
//! Finding 1). `mcp_client` sends every request to `CRUX_MCP_URL`, which a
//! supported login flow can point at a REMOTE hosted daemon. The product
//! promise is "unreadable to us": NO request the hook makes — not
//! `save_session`, not `store_fact` — may carry snapshot plaintext.
//!
//! This test stands up a capturing mock MCP daemon, runs the real PreCompact
//! hook with a passport seed present and hosted sync forced on, and asserts that
//! a fake secret + a PII path planted in the snapshot appear in NONE of the
//! captured requests. It also asserts both `save_session` and `store_fact`
//! actually fired (so we are testing the encrypting path, not an accidental
//! skip).
//!
//! Finding 6 companion: with the sync flag unset, the encrypted-fact path
//! (`store_fact`/`query_facts`/`sync_status`) must not fire at all.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::thread;
use std::time::Duration;

/// Serialise the env-mutating tests in this binary (they all set process-global
/// `CRUX_*` vars).
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Take the env lock, tolerating poisoning.
///
/// This lock orders env mutation; it guards no data invariant, so a poisoned
/// lock is still safe to use. `.lock().unwrap()` was actively harmful: when one
/// test failed a real assertion while holding it, every *other* test panicked at
/// its own `lock()` line. One genuine failure presented as three, and two of
/// them pointed at a line with nothing to do with the cause — which is exactly
/// how the underlying flake here was first misdiagnosed.
fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    env_lock().lock().unwrap_or_else(PoisonError::into_inner)
}

/// Per-connection read timeout for the mock. Bounds a hung test; it is not a
/// latency budget. See the note in `handle_conn`.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// A capturing mock MCP daemon: accepts any number of requests on a random
/// loopback port and records each raw request body. Stop + join to collect.
struct CapturingMock {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl CapturingMock {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).expect("nonblocking");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (req2, stop2) = (requests.clone(), stop.clone());

        let handle = thread::spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => handle_conn(stream, &req2),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            url: format!("http://127.0.0.1:{port}/mcp"),
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> Vec<String> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        Arc::try_unwrap(self.requests).unwrap().into_inner().unwrap()
    }
}

/// Read one HTTP request (headers + Content-Length body), record its body, and
/// reply with a generic JSON-RPC result satisfying every tool the hook calls.
fn handle_conn(mut stream: std::net::TcpStream, requests: &Arc<Mutex<Vec<String>>>) {
    stream.set_nonblocking(false).ok();
    // Deadlock guard, not a latency budget. The old 2s was tight enough to fire
    // under `cargo test --workspace` CPU contention: the read returned early,
    // this handler recorded a TRUNCATED request, and the caller's
    // `joined.contains("save_session")` assertion failed — a real-looking
    // plaintext-egress failure caused purely by machine load. Nothing here is
    // waiting on a network, so a long timeout costs nothing except in the hang
    // case it exists to bound.
    stream.set_read_timeout(Some(READ_TIMEOUT)).ok();

    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let mut header_end = None;
    let mut truncated: Option<(usize, usize)> = None;
    loop {
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = Some(pos + 4);
                    break;
                }
                if buf.len() > 262_144 {
                    break;
                }
            }
        }
    }
    if let Some(he) = header_end {
        let headers = String::from_utf8_lossy(&buf[..he]).to_ascii_lowercase();
        let body_len = headers
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while buf.len() < he + body_len {
            match stream.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
        // A short read here used to be indistinguishable from "the hook never
        // sent that tool call" — the caller just saw a missing `save_session`
        // and reported a plaintext-egress failure. Say so explicitly instead, so
        // a future occurrence names itself rather than accusing the hook.
        if buf.len() < he + body_len {
            truncated = Some((buf.len().saturating_sub(he), body_len));
        }
    }
    let captured = String::from_utf8_lossy(&buf).to_string();
    let entry = match truncated {
        Some((got, want)) => format!(
            "__TRUNCATED_CAPTURE__ read {got} of {want} expected body bytes (mock read timeout \
             or client disconnect — NOT evidence about what the hook sent)\n{captured}"
        ),
        None => captured,
    };
    requests.lock().unwrap_or_else(PoisonError::into_inner).push(entry);

    // A generic result: `content` for text tools, empty `structuredContent.rows`
    // for query_facts. Enough for every call the hook makes to succeed.
    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{}"}],"structuredContent":{"rows":[]}}}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// RAII env setter that restores the prior value on drop.
struct EnvVar {
    key: &'static str,
    prev: Option<String>,
}
impl EnvVar {
    fn set(key: &'static str, val: &str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::set_var(key, val);
        Self { key, prev }
    }
    fn unset(key: &'static str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::remove_var(key);
        Self { key, prev }
    }
}
impl Drop for EnvVar {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

const SECRET_MARKER: &str = "AKIA_FAKE_EGRESS_SECRET_9137";
const PII_PATH: &str = "/home/alice/private-repo/PII_MARKER_billing.ts";

fn precompact_input() -> String {
    serde_json::json!({
        "session_id": "egress-sess-1",
        "hook_event_name": "PreCompact",
        "trigger": "manual",
        "cwd": PII_PATH,
        "transcript_path": format!("/tmp/{SECRET_MARKER}.jsonl"),
    })
    .to_string()
}

#[test]
fn no_plaintext_egress_in_any_request_with_seed_present() {
    let _guard = lock_env();
    let seed_hex = "11".repeat(32); // 32-byte seed as 64 hex chars
    let key_file = std::env::temp_dir().join(format!("egress-passport-{}.key", std::process::id()));
    std::fs::write(&key_file, &seed_hex).unwrap();

    let mock = CapturingMock::spawn();

    let _e1 = EnvVar::set("CRUX_MCP_URL", &mock.url);
    let _e2 = EnvVar::set("CRUX_PASSPORT_KEY_PATH", key_file.to_str().unwrap());
    let _e3 = EnvVar::set("CRUX_COMPACTION_SYNC", "1"); // force hosted sync on
    let _e4 = EnvVar::set("CRUX_AGENT_TOKEN", "bearer-distinct-from-seed-abcdef0123456789");
    let _e5 = EnvVar::unset("CRUX_HOOK_OBSERVE_CAPTURE");
    let _e6 = EnvVar::unset("CRUX_HOOK_PRE_COMPACT");

    crux_claude_hooks::cmds::pre_compact::run(std::io::Cursor::new(precompact_input())).unwrap();

    let requests = mock.finish();
    std::fs::remove_file(&key_file).ok();

    assert!(!requests.is_empty(), "hook made no MCP requests");
    let joined = requests.join("\n----\n");

    // Fail on a truncated capture BEFORE the content assertions below, so a mock
    // read timeout is never reported as a plaintext-egress or missing-tool-call
    // failure. This is a harness fault, not a finding about the hook.
    assert!(
        !joined.contains("__TRUNCATED_CAPTURE__"),
        "mock captured a partial request — harness fault, no conclusion about egress:\n{joined}"
    );

    // The red line: no plaintext marker in ANY captured request.
    assert!(
        !joined.contains(SECRET_MARKER),
        "secret marker leaked in plaintext to the (possibly hosted) daemon:\n{joined}"
    );
    assert!(
        !joined.contains("PII_MARKER"),
        "PII path leaked in plaintext to the (possibly hosted) daemon:\n{joined}"
    );

    // And we exercised the encrypting path: both save_session and store_fact fired.
    assert!(joined.contains("save_session"), "save_session did not fire:\n{joined}");
    assert!(
        joined.contains("store_fact"),
        "store_fact (encrypted snapshot) did not fire:\n{joined}"
    );
}

#[test]
fn bearer_equal_to_seed_refuses_hosted_sync() {
    // Finding 5: if CRUX_AGENT_TOKEN IS the passport seed, the server would hold
    // the key material — refuse to enable hosted snapshot sync (no store_fact),
    // even with the flag on. (save_session to this loopback mock is allowed.)
    let _guard = lock_env();
    let seed_hex = "3a".repeat(32); // valid 64-hex seed
    let key_file = std::env::temp_dir().join(format!("egress-reuse-passport-{}.key", std::process::id()));
    std::fs::write(&key_file, &seed_hex).unwrap();

    let mock = CapturingMock::spawn();

    let _e1 = EnvVar::set("CRUX_MCP_URL", &mock.url);
    let _e2 = EnvVar::set("CRUX_PASSPORT_KEY_PATH", key_file.to_str().unwrap());
    let _e3 = EnvVar::set("CRUX_COMPACTION_SYNC", "1");
    let _e4 = EnvVar::set("CRUX_AGENT_TOKEN", &seed_hex); // bearer == seed (the misconfig)
    let _e5 = EnvVar::unset("CRUX_HOOK_OBSERVE_CAPTURE");
    let _e6 = EnvVar::unset("CRUX_HOOK_PRE_COMPACT");

    crux_claude_hooks::cmds::pre_compact::run(std::io::Cursor::new(precompact_input())).unwrap();

    let requests = mock.finish();
    std::fs::remove_file(&key_file).ok();

    let joined = requests.join("\n----\n");
    assert!(
        !joined.contains("store_fact"),
        "hosted snapshot sync must be refused when the bearer reuses the seed:\n{joined}"
    );
}

#[test]
fn flag_off_makes_no_encrypted_fact_calls() {
    // Finding 6: with the sync flag unset, the hosted-fact path must not fire —
    // no sync_status, no store_fact, no query_facts — even with a seed present.
    // save_session (the legacy path) still fires, sealed (Finding 1).
    let _guard = lock_env();
    let seed_hex = "22".repeat(32);
    let key_file = std::env::temp_dir().join(format!("egress-off-passport-{}.key", std::process::id()));
    std::fs::write(&key_file, &seed_hex).unwrap();

    let mock = CapturingMock::spawn();

    let _e1 = EnvVar::set("CRUX_MCP_URL", &mock.url);
    let _e2 = EnvVar::set("CRUX_PASSPORT_KEY_PATH", key_file.to_str().unwrap());
    let _e3 = EnvVar::unset("CRUX_COMPACTION_SYNC"); // default OFF
    let _e4 = EnvVar::set("CRUX_AGENT_TOKEN", "bearer-distinct-from-seed-abcdef0123456789");
    let _e5 = EnvVar::unset("CRUX_HOOK_OBSERVE_CAPTURE");
    let _e6 = EnvVar::unset("CRUX_HOOK_PRE_COMPACT");

    crux_claude_hooks::cmds::pre_compact::run(std::io::Cursor::new(precompact_input())).unwrap();

    let requests = mock.finish();
    std::fs::remove_file(&key_file).ok();

    let joined = requests.join("\n----\n");
    assert!(
        !joined.contains("store_fact"),
        "encrypted-fact store_fact must not fire with the sync flag off:\n{joined}"
    );
    assert!(
        !joined.contains("sync_status"),
        "sync_status must not fire with the sync flag off (no auto-enable):\n{joined}"
    );
    assert!(
        !joined.contains("query_facts"),
        "query_facts must not fire on the store path:\n{joined}"
    );
    // The save_session that does fire still carries no plaintext.
    assert!(
        !joined.contains(SECRET_MARKER) && !joined.contains("PII_MARKER"),
        "plaintext leaked on the flag-off path:\n{joined}"
    );
}
