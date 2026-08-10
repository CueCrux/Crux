// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

#![deny(clippy::unwrap_used)]
// CLI tool — printing to stdout/stderr is correct behaviour.
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! `corecruxctl` — CLI tool for Crux Daemon operations.
//!
//! Subcommands cover admin tasks (segment fingerprints, projection meta,
//! shard map, force-seal), receipt verification + export, audit packs,
//! benchmark drivers, parity smoke tests, replay tooling, and daemon-facing
//! onboarding commands. Trust tools such as replay and store verification stay
//! offline; commands such as ingest, memory, and repo registration use the
//! daemon's authenticated HTTP surface.
//!
//! See `corecruxctl --help` for the live subcommand listing.

pub mod admin;
pub mod agent_wiring;
pub mod attest_companions;
pub mod audit_export;
pub mod audit_pack;
pub mod benchmark;
pub mod c2pa_x509;
pub mod code_chain;
pub mod code_health;
pub mod compaction_sync;
pub mod config_bundle;
pub mod cost;
pub mod deploy_audit;
pub mod evidence;
pub mod explain;
pub mod export;
pub mod extensions;
pub mod fixture_digest;
pub mod gaps;
pub mod hooks;
pub mod identity_cli;
pub mod incident;
pub mod ingest;
pub mod inspect_receipt;
pub mod learn;
pub mod login;
pub mod machine;
pub mod memory;
pub mod memory_pack;
pub mod observe_ingest;
pub mod openclaw;
pub mod ops;
pub mod output_verify;
pub mod parity;
pub mod projections;
pub mod quickstart;
pub mod receipts;
pub mod reconcile;
pub mod repair_manifest;
pub mod replay;
pub mod repo;
pub mod session_sync;
pub mod shard;
pub mod shardmap;
pub mod smoke;
pub mod snapshot;
pub mod stage1_import;
pub mod start;
pub mod storage;
pub mod structured_log;
pub mod studio;
pub mod tooling_env;
pub mod verify_escrow;
pub mod verify_store;

#[cfg(test)]
pub(crate) mod test_support {
    /// Read one full HTTP request (headers + `Content-Length` body) from an
    /// accepted loopback-mock stream. Mirrors
    /// `crux_mcp::tools::test_support::read_full_request` — see incident
    /// 2026-06-12: accepted sockets inherit `O_NONBLOCK` from a nonblocking
    /// listener on BSD/macOS, so a single `read()` can return `WouldBlock`,
    /// look like an empty request, and the mock's reply+close races the
    /// client's in-flight write (EPIPE/EINVAL on macOS; broke the v0.5.3
    /// darwin-amd64 release build at corecruxctl's benchmark mock).
    pub(crate) fn read_full_request(stream: &mut std::net::TcpStream) -> String {
        use std::io::Read;
        stream.set_nonblocking(false).ok();
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).ok();
        let mut data = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break, // EOF or timeout
                Ok(n) => {
                    data.extend_from_slice(&buf[..n]);
                    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&data[..pos]);
                        let content_len = headers
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    v.trim().parse::<usize>().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        if data.len() >= pos + 4 + content_len {
                            break;
                        }
                    }
                    if data.len() > (1 << 20) {
                        break;
                    }
                }
            }
        }
        String::from_utf8_lossy(&data).into_owned()
    }

    /// Spawn a loopback HTTP stub that answers a fixed sequence of responses,
    /// one per accepted connection, and captures each raw request. Returns the
    /// bound port plus a join handle that yields the captured requests in
    /// arrival order. Each response sends `Connection: close` so `ureq` opens a
    /// fresh connection per request (keeps the accept loop in lock-step with
    /// the client's call sequence). `responses` is `(status_code, body)`.
    pub(crate) fn serve_responses(responses: Vec<(u16, String)>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        use std::io::Write as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let port = listener.local_addr().expect("addr").port();
        let handle = std::thread::spawn(move || {
            let mut captured = Vec::new();
            let mut pending = responses.into_iter();
            let Some(mut current) = pending.next() else {
                return captured;
            };
            loop {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let request = read_full_request(&mut stream);
                if request.is_empty() {
                    // A connection that carried no request: a pooled socket the
                    // client opened and dropped, or a stray probe. Consuming a
                    // scripted response for it shifts every later response by
                    // one and ends the loop early, so the next real request
                    // finds nothing listening and fails with ConnectionRefused
                    // -- which reads as an unrelated flake. Don't count it.
                    continue;
                }
                captured.push(request);
                let (status, body) = (current.0, &current.1);
                let resp = format!(
                    "HTTP/1.1 {status} S\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
                match pending.next() {
                    Some(next) => current = next,
                    None => break,
                }
            }
            captured
        });
        (port, handle)
    }

    #[cfg(test)]
    mod tests {
        use std::io::{Read as _, Write as _};

        #[test]
        fn a_connection_carrying_no_request_does_not_consume_a_response() {
            let (port, handle) = super::serve_responses(vec![(200, r#"{"ok":true}"#.to_string())]);

            // Phantom connection: connect, send nothing, close.
            drop(std::net::TcpStream::connect(("127.0.0.1", port)).expect("phantom connect"));

            // The single scripted response must still be waiting for the real
            // request. Before the guard, the phantom consumed it, the accept
            // loop ended, and this connect failed with ConnectionRefused.
            let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("real connect");
            stream
                .write_all(b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")
                .expect("write request");
            let mut response = String::new();
            stream.read_to_string(&mut response).expect("read response");
            assert!(response.contains("200"), "real request got: {response}");

            let captured = handle.join().expect("join stub");
            assert_eq!(captured.len(), 1, "only the real request should be captured");
        }
    }
}
