// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Process-level fixtures for native Codex `apply_patch` enforcement.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

struct MockHandle {
    url: String,
    join: thread::JoinHandle<Vec<String>>,
}

/// Multi-request MCP mock. Responses are selected by the requested punchcard
/// resource so concurrent arrival order cannot change the fixture.
fn spawn_mock(expected: usize, held: &[String], dropped: &[String]) -> MockHandle {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
    listener.set_nonblocking(true).expect("nonblocking listener");
    let port = listener.local_addr().unwrap().port();
    let held = held.iter().cloned().collect::<HashSet<_>>();
    let dropped = dropped.iter().cloned().collect::<HashSet<_>>();

    let join = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut captured = Vec::new();
        while captured.len() < expected && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("mock accept failed: {error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("request read timeout");
            let request = read_request(&mut stream);
            let resource = requested_resource(&request);
            captured.push(resource.clone());

            if dropped.contains(&resource) {
                continue;
            }

            let result = if held.contains(&resource) {
                json!({
                    "held_by_other": true,
                    "enforce": true,
                    "holder_passport": format!("holder:{resource}"),
                    "resource": resource,
                })
            } else {
                json!({"held_by_other": false, "enforce": true, "resource": resource})
            };
            let body = json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).expect("write response");
            stream.flush().expect("flush response");
        }
        assert_eq!(captured.len(), expected, "mock did not receive every expected probe");
        captured
    });

    MockHandle {
        url: format!("http://127.0.0.1:{port}/mcp"),
        join,
    }
}

fn read_request(stream: &mut impl Read) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    let mut header_end = None;
    loop {
        let count = stream.read(&mut chunk).expect("read headers");
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = Some(position + 4);
            break;
        }
    }

    if let Some(end) = header_end {
        let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
        let body_len = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while bytes.len() < end + body_len {
            let count = stream.read(&mut chunk).expect("read body");
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
    }
    bytes
}

fn requested_resource(request: &[u8]) -> String {
    let body = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| &request[position + 4..])
        .expect("HTTP body");
    let value: Value = serde_json::from_slice(body).expect("JSON-RPC request");
    value["params"]["arguments"]["resource"]
        .as_str()
        .expect("punchcard resource")
        .to_string()
}

fn run_hook(input: &Value, mcp_url: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_crux-hook"))
        .arg("observe-pre")
        .env("CRUX_MCP_URL", mcp_url)
        .env("CRUX_HOOK_OBSERVE_CAPTURE", "0")
        .env_remove("CRUX_AGENT_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn crux-hook");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(input.to_string().as_bytes())
        .expect("write hook input");
    child.wait_with_output().expect("wait for crux-hook")
}

fn codex_input(cwd: &std::path::Path, command: String) -> Value {
    json!({
        "session_id": "codex-e2e",
        "transcript_path": null,
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "tool_input": {"command": command},
    })
}

fn resource(path: &std::path::Path) -> String {
    format!("file://{}", path.display())
}

fn decision(output: &Output) -> Value {
    assert!(output.status.success(), "hook must always exit zero: {output:?}");
    serde_json::from_slice(&output.stdout).expect("structured hook decision")
}

#[test]
fn conflict_free_codex_patch_emits_zero_stdout() {
    let root = tempfile::tempdir().unwrap();
    let target = resource(&root.path().join("new.rs"));
    let mock = spawn_mock(1, &[], &[]);
    let input = codex_input(
        root.path(),
        "*** Begin Patch\n*** Add File: new.rs\n+new\n*** End Patch".to_string(),
    );
    let output = run_hook(&input, &mock.url);
    let captured = mock.join.join().unwrap();

    assert!(output.status.success());
    assert!(output.stdout.is_empty(), "Codex success must emit zero bytes");
    assert!(output.stderr.is_empty());
    assert_eq!(captured, [target]);
}

#[test]
fn add_update_delete_and_both_move_endpoints_are_probed_and_denied() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("update.rs"), "old").unwrap();
    std::fs::write(root.path().join("delete.rs"), "old").unwrap();
    std::fs::write(root.path().join("move.rs"), "old").unwrap();
    let paths =
        ["add.rs", "update.rs", "delete.rs", "move.rs", "moved.rs"].map(|name| resource(&root.path().join(name)));
    let mock = spawn_mock(paths.len(), &paths, &[]);
    let patch = "*** Begin Patch\n*** Add File: add.rs\n+new\n*** Update File: update.rs\n@@\n-old\n+new\n*** Delete File: delete.rs\n*** Update File: move.rs\n*** Move to: moved.rs\n-old\n+new\n*** End Patch";
    let output = run_hook(&codex_input(root.path(), patch.to_string()), &mock.url);
    let captured = mock.join.join().unwrap().into_iter().collect::<HashSet<_>>();
    let value = decision(&output);

    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    for path in &paths {
        assert!(captured.contains(path), "missing probe for {path}");
        assert!(
            value["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains(path),
            "denial did not name {path}"
        );
    }
}

#[test]
fn codex_whitespace_normalization_uses_the_same_add_and_move_resources() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("move.rs"), "old").unwrap();
    let add = resource(&root.path().join("add.rs"));
    let source = resource(&root.path().join("move.rs"));
    let destination = resource(&root.path().join("moved.rs"));
    let expected = [add.clone(), source.clone(), destination.clone()];
    let mock = spawn_mock(expected.len(), &[add.clone(), destination.clone()], &[]);
    let patch = "*** Begin Patch\n*** Add File: a\td\rd.rs \t\u{00a0}\n+new\n*** Update File: mo\tv\re.rs \t\n*** Move to: mo\tv\red.rs \t\u{00a0}\n-old\n+new\n*** End Patch";
    let output = run_hook(&codex_input(root.path(), patch.to_string()), &mock.url);
    let captured = mock.join.join().unwrap().into_iter().collect::<HashSet<_>>();
    let value = decision(&output);
    let reason = value["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();

    assert_eq!(captured, expected.into_iter().collect());
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(reason.contains(&add));
    assert!(reason.contains(&destination));
}

#[test]
fn all_three_waves_run_after_error_and_conflicts_stay_in_patch_order() {
    let root = tempfile::tempdir().unwrap();
    let mut sections = String::new();
    let mut resources = Vec::new();
    for index in 1..=24 {
        writeln!(&mut sections, "*** Add File: {index}.rs\n+{index}").unwrap();
        resources.push(resource(&root.path().join(format!("{index}.rs"))));
    }
    let patch = format!("*** Begin Patch\n{sections}*** End Patch");
    let held = [resources[8].clone(), resources[23].clone()];
    let dropped = [resources[0].clone()];
    let mock = spawn_mock(24, &held, &dropped);
    let output = run_hook(&codex_input(root.path(), patch), &mock.url);
    let captured = mock.join.join().unwrap().into_iter().collect::<HashSet<_>>();
    let value = decision(&output);
    let reason = value["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();

    assert_eq!(captured.len(), 24, "every target across three waves must be checked");
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(reason.find(&held[0]).unwrap() < reason.find(&held[1]).unwrap());
}

#[test]
fn all_transport_errors_remain_fail_open_no_decision() {
    let root = tempfile::tempdir().unwrap();
    let resources = [resource(&root.path().join("a.rs")), resource(&root.path().join("b.rs"))];
    let mock = spawn_mock(2, &[], &resources);
    let patch = "*** Begin Patch\n*** Add File: a.rs\n+a\n*** Add File: b.rs\n+b\n*** End Patch";
    let output = run_hook(&codex_input(root.path(), patch.to_string()), &mock.url);
    let captured = mock.join.join().unwrap();

    assert_eq!(captured.len(), 2);
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn malformed_codex_patch_denies_without_daemon() {
    let root = tempfile::tempdir().unwrap();
    let output = run_hook(
        &codex_input(root.path(), "not a canonical patch".to_string()),
        "http://127.0.0.1:1/mcp",
    );
    let value = decision(&output);

    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(value["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains("malformed apply_patch envelope"));
}

#[test]
fn claude_allow_and_deny_envelopes_are_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("claude.rs");
    std::fs::write(&path, "old").unwrap();
    let target = resource(&path);
    let input = json!({
        "session_id": "claude-e2e",
        "transcript_path": "",
        "cwd": root.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {"file_path": path},
    });

    let free = spawn_mock(1, &[], &[]);
    let free_output = run_hook(&input, &free.url);
    free.join.join().unwrap();
    assert_eq!(
        decision(&free_output),
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": ""
            }
        })
    );

    let held = spawn_mock(1, std::slice::from_ref(&target), &[]);
    let held_output = run_hook(&input, &held.url);
    held.join.join().unwrap();
    let value = decision(&held_output);
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(value["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains(&target));
}
