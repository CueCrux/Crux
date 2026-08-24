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

struct IdentityMockHandle {
    url: String,
    join: thread::JoinHandle<Vec<(String, String)>>,
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

            let result = if held
                .iter()
                .any(|held_resource| held_resource_covers_request(held_resource, &resource))
            {
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

/// Enforcing identity-aware mock: `holder_token` sees its lease as self-held,
/// while a different bearer sees the same resource as held by another
/// passport. This mirrors the daemon's passport comparison without placing a
/// real credential in the fixture.
fn spawn_identity_mock(expected: usize, held_resource: String, holder_token: &str) -> IdentityMockHandle {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
    listener.set_nonblocking(true).expect("nonblocking listener");
    let port = listener.local_addr().unwrap().port();
    let holder_token = holder_token.to_string();

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
                Err(error) => panic!("identity mock accept failed: {error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("request read timeout");
            let request = read_request(&mut stream);
            let resource = requested_resource(&request);
            let bearer = requested_bearer(&request);
            let held_by_other = resource == held_resource && bearer != holder_token;
            captured.push((resource.clone(), bearer));

            let result = json!({
                "held_by_other": held_by_other,
                "enforce": true,
                "holder_passport": held_by_other.then_some("passport:worker-a"),
                "resource": resource,
            });
            let body = json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).expect("write response");
            stream.flush().expect("flush response");
        }
        assert_eq!(captured.len(), expected, "identity mock missed a probe");
        captured
    });

    IdentityMockHandle {
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

fn requested_bearer(request: &[u8]) -> String {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP headers");
    String::from_utf8_lossy(&request[..header_end])
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().strip_prefix("Bearer ").unwrap_or("").to_string())
        })
        .unwrap_or_default()
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

#[cfg(unix)]
fn run_enforcement_wrapper(
    input: &Value,
    mcp_url: &str,
    process_token: Option<&str>,
    agent_name: &str,
    named_token: Option<&str>,
) -> Output {
    use std::os::unix::fs::symlink;

    let home = tempfile::tempdir().unwrap();
    let bin_dir = home.path().join(".local/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    symlink(env!("CARGO_BIN_EXE_crux-hook"), bin_dir.join("crux-hook")).unwrap();
    let config_dir = home.path().join(".config/cuecrux");
    let token_dir = config_dir.join("crux-tokens");
    std::fs::create_dir_all(&token_dir).unwrap();
    // The shared env intentionally carries a different identity. The wrapper
    // must preserve the per-process name/token or select that name's file.
    std::fs::write(
        config_dir.join("env"),
        "CRUX_AGENT_TOKEN=synthetic-shared-env-token\nCRUX_CODEX_AGENT_NAME=shared-env-agent\nCRUX_MCP_URL=http://127.0.0.1:1/mcp\nCRUX_AGENT_TOKEN_DIR=/does/not/exist\nCRUX_HOOK_OBSERVE_CAPTURE=1\n",
    )
    .unwrap();
    if let Some(named_token) = named_token {
        std::fs::write(token_dir.join(format!("{agent_name}.mcp-token")), named_token).unwrap();
    }
    let wrapper =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../integrations/codex-cli/hooks/crux-enforce.sh");
    let mut command = Command::new("bash");
    command
        .arg(wrapper)
        .env("HOME", home.path())
        .env("CRUX_CODEX_AGENT_NAME", agent_name)
        .env("CRUX_MCP_URL", mcp_url)
        .env("CRUX_AGENT_TOKEN_DIR", &token_dir)
        .env("CRUX_HOOK_OBSERVE_CAPTURE", "0")
        .env_remove("CRUX_HOOKS_ENV")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(token) = process_token {
        command.env("CRUX_AGENT_TOKEN", token);
    } else {
        command.env_remove("CRUX_AGENT_TOKEN");
    }
    let mut child = command.spawn().expect("spawn enforcement wrapper");
    child
        .stdin
        .take()
        .expect("wrapper stdin")
        .write_all(input.to_string().as_bytes())
        .expect("write wrapper input");
    child.wait_with_output().expect("wait for enforcement wrapper")
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

fn held_resource_covers_request(held: &str, request: &str) -> bool {
    if held == request {
        return true;
    }
    let Some(tree) = held.strip_prefix("tree://") else {
        return false;
    };
    let Some(path) = request
        .strip_prefix("file://")
        .or_else(|| request.strip_prefix("tree://"))
    else {
        return false;
    };
    let tree = tree.trim_end_matches('/');
    path == tree || path.strip_prefix(tree).is_some_and(|suffix| suffix.starts_with('/'))
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
fn absolute_file_probe_is_denied_by_enclosing_absolute_tree_lease() {
    let root = tempfile::tempdir().unwrap();
    let target = resource(&root.path().join("nested/new.rs"));
    let tree = format!("tree://{}", root.path().display());
    let mock = spawn_mock(1, &[tree], &[]);
    let input = codex_input(
        root.path(),
        "*** Begin Patch\n*** Add File: nested/new.rs\n+new\n*** End Patch".to_string(),
    );
    let output = run_hook(&input, &mock.url);
    let captured = mock.join.join().unwrap();
    let value = decision(&output);

    assert_eq!(captured, [target.clone()]);
    assert!(
        target.starts_with("file:///"),
        "probe must use an absolute file resource"
    );
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(value["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains(&target));
}

#[cfg(unix)]
#[test]
fn distinct_codex_worker_tokens_distinguish_self_from_peer_lease() {
    let root = tempfile::tempdir().unwrap();
    let target = resource(&root.path().join("shared.rs"));
    let holder_token = "synthetic-token-worker-a";
    let peer_token = "synthetic-token-worker-b";
    let mock = spawn_identity_mock(2, target.clone(), holder_token);
    let patch = "*** Begin Patch\n*** Add File: shared.rs\n+new\n*** End Patch".to_string();
    let input = codex_input(root.path(), patch);

    let own = run_enforcement_wrapper(&input, &mock.url, Some(holder_token), "worker-a", None);
    let peer = run_enforcement_wrapper(&input, &mock.url, Some(peer_token), "worker-b", None);
    let captured = mock.join.join().unwrap();

    assert!(own.status.success());
    assert!(own.stdout.is_empty(), "a holder must not conflict with its own lease");
    let peer_decision = decision(&peer);
    assert_eq!(peer_decision["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        captured,
        [
            (target.clone(), holder_token.to_string()),
            (target, peer_token.to_string())
        ]
    );
    for output in [&own, &peer] {
        let visible = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!visible.contains(holder_token));
        assert!(!visible.contains(peer_token));
        assert!(!visible.contains("synthetic-shared-env-token"));
    }
}

#[cfg(unix)]
#[test]
fn named_worker_token_and_name_override_the_shared_env_identity() {
    let root = tempfile::tempdir().unwrap();
    let target = resource(&root.path().join("named.rs"));
    let named_token = "synthetic-named-worker-token";
    let mock = spawn_identity_mock(1, target.clone(), named_token);
    let input = codex_input(
        root.path(),
        "*** Begin Patch\n*** Add File: named.rs\n+new\n*** End Patch".to_string(),
    );

    let output = run_enforcement_wrapper(&input, &mock.url, None, "worker-named", Some(named_token));
    let captured = mock.join.join().unwrap();

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(captured, [(target, named_token.to_string())]);
    assert!(!String::from_utf8_lossy(&output.stderr).contains(named_token));
}

#[cfg(unix)]
#[test]
fn enforcement_wrapper_without_selected_token_fails_open_before_hook() {
    let root = tempfile::tempdir().unwrap();
    let input = codex_input(
        root.path(),
        "*** Begin Patch\n*** Add File: unleased.rs\n+new\n*** End Patch".to_string(),
    );
    let output = run_enforcement_wrapper(&input, "http://127.0.0.1:1/mcp", None, "missing-worker", None);

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("enforcement is fail-open"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-shared-env-token"));
}

#[cfg(unix)]
#[test]
fn enforcement_wrapper_rejects_unsafe_or_overlong_agent_names_without_running_hook() {
    let root = tempfile::tempdir().unwrap();
    let input = codex_input(
        root.path(),
        "*** Begin Patch\n*** Add File: unleased.rs\n+new\n*** End Patch".to_string(),
    );
    let overlong = "a".repeat(65);
    for name in ["../escape", overlong.as_str()] {
        let output = run_enforcement_wrapper(
            &input,
            "http://127.0.0.1:1/mcp",
            Some("synthetic-must-not-be-used"),
            name,
            None,
        );
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("invalid CRUX_CODEX_AGENT_NAME"));
        assert!(!stderr.contains("synthetic-must-not-be-used"));
        assert!(!stderr.contains("synthetic-shared-env-token"));
    }
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
