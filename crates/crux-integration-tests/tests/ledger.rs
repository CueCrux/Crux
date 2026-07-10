// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Action-ledger integration tests (ExecPlan
//! crux-agent-action-ledger-token-accounting-2026-06-11, M2 gate).
//!
//! Proves that on a **CPU-only build** an MCP `tools/call` produces a
//! readable, fully-populated `agent.tool_invocation.v1` event on the
//! observations stream when `CORECRUXD_FEATURE_TOOL_LEDGER=1`, and
//! exactly zero events when the flag is off.
//!
//! Both daemons run inside ONE test function: the flag is delivered via
//! inherited process env at spawn time, and Rust tests in this binary
//! would otherwise race the env mutation.

use std::time::{Duration, Instant};

use crux_integration_tests::TestDaemon;
use serde_json::json;

const FLAG: &str = "CORECRUXD_FEATURE_TOOL_LEDGER";
const LEDGER_SESSION_PATH: &str = "/v1/sessions/ledger::__anon__/observations";

fn tool_call_body(id: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "store_fact",
            "arguments": {
                "entity": "ledger-it",
                "key": "probe",
                "value": "ledger integration probe",
                "token_budget": 500
            }
        }
    })
}

fn read_ledger_events(daemon: &TestDaemon) -> Vec<serde_json::Value> {
    let resp = match daemon.get(LEDGER_SESSION_PATH) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    if resp.status().as_u16() != 200 {
        return Vec::new();
    }
    let body: serde_json::Value = match resp.into_body().read_json() {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    body["observations"]
        .as_array()
        .or_else(|| body["records"].as_array())
        .or_else(|| body.as_array())
        .cloned()
        .unwrap_or_default()
}

#[test]
fn ledger_flag_controls_tool_invocation_events() {
    // The spawned daemon inherits this process's env. A developer
    // workstation may carry CRUX_AGENT_TOKEN, which would force MCP
    // bearer auth and 401 the anon tools/call this test exercises —
    // scrub it (this file is its own test binary with a single test,
    // so the env mutation races nothing).
    std::env::remove_var("CRUX_AGENT_TOKEN");

    // ── Arm 1: flag ON ────────────────────────────────────────────────
    std::env::set_var(FLAG, "1");
    let daemon_on = TestDaemon::start();
    std::env::remove_var(FLAG);

    let resp = daemon_on
        .mcp_post_json(tool_call_body("ledger-on-1"))
        .expect("MCP call");
    assert_eq!(resp.status().as_u16(), 200);

    // The append is fire-and-forget — poll for it.
    let deadline = Instant::now() + Duration::from_secs(10);
    let event = loop {
        let events: Vec<_> = read_ledger_events(&daemon_on)
            .into_iter()
            .filter(|o| o["kind"] == "agent.tool_invocation.v1")
            .collect();
        if let Some(e) = events.into_iter().find(|o| o["payload"]["tool"] == "store_fact") {
            break e;
        }
        assert!(
            Instant::now() < deadline,
            "no agent.tool_invocation.v1 event for store_fact within 10s; got: {:?}",
            read_ledger_events(&daemon_on)
        );
        std::thread::sleep(Duration::from_millis(150));
    };

    // Field population (M2 gate: readable + populated + attributed).
    assert_eq!(event["provider"], "crux-mcp");
    assert_eq!(event["principal"].as_str().is_some(), true, "CROWN principal present");
    let p = &event["payload"];
    assert_eq!(p["passport"], "__anon__", "anon sentinel attribution (QC.3)");
    assert_eq!(p["outcome"], "ok");
    assert!(
        p["args_hash"].as_str().unwrap_or_default().starts_with("blake3:"),
        "args_hash: {p}"
    );
    assert!(p.get("args_raw").is_none(), "raw args must not be captured by default");
    assert!(p["est_tokens_in"].as_u64().unwrap_or(0) >= 1);
    assert!(p["est_tokens_out"].as_u64().unwrap_or(0) >= 1);
    assert!(p["result_bytes"].as_u64().unwrap_or(0) >= 1);
    assert_eq!(p["token_budget_in"], 500);
    assert!(p["latency_ms"].as_u64().is_some());
    assert_eq!(p["request_id"], "ledger-on-1");
    assert!(p["predicted_effects"]
        .as_array()
        .map(|a| !a.is_empty())
        .unwrap_or(false));

    // Per-tool metrics are scrapeable on the same (CPU) build.
    let metrics_text = daemon_on
        .get("/metrics")
        .expect("metrics scrape")
        .into_body()
        .read_to_string()
        .expect("metrics body");
    assert!(
        metrics_text.contains("corecrux_tool_invocation_duration_seconds"),
        "per-tool latency histogram registered"
    );
    assert!(
        metrics_text.contains("corecrux_token_spend_total"),
        "token spend counter registered"
    );

    drop(daemon_on);

    // ── Arm 2: flag OFF (default) ─────────────────────────────────────
    std::env::remove_var(FLAG);
    let daemon_off = TestDaemon::start();
    let resp = daemon_off
        .mcp_post_json(tool_call_body("ledger-off-1"))
        .expect("MCP call");
    assert_eq!(resp.status().as_u16(), 200);
    // Give a would-be fire-and-forget write ample time to land, then
    // assert nothing did.
    std::thread::sleep(Duration::from_millis(750));
    let events = read_ledger_events(&daemon_off);
    assert!(
        events.is_empty(),
        "flag OFF must produce zero ledger events, got: {events:?}"
    );
}
