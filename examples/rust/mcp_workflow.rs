// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Demonstrates the built-in MCP endpoint with fact, entity, and session tools.
//!
//! This example shows how to:
//! - discover the MCP server
//! - list tools
//! - store public facts
//! - optionally store a private fact when `CRUX_AGENT_TOKEN` is configured
//! - query facts and list entities
//! - save and retrieve session state through MCP
//!
//! Prerequisites:
//! - `corecruxd` running with the built-in MCP server on `localhost:14801`
//! - optionally, `CRUX_AGENT_TOKEN` configured on both the server and client to
//!   exercise private facts
//!
//! ```bash
//! # Terminal 1 — start the daemon
//! CORECRUXD_AUTH_MODE=off CORECRUXD_DATA_DIR=./data ./target/release/corecruxd
//!
//! # Terminal 2 — run this example
//! cd examples/rust
//! cargo run --example mcp_workflow
//! ```

fn main() {
    let mcp_url = std::env::var("CORECRUX_MCP_URL").unwrap_or_else(|_| "http://localhost:14801/mcp".into());
    let agent_token = std::env::var("CRUX_AGENT_TOKEN").ok();
    let agent = ureq::Agent::new_with_defaults();

    // ── 1. Server info ──────────────────────────────────────────────────
    println!("1. MCP server info...");
    let resp: serde_json::Value = agent
        .get(&mcp_url)
        .call()
        .expect("MCP endpoint not reachable — is corecruxd running on port 14801?")
        .body_mut()
        .read_json()
        .expect("invalid JSON from GET /mcp");
    println!(
        "   server={} protocol={}",
        resp["serverInfo"]["name"], resp["protocolVersion"]
    );

    // ── 2. List tools ───────────────────────────────────────────────────
    println!("\n2. Listing tools...");
    let tools: serde_json::Value = mcp_post(
        &agent,
        &mcp_url,
        agent_token.as_deref(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }),
    );
    let tool_count = tools["result"]["tools"].as_array().map_or(0, |items| items.len());
    println!("   tool_count: {tool_count}");

    // ── 3. Store public facts ───────────────────────────────────────────
    println!("\n3. Storing public facts...");
    for body in [
        serde_json::json!({
            "entity": "project",
            "key": "language",
            "value": "The project is written in Rust with multiple workspace crates.",
            "confidence": 0.95
        }),
        serde_json::json!({
            "entity": "project",
            "key": "retrieval",
            "value": "Retrieval uses fused BM25 and graph signal scoring on the CPU path.",
            "confidence": 0.9
        }),
    ] {
        let resp = mcp_tool_call(&agent, &mcp_url, agent_token.as_deref(), "store_fact", body);
        println!("   {}", content_text(&resp));
    }

    // ── 4. Optionally store a private fact ──────────────────────────────
    println!("\n4. Storing a private fact...");
    if let Some(token) = agent_token.as_deref() {
        let resp = mcp_tool_call(
            &agent,
            &mcp_url,
            Some(token),
            "store_fact",
            serde_json::json!({
                "entity": "agent_notes",
                "key": "draft_plan",
                "value": "Internal draft: migrate storage layer to io_uring in Q3.",
                "confidence": 0.8,
                "private": true
            }),
        );
        println!("   {}", content_text(&resp));
    } else {
        println!("   skipped: set CRUX_AGENT_TOKEN to exercise private MCP facts.");
    }

    // ── 5. Query facts by keyword ───────────────────────────────────────
    println!("\n5. Querying facts for keyword 'Rust'...");
    let resp = mcp_tool_call(
        &agent,
        &mcp_url,
        agent_token.as_deref(),
        "query_facts",
        serde_json::json!({
            "query": "Rust",
            "top_k": 10
        }),
    );
    println!("   {}", content_text(&resp));

    // ── 6. List visible entities ────────────────────────────────────────
    println!("\n6. Listing entities...");
    let resp = mcp_tool_call(
        &agent,
        &mcp_url,
        agent_token.as_deref(),
        "list_entities",
        serde_json::json!({}),
    );
    println!("   {}", content_text(&resp));

    // ── 7. Save and read a session via MCP ──────────────────────────────
    println!("\n7. Saving and retrieving session state...");
    let resp = mcp_tool_call(
        &agent,
        &mcp_url,
        agent_token.as_deref(),
        "save_session",
        serde_json::json!({
            "session_id": "demo-session",
            "state": {
                "decisions": ["Use MCP for agent-private memory"],
                "open_questions": ["Should we enable authenticated MCP in dev?"]
            }
        }),
    );
    println!("   {}", content_text(&resp));

    let resp = mcp_tool_call(
        &agent,
        &mcp_url,
        agent_token.as_deref(),
        "get_session",
        serde_json::json!({
            "session_id": "demo-session"
        }),
    );
    println!("   session: {}", content_text(&resp));

    println!("\nDone.");
}

fn mcp_tool_call(
    agent: &ureq::Agent,
    mcp_url: &str,
    agent_token: Option<&str>,
    tool_name: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    mcp_post(
        agent,
        mcp_url,
        agent_token,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }),
    )
}

fn mcp_post(
    agent: &ureq::Agent,
    mcp_url: &str,
    agent_token: Option<&str>,
    body: serde_json::Value,
) -> serde_json::Value {
    let request = agent.post(mcp_url);
    let mut response = match agent_token {
        Some(token) => request
            .header("Authorization", format!("Bearer {token}"))
            .send_json(&body),
        None => request.send_json(&body),
    }
    .expect("MCP request failed");
    response.body_mut().read_json().expect("invalid MCP JSON response")
}

fn content_text(resp: &serde_json::Value) -> &str {
    resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("<missing content>")
}
