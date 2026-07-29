// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Minimal HTTP example: probe runtime features, append if the dataplane is
//! enabled, store a fact, and query it back.
//!
//! Prerequisites: `corecruxd` running on `localhost:14800` (see README.md).
//!
//! ```bash
//! # Terminal 1 — start the daemon
//! CORECRUXD_AUTH_MODE=off CORECRUXD_DATA_DIR=./data ./target/release/corecruxd
//!
//! # Terminal 2 — run this example
//! cd examples/rust
//! cargo run --example append_and_query
//! ```

fn main() {
    let base = std::env::var("CORECRUX_URL").unwrap_or_else(|_| "http://localhost:14800".into());
    let agent = ureq::Agent::new_with_defaults();

    // ── 1. Health check ─────────────────────────────────────────────────
    println!("1. Checking health...");
    let resp: serde_json::Value = agent
        .get(&format!("{base}/healthz"))
        .call()
        .expect("corecruxd not reachable — is it running on port 14800?")
        .body_mut()
        .read_json()
        .expect("invalid JSON from /healthz");
    println!("   ok: {}", resp["ok"]);

    println!("2. Reading feature flags...");
    let version: serde_json::Value = agent
        .get(&format!("{base}/v1/version"))
        .call()
        .expect("version endpoint unavailable")
        .body_mut()
        .read_json()
        .expect("invalid JSON from /v1/version");
    let text_search_enabled = version["features"]["text_search"].as_bool().unwrap_or(false);
    println!(
        "   mcp={}, text_search={}",
        version["features"]["mcp"], version["features"]["text_search"]
    );

    // ── 3. Append two events when the dataplane is available ────────────
    println!("3. Attempting append via compatibility alias /v1/append...");
    let append_body = serde_json::json!({
        "tenant_id": "demo",
        "stream_type": "docs",
        "stream_id": "corecrux-demo",
        "events": [
            {
                "event_id": "evt-demo-1",
                "occurred_at": "2026-04-09T12:00:00Z",
                "event_type": "doc.created",
                "content_type": "text/plain",
                "payload": "CoreCrux provides append-only event storage with fused BM25 and graph signal retrieval."
            },
            {
                "event_id": "evt-demo-2",
                "occurred_at": "2026-04-09T12:00:01Z",
                "event_type": "doc.created",
                "content_type": "text/plain",
                "payload": "Every query result is signed with a CROWN receipt and every gap in coverage is reported."
            }
        ]
    });
    match agent.post(&format!("{base}/v1/append")).send_json(&append_body) {
        Ok(mut resp) => {
            let body: serde_json::Value = resp.body_mut().read_json().expect("invalid JSON from append");
            println!("   append response: {body}");
        }
        Err(ureq::Error::StatusCode(501)) => {
            println!("   append skipped: dataplane disabled in this deployment.");
        }
        Err(err) => panic!("append failed: {err}"),
    }

    // ── 4. Store a fact ─────────────────────────────────────────────────
    println!("4. Storing a fact...");
    let fact_body = serde_json::json!({
        "entity": "project",
        "key": "status",
        "value": "Phase 1 complete — 12 milestones delivered",
        "confidence": 0.95
    });
    let resp: serde_json::Value = agent
        .put(&format!("{base}/v1/facts"))
        .send_json(&fact_body)
        .expect("fact store failed")
        .body_mut()
        .read_json()
        .expect("invalid JSON from PUT /v1/facts");
    let fact_id = resp["fact_id"].as_str().unwrap_or("unknown");
    println!("   fact_id: {fact_id}");

    // ── 5. Query via BM25 text search when enabled ──────────────────────
    println!("5. Querying text search...");
    if text_search_enabled {
        let query_body = serde_json::json!({
            "tenant_id": "demo",
            "query": "coverage gap reporting",
            "limit": 5,
            "token_budget": 4000
        });
        let resp: serde_json::Value = agent
            .post(&format!("{base}/v1/query/text-search"))
            .send_json(&query_body)
            .expect("text search failed")
            .body_mut()
            .read_json()
            .expect("invalid JSON from /v1/query/text-search");
        let hits = resp["results"].as_array().map_or(0, |a| a.len());
        println!("   results: {hits}");
    } else {
        println!("   text search skipped: CORECRUXD_QUERY_TEXT_SEARCH is disabled.");
    }

    // ── 6. Retrieve the fact ────────────────────────────────────────────
    println!("6. Querying facts...");
    let resp: serde_json::Value = agent
        .get(&format!("{base}/v1/facts?query=project+status&token_budget=500"))
        .call()
        .expect("fact query failed")
        .body_mut()
        .read_json()
        .expect("invalid JSON from GET /v1/facts");
    let fact_count = resp["facts"].as_array().map_or(0, |a| a.len());
    println!("   facts returned: {fact_count}");

    println!("\nDone. All operations completed successfully.");
}
