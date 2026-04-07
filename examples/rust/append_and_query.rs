// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Minimal example: append events, store a fact, and query both.
//!
//! Prerequisites: `corecruxd` running on `localhost:14800` (see README.md).
//!
//! ```bash
//! # Terminal 1 — start the daemon
//! CORECRUXD_DATA_DIR=./data ./target/release/corecruxd
//!
//! # Terminal 2 — run this example
//! cd examples/rust
//! cargo run --example append_and_query
//! ```

fn main() {
    let base = std::env::var("CORECRUX_URL").unwrap_or_else(|_| "http://localhost:14800".into());
    let agent = ureq::Agent::new();

    // ── 1. Health check ─────────────────────────────────────────────────
    println!("1. Checking health...");
    let resp: serde_json::Value = agent
        .get(&format!("{base}/healthz"))
        .call()
        .expect("corecruxd not reachable — is it running on port 14800?")
        .body_mut()
        .read_json()
        .expect("invalid JSON from /healthz");
    println!("   status: {}", resp["status"]);

    // ── 2. Append two events ────────────────────────────────────────────
    println!("2. Appending events...");
    let append_body = serde_json::json!({
        "stream_id": "docs",
        "events": [
            {
                "event_type": "doc.created",
                "content_type": "text/plain",
                "payload": "CoreCrux provides append-only event storage with fused BM25 and graph signal retrieval."
            },
            {
                "event_type": "doc.created",
                "content_type": "text/plain",
                "payload": "Every query result is signed with a CROWN receipt and every gap in coverage is reported."
            }
        ]
    });
    let resp: serde_json::Value = agent
        .post(&format!("{base}/v1/append"))
        .send_json(&append_body)
        .expect("append failed")
        .body_mut()
        .read_json()
        .expect("invalid JSON from /v1/append");
    println!(
        "   appended: {} events",
        resp["results"].as_array().map_or(0, |a| a.len())
    );

    // ── 3. Store a fact ─────────────────────────────────────────────────
    println!("3. Storing a fact...");
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

    // ── 4. Query via BM25 text search ───────────────────────────────────
    println!("4. Querying text search...");
    let query_body = serde_json::json!({
        "query": "coverage gap reporting",
        "top_k": 5,
        "token_budget": 4000
    });
    let resp: serde_json::Value = agent
        .post(&format!("{base}/v1/query/text-search"))
        .send_json(&query_body)
        .expect("text search failed")
        .body_mut()
        .read_json()
        .expect("invalid JSON from /v1/query/text-search");
    let hits = resp["hits"].as_array().map_or(0, |a| a.len());
    println!("   hits: {hits}");

    // ── 5. Retrieve the fact ────────────────────────────────────────────
    println!("5. Querying facts...");
    let resp: serde_json::Value = agent
        .get(&format!(
            "{base}/v1/facts?query=project+status&token_budget=500"
        ))
        .call()
        .expect("fact query failed")
        .body_mut()
        .read_json()
        .expect("invalid JSON from GET /v1/facts");
    let fact_count = resp["facts"].as_array().map_or(0, |a| a.len());
    println!("   facts returned: {fact_count}");

    println!("\nDone. All operations completed successfully.");
}
