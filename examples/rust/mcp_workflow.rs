// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Demonstrates the fact store + sync MCP tool workflow via the HTTP API.
//!
//! This example shows how to: store facts (including private), query by keyword,
//! list entities, export with pagination, and verify that private facts are
//! excluded from export — the same operations that the MCP `store_fact`,
//! `query_facts`, `list_entities`, and `sync_push` tools perform internally.
//!
//! Prerequisites: `corecruxd` running on `localhost:14800` (see README.md).
//!
//! ```bash
//! # Terminal 1 — start the daemon
//! CORECRUXD_DATA_DIR=./data ./target/release/corecruxd
//!
//! # Terminal 2 — run this example
//! cd examples/rust
//! cargo run --example mcp_workflow
//! ```

fn main() {
    let base = std::env::var("CORECRUX_URL").unwrap_or_else(|_| "http://localhost:14800".into());
    let agent = ureq::Agent::new_with_defaults();

    // ── 1. Health check ─────────────────────────────────────────────────
    println!("1. Health check...");
    let resp: serde_json::Value = agent
        .get(&format!("{base}/healthz"))
        .call()
        .expect("corecruxd not reachable — is it running on port 14800?")
        .body_mut()
        .read_json()
        .expect("invalid JSON from /healthz");
    println!("   status: {}", resp["status"]);

    // ── 2. Store 3 facts: 2 public, 1 private ──────────────────────────
    println!("\n2. Storing 3 facts (2 public, 1 private)...");

    let public_facts = vec![
        serde_json::json!({
            "entity": "project",
            "key": "language",
            "value": "The project is written in Rust with 17 workspace crates.",
            "confidence": 0.95
        }),
        serde_json::json!({
            "entity": "project",
            "key": "retrieval",
            "value": "Retrieval uses fused BM25 and graph signal scoring on the CPU path.",
            "confidence": 0.9
        }),
    ];

    let private_fact = serde_json::json!({
        "entity": "agent_notes",
        "key": "draft_plan",
        "value": "Internal draft: migrate storage layer to io_uring in Q3.",
        "confidence": 0.8,
        "private": true
    });

    let mut stored_ids: Vec<String> = Vec::new();

    for (i, body) in public_facts.iter().enumerate() {
        let resp: serde_json::Value = agent
            .put(&format!("{base}/v1/facts"))
            .send_json(body)
            .expect("fact store failed")
            .body_mut()
            .read_json()
            .expect("invalid JSON from PUT /v1/facts");
        let fid = resp["fact_id"].as_str().unwrap_or("unknown").to_string();
        println!("   public  fact {}: {} (entity={})", i + 1, fid, resp["entity"]);
        stored_ids.push(fid);
    }

    let resp: serde_json::Value = agent
        .put(&format!("{base}/v1/facts"))
        .send_json(&private_fact)
        .expect("private fact store failed")
        .body_mut()
        .read_json()
        .expect("invalid JSON from PUT /v1/facts");
    let private_id = resp["fact_id"].as_str().unwrap_or("unknown").to_string();
    println!("   private fact 3: {} (entity={}, private={})", private_id, resp["entity"], resp["private"]);
    stored_ids.push(private_id.clone());

    // ── 3. Query facts by keyword ───────────────────────────────────────
    println!("\n3. Querying facts for keyword 'Rust'...");
    let resp: serde_json::Value = agent
        .get(&format!("{base}/v1/facts?query=Rust&top_k=10"))
        .call()
        .expect("fact query failed")
        .body_mut()
        .read_json()
        .expect("invalid JSON from GET /v1/facts");
    let facts = resp["facts"].as_array().expect("expected facts array");
    println!("   matched: {} fact(s), total_tokens: {}", facts.len(), resp["total_tokens"]);
    for f in facts {
        println!(
            "     - [{}] {}/{} (confidence: {})",
            f["fact_id"].as_str().unwrap_or("?"),
            f["entity"].as_str().unwrap_or("?"),
            f["key"].as_str().unwrap_or("?"),
            f["confidence"]
        );
    }

    // ── 4. List entities (via query with no filter) ─────────────────────
    println!("\n4. Listing entities (query all facts, extract unique entities)...");
    let resp: serde_json::Value = agent
        .get(&format!("{base}/v1/facts?top_k=100"))
        .call()
        .expect("fact query failed")
        .body_mut()
        .read_json()
        .expect("invalid JSON from GET /v1/facts");
    let all_facts = resp["facts"].as_array().expect("expected facts array");
    let mut entities: Vec<String> = all_facts
        .iter()
        .filter_map(|f| f["entity"].as_str().map(String::from))
        .collect();
    entities.sort();
    entities.dedup();
    println!("   entities: {:?}", entities);

    // ── 5. Export facts (pagination) — private fact excluded ────────────
    println!("\n5. Exporting facts (limit=2 to show pagination)...");
    let resp: serde_json::Value = agent
        .get(&format!("{base}/v1/facts/export?limit=2"))
        .call()
        .expect("export failed")
        .body_mut()
        .read_json()
        .expect("invalid JSON from GET /v1/facts/export");

    let exported = resp["facts"].as_array().expect("expected facts array");
    let has_more = resp["has_more"].as_bool().unwrap_or(false);
    let next_cursor = resp["next_cursor"].as_str().unwrap_or("none");
    println!("   page 1: {} fact(s), has_more: {}, next_cursor: {}", exported.len(), has_more, next_cursor);
    for f in exported {
        println!(
            "     - [{}] {}/{} (private: {})",
            f["fact_id"].as_str().unwrap_or("?"),
            f["entity"].as_str().unwrap_or("?"),
            f["key"].as_str().unwrap_or("?"),
            f["private"]
        );
    }

    // Verify the private fact is absent from the full export
    println!("\n   Verifying private fact exclusion from export...");
    let resp: serde_json::Value = agent
        .get(&format!("{base}/v1/facts/export?limit=10000"))
        .call()
        .expect("export failed")
        .body_mut()
        .read_json()
        .expect("invalid JSON from GET /v1/facts/export");
    let all_exported = resp["facts"].as_array().expect("expected facts array");
    let private_in_export = all_exported
        .iter()
        .any(|f| f["fact_id"].as_str() == Some(private_id.as_str()));
    if private_in_export {
        println!("   FAIL: private fact {} found in export!", private_id);
    } else {
        println!("   OK: private fact {} correctly excluded from export.", private_id);
    }

    // ── 6. Summary ──────────────────────────────────────────────────────
    println!("\n6. Summary");
    println!("   Facts stored:      {} (2 public + 1 private)", stored_ids.len());
    println!("   Query hits:        {}", facts.len());
    println!("   Entities found:    {}", entities.len());
    println!("   Exported (page 1): {} fact(s)", exported.len());
    println!("   Private excluded:  {}", !private_in_export);
    println!(
        "\n   The MCP tools (store_fact, query_facts, list_entities, sync_push)"
    );
    println!("   use the same HTTP endpoints demonstrated above.");
    println!("\nDone.");
}
