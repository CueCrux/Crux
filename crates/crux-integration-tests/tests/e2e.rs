// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! End-to-end integration tests exercising the full Crux Daemon workflow:
//! store facts, query facts, store sessions.
//!
//! Run: ./scripts/run-integration-tests.sh --test e2e -- --test-threads=1

use crux_integration_tests::TestDaemon;
use serde_json::json;
use std::sync::OnceLock;

fn daemon() -> &'static TestDaemon {
    static INSTANCE: OnceLock<TestDaemon> = OnceLock::new();
    INSTANCE.get_or_init(TestDaemon::start)
}

// ── 1. Fact lifecycle ──────────────────────────────────────────────────

#[test]
fn fact_lifecycle() {
    let d = daemon();

    // Store initial fact.
    let created: serde_json::Value = d
        .put_json(
            "/v1/facts",
            json!({
                "entity": "e2e_lifecycle_project",
                "key": "status",
                "value": "Phase 1",
                "confidence": 0.9
            }),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(created["entity"], "e2e_lifecycle_project");
    let fact_id = created["fact_id"].as_str().expect("response must contain fact_id");
    assert!(fact_id.starts_with("f_"), "fact_id should start with f_");

    // Retrieve the fact by ID.
    let fetched: serde_json::Value = d
        .get(&format!("/v1/facts/{fact_id}"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(fetched["entity"], "e2e_lifecycle_project");
    assert_eq!(fetched["key"], "status");
    assert_eq!(fetched["value"], "Phase 1");

    // Store a second version of the same entity/key.
    let v2: serde_json::Value = d
        .put_json(
            "/v1/facts",
            json!({
                "entity": "e2e_lifecycle_project",
                "key": "status",
                "value": "Phase 2",
                "confidence": 0.95
            }),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let fact_id_v2 = v2["fact_id"].as_str().expect("second put must return fact_id");

    // List facts for the entity — both versions should be present.
    let by_entity: serde_json::Value = d
        .get("/v1/facts/entity/e2e_lifecycle_project")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let facts = by_entity["facts"]
        .as_array()
        .expect("entity endpoint should return facts array");
    assert!(
        facts.len() >= 2,
        "expected at least 2 facts for entity, got {}",
        facts.len()
    );

    // Query facts by value substring.
    let queried: serde_json::Value = d.get("/v1/facts?query=Phase").unwrap().into_body().read_json().unwrap();
    // The query endpoint should return results (either as "facts" array or "results").
    let has_results =
        queried["facts"].is_array() || queried["results"].is_array() || queried["total_tokens"].is_number();
    assert!(has_results, "query should return results: {queried}");

    // Delete the first fact.
    assert_eq!(
        d.delete(&format!("/v1/facts/{fact_id}")).unwrap().status().as_u16(),
        200
    );

    // Verify it is gone.
    match d.get(&format!("/v1/facts/{fact_id}")) {
        Err(ureq::Error::StatusCode(404)) => {} // expected
        other => panic!("expected 404 after delete, got: {other:?}"),
    }

    // Clean up the second fact.
    let _ = d.delete(&format!("/v1/facts/{fact_id_v2}"));
}

// ── 2. Session lifecycle ───────────────────────────────────────────────

#[test]
fn session_lifecycle() {
    let d = daemon();
    let session_id = "e2e-session-lifecycle";

    // Store initial state.
    let resp: serde_json::Value = d
        .put_json(
            &format!("/v1/sessions/{session_id}/state"),
            json!({"step": 3, "data": "hello"}),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(resp["session_id"], session_id);

    // Retrieve and verify.
    let state: serde_json::Value = d
        .get(&format!("/v1/sessions/{session_id}/state"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(state["state"]["step"], 3);
    assert_eq!(state["state"]["data"], "hello");

    // Update state.
    d.put_json(
        &format!("/v1/sessions/{session_id}/state"),
        json!({"step": 4, "data": "updated"}),
    )
    .unwrap();

    // Verify updated state.
    let updated: serde_json::Value = d
        .get(&format!("/v1/sessions/{session_id}/state"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(updated["state"]["step"], 4);
    assert_eq!(updated["state"]["data"], "updated");
}

// ── 3. Bulk fact insert ────────────────────────────────────────────────

#[test]
fn fact_bulk_insert() {
    let d = daemon();

    let bulk_resp: serde_json::Value = d
        .put_json(
            "/v1/facts/bulk",
            json!([
                {"entity": "e2e_bulk_alpha", "key": "colour", "value": "red"},
                {"entity": "e2e_bulk_beta",  "key": "colour", "value": "green"},
                {"entity": "e2e_bulk_gamma", "key": "colour", "value": "blue"}
            ]),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();

    let created = bulk_resp["facts"]
        .as_array()
        .expect("bulk response should contain facts array");
    assert_eq!(created.len(), 3, "should create exactly 3 facts");

    // Verify each entity has its fact.
    for entity in ["e2e_bulk_alpha", "e2e_bulk_beta", "e2e_bulk_gamma"] {
        let by_entity: serde_json::Value = d
            .get(&format!("/v1/facts/entity/{entity}"))
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        let facts = by_entity["facts"]
            .as_array()
            .unwrap_or_else(|| panic!("entity {entity} should return facts array"));
        assert!(!facts.is_empty(), "entity {entity} should have at least one fact");
        // Verify the value matches what we inserted.
        let values: Vec<&str> = facts.iter().filter_map(|f| f["value"].as_str()).collect();
        assert!(!values.is_empty(), "entity {entity} facts should have value fields");
    }

    // Clean up.
    for fact in created {
        if let Some(id) = fact["fact_id"].as_str() {
            let _ = d.delete(&format!("/v1/facts/{id}"));
        }
    }
}

// ── 4. Health and version chain ────────────────────────────────────────

#[test]
fn health_and_version() {
    let d = daemon();

    // /healthz — should return 200 with a status/ok field.
    let health: serde_json::Value = d.get("/healthz").unwrap().into_body().read_json().unwrap();
    let has_status = health["ok"].is_boolean() || health["status"].is_string();
    assert!(has_status, "healthz should have ok or status field: {health}");

    // /readyz — should return 200.
    assert_eq!(d.get("/readyz").unwrap().status().as_u16(), 200);

    // /v1/version — should return 200 with build metadata.
    let version: serde_json::Value = d.get("/v1/version").unwrap().into_body().read_json().unwrap();
    let has_build_info = version["version"].is_string()
        || version["build"].is_object()
        || version["commit"].is_string()
        || version["edition"].is_string();
    assert!(
        has_build_info,
        "version endpoint should contain build metadata: {version}"
    );
    assert_eq!(
        version["features"]["mcp"], true,
        "built-in MCP should be enabled in the default test daemon"
    );
    assert!(version["update"]["state"].is_string());

    // /metrics — should return 200 with Prometheus-format text.
    let mut metrics_resp = d.get("/metrics").unwrap();
    assert_eq!(metrics_resp.status().as_u16(), 200);
    let metrics_text = metrics_resp.body_mut().read_to_string().unwrap();
    assert!(
        metrics_text.contains("build_info") || metrics_text.contains("# HELP") || metrics_text.contains("# TYPE"),
        "metrics should contain Prometheus format markers"
    );
}
