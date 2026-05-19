// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Integration tests against a running corecruxd daemon.
//! Run: ./scripts/run-integration-tests.sh -- --test-threads=1

use crux_integration_tests::TestDaemon;
use serde_json::json;
use std::sync::OnceLock;

fn daemon() -> &'static TestDaemon {
    static D: OnceLock<TestDaemon> = OnceLock::new();
    D.get_or_init(TestDaemon::start)
}

#[test]
fn healthz() {
    let b: serde_json::Value = daemon().get("/healthz").unwrap().into_body().read_json().unwrap();
    assert_eq!(b["ok"], true);
}
#[test]
fn readyz() {
    assert_eq!(daemon().get("/readyz").unwrap().status().as_u16(), 200);
}
#[test]
fn metrics() {
    let t = daemon().get("/metrics").unwrap().into_body().read_to_string().unwrap();
    assert!(t.contains("build_info"));
}

#[test]
fn version_includes_update_status() {
    let body: serde_json::Value = daemon().get("/v1/version").unwrap().into_body().read_json().unwrap();
    assert!(body["update"]["state"].is_string());
    assert!(body["update"]["upgrade_hint"].is_string());
}

#[test]
fn console_shell_renders() {
    let html = daemon().get("/console").unwrap().into_body().read_to_string().unwrap();
    assert!(html.contains("Crux Console"));
    // Block runtime-loading of external assets (scripts/styles/iframes from
    // CDNs or any remote host). Documentation `<a href="https://...">` links
    // to ecosystem sites (cuecrux.com, vaultcrux.com, memorycrux.com,
    // github.com, etc.) are FINE — they don't load anything until the user
    // clicks them. Mirrors the unit-side check in
    // `corecruxd::playground::tests::console_shell_has_no_external_runtime_dependencies`.
    for blocked in [
        r#"<script src="http"#,
        r#"<link rel="stylesheet" href="http"#,
        r#"<iframe src="http"#,
        "unpkg.com",
        "jsdelivr.net",
        "cdnjs.cloudflare",
        "cdn.jsdelivr",
    ] {
        assert!(!html.contains(blocked), "external runtime dependency found: {blocked}");
    }

    let root = daemon().get("/").unwrap().into_body().read_to_string().unwrap();
    assert!(root.contains("Crux Console"));

    let alias = daemon()
        .get("/playground")
        .unwrap()
        .into_body()
        .read_to_string()
        .unwrap();
    assert!(alias.contains("Crux Console"));
}

#[test]
fn console_summary_api() {
    let body: serde_json::Value = daemon()
        .get("/v1/console/summary")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(body["console"]["route"], "/console");
    assert_eq!(body["daemon"]["mcp_enabled"], true);
    assert!(body["integrations"]["builtin_pack_count"].as_u64().unwrap() >= 1);
}

#[test]
fn console_integrations_api() {
    let body: serde_json::Value = daemon()
        .get("/v1/console/integrations")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(body["enabled"], true);
    assert!(body["packs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|pack| { pack["manifest"]["id"] == "mcp.cursor" }));
}
#[test]
fn shards() {
    let b: serde_json::Value = daemon().get("/v1/shards").unwrap().into_body().read_json().unwrap();
    assert!(b["shards"].is_array());
}
#[test]
fn shard_map() {
    assert_eq!(daemon().get("/v1/shard-map").unwrap().status().as_u16(), 200);
}
#[test]
fn admin_control() {
    let b: serde_json::Value = daemon()
        .get("/v1/admin/control")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert!(b["valves"].is_object());
}
#[test]
fn replication() {
    assert_eq!(
        daemon().get("/v1/admin/replication/status").unwrap().status().as_u16(),
        200
    );
}
#[test]
fn routing_status() {
    assert_eq!(daemon().get("/v1/routing/status").unwrap().status().as_u16(), 200);
}

#[test]
fn mcp_server_info() {
    let body: serde_json::Value = daemon().mcp_get().unwrap().into_body().read_json().unwrap();
    assert_eq!(body["serverInfo"]["name"], "crux");
    assert!(body["protocolVersion"].is_string());
}

#[test]
fn mcp_tools_list() {
    let body: serde_json::Value = daemon()
        .mcp_post_json(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    // Lower-bound assertion so this test doesn't break every time we add a
    // tool; the in-crate `crux_mcp::tools::tests::list_tools_returns_expected_count`
    // pins the exact count via `TOOL_COUNT`. The integration daemon may
    // gate a few config-dependent tools (e.g. sync_* without remote config),
    // hence the lower bound below the in-crate TOOL_COUNT.
    let tools = body["result"]["tools"].as_array().unwrap();
    assert!(tools.len() >= 35, "expected ≥35 MCP tools, got {}", tools.len());
    // Spot-check that the storyline tool registered (added 2026-05-03).
    let has_storyline = tools
        .iter()
        .any(|t| t["name"].as_str() == Some("get_workspace_storyline"));
    assert!(has_storyline, "get_workspace_storyline not in MCP catalogue");
}

#[test]
fn mcp_update_status_tool() {
    let body: serde_json::Value = daemon()
        .mcp_post_json(json!({
            "jsonrpc":"2.0",
            "id":2,
            "method":"tools/call",
            "params":{"name":"update_status","arguments":{}}
        }))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let text = body["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("\"state\""));
    assert!(text.contains("upgrade_playbook_query"));
}

#[test]
fn substrate_entity_round_trip() {
    let d = daemon();
    // Upsert a capability entity.
    let res = d
        .put_json(
            "/v1/entities/capability/CAPTEST-RT",
            json!({"payload":{"id":"CAPTEST-RT","name":"Round Trip","system":"Crux","maturity":"shipped"}}),
        )
        .expect("PUT entity");
    assert_eq!(res.status().as_u16(), 200, "PUT entity should 200");
    // GET it back.
    let got: serde_json::Value = d
        .get("/v1/entities/capability/CAPTEST-RT")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(got["entity"]["kind"], "capability");
    assert_eq!(got["entity"]["id"], "CAPTEST-RT");
    assert_eq!(got["entity"]["payload"]["name"], "Round Trip");
    // LIST by kind.
    let listed: serde_json::Value = d
        .get("/v1/entities?kind=capability")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let arr = listed["entities"].as_array().unwrap();
    assert!(
        arr.iter().any(|e| e["id"] == "CAPTEST-RT"),
        "list must contain the upserted entity"
    );
    // DELETE.
    assert_eq!(
        d.delete("/v1/entities/capability/CAPTEST-RT")
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    // GET after delete = 404 (ureq returns 4xx as Err).
    match d.get("/v1/entities/capability/CAPTEST-RT") {
        Err(ureq::Error::StatusCode(404)) => {}
        other => panic!("expected 404 after delete, got {other:?}"),
    }
}

#[test]
fn substrate_entity_history() {
    let d = daemon();
    // Three upserts on the same id; final delete.
    for v in 1..=3u64 {
        d.put_json(
            "/v1/entities/capability/CAPTEST-HIST",
            json!({"payload":{"id":"CAPTEST-HIST","name":"H","system":"X","maturity":"built","v":v}}),
        )
        .unwrap();
    }
    d.delete("/v1/entities/capability/CAPTEST-HIST").unwrap();
    let body: serde_json::Value = d
        .get("/v1/entities/capability/CAPTEST-HIST/history")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let versions = body["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 4, "3 upserts + 1 delete = 4 versions");
    assert_eq!(versions[0]["version"], 1);
    assert_eq!(versions.last().unwrap()["deleted"], true);
}

#[test]
fn substrate_edge_round_trip() {
    let d = daemon();
    // Need source + target entities first.
    d.put_json(
        "/v1/entities/capability/CAPTEST-EDGE-A",
        json!({"payload":{"id":"CAPTEST-EDGE-A","name":"A","system":"X","maturity":"built"}}),
    )
    .unwrap();
    d.put_json(
        "/v1/entities/capability/CAPTEST-EDGE-B",
        json!({"payload":{"id":"CAPTEST-EDGE-B","name":"B","system":"X","maturity":"built"}}),
    )
    .unwrap();
    // PUT edge.
    let res = d
        .put_json(
            "/v1/edges",
            json!({
                "from_kind":"capability","from_id":"CAPTEST-EDGE-A",
                "edge_kind":"depends_on",
                "to_kind":"capability","to_id":"CAPTEST-EDGE-B"
            }),
        )
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    // LIST from-side.
    let listed: serde_json::Value = d
        .get("/v1/edges?from_kind=capability&from_id=CAPTEST-EDGE-A")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert!(listed["count"].as_u64().unwrap() >= 1);
    // Cleanup (delete uses body via DELETE; not all clients support it, so we
    // assert basic round-trip and leave full cleanup to journal scoping).
}

#[test]
fn features_lens_end_to_end() {
    let d = daemon();
    // Seed two capability entities via the substrate.
    d.put_json(
        "/v1/entities/capability/FLENS-A",
        json!({"payload":{
            "id":"FLENS-A","name":"Feature A","system":"Crux","maturity":"shipped",
            "tests":{"unit":["a.rs"]}, "dod":["compiles"],
            "audit":{"status":"audited"},
            "promise_alignment":[1]
        }}),
    )
    .unwrap();
    d.put_json(
        "/v1/entities/capability/FLENS-B",
        json!({"payload":{
            "id":"FLENS-B","name":"Feature B","system":"Crux","maturity":"shipped",
            "tests":{}, "dod":[],
            "audit":{"status":"gap"},
            "promise_alignment":[1,7]
        }}),
    )
    .unwrap();

    // List via lens.
    let list: serde_json::Value = d
        .get("/v1/features/capabilities?system=Crux")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert!(list["count"].as_u64().unwrap() >= 2);

    // Gap analysis.
    let gaps: serde_json::Value = d
        .get("/v1/features/capabilities/analysis/gaps")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert!(gaps["gaps"].is_array());
    let gap_for_b = gaps["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["id"] == "FLENS-B" && g["type"] == "no_tests");
    assert!(gap_for_b, "B is shipped without tests → critical no_tests");

    // Promise coverage.
    let promises: serde_json::Value = d
        .get("/v1/features/capabilities/analysis/promises")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let p1 = promises["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["promise"] == 1)
        .unwrap()
        .clone();
    assert!(p1["total"].as_u64().unwrap() >= 2);

    // Coverage report.
    let coverage: serde_json::Value = d
        .get("/v1/features/capabilities/analysis/coverage")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert!(coverage["total_capabilities"].as_u64().unwrap() >= 2);

    // Audit POST.
    let audit_res = d
        .post_json(
            "/v1/features/capabilities/FLENS-B/audit",
            json!({"status":"audited","auditor":"qa","notes":"covered"}),
        )
        .unwrap();
    assert_eq!(audit_res.status().as_u16(), 200);
    // GET capability shows new audit status.
    let after: serde_json::Value = d
        .get("/v1/features/capabilities/FLENS-B")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(after["audit"]["status"], "audited");
}

#[test]
fn substrate_kinds_list() {
    // The substrate is generic; kinds start empty until a lens registers one.
    let body: serde_json::Value = daemon().get("/v1/kinds").unwrap().into_body().read_json().unwrap();
    assert!(body["kinds"].is_array(), "kinds response must include array");
    assert!(body["count"].is_number(), "kinds response must include count");
}

#[test]
fn mcp_requires_auth_when_agent_token_configured() {
    let daemon = TestDaemon::start_with_agent_token("secret-token");

    match daemon.mcp_post_json(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})) {
        Err(ureq::Error::StatusCode(401)) => {}
        other => panic!("expected 401 from unauthenticated MCP request, got {other:?}"),
    }

    let body: serde_json::Value = daemon
        .mcp_post_json_with_token(
            json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"tools/call",
                "params":{"name":"get_agent_identity","arguments":{}}
            }),
            "secret-token",
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(body["result"]["content"][0]["text"], "default");
}

#[test]
fn text_search_empty() {
    let b: serde_json::Value = daemon()
        .post_json(
            "/v1/query/text-search",
            json!({"tenant_id":"t","query":"hello","limit":10}),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert!(b["results"].is_array());
    assert!(b["coverage"]["score"].is_number());
}

#[test]
fn text_search_token_budget() {
    let b: serde_json::Value = daemon()
        .post_json(
            "/v1/query/text-search",
            json!({"tenant_id":"t","query":"test","token_budget":4000}),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    // Empty index returns early without tokens_used; just verify 200 OK with results array
    assert!(b["results"].is_array());
}

#[test]
fn text_search_min_score() {
    let b: serde_json::Value = daemon()
        .post_json(
            "/v1/query/text-search",
            json!({"tenant_id":"t","query":"x","min_score":0.5}),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert!(b["results"].is_array());
}

#[test]
fn text_search_scan_mode() {
    let b: serde_json::Value = daemon()
        .post_json(
            "/v1/query/text-search",
            json!({"tenant_id":"t","query":"scan","mode":"scan"}),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    // Empty index returns early response without scan_mode field
    assert!(b["results"].is_array());
}

#[test]
fn text_search_expand() {
    // Audit-triage tightening (2026-05-07): empty result_ids now 400s.
    // Pass one synthetic rid so the route runs end-to-end against the
    // (empty) test index; out-of-bounds segment_index is skipped, so
    // tokens_loaded stays 0.
    let b: serde_json::Value = daemon()
        .post_json(
            "/v1/query/text-search/expand",
            json!({"tenant_id":"t","result_ids":[{"segment_index":0,"doc_id":0}]}),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(b["tokens_loaded"], 0);
}

#[test]
fn text_search_bad_query() {
    match daemon().post_json("/v1/query/text-search", json!({"tenant_id":"t","query":"  "})) {
        Err(ureq::Error::StatusCode(400)) => {}
        other => panic!("expected 400: {other:?}"),
    }
}

#[test]
fn append_compat_alias_returns_not_implemented_without_dataplane() {
    match daemon().post_json(
        "/v1/append",
        json!({
            "tenant_id":"t",
            "stream_type":"docs",
            "stream_id":"example",
            "events":[{
                "event_id":"evt-1",
                "occurred_at":"2026-04-09T12:00:00Z",
                "event_type":"doc.created",
                "payload":"{\"title\":\"hello\"}"
            }]
        }),
    ) {
        Err(ureq::Error::StatusCode(501)) => {}
        other => panic!("expected 501 from append alias without dataplane, got {other:?}"),
    }
}

#[test]
fn fact_crud() {
    let d = daemon();
    let f: serde_json::Value = d
        .put_json(
            "/v1/facts",
            json!({"entity":"e","key":"k","value":"v","confidence":0.9}),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let id = f["fact_id"].as_str().unwrap();
    assert!(id.starts_with("f_"));

    let g: serde_json::Value = d
        .get(&format!("/v1/facts/{id}"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(g["entity"], "e");

    let e: serde_json::Value = d.get("/v1/facts/entity/e").unwrap().into_body().read_json().unwrap();
    assert!(!e["facts"].as_array().unwrap().is_empty());

    let q: serde_json::Value = d.get("/v1/facts?query=v").unwrap().into_body().read_json().unwrap();
    assert!(q["total_tokens"].is_number());

    assert_eq!(d.delete(&format!("/v1/facts/{id}")).unwrap().status().as_u16(), 200);
    match d.get(&format!("/v1/facts/{id}")) {
        Err(ureq::Error::StatusCode(404)) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn fact_bulk() {
    let b: serde_json::Value = daemon()
        .put_json(
            "/v1/facts/bulk",
            json!([{"entity":"a","key":"k","value":"v"},{"entity":"b","key":"k","value":"v"}]),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(b["facts"].as_array().unwrap().len(), 2);
}

#[test]
fn fact_private_true_rejected_over_http() {
    match daemon().put_json(
        "/v1/facts",
        json!({"entity":"agent","key":"secret","value":"hidden","private":true}),
    ) {
        Err(ureq::Error::StatusCode(400)) => {}
        other => panic!("expected 400 from private HTTP fact write, got {other:?}"),
    }
}

#[test]
fn session_crud() {
    let d = daemon();
    let s: serde_json::Value = d
        .put_json("/v1/sessions/s1/state", json!({"step":1}))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(s["session_id"], "s1");
    assert!(s["total_tokens"].as_u64().unwrap() > 0);

    let g: serde_json::Value = d.get("/v1/sessions/s1/state").unwrap().into_body().read_json().unwrap();
    assert_eq!(g["state"]["step"], 1);

    d.put_json("/v1/sessions/s1/state", json!({"step":2})).unwrap();
    let g2: serde_json::Value = d.get("/v1/sessions/s1/state").unwrap().into_body().read_json().unwrap();
    assert_eq!(g2["state"]["step"], 2);
}

#[test]
fn session_not_found() {
    match daemon().get("/v1/sessions/nonexistent/state") {
        Err(ureq::Error::StatusCode(404)) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn graceful_shutdown_on_sigterm() {
    let mut daemon = TestDaemon::start();
    // Verify the daemon is alive and responding.
    let b: serde_json::Value = daemon.get("/healthz").unwrap().into_body().read_json().unwrap();
    assert_eq!(b["ok"], true);

    // Send SIGTERM via the kill command (avoids unsafe block).
    let pid = daemon.process.id();
    std::process::Command::new("kill")
        .args(["-s", "TERM", &pid.to_string()])
        .status()
        .expect("failed to send SIGTERM");

    // Wait for the process to exit (up to 5 seconds).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match daemon.process.try_wait() {
            Ok(Some(status)) => {
                // Process exited — verify clean exit code.
                assert!(
                    status.success() || status.code() == Some(0),
                    "expected exit code 0, got: {status:?}"
                );
                // Prevent Drop from trying to kill an already-exited process.
                // (Drop's kill() on an exited child is harmless, so this is fine.)
                return;
            }
            Ok(None) => {
                assert!(
                    (std::time::Instant::now() <= deadline),
                    "corecruxd did not exit within 5 seconds after SIGTERM"
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => panic!("error waiting for corecruxd: {e}"),
        }
    }
}

#[test]
fn receipt_not_found() {
    for p in [
        "/v1/receipts/fake",
        "/v1/receipts/fake/signature",
        "/v1/receipts/fake/verification",
    ] {
        match daemon().get(p) {
            Err(ureq::Error::StatusCode(c)) if c == 400 || c == 404 || c == 501 || c == 412 => {}
            Ok(r) if [200, 400, 404, 412, 501].contains(&r.status().as_u16()) => {}
            other => panic!("{p}: {other:?}"),
        }
    }
}
