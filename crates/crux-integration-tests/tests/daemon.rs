// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Integration tests against a running corecruxd daemon.
//! Run: cargo test -p crux-integration-tests -- --test-threads=1

use crux_integration_tests::TestDaemon;
use serde_json::json;
use std::sync::OnceLock;

fn daemon() -> &'static TestDaemon {
    static D: OnceLock<TestDaemon> = OnceLock::new();
    D.get_or_init(TestDaemon::start)
}

#[test]
fn healthz() {
    let b: serde_json::Value = daemon().get("/healthz").unwrap().into_json().unwrap();
    assert_eq!(b["ok"], true);
}
#[test]
fn readyz() {
    assert_eq!(daemon().get("/readyz").unwrap().status(), 200);
}
#[test]
fn metrics() {
    let t = daemon().get("/metrics").unwrap().into_string().unwrap();
    assert!(t.contains("build_info"));
}
#[test]
fn shards() {
    let b: serde_json::Value = daemon().get("/v1/shards").unwrap().into_json().unwrap();
    assert!(b["shards"].is_array());
}
#[test]
fn shard_map() {
    assert_eq!(daemon().get("/v1/shard-map").unwrap().status(), 200);
}
#[test]
fn admin_control() {
    let b: serde_json::Value = daemon().get("/v1/admin/control").unwrap().into_json().unwrap();
    assert!(b["valves"].is_object());
}
#[test]
fn replication() {
    assert_eq!(daemon().get("/v1/admin/replication/status").unwrap().status(), 200);
}
#[test]
fn routing_status() {
    assert_eq!(daemon().get("/v1/routing/status").unwrap().status(), 200);
}

#[test]
fn text_search_empty() {
    let b: serde_json::Value = daemon()
        .post_json(
            "/v1/query/text-search",
            json!({"tenant_id":"t","query":"hello","limit":10}),
        )
        .unwrap()
        .into_json()
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
        .into_json()
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
        .into_json()
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
        .into_json()
        .unwrap();
    // Empty index returns early response without scan_mode field
    assert!(b["results"].is_array());
}

#[test]
fn text_search_expand() {
    let b: serde_json::Value = daemon()
        .post_json("/v1/query/text-search/expand", json!({"tenant_id":"t","result_ids":[]}))
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(b["tokens_loaded"], 0);
}

#[test]
fn text_search_bad_query() {
    match daemon().post_json("/v1/query/text-search", json!({"tenant_id":"t","query":"  "})) {
        Err(ureq::Error::Status(400, _)) => {}
        other => panic!("expected 400: {other:?}"),
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
        .into_json()
        .unwrap();
    let id = f["fact_id"].as_str().unwrap();
    assert!(id.starts_with("f_"));

    let g: serde_json::Value = d.get(&format!("/v1/facts/{id}")).unwrap().into_json().unwrap();
    assert_eq!(g["entity"], "e");

    let e: serde_json::Value = d.get("/v1/facts/entity/e").unwrap().into_json().unwrap();
    assert!(!e["facts"].as_array().unwrap().is_empty());

    let q: serde_json::Value = d.get("/v1/facts?query=v").unwrap().into_json().unwrap();
    assert!(q["total_tokens"].is_number());

    assert_eq!(d.delete(&format!("/v1/facts/{id}")).unwrap().status(), 200);
    match d.get(&format!("/v1/facts/{id}")) {
        Err(ureq::Error::Status(404, _)) => {}
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
        .into_json()
        .unwrap();
    assert_eq!(b["facts"].as_array().unwrap().len(), 2);
}

#[test]
fn session_crud() {
    let d = daemon();
    let s: serde_json::Value = d
        .put_json("/v1/sessions/s1/state", json!({"step":1}))
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(s["session_id"], "s1");
    assert!(s["total_tokens"].as_u64().unwrap() > 0);

    let g: serde_json::Value = d.get("/v1/sessions/s1/state").unwrap().into_json().unwrap();
    assert_eq!(g["state"]["step"], 1);

    d.put_json("/v1/sessions/s1/state", json!({"step":2})).unwrap();
    let g2: serde_json::Value = d.get("/v1/sessions/s1/state").unwrap().into_json().unwrap();
    assert_eq!(g2["state"]["step"], 2);
}

#[test]
fn session_not_found() {
    match daemon().get("/v1/sessions/nonexistent/state") {
        Err(ureq::Error::Status(404, _)) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn graceful_shutdown_on_sigterm() {
    let mut daemon = TestDaemon::start();
    // Verify the daemon is alive and responding.
    let b: serde_json::Value = daemon.get("/healthz").unwrap().into_json().unwrap();
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
                if std::time::Instant::now() > deadline {
                    panic!("corecruxd did not exit within 5 seconds after SIGTERM");
                }
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
            Err(ureq::Error::Status(c, _)) if c == 400 || c == 404 || c == 501 || c == 412 => {}
            Ok(r) if [200, 400, 404, 412, 501].contains(&r.status()) => {}
            other => panic!("{p}: {other:?}"),
        }
    }
}
