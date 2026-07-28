// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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

fn unique_id(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{nanos}")
}

fn mcp_tool_call(tool: &str, arguments: serde_json::Value) -> serde_json::Value {
    daemon()
        .mcp_post_json(json!({
            "jsonrpc": "2.0",
            "id": unique_id("mcp"),
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments
            }
        }))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap()
}

fn mcp_text_json(body: &serde_json::Value) -> serde_json::Value {
    let text = body["result"]["content"][0]["text"].as_str().unwrap_or_else(|| {
        // A JSON-RPC error, or a tool that skipped the `content` envelope, both
        // land here. Printing the whole body turns "unwrap on None" into a
        // message that names the actual failure.
        panic!("tools/call did not return result.content[0].text; body was: {body:#}")
    });
    serde_json::from_str(text).unwrap_or_else(|e| panic!("tools/call content was not JSON ({e}); text was: {text}"))
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
    // `corecruxd::console::tests::console_shell_has_no_external_runtime_dependencies`.
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

    let alias = daemon().get("/console").unwrap().into_body().read_to_string().unwrap();
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
fn projects_work_and_coordination_tools_flow() {
    let d = daemon();
    let project_id = unique_id("coverage-project");
    let actor_passport = unique_id("coverage-actor");
    let gated_passport = unique_id("coverage-gate");

    let actor: serde_json::Value = d
        .post_json(
            "/v1/passports",
            json!({
                "id": actor_passport,
                "category": "work"
            }),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(actor["id"], actor_passport);

    let passport: serde_json::Value = d
        .post_json(
            "/v1/passports",
            json!({
                "id": gated_passport,
                "category": "work",
                "agent_work_gate": true
            }),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(passport["id"], gated_passport);

    let created: serde_json::Value = d
        .post_json(
            "/v1/projects",
            json!({
                "id": project_id,
                "name": "Coverage Project",
                "planning_target": "github://cuecrux/crux",
                "default_passport_id": actor_passport,
                "working_tenants": ["tenant-a"]
            }),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(created["id"], project_id);

    let project: serde_json::Value = d
        .get(&format!("/v1/projects/{project_id}"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(project["id"], project_id);

    let patched: serde_json::Value = d
        .patch_json(
            &format!("/v1/projects/{project_id}"),
            json!({
                "name": "Coverage Project Updated",
                "planning_target": null,
                "archived": false
            }),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(patched["planning_target"], serde_json::Value::Null);

    let member: serde_json::Value = d
        .post_json(
            &format!("/v1/projects/{project_id}/passports"),
            json!({"passport_id": gated_passport, "role": "reviewer"}),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(member["role"], "reviewer");

    let tenant: serde_json::Value = d
        .post_json(
            &format!("/v1/projects/{project_id}/tenants"),
            json!({"tenant_id": "tenant-b", "default_passport_id": actor_passport}),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(tenant["tenant_id"], "tenant-b");

    let layer: serde_json::Value = d
        .put_json(
            &format!("/v1/projects/{project_id}/layers/vision"),
            json!({"content": "Coverage-driven project context"}),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(layer["layer"], "vision");

    let layers: serde_json::Value = d
        .get(&format!("/v1/projects/{project_id}/layers"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(layers["count"], 1);

    let repo_link: serde_json::Value = d
        .post_json(
            &format!("/v1/projects/{project_id}/repos"),
            json!({"repo": "cuecrux/crux", "plane_id": "backend", "role": "work"}),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(repo_link["owner"], "cuecrux");
    assert_eq!(repo_link["repo"], "crux");

    let repos: serde_json::Value = d
        .get(&format!("/v1/projects/{project_id}/repos"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(repos["count"], 1);

    let plane_repos: serde_json::Value = d
        .get(&format!("/v1/projects/{project_id}/planes/backend/repos"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(plane_repos["count"], 1);

    let graph: serde_json::Value = d
        .get(&format!("/v1/projects/{project_id}/context-graph"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert!(graph["nodes"].as_array().unwrap().len() >= 2);

    let work: serde_json::Value = d
        .post_json(
            "/v1/work",
            json!({
                "project_id": project_id,
                "title": "Raise coverage",
                "body": "Add deterministic coverage tests",
                "state": "planned",
                "assignee_passport": actor_passport,
                "tenant_id": "tenant-a",
                "linked_pr": "https://github.com/cuecrux/crux/pull/1",
                "linked_issue": "https://github.com/cuecrux/crux/issues/1",
                "created_by_passport": actor_passport
            }),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let work_id = work["id"].as_str().unwrap().to_string();

    let work_list: serde_json::Value = d
        .get(&format!(
            "/v1/work?project_id={project_id}&state=planned&tenant_id=tenant-a"
        ))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert!(work_list["count"].as_u64().unwrap() >= 1);

    let applied: serde_json::Value = d
        .patch_json(
            &format!("/v1/work/{work_id}"),
            json!({
                "state": "in_progress",
                "body": "Now underway",
                "by_passport": actor_passport
            }),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(applied["applied"], true);

    let comment: serde_json::Value = d
        .post_json(
            &format!("/v1/work/{work_id}/comments"),
            json!({"author_passport": actor_passport, "body": "Coverage flow exercised."}),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(comment["work_id"], work_id);

    let comments: serde_json::Value = d
        .get(&format!("/v1/work/{work_id}/comments"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(comments["comments"].as_array().unwrap().len(), 1);

    let transitions: serde_json::Value = d
        .get(&format!("/v1/work/{work_id}/transitions"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert!(!transitions["transitions"].as_array().unwrap().is_empty());

    let queued: serde_json::Value = d
        .patch_json(
            &format!("/v1/work/{work_id}"),
            json!({
                "state": "complete",
                "by_passport": gated_passport
            }),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(queued["applied"], false);
    let action_id = queued["queued"]["action_id"].as_str().unwrap();

    let pending: serde_json::Value = d
        .get(&format!("/v1/work/gate/pending?by_passport={gated_passport}"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(pending["count"], 1);

    let approved: serde_json::Value = d
        .post_json(
            &format!("/v1/work/gate/{action_id}/approve"),
            json!({"approver_passport": actor_passport}),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(approved["state"], "complete");

    let transitions: serde_json::Value = d
        .get(&format!("/v1/work/{work_id}/transitions"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let approved_transition = transitions["transitions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|transition| transition["gate_status"] == "approved")
        .unwrap();
    let expected_approver = format!("operator:unverified:{actor_passport}");
    assert_eq!(approved_transition["by_passport"], expected_approver);
    assert_ne!(approved_transition["by_passport"], actor_passport);
    assert_eq!(approved_transition["receipt_id"], approved["receipt_id"]);

    let mcp_projects = mcp_text_json(&mcp_tool_call("list_projects", json!({})));
    assert!(mcp_projects["projects"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["id"] == project_id));

    let mcp_project = mcp_text_json(&mcp_tool_call("get_project_context", json!({"project_id": project_id})));
    assert_eq!(mcp_project["id"], project_id);

    let mcp_work = mcp_text_json(&mcp_tool_call(
        "create_work",
        json!({
            "project_id": project_id,
            "title": "MCP-created coverage work",
            "body": "Created through coordination tool",
            "state": "planned",
            "tenant_id": "tenant-b",
            "created_by_passport": actor_passport
        }),
    ));
    let mcp_work_id = mcp_work["id"].as_str().unwrap();

    let mcp_list_work = mcp_text_json(&mcp_tool_call(
        "list_work",
        json!({"project_id": project_id, "tenant_id": "tenant-b"}),
    ));
    assert!(mcp_list_work["count"].as_u64().unwrap() >= 1);

    let mcp_updated = mcp_text_json(&mcp_tool_call(
        "update_work_state",
        json!({
            "work_id": mcp_work_id,
            "state": "blocked",
            "by_passport": actor_passport,
            "blocker_reason": "waiting for CI"
        }),
    ));
    assert_eq!(mcp_updated["applied"], true);

    let mcp_comment = mcp_text_json(&mcp_tool_call(
        "comment_on_work",
        json!({
            "work_id": mcp_work_id,
            "author_passport": actor_passport,
            "body": "MCP comment coverage"
        }),
    ));
    assert_eq!(mcp_comment["work_id"], mcp_work_id);

    assert_eq!(
        d.delete(&format!("/v1/projects/{project_id}/repos/cuecrux/crux"))
            .unwrap()
            .status()
            .as_u16(),
        204
    );
    assert_eq!(
        d.delete(&format!("/v1/projects/{project_id}/layers/vision"))
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        d.delete(&format!("/v1/projects/{project_id}/tenants/tenant-b"))
            .unwrap()
            .status()
            .as_u16(),
        204
    );
    assert_eq!(
        d.delete(&format!("/v1/projects/{project_id}/passports/{gated_passport}"))
            .unwrap()
            .status()
            .as_u16(),
        204
    );
}

#[test]
fn integration_setup_and_workspace_status_endpoints() {
    let d = daemon();

    let tools: serde_json::Value = d.get("/v1/mcp/tools").unwrap().into_body().read_json().unwrap();
    assert!(tools["count"].as_u64().unwrap() >= 35);

    match d.get("/v1/workspace/scan") {
        Err(ureq::Error::StatusCode(404)) => {}
        other => panic!("expected no persisted workspace scan yet, got {other:?}"),
    }
    match d.get("/v1/workspace/storyline?format=json") {
        Err(ureq::Error::StatusCode(404)) => {}
        other => panic!("expected storyline without scan to 404, got {other:?}"),
    }
    match d.post_json("/v1/workspace/scan", json!({})) {
        Err(ureq::Error::StatusCode(412)) => {}
        other => panic!("expected unconfigured workspace scan to 412, got {other:?}"),
    }

    let github_initial: serde_json::Value = d
        .get("/v1/integrations/github/status")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(github_initial["connected"], false);

    match d.get("/v1/integrations/github/repos/accessible") {
        Err(ureq::Error::StatusCode(412)) => {}
        other => panic!("expected GitHub accessible repos to require connect, got {other:?}"),
    }

    let github_connected: serde_json::Value = d
        .post_json(
            "/v1/integrations/github/connect",
            json!({
                "pat": "ghp_test_token",
                "skip_verify": true,
                "username_override": "coverage-bot"
            }),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(github_connected["connected"], true);
    assert_eq!(github_connected["username"], "coverage-bot");

    let selected: serde_json::Value = d
        .get("/v1/integrations/github/repos")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(selected["count"], 0);

    assert_eq!(
        d.post_json("/v1/integrations/github/disconnect", json!({}))
            .unwrap()
            .status()
            .as_u16(),
        204
    );

    let openai_initial: serde_json::Value = d
        .get("/v1/integrations/openai/status")
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(openai_initial["connected"], false);

    match d.post_json("/v1/integrations/openai/chat", json!({"messages": []})) {
        Err(ureq::Error::StatusCode(412)) => {}
        other => panic!("expected OpenAI chat to require connect, got {other:?}"),
    }

    let openai_connected: serde_json::Value = d
        .post_json(
            "/v1/integrations/openai/connect",
            json!({
                "api_key": "sk-test-token",
                "organization_id": "org-coverage",
                "default_model": "gpt-4o-mini",
                "skip_verify": true
            }),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(openai_connected["connected"], true);
    assert_eq!(openai_connected["organization_id"], "org-coverage");

    let openai_updated: serde_json::Value = d
        .patch_json(
            "/v1/integrations/openai/settings",
            json!({
                "default_model": "gpt-4.1-mini",
                "organization_id": ""
            }),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(openai_updated["default_model"], "gpt-4.1-mini");
    assert!(openai_updated.get("organization_id").is_none());

    assert_eq!(
        d.post_json("/v1/integrations/openai/disconnect", json!({}))
            .unwrap()
            .status()
            .as_u16(),
        204
    );
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
    // Must satisfy the agent-token strength policy (>= 32 bytes, safe charset);
    // a weaker token is rejected at registry build and would leave MCP in
    // no-auth mode. See crux_mcp::agent::is_safe_agent_token.
    let token = "crux_at_int_test_0123456789abcdef";
    let daemon = TestDaemon::start_with_agent_token(token);

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
            token,
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

/// Context-graph MCP tools must return exactly what their HTTP counterparts do.
///
/// The whole design of `crux-mcp::tools::context_graph` is "thin adapter, one
/// implementation" — the tools proxy to the same corecruxd routes rather than
/// re-deriving anything. That claim is only worth making if it is checked: a
/// divergence between the two surfaces would be a silent correctness bug, where
/// an agent and an operator looking at the same project disagree about it.
#[test]
fn context_graph_mcp_tools_match_their_http_counterparts() {
    let d = daemon();
    let project_id = unique_id("ctxgraph");
    let passport_id = unique_id("p-ctxgraph");

    d.post_json(
        "/v1/passports",
        json!({ "id": passport_id, "category": "work", "name": "ctx graph parity" }),
    )
    .unwrap();
    let created: serde_json::Value = d
        .post_json(
            "/v1/projects",
            json!({
                "id": project_id,
                "name": "Context Graph Parity",
                "planning_target": "github://cuecrux/crux",
                "default_passport_id": passport_id,
                "working_tenants": ["tenant-ctxgraph"]
            }),
        )
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    assert_eq!(created["id"], project_id);

    d.put_json(
        &format!("/v1/projects/{project_id}/layers/vision"),
        json!({ "content": "A daemon that remembers what every agent worked out." }),
    )
    .unwrap();

    // ── Storybook ────────────────────────────────────────────────────────
    let mcp_gen = mcp_text_json(&mcp_tool_call(
        "generate_project_storybook",
        json!({ "project_id": project_id }),
    ));
    assert_eq!(mcp_gen["project_id"], project_id.as_str());
    let first_ts = mcp_gen["generated_at_unix_ms"].as_u64().unwrap();

    let budget = 4000u64;
    let http_story: serde_json::Value = d
        .get(&format!("/v1/projects/{project_id}/storybook?token_budget={budget}"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let mcp_story = mcp_text_json(&mcp_tool_call(
        "get_project_storybook",
        json!({ "project_id": project_id, "token_budget": budget }),
    ));
    assert_eq!(
        http_story, mcp_story,
        "get_project_storybook diverged from GET /v1/projects/{{id}}/storybook"
    );
    assert!(http_story["available_versions"]
        .as_array()
        .is_some_and(|v| v.contains(&json!(first_ts))));

    // The section filter is the reason an agent would reach for this over
    // reading the whole readout, so it is checked for parity too.
    let http_alerts: serde_json::Value = d
        .get(&format!(
            "/v1/projects/{project_id}/storybook?token_budget=1500&section=60"
        ))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let mcp_alerts = mcp_text_json(&mcp_tool_call(
        "get_project_storybook",
        json!({ "project_id": project_id, "token_budget": 1500, "section": "60" }),
    ));
    assert_eq!(http_alerts, mcp_alerts, "section filter diverged");
    assert_eq!(http_alerts["truncated"], true);

    // A budget is a contract, not a hint: what came back must fit it.
    let sent = serde_json::to_string(&mcp_story).unwrap().len();
    assert!(
        sent.div_ceil(4) <= budget as usize,
        "storybook overshot: {sent} bytes for a {budget}-token budget"
    );

    // Regenerate so there are two versions to diff.
    let second = mcp_text_json(&mcp_tool_call(
        "generate_project_storybook",
        json!({ "project_id": project_id }),
    ));
    let second_ts = second["generated_at_unix_ms"].as_u64().unwrap();
    if second_ts != first_ts {
        let http_diff: serde_json::Value = d
            .get(&format!(
                "/v1/projects/{project_id}/storybook/diff?a={first_ts}&b={second_ts}"
            ))
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        let mcp_diff = mcp_text_json(&mcp_tool_call(
            "diff_project_storybook",
            json!({ "project_id": project_id, "a": first_ts, "b": second_ts }),
        ));
        assert_eq!(http_diff, mcp_diff, "diff_project_storybook diverged");
    }

    // ── Dossiers ─────────────────────────────────────────────────────────
    let auto = mcp_text_json(&mcp_tool_call(
        "generate_project_dossier",
        json!({ "project_id": project_id }),
    ));
    let auto_id = auto["dossier_id"].as_str().unwrap().to_string();
    assert_eq!(auto["project_id"], project_id.as_str());

    let published = mcp_text_json(&mcp_tool_call(
        "publish_project_dossier",
        json!({
            "project_id": project_id,
            "dossier": {
                "dossier_id": "dsr-parity-peer",
                "project_id": project_id,
                "agent_passport": "p_peer_agent",
                "claims": [{
                    "claim_id": "c1",
                    "kind": "implements",
                    "subject": "plane:parity:core",
                    "object": "crate:corecruxd",
                    "confidence": 0.9,
                    "evidence": ["crates/corecruxd/src/main.rs:1"]
                }],
                "open_questions": ["does the dense lane run on this build?"]
            }
        }),
    ));
    assert_eq!(published["stored"], true);
    assert_eq!(published["claim_count"], 1);

    let http_list: serde_json::Value = d
        .get(&format!("/v1/projects/{project_id}/dossiers?token_budget=2000"))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let mcp_list = mcp_text_json(&mcp_tool_call(
        "get_project_dossiers",
        json!({ "project_id": project_id, "token_budget": 2000 }),
    ));
    assert_eq!(http_list, mcp_list, "get_project_dossiers (list) diverged");
    assert!(http_list["count"].as_u64().unwrap() >= 2);

    let http_one: serde_json::Value = d
        .get(&format!(
            "/v1/projects/{project_id}/dossiers/{auto_id}?token_budget=3000"
        ))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let mcp_one = mcp_text_json(&mcp_tool_call(
        "get_project_dossiers",
        json!({ "project_id": project_id, "token_budget": 3000, "dossier_id": auto_id }),
    ));
    assert_eq!(http_one, mcp_one, "get_project_dossiers (single) diverged");

    let http_rec: serde_json::Value = d
        .get(&format!(
            "/v1/projects/{project_id}/dossiers/reconcile?token_budget=2000"
        ))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let mcp_rec = mcp_text_json(&mcp_tool_call(
        "reconcile_project_dossiers",
        json!({ "project_id": project_id, "token_budget": 2000 }),
    ));
    // `generated_at_unix_ms` is the report's own wall clock, stamped per call,
    // so it differs between two requests by construction. Everything derived
    // from stored state must match exactly.
    let strip_clock = |mut v: serde_json::Value| {
        if let Some(obj) = v.as_object_mut() {
            obj.remove("generated_at_unix_ms");
        }
        v
    };
    assert_eq!(
        strip_clock(http_rec.clone()),
        strip_clock(mcp_rec),
        "reconcile_project_dossiers diverged"
    );
    assert!(http_rec["agents"].as_array().is_some_and(|a| a.len() >= 2));

    let http_ddiff: serde_json::Value = d
        .get(&format!(
            "/v1/projects/{project_id}/dossiers/diff?a={auto_id}&b=dsr-parity-peer"
        ))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let mcp_ddiff = mcp_text_json(&mcp_tool_call(
        "diff_project_dossiers",
        json!({ "project_id": project_id, "a": auto_id, "b": "dsr-parity-peer" }),
    ));
    assert_eq!(http_ddiff, mcp_ddiff, "diff_project_dossiers diverged");
}

/// All eight context-graph tools must be listed by `tools/list` and reachable.
#[test]
fn context_graph_tools_are_listed_and_callable() {
    let listed: serde_json::Value = daemon()
        .mcp_post_json(json!({
            "jsonrpc": "2.0",
            "id": unique_id("mcp-list"),
            "method": "tools/list",
            "params": {}
        }))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    for tool in [
        "get_project_storybook",
        "generate_project_storybook",
        "diff_project_storybook",
        "get_project_dossiers",
        "generate_project_dossier",
        "publish_project_dossier",
        "reconcile_project_dossiers",
        "diff_project_dossiers",
    ] {
        assert!(names.contains(&tool), "tools/list is missing {tool}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime code intelligence — MCP ↔ HTTP parity.
//
// The five `code_*` MCP tools are thin adapters over `GET /v1/code-intel/*`.
// The failure this guards against is a future maintainer reimplementing any of
// the logic on the MCP side: the two surfaces would then answer differently for
// the same question and nothing would say so. Comparing whole payloads — not a
// field or a status code — is what makes that impossible to do quietly.
//
// Trace capture is off in this daemon, so the runtime side of every answer is
// empty. That is deliberate and does not weaken the test: parity is a property
// of the adapter, not of the data, and an empty-window answer still exercises
// argument mapping, encoding, scope and serialisation end to end.
// ─────────────────────────────────────────────────────────────────────────────

/// A path that exists, is small enough to scan instantly, and is real Rust —
/// this test crate's own source.
const CODE_INTEL_REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");

fn code_intel_repo() -> &'static str {
    static REGISTERED: OnceLock<String> = OnceLock::new();
    REGISTERED.get_or_init(|| {
        let repo_id = unique_id("codeintel");
        let raw = mcp_tool_call(
            "register_repo",
            json!({
                "tenant_id": "local",
                "repo_id": repo_id,
                "root_path": CODE_INTEL_REPO_ROOT,
                "languages": ["rust"],
            }),
        );
        let body = mcp_payload(&raw);
        assert_eq!(
            body["repo"]["repo_id"], repo_id,
            "register_repo did not return the registration: {raw}"
        );
        assert!(
            body["repo"]["last_scan_id"].is_string(),
            "registration did not trigger a scan, so the scan-backed tools have nothing to read: {raw}"
        );
        repo_id
    })
}

fn http_json(path: &str) -> serde_json::Value {
    daemon().get(path).unwrap().into_body().read_json().unwrap()
}

/// The tool's own payload, however this daemon chose to frame it.
///
/// Tool results arrive either as a bare `result` object or wrapped in the MCP
/// `content[0].text` envelope depending on the negotiated shape. Which framing
/// is in use is not what these tests are about, so normalise it away rather
/// than pinning one and failing spuriously when the envelope flag flips.
fn mcp_payload(body: &serde_json::Value) -> serde_json::Value {
    assert!(body.get("error").is_none(), "MCP call returned an error: {body}");
    if body["result"]["content"][0]["text"].is_string() {
        mcp_text_json(body)
    } else {
        body["result"].clone()
    }
}

#[test]
fn code_intel_tools_are_listed_with_a_mandatory_token_budget() {
    let body: serde_json::Value = daemon()
        .mcp_post_json(json!({ "jsonrpc": "2.0", "id": unique_id("mcp"), "method": "tools/list" }))
        .unwrap()
        .into_body()
        .read_json()
        .unwrap();
    let tools = body["result"]["tools"].as_array().unwrap();

    for name in [
        "code_path",
        "code_blast_radius",
        "code_liveness",
        "code_trace_diff",
        "code_dead_code",
    ] {
        let tool = tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("{name} not listed by tools/list — registered but undiscoverable"));
        let required: Vec<&str> = tool["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(
            required.contains(&"token_budget"),
            "{name}: token_budget must be required over the wire, got {required:?}"
        );
        assert_eq!(
            tool["inputSchema"]["x-crux-min-tier"], "free",
            "{name}: tier floor missing from the listed schema"
        );
    }
}

#[test]
fn code_intel_mcp_answers_match_http_exactly() {
    let repo = code_intel_repo();
    let budget = 500;

    for (tool, args, http_path) in [
        (
            "code_path",
            json!({ "tenant_id": "local", "entry_point": "post_query_text_search", "token_budget": budget }),
            format!("/v1/code-intel/path?tenant_id=local&entry_point=post_query_text_search&token_budget={budget}"),
        ),
        (
            "code_blast_radius",
            json!({ "tenant_id": "local", "repo_id": repo, "symbol": "TestDaemon", "token_budget": budget }),
            format!(
                "/v1/code-intel/blast-radius?tenant_id=local&repo_id={repo}&symbol=TestDaemon&token_budget={budget}"
            ),
        ),
        (
            "code_liveness",
            json!({ "tenant_id": "local", "repo_id": repo, "symbol": "TestDaemon", "token_budget": budget }),
            format!("/v1/code-intel/liveness?tenant_id=local&repo_id={repo}&symbol=TestDaemon&token_budget={budget}"),
        ),
        (
            "code_trace_diff",
            json!({ "tenant_id": "local", "trace_a": 1, "trace_b": 2, "token_budget": budget }),
            format!("/v1/code-intel/trace-diff?tenant_id=local&trace_a=1&trace_b=2&token_budget={budget}"),
        ),
        (
            "code_dead_code",
            json!({ "tenant_id": "local", "repo_id": repo, "token_budget": 2000 }),
            format!("/v1/code-intel/dead-code?tenant_id=local&repo_id={repo}&token_budget=2000"),
        ),
    ] {
        let via_mcp = mcp_payload(&mcp_tool_call(tool, args));
        let via_http = http_json(&http_path);
        assert_eq!(
            via_mcp, via_http,
            "{tool}: MCP and HTTP answers diverged — the adapter is no longer thin.\n  mcp:  {via_mcp}\n  http: {via_http}"
        );
    }
}

#[test]
fn code_intel_rejects_a_missing_token_budget() {
    // A tool that silently defaults to "everything" defeats the purpose of the
    // surface, so the omission must be an error the caller can read, not a
    // large answer they did not ask for.
    let body = mcp_tool_call("code_path", json!({ "tenant_id": "local", "entry_point": "x" }));
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("token_budget"),
        "expected a token_budget error, got: {body}"
    );
}

#[test]
fn code_liveness_never_reports_an_unseen_symbol_as_dead() {
    // The window is part of the answer. With capture off the window is empty,
    // so the only honest verdict is "not observed" — never "dead".
    let repo = code_intel_repo();
    let body = mcp_payload(&mcp_tool_call(
        "code_liveness",
        json!({ "tenant_id": "local", "repo_id": repo, "symbol": "TestDaemon", "token_budget": 300 }),
    ));
    assert_eq!(body["executed"], false);
    assert!(body["window"].is_object(), "liveness must state its window: {body}");
    let verdict = body["verdict"].as_str().unwrap_or_default();
    assert!(
        !verdict.eq_ignore_ascii_case("dead"),
        "an empty observation window must not yield a `dead` verdict, got {verdict:?}"
    );
}
