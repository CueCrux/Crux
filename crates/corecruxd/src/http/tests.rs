// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use super::admin::*;
use super::append::*;
use super::facts::*;
use super::health::*;
use super::observe::*;
use super::projections::*;
use super::query::*;
use super::receipts::*;
use super::routing::*;
use super::*;

use crate::auth::AuthMode;
use crate::shard_map::LoadedShardMap;
use axum::body::to_bytes;
use corecrux_types::{
    compute_shard_map_v1_blake3_hex, format_u64_hex, HashRange, KnowledgeAuthorityModeV1, KnowledgeRolloutStageV1,
    NodeAddr, ShardDescriptor, ShardMapV1, ShardState, DEFAULT_COMPAT_REQUIRES, DEFAULT_SDK_VERSION,
    SHARDMAP_HASH_FN_V1, SHARDMAP_KEY_ENCODING_V1, SHARDMAP_V1,
};

fn test_node(node_id: &str, http_addr: &str, grpc_addr: &str) -> NodeAddr {
    NodeAddr {
        node_id: node_id.to_string(),
        grpc_addr: grpc_addr.to_string(),
        http_addr: http_addr.to_string(),
    }
}

fn test_routing() -> RoutingTable {
    let mut map = ShardMapV1 {
        v: SHARDMAP_V1,
        cluster_id: "test-cluster".to_string(),
        version: 1,
        created_at: "2026-03-04T00:00:00Z".to_string(),
        hash_fn: SHARDMAP_HASH_FN_V1.to_string(),
        key_encoding: SHARDMAP_KEY_ENCODING_V1.to_string(),
        shards: vec![ShardDescriptor {
            shard_id: "shard-0001".to_string(),
            epoch: 1,
            state: ShardState::Active,
            ranges: vec![HashRange {
                start_inclusive: format_u64_hex(0),
                end_exclusive: format_u64_hex(0),
            }],
            leader: test_node("node-a", "http://127.0.0.1:4006", "http://127.0.0.1:50051"),
            followers: None,
            data_dir: None,
            gpu_id: Some(0),
        }],
        blake3: String::new(),
        prev_blake3: None,
    };
    map.blake3 = compute_shard_map_v1_blake3_hex(&map).expect("compute shardmap hash");
    RoutingTable::new(LoadedShardMap {
        current_version: map.version,
        shard_map: map,
    })
    .expect("routing table")
}

fn test_app_state_with_auth(action_max_pending: usize, auth_mode: AuthMode) -> AppState {
    let build = corecrux_types::BuildInfo {
        version: "test".to_string(),
        commit: "test".to_string(),
    };
    let metrics = crate::metrics::Metrics::new(&build, "corecruxd-test");
    let auth = Authz::from_env(auth_mode).expect("auth init");

    let root = std::env::temp_dir().join(format!("corecruxd-http-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("create test dir");
    let control_path = root.join("CONTROL.json");

    AppState {
        lock_held: true,
        build,
        compat: CompatContract {
            requires: DEFAULT_COMPAT_REQUIRES.to_string(),
        },
        sdk_version: DEFAULT_SDK_VERSION.to_string(),
        auth,
        data_dir: root.clone(),
        mcp_enabled: true,
        console_enabled: true,
        integrations_enabled: true,
        integrations_safe_mode: false,
        integrations_allow_executable_helpers: false,
        read_retry_failed_readyz_threshold: 0,
        commit_level: CommitLevel::LocalCommit,
        metrics,
        node_id: "node-a".to_string(),
        passport_fpr: "p_test".to_string(),
        passport_public_key_hex: "00".repeat(32),
        mcp_agent_count: 0,
        routing: Arc::new(RwLock::new(test_routing())),
        routing_errors: Arc::new(RwLock::new(Vec::new())),
        dataplane_pool: None,
        http_dataplane: pool_backed_http_dataplane(None),
        readiness: Arc::new(RwLock::new(Readiness::default())),
        control: Arc::new(RwLock::new(control::ControlV1::default())),
        control_path,
        action_max_pending,
        action_timeout_secs: 5,
        scrub_scope: "recent".to_string(),
        scrub_mode: "sampled".to_string(),
        scrub_sample_rate: 0.25,
        admin_actions: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
        corruption_detected: Arc::new(RwLock::new(false)),
        admin_force_seal_enabled: false,
        retrieval_index: Arc::new(RwLock::new(corecrux_retrieval::IndexManager::new())),
        fact_store: Arc::new(RwLock::new(corecrux_memory::FactStore::new())),
        session_store: Arc::new(RwLock::new(corecrux_memory::SessionStore::new())),
        update_status: Arc::new(RwLock::new(corecrux_types::UpdateStatus::default())),
        event_bus: corecrux_memory::events::EventBus::new(16),
        capacity: Arc::new(RwLock::new(CapacityState {
            total_bytes: 100,
            free_bytes: 80,
            free_ratio: 0.8,
            warning_free_ratio: 0.20,
            critical_free_ratio: 0.10,
            emergency_free_ratio: 0.10,
            auto_paused: false,
            error: None,
        })),
        session: None,
        extraction_cache: std::sync::Arc::new(tokio::sync::RwLock::new(
            corecrux_projections::ExtractionCacheMaterializer::new(),
        )),
    }
}

fn test_app_state(action_max_pending: usize) -> AppState {
    test_app_state_with_auth(action_max_pending, AuthMode::Off)
}

fn dev_scope_headers(scopes: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-corecrux-scopes",
        HeaderValue::from_str(scopes).expect("valid test scope header"),
    );
    headers
}

async fn json_body(resp: Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
    serde_json::from_slice(&bytes).expect("json body")
}

async fn mark_ready_except_control(state: &AppState) {
    // No GPU fields to set; Readiness::default() is already ready for CPU-only.
    let _ = state.readiness.read().await;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeAppendCall {
    tenant_id: String,
    stream_type: String,
    stream_id: String,
    expected_next_seq: u64,
    event_ids: Vec<String>,
}

#[derive(Default)]
struct FakeHttpDataplane {
    enabled: bool,
    append_calls: std::sync::Mutex<Vec<FakeAppendCall>>,
    read_stream_events: Vec<corecrux_storage::StoredEvent>,
    verification_report: Option<corecrux_receipts::VerificationReportV1>,
    graph_expand_response: Option<corecrux_projections::query::graph_expand::GraphExpandResponse>,
    projection_meta: Option<corecrux_projections::ProjectionsMetaV1>,
}

#[tonic::async_trait]
impl HttpDataplane for FakeHttpDataplane {
    fn enabled(&self) -> bool {
        self.enabled
    }

    async fn append_batch(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        expected_next_seq: u64,
        events: &[AppendEvent],
    ) -> Result<(), HttpDataplaneError> {
        self.append_calls.lock().unwrap().push(FakeAppendCall {
            tenant_id: tenant_id.to_string(),
            stream_type: stream_type.to_string(),
            stream_id: stream_id.to_string(),
            expected_next_seq,
            event_ids: events.iter().map(|event| event.event_id.clone()).collect(),
        });
        Ok(())
    }

    async fn read_stream(
        &self,
        _tenant_id: &str,
        _stream_type: &str,
        _stream_id: &str,
        _from_seq: u64,
        _max_events: u32,
    ) -> Result<Vec<corecrux_storage::StoredEvent>, HttpDataplaneError> {
        Ok(self.read_stream_events.clone())
    }

    async fn read_tail(
        &self,
        _tenant_id: &str,
        _stream_type: &str,
        _stream_id: &str,
        _count: u32,
    ) -> Result<Vec<corecrux_storage::StoredEvent>, HttpDataplaneError> {
        Ok(Vec::new())
    }

    async fn verify_receipt_stream(
        &self,
        _tenant_id: &str,
        _receipt_id: &str,
        _shard_id_hint: Option<u32>,
    ) -> Result<Option<corecrux_receipts::VerificationReportV1>, HttpDataplaneError> {
        Ok(self.verification_report.clone())
    }

    async fn graph_expand(
        &self,
        _req: super::dataplane::GraphExpandRequest<'_>,
    ) -> Result<corecrux_projections::query::graph_expand::GraphExpandResponse, HttpDataplaneError> {
        Ok(self.graph_expand_response.clone().unwrap_or(
            corecrux_projections::query::graph_expand::GraphExpandResponse {
                artifacts: Vec::new(),
                stats: Default::default(),
            },
        ))
    }

    async fn time_range(
        &self,
        _tenant_id: &str,
        _start_micros: i64,
        _end_micros: i64,
        _artifact_ids: &[u32],
        _include_relations: bool,
        _limit: usize,
    ) -> Result<corecrux_projections::query::time_range::TimeRangeResponse, HttpDataplaneError> {
        Ok(corecrux_projections::query::time_range::TimeRangeResponse {
            artifacts: Vec::new(),
            stats: Default::default(),
        })
    }

    async fn projection_meta(
        &self,
        _shard_id: &str,
    ) -> Result<Option<corecrux_projections::ProjectionsMetaV1>, HttpDataplaneError> {
        Ok(self.projection_meta.clone())
    }

    async fn projection_artifact_state(
        &self,
        _tenant_id: &str,
        _artifact_id: u32,
    ) -> Result<Option<corecrux_projections::LivingStateRowV1>, HttpDataplaneError> {
        Ok(None)
    }

    async fn projection_relations(
        &self,
        _tenant_id: &str,
        _artifact_id: u32,
        _direction: &str,
        _relation_type: Option<&str>,
        _limit: usize,
        _offset: usize,
    ) -> Result<Vec<crate::dataplane_store::ProjectionRelationRowV1>, HttpDataplaneError> {
        Ok(Vec::new())
    }

    async fn projection_dependents(
        &self,
        _tenant_id: &str,
        _artifact_id: u32,
        _dependent_type: Option<&str>,
        _limit: usize,
        _offset: usize,
    ) -> Result<Vec<crate::dataplane_store::ProjectionDependentRowV1>, HttpDataplaneError> {
        Ok(Vec::new())
    }

    async fn projection_pressure_events(
        &self,
        _tenant_id: &str,
        _artifact_id: u32,
        _open_only: bool,
        _limit: usize,
        _offset: usize,
    ) -> Result<Vec<crate::dataplane_store::ProjectionPressureEventRowV1>, HttpDataplaneError> {
        Ok(Vec::new())
    }

    async fn rebuild_projections_online(
        &self,
        _max_frames: u32,
    ) -> Result<Vec<(String, Result<crate::dataplane_store::ForceSealAndTickResult, String>)>, HttpDataplaneError> {
        Ok(Vec::new())
    }

    async fn entity_count(
        &self,
        _tenant_id: &str,
        _entity_type: &str,
        _predicate: &str,
    ) -> Result<Vec<String>, HttpDataplaneError> {
        Ok(Vec::new())
    }

    async fn entity_timeline(
        &self,
        _tenant_id: &str,
        _entity_type: &str,
        _predicate: &str,
    ) -> Result<Vec<(String, String, i64)>, HttpDataplaneError> {
        Ok(Vec::new())
    }

    async fn entity_current_state(
        &self,
        _tenant_id: &str,
        _entity_name: &str,
        _predicate: &str,
    ) -> Result<Option<(String, i64, Option<String>, Option<i64>)>, HttpDataplaneError> {
        Ok(None)
    }
}

fn fake_stored_event(seq: u64, event_type: &str, content_type: &str, payload: &[u8]) -> corecrux_storage::StoredEvent {
    corecrux_storage::StoredEvent {
        seq,
        event_id: format!("evt-{seq}"),
        occurred_at: "2026-04-08T12:00:00Z".to_string(),
        ingested_at: "2026-04-08T12:00:01Z".to_string(),
        event_type: event_type.to_string(),
        content_type: content_type.to_string(),
        payload: payload.to_vec(),
        location: corecrux_storage::FrameLocation {
            shard_id: 1,
            epoch: 1,
            segment_seq: 1,
            offset: seq * 16,
        },
    }
}

#[tokio::test]
async fn readyz_fails_when_hosted_control_evidence_is_invalid() {
    let state = test_app_state(16);
    mark_ready_except_control(&state).await;
    {
        let mut readiness = state.readiness.write().await;
        readiness.control_evidence_hosted = true;
        readiness.control_evidence_ok = false;
        readiness.control_evidence_error = Some("checkpoint mismatch".to_string());
    }

    let resp = health::readyz(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = json_body(resp).await;
    assert_eq!(body["ok"], false);
    let checks = body["checks"].as_array().expect("checks array");
    assert!(checks
        .iter()
        .any(|check| { check["name"] == "control_evidence_ok" && check["error"] == "checkpoint mismatch" }));
}

#[tokio::test]
async fn readyz_ignores_control_evidence_errors_when_stream_not_hosted() {
    let state = test_app_state(16);
    mark_ready_except_control(&state).await;
    {
        let mut readiness = state.readiness.write().await;
        readiness.control_evidence_hosted = false;
        readiness.control_evidence_ok = false;
        readiness.control_evidence_error = Some("not hosted locally; checkpoint fallback".to_string());
    }

    let resp = health::readyz(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["ok"], true);
}

#[tokio::test]
async fn runtime_knob_update_updates_knowledge_authority() {
    let state = test_app_state(16);
    let params = serde_json::json!({
        "actor": "ops",
        "reason": "rollout-stage",
        "knowledgeAuthorityMode": "knowledge_dual_write",
        "knowledgeAuthorityRolloutStage": "tenant_validation",
        "knowledgeMaxMismatchCount": 3,
        "knowledgeMaxCursorMissingCount": 5,
        "knowledgeMinPassRatioBps": 9750,
        "knowledgeMaxProjectionLagMs": 1500,
        "knowledgeMaxCursorAgeMs": 2400,
        "knowledgeRollbackTriggered": true,
        "knowledgeLastParityStatus": "warn",
        "knowledgeLastParityCheckedAtUnixMs": 111,
        "knowledgeLastParityMismatchCount": 2,
        "knowledgeLastParityCursorMissingCount": 1,
        "knowledgeLastParityPassRatioBps": 9810,
        "knowledgeLastParityLagMs": 444,
        "knowledgeLastParityDetail": "parity drift"
    });

    let result = admin::execute_admin_action(
        &state,
        "act-knowledge-1",
        "runtime-knob-update",
        Some(&params),
        None,
        None,
    )
    .await
    .expect("runtime knob update succeeds");

    assert_eq!(
        result.result["knowledgeAuthority"]["mode"],
        serde_json::json!("knowledge_dual_write")
    );

    let control = state.control.read().await.clone();
    assert_eq!(control.knowledge_authority.mode, KnowledgeAuthorityModeV1::DualWrite);
    assert_eq!(
        control.knowledge_authority.rollout_stage,
        KnowledgeRolloutStageV1::TenantValidation
    );
    assert_eq!(control.knowledge_authority.parity_thresholds.max_mismatch_count, 3);
    assert_eq!(
        control.knowledge_authority.parity_thresholds.max_cursor_missing_count,
        5
    );
    assert_eq!(control.knowledge_authority.parity_thresholds.min_pass_ratio_bps, 9750);
    assert_eq!(control.knowledge_authority.lag_thresholds.max_projection_lag_ms, 1500);
    assert_eq!(control.knowledge_authority.lag_thresholds.max_cursor_age_ms, 2400);
    assert!(control.knowledge_authority.rollback_triggered);
    assert_eq!(control.knowledge_authority.actor, "ops");
    assert_eq!(control.knowledge_authority.reason, "rollout-stage");
    assert!(control.knowledge_authority.updated_at_unix_ns > 0);
    let parity = control
        .knowledge_authority
        .last_parity_outcome
        .expect("parity outcome recorded");
    assert_eq!(parity.status.as_str(), "warn");
    assert_eq!(parity.checked_at_unix_ms, 111);
    assert_eq!(parity.mismatch_count, 2);
    assert_eq!(parity.cursor_missing_count, 1);
    assert_eq!(parity.pass_ratio_bps, 9810);
    assert_eq!(parity.projection_lag_ms, 444);
    assert_eq!(parity.detail.as_deref(), Some("parity drift"));
}

#[tokio::test]
async fn runtime_knob_update_updates_tenant_throttles() {
    let state = test_app_state(16);
    let params = serde_json::json!({
        "actor": "ops",
        "reason": "tenant-isolation",
        "tenantThrottleRules": [
            {
                "tenantId": "tenant-a",
                "eventsPerSec": 15,
                "bytesPerSec": 4096,
                "maxInFlight": 3
            }
        ]
    });

    let result = admin::execute_admin_action(
        &state,
        "act-tenant-throttle-1",
        "runtime-knob-update",
        Some(&params),
        None,
        None,
    )
    .await
    .expect("runtime knob update succeeds");

    assert_eq!(
        result.result["tenantThrottles"][0]["tenantId"],
        serde_json::json!("tenant-a")
    );
    let control = state.control.read().await.clone();
    assert_eq!(control.tenant_throttles.len(), 1);
    assert_eq!(control.tenant_throttles[0].tenant_id, "tenant-a");
    assert_eq!(control.tenant_throttles[0].events_per_sec, Some(15));
    assert_eq!(control.tenant_throttles[0].bytes_per_sec, Some(4096));
    assert_eq!(control.tenant_throttles[0].max_in_flight, Some(3));
}

#[tokio::test]
async fn runtime_knob_update_clears_knowledge_parity_outcome() {
    let state = test_app_state(16);
    admin::execute_admin_action(
        &state,
        "act-knowledge-seed",
        "runtime-knob-update",
        Some(&serde_json::json!({
            "actor": "ops",
            "reason": "seed-parity",
            "knowledgeLastParityStatus": "fail",
            "knowledgeLastParityCheckedAtUnixMs": 222,
            "knowledgeLastParityMismatchCount": 9
        })),
        None,
        None,
    )
    .await
    .expect("seed parity outcome");

    admin::execute_admin_action(
        &state,
        "act-knowledge-clear",
        "runtime-knob-update",
        Some(&serde_json::json!({
            "actor": "ops",
            "reason": "clear-parity",
            "knowledgeClearParityOutcome": true
        })),
        None,
        None,
    )
    .await
    .expect("clear parity outcome");

    assert!(state
        .control
        .read()
        .await
        .knowledge_authority
        .last_parity_outcome
        .is_none());
}

#[tokio::test]
async fn get_control_returns_knowledge_authority() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut control = state.control.write().await;
        control.knowledge_authority.mode = KnowledgeAuthorityModeV1::Authoritative;
        control.knowledge_authority.rollout_stage = KnowledgeRolloutStageV1::FullProductionAuthority;
    }

    let resp = admin::get_control(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["knowledgeAuthority"]["mode"], "knowledge_authoritative");
    assert_eq!(body["knowledgeAuthority"]["rolloutStage"], "full_production_authority");
}

#[tokio::test]
async fn admin_action_submit_is_idempotent_by_action_id() {
    let state = test_app_state(16);
    let req_a = admin::PostAdminActionRequest {
        action_id: Some("act-fixed-1".to_string()),
        action_type: "runtime-knob-update".to_string(),
        actor: Some("test".to_string()),
        reason: Some("idempotency-check".to_string()),
        params: Some(serde_json::json!({
            "throttleEnabled": true,
            "throttleEventsPerSec": 42
        })),
    };

    let resp_a = admin::post_admin_action(State(state.clone()), HeaderMap::new(), Json(req_a))
        .await
        .into_response();
    assert_eq!(resp_a.status(), StatusCode::ACCEPTED);
    let body_a = json_body(resp_a).await;
    assert_eq!(body_a["accepted"], true);
    assert_eq!(body_a["action"]["actionId"], "act-fixed-1");

    let req_b = admin::PostAdminActionRequest {
        action_id: Some("act-fixed-1".to_string()),
        action_type: "runtime-knob-update".to_string(),
        actor: Some("test".to_string()),
        reason: Some("idempotency-check".to_string()),
        params: Some(serde_json::json!({
            "throttleEnabled": true,
            "throttleEventsPerSec": 42
        })),
    };
    let resp_b = admin::post_admin_action(State(state.clone()), HeaderMap::new(), Json(req_b))
        .await
        .into_response();
    assert_eq!(resp_b.status(), StatusCode::ACCEPTED);
    let body_b = json_body(resp_b).await;
    assert_eq!(body_b["accepted"], true);
    assert_eq!(body_b["action"]["actionId"], "act-fixed-1");

    let actions = state.admin_actions.read().await;
    assert_eq!(actions.len(), 1, "idempotent submit must not create duplicates");
    drop(actions);

    let get_resp = admin::get_admin_action(State(state), HeaderMap::new(), Path("act-fixed-1".to_string()))
        .await
        .into_response();
    assert_eq!(get_resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn admin_action_unknown_type_returns_problem_details() {
    let state = test_app_state(16);
    let req = admin::PostAdminActionRequest {
        action_id: None,
        action_type: "unknown-action".to_string(),
        actor: None,
        reason: None,
        params: None,
    };

    let resp = admin::post_admin_action(State(state), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json")
    );

    let body = json_body(resp).await;
    assert_eq!(body["status"], 400);
    assert_eq!(body["title"], "Bad Request");
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(detail.contains("unknown actionType"), "unexpected detail: {detail}");
}

#[tokio::test]
async fn admin_action_get_missing_returns_problem_details() {
    let state = test_app_state(16);
    let resp = admin::get_admin_action(State(state), HeaderMap::new(), Path("missing-action".to_string()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json")
    );
    let body = json_body(resp).await;
    assert_eq!(body["status"], 404);
    assert_eq!(body["title"], "Not Found");
    assert!(body["detail"].as_str().unwrap_or_default().contains("missing-action"));
}

#[tokio::test]
async fn shard_map_requires_admin_scope_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    let unauthorized = admin::get_shard_map(State(state.clone()), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorized = admin::get_shard_map(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(authorized.status(), StatusCode::OK);
}

#[tokio::test]
async fn console_read_endpoints_require_admin_scope_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    let missing = console::get_console_summary(State(state.clone()), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let wrong_scope = console::get_console_summary(State(state.clone()), dev_scope_headers("facts:read"))
        .await
        .into_response();
    assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);

    let allowed = console::get_console_summary(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(allowed.status(), StatusCode::OK);
}

#[tokio::test]
async fn console_redacts_private_facts_and_session_state() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut facts = state.fact_store.write().await;
        facts.store(corecrux_memory::fact_store::StoreFact {
            entity: "tenant-a::service".to_string(),
            key: "public".to_string(),
            value: "safe value".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        });
        facts.store(corecrux_memory::fact_store::StoreFact {
            entity: "tenant-a::service".to_string(),
            key: "api_key".to_string(),
            value: "secret-token-123".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
        });
    }
    state.session_store.write().await.put(
        "sess-secret",
        serde_json::json!({"token": "secret-session-token"}),
        None,
    );

    let facts_resp = console::get_console_facts(State(state.clone()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(facts_resp.status(), StatusCode::OK);
    let facts_body = json_body(facts_resp).await;
    assert_eq!(facts_body["private_facts_hidden"], true);
    assert_eq!(facts_body["visible_count"], 1);
    let facts_text = serde_json::to_string(&facts_body).expect("facts json");
    assert!(!facts_text.contains("secret-token-123"));

    let sessions_resp = console::get_console_sessions(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(sessions_resp.status(), StatusCode::OK);
    let sessions_body = json_body(sessions_resp).await;
    assert_eq!(sessions_body["raw_state_exposed"], false);
    assert_eq!(sessions_body["sessions"][0], "sess-secret");
    let sessions_text = serde_json::to_string(&sessions_body).expect("sessions json");
    assert!(!sessions_text.contains("secret-session-token"));
}

#[tokio::test]
async fn console_integration_install_grant_disable_roundtrip() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    let install = console::post_console_integration_install(
        State(state.clone()),
        Path("mcp.cursor".to_string()),
        dev_scope_headers("integrations:install"),
        Json(console::InstallIntegrationBody {
            manifest: None,
            pack_id: None,
            version: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(install.status(), StatusCode::CREATED);

    let grant = console::post_console_integration_grant(
        State(state.clone()),
        Path("mcp.cursor".to_string()),
        dev_scope_headers("integrations:grant"),
        Json(console::GrantIntegrationBody {
            version: "0.1.0".to_string(),
            capabilities: vec!["integrations:read".to_string(), "passport:read".to_string()],
            reason: Some("test grant".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(grant.status(), StatusCode::OK);
    let grant_body = json_body(grant).await;
    assert_eq!(grant_body["enabled"], true);

    let snapshot = console::get_console_integrations(State(state.clone()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(snapshot.status(), StatusCode::OK);
    let snapshot_body = json_body(snapshot).await;
    let cursor = snapshot_body["packs"]
        .as_array()
        .expect("packs array")
        .iter()
        .find(|pack| pack["manifest"]["id"] == "mcp.cursor")
        .expect("cursor pack");
    assert_eq!(cursor["install_state"], "enabled");
    assert_eq!(snapshot_body["grants"].as_array().expect("grants array").len(), 1);

    let disabled = console::post_console_integration_disable(
        State(state.clone()),
        Path("mcp.cursor".to_string()),
        dev_scope_headers("integrations:disable"),
        Json(console::DisableIntegrationBody {
            reason: Some("test disable".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(disabled.status(), StatusCode::OK);
    let disabled_body = json_body(disabled).await;
    assert_eq!(disabled_body["enabled"], false);
}

#[tokio::test]
async fn console_integration_grant_requires_specific_scope() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let install = console::post_console_integration_install(
        State(state.clone()),
        Path("mcp.cursor".to_string()),
        dev_scope_headers("integrations:install"),
        Json(console::InstallIntegrationBody {
            manifest: None,
            pack_id: None,
            version: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(install.status(), StatusCode::CREATED);

    let rejected = console::post_console_integration_grant(
        State(state),
        Path("mcp.cursor".to_string()),
        dev_scope_headers("admin:read"),
        Json(console::GrantIntegrationBody {
            version: "0.1.0".to_string(),
            capabilities: vec!["integrations:read".to_string()],
            reason: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn console_chunk_index_lists_metadata_and_scoped_redacted_preview() {
    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    state.http_dataplane = Arc::new(FakeHttpDataplane {
        enabled: true,
        ..Default::default()
    });
    let body = append::AppendBody {
        tenant_id: "tenant-a".to_string(),
        stream_type: "artifact".to_string(),
        stream_id: "stream-a".to_string(),
        expected_next_seq: 7,
        events: vec![append::AppendEventBody {
            event_id: "evt-secret".to_string(),
            occurred_at: "2026-05-01T12:00:00Z".to_string(),
            event_type: "artifact.updated".to_string(),
            content_type: "application/json".to_string(),
            payload: r#"{"token":"secret-value","ok":true}"#.to_string(),
        }],
    };
    let append_resp = append::post_admin_append(State(state.clone()), dev_scope_headers("admin:write"), Json(body))
        .await
        .into_response();
    assert_eq!(append_resp.status(), StatusCode::CREATED);

    let denied_list = console::get_console_tenant_chunks(
        State(state.clone()),
        Path("tenant-a".to_string()),
        Query(console::ConsoleChunksQuery {
            limit: Some(10),
            cursor: None,
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(denied_list.status(), StatusCode::FORBIDDEN);

    let list_resp = console::get_console_tenant_chunks(
        State(state.clone()),
        Path("tenant-a".to_string()),
        Query(console::ConsoleChunksQuery {
            limit: Some(10),
            cursor: None,
        }),
        dev_scope_headers("tenant:chunks:read"),
    )
    .await
    .into_response();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_body = json_body(list_resp).await;
    assert_eq!(list_body["chunks"].as_array().expect("chunks array").len(), 1);
    assert_eq!(list_body["chunks"][0]["seq"], 7);
    let chunk_digest = list_body["chunks"][0]["chunk_digest"]
        .as_str()
        .expect("chunk digest")
        .to_string();
    let list_text = serde_json::to_string(&list_body).expect("chunks json");
    assert!(!list_text.contains("secret-value"));

    let preview_denied = console::get_console_chunk_preview(
        State(state.clone()),
        Path(chunk_digest.clone()),
        dev_scope_headers("tenant:chunks:read"),
    )
    .await
    .into_response();
    assert_eq!(preview_denied.status(), StatusCode::FORBIDDEN);

    let preview = console::get_console_chunk_preview(
        State(state),
        Path(chunk_digest),
        dev_scope_headers("tenant:content:preview"),
    )
    .await
    .into_response();
    assert_eq!(preview.status(), StatusCode::OK);
    let preview_body = json_body(preview).await;
    assert_eq!(preview_body["redacted"], true);
    assert_eq!(preview_body["preview"], "[redacted secret-like content]");
}

// ── Phase 1 / 1.5 endpoint tests ─────────────────────────────────

// ── Fact Store (PUT /v1/facts) ──────────────────────────────────

#[tokio::test]
async fn put_fact_returns_created() {
    let state = test_app_state(16);
    let body = corecrux_memory::fact_store::StoreFact {
        entity: "server".to_string(),
        key: "role".to_string(),
        value: "database primary".to_string(),
        source_receipt: Some("crx_abc".to_string()),
        confidence: 0.95,
        private: false,
    };

    let resp = facts::put_fact(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert!(body["fact_id"].as_str().unwrap().starts_with("f_"));
    assert_eq!(body["entity"], "server");
    assert_eq!(body["key"], "role");
    assert_eq!(body["value"], "database primary");
    assert_eq!(body["source_receipt"], "crx_abc");
    assert_eq!(body["deleted"], false);
}

#[tokio::test]
async fn put_fact_rejects_private_true_over_http() {
    let state = test_app_state(16);
    let body = corecrux_memory::fact_store::StoreFact {
        entity: "server".to_string(),
        key: "internal".to_string(),
        value: "secret".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: true,
    };

    let resp = facts::put_fact(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert!(body["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("private facts require MCP agent identity"));
}

#[tokio::test]
async fn put_facts_bulk_rejects_private_true_over_http() {
    let state = test_app_state(16);
    let body = vec![
        corecrux_memory::fact_store::StoreFact {
            entity: "server".to_string(),
            key: "role".to_string(),
            value: "primary".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        },
        corecrux_memory::fact_store::StoreFact {
            entity: "server".to_string(),
            key: "internal".to_string(),
            value: "secret".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
        },
    ];

    let resp = facts::put_facts_bulk(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert!(body["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("private facts require MCP agent identity"));
}

// ── Fact Store (GET /v1/facts/{factId}) ─────────────────────────

#[tokio::test]
async fn get_fact_returns_stored_fact() {
    let state = test_app_state(16);
    let body = corecrux_memory::fact_store::StoreFact {
        entity: "deploy".to_string(),
        key: "strategy".to_string(),
        value: "canary".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
    };

    let create_resp = facts::put_fact(State(state.clone()), HeaderMap::new(), Json(body))
        .await
        .into_response();
    let created = json_body(create_resp).await;
    let fact_id = created["fact_id"].as_str().unwrap().to_string();

    let resp = facts::get_fact(State(state), HeaderMap::new(), Path(fact_id.clone()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["fact_id"], fact_id);
    assert_eq!(body["value"], "canary");
}

#[tokio::test]
async fn get_fact_not_found() {
    let state = test_app_state(16);
    let resp = get_fact(State(state), HeaderMap::new(), Path("nonexistent".to_string()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = json_body(resp).await;
    assert!(body["detail"].as_str().unwrap_or_default().contains("nonexistent"));
}

// ── Fact Store (DELETE /v1/facts/{factId}) ──────────────────────

#[tokio::test]
async fn delete_fact_soft_deletes() {
    let state = test_app_state(16);
    let body = corecrux_memory::fact_store::StoreFact {
        entity: "e".to_string(),
        key: "k".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
    };

    let create_resp = facts::put_fact(State(state.clone()), HeaderMap::new(), Json(body))
        .await
        .into_response();
    let created = json_body(create_resp).await;
    let fact_id = created["fact_id"].as_str().unwrap().to_string();

    let del_resp = facts::delete_fact(State(state.clone()), HeaderMap::new(), Path(fact_id.clone()))
        .await
        .into_response();
    assert_eq!(del_resp.status(), StatusCode::OK);
    let del_body = json_body(del_resp).await;
    assert_eq!(del_body["deleted"], true);

    // GET after delete should return 404
    let get_resp = facts::get_fact(State(state), HeaderMap::new(), Path(fact_id))
        .await
        .into_response();
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_fact_not_found() {
    let state = test_app_state(16);
    let resp = delete_fact(State(state), HeaderMap::new(), Path("no-such-fact".to_string()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Fact Store (GET /v1/facts/entity/{entity}) ──────────────────

#[tokio::test]
async fn get_facts_by_entity_returns_matching() {
    let state = test_app_state(16);

    for (entity, key, value) in [
        ("proj-a", "name", "alpha"),
        ("proj-a", "status", "active"),
        ("proj-b", "name", "beta"),
    ] {
        let body = corecrux_memory::fact_store::StoreFact {
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        };
        let _ = facts::put_fact(State(state.clone()), HeaderMap::new(), Json(body))
            .await
            .into_response();
    }

    let resp = facts::get_facts_by_entity(State(state), HeaderMap::new(), Path("proj-a".to_string()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let facts = body["facts"].as_array().expect("facts array");
    assert_eq!(facts.len(), 2);
}

#[tokio::test]
async fn get_facts_by_entity_empty() {
    let state = test_app_state(16);
    let resp = facts::get_facts_by_entity(State(state), HeaderMap::new(), Path("no-entity".to_string()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let facts = body["facts"].as_array().expect("facts array");
    assert!(facts.is_empty());
}

// ── Fact Store (PUT /v1/facts/bulk) ─────────────────────────────

#[tokio::test]
async fn bulk_store_facts() {
    let state = test_app_state(16);
    let facts = vec![
        corecrux_memory::fact_store::StoreFact {
            entity: "a".to_string(),
            key: "k1".to_string(),
            value: "v1".to_string(),
            source_receipt: None,
            confidence: 0.8,
            private: false,
        },
        corecrux_memory::fact_store::StoreFact {
            entity: "b".to_string(),
            key: "k2".to_string(),
            value: "v2".to_string(),
            source_receipt: Some("rcpt".to_string()),
            confidence: 0.9,
            private: false,
        },
    ];

    let resp = facts::put_facts_bulk(State(state.clone()), HeaderMap::new(), Json(facts))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    let stored = body["facts"].as_array().expect("facts array");
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0]["entity"], "a");
    assert_eq!(stored[1]["entity"], "b");

    // Verify they're queryable
    let store = state.fact_store.read().await;
    assert_eq!(store.count(), 2);
}

// ── Fact Store (GET /v1/facts?query=...) ────────────────────────

#[tokio::test]
async fn query_facts_by_keyword() {
    let state = test_app_state(16);
    for (entity, key, value) in [
        ("deploy", "method", "canary deployment"),
        ("testing", "approach", "integration tests"),
    ] {
        let body = corecrux_memory::fact_store::StoreFact {
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        };
        let _ = facts::put_fact(State(state.clone()), HeaderMap::new(), Json(body))
            .await
            .into_response();
    }

    let params = QueryFactsParams {
        query: Some("canary".to_string()),
        entity: None,
        entity_prefix: None,
        top_k: None,
        token_budget: None,
    };

    let resp = facts::query_facts(State(state), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let facts = body["facts"].as_array().expect("facts array");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0]["entity"], "deploy");
    assert!(body["total_tokens"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn query_facts_no_params_returns_all() {
    let state = test_app_state(16);
    for i in 0..3 {
        let body = corecrux_memory::fact_store::StoreFact {
            entity: format!("e{}", i),
            key: "k".to_string(),
            value: format!("val{}", i),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        };
        let _ = facts::put_fact(State(state.clone()), HeaderMap::new(), Json(body))
            .await
            .into_response();
    }

    let params = QueryFactsParams {
        query: None,
        entity: None,
        entity_prefix: None,
        top_k: None,
        token_budget: None,
    };
    let resp = facts::query_facts(State(state), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let facts = body["facts"].as_array().expect("facts array");
    assert_eq!(facts.len(), 3);
}

#[tokio::test]
async fn query_facts_accepts_admin_read_fallback_in_dev_scopes_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let body = corecrux_memory::fact_store::StoreFact {
        entity: "deploy".to_string(),
        key: "status".to_string(),
        value: "green".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
    };
    let _ = facts::put_fact(State(state.clone()), dev_scope_headers("admin:read"), Json(body))
        .await
        .into_response();

    let params = QueryFactsParams {
        query: Some("green".to_string()),
        entity: None,
        entity_prefix: None,
        top_k: None,
        token_budget: None,
    };
    let resp = facts::query_facts(State(state), dev_scope_headers("admin:read"), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["facts"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn export_facts_handles_invalid_since_and_limit_and_skips_private() {
    let state = test_app_state(16);
    {
        let mut store = state.fact_store.write().await;
        store.store(corecrux_memory::fact_store::StoreFact {
            entity: "public".to_string(),
            key: "status".to_string(),
            value: "green".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        });
        store.store(corecrux_memory::fact_store::StoreFact {
            entity: "secret".to_string(),
            key: "salary".to_string(),
            value: "redacted".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
        });
    }

    let params = ExportFactsParams {
        since: Some("not-a-date".to_string()),
        cursor: None,
        limit: None,
    };

    let resp = facts::export_facts(State(state), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let facts = body["facts"].as_array().unwrap();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0]["entity"], "public");
    assert_eq!(body["has_more"], false);
}

#[tokio::test]
async fn export_facts_honors_cursor_and_reports_next_cursor() {
    let state = test_app_state(16);
    let mut fact_ids = Vec::new();
    for value in ["one", "two", "three"] {
        let mut store = state.fact_store.write().await;
        let fact = store.store(corecrux_memory::fact_store::StoreFact {
            entity: "deploy".to_string(),
            key: value.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        });
        fact_ids.push(fact.fact_id);
    }

    let params = ExportFactsParams {
        since: None,
        cursor: Some(fact_ids[0].clone()),
        limit: Some(1),
    };

    let resp = facts::export_facts(State(state), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let facts = body["facts"].as_array().unwrap();
    assert_eq!(facts.len(), 1);
    assert_eq!(body["has_more"], true);
    assert_eq!(body["next_cursor"], facts[0]["fact_id"]);
}

// ── Session Store (PUT /v1/sessions/{sessionId}/state) ──────────

#[tokio::test]
async fn put_session_state_creates_session() {
    let state = test_app_state(16);
    let session_data = serde_json::json!({
        "decisions": ["chose canary"],
        "open_questions": ["GPU timing"],
    });

    let resp = facts::put_session_state(
        State(state.clone()),
        HeaderMap::new(),
        Path("sess-001".to_string()),
        Json(session_data.clone()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["session_id"], "sess-001");
    assert!(body["total_tokens"].as_u64().unwrap() > 0);
}

// ── Session Store (GET /v1/sessions/{sessionId}/state) ──────────

#[tokio::test]
async fn get_session_state_round_trip() {
    let state = test_app_state(16);
    let session_data = serde_json::json!({"step": 1, "context": "building"});

    let _ = facts::put_session_state(
        State(state.clone()),
        HeaderMap::new(),
        Path("sess-rt".to_string()),
        Json(session_data.clone()),
    )
    .await
    .into_response();

    let resp = facts::get_session_state(State(state), HeaderMap::new(), Path("sess-rt".to_string()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["session_id"], "sess-rt");
    assert_eq!(body["state"]["step"], 1);
    assert_eq!(body["state"]["context"], "building");
}

#[tokio::test]
async fn get_session_state_not_found() {
    let state = test_app_state(16);
    let resp = facts::get_session_state(State(state), HeaderMap::new(), Path("no-session".to_string()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = json_body(resp).await;
    assert!(body["detail"].as_str().unwrap_or_default().contains("no-session"));
}

#[tokio::test]
async fn get_session_state_accepts_admin_read_fallback_in_dev_scopes_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let _ = facts::put_session_state(
        State(state.clone()),
        dev_scope_headers("admin:read"),
        Path("sess-admin".to_string()),
        Json(serde_json::json!({"step": 2})),
    )
    .await
    .into_response();

    let resp = facts::get_session_state(
        State(state),
        dev_scope_headers("admin:read"),
        Path("sess-admin".to_string()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["state"]["step"], 2);
}

#[tokio::test]
async fn put_session_state_overwrites() {
    let state = test_app_state(16);

    let _ = facts::put_session_state(
        State(state.clone()),
        HeaderMap::new(),
        Path("sess-ow".to_string()),
        Json(serde_json::json!({"v": 1})),
    )
    .await
    .into_response();

    let _ = facts::put_session_state(
        State(state.clone()),
        HeaderMap::new(),
        Path("sess-ow".to_string()),
        Json(serde_json::json!({"v": 2, "extra": true})),
    )
    .await
    .into_response();

    let resp = facts::get_session_state(State(state), HeaderMap::new(), Path("sess-ow".to_string()))
        .await
        .into_response();
    let body = json_body(resp).await;
    assert_eq!(body["state"]["v"], 2);
    assert_eq!(body["state"]["extra"], true);
}

#[tokio::test]
async fn fact_and_session_endpoints_accept_admin_read_fallback_in_dev_scopes_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let admin_headers = dev_scope_headers("admin:read");

    let create_resp = facts::put_fact(
        State(state.clone()),
        admin_headers.clone(),
        Json(corecrux_memory::fact_store::StoreFact {
            entity: "proj-admin".to_string(),
            key: "status".to_string(),
            value: "green".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        }),
    )
    .await
    .into_response();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let created_fact = json_body(create_resp).await;
    let fact_id = created_fact["fact_id"].as_str().unwrap().to_string();

    let bulk_resp = facts::put_facts_bulk(
        State(state.clone()),
        admin_headers.clone(),
        Json(vec![
            corecrux_memory::fact_store::StoreFact {
                entity: "proj-admin".to_string(),
                key: "owner".to_string(),
                value: "ops".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            },
            corecrux_memory::fact_store::StoreFact {
                entity: "proj-admin:beta".to_string(),
                key: "status".to_string(),
                value: "yellow".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            },
        ]),
    )
    .await
    .into_response();
    assert_eq!(bulk_resp.status(), StatusCode::CREATED);
    let bulk_body = json_body(bulk_resp).await;
    assert_eq!(bulk_body["facts"].as_array().unwrap().len(), 2);

    let get_resp = facts::get_fact(State(state.clone()), admin_headers.clone(), Path(fact_id.clone()))
        .await
        .into_response();
    assert_eq!(get_resp.status(), StatusCode::OK);

    let entity_resp = facts::get_facts_by_entity(
        State(state.clone()),
        admin_headers.clone(),
        Path("proj-admin".to_string()),
    )
    .await
    .into_response();
    assert_eq!(entity_resp.status(), StatusCode::OK);
    let entity_body = json_body(entity_resp).await;
    assert_eq!(entity_body["facts"].as_array().unwrap().len(), 2);

    let delete_resp = facts::delete_fact(State(state.clone()), admin_headers.clone(), Path(fact_id.clone()))
        .await
        .into_response();
    assert_eq!(delete_resp.status(), StatusCode::OK);

    let export_params = ExportFactsParams {
        since: Some((chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339()),
        cursor: None,
        limit: Some(20000),
    };
    let export_resp = facts::export_facts(State(state.clone()), admin_headers.clone(), Query(export_params))
        .await
        .into_response();
    assert_eq!(export_resp.status(), StatusCode::OK);
    let export_body = json_body(export_resp).await;
    assert!(export_body["facts"].as_array().unwrap().is_empty());

    let session_resp = facts::put_session_state(
        State(state.clone()),
        admin_headers.clone(),
        Path("sess-admin-write".to_string()),
        Json(serde_json::json!({"step": 3, "owner": "admin"})),
    )
    .await
    .into_response();
    assert_eq!(session_resp.status(), StatusCode::OK);
    let session_body = json_body(session_resp).await;
    assert_eq!(session_body["session_id"], "sess-admin-write");
}

#[tokio::test]
async fn query_facts_supports_entity_prefix_top_k_and_token_budget() {
    let state = test_app_state(16);
    for (entity, key, value) in [
        ("proj-a", "status", "green deploy"),
        ("proj-a:beta", "owner", "ops team"),
        ("proj-b", "status", "red deploy"),
    ] {
        let _ = facts::put_fact(
            State(state.clone()),
            HeaderMap::new(),
            Json(corecrux_memory::fact_store::StoreFact {
                entity: entity.to_string(),
                key: key.to_string(),
                value: value.to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            }),
        )
        .await
        .into_response();
    }

    let params = QueryFactsParams {
        query: None,
        entity: None,
        entity_prefix: Some("proj-a".to_string()),
        top_k: Some(99),
        token_budget: Some(1),
    };

    let resp = facts::query_facts(State(state), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let facts = body["facts"].as_array().unwrap();
    assert_eq!(facts.len(), 1);
    assert!(facts[0]["entity"].as_str().unwrap().starts_with("proj-a"));
    assert!(body["total_tokens"].as_u64().unwrap() > 0);
}

// ── Text Search (POST /v1/query/text-search) ────────────────────
//
// NOTE: text-search tests rely on the CORECRUXD_QUERY_TEXT_SEARCH env var
// which is process-global. These tests set it to "1" and must be run with
// --test-threads=1 if the feature-gate-off test is included. The enable
// helper sets it once at the start of each test to minimise races.

#[allow(deprecated)]
fn enable_text_search() {
    std::env::set_var("CORECRUXD_QUERY_TEXT_SEARCH", "1");
}

fn build_test_ccxi(docs: &[&str]) -> Vec<u8> {
    let tenant_hash = xxhash_rust::xxh64::xxh64(b"tenant-a", 0);
    let mut builder = corecrux_index::CcxiBuilder::new(0, 1, 100);
    for (i, text) in docs.iter().enumerate() {
        builder.add_document(i as u32, text, (i as u32) * 100, tenant_hash);
    }
    builder.build()
}

async fn load_test_index(state: &AppState, ccxi_bytes: &[u8]) {
    let mut index = state.retrieval_index.write().await;
    index.load_ccxi_bytes(ccxi_bytes).expect("load test ccxi");
}

#[tokio::test]
async fn text_search_empty_index_returns_empty_results() {
    enable_text_search();

    let state = test_app_state(16);
    let body = query::TextSearchBody {
        tenant_id: "tenant-a".to_string(),
        query: "hello world".to_string(),
        limit: 10,
        token_budget: None,
        min_score: None,
        mode: None,
        include_receipt: None,
    };

    let resp = query::post_query_text_search(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let results = body["results"].as_array().expect("results array");
    assert!(results.is_empty());
    assert_eq!(body["coverage"]["score"], 0.0);
    assert_eq!(body["meta"]["segments_searched"], 0);
    assert_eq!(body["meta"]["total_docs"], 0);
}

#[tokio::test]
async fn text_search_empty_query_returns_400() {
    enable_text_search();

    let state = test_app_state(16);
    let body = query::TextSearchBody {
        tenant_id: "tenant-a".to_string(),
        query: "   ".to_string(),
        limit: 10,
        token_budget: None,
        min_score: None,
        mode: None,
        include_receipt: None,
    };

    let resp = query::post_query_text_search(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn is_query_feature_disabled_by_default() {
    // Test the feature gate logic directly without env var mutation (avoids races)
    assert!(!is_query_feature_enabled("CORECRUXD_QUERY_TEXT_SEARCH_TEST_FAKE_ENV"));
}

#[tokio::test]
async fn text_search_with_index_returns_hits() {
    enable_text_search();

    let state = test_app_state(16);
    let ccxi_bytes = build_test_ccxi(&[
        "the rust programming language is fast",
        "python is great for data science",
        "rust and python are both popular languages",
    ]);
    load_test_index(&state, &ccxi_bytes).await;

    let body = query::TextSearchBody {
        tenant_id: "tenant-a".to_string(),
        query: "rust programming".to_string(),
        limit: 10,
        token_budget: None,
        min_score: None,
        mode: None,
        include_receipt: None,
    };

    let resp = query::post_query_text_search(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let results = body["results"].as_array().expect("results array");
    assert!(
        !results.is_empty(),
        "should have at least one hit for 'rust programming'"
    );
    assert!(body["meta"]["segments_searched"].as_u64().unwrap() > 0);
    assert!(body["meta"]["total_docs"].as_u64().unwrap() == 3);
    assert!(body["coverage"]["score"].as_f64().is_some());
}

#[tokio::test]
async fn text_search_scan_mode() {
    enable_text_search();

    let state = test_app_state(16);
    let ccxi_bytes = build_test_ccxi(&["hello world test document"]);
    load_test_index(&state, &ccxi_bytes).await;

    let body = query::TextSearchBody {
        tenant_id: "tenant-a".to_string(),
        query: "hello".to_string(),
        limit: 10,
        token_budget: None,
        min_score: None,
        mode: Some("scan".to_string()),
        include_receipt: None,
    };

    let resp = query::post_query_text_search(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["scan_mode"], true);
}

#[tokio::test]
async fn text_search_with_token_budget() {
    enable_text_search();

    let state = test_app_state(16);
    let ccxi_bytes = build_test_ccxi(&[
        "shared term document one with extra words here",
        "shared term document two also has extra words",
        "shared term document three many more words added",
    ]);
    load_test_index(&state, &ccxi_bytes).await;

    let body = query::TextSearchBody {
        tenant_id: "tenant-a".to_string(),
        query: "shared term".to_string(),
        limit: 10,
        token_budget: Some(10),
        min_score: None,
        mode: None,
        include_receipt: None,
    };

    let resp = query::post_query_text_search(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["tokens_used"].as_u64().is_some());
    assert!(body["tokens_available"].as_u64().unwrap() == 10);
}

// ── Text Search Expand (POST /v1/query/text-search/expand) ──────

#[tokio::test]
async fn text_search_expand_returns_chunks() {
    enable_text_search();

    let state = test_app_state(16);
    let ccxi_bytes = build_test_ccxi(&["hello world test", "another document here"]);
    load_test_index(&state, &ccxi_bytes).await;

    let body = query::TextSearchExpandBody {
        tenant_id: "tenant-a".to_string(),
        result_ids: vec![
            query::ExpandResultId {
                segment_index: 0,
                doc_id: 0,
            },
            query::ExpandResultId {
                segment_index: 0,
                doc_id: 1,
            },
        ],
    };

    let resp = query::post_query_text_search_expand(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let chunks = body["chunks"].as_array().expect("chunks array");
    assert_eq!(chunks.len(), 2);
    assert!(body["tokens_loaded"].as_u64().unwrap() > 0);
    assert_eq!(chunks[0]["segment_index"], 0);
    assert_eq!(chunks[0]["doc_id"], 0);
    assert_eq!(chunks[1]["doc_id"], 1);
}

#[tokio::test]
async fn text_search_expand_skips_invalid_ids() {
    enable_text_search();

    let state = test_app_state(16);
    let ccxi_bytes = build_test_ccxi(&["only doc"]);
    load_test_index(&state, &ccxi_bytes).await;

    let body = query::TextSearchExpandBody {
        tenant_id: "tenant-a".to_string(),
        result_ids: vec![
            query::ExpandResultId {
                segment_index: 0,
                doc_id: 0,
            },
            query::ExpandResultId {
                segment_index: 99,
                doc_id: 0,
            },
            query::ExpandResultId {
                segment_index: 0,
                doc_id: 999,
            },
        ],
    };

    let resp = query::post_query_text_search_expand(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let chunks = body["chunks"].as_array().expect("chunks array");
    assert_eq!(chunks.len(), 1, "only valid doc should be returned");
}

#[tokio::test]
async fn text_search_expand_empty_index() {
    enable_text_search();

    let state = test_app_state(16);

    let body = query::TextSearchExpandBody {
        tenant_id: "tenant-a".to_string(),
        result_ids: vec![query::ExpandResultId {
            segment_index: 0,
            doc_id: 0,
        }],
    };

    let resp = query::post_query_text_search_expand(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let chunks = body["chunks"].as_array().expect("chunks array");
    assert!(chunks.is_empty());
    assert_eq!(body["tokens_loaded"], 0);
}

#[test]
fn is_query_feature_enabled_when_set_true() {
    #[allow(deprecated)]
    std::env::set_var("__TEST_GATE_ENABLED__", "1");
    assert!(is_query_feature_enabled("__TEST_GATE_ENABLED__"));
    #[allow(deprecated)]
    std::env::remove_var("__TEST_GATE_ENABLED__");
}

// ── Auth gating for Phase 1 / 1.5 endpoints (DevScopes) ────────

#[tokio::test]
async fn fact_endpoints_require_auth_in_dev_scopes_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    // PUT /v1/facts — no scopes → 401
    let body = corecrux_memory::fact_store::StoreFact {
        entity: "e".to_string(),
        key: "k".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
    };
    let resp = facts::put_fact(State(state.clone()), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // PUT /v1/facts — with query:read → 201
    let body2 = corecrux_memory::fact_store::StoreFact {
        entity: "e".to_string(),
        key: "k".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
    };
    let resp2 = put_fact(State(state.clone()), dev_scope_headers("query:read"), Json(body2))
        .await
        .into_response();
    assert_eq!(resp2.status(), StatusCode::CREATED);

    // GET /v1/sessions/{id}/state — no scopes → 401
    let resp3 = facts::get_session_state(State(state), HeaderMap::new(), Path("sess".to_string()))
        .await
        .into_response();
    assert_eq!(resp3.status(), StatusCode::UNAUTHORIZED);
}

// ── healthz ────────────────────────────────────────────────────────

#[tokio::test]
async fn healthz_returns_ok_with_build_and_routing() {
    let state = test_app_state(16);
    let resp = health::healthz(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["build"]["version"], "test");
    assert_eq!(body["build"]["commit"], "test");
    assert!(body["routing"]["shardMapVersion"].as_u64().is_some());
    assert!(body["routing"]["shardCount"].as_u64().unwrap() > 0);
    assert_eq!(body["routing"]["nodeId"], "node-a");
    // Valves should be present
    assert!(body["valves"]["pauseIngest"].is_object());
    assert!(body["valves"]["pauseCompaction"].is_object());
    assert!(body["valves"]["throttle"].is_object());
    assert!(body["valves"]["readOnly"].is_object());
    assert!(body["valves"]["emergencyBrake"].is_object());
}

#[tokio::test]
async fn healthz_valves_reflect_control_state() {
    let state = test_app_state(16);
    {
        let mut c = state.control.write().await;
        c.valves.pause_ingest.set(true, "test", "unit-test", 123);
    }
    let resp = health::healthz(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["valves"]["pauseIngest"]["enabled"], true);
    assert_eq!(body["valves"]["pauseIngest"]["actor"], "test");
    assert_eq!(body["valves"]["pauseIngest"]["reason"], "unit-test");
}

// ── readyz (happy path) ──────────────────────────────────────────

#[tokio::test]
async fn readyz_returns_ok_when_all_checks_pass() {
    let state = test_app_state(16);
    mark_ready_except_control(&state).await;
    let resp = health::readyz(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["ok"], true);
}

#[tokio::test]
async fn readyz_fails_when_lock_not_held() {
    let mut state = test_app_state(16);
    state.lock_held = false;
    mark_ready_except_control(&state).await;
    let resp = health::readyz(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = json_body(resp).await;
    assert_eq!(body["ok"], false);
    let checks = body["checks"].as_array().expect("checks array");
    assert!(checks.iter().any(|c| c["name"] == "data_dir_lock_held"));
}

#[tokio::test]
async fn readyz_fails_when_corruption_detected() {
    let state = test_app_state(16);
    mark_ready_except_control(&state).await;
    {
        *state.corruption_detected.write().await = true;
    }
    let resp = health::readyz(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = json_body(resp).await;
    assert_eq!(body["ok"], false);
    let checks = body["checks"].as_array().expect("checks array");
    assert!(checks.iter().any(|c| c["name"] == "corruption_state_clear"));
}

#[tokio::test]
async fn readyz_fails_when_capacity_low() {
    let state = test_app_state(16);
    mark_ready_except_control(&state).await;
    {
        let mut cap = state.capacity.write().await;
        cap.free_ratio = 0.05; // Below emergency threshold of 0.10
        cap.free_bytes = 5;
        cap.total_bytes = 100;
    }
    let resp = health::readyz(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = json_body(resp).await;
    assert_eq!(body["ok"], false);
    let checks = body["checks"].as_array().expect("checks array");
    assert!(checks.iter().any(|c| c["name"] == "data_dir_capacity"));
}

#[tokio::test]
async fn readyz_ok_with_default_readiness() {
    let state = test_app_state(16);
    // Default Readiness is sufficient for CPU-only (no GPU fields).
    let resp = health::readyz(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── metrics ──────────────────────────────────────────────────────

#[tokio::test]
async fn metrics_returns_prometheus_text() {
    let state = test_app_state(16);
    let resp = health::metrics(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(ct.contains("text/plain"), "expected text/plain, got: {ct}");
    // Body should be non-empty prometheus text
    let body_bytes = to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
    assert!(!body_bytes.is_empty());
}

// ── get_gpus (no dataplane) ─────────────────────────────────────

#[tokio::test]
async fn get_gpus_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let resp = routing::get_gpus(State(state), HeaderMap::new()).await.into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    let body = json_body(resp).await;
    assert!(body["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("proprietary edition"));
}

// ── get_shards ──────────────────────────────────────────────────

#[tokio::test]
async fn get_shards_returns_shard_info() {
    let state = test_app_state(16);
    let resp = routing::get_shards(State(state), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["nodeId"], "node-a");
    assert!(body["shardMapVersion"].as_u64().unwrap() > 0);
    assert_eq!(body["defaultGpuId"], 0);
    let shards = body["shards"].as_array().expect("shards array");
    assert_eq!(shards.len(), 1);
    assert_eq!(shards[0]["shardId"], "shard-0001");
    assert_eq!(shards[0]["epoch"], 1);
    assert_eq!(shards[0]["workerUp"], false);
    assert_eq!(shards[0]["shardHosted"], false);
}

#[tokio::test]
async fn get_shards_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = routing::get_shards(State(state.clone()), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp2 = routing::get_shards(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(resp2.status(), StatusCode::OK);
}

// ── route_v1 ────────────────────────────────────────────────────

#[tokio::test]
async fn route_v1_returns_routing_decision() {
    let state = test_app_state(16);
    let q = routing::RouteQuery {
        tenant_id: "tenant-a".to_string(),
        stream_type: "answers".to_string(),
        stream_id: "stream-1".to_string(),
    };
    let resp = routing::route_v1(State(state), axum::extract::Query(q), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["streamHash"].as_str().is_some());
    assert_eq!(body["shardId"], "shard-0001");
    assert_eq!(body["epoch"], 1);
    assert!(body["shardMapVersion"].as_u64().unwrap() > 0);
    assert!(body["leaderGrpcAddr"].as_str().is_some());
    assert_eq!(body["leaderNodeId"], "node-a");
    assert_eq!(body["ownerGpuId"], 0);
    assert_eq!(body["workerUp"], false);
    assert_eq!(body["shardHosted"], false);
}

#[tokio::test]
async fn route_v1_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let q = routing::RouteQuery {
        tenant_id: "tenant-a".to_string(),
        stream_type: "answers".to_string(),
        stream_id: "stream-1".to_string(),
    };
    let resp = routing::route_v1(State(state), axum::extract::Query(q), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── get_receipt_body_v1 (no dataplane) ──────────────────────────

#[tokio::test]
async fn get_receipt_body_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let resp = receipts::get_receipt_body_v1(
        State(state),
        Path("crx_abc".to_string()),
        Query(TenantQuery {
            tenant_id: "tenant-a".to_string(),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn get_receipt_body_uses_http_dataplane_fake() {
    let fake = Arc::new(FakeHttpDataplane {
        enabled: true,
        read_stream_events: vec![
            fake_stored_event(1, EVT_RECEIPT_BODY_V1, "application/json", br#"{"ok":false}"#),
            fake_stored_event(2, EVT_RECEIPT_BODY_V1, "application/json", br#"{"ok":true}"#),
        ],
        ..Default::default()
    });
    let mut state = test_app_state(16);
    state.http_dataplane = fake;

    let resp = receipts::get_receipt_body_v1(
        State(state),
        Path("crx_live".to_string()),
        Query(TenantQuery {
            tenant_id: "tenant-a".to_string(),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["receipt_id"], "crx_live");
    assert_eq!(body["contentType"], "application/json");
    assert_eq!(body["seq"], 2);
}

// ── get_receipt_signature_v1 (no dataplane) ─────────────────────

#[tokio::test]
async fn get_receipt_signature_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let resp = receipts::get_receipt_signature_v1(
        State(state),
        Path("crx_abc".to_string()),
        Query(TenantQuery {
            tenant_id: "tenant-a".to_string(),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── get_receipt_verification_v1 (no dataplane) ──────────────────

#[tokio::test]
async fn get_receipt_verification_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let resp = receipts::get_receipt_verification_v1(
        State(state),
        Path("crx_abc".to_string()),
        Query(TenantQuery {
            tenant_id: "tenant-a".to_string(),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn get_receipt_verification_uses_http_dataplane_fake() {
    let fake = Arc::new(FakeHttpDataplane {
        enabled: true,
        verification_report: Some(
            serde_json::from_value(serde_json::json!({
                "schema": "cuecrux.receipt.verify.v1",
                "receipt_id": "crx_verified",
                "tenant_id": "tenant-a",
                "payload_hash": "abcd",
                "signature": {
                    "alg": "ed25519",
                    "key_id": "kid-1"
                },
                "integrity": {
                    "payload_hash_matches": true,
                    "canonical_bytes_parse_ok": true
                },
                "trace_checks": {
                    "retrieval_trace_present": false,
                    "lanes_used_present": false,
                    "candidate_generation_present": false,
                    "filters_present": false,
                    "normalisation_present": false,
                    "fusion_present": false,
                    "priors_applied_present": false,
                    "anchors_present": false,
                    "anchors_ids_present": false,
                    "anchors_derivation_method_present": false,
                    "rerank_present": false,
                    "candidates_present": false,
                    "candidate_digest_present": false
                },
                "signature_valid": true,
                "pubkey_fingerprint": "fp",
                "error_code": "OK",
                "verified_at": "2026-04-08T12:00:00Z",
                "verifier_build": "test"
            }))
            .expect("verification report"),
        ),
        ..Default::default()
    });
    let mut state = test_app_state(16);
    state.http_dataplane = fake;

    let resp = receipts::get_receipt_verification_v1(
        State(state),
        Path("crx_verified".to_string()),
        Query(TenantQuery {
            tenant_id: "tenant-a".to_string(),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["receipt_id"], "crx_verified");
    assert_eq!(body["signature_valid"], true);
}

// ── get_receipt_export_v1 (no dataplane) ────────────────────────

#[tokio::test]
async fn get_receipt_export_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let resp = receipts::get_receipt_export_v1(
        State(state),
        Path("crx_abc".to_string()),
        Query(receipts::ExportQueryV1 {
            tenant_id: "tenant-a".to_string(),
            include: None,
            redaction: None,
            format: None,
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── get_answer_export_v1 (not found path) ───────────────────────

#[tokio::test]
async fn get_answer_export_not_found_without_subject_link() {
    let state = test_app_state(16);
    let resp = receipts::get_answer_export_v1(
        State(state),
        Path("ans-123".to_string()),
        Query(SubjectExportQueryV1 {
            tenant_id: "tenant-a".to_string(),
            mode: None,
            include: None,
            redaction: None,
            format: None,
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_answer_export_invalid_mode() {
    let state = test_app_state(16);
    let resp = receipts::get_answer_export_v1(
        State(state),
        Path("ans-123".to_string()),
        Query(SubjectExportQueryV1 {
            tenant_id: "tenant-a".to_string(),
            mode: Some("bogus".to_string()),
            include: None,
            redaction: None,
            format: None,
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert!(body["detail"].as_str().unwrap_or_default().contains("invalid mode"));
}

// ── get_action_export_v1 (not found path) ───────────────────────

#[tokio::test]
async fn get_action_export_not_found_without_subject_link() {
    let state = test_app_state(16);
    let resp = receipts::get_action_export_v1(
        State(state),
        Path("act-123".to_string()),
        Query(SubjectExportQueryV1 {
            tenant_id: "tenant-a".to_string(),
            mode: None,
            include: None,
            redaction: None,
            format: None,
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── get_stream_export_v1 (no dataplane) ─────────────────────────

#[tokio::test]
async fn get_stream_export_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let resp = receipts::get_stream_export_v1(
        State(state),
        Path(("receipt".to_string(), "crx_abc".to_string())),
        Query(StreamExportQueryV1 {
            tenant_id: "tenant-a".to_string(),
            from_seq: None,
            to_seq: None,
            max_events: None,
            include: None,
            redaction: None,
            format: None,
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── post_shard_map (not implemented) ────────────────────────────

#[tokio::test]
async fn post_shard_map_returns_501() {
    let state = test_app_state(16);
    let resp = admin::post_shard_map(State(state), HeaderMap::new(), axum::body::Bytes::from_static(b"{}"))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    let body = json_body(resp).await;
    assert!(body["detail"].as_str().unwrap_or_default().contains("CLI-only"));
}

// ── get_shard_map (happy path) ──────────────────────────────────

#[tokio::test]
async fn get_shard_map_returns_map_body() {
    let state = test_app_state(16);
    let resp = admin::get_shard_map(State(state), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["currentVersion"].as_u64().unwrap() > 0);
    assert!(body["blake3"].as_str().is_some());
    let sm = &body["shardMap"];
    assert_eq!(sm["clusterId"], "test-cluster");
    assert_eq!(sm["shards"].as_array().unwrap().len(), 1);
}

// ── get_control (happy path, valves) ────────────────────────────

#[tokio::test]
async fn get_control_returns_valves() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut c = state.control.write().await;
        c.valves.pause_ingest.set(true, "ops", "maintenance", 1000);
    }
    let resp = admin::get_control(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["valves"]["pauseIngest"]["enabled"].as_bool().unwrap());
}

#[tokio::test]
async fn get_control_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = admin::get_control(State(state), HeaderMap::new()).await.into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── get_ops_log (no dataplane) ──────────────────────────────────

#[serial_test::serial]
#[tokio::test]
async fn get_ops_log_returns_precondition_failed_without_dataplane() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = admin::get_ops_log(
        State(state),
        Query(admin::OpsLogQuery {
            node_id: None,
            since: None,
            until: None,
            from_seq: None,
            max_events: None,
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

// ── post_valves (validation) ────────────────────────────────────

#[tokio::test]
async fn post_valves_rejects_empty_actor_and_reason() {
    let state = test_app_state(16);
    let req = admin::SetValvesReq {
        actor: "".to_string(),
        reason: "".to_string(),
        pause_ingest: Some(true),
        pause_compaction: None,
        throttle: None,
        read_only: None,
        emergency_brake: None,
    };
    let resp = admin::post_valves(State(state), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert!(body["detail"].as_str().unwrap_or_default().contains("actor and reason"));
}

// ── post_stream_meta (validation + no dataplane) ────────────────

#[tokio::test]
async fn post_stream_meta_rejects_empty_actor() {
    let state = test_app_state(16);
    let req = admin::StreamMetaReq {
        tenant_id: "tenant-a".to_string(),
        stream_type: "answers".to_string(),
        stream_id: "stream-1".to_string(),
        min_live_seq: Some(5),
        tombstone_seq: None,
        actor: "  ".to_string(),
        reason: "  ".to_string(),
    };
    let resp = admin::post_stream_meta(State(state), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_stream_meta_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let req = admin::StreamMetaReq {
        tenant_id: "tenant-a".to_string(),
        stream_type: "answers".to_string(),
        stream_id: "stream-1".to_string(),
        min_live_seq: Some(5),
        tombstone_seq: None,
        actor: "ops".to_string(),
        reason: "cleanup".to_string(),
    };
    let resp = admin::post_stream_meta(State(state), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── post_replication_segment (validation) ───────────────────────

#[tokio::test]
async fn post_replication_segment_rejects_empty_shard_id() {
    let state = test_app_state(16);
    let req = admin::ReplicationSegmentReq {
        shard_id: "".to_string(),
        epoch: 1,
        leader_node_id: None,
        segment_base64: "AAAA".to_string(),
        segment_hash: None,
    };
    let resp = admin::post_replication_segment(State(state), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert!(body["detail"].as_str().unwrap_or_default().contains("shardId"));
}

#[tokio::test]
async fn post_replication_segment_rejects_empty_segment() {
    let state = test_app_state(16);
    let req = admin::ReplicationSegmentReq {
        shard_id: "shard-0001".to_string(),
        epoch: 1,
        leader_node_id: None,
        segment_base64: "".to_string(),
        segment_hash: None,
    };
    let resp = admin::post_replication_segment(State(state), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert!(body["detail"].as_str().unwrap_or_default().contains("segmentBase64"));
}

// ── post_admin_append (no dataplane) ────────────────────────────

#[tokio::test]
async fn post_admin_append_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let body = append::AppendBody {
        tenant_id: "tenant-a".to_string(),
        stream_type: "test".to_string(),
        stream_id: "stream-1".to_string(),
        expected_next_seq: 0,
        events: vec![append::AppendEventBody {
            event_id: "ev1".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            event_type: "test.v1".to_string(),
            content_type: "application/json".to_string(),
            payload: "{}".to_string(),
        }],
    };
    let resp = append::post_admin_append(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn post_admin_append_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let body = append::AppendBody {
        tenant_id: "tenant-a".to_string(),
        stream_type: "test".to_string(),
        stream_id: "stream-1".to_string(),
        expected_next_seq: 0,
        events: vec![append::AppendEventBody {
            event_id: "ev1".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            event_type: "test.v1".to_string(),
            content_type: "application/json".to_string(),
            payload: "{}".to_string(),
        }],
    };
    let resp = append::post_admin_append(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn post_admin_append_uses_http_dataplane_fake() {
    let fake = Arc::new(FakeHttpDataplane {
        enabled: true,
        ..Default::default()
    });
    let mut state = test_app_state(16);
    state.http_dataplane = fake.clone();

    let body = append::AppendBody {
        tenant_id: "tenant-a".to_string(),
        stream_type: "test".to_string(),
        stream_id: "stream-1".to_string(),
        expected_next_seq: 4,
        events: vec![append::AppendEventBody {
            event_id: "ev1".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            event_type: "test.v1".to_string(),
            content_type: "application/json".to_string(),
            payload: "{\"ok\":true}".to_string(),
        }],
    };
    let resp = append::post_admin_append(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert_eq!(body["appended"], 1);
    let calls = fake.append_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].expected_next_seq, 4);
    assert_eq!(calls[0].event_ids, vec!["ev1".to_string()]);
}

// ── post_query_graph_expand (feature gate + no dataplane) ───────

#[serial_test::serial]
#[tokio::test]
async fn post_query_graph_expand_returns_not_found_when_disabled() {
    // Feature gate is off by default
    let state = test_app_state(16);
    let body = query::GraphExpandBody {
        tenant_id: "tenant-a".to_string(),
        seed_artifact_ids: vec![1, 2],
        edge_types: vec![],
        max_hops: 2,
        budget: 50,
        min_confidence: 0.0,
        include_state: false,
    };
    let resp = query::post_query_graph_expand(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[allow(deprecated)]
#[serial_test::serial]
#[tokio::test]
async fn post_query_graph_expand_uses_http_dataplane_fake() {
    std::env::set_var("CORECRUXD_QUERY_GRAPH_EXPAND", "1");
    let fake = Arc::new(FakeHttpDataplane {
        enabled: true,
        graph_expand_response: Some(corecrux_projections::query::graph_expand::GraphExpandResponse {
            artifacts: vec![corecrux_projections::query::graph_expand::GraphExpandArtifact {
                artifact_id: 42,
                score: 0.9,
                hop_distance: 1,
                edge_types_used: vec![corecrux_projections::RelationTypeV1::Supports],
                state: None,
            }],
            stats: corecrux_projections::query::graph_expand::GraphExpandStats {
                nodes_visited: 3,
                hops_used: 1,
                budget_remaining: 49,
                edges_traversed: 2,
            },
        }),
        ..Default::default()
    });
    let mut state = test_app_state(16);
    state.http_dataplane = fake;

    let body = query::GraphExpandBody {
        tenant_id: "tenant-a".to_string(),
        seed_artifact_ids: vec![1],
        edge_types: vec![],
        max_hops: 2,
        budget: 50,
        min_confidence: 0.0,
        include_state: false,
    };
    let resp = query::post_query_graph_expand(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    std::env::remove_var("CORECRUXD_QUERY_GRAPH_EXPAND");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["artifacts"][0]["artifact_id"], 42);
    assert_eq!(body["traversal_stats"]["nodes_visited"], 3);
}

// ── post_query_time_range (feature gate + validation) ───────────

#[tokio::test]
async fn post_query_time_range_returns_not_found_when_disabled() {
    let state = test_app_state(16);
    let body = query::TimeRangeBody {
        tenant_id: "tenant-a".to_string(),
        start_micros: 1000,
        end_micros: 2000,
        artifact_ids: vec![],
        include_relations: false,
        limit: 10,
    };
    let resp = query::post_query_time_range(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── get_proj_meta (no dataplane) ────────────────────────────────

#[tokio::test]
async fn get_proj_meta_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let resp = get_proj_meta(
        State(state),
        Query(ProjMetaQuery {
            shard_id: "shard-0001".to_string(),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn get_proj_meta_uses_http_dataplane_fake() {
    let mut meta = corecrux_projections::ProjectionsMetaV1::empty_now();
    meta.commit_id = 7;
    let fake = Arc::new(FakeHttpDataplane {
        enabled: true,
        projection_meta: Some(meta),
        ..Default::default()
    });
    let mut state = test_app_state(16);
    state.http_dataplane = fake;

    let resp = get_proj_meta(
        State(state),
        Query(ProjMetaQuery {
            shard_id: "shard-0001".to_string(),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["commitId"], 7);
}

// ── post_projection_rebuild (no dataplane) ──────────────────────

#[tokio::test]
async fn post_projection_rebuild_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let resp = post_projection_rebuild(State(state), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── get_proj_artifact_state (no dataplane) ──────────────────────

#[tokio::test]
async fn get_proj_artifact_state_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let resp = get_proj_artifact_state(
        State(state),
        Path(1u32),
        Query(TenantQuery {
            tenant_id: "tenant-a".to_string(),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── get_proj_artifact_relations (no dataplane) ──────────────────

#[tokio::test]
async fn get_proj_artifact_relations_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let resp = get_proj_artifact_relations(
        State(state),
        Path(1u32),
        Query(RelationsQuery {
            tenant_id: "tenant-a".to_string(),
            direction: None,
            relation_type: None,
            limit: None,
            offset: None,
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── get_proj_artifact_dependents (no dataplane) ─────────────────

#[tokio::test]
async fn get_proj_artifact_dependents_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let resp = get_proj_artifact_dependents(
        State(state),
        Path(1u32),
        Query(DependentsQuery {
            tenant_id: "tenant-a".to_string(),
            dependent_type: None,
            limit: None,
            offset: None,
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── get_proj_artifact_pressure_events (no dataplane) ────────────

#[tokio::test]
async fn get_proj_artifact_pressure_events_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let resp = get_proj_artifact_pressure_events(
        State(state),
        Path(1u32),
        Query(PressureQuery {
            tenant_id: "tenant-a".to_string(),
            open_only: None,
            limit: None,
            offset: None,
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── Entity projection endpoints (no dataplane) ──────────────────

#[tokio::test]
async fn get_entity_count_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let mut params = std::collections::HashMap::new();
    params.insert("tenant_id".to_string(), "tenant-a".to_string());
    params.insert("entity_type".to_string(), "server".to_string());
    let resp = get_entity_count(State(state), axum::extract::Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn get_entity_timeline_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let mut params = std::collections::HashMap::new();
    params.insert("tenant_id".to_string(), "tenant-a".to_string());
    let resp = get_entity_timeline(State(state), axum::extract::Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn get_entity_current_state_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let mut params = std::collections::HashMap::new();
    params.insert("tenant_id".to_string(), "tenant-a".to_string());
    params.insert("entity_name".to_string(), "server-1".to_string());
    let resp = get_entity_current_state(State(state), axum::extract::Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── get_replication_status ──────────────────────────────────────

#[tokio::test]
async fn get_replication_status_returns_ok_without_dataplane() {
    let state = test_app_state(16);
    let resp = get_replication_status(State(state), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["nodeId"], "node-a");
    assert_eq!(body["commitLevel"], "LocalCommit");
    assert!(body["shardMapVersion"].as_u64().unwrap() > 0);
    let shards = body["shards"].as_array().expect("shards array");
    assert_eq!(shards.len(), 1);
    assert_eq!(shards[0]["shardId"], "shard-0001");
    assert_eq!(shards[0]["role"], "leader");
}

#[tokio::test]
async fn get_replication_status_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = get_replication_status(State(state), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── route_debug (happy path) ────────────────────────────────────

#[tokio::test]
async fn route_debug_returns_routing_info() {
    let state = test_app_state(16);
    let q = routing::RouteQuery {
        tenant_id: "tenant-a".to_string(),
        stream_type: "answers".to_string(),
        stream_id: "stream-1".to_string(),
    };
    let resp = route_debug(State(state), axum::extract::Query(q), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["streamHash"].as_str().is_some());
    assert_eq!(body["shardId"], "shard-0001");
    assert_eq!(body["epoch"], 1);
}

// ── routing_status (happy path) ─────────────────────────────────

#[tokio::test]
async fn routing_status_returns_version_and_shards() {
    let state = test_app_state(16);
    let resp = routing_status(State(state), HeaderMap::new()).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["routingTableVersion"].as_u64().unwrap() > 0);
    assert!(body["lastReloadAt"].as_str().is_some());
    let shards = body["shardsLoaded"].as_array().expect("shardsLoaded array");
    // Without dataplane, lists shards from shard map
    assert_eq!(shards.len(), 1);
    assert_eq!(shards[0], "shard-0001");
}

// ── parse_receipt_export_options_v1 ─────────────────────────────

#[test]
fn parse_export_options_defaults() {
    let opts = parse_receipt_export_options_v1(None, None, None).unwrap();
    assert!(matches!(opts.format, ExportFormatV1::Zip));
    assert!(matches!(opts.redaction, ExportRedactionV1::TenantSafe));
    assert!(opts.include.is_empty());
}

#[test]
fn parse_export_options_invalid_format() {
    let result = parse_receipt_export_options_v1(None, None, Some("badformat"));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("invalid format"));
}

#[test]
fn parse_export_options_invalid_redaction() {
    let result = parse_receipt_export_options_v1(None, Some("badredaction"), None);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("invalid redaction"));
}

#[test]
fn parse_export_options_invalid_include() {
    let result = parse_receipt_export_options_v1(Some("badinclude"), None, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("invalid include"));
}

#[test]
fn parse_export_options_valid_include() {
    let opts = parse_receipt_export_options_v1(Some("body,sig"), None, None).unwrap();
    assert_eq!(opts.include.len(), 2);
}

// ── wants_cbor ──────────────────────────────────────────────────

#[test]
fn wants_cbor_false_by_default() {
    let headers = HeaderMap::new();
    assert!(!wants_cbor(&headers));
}

#[test]
fn wants_cbor_true_with_accept_header() {
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/cbor"));
    assert!(wants_cbor(&headers));
}

#[test]
fn wants_cbor_true_with_mixed_accept() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/json, application/cbor"),
    );
    assert!(wants_cbor(&headers));
}

#[test]
fn wants_cbor_false_for_json_only() {
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    assert!(!wants_cbor(&headers));
}

// ── hex16 / hex32 ───────────────────────────────────────────────

#[test]
fn hex16_formats_correctly() {
    let bytes = [0u8; 16];
    assert_eq!(hex16(&bytes), "00000000000000000000000000000000");
    let bytes2 = [0xFF; 16];
    assert_eq!(hex16(&bytes2), "ffffffffffffffffffffffffffffffff");
}

#[test]
fn hex32_formats_correctly() {
    let bytes = [0u8; 32];
    assert_eq!(hex32(&bytes).len(), 64);
    assert_eq!(hex32(&bytes), "0".repeat(64));
}

// ── problem_for_status ──────────────────────────────────────────

#[test]
fn problem_for_status_sets_correct_fields() {
    let problem = problem_for_status(StatusCode::BAD_REQUEST, "test error");
    let resp = problem.into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn problem_for_status_not_found() {
    let problem = problem_for_status(StatusCode::NOT_FOUND, "not here");
    let resp = problem.into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test]
fn problem_for_status_service_unavailable() {
    let problem = problem_for_status(StatusCode::SERVICE_UNAVAILABLE, "down");
    let resp = problem.into_response();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn problem_for_status_payload_too_large() {
    let problem = problem_for_status(StatusCode::PAYLOAD_TOO_LARGE, "too big");
    let resp = problem.into_response();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

// ── is_known_admin_action ───────────────────────────────────────

#[test]
fn known_admin_actions_match() {
    assert!(is_known_admin_action("verify-store"));
    assert!(is_known_admin_action("scrub-now"));
    assert!(is_known_admin_action("snapshot-verify"));
    assert!(is_known_admin_action("projection-rebuild"));
    assert!(is_known_admin_action("parity-pack"));
    assert!(is_known_admin_action("runtime-knob-update"));
    assert!(is_known_admin_action("force-seal"));
    assert!(!is_known_admin_action("unknown"));
    assert!(!is_known_admin_action(""));
}

// ── read_param helpers ──────────────────────────────────────────

#[test]
fn read_param_str_extracts_value() {
    let v = serde_json::json!({"key": "value", "empty": "", "ws": "  "});
    assert_eq!(read_param_str(Some(&v), "key"), Some("value"));
    assert_eq!(read_param_str(Some(&v), "missing"), None);
    assert_eq!(read_param_str(Some(&v), "empty"), None);
    assert_eq!(read_param_str(Some(&v), "ws"), None);
    assert_eq!(read_param_str(None, "key"), None);
}

#[test]
fn read_param_bool_extracts_value() {
    let v = serde_json::json!({"t": true, "f": false, "s_true": "yes", "s_false": "no", "bad": "maybe"});
    assert_eq!(read_param_bool(Some(&v), "t"), Some(true));
    assert_eq!(read_param_bool(Some(&v), "f"), Some(false));
    assert_eq!(read_param_bool(Some(&v), "s_true"), Some(true));
    assert_eq!(read_param_bool(Some(&v), "s_false"), Some(false));
    assert_eq!(read_param_bool(Some(&v), "bad"), None);
    assert_eq!(read_param_bool(Some(&v), "missing"), None);
    assert_eq!(read_param_bool(None, "t"), None);
}

#[test]
fn read_param_u64_extracts_value() {
    let v = serde_json::json!({"n": 42, "s": "100", "bad": "xyz"});
    assert_eq!(read_param_u64(Some(&v), "n"), Some(42));
    assert_eq!(read_param_u64(Some(&v), "s"), Some(100));
    assert_eq!(read_param_u64(Some(&v), "bad"), None);
    assert_eq!(read_param_u64(Some(&v), "missing"), None);
    assert_eq!(read_param_u64(None, "n"), None);
}

#[test]
fn read_param_u32_extracts_value() {
    let v = serde_json::json!({"n": 42, "big": 5000000000u64});
    assert_eq!(read_param_u32(Some(&v), "n"), Some(42));
    assert_eq!(read_param_u32(Some(&v), "big"), None); // u32 overflow
}

#[test]
fn read_param_f64_extracts_value() {
    let v = serde_json::json!({"n": 3.14, "s": "2.5", "bad": "xyz"});
    assert_eq!(read_param_f64(Some(&v), "n"), Some(3.14));
    assert_eq!(read_param_f64(Some(&v), "s"), Some(2.5));
    assert_eq!(read_param_f64(Some(&v), "bad"), None);
    assert_eq!(read_param_f64(None, "n"), None);
}

// ── parse_tenant_throttle_rules ─────────────────────────────────

#[test]
fn parse_tenant_throttle_rules_valid() {
    let v = serde_json::json!([
        {"tenantId": "t1", "eventsPerSec": 10, "bytesPerSec": 1024, "maxInFlight": 3}
    ]);
    let rules = parse_tenant_throttle_rules(&v).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].tenant_id, "t1");
}

#[test]
fn parse_tenant_throttle_rules_empty_tenant_id() {
    let v = serde_json::json!([
        {"tenantId": "  ", "eventsPerSec": 10}
    ]);
    let result = parse_tenant_throttle_rules(&v);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("non-empty tenantId"));
}

#[test]
fn parse_tenant_throttle_rules_invalid_json() {
    let v = serde_json::json!("not an array");
    let result = parse_tenant_throttle_rules(&v);
    assert!(result.is_err());
}

// ── parse_knowledge_authority_mode / rollout_stage ──────────────

#[test]
fn parse_knowledge_authority_modes() {
    assert!(parse_knowledge_authority_mode("knowledge_shadow").is_some());
    assert!(parse_knowledge_authority_mode("shadow").is_some());
    assert!(parse_knowledge_authority_mode("knowledge_dual_write").is_some());
    assert!(parse_knowledge_authority_mode("dual_write").is_some());
    assert!(parse_knowledge_authority_mode("knowledge_shadow_read").is_some());
    assert!(parse_knowledge_authority_mode("knowledge_authoritative").is_some());
    assert!(parse_knowledge_authority_mode("authoritative").is_some());
    assert!(parse_knowledge_authority_mode("invalid").is_none());
    assert!(parse_knowledge_authority_mode("").is_none());
}

#[test]
fn parse_knowledge_rollout_stages() {
    assert!(parse_knowledge_rollout_stage("internal_shadow").is_some());
    assert!(parse_knowledge_rollout_stage("shadow").is_some());
    assert!(parse_knowledge_rollout_stage("tenant_validation").is_some());
    assert!(parse_knowledge_rollout_stage("internal_authority").is_some());
    assert!(parse_knowledge_rollout_stage("limited_production_authority").is_some());
    assert!(parse_knowledge_rollout_stage("full_production_authority").is_some());
    assert!(parse_knowledge_rollout_stage("invalid").is_none());
    assert!(parse_knowledge_rollout_stage("").is_none());
}

#[test]
fn parse_knowledge_parity_statuses() {
    assert!(parse_knowledge_parity_status("unknown").is_some());
    assert!(parse_knowledge_parity_status("pass").is_some());
    assert!(parse_knowledge_parity_status("warn").is_some());
    assert!(parse_knowledge_parity_status("fail").is_some());
    assert!(parse_knowledge_parity_status("invalid").is_none());
    assert!(parse_knowledge_parity_status("").is_none());
}

// ── admin_action_error ──────────────────────────────────────────

#[test]
fn admin_action_error_wraps_message() {
    let err = admin_action_error("something broke");
    assert!(err.contains("something broke"));
}

// ── post_admin_action (queue full) ──────────────────────────────

#[tokio::test]
async fn post_admin_action_queue_full_returns_503() {
    let state = test_app_state(1); // max 1 pending
                                   // Submit first action
    let req1 = admin::PostAdminActionRequest {
        action_id: Some("act-fill-1".to_string()),
        action_type: "runtime-knob-update".to_string(),
        actor: Some("test".to_string()),
        reason: Some("fill queue".to_string()),
        params: Some(serde_json::json!({"throttleEnabled": false})),
    };
    let resp1 = admin::post_admin_action(State(state.clone()), HeaderMap::new(), Json(req1))
        .await
        .into_response();
    assert_eq!(resp1.status(), StatusCode::ACCEPTED);

    // Wait briefly for background task
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Manually put an action into running state to block queue
    {
        let mut actions = state.admin_actions.write().await;
        actions.insert(
            "act-running-1".to_string(),
            AdminActionRecord {
                action_id: "act-running-1".to_string(),
                action_type: "verify-store".to_string(),
                status: AdminActionStatus::Running,
                submitted_at_unix_ms: 1000,
                started_at_unix_ms: Some(1000),
                finished_at_unix_ms: None,
                actor: None,
                reason: None,
                params: None,
                result: None,
                error: None,
                auth_context: None,
                request_context: None,
            },
        );
    }

    // Submit another (should be rejected)
    let req2 = admin::PostAdminActionRequest {
        action_id: Some("act-overflow".to_string()),
        action_type: "runtime-knob-update".to_string(),
        actor: Some("test".to_string()),
        reason: Some("overflow".to_string()),
        params: Some(serde_json::json!({"throttleEnabled": true})),
    };
    let resp2 = admin::post_admin_action(State(state), HeaderMap::new(), Json(req2))
        .await
        .into_response();
    assert_eq!(resp2.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn post_admin_action_empty_type_returns_400() {
    let state = test_app_state(16);
    let req = admin::PostAdminActionRequest {
        action_id: None,
        action_type: "  ".to_string(),
        actor: None,
        reason: None,
        params: None,
    };
    let resp = admin::post_admin_action(State(state), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_admin_action_too_long_id_returns_400() {
    let state = test_app_state(16);
    let req = admin::PostAdminActionRequest {
        action_id: Some("x".repeat(200)),
        action_type: "runtime-knob-update".to_string(),
        actor: None,
        reason: None,
        params: None,
    };
    let resp = admin::post_admin_action(State(state), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert!(body["detail"].as_str().unwrap_or_default().contains("128 characters"));
}

// ── to_valve_info ───────────────────────────────────────────────

#[test]
fn to_valve_info_maps_fields() {
    let v = control::ValveV1 {
        enabled: true,
        actor: "ops".to_string(),
        reason: "test".to_string(),
        updated_at_unix_ns: 999,
        retry_after_ms: Some(5000),
        events_per_sec: None,
        bytes_per_sec: None,
        max_in_flight: None,
    };
    let info = to_valve_info(&v);
    assert!(info.enabled);
    assert_eq!(info.actor, "ops");
    assert_eq!(info.reason, "test");
    assert_eq!(info.updated_at_unix_ns, 999);
    assert_eq!(info.retry_after_ms, Some(5000));
}

// ── default value functions ─────────────────────────────────────

#[test]
fn default_values_are_correct() {
    assert_eq!(default_max_hops(), 2);
    assert_eq!(default_budget(), 50);
    assert_eq!(default_time_range_limit(), 100);
    assert_eq!(default_text_search_limit(), 10);
    assert_eq!(default_content_type(), "application/json");
}

// ── map_store_error_http ────────────────────────────────────────

#[test]
fn map_store_error_bad_request() {
    let err = AppendError::InvalidArgument("test".to_string());
    let resp = map_store_error_http(err).into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn map_store_error_precondition_failed() {
    let err = AppendError::FailedPrecondition("test".to_string());
    let resp = map_store_error_http(err).into_response();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

#[test]
fn map_store_error_rate_limited() {
    let err = AppendError::ResourceExhausted("test".to_string());
    let resp = map_store_error_http(err).into_response();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn map_store_error_io_backend() {
    let err = AppendError::IoBackend("test".to_string());
    let resp = map_store_error_http(err).into_response();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn map_store_error_internal() {
    let err = AppendError::Internal("test".to_string());
    let resp = map_store_error_http(err).into_response();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn map_store_error_shard_unavailable() {
    let err = AppendError::ShardUnavailable {
        shard_id: "shard-0001".to_string(),
        owner_gpu_id: 0,
        current_shard_map_version: 1,
    };
    let resp = map_store_error_http(err).into_response();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn map_store_error_wrong_shard() {
    let err = AppendError::WrongShard {
        leader_grpc_addr: "http://localhost:50051".to_string(),
        current_shard_map_version: 1,
    };
    let resp = map_store_error_http(err).into_response();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

#[test]
fn map_store_error_version_mismatch() {
    let err = AppendError::ShardMapVersionMismatch {
        client_version: 1,
        current_version: 2,
    };
    let resp = map_store_error_http(err).into_response();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

// ── Readiness default ───────────────────────────────────────────

#[test]
fn readiness_default_has_correct_values() {
    let r = Readiness::default();
    assert!(!r.control_evidence_hosted);
    assert!(r.control_evidence_ok); // default is true
}

// ── CapacityState default ───────────────────────────────────────

#[test]
fn capacity_state_default_has_correct_values() {
    let c = CapacityState::default();
    assert_eq!(c.total_bytes, 0);
    assert_eq!(c.free_bytes, 0);
    assert_eq!(c.free_ratio, 1.0);
    assert!(!c.auto_paused);
    assert!(c.error.is_none());
}

#[tokio::test]
async fn routing_debug_and_status_require_admin_scope_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let query = routing::RouteQuery {
        tenant_id: "tenant-a".to_string(),
        stream_type: "answers".to_string(),
        stream_id: "stream-a".to_string(),
    };

    let debug_unauthorized = route_debug(State(state.clone()), axum::extract::Query(query), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(debug_unauthorized.status(), StatusCode::UNAUTHORIZED);

    let debug_authorized = route_debug(
        State(state.clone()),
        axum::extract::Query(routing::RouteQuery {
            tenant_id: "tenant-a".to_string(),
            stream_type: "answers".to_string(),
            stream_id: "stream-a".to_string(),
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(debug_authorized.status(), StatusCode::OK);

    let status_unauthorized = routing_status(State(state.clone()), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(status_unauthorized.status(), StatusCode::UNAUTHORIZED);

    let status_authorized = routing_status(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(status_authorized.status(), StatusCode::OK);
}

// ── trace_id_from_traceparent ──────────────────────────────────

#[test]
fn trace_id_from_traceparent_valid() {
    let tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let id = trace_id_from_traceparent(Some(tp));
    assert_eq!(id.as_deref(), Some("0af7651916cd43dd8448eb211c80319c"));
}

#[test]
fn trace_id_from_traceparent_none() {
    assert_eq!(trace_id_from_traceparent(None), None);
}

#[test]
fn trace_id_from_traceparent_invalid_length() {
    let tp = "00-tooshort-span-01";
    assert_eq!(trace_id_from_traceparent(Some(tp)), None);
}

#[test]
fn trace_id_from_traceparent_non_hex() {
    let tp = "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-span-01";
    assert_eq!(trace_id_from_traceparent(Some(tp)), None);
}

#[test]
fn trace_id_from_traceparent_missing_parts() {
    assert_eq!(trace_id_from_traceparent(Some("00")), None);
    assert_eq!(trace_id_from_traceparent(Some("")), None);
}

// ── evaluate_replicated_commit_topology ─────────────────────────

#[test]
fn evaluate_replicated_commit_topology_no_followers() {
    let routing = test_routing();
    let status = evaluate_replicated_commit_topology(&routing, "node-a");
    assert_eq!(status.local_leader_shards, 1);
    assert_eq!(status.missing_followers.len(), 1);
    assert_eq!(status.missing_followers[0], "shard-0001");
}

#[test]
fn evaluate_replicated_commit_topology_with_followers() {
    let mut map = ShardMapV1 {
        v: SHARDMAP_V1,
        cluster_id: "test-cluster".to_string(),
        version: 1,
        created_at: "2026-03-04T00:00:00Z".to_string(),
        hash_fn: SHARDMAP_HASH_FN_V1.to_string(),
        key_encoding: SHARDMAP_KEY_ENCODING_V1.to_string(),
        shards: vec![ShardDescriptor {
            shard_id: "shard-0001".to_string(),
            epoch: 1,
            state: ShardState::Active,
            ranges: vec![HashRange {
                start_inclusive: format_u64_hex(0),
                end_exclusive: format_u64_hex(0),
            }],
            leader: test_node("node-a", "http://127.0.0.1:4006", "http://127.0.0.1:50051"),
            followers: Some(vec![test_node("node-b", "http://node-b:4006", "http://node-b:50051")]),
            data_dir: None,
            gpu_id: Some(0),
        }],
        blake3: String::new(),
        prev_blake3: None,
    };
    map.blake3 = compute_shard_map_v1_blake3_hex(&map).expect("hash");
    let routing = RoutingTable::new(LoadedShardMap {
        current_version: map.version,
        shard_map: map,
    })
    .expect("routing table");
    let status = evaluate_replicated_commit_topology(&routing, "node-a");
    assert_eq!(status.local_leader_shards, 1);
    assert!(status.missing_followers.is_empty());
}

#[test]
fn evaluate_replicated_commit_topology_not_leader() {
    let routing = test_routing();
    let status = evaluate_replicated_commit_topology(&routing, "node-b");
    assert_eq!(status.local_leader_shards, 0);
    assert!(status.missing_followers.is_empty());
}

// ── build_trace_summary_json_v1 ────────────────────────────────

#[test]
fn build_trace_summary_valid_json() {
    let bytes = build_trace_summary_json_v1("tenant-a", "crx_abc", b"{}");
    let val: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
    assert_eq!(val["schema"], "cuecrux.receipt.trace_summary.v1");
    assert_eq!(val["tenant_id"], "tenant-a");
    assert_eq!(val["receipt_id"], "crx_abc");
}

#[test]
fn build_trace_summary_unparseable_body() {
    let bytes = build_trace_summary_json_v1("t", "r", b"not-json");
    let val: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
    assert_eq!(val["parse_ok"], false);
}

// ── build_subject_links_json_v1 ────────────────────────────────

#[test]
fn build_subject_links_valid_json() {
    let bytes = build_subject_links_json_v1("tenant-a", "crx_abc", b"{}");
    let val: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
    assert_eq!(val["schema"], "cuecrux.receipt.subject_links.v1");
    assert_eq!(val["tenant_id"], "tenant-a");
    assert_eq!(val["receipt_id"], "crx_abc");
}

#[test]
fn build_subject_links_unparseable_body() {
    let bytes = build_subject_links_json_v1("t", "r", b"not-json");
    let val: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
    assert_eq!(val["parse_ok"], false);
}

// ── build_lineage_json_v1 ──────────────────────────────────────

#[test]
fn build_lineage_valid_json() {
    let bytes = build_lineage_json_v1("tenant-a", "crx_abc", b"{}");
    let val: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
    assert_eq!(val["schema"], "cuecrux.receipt.lineage.v1");
    assert_eq!(val["tenant_id"], "tenant-a");
    assert_eq!(val["receipt_id"], "crx_abc");
}

#[test]
fn build_lineage_unparseable_body() {
    let bytes = build_lineage_json_v1("t", "r", b"not-json");
    let val: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
    assert_eq!(val["parse_ok"], false);
}

// ── build_zip_deterministic_bytes ──────────────────────────────

#[test]
fn build_zip_deterministic_round_trip() {
    let files = vec![
        ("hello.txt".to_string(), b"hello world".to_vec()),
        ("sub/nested.json".to_string(), b"{}".to_vec()),
    ];
    let bytes = build_zip_deterministic_bytes(&files).expect("zip build");
    assert!(!bytes.is_empty());

    // Verify it's a valid zip
    let cursor = std::io::Cursor::new(&bytes);
    let mut archive = zip::ZipArchive::new(cursor).expect("valid zip");
    assert_eq!(archive.len(), 2);
    let names: Vec<String> = (0..archive.len())
        .map(|i| archive.by_index(i).unwrap().name().to_string())
        .collect();
    assert!(names.contains(&"hello.txt".to_string()));
    assert!(names.contains(&"sub/nested.json".to_string()));
}

#[test]
fn build_zip_deterministic_empty() {
    let bytes = build_zip_deterministic_bytes(&[]).expect("empty zip");
    assert!(!bytes.is_empty());
}

#[test]
fn build_zip_deterministic_is_reproducible() {
    let files = vec![("a.txt".to_string(), b"data".to_vec())];
    let b1 = build_zip_deterministic_bytes(&files).expect("zip1");
    let b2 = build_zip_deterministic_bytes(&files).expect("zip2");
    assert_eq!(b1, b2, "deterministic zip must be reproducible");
}

// ── build_tar_zst_deterministic_bytes ──────────────────────────

#[test]
fn build_tar_zst_deterministic_round_trip() {
    let files = vec![
        ("file1.txt".to_string(), b"content1".to_vec()),
        ("file2.bin".to_string(), vec![0u8; 64]),
    ];
    let bytes = build_tar_zst_deterministic_bytes(&files).expect("tar.zst build");
    assert!(!bytes.is_empty());

    // Decompress and verify
    let decompressed = zstd::decode_all(std::io::Cursor::new(&bytes)).expect("zstd decompress");
    let mut archive = tar::Archive::new(std::io::Cursor::new(&decompressed));
    let entries: Vec<String> = archive
        .entries()
        .expect("entries")
        .filter_map(|e| e.ok())
        .map(|e| e.path().unwrap().to_string_lossy().to_string())
        .collect();
    assert_eq!(entries.len(), 2);
}

#[test]
fn build_tar_zst_deterministic_is_reproducible() {
    let files = vec![("a.txt".to_string(), b"data".to_vec())];
    let b1 = build_tar_zst_deterministic_bytes(&files).expect("tar.zst 1");
    let b2 = build_tar_zst_deterministic_bytes(&files).expect("tar.zst 2");
    assert_eq!(b1, b2, "deterministic tar.zst must be reproducible");
}

// ── post_valves (happy path with pause_ingest) ─────────────────

#[tokio::test]
async fn post_valves_sets_pause_ingest() {
    let state = test_app_state(16);
    let req = admin::SetValvesReq {
        actor: "ops".to_string(),
        reason: "maintenance window".to_string(),
        pause_ingest: Some(true),
        pause_compaction: None,
        throttle: None,
        read_only: None,
        emergency_brake: None,
    };
    let resp = admin::post_valves(State(state.clone()), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let c = state.control.read().await;
    assert!(c.valves.pause_ingest.enabled);
    assert_eq!(c.valves.pause_ingest.actor, "ops");
    assert_eq!(c.valves.pause_ingest.reason, "maintenance window");
}

#[tokio::test]
async fn post_valves_sets_read_only() {
    let state = test_app_state(16);
    let req = admin::SetValvesReq {
        actor: "ops".to_string(),
        reason: "pre-upgrade".to_string(),
        pause_ingest: None,
        pause_compaction: None,
        throttle: None,
        read_only: Some(true),
        emergency_brake: None,
    };
    let resp = admin::post_valves(State(state.clone()), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let c = state.control.read().await;
    assert!(c.valves.read_only.enabled);
}

#[tokio::test]
async fn post_valves_emergency_brake_cascades() {
    let state = test_app_state(16);
    let req = admin::SetValvesReq {
        actor: "ops".to_string(),
        reason: "emergency".to_string(),
        pause_ingest: None,
        pause_compaction: None,
        throttle: None,
        read_only: None,
        emergency_brake: Some(true),
    };
    let resp = admin::post_valves(State(state.clone()), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let c = state.control.read().await;
    assert!(c.valves.emergency_brake.enabled);
    assert!(c.valves.read_only.enabled, "emergency brake implies read_only");
    assert!(c.valves.pause_ingest.enabled, "emergency brake implies pause_ingest");
    assert!(
        c.valves.pause_compaction.enabled,
        "emergency brake implies pause_compaction"
    );
}

#[tokio::test]
async fn post_valves_requires_admin_write_scope() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let req = admin::SetValvesReq {
        actor: "ops".to_string(),
        reason: "test".to_string(),
        pause_ingest: Some(true),
        pause_compaction: None,
        throttle: None,
        read_only: None,
        emergency_brake: None,
    };
    let resp = admin::post_valves(State(state), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn post_valves_sets_throttle_with_params() {
    let state = test_app_state(16);
    let req = admin::SetValvesReq {
        actor: "ops".to_string(),
        reason: "rate-limit".to_string(),
        pause_ingest: None,
        pause_compaction: None,
        throttle: Some(SetThrottle {
            enabled: true,
            retry_after_ms: Some(500),
            events_per_sec: Some(100),
            bytes_per_sec: Some(1_000_000),
            max_in_flight: Some(10),
        }),
        read_only: None,
        emergency_brake: None,
    };
    let resp = admin::post_valves(State(state.clone()), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let c = state.control.read().await;
    assert!(c.valves.throttle.enabled);
    assert_eq!(c.valves.throttle.retry_after_ms, Some(500));
    assert_eq!(c.valves.throttle.events_per_sec, Some(100));
    assert_eq!(c.valves.throttle.bytes_per_sec, Some(1_000_000));
    assert_eq!(c.valves.throttle.max_in_flight, Some(10));
}

// ── post_replication_segment (bad base64) ──────────────────────

#[tokio::test]
async fn post_replication_segment_rejects_bad_base64() {
    let state = test_app_state(16);
    let req = admin::ReplicationSegmentReq {
        shard_id: "shard-0001".to_string(),
        epoch: 1,
        leader_node_id: None,
        segment_base64: "!!!not-valid-base64!!!".to_string(),
        segment_hash: None,
    };
    let resp = admin::post_replication_segment(State(state), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert!(body["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("segmentBase64 decode failed"));
}

#[tokio::test]
async fn post_replication_segment_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let req = admin::ReplicationSegmentReq {
        shard_id: "shard-0001".to_string(),
        epoch: 1,
        leader_node_id: None,
        segment_base64: base64::engine::general_purpose::STANDARD.encode(b"segment-data"),
        segment_hash: None,
    };
    let resp = admin::post_replication_segment(State(state), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── problem_for_status (additional edge cases) ─────────────────

#[test]
fn problem_for_status_not_implemented() {
    let problem = problem_for_status(StatusCode::NOT_IMPLEMENTED, "not yet");
    let resp = problem.into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[test]
fn problem_for_status_internal_server_error_fallback() {
    let problem = problem_for_status(StatusCode::INTERNAL_SERVER_ERROR, "oops");
    let resp = problem.into_response();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn problem_for_status_precondition_failed() {
    let problem = problem_for_status(StatusCode::PRECONDITION_FAILED, "stale");
    let resp = problem.into_response();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

// ── evidence helper functions ──────────────────────────────────

#[test]
fn evidence_node_context_populates_fields() {
    let state = test_app_state(16);
    let ctx = evidence_node_context(&state);
    assert_eq!(ctx.node_id, "node-a");
    assert_eq!(ctx.build.version, "test");
    assert_eq!(ctx.build.commit, "test");
}

#[test]
fn submitted_event_id_format() {
    let id = submitted_event_id("act-1");
    assert!(id.contains("act-1"));
    assert!(id.starts_with(EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1));
}

#[test]
fn finished_event_id_format() {
    let id = finished_event_id("act-1", "succeeded");
    assert!(id.contains("act-1"));
    assert!(id.contains("succeeded"));
}

#[test]
fn mutation_event_id_format() {
    let long_hash = "0123456789abcdef0123456789abcdef";
    let id = mutation_event_id("act-1", long_hash);
    assert!(id.contains("act-1"));
    assert!(id.contains("0123456789abcdef"));
}

#[test]
fn mutation_event_id_short_hash() {
    let id = mutation_event_id("act-1", "short");
    assert!(id.contains("short"));
}

#[test]
fn checkpoint_id_format() {
    let id = checkpoint_id("act-1", "0123456789abcdef0123456789abcdef");
    assert!(id.starts_with("checkpoint:"));
    assert!(id.contains("act-1"));
}

#[test]
fn checkpoint_event_id_format() {
    let id = checkpoint_event_id("checkpoint:act-1:hash");
    assert!(id.contains("checkpoint:act-1:hash"));
}

// ── now_unix_ms ────────────────────────────────────────────────

#[test]
fn now_unix_ms_returns_plausible_value() {
    let ms = now_unix_ms();
    // Should be after year 2020 in milliseconds
    assert!(ms > 1_577_836_800_000);
}

// ── sync_control_metrics ───────────────────────────────────────

#[test]
fn sync_control_metrics_runs_without_panic() {
    let state = test_app_state(16);
    let mut c = control::ControlV1::default();
    c.valves.pause_ingest.enabled = true;
    c.valves.throttle.enabled = true;
    sync_control_metrics(&state.metrics, &c);
    // No panic = pass (metrics are set internally)
}

// ── post_admin_append (validation) ─────────────────────────────

#[tokio::test]
async fn post_admin_append_empty_events_returns_501() {
    let state = test_app_state(16);
    let body = append::AppendBody {
        tenant_id: "tenant-a".to_string(),
        stream_type: "test".to_string(),
        stream_id: "stream-1".to_string(),
        expected_next_seq: 0,
        events: vec![],
    };
    let resp = append::post_admin_append(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    // No dataplane -> 501
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── get_proj_meta / post_projection_rebuild auth ───────────────

#[tokio::test]
async fn get_proj_meta_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = get_proj_meta(
        State(state.clone()),
        Query(ProjMetaQuery {
            shard_id: "shard-0001".to_string(),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp2 = get_proj_meta(
        State(state),
        Query(ProjMetaQuery {
            shard_id: "shard-0001".to_string(),
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(resp2.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn post_projection_rebuild_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = post_projection_rebuild(State(state.clone()), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp2 = post_projection_rebuild(State(state), dev_scope_headers("admin:write"))
        .await
        .into_response();
    assert_eq!(resp2.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── get_gpus requires auth ─────────────────────────────────────

#[tokio::test]
async fn get_gpus_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = routing::get_gpus(State(state), HeaderMap::new()).await.into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── post_stream_meta requires auth ─────────────────────────────

#[tokio::test]
async fn post_stream_meta_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let req = admin::StreamMetaReq {
        tenant_id: "tenant-a".to_string(),
        stream_type: "answers".to_string(),
        stream_id: "stream-1".to_string(),
        min_live_seq: Some(5),
        tombstone_seq: None,
        actor: "ops".to_string(),
        reason: "cleanup".to_string(),
    };
    let resp = admin::post_stream_meta(State(state), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── receipt endpoints require auth ──────────────────────────────

#[tokio::test]
async fn receipt_body_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = receipts::get_receipt_body_v1(
        State(state),
        Path("crx_abc".to_string()),
        Query(TenantQuery {
            tenant_id: "tenant-a".to_string(),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn receipt_signature_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = receipts::get_receipt_signature_v1(
        State(state),
        Path("crx_abc".to_string()),
        Query(TenantQuery {
            tenant_id: "tenant-a".to_string(),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn receipt_verification_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = receipts::get_receipt_verification_v1(
        State(state),
        Path("crx_abc".to_string()),
        Query(TenantQuery {
            tenant_id: "tenant-a".to_string(),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn receipt_export_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = receipts::get_receipt_export_v1(
        State(state),
        Path("crx_abc".to_string()),
        Query(receipts::ExportQueryV1 {
            tenant_id: "tenant-a".to_string(),
            include: None,
            redaction: None,
            format: None,
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── replication segment requires auth ──────────────────────────

#[tokio::test]
async fn post_replication_segment_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let req = admin::ReplicationSegmentReq {
        shard_id: "shard-0001".to_string(),
        epoch: 1,
        leader_node_id: None,
        segment_base64: "AAAA".to_string(),
        segment_hash: None,
    };
    let resp = admin::post_replication_segment(State(state), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── parse_export_options (tar.zst format) ──────────────────────

#[test]
fn parse_export_options_tar_zst_format() {
    let opts = parse_receipt_export_options_v1(None, None, Some("tar.zst")).unwrap();
    assert!(matches!(opts.format, ExportFormatV1::TarZst));
}

#[test]
fn parse_export_options_zip_format() {
    let opts = parse_receipt_export_options_v1(None, None, Some("zip")).unwrap();
    assert!(matches!(opts.format, ExportFormatV1::Zip));
}

#[test]
fn parse_export_options_redaction_none() {
    let opts = parse_receipt_export_options_v1(None, Some("none"), None).unwrap();
    assert!(matches!(opts.redaction, ExportRedactionV1::None));
}

#[test]
fn parse_export_options_redaction_metadata_only() {
    let opts = parse_receipt_export_options_v1(None, Some("metadata_only"), None).unwrap();
    assert!(matches!(opts.redaction, ExportRedactionV1::MetadataOnly));
}

#[test]
fn parse_export_options_redaction_tenant_safe() {
    let opts = parse_receipt_export_options_v1(None, Some("tenant_safe"), None).unwrap();
    assert!(matches!(opts.redaction, ExportRedactionV1::TenantSafe));
}

// ── map_store_error_http (additional edge case) ────────────────

#[tokio::test]
async fn map_store_error_http_shard_unavailable_body_fields() {
    let err = AppendError::ShardUnavailable {
        shard_id: "shard-0042".to_string(),
        owner_gpu_id: 7,
        current_shard_map_version: 99,
    };
    let resp = map_store_error_http(err).into_response();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = json_body(resp).await;
    // Extensions are flattened into the top-level JSON
    assert_eq!(body["code"], "SHARD_UNAVAILABLE");
    assert_eq!(body["shardId"], "shard-0042");
    assert_eq!(body["ownerGpuId"], 7);
    assert_eq!(body["currentShardMapVersion"], 99);
}

#[tokio::test]
async fn map_store_error_http_wrong_shard_body_fields() {
    let err = AppendError::WrongShard {
        leader_grpc_addr: "http://leader:50051".to_string(),
        current_shard_map_version: 3,
    };
    let resp = map_store_error_http(err).into_response();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    let body = json_body(resp).await;
    assert_eq!(body["code"], "WRONG_SHARD");
    assert_eq!(body["leaderGrpcAddr"], "http://leader:50051");
}

#[tokio::test]
async fn map_store_error_http_version_mismatch_body_fields() {
    let err = AppendError::ShardMapVersionMismatch {
        client_version: 5,
        current_version: 8,
    };
    let resp = map_store_error_http(err).into_response();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    let body = json_body(resp).await;
    assert_eq!(body["code"], "SHARDMAP_VERSION_MISMATCH");
    assert_eq!(body["clientShardMapVersion"], 5);
    assert_eq!(body["currentShardMapVersion"], 8);
}

// ── CapacityState auto_paused ──────────────────────────────────

#[tokio::test]
async fn readyz_ok_when_capacity_warning_but_above_emergency() {
    let state = test_app_state(16);
    mark_ready_except_control(&state).await;
    {
        let mut cap = state.capacity.write().await;
        cap.free_ratio = 0.15; // Above emergency (0.10) but below warning (0.20)
        cap.free_bytes = 15;
        cap.total_bytes = 100;
    }
    let resp = health::readyz(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── post_admin_action (runtime-knob-update with throttle params) ─

#[tokio::test]
async fn runtime_knob_update_throttle_params() {
    let state = test_app_state(16);
    let params = serde_json::json!({
        "actor": "ops",
        "reason": "throttle-config",
        "throttleEnabled": true,
        "throttleEventsPerSec": 50,
        "throttleBytesPerSec": 102400,
        "throttleMaxInFlight": 8,
        "throttleRetryAfterMs": 200
    });

    let result = admin::execute_admin_action(
        &state,
        "act-throttle-1",
        "runtime-knob-update",
        Some(&params),
        None,
        None,
    )
    .await
    .expect("runtime knob update succeeds");

    let control = state.control.read().await.clone();
    assert!(control.valves.throttle.enabled);
    assert_eq!(control.valves.throttle.events_per_sec, Some(50));
    assert_eq!(control.valves.throttle.bytes_per_sec, Some(102400));
    assert_eq!(control.valves.throttle.max_in_flight, Some(8));
    assert_eq!(control.valves.throttle.retry_after_ms, Some(200));
    assert!(result.result.is_object());
}

// ── text search with min_score ─────────────────────────────────

#[tokio::test]
async fn text_search_with_min_score_filters() {
    enable_text_search();

    let state = test_app_state(16);
    let ccxi_bytes = build_test_ccxi(&["the rust programming language", "unrelated document about cooking"]);
    load_test_index(&state, &ccxi_bytes).await;

    let body = query::TextSearchBody {
        tenant_id: "tenant-a".to_string(),
        query: "rust programming".to_string(),
        limit: 10,
        token_budget: None,
        min_score: Some(100.0), // Very high threshold
        mode: None,
        include_receipt: None,
    };

    let resp = query::post_query_text_search(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── ops log requires auth ──────────────────────────────────────

#[serial_test::serial]
#[tokio::test]
async fn get_ops_log_requires_auth_in_dev_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = admin::get_ops_log(
        State(state),
        Query(admin::OpsLogQuery {
            node_id: None,
            since: None,
            until: None,
            from_seq: None,
            max_events: None,
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── post_valves with pause_compaction ───────────────────────────

#[tokio::test]
async fn post_valves_sets_pause_compaction() {
    let state = test_app_state(16);
    let req = admin::SetValvesReq {
        actor: "ops".to_string(),
        reason: "compaction-pause".to_string(),
        pause_ingest: None,
        pause_compaction: Some(true),
        throttle: None,
        read_only: None,
        emergency_brake: None,
    };
    let resp = admin::post_valves(State(state.clone()), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let c = state.control.read().await;
    assert!(c.valves.pause_compaction.enabled);
}

// ── get_entity_count validation ────────────────────────────────

#[tokio::test]
async fn get_entity_count_missing_tenant_id_returns_501() {
    let state = test_app_state(16);
    let params = std::collections::HashMap::new();
    let resp = get_entity_count(State(state), axum::extract::Query(params))
        .await
        .into_response();
    // Missing tenant_id should still reach no-dataplane path -> 501
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

// ── admin_action_error helper ──────────────────────────────────

#[test]
fn admin_action_error_wraps_multiple_messages() {
    let err = admin_action_error("first failure");
    assert!(err.contains("first failure"));
    let err2 = admin_action_error("second failure with details");
    assert!(err2.contains("second failure with details"));
}

// ── problem_response helper ────────────────────────────────────

#[tokio::test]
async fn problem_response_returns_correct_status_and_content_type() {
    let resp = problem_response(StatusCode::CONFLICT, "conflict happened");
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR); // CONFLICT uses fallback -> internal
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(ct.contains("application/problem+json"));
}

// ── hex16 ───────────────────────────────────────────────────────

#[test]
fn hex16_encodes_all_zeros() {
    let bytes = [0u8; 16];
    assert_eq!(hex16(&bytes), "00000000000000000000000000000000");
}

#[test]
fn hex16_encodes_all_ff() {
    let bytes = [0xffu8; 16];
    assert_eq!(hex16(&bytes), "ffffffffffffffffffffffffffffffff");
}

#[test]
fn hex16_encodes_known_pattern() {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xde;
    bytes[1] = 0xad;
    bytes[15] = 0xef;
    let hex = hex16(&bytes);
    assert!(hex.starts_with("dead"));
    assert!(hex.ends_with("ef"));
    assert_eq!(hex.len(), 32);
}

// ── read_param_str ──────────────────────────────────────────────

#[test]
fn read_param_str_extracts_and_trims() {
    let params = serde_json::json!({"name": "  hello  "});
    assert_eq!(read_param_str(Some(&params), "name"), Some("hello"));
}

#[test]
fn read_param_str_none_for_missing() {
    let params = serde_json::json!({"name": "val"});
    assert_eq!(read_param_str(Some(&params), "missing"), None);
}

#[test]
fn read_param_str_none_for_empty() {
    let params = serde_json::json!({"name": "  "});
    assert_eq!(read_param_str(Some(&params), "name"), None);
}

#[test]
fn read_param_str_none_for_none_params() {
    assert_eq!(read_param_str(None, "name"), None);
}

// ── read_param_bool ─────────────────────────────────────────────

#[test]
fn read_param_bool_from_bool_value() {
    let params = serde_json::json!({"flag": true});
    assert_eq!(read_param_bool(Some(&params), "flag"), Some(true));
    let params = serde_json::json!({"flag": false});
    assert_eq!(read_param_bool(Some(&params), "flag"), Some(false));
}

#[test]
fn read_param_bool_from_string_value() {
    for (s, expected) in [
        ("true", true),
        ("1", true),
        ("yes", true),
        ("y", true),
        ("false", false),
        ("0", false),
        ("no", false),
        ("n", false),
    ] {
        let params = serde_json::json!({"flag": s});
        assert_eq!(read_param_bool(Some(&params), "flag"), Some(expected), "failed for {s}");
    }
}

#[test]
fn read_param_bool_none_for_invalid() {
    let params = serde_json::json!({"flag": "maybe"});
    assert_eq!(read_param_bool(Some(&params), "flag"), None);
}

#[test]
fn read_param_bool_none_for_missing() {
    let params = serde_json::json!({});
    assert_eq!(read_param_bool(Some(&params), "flag"), None);
}

// ── read_param_u64 ──────────────────────────────────────────────

#[test]
fn read_param_u64_from_number() {
    let params = serde_json::json!({"val": 42});
    assert_eq!(read_param_u64(Some(&params), "val"), Some(42));
}

#[test]
fn read_param_u64_from_string() {
    let params = serde_json::json!({"val": "99"});
    assert_eq!(read_param_u64(Some(&params), "val"), Some(99));
}

#[test]
fn read_param_u64_none_for_invalid() {
    let params = serde_json::json!({"val": "not-a-number"});
    assert_eq!(read_param_u64(Some(&params), "val"), None);
}

// ── read_param_u32 ──────────────────────────────────────────────

#[test]
fn read_param_u32_valid() {
    let params = serde_json::json!({"val": 100});
    assert_eq!(read_param_u32(Some(&params), "val"), Some(100));
}

#[test]
fn read_param_u32_overflow() {
    let params = serde_json::json!({"val": u64::MAX});
    assert_eq!(read_param_u32(Some(&params), "val"), None);
}

// ── read_param_f64 ──────────────────────────────────────────────

#[test]
fn read_param_f64_from_number() {
    let params = serde_json::json!({"val": 3.14});
    let result = read_param_f64(Some(&params), "val");
    assert!(result.is_some());
    assert!((result.unwrap() - 3.14).abs() < 0.001);
}

#[test]
fn read_param_f64_from_string() {
    let params = serde_json::json!({"val": "2.718"});
    let result = read_param_f64(Some(&params), "val");
    assert!(result.is_some());
    assert!((result.unwrap() - 2.718).abs() < 0.001);
}

#[test]
fn read_param_f64_none_for_invalid() {
    let params = serde_json::json!({"val": "abc"});
    assert_eq!(read_param_f64(Some(&params), "val"), None);
}

// ── is_known_admin_action ───────────────────────────────────────

#[test]
fn is_known_admin_action_all_known() {
    for action in [
        "verify-store",
        "scrub-now",
        "snapshot-verify",
        "projection-rebuild",
        "parity-pack",
        "runtime-knob-update",
        "force-seal",
    ] {
        assert!(is_known_admin_action(action), "expected {action} to be known");
    }
}

#[test]
fn is_known_admin_action_unknown() {
    assert!(!is_known_admin_action("unknown-action"));
    assert!(!is_known_admin_action(""));
    assert!(!is_known_admin_action("VERIFY-STORE")); // case sensitive
}

// ── trace_id_from_traceparent (additional) ──────────────────────

#[test]
fn trace_id_from_traceparent_valid_w3c() {
    let tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    assert_eq!(
        trace_id_from_traceparent(Some(tp)),
        Some("0af7651916cd43dd8448eb211c80319c".to_string())
    );
}

#[test]
fn trace_id_from_traceparent_none_input() {
    assert_eq!(trace_id_from_traceparent(None), None);
}

#[test]
fn trace_id_from_traceparent_bad_format() {
    assert_eq!(trace_id_from_traceparent(Some("invalid")), None);
    assert_eq!(trace_id_from_traceparent(Some("00-short-b7-01")), None);
}

// ── parse_knowledge_authority_mode ──────────────────────────────

#[test]
fn parse_knowledge_authority_mode_all_variants() {
    assert_eq!(
        parse_knowledge_authority_mode("shadow"),
        Some(KnowledgeAuthorityModeV1::Shadow)
    );
    assert_eq!(
        parse_knowledge_authority_mode("knowledge_shadow"),
        Some(KnowledgeAuthorityModeV1::Shadow)
    );
    assert_eq!(
        parse_knowledge_authority_mode("dual_write"),
        Some(KnowledgeAuthorityModeV1::DualWrite)
    );
    assert_eq!(
        parse_knowledge_authority_mode("shadow_read"),
        Some(KnowledgeAuthorityModeV1::ShadowRead)
    );
    assert_eq!(
        parse_knowledge_authority_mode("authoritative"),
        Some(KnowledgeAuthorityModeV1::Authoritative)
    );
    assert_eq!(parse_knowledge_authority_mode("unknown"), None);
}

// ── parse_knowledge_rollout_stage ──────────────────────────────

#[test]
fn parse_knowledge_rollout_stage_all_variants() {
    assert_eq!(
        parse_knowledge_rollout_stage("shadow"),
        Some(KnowledgeRolloutStageV1::InternalShadow)
    );
    assert_eq!(
        parse_knowledge_rollout_stage("internal_shadow"),
        Some(KnowledgeRolloutStageV1::InternalShadow)
    );
    assert_eq!(
        parse_knowledge_rollout_stage("tenant_validation"),
        Some(KnowledgeRolloutStageV1::TenantValidation)
    );
    assert_eq!(
        parse_knowledge_rollout_stage("internal_authority"),
        Some(KnowledgeRolloutStageV1::InternalAuthority)
    );
    assert_eq!(
        parse_knowledge_rollout_stage("limited_production_authority"),
        Some(KnowledgeRolloutStageV1::LimitedProductionAuthority)
    );
    assert_eq!(
        parse_knowledge_rollout_stage("full_production_authority"),
        Some(KnowledgeRolloutStageV1::FullProductionAuthority)
    );
    assert_eq!(parse_knowledge_rollout_stage("unknown"), None);
}

// ── parse_knowledge_parity_status ──────────────────────────────

#[test]
fn parse_knowledge_parity_status_all_variants() {
    use corecrux_types::KnowledgeParityStatusV1;
    assert_eq!(
        parse_knowledge_parity_status("unknown"),
        Some(KnowledgeParityStatusV1::Unknown)
    );
    assert_eq!(
        parse_knowledge_parity_status("pass"),
        Some(KnowledgeParityStatusV1::Pass)
    );
    assert_eq!(
        parse_knowledge_parity_status("warn"),
        Some(KnowledgeParityStatusV1::Warn)
    );
    assert_eq!(
        parse_knowledge_parity_status("fail"),
        Some(KnowledgeParityStatusV1::Fail)
    );
    assert_eq!(parse_knowledge_parity_status("other"), None);
}

// ── parse_tenant_throttle_rules ─────────────────────────────────

#[test]
fn parse_tenant_throttle_rules_valid_array() {
    let rules = serde_json::json!([
        {"tenantId": "t1", "eventsPerSec": 100},
        {"tenantId": "t2", "bytesPerSec": 1000}
    ]);
    let result = parse_tenant_throttle_rules(&rules);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 2);
}

#[test]
fn parse_tenant_throttle_rules_empty_tenant_fails() {
    let rules = serde_json::json!([
        {"tenantId": "  ", "eventsPerSec": 100}
    ]);
    let result = parse_tenant_throttle_rules(&rules);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("non-empty tenantId"));
}

#[test]
fn parse_tenant_throttle_rules_string_input_fails() {
    let rules = serde_json::json!("not an array");
    let result = parse_tenant_throttle_rules(&rules);
    assert!(result.is_err());
}

// ── event_id helpers (additional) ─────────────────────────────────

#[test]
fn submitted_event_id_contains_schema() {
    let id = submitted_event_id("act-99");
    assert!(id.contains("act-99"));
    assert!(id.contains("submitted"));
}

#[test]
fn finished_event_id_contains_status() {
    let id = finished_event_id("act-99", "failed");
    assert!(id.contains("act-99"));
    assert!(id.contains("failed"));
}

#[test]
fn mutation_event_id_with_short_hash() {
    let id = mutation_event_id("act-1", "short");
    assert!(id.contains("act-1"));
    assert!(id.contains("short"));
}

#[test]
fn checkpoint_id_with_long_hash() {
    let id = checkpoint_id("act-2", "0123456789abcdef0123456789abcdef");
    assert!(id.starts_with("checkpoint:"));
    assert!(id.contains("act-2"));
}

// ── now_unix_ms (additional) ────────────────────────────────────

#[test]
fn now_unix_ms_after_2025() {
    let ms = now_unix_ms();
    assert!(ms > 1_735_689_600_000); // after 2025-01-01
}

// ── AdminActionStatus serialization ─────────────────────────────

#[test]
fn admin_action_status_serializes() {
    assert_eq!(
        serde_json::to_string(&AdminActionStatus::Submitted).unwrap(),
        "\"submitted\""
    );
    assert_eq!(
        serde_json::to_string(&AdminActionStatus::Running).unwrap(),
        "\"running\""
    );
    assert_eq!(
        serde_json::to_string(&AdminActionStatus::Succeeded).unwrap(),
        "\"succeeded\""
    );
    assert_eq!(serde_json::to_string(&AdminActionStatus::Failed).unwrap(), "\"failed\"");
}

#[test]
fn admin_action_status_round_trip() {
    for status in [
        AdminActionStatus::Submitted,
        AdminActionStatus::Running,
        AdminActionStatus::Succeeded,
        AdminActionStatus::Failed,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let parsed: AdminActionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, status);
    }
}

// ── crux-observe endpoint tests ──────────────────────────────────

#[serial_test::serial]
#[tokio::test]
async fn ops_facts_returns_501_when_observe_disabled() {
    std::env::remove_var("CRUX_SELF_OBSERVE");
    let state = test_app_state(16);
    let headers = dev_scope_headers("admin:read");
    let params = std::collections::HashMap::new();
    let resp = query_ops_facts(State(state), headers, Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[serial_test::serial]
#[tokio::test]
async fn ops_facts_returns_200_when_observe_enabled() {
    std::env::set_var("CRUX_SELF_OBSERVE", "true");
    let state = test_app_state(16);
    let headers = dev_scope_headers("admin:read");
    let params = std::collections::HashMap::new();
    let resp = query_ops_facts(State(state), headers, Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["facts"].is_array());
    std::env::remove_var("CRUX_SELF_OBSERVE");
}

#[serial_test::serial]
#[tokio::test]
async fn ops_errors_returns_501_when_observe_disabled() {
    std::env::remove_var("CRUX_SELF_OBSERVE");
    let state = test_app_state(16);
    let headers = dev_scope_headers("admin:read");
    let params = std::collections::HashMap::new();
    let resp = query_ops_errors(State(state), headers, Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}
#[serial_test::serial]
#[serial_test::serial]
#[tokio::test]
async fn ops_errors_returns_facts_when_enabled() {
    std::env::set_var("CRUX_SELF_OBSERVE", "true");
    let state = test_app_state(16);
    // Store an error fact
    {
        let mut store = state.fact_store.write().await;
        store.store(corecrux_memory::fact_store::StoreFact {
            entity: "__ops__::error:test-err-1".to_string(),
            key: "test error".to_string(),
            value: "something went wrong".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        });
    }
    let headers = dev_scope_headers("admin:read");
    let params = std::collections::HashMap::new();
    let resp = query_ops_errors(State(state), headers, Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let facts = body["facts"].as_array().unwrap();
    assert_eq!(facts.len(), 1);
    std::env::remove_var("CRUX_SELF_OBSERVE");
}
#[serial_test::serial]
#[tokio::test]
async fn ops_health_returns_latest_per_component() {
    std::env::set_var("CRUX_SELF_OBSERVE", "true");
    let state = test_app_state(16);
    {
        let mut store = state.fact_store.write().await;
        store.store(corecrux_memory::fact_store::StoreFact {
            entity: "__ops__::health:shard_store".to_string(),
            key: "health".to_string(),
            value: "degraded".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        });
        store.store(corecrux_memory::fact_store::StoreFact {
            entity: "__ops__::health:shard_store".to_string(),
            key: "health".to_string(),
            value: "healthy".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        });
    }
    let headers = dev_scope_headers("admin:read");
    let resp = get_ops_health(State(state), headers).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let health = body["health"].as_array().unwrap();
    // Should deduplicate to 1 entry for the component
    assert_eq!(health.len(), 1);
    std::env::remove_var("CRUX_SELF_OBSERVE");
}

#[serial_test::serial]
#[tokio::test]
async fn bootstrap_pull_returns_501_when_disabled() {
    std::env::remove_var("CRUX_SELF_OBSERVE");
    let state = test_app_state(16);
    let headers = dev_scope_headers("admin:read");
    let body = BootstrapPullBody {
        query: "error".to_string(),
        top_k: 10,
        token_budget: None,
    };
    let resp = post_bootstrap_pull(State(state), headers, Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[serial_test::serial]
#[tokio::test]
async fn bootstrap_pull_returns_facts_when_enabled() {
    std::env::set_var("CRUX_SELF_OBSERVE", "true");
    let state = test_app_state(16);
    // Seed bootstrap data
    {
        let seeder = crux_observe::bootstrap::BootstrapSeeder::new(state.fact_store.clone());
        seeder.seed().await;
    }
    let headers = dev_scope_headers("admin:read");
    let body = BootstrapPullBody {
        query: "error".to_string(),
        top_k: 10,
        token_budget: None,
    };
    let resp = post_bootstrap_pull(State(state), headers, Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["source"].as_str(), Some("__bootstrap__"));
    assert!(body["facts"].is_array());
    std::env::remove_var("CRUX_SELF_OBSERVE");
}

#[serial_test::serial]
#[tokio::test]
async fn bootstrap_status_returns_seeded_false_initially() {
    std::env::set_var("CRUX_SELF_OBSERVE", "true");
    let state = test_app_state(16);
    let headers = dev_scope_headers("admin:read");
    let resp = get_bootstrap_status(State(state), headers).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["seeded"].as_bool(), Some(false));
    assert_eq!(body["fact_count"].as_u64(), Some(0));
    std::env::remove_var("CRUX_SELF_OBSERVE");
}

#[serial_test::serial]
#[tokio::test]
async fn bootstrap_status_returns_seeded_true_after_seed() {
    std::env::set_var("CRUX_SELF_OBSERVE", "true");
    let state = test_app_state(16);
    {
        let seeder = crux_observe::bootstrap::BootstrapSeeder::new(state.fact_store.clone());
        seeder.seed().await;
    }
    let headers = dev_scope_headers("admin:read");
    let resp = get_bootstrap_status(State(state), headers).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["seeded"].as_bool(), Some(true));
    assert!(body["fact_count"].as_u64().unwrap() > 0);
    assert!(body["categories"].is_object());
    std::env::remove_var("CRUX_SELF_OBSERVE");
}

// ── Production hardening: timeout layer compiles ────────────────

#[tokio::test]
async fn router_with_timeout_and_panic_layers_compiles() {
    let state = test_app_state(16);
    let app = router(state);
    // Verify the router can be converted to a service (layers are applied).
    let _service = app.into_service::<axum::body::Body>();
}

// ── Production hardening: panic handler returns 500 ─────────────

#[tokio::test]
async fn panic_handler_returns_500_problem_json() {
    let resp = handle_panic(Box::new("test panic"));
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert_eq!(ct, "application/problem+json");
    let body = json_body(resp).await;
    assert_eq!(body["status"], 500);
}

#[tokio::test]
async fn panic_handler_handles_string_panic() {
    let resp = handle_panic(Box::new(String::from("string panic")));
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = json_body(resp).await;
    assert_eq!(body["status"], 500);
}

// ── Production hardening: /v1/version endpoint ──────────────────

#[serial_test::serial]
#[tokio::test]
async fn version_endpoint_returns_build_info_and_features() {
    std::env::remove_var("CORECRUXD_SYNC_ENABLED");
    std::env::remove_var("CORECRUXD_SYNC_REMOTE_URL");
    std::env::remove_var("CORECRUXD_SYNC_API_KEY");
    let state = test_app_state(16);
    *state.update_status.write().await = corecrux_types::UpdateStatus {
        enabled: true,
        state: corecrux_types::UpdateCheckState::Current,
        remote: "origin".to_string(),
        ref_name: "main".to_string(),
        tracking_ref: "origin/main".to_string(),
        repo_dir: Some("/tmp/crux".to_string()),
        current_commit: Some("abc123".to_string()),
        latest_commit: Some("abc123".to_string()),
        ahead_by: 0,
        behind_by: 0,
        checked_at: Some("2026-04-09T12:00:00Z".to_string()),
        error: None,
        upgrade_hint: "current".to_string(),
    };
    let resp = get_version(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["version"], "test");
    assert_eq!(body["commit"], "test");
    assert_eq!(body["msrv"], "1.88.0");
    assert!(body["features"].is_object());
    // Features should be booleans
    assert!(body["features"]["text_search"].is_boolean());
    assert!(body["features"]["graph_expand"].is_boolean());
    assert!(body["features"]["self_observe"].is_boolean());
    assert!(body["features"]["mcp"].is_boolean());
    assert_eq!(body["sync"]["mode"], "local_only");
    assert_eq!(body["sync"]["configured"], false);
    assert_eq!(body["update"]["state"], "current");
    assert_eq!(body["update"]["tracking_ref"], "origin/main");
    assert_eq!(body["update"]["current_commit"], "abc123");
    assert!(body["update"]["repo_dir"].is_null());
    assert!(body["update"]["error"].is_null());
}

#[serial_test::serial]
#[tokio::test]
async fn version_endpoint_reports_degraded_sync_when_remote_is_incomplete() {
    std::env::set_var("CORECRUXD_SYNC_ENABLED", "true");
    std::env::set_var("CORECRUXD_SYNC_REMOTE_URL", "http://example.test:14800");
    std::env::remove_var("CORECRUXD_SYNC_API_KEY");

    let state = test_app_state(16);
    let resp = get_version(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["sync"]["mode"], "degraded");
    assert_eq!(body["sync"]["configured"], false);
    assert_eq!(body["sync"]["background_sync_enabled"], true);
    assert_eq!(body["sync"]["remote_url"], "http://example.test:14800");
    assert_eq!(body["sync"]["api_key_configured"], false);
    assert!(body["sync"]["degraded_reason"]
        .as_str()
        .unwrap_or_default()
        .contains("CORECRUXD_SYNC_API_KEY"));

    std::env::remove_var("CORECRUXD_SYNC_ENABLED");
    std::env::remove_var("CORECRUXD_SYNC_REMOTE_URL");
    std::env::remove_var("CORECRUXD_SYNC_API_KEY");
}
