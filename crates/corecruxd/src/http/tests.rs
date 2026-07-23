// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Integration tests for the HTTP surface — spins up `AppState` and exercises every route family.

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
use crate::test_support::EnvVarGuard;
use axum::body::to_bytes;
use corecrux_types::{
    compute_shard_map_v1_blake3_hex, format_u64_hex, HashRange, KnowledgeAuthorityModeV1, KnowledgeRolloutStageV1,
    NodeAddr, ShardDescriptor, ShardMapV1, ShardState, DEFAULT_COMPAT_REQUIRES, DEFAULT_SDK_VERSION,
    SHARDMAP_HASH_FN_V1, SHARDMAP_KEY_ENCODING_V1, SHARDMAP_V1,
};
use ed25519_dalek::{Signer as _, SigningKey};
use tower::ServiceExt as _;

fn test_node(node_id: &str, http_addr: &str, grpc_addr: &str) -> NodeAddr {
    NodeAddr {
        node_id: node_id.to_string(),
        grpc_addr: grpc_addr.to_string(),
        http_addr: http_addr.to_string(),
    }
}

/// Build a canned receipt-stream [`StoredEvent`] for the dataplane stub.
pub(super) fn receipt_stored_event(event_type: &str, seq: u64, payload: &[u8]) -> corecrux_storage::StoredEvent {
    corecrux_storage::StoredEvent {
        seq,
        event_id: format!("evt-{seq}"),
        occurred_at: "2026-06-17T00:00:00Z".to_string(),
        ingested_at: "2026-06-17T00:00:01Z".to_string(),
        event_type: event_type.to_string(),
        content_type: "application/cbor".to_string(),
        payload: payload.to_vec(),
        location: corecrux_storage::FrameLocation {
            shard_id: 0,
            epoch: 1,
            segment_seq: 1,
            offset: 0,
        },
    }
}

/// Build an enabled [`FakeHttpDataplane`] (the capable shared double) for
/// handler tests in sibling modules. `read_stream_events` feeds `read_stream`;
/// `verification_report` feeds `verify_receipt_stream` (so the success path can
/// be asserted, not just the 404 arm).
pub(super) fn enabled_dataplane(
    read_stream_events: Vec<corecrux_storage::StoredEvent>,
    verification_report: Option<corecrux_receipts::VerificationReportV1>,
) -> super::dataplane::SharedHttpDataplane {
    Arc::new(FakeHttpDataplane {
        enabled: true,
        read_stream_events,
        verification_report,
        ..Default::default()
    })
}

/// A well-formed [`VerificationReportV1`] for asserting the receipt-verification
/// success path.
pub(super) fn sample_verification_report(receipt_id: &str, tenant_id: &str) -> corecrux_receipts::VerificationReportV1 {
    serde_json::from_value(serde_json::json!({
        "schema": "cuecrux.receipt.verify.v1",
        "receipt_id": receipt_id,
        "tenant_id": tenant_id,
        "payload_hash": "abcd",
        "signature": { "alg": "ed25519", "key_id": "kid-1" },
        "integrity": { "payload_hash_matches": true, "canonical_bytes_parse_ok": true },
        "trace_checks": {
            "retrieval_trace_present": false, "lanes_used_present": false,
            "candidate_generation_present": false, "filters_present": false,
            "normalisation_present": false, "fusion_present": false,
            "priors_applied_present": false, "anchors_present": false,
            "anchors_ids_present": false, "anchors_derivation_method_present": false,
            "rerank_present": false, "candidates_present": false, "candidate_digest_present": false
        },
        "signature_valid": true,
        "pubkey_fingerprint": "fp",
        "error_code": "OK",
        "verified_at": "2026-04-08T12:00:00Z",
        "verifier_build": "test"
    }))
    .expect("sample verification report")
}

fn sync_test_passport_fpr(public_key: &[u8; 32]) -> String {
    let digest = blake3::hash(public_key);
    format!("p_{}", hex::encode(&digest.as_bytes()[..16]))
}

fn sync_test_peer(tenant_id: &str) -> (SigningKey, SigningKey, rcx_capability_token::RcxCapabilityToken) {
    let trust_root = SigningKey::from_bytes(&[0x41; 32]);
    let subject = SigningKey::from_bytes(&[0x42; 32]);
    let trust_root_fpr = sync_test_passport_fpr(&trust_root.verifying_key().to_bytes());
    let mut token = rcx_capability_token::free_local_verified_fixture();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    token.token_id = "rcxct_peer_handshake_http_test".to_string();
    token.issued_at = now.saturating_sub(60);
    token.refresh_hint_at = now.saturating_add(1_800);
    token.expires_at = now.saturating_add(3_600);
    token.subject.passport_fpr = sync_test_passport_fpr(&subject.verifying_key().to_bytes());
    token.tenant_scope.tenant_id = tenant_id.to_string();
    token.issuer.passport_kid.clone_from(&trust_root_fpr);
    token.signature.kid.clone_from(&trust_root_fpr);
    token.backends[0].trust_root_kid = trust_root_fpr;
    token.signature.sig = trust_root.sign(&token.token_hash()).to_bytes();
    (trust_root, subject, token)
}

fn sync_peer_headers(
    token: &rcx_capability_token::RcxCapabilityToken,
    subject: &SigningKey,
    possession_key: &SigningKey,
    nonce: &[u8],
) -> HeaderMap {
    let mut signing_message = crux_sync::peer_handshake::PEER_HANDSHAKE_SIGNING_DOMAIN.to_vec();
    signing_message.extend_from_slice(token.token_id.as_bytes());
    signing_message.push(0);
    signing_message.extend_from_slice(nonce);

    let mut headers = HeaderMap::new();
    headers.insert(
        "x-crux-peer-token",
        HeaderValue::from_str(&base64::engine::general_purpose::STANDARD.encode(token.to_canonical_json().as_bytes()))
            .expect("peer token header"),
    );
    headers.insert(
        "x-crux-peer-pubkey",
        HeaderValue::from_str(&hex::encode(subject.verifying_key().to_bytes())).expect("peer public key header"),
    );
    headers.insert(
        "x-crux-peer-nonce",
        HeaderValue::from_str(&hex::encode(nonce)).expect("peer nonce header"),
    );
    headers.insert(
        "x-crux-peer-sig",
        HeaderValue::from_str(&hex::encode(possession_key.sign(&signing_message).to_bytes()))
            .expect("peer signature header"),
    );
    headers
}

fn sync_http_request(method: &str, uri: &str, headers: HeaderMap) -> axum::http::Request<axum::body::Body> {
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .body(axum::body::Body::empty())
        .expect("sync request");
    *request.headers_mut() = headers;
    request
}

fn sync_mutual_auth_app(trust_root: &SigningKey) -> Router {
    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    state.sync_mutual_auth = true;
    state.sync_peer_trust_root = Some(trust_root.verifying_key().to_bytes().to_vec());
    router_with_route_auth(state, test_case_store(), RouteAuthMode::Enforce)
}

async fn issue_sync_handshake_nonce(app: &Router) -> Vec<u8> {
    let response = app
        .clone()
        .oneshot(sync_http_request("POST", "/v1/sync/handshake/nonce", HeaderMap::new()))
        .await
        .expect("nonce response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    let body = json_body(response).await;
    assert_eq!(body["ttl_seconds"], SYNC_HANDSHAKE_NONCE_TTL_SECONDS);
    hex::decode(body["nonce"].as_str().expect("nonce string")).expect("nonce hex")
}

#[tokio::test]
async fn sync_mutual_auth_accepts_valid_peer_for_bound_tenant() {
    let (trust_root, subject, token) = sync_test_peer("tenant-acme");
    let app = sync_mutual_auth_app(&trust_root);
    let nonce = issue_sync_handshake_nonce(&app).await;
    let response = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-acme/manifest",
            sync_peer_headers(&token, &subject, &subject, &nonce),
        ))
        .await
        .expect("manifest response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn sync_mutual_auth_rejects_peer_with_revoked_identity_link() {
    // M3: a peer whose identity link carries `revoked_at` is rejected at the sync
    // boundary with `peer_revoked`, even though its handshake is otherwise valid.
    let (trust_root, subject, token) = sync_test_peer("tenant-acme");

    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    state.sync_mutual_auth = true;
    state.sync_peer_trust_root = Some(trust_root.verifying_key().to_bytes().to_vec());
    state.identity_links_enabled = true;
    {
        let mut entities = state.entity_store.write().await;
        let revoked = corecrux_memory::identity_link::IdentityLinkPayload {
            schema_version: "1".to_string(),
            local_passport_id: "personal-default".to_string(),
            local_fpr: "local-fpr".to_string(),
            remote_fpr: token.subject.passport_fpr.clone(),
            remote_public_key_hex: hex::encode(subject.verifying_key().to_bytes()),
            subject_kind: "passport".to_string(),
            scope: "memory.read".to_string(),
            statement_hash: "blake3:00".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            sig_local: "00".repeat(64),
            sig_remote: "00".repeat(64),
            revoked_at: Some("2026-07-16T00:00:00Z".to_string()),
        };
        entities
            .upsert(
                corecrux_memory::identity_link::IDENTITY_LINK_KIND,
                "link-revoked-1",
                serde_json::to_value(&revoked).unwrap(),
                "test",
                None,
            )
            .unwrap();
    }
    let app = router_with_route_auth(state, test_case_store(), RouteAuthMode::Enforce);

    let nonce = issue_sync_handshake_nonce(&app).await;
    let response = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-acme/manifest",
            sync_peer_headers(&token, &subject, &subject, &nonce),
        ))
        .await
        .expect("manifest response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(response).await;
    assert_eq!(body["reason_class"], "peer_revoked");
}

#[tokio::test]
async fn sync_mutual_auth_rejects_missing_handshake_headers_even_with_admin_scope() {
    let (trust_root, _, _) = sync_test_peer("tenant-acme");
    let app = sync_mutual_auth_app(&trust_root);
    let response = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-acme/manifest",
            dev_scope_headers("admin:read"),
        ))
        .await
        .expect("manifest response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(response).await;
    assert_eq!(body["code"], "SYNC_PEER_AUTH_FAILED");
    assert_eq!(body["reason_class"], "missing_peer_handshake");
}

#[tokio::test]
async fn sync_mutual_auth_rejects_bad_possession_signature() {
    let (trust_root, subject, token) = sync_test_peer("tenant-acme");
    let attacker = SigningKey::from_bytes(&[0x43; 32]);
    let app = sync_mutual_auth_app(&trust_root);
    let nonce = issue_sync_handshake_nonce(&app).await;
    let response = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-acme/manifest",
            sync_peer_headers(&token, &subject, &attacker, &nonce),
        ))
        .await
        .expect("manifest response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(response).await;
    assert_eq!(body["reason_class"], "peer_possession_rejected");
}

#[tokio::test]
async fn sync_mutual_auth_rejects_tenant_mismatch() {
    let (trust_root, subject, token) = sync_test_peer("tenant-acme");
    let app = sync_mutual_auth_app(&trust_root);
    let nonce = issue_sync_handshake_nonce(&app).await;
    let response = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-other/manifest",
            sync_peer_headers(&token, &subject, &subject, &nonce),
        ))
        .await
        .expect("manifest response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = json_body(response).await;
    assert_eq!(body["code"], "SYNC_PEER_TENANT_MISMATCH");
    assert_eq!(body["reason_class"], "peer_tenant_mismatch");
}

#[tokio::test]
async fn sync_mutual_auth_flag_off_preserves_scope_auth_and_hides_nonce() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let app = router_with_route_auth(state, test_case_store(), RouteAuthMode::Enforce);
    let nonce_response = app
        .clone()
        .oneshot(sync_http_request("POST", "/v1/sync/handshake/nonce", HeaderMap::new()))
        .await
        .expect("nonce response");
    assert_eq!(nonce_response.status(), StatusCode::NOT_FOUND);

    let manifest_response = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-acme/manifest",
            dev_scope_headers("facts:read"),
        ))
        .await
        .expect("manifest response");
    assert_eq!(manifest_response.status(), StatusCode::OK);
}

// --- M3′: recipient-bound v1.1 delegation at the sync boundary --------------

/// A CruxEngine-issued sync-delegation base token per the 2026-07-22 convention:
/// `rcx-ct/1.1`, `crux-sync` backend granting `corecrux.sync.pull|push`
/// (attestation `passport_bound`), CruxSync PoP policy allowing `delegate`.
/// Returns `(issuer, subject, delegate, base_token)`.
fn sync_delegation_base_token(
    tenant_id: &str,
) -> (
    SigningKey,
    SigningKey,
    SigningKey,
    rcx_capability_token::RcxCapabilityToken,
) {
    use rcx_capability_token::{
        DataEgressClass, DelegationAudience, DelegationPolicy, DelegationPresentation, PermittedCapability,
        RCX_CT_DELEGATION_SPEC_VERSION, RCX_SYNC_BACKEND_ID, RCX_SYNC_PASSPORT_ATTESTATION, RCX_SYNC_PULL_CAPABILITY,
        RCX_SYNC_PUSH_CAPABILITY,
    };
    let issuer = SigningKey::from_bytes(&[0x41; 32]);
    let subject = SigningKey::from_bytes(&[0x42; 32]);
    let delegate = SigningKey::from_bytes(&[0x43; 32]);
    let issuer_fpr = sync_test_passport_fpr(&issuer.verifying_key().to_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let mut token = rcx_capability_token::free_local_verified_fixture();
    token.spec_version = RCX_CT_DELEGATION_SPEC_VERSION.to_string();
    token.token_id = "rcxct_sync_delegation_http_test".to_string();
    token.issued_at = now.saturating_sub(60);
    token.refresh_hint_at = now.saturating_add(1_800);
    token.expires_at = now.saturating_add(3_600);
    token.subject.passport_fpr = sync_test_passport_fpr(&subject.verifying_key().to_bytes());
    token.tenant_scope.tenant_id = tenant_id.to_string();
    token.issuer.passport_kid.clone_from(&issuer_fpr);
    token.signature.kid.clone_from(&issuer_fpr);
    token.backends[0].backend_id = RCX_SYNC_BACKEND_ID.to_string();
    token.backends[0].trust_root_kid.clone_from(&issuer_fpr);
    token.backends[0].permitted_capabilities = vec![
        PermittedCapability {
            capability: RCX_SYNC_PULL_CAPABILITY.to_string(),
            data_egress_classes: vec![DataEgressClass::None],
            required_attestations: vec![RCX_SYNC_PASSPORT_ATTESTATION.to_string()],
            credit_cost: None,
        },
        PermittedCapability {
            capability: RCX_SYNC_PUSH_CAPABILITY.to_string(),
            data_egress_classes: vec![DataEgressClass::None],
            required_attestations: vec![RCX_SYNC_PASSPORT_ATTESTATION.to_string()],
            credit_cost: None,
        },
    ];
    token.delegation_policy = Some(DelegationPolicy {
        presentation: DelegationPresentation::ProofOfPossession,
        max_depth: 1,
        audience: DelegationAudience::CruxSync,
        allowed_delegate_fprs: vec![sync_test_passport_fpr(&delegate.verifying_key().to_bytes())],
    });
    token.signature.sig = issuer.sign(&token.token_hash()).to_bytes();
    (issuer, subject, delegate, token)
}

fn sync_delegated_token(
    base: &rcx_capability_token::RcxCapabilityToken,
    subject: &SigningKey,
    delegate: &SigningKey,
    caveats: Vec<rcx_capability_token::Caveat>,
) -> rcx_capability_token::RcxCapabilityToken {
    base.attenuate_for(caveats, delegate.verifying_key().to_bytes(), "delegation-1", subject)
        .expect("attenuate_for")
}

/// Recipient (`delegate`) presentation headers: the proof is signed over the
/// exact `AttenuationContext` the sync boundary builds for `(tenant, capability)`.
fn sync_delegation_headers(
    token: &rcx_capability_token::RcxCapabilityToken,
    delegate: &SigningKey,
    nonce: &[u8],
    tenant_id: &str,
    capability: &str,
) -> HeaderMap {
    use rcx_capability_token::{
        presentation_proof_message, AttenuationContext, DelegationAudience, RCX_SYNC_BACKEND_ID,
        RCX_SYNC_PASSPORT_ATTESTATION,
    };
    let attestations = [RCX_SYNC_PASSPORT_ATTESTATION];
    let context = AttenuationContext {
        audience: DelegationAudience::CruxSync,
        tenant_id,
        backend_id: RCX_SYNC_BACKEND_ID,
        capability,
        data_egress_classes: &[],
        present_attestations: &attestations,
    };
    let signature = delegate
        .sign(&presentation_proof_message(token, context, nonce))
        .to_bytes();
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-crux-peer-token",
        HeaderValue::from_str(&base64::engine::general_purpose::STANDARD.encode(token.to_canonical_json().as_bytes()))
            .expect("peer token header"),
    );
    headers.insert(
        "x-crux-peer-pubkey",
        HeaderValue::from_str(&hex::encode(delegate.verifying_key().to_bytes())).expect("peer public key header"),
    );
    headers.insert(
        "x-crux-peer-nonce",
        HeaderValue::from_str(&hex::encode(nonce)).expect("peer nonce header"),
    );
    headers.insert(
        "x-crux-peer-sig",
        HeaderValue::from_str(&hex::encode(signature)).expect("peer signature header"),
    );
    headers
}

fn sync_delegation_app(trust_root: &SigningKey) -> Router {
    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    state.sync_mutual_auth = true;
    state.sync_peer_trust_root = Some(trust_root.verifying_key().to_bytes().to_vec());
    state.sync_delegation_enforce = true;
    router_with_route_auth(state, test_case_store(), RouteAuthMode::Enforce)
}

fn sync_far_future_expiry() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
        .saturating_add(1_800)
}

#[tokio::test]
async fn sync_delegation_accepts_valid_recipient_for_bound_tenant() {
    use rcx_capability_token::Caveat;
    let (issuer, subject, delegate, base) = sync_delegation_base_token("tenant-acme");
    let token = sync_delegated_token(
        &base,
        &subject,
        &delegate,
        vec![
            Caveat::TenantIdEq {
                tenant_id: "tenant-acme".to_string(),
            },
            Caveat::ExpiresAtLe {
                expires_at: sync_far_future_expiry(),
            },
        ],
    );
    let app = sync_delegation_app(&issuer);
    let nonce = issue_sync_handshake_nonce(&app).await;
    let response = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-acme/manifest",
            sync_delegation_headers(&token, &delegate, &nonce, "tenant-acme", "corecrux.sync.pull"),
        ))
        .await
        .expect("manifest response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn sync_delegation_flag_off_rejects_contextual_token_fail_closed() {
    use rcx_capability_token::Caveat;
    let (issuer, subject, delegate, base) = sync_delegation_base_token("tenant-acme");
    let token = sync_delegated_token(
        &base,
        &subject,
        &delegate,
        vec![
            Caveat::TenantIdEq {
                tenant_id: "tenant-acme".to_string(),
            },
            Caveat::ExpiresAtLe {
                expires_at: sync_far_future_expiry(),
            },
        ],
    );
    // sync_mutual_auth_app leaves sync_delegation_enforce OFF.
    let app = sync_mutual_auth_app(&issuer);
    let nonce = issue_sync_handshake_nonce(&app).await;
    let response = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-acme/manifest",
            sync_delegation_headers(&token, &delegate, &nonce, "tenant-acme", "corecrux.sync.pull"),
        ))
        .await
        .expect("manifest response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["reason_class"], "peer_delegation_disabled");
}

#[tokio::test]
async fn sync_delegation_rejects_request_for_other_tenant() {
    use rcx_capability_token::Caveat;
    let (issuer, subject, delegate, base) = sync_delegation_base_token("tenant-acme");
    let token = sync_delegated_token(
        &base,
        &subject,
        &delegate,
        vec![
            Caveat::TenantIdEq {
                tenant_id: "tenant-acme".to_string(),
            },
            Caveat::ExpiresAtLe {
                expires_at: sync_far_future_expiry(),
            },
        ],
    );
    let app = sync_delegation_app(&issuer);
    let nonce = issue_sync_handshake_nonce(&app).await;
    let response = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-other/manifest",
            sync_delegation_headers(&token, &delegate, &nonce, "tenant-other", "corecrux.sync.pull"),
        ))
        .await
        .expect("manifest response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["reason_class"], "peer_context_denied");
}

#[tokio::test]
async fn sync_delegation_rejects_expired_caveat() {
    use rcx_capability_token::Caveat;
    let (issuer, subject, delegate, base) = sync_delegation_base_token("tenant-acme");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let token = sync_delegated_token(
        &base,
        &subject,
        &delegate,
        vec![Caveat::ExpiresAtLe {
            expires_at: now.saturating_sub(1),
        }],
    );
    let app = sync_delegation_app(&issuer);
    let nonce = issue_sync_handshake_nonce(&app).await;
    let response = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-acme/manifest",
            sync_delegation_headers(&token, &delegate, &nonce, "tenant-acme", "corecrux.sync.pull"),
        ))
        .await
        .expect("manifest response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["reason_class"], "peer_caveat_denied");
}

#[tokio::test]
async fn sync_delegation_rejects_scope_subset_excluding_the_request() {
    use rcx_capability_token::Caveat;
    let (issuer, subject, delegate, base) = sync_delegation_base_token("tenant-acme");
    // Narrow to push only, then request a pull (manifest read).
    let token = sync_delegated_token(
        &base,
        &subject,
        &delegate,
        vec![Caveat::ScopeSubset {
            scopes: vec!["corecrux.sync.push".to_string()],
        }],
    );
    let app = sync_delegation_app(&issuer);
    let nonce = issue_sync_handshake_nonce(&app).await;
    let response = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-acme/manifest",
            sync_delegation_headers(&token, &delegate, &nonce, "tenant-acme", "corecrux.sync.pull"),
        ))
        .await
        .expect("manifest response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["reason_class"], "peer_caveat_denied");
}

#[tokio::test]
async fn sync_delegation_rejects_unissued_nonce() {
    use rcx_capability_token::Caveat;
    let (issuer, subject, delegate, base) = sync_delegation_base_token("tenant-acme");
    let token = sync_delegated_token(
        &base,
        &subject,
        &delegate,
        vec![
            Caveat::TenantIdEq {
                tenant_id: "tenant-acme".to_string(),
            },
            Caveat::ExpiresAtLe {
                expires_at: sync_far_future_expiry(),
            },
        ],
    );
    let app = sync_delegation_app(&issuer);
    // Never issued by the server.
    let nonce = [0x5a_u8; 32].to_vec();
    let response = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-acme/manifest",
            sync_delegation_headers(&token, &delegate, &nonce, "tenant-acme", "corecrux.sync.pull"),
        ))
        .await
        .expect("manifest response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["reason_class"], "peer_nonce_rejected");
}

#[tokio::test]
async fn sync_delegation_denies_replayed_nonce() {
    use rcx_capability_token::Caveat;
    let (issuer, subject, delegate, base) = sync_delegation_base_token("tenant-acme");
    let token = sync_delegated_token(
        &base,
        &subject,
        &delegate,
        vec![
            Caveat::TenantIdEq {
                tenant_id: "tenant-acme".to_string(),
            },
            Caveat::ExpiresAtLe {
                expires_at: sync_far_future_expiry(),
            },
        ],
    );
    let app = sync_delegation_app(&issuer);
    let nonce = issue_sync_handshake_nonce(&app).await;

    let first = app
        .clone()
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-acme/manifest",
            sync_delegation_headers(&token, &delegate, &nonce, "tenant-acme", "corecrux.sync.pull"),
        ))
        .await
        .expect("first manifest response");
    assert_eq!(first.status(), StatusCode::OK);

    // Second presentation of the same (now consumed) nonce fails closed.
    let second = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-acme/manifest",
            sync_delegation_headers(&token, &delegate, &nonce, "tenant-acme", "corecrux.sync.pull"),
        ))
        .await
        .expect("second manifest response");
    assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(second).await["reason_class"], "peer_nonce_rejected");
}

#[tokio::test]
async fn sync_delegation_enforce_on_leaves_v1_peer_unchanged() {
    // A plain v1.0 (non-contextual) peer token keeps working through the
    // existing path, with delegation enforcement ON.
    let (trust_root, subject, token) = sync_test_peer("tenant-acme");
    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    state.sync_mutual_auth = true;
    state.sync_peer_trust_root = Some(trust_root.verifying_key().to_bytes().to_vec());
    state.sync_delegation_enforce = true;
    let app = router_with_route_auth(state, test_case_store(), RouteAuthMode::Enforce);
    let nonce = issue_sync_handshake_nonce(&app).await;
    let response = app
        .oneshot(sync_http_request(
            "GET",
            "/v1/sync/tenants/tenant-acme/manifest",
            sync_peer_headers(&token, &subject, &subject, &nonce),
        ))
        .await
        .expect("manifest response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn sync_manifest_and_collection_page_are_tenant_scoped() {
    let state = test_app_state(1);
    {
        let mut store = state.fact_store.write().await;
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "business::acme::note".to_string(),
            key: "summary".to_string(),
            value: "shared tenant fact".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "business::other::note".to_string(),
            key: "summary".to_string(),
            value: "other tenant fact".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
    }

    let manifest = super::sync::get_tenant_manifest(
        State(state.clone()),
        HeaderMap::new(),
        Path("business::acme".to_string()),
        Query(super::sync::ManifestQuery {
            tenant_category: None,
            owner_id: Some("owner-a".to_string()),
            membership_epoch: Some(2),
            role_grants: Some("reader,writer".to_string()),
        }),
    )
    .await;
    assert_eq!(manifest.status(), StatusCode::OK);
    let body = json_body(manifest).await;
    assert_eq!(body["tenant_category"], "business");
    assert_eq!(body["membership_epoch"], 2);

    let page = super::sync::get_tenant_collection(
        State(state),
        HeaderMap::new(),
        Path(("business::acme".to_string(), "facts".to_string())),
        Query(super::sync::CollectionQuery {
            cursor: None,
            limit: Some(10),
            include_content: true,
        }),
    )
    .await;
    assert_eq!(page.status(), StatusCode::OK);
    let body = json_body(page).await;
    assert_eq!(body["records"].as_array().unwrap().len(), 1);
    assert_eq!(body["records"][0]["entity"], "business::acme::note");
    assert!(body["records"][0]["fact"].is_object());
}

#[tokio::test]
async fn sync_promotion_preview_respects_allowlist() {
    let state = test_app_state(1);
    {
        let mut store = state.fact_store.write().await;
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "business::acme::note".to_string(),
            key: "summary".to_string(),
            value: "promote".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "business::acme::constraint::deploy".to_string(),
            key: "constraint".to_string(),
            value: "skip by allowlist".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
    }

    let resp = super::sync::post_promotion_preview(
        State(state),
        HeaderMap::new(),
        Path("business::acme".to_string()),
        Json(super::sync::PromotionRequest {
            allowlist: vec!["facts".to_string()],
            include_content: false,
            confirm_hash: None,
            records: Vec::new(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["promote_count"], 1);
    assert_eq!(body["skipped_not_allowlisted"], 1);
    assert!(body["preview_hash"].as_str().unwrap().starts_with("blake3:"));
}

#[tokio::test]
async fn sync_promotion_confirm_applies_remote_records() {
    let state = test_app_state(1);
    let fact = corecrux_memory::fact_store::Fact {
        fact_id: "f_promoted_remote".to_string(),
        tenant_hash: "default".to_string(),
        entity: "business::acme::note".to_string(),
        key: "summary".to_string(),
        value: "cloud promoted".to_string(),
        source_receipt: None,
        confidence: 1.0,
        stored_at: chrono::Utc::now(),
        tokens: 2,
        deleted: false,
        version: 1,
        supersedes: None,
        private: false,
        horizon_class: corecrux_memory::HorizonClass::None,
        reverified_at: None,
        superseded_by: None,
        actor: None,
        valid_from: None,
        valid_to: None,
        access_count: 0,
        last_accessed_at: None,
    };
    let record = corecrux_memory::sync::SyncCollectionRecord {
        collection: "facts".to_string(),
        record_id: fact.fact_id.clone(),
        entity: fact.entity.clone(),
        key: fact.key.clone(),
        identity_hash: "blake3:identity".to_string(),
        content_hash: "blake3:content".to_string(),
        value_hash: "blake3:test".to_string(),
        updated_at: fact.stored_at.to_rfc3339(),
        deleted: false,
        source_receipt: None,
        semantic_profile_id: None,
        local_semantic_profile_id: None,
        fact: Some(fact),
    };

    let resp = super::sync::post_promotion_confirm(
        State(state.clone()),
        HeaderMap::new(),
        Path("business::acme".to_string()),
        Json(super::sync::PromotionRequest {
            allowlist: Vec::new(),
            include_content: false,
            confirm_hash: None,
            records: vec![record],
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["applied_count"], 1);
    let store = state.fact_store.read().await;
    let stored = store.get("f_promoted_remote").expect("promoted fact");
    assert!(stored
        .source_receipt
        .as_deref()
        .unwrap()
        .starts_with("sync-promotion:http:node-a:"));
}

#[tokio::test]
async fn sync_offboard_signs_wipe_receipt_and_stores_proof() {
    let mut state = test_app_state(1);
    bind_test_state_to_root_passport_key(&mut state);
    {
        let mut store = state.fact_store.write().await;
        store.store_synced(corecrux_memory::fact_store::Fact {
            fact_id: "f_acme_mirror".to_string(),
            tenant_hash: "default".to_string(),
            entity: "business::acme::remote".to_string(),
            key: "summary".to_string(),
            value: "mirrored".to_string(),
            source_receipt: Some("sync:http://cloud:f_acme_mirror".to_string()),
            confidence: 1.0,
            stored_at: chrono::Utc::now(),
            tokens: 1,
            deleted: false,
            version: 1,
            supersedes: None,
            private: false,
            horizon_class: corecrux_memory::HorizonClass::None,
            reverified_at: None,
            superseded_by: None,
            actor: None,
            valid_from: None,
            valid_to: None,
            access_count: 0,
            last_accessed_at: None,
        });
    }

    let resp = super::sync::post_tenant_offboard(
        State(state.clone()),
        HeaderMap::new(),
        Path("business::acme".to_string()),
        Json(super::sync::OffboardRequest { membership_epoch: 5 }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["membership_epoch"], 5);
    assert_eq!(body["signed_by"], state.passport_fpr);
    assert_eq!(body["signature"].as_str().unwrap().len(), 128);
    assert_eq!(body["deleted_fact_ids"][0], "f_acme_mirror");

    let receipt_entity = "__sync_wipe_receipt__::business::acme";
    let store = state.fact_store.read().await;
    assert!(store.get("f_acme_mirror").is_none());
    assert_eq!(store.get_by_entity(receipt_entity).len(), 1);
    assert!(store.get_by_entity(receipt_entity)[0].private);
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

pub(crate) fn test_app_state_with_auth(action_max_pending: usize, auth_mode: AuthMode) -> AppState {
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
        rcx_router: None,
        data_dir: root.clone(),
        sync_mutual_auth: false,
        sync_peer_trust_root: None,
        sync_delegation_enforce: false,
        sync_handshake_nonces: Arc::new(std::sync::Mutex::new(crux_sync::peer_handshake::NonceCache::new(
            SYNC_HANDSHAKE_NONCE_TTL_SECONDS,
        ))),
        witness: crate::witness::WitnessRuntimeConfigV1::disabled(),
        witness_proofs: std::sync::Arc::new(tokio::sync::RwLock::new(
            crate::witness_proofs::WitnessProofStore::default(),
        )),
        cloud_witness_replay_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        mcp_enabled: true,
        console_enabled: true,
        passport_mint_requests_enabled: false,
        coord_enabled: true,
        coord_presence_ttl_secs: crate::coord::DEFAULT_PRESENCE_TTL_SECS,
        consolidation_scheduler_enabled: false,
        context_surface_enabled: true,
        compute_provider_enabled: false,
        auto_capture_enabled: true,
        local_ingest_enabled: false,
        stream_receipts_enabled: false,
        usage_receipts_enabled: false,
        handoff_observations_enabled: false,
        usage_submit: crate::usage_submit::UsageSubmitConfig::default(),
        latest_release: Arc::new(std::sync::RwLock::new(None)),
        quota_enabled: false,
        assembly_cache: None,
        quota_hosted_surfaces: Arc::new(Vec::new()),
        quota_ledger: Arc::new(std::sync::Mutex::new(crux_router::quota::QuotaLedger::new())),
        credit_meter: None,
        openai_shim_enabled: false,
        memory_import_enabled: true,
        identity_links_enabled: true,
        mcp_context: None,
        integrations_enabled: true,
        integrations_safe_mode: false,
        integrations_allow_executable_helpers: false,
        operating_mode: crate::product::OperatingMode::FreeLocal,
        enabled_pro_services: Vec::new(),
        read_retry_failed_readyz_threshold: 0,
        commit_level: CommitLevel::LocalCommit,
        metrics,
        node_id: "node-a".to_string(),
        passport_key_path: root.join("passport.key"),
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
        repo_scan_max_pending: 32,
        scrub_scope: "recent".to_string(),
        scrub_mode: "sampled".to_string(),
        scrub_sample_rate: 0.25,
        admin_actions: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
        repo_scan_jobs: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
        repo_scan_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
        corruption_detected: Arc::new(RwLock::new(false)),
        admin_force_seal_enabled: false,
        local_ingest_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        retention_days: None,
        retrieval_index: Arc::new(RwLock::new(corecrux_retrieval::IndexManager::new())),
        fact_store: Arc::new(RwLock::new(corecrux_memory::FactStore::new())),
        repo_watch: None,
        extension_rate_table: Arc::new(crate::extension_outbound::RateTable::new()),
        #[cfg(feature = "wasm-extensions")]
        wasm_engine: None,
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
        onboarding: Arc::new(RwLock::new(crate::onboarding::OnboardingState::default())),
        http_bind_loopback: true,
        allow_insecure_dev_auth_bind: false,
        projection_state: Arc::new(RwLock::new(corecrux_projections::ProjectionState::default())),
        integration_encryption_key: Arc::new([0u8; 32]),
        presence: crate::presence::PresenceTracker::new(),
        privacy_policy: crate::fact_privacy::PrivacyPolicy::from_env(),
        entity_store: Arc::new(RwLock::new(corecrux_memory::EntityStore::new())),
        edge_store: Arc::new(RwLock::new(corecrux_memory::EdgeStore::new())),
        kind_registry: Arc::new(RwLock::new(corecrux_memory::KindRegistry::new())),
        artefact_store: Arc::new(RwLock::new(corecrux_memory::ArtefactStore::new())),
    }
}

pub(super) fn test_app_state(action_max_pending: usize) -> AppState {
    test_app_state_with_auth(action_max_pending, AuthMode::Off)
}

/// Fresh in-memory case store for `router(state, …)` test calls (M3).
fn test_case_store() -> std::sync::Arc<tokio::sync::RwLock<corecrux_memory::CaseStore>> {
    std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_memory::CaseStore::new()))
}

fn pro_workbench_state(services: &[&str]) -> AppState {
    let mut state = test_app_state(16);
    state.operating_mode = crate::product::OperatingMode::ProHybrid;
    state.enabled_pro_services = services.iter().map(|service| (*service).to_string()).collect();
    state
}

fn bind_test_state_to_root_passport_key(state: &mut AppState) {
    let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).expect("root passport key");
    state.passport_fpr = key.passport_fpr().to_string();
    state.passport_public_key_hex = key.public_key_hex().to_string();
}

fn test_rcx_router(capabilities: Vec<&str>) -> std::sync::Arc<crux_router::RcxRouter> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let signing = SigningKey::from_bytes(&[0x44; 32]);
    let mut token = crux_router::mint_free_local_token(
        "p_0123456789abcdef0123456789abcdef",
        "daemon_01HV0000000000000000000000",
        "default",
        capabilities.into_iter().map(str::to_string).collect(),
        now.saturating_sub(60),
        now.saturating_add(3600),
        [0x22; 64],
    );
    token.signature.sig = signing.sign(&token.token_hash()).to_bytes();
    std::sync::Arc::new(crux_router::RcxRouter::new_with_trusted_issuer_pubkey(
        token,
        signing.verifying_key().to_bytes(),
    ))
}

fn dev_scope_headers(scopes: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-corecrux-scopes",
        HeaderValue::from_str(scopes).expect("valid test scope header"),
    );
    headers
}

fn dev_scope_passport_headers(scopes: &str, passport_id: &str) -> HeaderMap {
    let mut headers = dev_scope_headers(scopes);
    headers.insert(
        "x-corecrux-passport-id",
        HeaderValue::from_str(passport_id).expect("valid test passport header"),
    );
    headers
}

async fn json_body(resp: Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
    serde_json::from_slice(&bytes).expect("json body")
}

#[tokio::test]
async fn witness_smoke_route_reports_default_off_ok() {
    let state = test_app_state(1);
    let response = super::witness::get_witness_smoke(State(state)).await.into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["mode"], "local_config_only");
    assert_eq!(body["witness"]["enabled"], false);
    assert_eq!(body["tsa"]["enabled"], false);
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
async fn admin_restart_requires_admin_write() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    let missing = admin::post_restart_daemon(State(state.clone()), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let read_only = admin::post_restart_daemon(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(read_only.status(), StatusCode::FORBIDDEN);
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

// ── Mediation-plane hardening (B4: T.1 cross-tenant / T.3 unauth) ──────────

async fn seed_default_passports(state: &AppState) {
    let mut store = state.fact_store.write().await;
    crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed passports");
}

fn resolve_query(passport_id: &str) -> axum::extract::Query<principal::ResolvePrincipalQuery> {
    axum::extract::Query(principal::ResolvePrincipalQuery {
        session_id: None,
        passport_id: Some(passport_id.to_string()),
        include_candidates: None,
    })
}

fn resolve_query_with_candidates(passport_id: &str) -> axum::extract::Query<principal::ResolvePrincipalQuery> {
    axum::extract::Query(principal::ResolvePrincipalQuery {
        session_id: None,
        passport_id: Some(passport_id.to_string()),
        include_candidates: Some("1".to_string()),
    })
}

#[tokio::test]
async fn resolve_principal_unauthenticated_denied_t3() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    seed_default_passports(&state).await;
    // No credentials → 401 (T.3 anonymous denied).
    let resp = principal::get_resolve_principal(
        State(state.clone()),
        resolve_query("personal-default"),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn resolve_principal_insufficient_scope_denied() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    seed_default_passports(&state).await;
    // Authenticated but lacks sessions:read / admin:read → 403 at the tenant guard.
    let resp = principal::get_resolve_principal(
        State(state.clone()),
        resolve_query("personal-default"),
        dev_scope_headers("facts:read"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mediation_receipt_unauthenticated_denied_t3() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = observations::post_mediation_receipt(
        State(state.clone()),
        HeaderMap::new(),
        Json(serde_json::json!({
            "passport_id": "personal-default",
            "tool_server": "openclaw",
            "tool": "openclaw_status",
            "decision": "allow",
            "outcome": "ok",
        })),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial_test::serial]
async fn resolve_principal_cross_tenant_denied_t1() {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    const TEST_HS256_SECRET: &str = "0123456789abcdef0123456789abcdef";

    std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
    std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
    std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");

    let state = test_app_state_with_auth(16, AuthMode::JwtHs256);
    seed_default_passports(&state).await;

    #[derive(serde::Serialize)]
    struct Claims<'a> {
        exp: usize,
        iss: &'a str,
        aud: &'a str,
        scope: &'a str,
        tenant_id: &'a str,
    }
    let bearer_for = |tenant: &str| {
        let claims = Claims {
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as usize,
            iss: "corecrux-test",
            aud: "corecrux",
            scope: "sessions:read",
            tenant_id: tenant,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
        )
        .expect("jwt");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    };

    // `personal-default` resolves to tenant "personal". A token scoped to a
    // different tenant must be denied (T.1 — no cross-tenant resolution).
    let denied = principal::get_resolve_principal(
        State(state.clone()),
        resolve_query("personal-default"),
        bearer_for("work::other"),
    )
    .await
    .into_response();
    assert_eq!(
        denied.status(),
        StatusCode::FORBIDDEN,
        "cross-tenant resolve must be denied"
    );

    // Same passport, token scoped to its own tenant → allowed (positive control).
    let ok = principal::get_resolve_principal(
        State(state.clone()),
        resolve_query("personal-default"),
        bearer_for("personal"),
    )
    .await
    .into_response();
    assert_eq!(ok.status(), StatusCode::OK, "same-tenant resolve must succeed");

    std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
    std::env::remove_var("CORECRUXD_JWT_ISS");
    std::env::remove_var("CORECRUXD_JWT_AUD");
}

#[tokio::test]
#[serial_test::serial]
async fn tenant_write_stamp_isolates_reads_end_to_end_m1() {
    // OD-37 / audit-v2 closeout M1: a write authorized for tenant A stamps
    // tenant_hash == A; a reader in tenant A sees it, a reader in tenant B does not.
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    const TEST_HS256_SECRET: &str = "0123456789abcdef0123456789abcdef";

    std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
    std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
    std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");
    std::env::set_var("CORECRUXD_TENANT_WRITE_STAMP", "1");

    let state = test_app_state_with_auth(16, AuthMode::JwtHs256);

    #[derive(serde::Serialize)]
    struct Claims<'a> {
        exp: usize,
        iss: &'a str,
        aud: &'a str,
        scope: &'a str,
        tenant_id: &'a str,
    }
    let bearer = |scope: &str, tenant: &str| {
        let claims = Claims {
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as usize,
            iss: "corecrux-test",
            aud: "corecrux",
            scope,
            tenant_id: tenant,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
        )
        .expect("jwt");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    };

    let entity = "tenant-iso-m1-widget";
    let body: corecrux_memory::fact_store::StoreFact =
        serde_json::from_value(serde_json::json!({ "entity": entity, "key": "k", "value": "v" })).unwrap();

    // Write authorized for tenant A → stamps tenant-a.
    let resp = facts::put_fact(State(state.clone()), bearer("facts:write", "tenant-a"), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED, "authorized write must succeed");
    let bytes = to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
    let stored: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(stored["tenant_hash"], "tenant-a", "write must stamp the token's tenant");

    // Reader in tenant A sees it.
    let resp_a = facts::get_facts_by_entity(
        State(state.clone()),
        bearer("query:read", "tenant-a"),
        Path(entity.to_string()),
    )
    .await
    .into_response();
    assert_eq!(resp_a.status(), StatusCode::OK);
    let a: serde_json::Value = serde_json::from_slice(&to_bytes(resp_a.into_body(), 1_048_576).await.unwrap()).unwrap();
    assert_eq!(
        a["facts"].as_array().unwrap().len(),
        1,
        "same-tenant reader must see the fact"
    );

    // Reader in tenant B must NOT see it (T.1 cross-tenant read).
    let resp_b = facts::get_facts_by_entity(
        State(state.clone()),
        bearer("query:read", "tenant-b"),
        Path(entity.to_string()),
    )
    .await
    .into_response();
    assert_eq!(resp_b.status(), StatusCode::OK);
    let b: serde_json::Value = serde_json::from_slice(&to_bytes(resp_b.into_body(), 1_048_576).await.unwrap()).unwrap();
    assert_eq!(
        b["facts"].as_array().unwrap().len(),
        0,
        "cross-tenant reader must NOT see the fact"
    );

    std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
    std::env::remove_var("CORECRUXD_JWT_ISS");
    std::env::remove_var("CORECRUXD_JWT_AUD");
    std::env::remove_var("CORECRUXD_TENANT_WRITE_STAMP");
}

#[tokio::test]
async fn console_redacts_private_facts_and_session_state() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut facts = state.fact_store.write().await;
        facts.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "tenant-a::service".to_string(),
            key: "public".to_string(),
            value: "safe value".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        facts.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "tenant-a::service".to_string(),
            key: "api_key".to_string(),
            value: "secret-token-123".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
    }
    state.session_store.write().await.put(
        "sess-secret",
        serde_json::json!({"token": "secret-session-token"}),
        None,
    );

    let facts_resp = console::get_console_facts(
        State(state.clone()),
        Query(console::ConsoleFactsQuery {
            q: None,
            top_k: None,
            as_of_unix_ms: None,
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(facts_resp.status(), StatusCode::OK);
    let facts_body = json_body(facts_resp).await;
    assert_eq!(facts_body["private_facts_hidden"], true);
    assert_eq!(facts_body["visible_count"], 1);
    let facts_text = serde_json::to_string(&facts_body).expect("facts json");
    assert!(!facts_text.contains("secret-token-123"));

    let sessions_resp = console::get_console_sessions(
        State(state),
        dev_scope_headers("admin:read"),
        axum::extract::Query(console::ConsoleSessionsQuery {
            include_archived: false,
        }),
    )
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
async fn console_sessions_friendly_titles_and_archive_filter() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    // A scoped session (agent-prefixed) and a plain one.
    let scoped = "__agent_session::anthropic::demo-memoryhook:mh-p0";
    state
        .session_store
        .write()
        .await
        .put(scoped, serde_json::json!({"v": 1}), None);
    state
        .session_store
        .write()
        .await
        .put("plain-session", serde_json::json!({"v": 2}), None);

    let fetch = |st: AppState, include: bool| async move {
        let resp = console::get_console_sessions(
            State(st),
            dev_scope_headers("admin:read"),
            axum::extract::Query(console::ConsoleSessionsQuery {
                include_archived: include,
            }),
        )
        .await
        .into_response();
        json_body(resp).await
    };

    // Friendly title strips the `__agent_session::<agent>::` prefix; agent surfaced separately.
    let body = fetch(state.clone(), false).await;
    let rows = body["session_rows"].as_array().expect("rows");
    let demo = rows
        .iter()
        .find(|r| r["raw_key"] == scoped)
        .expect("scoped row present");
    assert_eq!(demo["session_id"], "demo-memoryhook:mh-p0");
    assert_eq!(demo["agent"], "anthropic");
    assert_eq!(demo["archived"], false);

    // Archive it via the HTTP endpoint (raw admin:write → raw key).
    let arch = super::facts::archive_session(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        axum::extract::Path(scoped.to_string()),
        None,
    )
    .await
    .into_response();
    assert_eq!(arch.status(), StatusCode::OK);

    // Hidden from the default listing...
    let body = fetch(state.clone(), false).await;
    assert!(
        !body["session_rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["raw_key"] == scoped),
        "archived session must be hidden by default"
    );
    assert_eq!(body["archived_count"], 1);
    // ...but present with include_archived=true.
    let body = fetch(state.clone(), true).await;
    let demo = body["session_rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["raw_key"] == scoped)
        .expect("archived row visible with include_archived");
    assert_eq!(demo["archived"], true);

    // Unarchive restores it to the default listing.
    let un = super::facts::unarchive_session(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        axum::extract::Path(scoped.to_string()),
    )
    .await
    .into_response();
    assert_eq!(un.status(), StatusCode::OK);
    let body = fetch(state.clone(), false).await;
    assert!(
        body["session_rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["raw_key"] == scoped),
        "unarchived session must reappear in the default listing"
    );
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
        tenant_hash: "client-supplied-must-be-ignored".to_string(),
        entity: "server".to_string(),
        key: "role".to_string(),
        value: "database primary".to_string(),
        source_receipt: Some("crx_abc".to_string()),
        confidence: 0.95,
        private: false,
        horizon_class: None,
        actor: None,
    };

    let resp = facts::put_fact(State(state), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert!(body["fact_id"].as_str().unwrap().starts_with("f_"));
    assert_eq!(body["tenant_hash"], "default");
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
        tenant_hash: "default".to_string(),
        entity: "server".to_string(),
        key: "internal".to_string(),
        value: "secret".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
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
            tenant_hash: "default".to_string(),
            entity: "server".to_string(),
            key: "role".to_string(),
            value: "primary".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        },
        corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "server".to_string(),
            key: "internal".to_string(),
            value: "secret".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
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

#[tokio::test]
async fn put_fact_forces_reserved_prefix_private_before_store() {
    let state = test_app_state(16);
    let body = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: "__ops__::deploy".to_string(),
        key: "status".to_string(),
        value: "ready".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };

    let resp = facts::put_fact(State(state.clone()), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let store = state.fact_store.read().await;
    let fact = store.all_facts().find(|fact| fact.entity == "__ops__::deploy").unwrap();
    assert!(fact.private);
}

#[tokio::test]
async fn put_facts_bulk_forces_reserved_prefix_private_before_store() {
    let state = test_app_state(16);
    let body = vec![
        corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__bootstrap__::patterns".to_string(),
            key: "p1".to_string(),
            value: "pattern".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        },
        corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "public".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        },
    ];

    let resp = facts::put_facts_bulk(State(state.clone()), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let store = state.fact_store.read().await;
    let reserved = store
        .all_facts()
        .find(|fact| fact.entity == "__bootstrap__::patterns")
        .unwrap();
    assert!(reserved.private);
    let public = store.all_facts().find(|fact| fact.entity == "public").unwrap();
    assert!(!public.private);
}

#[tokio::test]
async fn put_fact_passport_rejects_daemon_owned_entity_prefix() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let body = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "client-supplied-must-be-ignored".to_string(),
        entity: "__legal_hold__::hold-1".to_string(),
        key: "state".to_string(),
        value: "attacker".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };

    let resp = facts::put_fact(
        State(state.clone()),
        dev_scope_passport_headers("facts:write", "work-default"),
        Json(body),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = json_body(resp).await;
    assert_eq!(body["code"], "RESERVED_ENTITY_PREFIX");
    assert_eq!(body["reserved_prefix"], "__legal_hold__::");
    assert!(state
        .fact_store
        .read()
        .await
        .get_by_entity("__legal_hold__::hold-1")
        .is_empty());
}

#[tokio::test]
async fn put_facts_bulk_rejects_daemon_owned_entity_prefix_atomically() {
    let state = test_app_state(16);
    let body = vec![
        corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "public".to_string(),
            key: "safe".to_string(),
            value: "must-not-partially-store".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        },
        corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__incident__::incident-1".to_string(),
            key: "state".to_string(),
            value: "attacker".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        },
    ];

    let resp = facts::put_facts_bulk(State(state.clone()), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = json_body(resp).await;
    assert_eq!(body["code"], "RESERVED_ENTITY_PREFIX");
    assert_eq!(body["reserved_prefix"], "__incident__::");
    assert_eq!(state.fact_store.read().await.all_facts().count(), 0);
}

// ── Fact Store (GET /v1/facts/{factId}) ─────────────────────────

#[tokio::test]
async fn get_fact_returns_stored_fact() {
    let state = test_app_state(16);
    let body = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: "deploy".to_string(),
        key: "strategy".to_string(),
        value: "canary".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
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
        tenant_hash: "default".to_string(),
        entity: "e".to_string(),
        key: "k".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
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
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
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
            tenant_hash: "client-tenant-a".to_string(),
            entity: "a".to_string(),
            key: "k1".to_string(),
            value: "v1".to_string(),
            source_receipt: None,
            confidence: 0.8,
            private: false,
            horizon_class: None,
            actor: None,
        },
        corecrux_memory::fact_store::StoreFact {
            tenant_hash: "client-tenant-b".to_string(),
            entity: "b".to_string(),
            key: "k2".to_string(),
            value: "v2".to_string(),
            source_receipt: Some("rcpt".to_string()),
            confidence: 0.9,
            private: false,
            horizon_class: None,
            actor: None,
        },
    ];

    let resp = facts::put_facts_bulk(State(state.clone()), HeaderMap::new(), Json(facts))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    let stored = body["facts"].as_array().expect("facts array");
    assert_eq!(stored.len(), 2);
    assert!(stored.iter().all(|fact| fact["tenant_hash"] == "default"));
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
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };
        let _ = facts::put_fact(State(state.clone()), HeaderMap::new(), Json(body))
            .await
            .into_response();
    }

    let params = QueryFactsParams {
        min_effective_confidence: None,
        query: Some("canary".to_string()),
        entity: None,
        entity_prefix: None,
        top_k: None,
        token_budget: None,
        as_of: None,
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
async fn query_facts_as_of_filters_world_time() {
    let state = test_app_state(16);
    let ts = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    for value in ["London", "Berlin"] {
        let body = corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "person:zoe".to_string(),
            key: "city".to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };
        let _ = facts::put_fact(State(state.clone()), HeaderMap::new(), Json(body))
            .await
            .into_response();
    }
    {
        let mut store = state.fact_store.write().await;
        let entries: Vec<(String, String)> = store
            .get_by_entity("person:zoe")
            .into_iter()
            .map(|f| (f.fact_id.clone(), f.value.clone()))
            .collect();
        for (id, value) in entries {
            if value == "London" {
                store.set_validity(&id, Some(ts("2026-01-01T00:00:00Z")), Some(ts("2026-06-01T00:00:00Z")));
            } else {
                store.set_validity(&id, Some(ts("2026-06-01T00:00:00Z")), None);
            }
        }
    }

    let params = QueryFactsParams {
        min_effective_confidence: None,
        query: None,
        entity: Some("person:zoe".to_string()),
        entity_prefix: None,
        top_k: Some(10),
        token_budget: None,
        as_of: Some("2026-03-01T00:00:00Z".to_string()),
    };
    let resp = facts::query_facts(State(state.clone()), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let values: Vec<String> = body["facts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["value"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        values.contains(&"London".to_string()),
        "as-of March → London, got {values:?}"
    );
    assert!(
        !values.contains(&"Berlin".to_string()),
        "as-of March must exclude Berlin"
    );

    // A bad (unparseable) as_of → 400.
    let bad = QueryFactsParams {
        min_effective_confidence: None,
        query: None,
        entity: None,
        entity_prefix: None,
        top_k: None,
        token_budget: None,
        as_of: Some("nope".to_string()),
    };
    let resp = facts::query_facts(State(state), HeaderMap::new(), Query(bad))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn query_facts_no_params_returns_all() {
    let state = test_app_state(16);
    for i in 0..3 {
        let body = corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: format!("e{}", i),
            key: "k".to_string(),
            value: format!("val{}", i),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };
        let _ = facts::put_fact(State(state.clone()), HeaderMap::new(), Json(body))
            .await
            .into_response();
    }

    let params = QueryFactsParams {
        min_effective_confidence: None,
        query: None,
        entity: None,
        entity_prefix: None,
        top_k: None,
        token_budget: None,
        as_of: None,
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
async fn query_facts_min_effective_confidence_floor_filters_and_counts() {
    // P2 (M7): GET /v1/facts?min_effective_confidence drops below-floor facts and
    // reports `filtered_below_threshold`. Fresh facts have effective == stored
    // confidence, so a 0.5 floor keeps the 0.9 fact and drops the 0.3 fact.
    let state = test_app_state(16);
    for (key, conf) in [("hi", 0.9f32), ("lo", 0.3f32)] {
        let body = corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "floor-test".to_string(),
            key: key.to_string(),
            value: format!("v-{key}"),
            source_receipt: None,
            confidence: conf,
            private: false,
            horizon_class: None,
            actor: None,
        };
        let _ = facts::put_fact(State(state.clone()), HeaderMap::new(), Json(body))
            .await
            .into_response();
    }

    let params = QueryFactsParams {
        min_effective_confidence: Some(0.5),
        query: None,
        entity: Some("floor-test".to_string()),
        entity_prefix: None,
        top_k: None,
        token_budget: None,
        as_of: None,
    };
    let resp = facts::query_facts(State(state), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(
        body["facts"].as_array().unwrap().len(),
        1,
        "only the 0.9 fact clears the 0.5 floor"
    );
    assert_eq!(body["filtered_below_threshold"], 1);
}

#[tokio::test]
async fn query_facts_rejects_out_of_range_floor() {
    // Finding 5: a floor outside 0..=1 is a 400, not a silent all-filtered result.
    let state = test_app_state(16);
    let params = QueryFactsParams {
        min_effective_confidence: Some(1.5),
        query: None,
        entity: None,
        entity_prefix: None,
        top_k: None,
        token_budget: None,
        as_of: None,
    };
    let resp = facts::query_facts(State(state), HeaderMap::new(), Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Case store (POST /v1/cases, /v1/cases/retrieve) ─────────────

#[tokio::test]
async fn cases_record_and_retrieve_similar() {
    let state = test_app_state(16);
    let case_store = std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_memory::CaseStore::new()));

    let mk = |task: &str, action: &str, success: bool, reward: f32| corecrux_memory::case_store::RecordCase {
        task: task.to_string(),
        context: None,
        action: action.to_string(),
        outcome: "done".to_string(),
        success,
        reward,
        tags: vec![],
        source_receipt: None,
    };

    for req in [
        mk(
            "deploy daemon to gpu host",
            "staged cargo-deploy + dense-lane flags",
            true,
            0.9,
        ),
        mk("deploy daemon to gpu host", "flipped flag, broke prod", false, 0.0),
        mk("write a changelog entry", "wrote prose", true, 1.0),
    ] {
        let resp = cases::record_case(
            State(state.clone()),
            HeaderMap::new(),
            axum::Extension(case_store.clone()),
            Json(req),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // only_success=true drops the failed deploy case and the unrelated one.
    let body = cases::RetrieveCasesBody {
        task: "deploy daemon gpu host".to_string(),
        top_k: 5,
        only_success: true,
    };
    let resp = cases::retrieve_cases(
        State(state.clone()),
        HeaderMap::new(),
        axum::Extension(case_store.clone()),
        Json(body),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let cases = json["cases"].as_array().expect("cases array");
    assert_eq!(cases.len(), 1, "only the successful deploy precedent matches");
    assert!(cases[0]["action"].as_str().unwrap().contains("dense-lane"));

    // Missing action → 400.
    let bad = cases::record_case(
        State(state),
        HeaderMap::new(),
        axum::Extension(case_store),
        Json(mk("t", "  ", true, 1.0)),
    )
    .await
    .into_response();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn query_facts_accepts_admin_read_fallback_in_dev_scopes_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let body = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: "deploy".to_string(),
        key: "status".to_string(),
        value: "green".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    let _ = facts::put_fact(State(state.clone()), dev_scope_headers("facts:write"), Json(body))
        .await
        .into_response();

    let params = QueryFactsParams {
        min_effective_confidence: None,
        query: Some("green".to_string()),
        entity: None,
        entity_prefix: None,
        top_k: None,
        token_budget: None,
        as_of: None,
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
            tenant_hash: "default".to_string(),
            entity: "public".to_string(),
            key: "status".to_string(),
            value: "green".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "secret".to_string(),
            key: "salary".to_string(),
            value: "redacted".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
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
            tenant_hash: "default".to_string(),
            entity: "deploy".to_string(),
            key: value.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
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
        dev_scope_headers("sessions:write"),
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
async fn fact_and_session_endpoints_use_read_and_write_scopes_in_dev_scopes_mode() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let admin_headers = dev_scope_headers("admin:read admin:write");

    let create_resp = facts::put_fact(
        State(state.clone()),
        admin_headers.clone(),
        Json(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj-admin".to_string(),
            key: "status".to_string(),
            value: "green".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
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
                tenant_hash: "default".to_string(),
                entity: "proj-admin".to_string(),
                key: "owner".to_string(),
                value: "ops".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            },
            corecrux_memory::fact_store::StoreFact {
                tenant_hash: "default".to_string(),
                entity: "proj-admin:beta".to_string(),
                key: "status".to_string(),
                value: "yellow".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
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
                tenant_hash: "default".to_string(),
                entity: entity.to_string(),
                key: key.to_string(),
                value: value.to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            }),
        )
        .await
        .into_response();
    }

    let params = QueryFactsParams {
        min_effective_confidence: None,
        query: None,
        entity: None,
        entity_prefix: Some("proj-a".to_string()),
        top_k: Some(99),
        token_budget: Some(1),
        as_of: None,
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

#[tokio::test]
async fn query_facts_applies_passport_private_visibility() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "public".to_string(),
            key: "status".to_string(),
            value: "shared".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: crux_mcp::scope::private_entity_for_agent("alice", "notes"),
            key: "secret".to_string(),
            value: "alice-only".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: crux_mcp::scope::private_entity_for_agent("bob", "notes"),
            key: "secret".to_string(),
            value: "bob-only".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
    }

    let params = QueryFactsParams {
        min_effective_confidence: None,
        query: None,
        entity: None,
        entity_prefix: None,
        top_k: Some(10),
        token_budget: None,
        as_of: None,
    };
    let alice = facts::query_facts(
        State(state.clone()),
        dev_scope_passport_headers("query:read", "alice"),
        Query(params),
    )
    .await
    .into_response();
    assert_eq!(alice.status(), StatusCode::OK);
    let body = json_body(alice).await;
    let text = serde_json::to_string(&body["facts"]).expect("facts json");
    assert!(text.contains("alice-only"));
    assert!(text.contains("\"entity\":\"notes\""));
    assert!(!text.contains("bob-only"));

    let anonymous_params = QueryFactsParams {
        min_effective_confidence: None,
        query: None,
        entity: None,
        entity_prefix: None,
        top_k: Some(10),
        token_budget: None,
        as_of: None,
    };
    let anonymous = facts::query_facts(
        State(state.clone()),
        dev_scope_headers("query:read"),
        Query(anonymous_params),
    )
    .await
    .into_response();
    let body = json_body(anonymous).await;
    let text = serde_json::to_string(&body["facts"]).expect("facts json");
    assert!(text.contains("shared"));
    assert!(!text.contains("alice-only"));
    assert!(!text.contains("bob-only"));

    let admin_params = QueryFactsParams {
        min_effective_confidence: None,
        query: None,
        entity: None,
        entity_prefix: None,
        top_k: Some(10),
        token_budget: None,
        as_of: None,
    };
    let admin = facts::query_facts(State(state), dev_scope_headers("admin:read"), Query(admin_params))
        .await
        .into_response();
    let body = json_body(admin).await;
    let text = serde_json::to_string(&body["facts"]).expect("facts json");
    assert!(text.contains("__agent::alice::notes"));
    assert!(text.contains("__agent::bob::notes"));
}

#[tokio::test]
async fn http_session_state_with_passport_uses_mcp_session_scope() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    let save = facts::put_session_state(
        State(state.clone()),
        dev_scope_passport_headers("sessions:write", "alice"),
        Path("sess-42".to_string()),
        Json(serde_json::json!({"step": 1})),
    )
    .await
    .into_response();
    assert_eq!(save.status(), StatusCode::OK);
    let save_body = json_body(save).await;
    assert_eq!(save_body["session_id"], "sess-42");
    assert!(state
        .session_store
        .read()
        .await
        .get("__agent_session::alice::sess-42")
        .is_some());

    let bob = facts::get_session_state(
        State(state.clone()),
        dev_scope_passport_headers("query:read", "bob"),
        Path("sess-42".to_string()),
    )
    .await
    .into_response();
    assert_eq!(bob.status(), StatusCode::NOT_FOUND);

    let alice = facts::get_session_state(
        State(state),
        dev_scope_passport_headers("query:read", "alice"),
        Path("sess-42".to_string()),
    )
    .await
    .into_response();
    assert_eq!(alice.status(), StatusCode::OK);
    let alice_body = json_body(alice).await;
    assert_eq!(alice_body["session_id"], "sess-42");
    assert_eq!(alice_body["state"]["step"], 1);
}

// ── Text Search (POST /v1/query/text-search) ────────────────────
//
// Text search is available by default. These serialized tests clear the
// process-wide override before exercising that default.

#[allow(deprecated)]
fn use_default_text_search() {
    std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
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
#[serial_test::serial]
async fn text_search_empty_index_returns_empty_results() {
    use_default_text_search();

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
    assert_eq!(body["meta"]["score_space"], "bm25_lexical");
    assert_eq!(body["meta"]["score_merge_rule"], "single_score_space");
    assert_eq!(
        body["meta"]["mixed_profile_merge_rule"],
        "rank_fusion_or_single_profile_rerank_required"
    );
    assert!(body["meta"]["semantic_profile_id"].is_null());
    assert!(body["meta"]["local_semantic_profile_id"].is_null());
}

#[tokio::test]
#[serial_test::serial]
async fn text_search_reports_local_semantic_profile_when_embeddings_configured() {
    use_default_text_search();

    let state = test_app_state(16);
    state
        .fact_store
        .write()
        .await
        .set_embedding_client(corecrux_memory::embeddings::EmbeddingClient::new(
            corecrux_memory::embeddings::EmbeddingConfig {
                base_url: "http://localhost:11434".to_string(),
                model: "nomic-embed-text".to_string(),
                dimensions: 768,
            },
        ));
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
    assert!(body["meta"]["semantic_profile_id"].is_null());
    assert!(body["meta"]["local_semantic_profile_id"]
        .as_str()
        .unwrap_or_default()
        .starts_with("sp_"));
    assert_eq!(
        body["meta"]["local_semantic_profile"]["schema"],
        "cuecrux.semantic_profile.v1"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn text_search_with_rcx_router_sets_mode_header() {
    use_default_text_search();

    let mut state = test_app_state(16);
    state.rcx_router = Some(test_rcx_router(vec!["corecrux.query.local"]));
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
    assert_eq!(resp.headers().get("x-crux-mode").unwrap(), "local");
}

#[tokio::test]
#[serial_test::serial]
async fn text_search_denied_by_rcx_router_returns_refusal_receipt() {
    use_default_text_search();

    let mut state = test_app_state(16);
    state.rcx_router = Some(test_rcx_router(vec!["crux-mcp.store_fact"]));
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
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.headers().get("x-crux-mode").unwrap(), "refused");
    let body = json_body(resp).await;
    assert_eq!(body["error"], "rcx_capability_denied");
    assert_eq!(body["reason_code"], "denied:capability_not_permitted");
    assert_eq!(body["refusal_receipt"]["capability"], "corecrux.query.local");
}

#[tokio::test]
#[serial_test::serial]
async fn text_search_empty_query_returns_400() {
    use_default_text_search();

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

#[tokio::test]
#[serial_test::serial]
async fn text_search_query_read_requires_non_empty_tenant_id() {
    use_default_text_search();

    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let body = query::TextSearchBody {
        tenant_id: String::new(),
        query: "hello".to_string(),
        limit: 10,
        token_budget: None,
        min_score: None,
        mode: None,
        include_receipt: None,
    };

    let resp = query::post_query_text_search(State(state), dev_scope_headers("query:read"), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial]
async fn text_search_admin_can_explicitly_query_all_tenants() {
    use_default_text_search();

    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let ccxi_bytes = build_test_ccxi(&["hello world test document"]);
    load_test_index(&state, &ccxi_bytes).await;
    let body = query::TextSearchBody {
        tenant_id: "*".to_string(),
        query: "hello".to_string(),
        limit: 10,
        token_budget: None,
        min_score: None,
        mode: None,
        include_receipt: None,
    };

    let resp = query::post_query_text_search(State(state), dev_scope_headers("admin:read"), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["results"].as_array().unwrap().len(), 1);
}

#[test]
fn opt_in_query_features_remain_disabled_by_default() {
    assert!(!is_query_feature_enabled("CORECRUXD_QUERY_GRAPH_EXPAND_TEST_FAKE_ENV"));
    assert!(!is_query_feature_enabled("CORECRUXD_QUERY_TIME_RANGE_TEST_FAKE_ENV"));
}

#[test]
#[serial_test::serial]
fn text_search_is_enabled_by_default() {
    use_default_text_search();
    assert!(is_query_feature_enabled("CORECRUXD_QUERY_TEXT_SEARCH"));
}

#[tokio::test]
#[serial_test::serial]
async fn text_search_with_index_returns_hits() {
    use_default_text_search();

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
    assert_eq!(body["meta"]["source_label"], "local_tenant_index");
    assert_eq!(body["meta"]["score_space"], "bm25_lexical");
    assert_eq!(results[0]["source_label"], "local_tenant_index");
    assert_eq!(results[0]["score_space"], "bm25_lexical");
    assert_eq!(results[0]["rank"], 1);
    assert!(results[0]["semantic_profile_id"].is_null());
}

#[tokio::test]
#[serial_test::serial]
async fn text_search_scan_mode() {
    use_default_text_search();

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
#[serial_test::serial]
async fn text_search_with_token_budget() {
    use_default_text_search();

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
#[serial_test::serial]
async fn text_search_expand_returns_chunks() {
    use_default_text_search();

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
    assert_eq!(body["meta"]["score_space"], "bm25_lexical");
    assert_eq!(chunks[0]["segment_index"], 0);
    assert_eq!(chunks[0]["doc_id"], 0);
    assert_eq!(chunks[0]["source_label"], "local_tenant_index");
    assert_eq!(chunks[0]["score_space"], "bm25_lexical");
    assert_eq!(chunks[1]["doc_id"], 1);
}

#[tokio::test]
#[serial_test::serial]
async fn text_search_expand_skips_invalid_ids() {
    use_default_text_search();

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
#[serial_test::serial]
async fn text_search_expand_empty_index() {
    use_default_text_search();

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
        tenant_hash: "default".to_string(),
        entity: "e".to_string(),
        key: "k".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    let resp = facts::put_fact(State(state.clone()), HeaderMap::new(), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // PUT /v1/facts — with query:read only → 403
    let body2 = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: "e".to_string(),
        key: "k".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    let resp2 = put_fact(State(state.clone()), dev_scope_headers("query:read"), Json(body2))
        .await
        .into_response();
    assert_eq!(resp2.status(), StatusCode::FORBIDDEN);

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
    assert_platform_upgrade_501(resp, "gpus").await;
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

// Serialized: reads CORECRUXD_QUERY_TIME_RANGE (expects unset). Without this,
// it can run concurrently with the #[serial] test that sets the flag and
// observe a leaked value (process-global env), returning 501 not 404.
#[serial_test::serial]
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

#[tokio::test]
async fn get_projection_modules_returns_runtime_registry_without_dataplane() {
    let state = test_app_state(16);
    let resp = get_projection_modules(
        State(state),
        Query(ProjectionModulesQuery { shard_id: None }),
        HeaderMap::new(),
    )
    .await
    .into_response();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["schema"], corecrux_projections::PROJECTION_MODULES_LIST_SCHEMA_V1);
    assert_eq!(body["dataplane_enabled"], false);
    assert_eq!(body["source"], "runtime_current");
    assert_eq!(body["modules"].as_array().unwrap().len(), 4);
    assert!(body["replay_availability"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["historical_replay_available"] == true));
}

#[tokio::test]
async fn get_projection_modules_uses_persisted_meta_registry_when_available() {
    let mut meta = corecrux_projections::ProjectionsMetaV1::empty_now();
    meta.commit_id = 42;
    corecrux_projections::record_current_projection_modules_v1(&mut meta);
    let fake = Arc::new(FakeHttpDataplane {
        enabled: true,
        projection_meta: Some(meta),
        ..Default::default()
    });
    let mut state = test_app_state(16);
    state.http_dataplane = fake;

    let resp = get_projection_modules(
        State(state),
        Query(ProjectionModulesQuery {
            shard_id: Some("shard-0001".to_string()),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["source"], "projection_meta");
    assert_eq!(body["commit_id"], 42);
    assert!(body["module_refs"]["artifact_relations"].is_object());
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
    let resp = get_entity_count(State(state), HeaderMap::new(), axum::extract::Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn get_entity_timeline_returns_501_without_dataplane() {
    let state = test_app_state(16);
    let mut params = std::collections::HashMap::new();
    params.insert("tenant_id".to_string(), "tenant-a".to_string());
    let resp = get_entity_timeline(State(state), HeaderMap::new(), axum::extract::Query(params))
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
    let resp = get_entity_current_state(State(state), HeaderMap::new(), axum::extract::Query(params))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn entity_projection_routes_require_query_read() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let mut params = std::collections::HashMap::new();
    params.insert("tenant_id".to_string(), "tenant-a".to_string());
    params.insert("entity_type".to_string(), "server".to_string());

    let missing = get_entity_count(
        State(state.clone()),
        HeaderMap::new(),
        axum::extract::Query(params.clone()),
    )
    .await
    .into_response();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let wrong_scope = get_entity_count(
        State(state.clone()),
        dev_scope_headers("facts:write"),
        axum::extract::Query(params.clone()),
    )
    .await
    .into_response();
    assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);

    let allowed = get_entity_count(
        State(state),
        dev_scope_headers("query:read"),
        axum::extract::Query(params),
    )
    .await
    .into_response();
    assert_eq!(allowed.status(), StatusCode::NOT_IMPLEMENTED);
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
                authenticated_passport: None,
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
    assert!(body["detail"].as_str().unwrap_or_default().contains("1..=128"));
}

#[tokio::test]
async fn admin_action_id_rejects_unsafe_chars() {
    let state = test_app_state(16);
    let req = admin::PostAdminActionRequest {
        action_id: Some("act:bad/../id".to_string()),
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
    assert!(body["detail"].as_str().unwrap_or_default().contains("[A-Za-z0-9._-]"));
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
#[serial_test::serial]
async fn text_search_with_min_score_filters() {
    use_default_text_search();

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
    let resp = get_entity_count(State(state), HeaderMap::new(), axum::extract::Query(params))
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
    // CONFLICT (409) is a recognised status — passes through directly.
    let resp = problem_response(StatusCode::CONFLICT, "conflict happened");
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(ct.contains("application/problem+json"));

    // An unrecognised status (e.g., I_AM_A_TEAPOT 418) still falls back to 500.
    let fallback = problem_response(StatusCode::IM_A_TEAPOT, "tea time");
    assert_eq!(fallback.status(), StatusCode::INTERNAL_SERVER_ERROR);
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
            tenant_hash: "default".to_string(),
            entity: "__ops__::error:test-err-1".to_string(),
            key: "test error".to_string(),
            value: "something went wrong".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
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
            tenant_hash: "default".to_string(),
            entity: "__ops__::health:shard_store".to_string(),
            key: "health".to_string(),
            value: "degraded".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__ops__::health:shard_store".to_string(),
            key: "health".to_string(),
            value: "healthy".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
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
    let app = router(state, test_case_store());
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

fn runtime_capability_profile_env() -> [EnvVarGuard; 6] {
    [
        EnvVarGuard::set("CORECRUXD_SYNC_ENABLED", "true"),
        EnvVarGuard::set("CORECRUXD_SYNC_REMOTE_URL", "http://sync.example.test:14800"),
        EnvVarGuard::set("CORECRUXD_SYNC_API_KEY", "test-key"),
        EnvVarGuard::set("CORECRUXD_QUERY_GRAPH_EXPAND", "1"),
        EnvVarGuard::set("CORECRUXD_GPU1_BASE_URL", "http://gpu.example.test"),
        EnvVarGuard::set("CORECRUXD_CORECRUX_GRAPH_BASE_URL", "http://graph.example.test"),
    ]
}

fn full_runtime_capability_state() -> AppState {
    let mut state = test_app_state(16);
    state.operating_mode = crate::product::OperatingMode::ProHybrid;
    state.enabled_pro_services = vec!["gpu1:rerank".to_string(), "sync:mirror".to_string()];
    state
}

#[serial_test::serial]
#[tokio::test]
async fn version_runtime_capability_descriptor_full_profile() {
    let _env = runtime_capability_profile_env();
    let mut state = full_runtime_capability_state();
    state.http_dataplane = enabled_dataplane(Vec::new(), None);
    state
        .fact_store
        .write()
        .await
        .set_embedder(Box::<corecrux_memory::embeddings::LocalHashEmbedder>::default());

    let body = json_body(get_version(State(state)).await.into_response()).await;
    let descriptor = &body["product"]["runtime_capabilities"];
    let capabilities = &descriptor["capabilities"];

    assert_eq!(descriptor["schema_version"], 1);
    let Some(capability_values) = capabilities.as_object() else {
        panic!("runtime_capabilities.capabilities must be a JSON object");
    };
    assert_eq!(capability_values.len(), 8);
    for capability in capability_values.values() {
        assert!(capability["availability"].is_string());
        assert!(capability["reason_code"].is_string());
        assert!(capability["reason"].as_str().is_some_and(|reason| !reason.is_empty()));
        for stage in ["compiled", "configured", "initialized", "entitled", "degraded"] {
            assert!(capability[stage].is_boolean(), "missing stage {stage}");
        }
    }
    for capability in [
        "append",
        "local_embedders",
        "hosted_sync",
        "projection_queries",
        "graph_expand",
        "console_link_graph",
    ] {
        assert_eq!(capabilities[capability]["availability"], "available", "{capability}");
        assert_eq!(capabilities[capability]["reason_code"], "available", "{capability}");
        assert_eq!(capabilities[capability]["compiled"], true, "{capability}");
        assert_eq!(capabilities[capability]["configured"], true, "{capability}");
        assert_eq!(capabilities[capability]["initialized"], true, "{capability}");
        assert_eq!(capabilities[capability]["entitled"], true, "{capability}");
        assert_eq!(capabilities[capability]["degraded"], false, "{capability}");
    }
    assert_eq!(capabilities["embedding_delegation"]["availability"], "unavailable");
    assert_eq!(
        capabilities["embedding_delegation"]["reason_code"],
        "embedding_delegation_not_configured"
    );
    assert_eq!(capabilities["embedding_delegation"]["configured"], false);
    #[cfg(feature = "hosted-surfaces")]
    {
        assert_eq!(capabilities["rerank_gpu"]["availability"], "available");
        assert_eq!(capabilities["rerank_gpu"]["compiled"], true);
        assert_eq!(capabilities["rerank_gpu"]["configured"], true);
        assert_eq!(capabilities["rerank_gpu"]["initialized"], true);
        assert_eq!(capabilities["rerank_gpu"]["entitled"], true);
        assert_eq!(capabilities["rerank_gpu"]["degraded"], false);
    }
    #[cfg(not(feature = "hosted-surfaces"))]
    {
        assert_eq!(capabilities["rerank_gpu"]["availability"], "unavailable");
        assert_eq!(capabilities["rerank_gpu"]["reason_code"], "rerank_not_compiled");
        assert_eq!(capabilities["rerank_gpu"]["compiled"], false);
        assert_eq!(capabilities["rerank_gpu"]["configured"], true);
        assert_eq!(capabilities["rerank_gpu"]["initialized"], false);
        assert_eq!(capabilities["rerank_gpu"]["entitled"], true);
        assert_eq!(capabilities["rerank_gpu"]["degraded"], false);
    }
}

#[serial_test::serial]
#[tokio::test]
async fn version_runtime_capability_descriptor_dataplane_off_profile() {
    let _env = runtime_capability_profile_env();
    let state = full_runtime_capability_state();
    state
        .fact_store
        .write()
        .await
        .set_embedder(Box::<corecrux_memory::embeddings::LocalHashEmbedder>::default());

    let body = json_body(get_version(State(state)).await.into_response()).await;
    let capabilities = &body["product"]["runtime_capabilities"]["capabilities"];

    for capability in ["append", "projection_queries", "graph_expand"] {
        assert_eq!(capabilities[capability]["availability"], "unavailable", "{capability}");
        assert_eq!(
            capabilities[capability]["reason_code"], "http_dataplane_disabled",
            "{capability}"
        );
        assert_eq!(capabilities[capability]["initialized"], false, "{capability}");
    }
    assert_eq!(capabilities["append"]["compiled"], true);
    assert_eq!(capabilities["append"]["configured"], false);
    assert_eq!(capabilities["append"]["entitled"], true);
    assert_eq!(capabilities["local_embedders"]["availability"], "available");
    assert_eq!(capabilities["hosted_sync"]["availability"], "available");
}

#[serial_test::serial]
#[tokio::test]
async fn version_runtime_capability_descriptor_no_local_embedder_profile() {
    let _env = runtime_capability_profile_env();
    let mut state = full_runtime_capability_state();
    state.http_dataplane = enabled_dataplane(Vec::new(), None);
    state
        .fact_store
        .write()
        .await
        .set_embedding_client(corecrux_memory::embeddings::EmbeddingClient::new(
            corecrux_memory::embeddings::EmbeddingConfig {
                base_url: "http://embed.example.test".to_string(),
                model: "remote-test".to_string(),
                dimensions: 8,
            },
        ));

    let body = json_body(get_version(State(state)).await.into_response()).await;
    let capabilities = &body["product"]["runtime_capabilities"]["capabilities"];

    assert_eq!(body["features"]["embeddings"], true);
    assert_eq!(body["semantic_profile"]["model"], "remote-test");
    assert_eq!(capabilities["append"]["availability"], "available");
    assert_eq!(capabilities["projection_queries"]["availability"], "available");
    assert_eq!(capabilities["local_embedders"]["availability"], "unavailable");
    assert_eq!(
        capabilities["local_embedders"]["reason_code"],
        "local_embedder_unavailable"
    );
    assert_eq!(capabilities["local_embedders"]["compiled"], true);
    assert_eq!(capabilities["local_embedders"]["configured"], false);
    assert_eq!(capabilities["local_embedders"]["initialized"], false);
    assert_eq!(capabilities["local_embedders"]["entitled"], true);
    assert_eq!(capabilities["local_embedders"]["degraded"], false);
}

#[serial_test::serial]
#[tokio::test]
async fn version_runtime_capability_descriptor_delegating_lite_profile(
) -> Result<(), corecrux_memory::embeddings::EmbeddingError> {
    let _env = runtime_capability_profile_env();
    let mut state = full_runtime_capability_state();
    state.http_dataplane = enabled_dataplane(Vec::new(), None);
    let delegate = corecrux_memory::embeddings::DelegatingEmbedder::new(
        corecrux_memory::embeddings::DelegatingEmbeddingConfig::new(
            "http://compute.example.test".to_string(),
            "test-delegate-token".to_string(),
            "remote-test".to_string(),
            8,
        ),
    )?;
    state.fact_store.write().await.set_embedder(Box::new(delegate));

    let body = json_body(get_version(State(state)).await.into_response()).await;
    let capabilities = &body["product"]["runtime_capabilities"]["capabilities"];

    assert_eq!(body["product"]["runtime_capabilities"]["schema_version"], 1);
    assert_eq!(body["features"]["embeddings"], true);
    assert_eq!(body["semantic_profile"]["model"], "remote-test");
    assert_eq!(body["semantic_profile"]["dimensions"], 8);
    assert_eq!(capabilities["local_embedders"]["availability"], "unavailable");
    assert_eq!(capabilities["local_embedders"]["reason_code"], "delegated_to_remote");
    assert_eq!(capabilities["embedding_delegation"]["availability"], "available");
    assert_eq!(capabilities["embedding_delegation"]["reason_code"], "available");
    assert_eq!(capabilities["embedding_delegation"]["configured"], true);
    assert_eq!(capabilities["embedding_delegation"]["initialized"], true);
    assert_eq!(capabilities["embedding_delegation"]["degraded"], false);
    Ok(())
}

#[serial_test::serial]
#[tokio::test]
async fn version_public_view_is_redacted() {
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
        comparison_stale: false,
        basis: "binary".to_string(),
        binary_commit: Some("def4567".to_string()),
        checkout_commit: Some("abc1234".to_string()),
        checkout_ahead_by: 0,
        checkout_behind_by: 5,
        upgrade_hint: "current".to_string(),
    };
    let resp = get_version(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["version"], "test");
    assert_eq!(body["msrv"], "1.88.0");
    assert!(body["commit"].is_null());
    assert!(body["passport"].is_null());
    assert!(body["cloud"].is_null());
    assert!(body["action_enrichment"].is_null());
    assert!(body["gpu1_compute"].is_null());
    // Update *status* is public (product-facing), but commit SHAs and repo
    // internals are not — consistent with the top-level `commit` redaction.
    assert!(body["update"]["state"].is_string());
    assert!(body["update"]["upgrade_hint"].is_string());
    assert!(body["update"]["current_commit"].is_null());
    assert!(body["update"]["latest_commit"].is_null());
    assert!(body["update"]["repo_dir"].is_null());
    assert!(body["update"]["remote"].is_null());
    assert!(body["update"]["tracking_ref"].is_null());
    // basis + checkout drift counts are product-facing; the commit SHAs
    // (binary_commit/checkout_commit) stay admin-only like current_commit.
    assert_eq!(body["update"]["basis"], "binary");
    assert_eq!(body["update"]["checkout_behind_by"], 5);
    assert_eq!(body["update"]["checkout_ahead_by"], 0);
    assert!(body["update"]["binary_commit"].is_null());
    assert!(body["update"]["checkout_commit"].is_null());
    assert_eq!(body["product"]["mode"], "free_local");
    assert_eq!(body["product"]["tier"], "free");
    assert_eq!(body["product"]["free_safety_baseline_active"], true);
    #[cfg(feature = "hosted-surfaces")]
    assert_eq!(body["cloud_access"]["contract_path"], "/v1/cloud/access-contract");
    // CE: the cloud access-contract route is compiled out, so its pointer is null.
    #[cfg(not(feature = "hosted-surfaces"))]
    assert!(body["cloud_access"]["contract_path"].is_null());
    assert_eq!(body["agent_workbench"]["contract_path"], "/v1/workbench/contract");
    assert!(body["product"]["enabled_capability_claims"]
        .as_array()
        .unwrap()
        .iter()
        .any(|claim| claim == "daemon:local"));
    assert!(body["product"]["enabled_capability_claims"]
        .as_array()
        .unwrap()
        .iter()
        .any(|claim| claim == "tenant:isolation"));
    assert!(!body["product"]["enabled_capability_claims"]
        .as_array()
        .unwrap()
        .iter()
        .any(|claim| claim == "gpu1:answer"));
    assert!(body["semantic_profile"].is_null());
    assert_eq!(body["protocol_contracts"]["session_plan_contract"]["status"], "current");
    assert_eq!(
        body["protocol_contracts"]["session_plan_contract"]["target"],
        "cuecrux.shared.session_plan.v2"
    );
    assert_eq!(
        body["protocol_contracts"]["corecrux_retrieval_contract"]["status"],
        "partial"
    );
    assert_eq!(
        body["protocol_contracts"]["semantic_profile_contract"]["status"],
        "missing"
    );
    assert_eq!(
        body["protocol_contracts"]["projection_module_contract"]["status"],
        "current"
    );
    assert_eq!(
        body["protocol_contracts"]["extension_registry_contract"]["status"],
        "current"
    );
    assert_eq!(
        body["protocol_contracts"]["rcx_registry_publish_contract"]["status"],
        "current"
    );
    assert!(body["features"].is_object());
    // Features should be booleans
    assert!(body["features"]["text_search"].is_boolean());
    assert!(body["features"]["graph_expand"].is_boolean());
    assert!(body["features"]["self_observe"].is_boolean());
    assert!(body["features"]["mcp"].is_boolean());
    assert_eq!(body["sync"]["mode"], "local_only");
    assert_eq!(body["sync"]["configured"], false);
    assert_eq!(body["sync"]["remote_url_redacted"], false);
}

#[serial_test::serial]
#[tokio::test]
async fn version_reports_text_search_default_and_explicit_off() {
    std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
    let resp = get_version(State(test_app_state(16))).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["features"]["text_search"], true);

    for value in ["0", "false"] {
        std::env::set_var("CORECRUXD_QUERY_TEXT_SEARCH", value);
        let resp = get_version(State(test_app_state(16))).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(
            body["features"]["text_search"], false,
            "{value} must be reported as off"
        );
    }

    std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
}

#[serial_test::serial]
#[tokio::test]
async fn version_admin_view_includes_operational_details() {
    std::env::remove_var("CORECRUXD_SYNC_ENABLED");
    std::env::remove_var("CORECRUXD_SYNC_REMOTE_URL");
    std::env::remove_var("CORECRUXD_SYNC_API_KEY");
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
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
        comparison_stale: false,
        basis: "binary".to_string(),
        binary_commit: Some("def4567".to_string()),
        checkout_commit: Some("abc1234".to_string()),
        checkout_ahead_by: 0,
        checkout_behind_by: 5,
        upgrade_hint: "current".to_string(),
    };

    let resp = get_admin_version(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["version"], "test");
    assert_eq!(body["commit"], "test");
    assert_eq!(body["passport"]["alg"], "ed25519");
    assert_eq!(body["cloud"]["tenant_connectivity"], "not_configured");
    #[cfg(feature = "hosted-surfaces")]
    assert_eq!(body["cloud_access"]["contract_path"], "/v1/cloud/access-contract");
    // CE: the cloud access-contract route is compiled out, so its pointer is null.
    #[cfg(not(feature = "hosted-surfaces"))]
    assert!(body["cloud_access"]["contract_path"].is_null());
    assert_eq!(body["action_enrichment"]["contract_path"], "/v1/actions/enrich");
    assert_eq!(body["agent_workbench"]["contract_path"], "/v1/workbench/contract");
    #[cfg(feature = "hosted-surfaces")]
    assert_eq!(body["gpu1_compute"]["contract_path"], "/v1/gpu1/contract");
    // CE: the GPU-1 compute bridge is compiled out, so its posture block is null.
    #[cfg(not(feature = "hosted-surfaces"))]
    assert!(body["gpu1_compute"].is_null());
    assert_eq!(body["update"]["state"], "current");
    assert_eq!(body["update"]["tracking_ref"], "origin/main");
    assert_eq!(body["update"]["current_commit"], "abc123");
    assert!(body["update"]["repo_dir"].is_null());
    assert!(body["update"]["error"].is_null());
    // Admin view (public_view) keeps the basis fields, including commit SHAs.
    assert_eq!(body["update"]["basis"], "binary");
    assert_eq!(body["update"]["binary_commit"], "def4567");
    assert_eq!(body["update"]["checkout_commit"], "abc1234");
    assert_eq!(body["update"]["checkout_behind_by"], 5);
}

#[serial_test::serial]
#[tokio::test]
async fn version_endpoint_reports_degraded_sync_when_remote_is_incomplete() {
    std::env::set_var("CORECRUXD_SYNC_ENABLED", "true");
    std::env::set_var("CORECRUXD_SYNC_REMOTE_URL", "http://example.test:14800");
    std::env::remove_var("CORECRUXD_SYNC_API_KEY");

    let mut state = test_app_state(16);
    state.operating_mode = crate::product::OperatingMode::ProHybrid;
    state.enabled_pro_services = vec!["sync:mirror".to_string()];
    let resp = get_version(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["sync"]["mode"], "degraded");
    assert_eq!(body["sync"]["configured"], false);
    assert_eq!(body["sync"]["background_sync_enabled"], true);
    assert!(body["sync"]["remote_url"].is_null());
    assert_eq!(body["sync"]["remote_url_redacted"], true);
    assert_eq!(body["sync"]["api_key_configured"], false);
    assert!(body["sync"]["degraded_reason"]
        .as_str()
        .unwrap_or_default()
        .contains("CORECRUXD_SYNC_API_KEY"));
    let hosted_sync = &body["product"]["runtime_capabilities"]["capabilities"]["hosted_sync"];
    assert_eq!(hosted_sync["availability"], "degraded");
    assert_eq!(hosted_sync["reason_code"], "hosted_sync_degraded");
    assert_eq!(hosted_sync["configured"], false);
    assert_eq!(hosted_sync["initialized"], true);
    assert_eq!(hosted_sync["entitled"], true);
    assert_eq!(hosted_sync["degraded"], true);

    std::env::remove_var("CORECRUXD_SYNC_ENABLED");
    std::env::remove_var("CORECRUXD_SYNC_REMOTE_URL");
    std::env::remove_var("CORECRUXD_SYNC_API_KEY");
}

#[serial_test::serial]
#[tokio::test]
async fn version_endpoint_reports_pro_agent_workbench_posture() {
    std::env::remove_var("CORECRUXD_SYNC_ENABLED");
    std::env::remove_var("CORECRUXD_SYNC_REMOTE_URL");
    std::env::remove_var("CORECRUXD_SYNC_API_KEY");
    let mut state = test_app_state(16);
    state.operating_mode = crate::product::OperatingMode::ProHybrid;
    state.enabled_pro_services = vec![
        "gpu1:answer".to_string(),
        "context_pack:budgeted".to_string(),
        "gpu:onsite".to_string(),
    ];

    let resp = get_version(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    assert_eq!(body["product"]["mode"], "pro_hybrid");
    assert_eq!(body["product"]["tier"], "pro");
    assert!(body["product"]["enabled_capability_claims"]
        .as_array()
        .unwrap()
        .iter()
        .any(|claim| claim == "receipts:local"));
    assert!(body["product"]["enabled_capability_claims"]
        .as_array()
        .unwrap()
        .iter()
        .any(|claim| claim == "gpu1:answer"));
    assert!(!body["product"]["enabled_capability_claims"]
        .as_array()
        .unwrap()
        .iter()
        .any(|claim| claim == "gpu:onsite"));
    assert_eq!(
        body["product"]["enabled_pro_services"],
        serde_json::json!(["gpu1:answer", "context_pack:budgeted"])
    );
    assert!(body["product"]["capability_catalog"]["pro_claim_placements"]
        .as_array()
        .unwrap()
        .iter()
        .any(|placement| placement["claim"] == "impact:preflight" && placement["implementation"] == "daemon"));
    assert!(body["product"]["capability_catalog"]["pro_claim_placements"]
        .as_array()
        .unwrap()
        .iter()
        .any(|placement| placement["claim"] == "sso:rbac" && placement["implementation"] == "hosted_control_plane"));
    assert!(body["agent_workbench"]["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .any(|surface| surface["capability"] == "context_pack:budgeted" && surface["status"] == "enabled"));
    assert_eq!(body["cloud_access"]["cloud_only_entitled"], true);
    assert_eq!(body["cloud_access"]["mode_switching_supported"], true);
}

// Exercises the `http::cloud` handler directly — hosted-surface only (M4).
#[cfg(feature = "hosted-surfaces")]
#[serial_test::serial]
#[tokio::test]
async fn cloud_access_contract_reports_cloud_only_no_daemon_path() {
    std::env::remove_var("CORECRUXD_SYNC_ENABLED");
    std::env::set_var("CORECRUXD_SYNC_REMOTE_URL", "https://memory.example");
    std::env::set_var("CORECRUXD_SYNC_API_KEY", "test-key");
    let mut state = test_app_state(16);
    state.operating_mode = crate::product::OperatingMode::ProCloudOnly;
    state.enabled_pro_services = vec!["gpu1:answer".to_string(), "gpu1:rerank".to_string()];

    let resp = super::cloud::get_cloud_access_contract(State(state), HeaderMap::new()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    assert_eq!(body["schema"], crate::product::CLOUD_ACCESS_CONTRACT_SCHEMA);
    assert_eq!(body["mode"], "pro_cloud_only");
    assert_eq!(body["cloud_only_entitled"], true);
    assert_eq!(body["cloud_only_active"], true);
    assert_eq!(body["local_daemon_required_for_current_mode"], false);
    assert_eq!(body["configured_rest_base_url"], "https://memory.example");
    assert_eq!(body["hosted_mcp"]["local_daemon_required"], false);
    assert!(body["hosted_mcp"]["tool_catalog"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tool| tool == "cuecrux_session"));
    assert!(body["tenant_memory_model"]["collections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|collection| collection == "semantic_profiles"));
    assert!(body["hosted_rest"]["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .any(|endpoint| endpoint["hosted_path"] == "/v1/session" && endpoint["local_path"] == "/session"));
    assert!(body["hosted_rest"]["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .any(|endpoint| endpoint["hosted_path"] == "/v1/workbench/context-pack"
            && endpoint["scopes"] == serde_json::json!(["context_pack:budgeted"])));
    assert!(body["pro_gpu_services"]
        .as_array()
        .unwrap()
        .iter()
        .any(|service| service["capability"] == "gpu1:answer" && service["status"] == "enabled"));
    assert!(body["pro_claim_placements"]
        .as_array()
        .unwrap()
        .iter()
        .any(|placement| placement["claim"] == "sso:rbac"
            && placement["hosted_control_plane"] == true
            && placement["daemon_implemented"] == false));

    std::env::remove_var("CORECRUXD_SYNC_REMOTE_URL");
    std::env::remove_var("CORECRUXD_SYNC_API_KEY");
}

// Exercises the `http::cloud` handler directly — hosted-surface only (M4).
#[cfg(feature = "hosted-surfaces")]
#[tokio::test]
async fn cloud_access_contract_is_visible_in_free_but_not_entitled() {
    let state = test_app_state(16);

    let resp = super::cloud::get_cloud_access_contract(State(state), HeaderMap::new()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    assert_eq!(body["mode"], "free_local");
    assert_eq!(body["cloud_only_entitled"], false);
    assert_eq!(body["cloud_only_active"], false);
    assert_eq!(body["local_daemon_required_for_current_mode"], true);
    assert!(body["pro_gpu_services"]
        .as_array()
        .unwrap()
        .iter()
        .all(|service| service["status"] == "pro_required"));
}

#[tokio::test]
async fn action_enrich_basic_is_free_and_stores_private_receipt() {
    let state = test_app_state(16);
    let shared = state.clone();

    let resp = super::actions::post_action_enrich(
        State(state),
        HeaderMap::new(),
        Json(corecrux_memory::action_enrichment::ActionEnrichmentInput {
            tenant_id: Some("business::acme".to_string()),
            tool_name: "calendar.move_event".to_string(),
            tool_parameters: serde_json::json!({
                "event_id": "evt_1",
                "attendees": ["customer@example.com"],
                "new_time": "2026-05-08T16:00:00Z"
            }),
            action_description: Some("Move customer meeting".to_string()),
            include_first_party_enrichers: false,
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(
        body["schema"],
        corecrux_memory::action_enrichment::ACTION_ENRICHMENT_SCHEMA
    );
    assert_eq!(body["first_party_enrichers_used"], false);
    assert_eq!(body["proposal"]["consequence_metadata"]["domain"], "email_calendar");

    let store = shared.fact_store.read().await;
    let facts = store.query(&corecrux_memory::fact_store::FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some("__action_enrichment_receipt__::business::acme".to_string()),
        top_k: 10,
        token_budget: None,
    });
    assert_eq!(facts.facts.len(), 1);
    assert!(facts.facts[0].private);
    assert_eq!(facts.facts[0].key, "proposal");
}

#[tokio::test]
async fn action_enrich_first_party_requires_enabled_pro_service() {
    let state = test_app_state(16);

    let resp = super::actions::post_action_enrich(
        State(state),
        HeaderMap::new(),
        Json(corecrux_memory::action_enrichment::ActionEnrichmentInput {
            tenant_id: Some("business::acme".to_string()),
            tool_name: "calendar.move_event".to_string(),
            tool_parameters: serde_json::json!({ "event_id": "evt_1" }),
            action_description: None,
            include_first_party_enrichers: true,
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let body = json_body(resp).await;
    assert_eq!(body["status"], "pro_service_not_enabled");
    assert_eq!(body["capability"], "enrichers:first_party");
}

#[tokio::test]
async fn action_enrich_first_party_uses_local_tenant_context_when_enabled() {
    let mut state = test_app_state(16);
    state.operating_mode = crate::product::OperatingMode::ProHybrid;
    state.enabled_pro_services = vec!["enrichers:first_party".to_string()];
    state
        .fact_store
        .write()
        .await
        .store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "business::acme::customer::cfo".to_string(),
            key: "constraint".to_string(),
            value: "Customer meeting conflicts with Sarah's preparation block".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

    let resp = super::actions::post_action_enrich(
        State(state),
        HeaderMap::new(),
        Json(corecrux_memory::action_enrichment::ActionEnrichmentInput {
            tenant_id: Some("business::acme".to_string()),
            tool_name: "calendar.move_event".to_string(),
            tool_parameters: serde_json::json!({
                "customer": "acme",
                "attendees": ["sarah@example.com"],
                "new_time": "2026-05-08T16:00:00Z"
            }),
            action_description: Some("Move Acme customer meeting".to_string()),
            include_first_party_enrichers: true,
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["first_party_enrichers_used"], true);
    assert_eq!(body["proposal"]["enrichment_mode"], "first_party");
    assert_eq!(body["proposal"]["relationship_hits"].as_array().unwrap().len(), 1);
    assert!(body["proposal"]["narrative"]
        .as_str()
        .unwrap()
        .contains("first_party_hits=1"));
}

#[tokio::test]
async fn workbench_contract_visible_in_free_lists_pro_surfaces() {
    let state = test_app_state(16);

    let resp = super::workbench::get_workbench_contract(State(state), HeaderMap::new()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    assert_eq!(body["schema"], super::workbench::WORKBENCH_CONTRACT_SCHEMA);
    assert_eq!(body["tier"], "free");
    assert!(body["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .any(|surface| surface["capability"] == "context_pack:budgeted"
            && surface["path"] == "/v1/workbench/context-pack"
            && surface["status"] == "pro_required"));
}

#[tokio::test]
async fn workbench_brief_requires_enabled_pro_service() {
    let state = test_app_state(16);

    let resp = super::workbench::get_agent_brief(
        State(state),
        HeaderMap::new(),
        Query(super::workbench::TenantWorkbenchQuery {
            tenant_id: "business::acme".to_string(),
            project_id: None,
            limit: None,
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let body = json_body(resp).await;
    assert_eq!(body["status"], "pro_service_not_enabled");
    assert_eq!(body["capability"], "agent_brief:pro");
}

#[tokio::test]
async fn workbench_context_pack_and_command_ledger_store_private_receipts() {
    let state = pro_workbench_state(&["context_pack:budgeted", "ledger:history"]);
    let shared = state.clone();
    {
        let mut store = shared.fact_store.write().await;
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "business::acme::memory::route-scope".to_string(),
            key: "summary".to_string(),
            value: "business::acme route scope drift context for command ledger".to_string(),
            source_receipt: Some("rcpt_seed".to_string()),
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
    }

    let pack_resp = super::workbench::post_context_pack(
        State(state.clone()),
        HeaderMap::new(),
        Json(super::workbench::ContextPackBody {
            tenant_id: "business::acme".to_string(),
            query: "route scope drift".to_string(),
            token_budget: 128,
            include_private: false,
            source_labels: vec!["fact_store".to_string()],
        }),
    )
    .await;
    assert_eq!(pack_resp.status(), StatusCode::OK);
    let pack = json_body(pack_resp).await;
    assert_eq!(pack["pack"]["schema"], "crux.agent_workbench.context_pack.v1");
    assert_eq!(pack["pack"]["tenant_id"], "business::acme");
    assert_eq!(pack["pack"]["items"].as_array().unwrap().len(), 1);
    assert!(pack["receipt"]["receipt_id"]
        .as_str()
        .unwrap()
        .starts_with("workbench:context_pack:"));

    let ledger_resp = super::workbench::post_command_ledger(
        State(state.clone()),
        HeaderMap::new(),
        Json(super::workbench::CommandLedgerBody {
            tenant_id: "business::acme".to_string(),
            command: "cargo".to_string(),
            args: vec!["test".to_string(), "-p".to_string(), "corecruxd".to_string()],
            cwd: Some("/home/myles/CueCrux/Crux".to_string()),
            exit_status: Some(0),
            duration_ms: Some(42),
            started_at_unix_ms: Some(100),
            completed_at_unix_ms: Some(142),
            stdout_hash: Some("blake3:stdout".to_string()),
            stderr_hash: None,
            linked_receipts: vec![pack["receipt"]["receipt_id"].as_str().unwrap().to_string()],
            project_id: Some("alpha".to_string()),
            work_id: Some("work-1".to_string()),
        }),
    )
    .await;
    assert_eq!(ledger_resp.status(), StatusCode::OK);

    let list_resp = super::workbench::get_command_ledger(
        State(state),
        HeaderMap::new(),
        Query(super::workbench::TenantWorkbenchQuery {
            tenant_id: "business::acme".to_string(),
            project_id: None,
            limit: Some(10),
        }),
    )
    .await;
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list = json_body(list_resp).await;
    assert_eq!(list["count"], 1);
    assert_eq!(list["entries"][0]["record"]["command"], "cargo");

    let store = shared.fact_store.read().await;
    let facts = store.query(&corecrux_memory::fact_store::FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some("__workbench__::business::acme::".to_string()),
        top_k: 10,
        token_budget: None,
    });
    assert_eq!(facts.facts.len(), 2);
    assert!(facts.facts.iter().all(|fact| fact.private));
}

#[tokio::test]
async fn workbench_handoff_observations_are_default_off_and_flagged_on() {
    let mut off_state = pro_workbench_state(&["handoff:v2"]);
    bind_test_state_to_root_passport_key(&mut off_state);
    let off_resp = super::workbench::post_handoff_v2(
        State(off_state.clone()),
        HeaderMap::new(),
        Json(super::workbench::HandoffV2Body {
            tenant_id: "business::acme".to_string(),
            goal: "handoff without observation".to_string(),
            session_id: Some("sess-h".to_string()),
            project_id: Some("proj".to_string()),
            source_agent: Some("anthropic".to_string()),
            target_agent: Some("openai".to_string()),
            evidence_refs: Vec::new(),
            next_actions: Vec::new(),
        }),
    )
    .await;
    assert_eq!(off_resp.status(), StatusCode::OK);
    let off_body = json_body(off_resp).await;
    assert!(off_body.get("handoff_observation_id").is_none());
    let obs_path = super::observations::observation_file_path(&off_state.data_dir, "handoff::business::acme::sess-h");
    assert!(!obs_path.exists(), "flag-off handoff must not write observations");

    let mut on_state = pro_workbench_state(&["handoff:v2"]);
    bind_test_state_to_root_passport_key(&mut on_state);
    on_state.handoff_observations_enabled = true;
    let on_resp = super::workbench::post_handoff_v2(
        State(on_state.clone()),
        HeaderMap::new(),
        Json(super::workbench::HandoffV2Body {
            tenant_id: "business::acme".to_string(),
            goal: "handoff with observation".to_string(),
            session_id: Some("sess-h".to_string()),
            project_id: Some("proj".to_string()),
            source_agent: Some("anthropic".to_string()),
            target_agent: Some("openai".to_string()),
            evidence_refs: Vec::new(),
            next_actions: Vec::new(),
        }),
    )
    .await;
    assert_eq!(on_resp.status(), StatusCode::OK);
    let on_body = json_body(on_resp).await;
    assert!(on_body["handoff_observation_id"].as_str().is_some());

    let obs_path = super::observations::observation_file_path(&on_state.data_dir, "handoff::business::acme::sess-h");
    let line = std::fs::read_to_string(obs_path)
        .expect("handoff observation JSONL")
        .lines()
        .next()
        .expect("one handoff observation")
        .to_string();
    let record: serde_json::Value = serde_json::from_str(&line).expect("observation json");
    assert_eq!(record["kind"], "handoff");
    assert_eq!(record["provider"], "crux-handoff");
    assert_eq!(record["principal"], "claude-work");
    assert_eq!(record["payload"]["source_passport"], "claude-work");
    assert_eq!(record["payload"]["target_passport"], "codex-work");
    assert_eq!(record["payload"]["cross_vendor"], true);
}

#[serial_test::serial]
#[tokio::test]
async fn workbench_context_pack_honors_jwt_tenant_binding() {
    const TEST_HS256_SECRET: &str = "0123456789abcdef0123456789abcdef";

    std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
    std::env::remove_var("CORECRUXD_JWT_ISS");
    std::env::remove_var("CORECRUXD_JWT_AUD");
    let mut state = test_app_state_with_auth(16, AuthMode::JwtHs256);
    state.operating_mode = crate::product::OperatingMode::ProHybrid;
    state.enabled_pro_services = vec!["context_pack:budgeted".to_string()];
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &serde_json::json!({
            "sub": "agent-a",
            "scope": "context_pack:budgeted",
            "tenant_id": "business::other",
            "exp": exp,
        }),
        &jsonwebtoken::EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
    )
    .expect("jwt");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).expect("bearer"),
    );

    let resp = super::workbench::post_context_pack(
        State(state),
        headers,
        Json(super::workbench::ContextPackBody {
            tenant_id: "business::acme".to_string(),
            query: "route scope drift".to_string(),
            token_budget: 128,
            include_private: false,
            source_labels: Vec::new(),
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = json_body(resp).await;
    assert_eq!(body["code"], "TENANT_FORBIDDEN");
    assert_eq!(body["tenantId"], "business::acme");
    std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
}

#[tokio::test]
async fn workbench_route_probe_and_api_drift_use_workspace_scan() {
    let state = pro_workbench_state(&["route_probe:lab", "api_drift:check"]);
    let mut scan = crate::workspace_scan::WorkspaceScan::default();
    scan.scan_id = "scan-test".to_string();
    scan.root_path = "/home/myles/CueCrux/Crux".to_string();
    scan.routes.push(crate::workspace_scan::RouteHit {
        method: "POST".to_string(),
        path: "/v1/work".to_string(),
        handler_fn: "post_work".to_string(),
        framework: None,
        handler_file: Some("crates/corecruxd/src/http/work.rs".to_string()),
        handler_line: Some(120),
        source_file: "crates/corecruxd/src/http/mod.rs".to_string(),
        source_line: 430,
    });
    scan.diagnostics
        .unresolved_routes
        .push(crate::workspace_scan::UnresolvedRoute {
            method: "GET".to_string(),
            path: "/v1/generated".to_string(),
            handler_fn: "generated_handler".to_string(),
            source_file: "crates/corecruxd/src/http/mod.rs".to_string(),
            source_line: 999,
            reason: "not_found".to_string(),
        });
    scan.stats.route_count = scan.routes.len();
    scan.stats.routes_by_crate.insert("corecruxd".to_string(), 1);
    state
        .fact_store
        .write()
        .await
        .store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__workspace_scan__::latest".to_string(),
            key: "content".to_string(),
            value: serde_json::to_string(&scan).expect("serialize scan"),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });

    let probe_resp = super::workbench::post_route_probe(
        State(state.clone()),
        HeaderMap::new(),
        Json(super::workbench::RouteProbeBody {
            route: "POST /v1/work".to_string(),
            include_storyline: false,
            include_tests: false,
        }),
    )
    .await;
    assert_eq!(probe_resp.status(), StatusCode::OK);
    let probe = json_body(probe_resp).await;
    assert_eq!(probe["route"]["handler_fn"], "post_work");
    assert!(probe["scope_hints"]
        .as_array()
        .unwrap()
        .iter()
        .any(|scope| scope == "facts:write"));

    let drift_resp = super::workbench::get_api_drift(
        State(state),
        HeaderMap::new(),
        Query(super::workbench::TenantWorkbenchQuery {
            tenant_id: "business::acme".to_string(),
            project_id: None,
            limit: None,
        }),
    )
    .await;
    assert_eq!(drift_resp.status(), StatusCode::OK);
    let drift = json_body(drift_resp).await;
    assert_eq!(drift["status"], "drift_detected");
    assert_eq!(drift["queues"][0]["category"], "unresolved_routes");
    assert_eq!(drift["queues"][0]["count"], 1);
}

#[tokio::test]
async fn workbench_impact_preflight_reports_living_object_drift() {
    let state = pro_workbench_state(&["impact:preflight"]);
    {
        let tenant_hash = corecrux_projections::tenant_hash_xxhash64("business::acme");
        let mut row = corecrux_projections::LivingStateRowV1::default();
        row.living_status = corecrux_projections::LivingStatusV1::Stale;
        row.confidence_q16 = u16::MAX;
        row.dependents_count = 2;
        row.pressure_level = 1;
        state
            .projection_state
            .write()
            .await
            .living
            .insert((tenant_hash, 42), row);
    }

    let resp = super::workbench::post_impact_preflight(
        State(state),
        HeaderMap::new(),
        Json(super::workbench::ImpactPreflightBody {
            tenant_id: "business::acme".to_string(),
            changed_paths: vec!["crates/corecruxd/src/http/replay.rs".to_string()],
            routes: Vec::new(),
            selected_tests: Vec::new(),
            include_storyline: false,
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["preflight"]["living_objects"]["status"], "stale");
    assert_eq!(body["preflight"]["living_objects"]["status_counts"]["stale"], 1);
    assert!(body["preflight"]["living_objects"]["drift_categories"]
        .as_array()
        .unwrap()
        .iter()
        .any(|category| category == "living_state_stale"));
}

#[tokio::test]
async fn workbench_audit_triage_groups_replay_failures() {
    let state = pro_workbench_state(&["audit:triage"]);
    let evidence = {
        let mut store = state.fact_store.write().await;
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "business::acme::doc::answer-source".to_string(),
            key: "summary".to_string(),
            value: "original answer source".to_string(),
            source_receipt: Some("source:receipt".to_string()),
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        })
    };
    let capsule =
        corecrux_memory::replay::AnswerReplayCapsule::build(corecrux_memory::replay::BuildAnswerReplayCapsule {
            answer_id: "answer-a".to_string(),
            tenant_id: "business::acme".to_string(),
            source: "test".to_string(),
            question: "What changed?".to_string(),
            stored_answer: serde_json::json!({"answer": "original answer"}),
            evidence: vec![corecrux_memory::replay::ReplayEvidenceRef {
                record_id: evidence.fact_id.clone(),
                artifact_id: None,
                source_label: Some("fact_store".to_string()),
                text: None,
                text_hash: Some(corecrux_memory::replay::hash_text(&evidence.value)),
                content_hash: None,
                semantic_profile_id: None,
                local_semantic_profile_id: None,
                score_space: None,
                receipt_id: evidence.source_receipt.clone(),
            }],
            projection_refs: Vec::new(),
            source_receipts: vec!["source:receipt".to_string()],
            context_pack_receipt_id: None,
            semantic_profile_id: None,
            local_semantic_profile_id: None,
            created_at: "2026-05-07T00:00:00Z".to_string(),
        });
    super::replay::store_answer_capsule(&state, &capsule)
        .await
        .expect("store replay capsule");
    {
        state
            .fact_store
            .write()
            .await
            .store(corecrux_memory::fact_store::StoreFact {
                tenant_hash: "default".to_string(),
                entity: "business::acme::doc::answer-source".to_string(),
                key: "summary".to_string(),
                value: "updated answer source".to_string(),
                source_receipt: Some("source:receipt:2".to_string()),
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
    }

    let resp = super::workbench::get_audit_triage(
        State(state),
        HeaderMap::new(),
        Query(super::workbench::TenantWorkbenchQuery {
            tenant_id: "business::acme".to_string(),
            project_id: None,
            limit: None,
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let replay_queue = body["queues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|queue| queue["category"] == "replay_failures")
        .expect("replay failure queue");
    assert_eq!(replay_queue["severity"], "medium");
    assert_eq!(replay_queue["count"], 1);
    assert_eq!(replay_queue["items"][0]["answer_id"], "answer-a");
    assert!(replay_queue["items"][0]["categories"]
        .as_array()
        .unwrap()
        .iter()
        .any(|category| category == "fact_superseded"));
}

// Drives the `http::cloud` and `http::gpu1` handlers directly — hosted-surface only (M4).
#[cfg(feature = "hosted-surfaces")]
#[serial_test::serial]
#[tokio::test]
async fn m11_closure_suite_exercises_hybrid_workbench_replay_and_offboarding() {
    std::env::remove_var("CORECRUXD_GPU1_BASE_URL");
    std::env::remove_var("CRUX_GPU1_BASE_URL");
    let mut state = pro_workbench_state(&[
        "context_pack:budgeted",
        "impact:preflight",
        "audit:triage",
        "gpu1:answer",
        "replay:answer",
    ]);
    bind_test_state_to_root_passport_key(&mut state);
    let evidence = {
        let mut store = state.fact_store.write().await;
        let evidence = store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "business::acme::doc::m11-source".to_string(),
            key: "summary".to_string(),
            value: "business::acme closure context for deterministic replay".to_string(),
            source_receipt: Some("m11:source:1".to_string()),
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store_synced(corecrux_memory::fact_store::Fact {
            fact_id: "f_m11_business_mirror".to_string(),
            tenant_hash: "default".to_string(),
            entity: "business::acme::mirror::cloud".to_string(),
            key: "summary".to_string(),
            value: "mirrored business tenant state".to_string(),
            source_receipt: Some("sync:http://cloud:f_m11_business_mirror".to_string()),
            confidence: 1.0,
            stored_at: chrono::Utc::now(),
            tokens: 4,
            deleted: false,
            version: 1,
            supersedes: None,
            private: false,
            horizon_class: corecrux_memory::HorizonClass::None,
            reverified_at: None,
            superseded_by: None,
            actor: None,
            valid_from: None,
            valid_to: None,
            access_count: 0,
            last_accessed_at: None,
        });
        evidence
    };

    let cloud = super::cloud::get_cloud_access_contract(State(state.clone()), HeaderMap::new()).await;
    assert_eq!(cloud.status(), StatusCode::OK);
    let cloud_body = json_body(cloud).await;
    assert_eq!(cloud_body["cloud_only_entitled"], true);
    assert!(cloud_body["pro_claim_placements"]
        .as_array()
        .unwrap()
        .iter()
        .any(|placement| placement["claim"] == "sso:rbac" && placement["implementation"] == "hosted_control_plane"));

    let pack = super::workbench::post_context_pack(
        State(state.clone()),
        HeaderMap::new(),
        Json(super::workbench::ContextPackBody {
            tenant_id: "business::acme".to_string(),
            query: "closure deterministic replay".to_string(),
            token_budget: 256,
            include_private: false,
            source_labels: Vec::new(),
        }),
    )
    .await;
    assert_eq!(pack.status(), StatusCode::OK);
    let pack_body = json_body(pack).await;
    assert_eq!(pack_body["pack"]["items"].as_array().unwrap().len(), 1);

    let answer = super::gpu1::post_gpu1_answer(
        State(state.clone()),
        HeaderMap::new(),
        Json(super::gpu1::Gpu1AnswerRequest {
            tenant_id: "business::acme".to_string(),
            question: "What changed in M11?".to_string(),
            evidence: vec![super::gpu1::Gpu1Evidence {
                record_id: evidence.fact_id.clone(),
                artifact_id: None,
                source_label: Some("local_tenant_index".to_string()),
                text: Some(evidence.value.clone()),
                content_hash: Some(corecrux_memory::replay::hash_text(&evidence.value)),
                semantic_profile_id: None,
                local_semantic_profile_id: None,
                score: Some(1.0),
                score_space: Some("bm25_lexical".to_string()),
                receipt_id: evidence.source_receipt.clone(),
            }],
            token_budget: Some(256),
            semantic_profile_id: None,
            local_semantic_profile_id: None,
            context_pack_receipt_id: pack_body["receipt"]["receipt_id"].as_str().map(str::to_string),
            options: serde_json::Value::Null,
        }),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::OK);
    let answer_body = json_body(answer).await;
    let answer_id = answer_body["answer_replay"]["answer_id"]
        .as_str()
        .expect("answer id")
        .to_string();
    assert!(answer_body["answer_replay"]["validity_path"]
        .as_str()
        .unwrap()
        .contains(&answer_id));

    state
        .fact_store
        .write()
        .await
        .store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: evidence.entity.clone(),
            key: evidence.key.clone(),
            value: "business::acme closure context changed after answer".to_string(),
            source_receipt: Some("m11:source:2".to_string()),
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
    let triage = super::workbench::get_audit_triage(
        State(state.clone()),
        HeaderMap::new(),
        Query(super::workbench::TenantWorkbenchQuery {
            tenant_id: "business::acme".to_string(),
            project_id: None,
            limit: None,
        }),
    )
    .await;
    assert_eq!(triage.status(), StatusCode::OK);
    let triage_body = json_body(triage).await;
    let replay_queue = triage_body["queues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|queue| queue["category"] == "replay_failures")
        .expect("replay failure queue");
    assert_eq!(replay_queue["count"], 1);

    let offboard = super::sync::post_tenant_offboard(
        State(state.clone()),
        HeaderMap::new(),
        Path("business::acme".to_string()),
        Json(super::sync::OffboardRequest { membership_epoch: 11 }),
    )
    .await;
    assert_eq!(offboard.status(), StatusCode::OK);
    let offboard_body = json_body(offboard).await;
    assert_eq!(offboard_body["deleted_fact_ids"][0], "f_m11_business_mirror");
    assert_eq!(offboard_body["signed_by"], state.passport_fpr);
}

#[tokio::test]
async fn workbench_policy_simulation_blocks_matching_critical_constraint() {
    let state = pro_workbench_state(&["policy:simulate"]);
    state
        .fact_store
        .write()
        .await
        .store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__constraints__::business::acme::no-prod-deploy".to_string(),
            key: "constraint".to_string(),
            value: serde_json::json!({
                "constraint_id": "no-prod-deploy",
                "assertion": "No production deploy for business::acme without approval",
                "severity": "critical",
                "status": "active"
            })
            .to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });

    let resp = super::workbench::post_policy_simulation(
        State(state),
        HeaderMap::new(),
        Json(super::workbench::PolicySimulationBody {
            action: corecrux_memory::action_enrichment::ActionEnrichmentInput {
                tenant_id: Some("business::acme".to_string()),
                tool_name: "github.deploy_production".to_string(),
                tool_parameters: serde_json::json!({
                    "environment": "production",
                    "service": "api"
                }),
                action_description: Some("Deploy production API for business::acme".to_string()),
                include_first_party_enrichers: false,
            },
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["simulation"]["verdict"], "block");
    assert_eq!(
        body["simulation"]["matched_constraints"][0]["constraint_id"],
        "no-prod-deploy"
    );
    assert!(body["receipt"]["receipt_id"]
        .as_str()
        .unwrap()
        .starts_with("workbench:policy_simulation:"));
}

// Exercises the `http::gpu1` handler directly — hosted-surface only (M4).
#[cfg(feature = "hosted-surfaces")]
#[serial_test::serial]
#[tokio::test]
async fn gpu1_contract_reports_enabled_degraded_without_endpoint() {
    std::env::remove_var("CORECRUXD_GPU1_BASE_URL");
    std::env::remove_var("CRUX_GPU1_BASE_URL");
    std::env::remove_var("CORECRUXD_GPU1_API_KEY");
    std::env::remove_var("CRUX_GPU1_API_KEY");
    let mut state = test_app_state(16);
    state.operating_mode = crate::product::OperatingMode::ProHybrid;
    state.enabled_pro_services = vec!["gpu1:coverage".to_string(), "gpu1:developer".to_string()];

    let resp = super::gpu1::get_gpu1_contract(State(state), HeaderMap::new()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    assert_eq!(body["schema"], super::gpu1::GPU1_COMPUTE_CONTRACT_SCHEMA);
    assert_eq!(body["endpoint_configured"], false);
    assert_eq!(body["remote_memory_sync_required"], false);
    assert!(body["enabled_services"]
        .as_array()
        .unwrap()
        .iter()
        .any(|service| service == "gpu1:developer"));
    assert!(body["services"].as_array().unwrap().iter().any(|service| {
        service["operation"] == "coverage"
            && service["status"] == "enabled_degraded_not_configured"
            && service["local_path"] == "/v1/gpu1/coverage"
            && service["remote_path"] == "/v1/query/coverage"
    }));
}

// Exercises the `http::gpu1` handler directly — hosted-surface only (M4).
#[cfg(feature = "hosted-surfaces")]
#[tokio::test]
async fn gpu1_answer_requires_enabled_pro_service() {
    let state = test_app_state(16);
    let resp = super::gpu1::post_gpu1_answer(
        State(state),
        HeaderMap::new(),
        Json(super::gpu1::Gpu1AnswerRequest {
            tenant_id: "tenant-a".to_string(),
            question: "What changed?".to_string(),
            evidence: Vec::new(),
            token_budget: None,
            semantic_profile_id: None,
            local_semantic_profile_id: None,
            context_pack_receipt_id: None,
            options: serde_json::Value::Null,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let body = json_body(resp).await;
    assert_eq!(body["status"], "pro_service_not_enabled");
    assert_eq!(body["remote_memory_sync_required"], false);
}

// Exercises the `http::gpu1` handler directly — hosted-surface only (M4).
#[cfg(feature = "hosted-surfaces")]
#[serial_test::serial]
#[tokio::test]
async fn gpu1_answer_falls_back_without_endpoint_and_stores_private_receipt() {
    std::env::remove_var("CORECRUXD_GPU1_BASE_URL");
    std::env::remove_var("CRUX_GPU1_BASE_URL");
    let mut state = test_app_state(16);
    state.operating_mode = crate::product::OperatingMode::ProHybrid;
    state.enabled_pro_services = vec!["gpu1:answer".to_string()];
    let shared = state.clone();

    let resp = super::gpu1::post_gpu1_answer(
        State(state),
        HeaderMap::new(),
        Json(super::gpu1::Gpu1AnswerRequest {
            tenant_id: "tenant-a".to_string(),
            question: "What changed?".to_string(),
            evidence: vec![super::gpu1::Gpu1Evidence {
                record_id: "r1".to_string(),
                artifact_id: None,
                source_label: Some("local_tenant_index".to_string()),
                text: Some("The route changed auth scopes.".to_string()),
                content_hash: Some("blake3:test".to_string()),
                semantic_profile_id: None,
                local_semantic_profile_id: Some("sp_local".to_string()),
                score: Some(1.0),
                score_space: Some("bm25_lexical".to_string()),
                receipt_id: Some("rcpt_1".to_string()),
            }],
            token_budget: Some(512),
            semantic_profile_id: None,
            local_semantic_profile_id: Some("sp_local".to_string()),
            context_pack_receipt_id: Some("ctx_1".to_string()),
            options: serde_json::Value::Null,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["mode"], "local_fallback");
    assert_eq!(body["fallback"]["reason_code"], "gpu1_not_configured");
    assert_eq!(body["remote_memory_sync_required"], false);
    assert_eq!(body["receipts"]["request"]["remote_memory_sync_required"], false);
    assert_eq!(
        body["receipts"]["context_pack"]["event_type"],
        "gpu1_local_context_pack"
    );
    let answer_id = body["answer_replay"]["answer_id"].as_str().expect("answer id");
    assert!(answer_id.starts_with("ans_"));
    assert_eq!(body["answer_replay"]["agent_required"], false);
    assert_eq!(body["answer_replay"]["llm_required"], false);

    let store = shared.fact_store.read().await;
    let receipts = store.get_by_entity("__gpu1_receipt__::tenant-a::answer");
    assert_eq!(receipts.len(), 1);
    assert!(receipts[0].private);
    assert_eq!(receipts[0].key, "receipt_bundle");
    let capsules = store.get_by_entity(&format!("__answer_replay_capsule__::tenant-a::{answer_id}"));
    assert_eq!(capsules.len(), 1);
    assert!(capsules[0].private);
    assert_eq!(capsules[0].key, "capsule");
}

// Uses the `http::gpu1` answer handler to seed the replay capsule — hosted-surface only (M4).
#[cfg(feature = "hosted-surfaces")]
#[serial_test::serial]
#[tokio::test]
async fn answer_replay_renders_stored_answer_and_validity_detects_superseded_evidence() {
    std::env::remove_var("CORECRUXD_GPU1_BASE_URL");
    std::env::remove_var("CRUX_GPU1_BASE_URL");
    let mut state = test_app_state(16);
    state.operating_mode = crate::product::OperatingMode::ProHybrid;
    state.enabled_pro_services = vec!["gpu1:answer".to_string(), "replay:answer".to_string()];
    let evidence_fact = state
        .fact_store
        .write()
        .await
        .store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "tenant-a::doc::route-scope".to_string(),
            key: "content".to_string(),
            value: "The route changed auth scopes.".to_string(),
            source_receipt: Some("rcpt_1".to_string()),
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

    let resp = super::gpu1::post_gpu1_answer(
        State(state.clone()),
        HeaderMap::new(),
        Json(super::gpu1::Gpu1AnswerRequest {
            tenant_id: "tenant-a".to_string(),
            question: "What changed?".to_string(),
            evidence: vec![super::gpu1::Gpu1Evidence {
                record_id: evidence_fact.fact_id.clone(),
                artifact_id: Some(42),
                source_label: Some("local_tenant_index".to_string()),
                text: Some(evidence_fact.value.clone()),
                content_hash: Some(corecrux_memory::replay::hash_text(&evidence_fact.value)),
                semantic_profile_id: None,
                local_semantic_profile_id: Some("sp_local".to_string()),
                score: Some(1.0),
                score_space: Some("bm25_lexical".to_string()),
                receipt_id: evidence_fact.source_receipt.clone(),
            }],
            token_budget: Some(512),
            semantic_profile_id: None,
            local_semantic_profile_id: Some("sp_local".to_string()),
            context_pack_receipt_id: Some("ctx_1".to_string()),
            options: serde_json::Value::Null,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let answer_id = body["answer_replay"]["answer_id"]
        .as_str()
        .expect("answer id")
        .to_string();

    let replay = super::replay::get_answer_replay(
        State(state.clone()),
        Path(answer_id.clone()),
        Query(super::replay::ReplayQuery {
            tenant_id: "tenant-a".to_string(),
            shard_id: None,
        }),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::OK);
    let replay_body = json_body(replay).await;
    assert_eq!(replay_body["agent_required"], false);
    assert_eq!(replay_body["llm_required"], false);
    assert!(replay_body["rendered_answer"]
        .as_str()
        .unwrap()
        .contains("GPU-1 answer unavailable"));
    assert_eq!(replay_body["evidence"][0]["text"], "The route changed auth scopes.");

    state
        .fact_store
        .write()
        .await
        .store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: evidence_fact.entity.clone(),
            key: evidence_fact.key.clone(),
            value: "The route changed auth scopes and tenant checks.".to_string(),
            source_receipt: Some("rcpt_2".to_string()),
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
    let tenant_hash = corecrux_projections::tenant_hash_xxhash64("tenant-a");
    let dependent_id = uuid::Uuid::new_v4();
    let pressure_id = uuid::Uuid::new_v4();
    {
        let mut projection = state.projection_state.write().await;
        projection.living.insert(
            (tenant_hash, 42),
            corecrux_projections::LivingStateRowV1 {
                living_status: corecrux_projections::LivingStatusV1::Stale,
                confidence_q16: corecrux_projections::quantize_confidence_q16(0.72),
                updated_at_micros: 1_000_000,
                dependents_count: 1,
                ..Default::default()
            },
        );
        projection.relations.insert(
            (
                tenant_hash,
                42,
                43,
                corecrux_projections::RelationTypeV1::Contradicts.to_u8(),
            ),
            corecrux_projections::RelationEdgeV1 {
                confidence_q16: corecrux_projections::quantize_confidence_q16(0.9),
                evidence_ref_hash16: [7u8; 16],
                created_at_micros: 1_000_000,
                updated_at_micros: 2_000_000,
            },
        );
        projection.dependents.insert(
            (
                tenant_hash,
                42,
                corecrux_projections::DependentTypeV1::Answer.to_u8(),
                dependent_id,
            ),
            corecrux_projections::DependentEdgeV1 {
                last_seen_at_micros: 2_000_000,
                usage_weight_q16: corecrux_projections::quantize_confidence_q16(0.8),
            },
        );
        projection.pressure.insert(
            (tenant_hash, 42, pressure_id),
            corecrux_projections::PressureEventRowV1 {
                pressure_code_id: corecrux_projections::pressure_code_id_xxhash16("stale_answer"),
                severity: 2,
                observed_at_micros: 2_000_000,
                acknowledged_at_micros: 0,
                resolved_at_micros: 0,
                receipt_id: None,
            },
        );
    }

    let validity = super::replay::get_answer_replay_validity(
        State(state),
        Path(answer_id),
        Query(super::replay::ReplayQuery {
            tenant_id: "tenant-a".to_string(),
            shard_id: None,
        }),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(validity.status(), StatusCode::OK);
    let validity_body = json_body(validity).await;
    assert_eq!(validity_body["overall"], "drift_detected");
    assert_eq!(validity_body["historical_answer"]["status"], "verified");
    assert_eq!(validity_body["current_answer"]["status"], "stale");
    assert_eq!(validity_body["evidence"][0]["status"], "superseded");
    let categories = validity_body["current_answer"]["drift_categories"].as_array().unwrap();
    assert!(categories.iter().any(|category| category == "fact_superseded"));
    assert!(categories.iter().any(|category| category == "living_state_stale"));
    assert!(categories.iter().any(|category| category == "relation_contradicts"));
    assert!(categories.iter().any(|category| category == "pressure_open"));
    assert_eq!(validity_body["living_objects"]["status"], "stale");
    assert_eq!(
        validity_body["living_objects"]["affected_downstream_projections"]["dependent_count"],
        1
    );
    assert_eq!(
        validity_body["living_objects"]["artifacts"][0]["downstream_dependents"][0]["dependent_type"],
        "answer"
    );
    assert_eq!(validity_body["projection_modules"]["status"], "current");
    assert_eq!(validity_body["projection_modules"]["refs"].as_array().unwrap().len(), 4);
    assert!(validity_body["projection_modules"]["refs"][0]["schema_version"]
        .as_u64()
        .is_some());
    assert!(
        validity_body["projection_modules"]["refs"][0]["projection_registry_hash"]
            .as_str()
            .unwrap()
            .starts_with("blake3:")
    );
    assert_eq!(validity_body["historical_replay_available"], true);
}

// Uses the `http::gpu1` answer handler to seed the replay capsule — hosted-surface only (M4).
#[cfg(feature = "hosted-surfaces")]
#[serial_test::serial]
#[tokio::test]
async fn answer_replay_export_uses_local_capsule_without_dataplane() {
    std::env::remove_var("CORECRUXD_GPU1_BASE_URL");
    std::env::remove_var("CRUX_GPU1_BASE_URL");
    let mut state = test_app_state(16);
    state.operating_mode = crate::product::OperatingMode::ProHybrid;
    state.enabled_pro_services = vec!["gpu1:answer".to_string(), "replay:answer".to_string()];

    let resp = super::gpu1::post_gpu1_answer(
        State(state.clone()),
        HeaderMap::new(),
        Json(super::gpu1::Gpu1AnswerRequest {
            tenant_id: "tenant-a".to_string(),
            question: "What changed?".to_string(),
            evidence: Vec::new(),
            token_budget: Some(512),
            semantic_profile_id: None,
            local_semantic_profile_id: None,
            context_pack_receipt_id: None,
            options: serde_json::Value::Null,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let answer_id = body["answer_replay"]["answer_id"]
        .as_str()
        .expect("answer id")
        .to_string();

    let export = super::receipts::get_answer_export_v1(
        State(state),
        Path(answer_id),
        Query(super::receipts::SubjectExportQueryV1 {
            tenant_id: "tenant-a".to_string(),
            mode: None,
            include: None,
            redaction: Some("metadata_only".to_string()),
            format: Some("zip".to_string()),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(export.status(), StatusCode::OK);
    assert_eq!(export.headers().get(header::CONTENT_TYPE).unwrap(), "application/zip");
    let bytes = to_bytes(export.into_body(), 1_048_576).await.expect("zip body");
    assert!(bytes.starts_with(b"PK"));
}

// Exercises the `http::gpu1` handler directly — hosted-surface only (M4).
#[cfg(feature = "hosted-surfaces")]
#[serial_test::serial]
#[tokio::test]
async fn gpu1_coverage_local_fallback_is_deterministic() {
    std::env::remove_var("CORECRUXD_GPU1_BASE_URL");
    std::env::remove_var("CRUX_GPU1_BASE_URL");
    let mut state = test_app_state(16);
    state.operating_mode = crate::product::OperatingMode::ProHybrid;
    state.enabled_pro_services = vec!["gpu1:coverage".to_string()];

    let resp = super::gpu1::post_gpu1_coverage(
        State(state),
        HeaderMap::new(),
        Json(super::gpu1::Gpu1CoverageRequest {
            tenant_id: "tenant-a".to_string(),
            query: "route scopes receipts".to_string(),
            evidence: vec![super::gpu1::Gpu1Evidence {
                record_id: "r1".to_string(),
                artifact_id: None,
                source_label: None,
                text: Some("route receipts".to_string()),
                content_hash: None,
                semantic_profile_id: None,
                local_semantic_profile_id: None,
                score: None,
                score_space: None,
                receipt_id: None,
            }],
            coverage_floor: Some(0.8),
            semantic_profile_id: None,
            local_semantic_profile_id: None,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["mode"], "local_fallback");
    assert_eq!(body["result"]["coverage_model"], "local_lexical_fallback");
    assert_eq!(body["result"]["missing_terms"], serde_json::json!(["scopes"]));
}

#[serial_test::serial]
#[tokio::test]
async fn version_endpoint_reports_semantic_profile_when_embeddings_configured() {
    std::env::remove_var("CORECRUXD_SYNC_ENABLED");
    std::env::remove_var("CORECRUXD_SYNC_REMOTE_URL");
    std::env::remove_var("CORECRUXD_SYNC_API_KEY");
    let state = test_app_state(16);
    state
        .fact_store
        .write()
        .await
        .set_embedding_client(corecrux_memory::embeddings::EmbeddingClient::new(
            corecrux_memory::embeddings::EmbeddingConfig {
                base_url: "http://localhost:11434".to_string(),
                model: "nomic-embed-text".to_string(),
                dimensions: 768,
            },
        ));

    let resp = get_version(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    assert_eq!(body["semantic_profile"]["schema"], "cuecrux.semantic_profile.v1");
    assert_eq!(body["semantic_profile"]["model"], "nomic-embed-text");
    assert_eq!(body["semantic_profile"]["dimensions"], 768);
    assert!(body["semantic_profile"]["profile_id"]
        .as_str()
        .unwrap_or_default()
        .starts_with("sp_"));
    assert_eq!(
        body["protocol_contracts"]["semantic_profile_contract"]["status"],
        "partial"
    );
}

#[tokio::test]
async fn segment_fingerprints_reports_cpu_only_retrieval_posture() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let headers = dev_scope_headers("admin:read");

    let resp = get_segment_fingerprints(State(state), headers).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    assert_eq!(body["schema"], "crux.admin.segment_fingerprints.v1");
    assert_eq!(body["contract"], "corecrux.retrieval.v6.fingerprinted_segments");
    assert_eq!(body["status"], "partial");
    assert_eq!(body["cpu_only"], true);
    assert_eq!(body["segments"]["count"], 0);
    assert_eq!(body["segments"]["total_docs"], 0);
    assert_eq!(body["fingerprint_guard"]["mode"], "not_enforced");
    assert!(body["semantic_profile"].is_null());
    assert!(body["embedding_fingerprint"].is_null());
}

#[tokio::test]
async fn segment_fingerprints_includes_semantic_profile_when_configured() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    state
        .fact_store
        .write()
        .await
        .set_embedding_client(corecrux_memory::embeddings::EmbeddingClient::new(
            corecrux_memory::embeddings::EmbeddingConfig {
                base_url: "http://localhost:11434".to_string(),
                model: "nomic-embed-text".to_string(),
                dimensions: 768,
            },
        ));
    let headers = dev_scope_headers("admin:read");

    let resp = get_segment_fingerprints(State(state), headers).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    assert_eq!(body["semantic_profile"]["schema"], "cuecrux.semantic_profile.v1");
    assert_eq!(
        body["embedding_fingerprint"]["schema"],
        "cuecrux.embedding_fingerprint.v1"
    );
    assert_eq!(body["semantic_profile_id"], body["semantic_profile"]["profile_id"]);
}

#[tokio::test]
async fn console_onboarding_get_returns_default_state() {
    let state = test_app_state(16);
    let resp = console::get_console_onboarding(State(state)).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["completed_at_unix_ms"].is_null());
    assert!(body["chosen_auth_mode"].is_null());
    assert_eq!(body["bind_is_loopback"], true);
    assert_eq!(body["allow_insecure_dev_auth_bind"], false);
    assert_eq!(body["running_auth_mode"], "off");
}

#[tokio::test]
async fn console_onboarding_complete_persists_and_marks_restart_required() {
    let state = test_app_state(16);
    let resp = console::post_console_onboarding_complete(
        State(state.clone()),
        HeaderMap::new(),
        Json(console::CompleteOnboardingBody {
            auth_mode: "dev_scopes".to_string(),
            hide_onboarding: true,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["chosen_auth_mode"], "dev_scopes");
    assert_eq!(body["restart_required"], true);
    assert!(body["completed_at_unix_ms"].is_u64());

    // Persisted to disk and reloads correctly.
    let reloaded = crate::onboarding::read_state(&state.data_dir).expect("reload settings");
    assert_eq!(reloaded.chosen_auth_mode.as_deref(), Some("dev_scopes"));
    assert!(reloaded.completed_at_unix_ms.is_some());
}

#[tokio::test]
async fn console_onboarding_complete_rejects_unknown_auth_mode() {
    let state = test_app_state(16);
    let resp = console::post_console_onboarding_complete(
        State(state),
        HeaderMap::new(),
        Json(console::CompleteOnboardingBody {
            auth_mode: "magical".to_string(),
            hide_onboarding: false,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn console_onboarding_complete_refuses_off_on_non_loopback() {
    let mut state = test_app_state(16);
    state.http_bind_loopback = false;
    state.allow_insecure_dev_auth_bind = false;
    let resp = console::post_console_onboarding_complete(
        State(state),
        HeaderMap::new(),
        Json(console::CompleteOnboardingBody {
            auth_mode: "off".to_string(),
            hide_onboarding: true,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn console_onboarding_complete_allows_off_when_insecure_bind_overridden() {
    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    state.http_bind_loopback = false;
    state.allow_insecure_dev_auth_bind = true;
    let resp = console::post_console_onboarding_complete(
        State(state),
        dev_scope_headers("admin:write"),
        Json(console::CompleteOnboardingBody {
            auth_mode: "off".to_string(),
            hide_onboarding: false,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn onboarding_complete_is_first_run_only_without_admin_write() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut current = state.onboarding.write().await;
        current.completed_at_unix_ms = Some(123);
        current.chosen_auth_mode = Some("dev_scopes".to_string());
        crate::onboarding::write_state(&state.data_dir, &current).expect("seed write");
    }
    let resp = console::post_console_onboarding_complete(
        State(state.clone()),
        dev_scope_headers("admin:read"),
        Json(console::CompleteOnboardingBody {
            auth_mode: "jwt_hs256".to_string(),
            hide_onboarding: true,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let reloaded = crate::onboarding::read_state(&state.data_dir).expect("reload settings");
    assert_eq!(reloaded.chosen_auth_mode.as_deref(), Some("dev_scopes"));
    assert_eq!(reloaded.completed_at_unix_ms, Some(123));
}

#[tokio::test]
async fn console_fact_add_then_search_round_trip() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    // Add via console endpoint.
    let add_resp = console::post_console_fact_add(
        State(state.clone()),
        dev_scope_headers("facts:write"),
        Json(console::ConsoleAddFactBody {
            entity: "personal::project".to_string(),
            key: "favourite_colour".to_string(),
            value: "ultraviolet".to_string(),
            confidence: 0.9,
        }),
    )
    .await
    .into_response();
    assert_eq!(add_resp.status(), StatusCode::CREATED);

    // Search returns the same fact.
    let search_resp = console::get_console_facts(
        State(state),
        Query(console::ConsoleFactsQuery {
            q: Some("ultraviolet".to_string()),
            top_k: Some(10),
            as_of_unix_ms: None,
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(search_resp.status(), StatusCode::OK);
    let body = json_body(search_resp).await;
    assert_eq!(body["query"], "ultraviolet");
    let facts = body["facts"].as_array().expect("facts array");
    assert!(
        facts
            .iter()
            .any(|f| f["value"] == "ultraviolet" && f["entity"] == "personal::project"),
        "expected newly added fact in search results: {body}"
    );
}

#[tokio::test]
async fn console_fact_add_requires_facts_write_scope() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::post_console_fact_add(
        State(state.clone()),
        dev_scope_headers("admin:read"),
        Json(console::ConsoleAddFactBody {
            entity: "x".to_string(),
            key: "y".to_string(),
            value: "z".to_string(),
            confidence: 1.0,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp_anon = console::post_console_fact_add(
        State(state),
        HeaderMap::new(),
        Json(console::ConsoleAddFactBody {
            entity: "x".to_string(),
            key: "y".to_string(),
            value: "z".to_string(),
            confidence: 1.0,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp_anon.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn console_fact_add_validates_inputs() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    for (entity, key, value, confidence, label) in [
        ("", "k", "v", 1.0, "empty entity"),
        ("e", "", "v", 1.0, "empty key"),
        ("e", "k", "", 1.0, "empty value"),
        ("e", "k", "v", -0.1, "confidence too low"),
        ("e", "k", "v", 1.1, "confidence too high"),
    ] {
        let resp = console::post_console_fact_add(
            State(state.clone()),
            dev_scope_headers("facts:write"),
            Json(console::ConsoleAddFactBody {
                entity: entity.to_string(),
                key: key.to_string(),
                value: value.to_string(),
                confidence,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "expected 400 for {label}");
    }
}

#[tokio::test]
async fn console_tenants_classify_by_prefix_and_filter() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut facts = state.fact_store.write().await;
        for entity in [
            "personal::notes::status",
            "work::team::status",
            "public::release::status",
            "myproject::status", // unknown prefix → work (default flipped by ExecPlan crux-tenant-category-model-2026-05-22)
        ] {
            facts.store(corecrux_memory::fact_store::StoreFact {
                tenant_hash: "default".to_string(),
                entity: entity.to_string(),
                key: "x".to_string(),
                value: "v".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }
    }

    // Default: all tenants returned with category field.
    let resp = console::get_console_tenants(
        State(state.clone()),
        Query(console::ConsoleTenantsQuery { category: None }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let tenants = body["tenants"].as_array().expect("tenants");
    let with_cat = |id: &str| -> &str {
        tenants
            .iter()
            .find(|t| t["tenant_id"] == id)
            .and_then(|t| t["category"].as_str())
            .unwrap_or("MISSING")
    };
    assert_eq!(with_cat("personal"), "personal");
    assert_eq!(with_cat("work"), "work");
    assert_eq!(with_cat("public"), "public");
    // Default flipped to "work" by ExecPlan crux-tenant-category-model-2026-05-22:
    // any tenant id without an explicit personal::/work::/public:: prefix that
    // also isn't a __system__:: prefix lands in Work.
    assert_eq!(with_cat("myproject"), "work");
    assert_eq!(with_cat("local"), "work");

    // ?category=work → only work tenants.
    let resp = console::get_console_tenants(
        State(state.clone()),
        Query(console::ConsoleTenantsQuery {
            category: Some("work".to_string()),
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    let body = json_body(resp).await;
    let only_work = body["tenants"].as_array().expect("tenants");
    assert!(!only_work.is_empty());
    for t in only_work {
        assert_eq!(t["category"], "work");
    }

    // ?category=bogus → 400.
    let resp = console::get_console_tenants(
        State(state),
        Query(console::ConsoleTenantsQuery {
            category: Some("bogus".to_string()),
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── ExecPlan crux-tenant-category-model-2026-05-22 M2 ────────────────────
// GET/PATCH /v1/console/tenants/:tenant/category — override layer for the
// derived classification. System category not user-settable; system-prefix
// tenant ids not overridable.

#[tokio::test]
async fn console_tenant_category_get_returns_derived_when_no_override() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::get_console_tenant_category(
        State(state),
        axum::extract::Path("execplan".to_string()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["tenant_id"], "execplan");
    // Default-flipped-to-work + no override = derived & effective both "work".
    assert_eq!(body["derived"], "work");
    assert_eq!(body["effective"], "work");
    assert!(body["override"].is_null());
}

#[tokio::test]
async fn console_tenant_category_patch_sets_override_then_get_reflects_it() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    // Seed at least one entity under the "execplan" prefix so it gets
    // enumerated by `get_console_tenants` (which builds the tenant list from
    // stored entity prefixes). The override alone is stored at
    // `__tenant_metadata__::execplan` and would otherwise not surface
    // "execplan" in the list.
    {
        let mut facts = state.fact_store.write().await;
        facts.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "execplan::foo".to_string(),
            key: "x".to_string(),
            value: "v".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
    }
    // PATCH to "personal"
    let resp = console::patch_console_tenant_category(
        State(state.clone()),
        axum::extract::Path("execplan".to_string()),
        dev_scope_headers("admin:write"),
        Json(crate::tenant_metadata::PatchTenantCategoryBody {
            category: "personal".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["derived"], "work");
    assert_eq!(body["override"], "personal");
    assert_eq!(body["effective"], "personal");

    // GET reflects it
    let resp = console::get_console_tenant_category(
        State(state.clone()),
        axum::extract::Path("execplan".to_string()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    let body = json_body(resp).await;
    assert_eq!(body["override"], "personal");
    assert_eq!(body["effective"], "personal");

    // The override also flows through /v1/console/tenants list
    let resp = console::get_console_tenants(
        State(state),
        Query(console::ConsoleTenantsQuery { category: None }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    let body = json_body(resp).await;
    let row = body["tenants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tenant_id"] == "execplan")
        .expect("execplan present once it has an override");
    assert_eq!(row["category"], "personal");
    assert_eq!(row["override"], "personal");
}

#[tokio::test]
async fn console_tenant_category_patch_rejects_system_category() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::patch_console_tenant_category(
        State(state),
        axum::extract::Path("execplan".to_string()),
        dev_scope_headers("admin:write"),
        Json(crate::tenant_metadata::PatchTenantCategoryBody {
            category: "system".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn console_tenant_category_patch_rejects_system_prefix_target() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::patch_console_tenant_category(
        State(state),
        axum::extract::Path("__bootstrap__".to_string()),
        dev_scope_headers("admin:write"),
        Json(crate::tenant_metadata::PatchTenantCategoryBody {
            category: "work".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn console_tenant_category_patch_rejects_invalid_category_string() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::patch_console_tenant_category(
        State(state),
        axum::extract::Path("execplan".to_string()),
        dev_scope_headers("admin:write"),
        Json(crate::tenant_metadata::PatchTenantCategoryBody {
            category: "rubbish".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn console_tenant_category_patch_requires_admin_write_scope() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    // dev_scope_headers("admin:read") is the read scope; PATCH should reject.
    let resp = console::patch_console_tenant_category(
        State(state),
        axum::extract::Path("execplan".to_string()),
        dev_scope_headers("admin:read"),
        Json(crate::tenant_metadata::PatchTenantCategoryBody {
            category: "personal".to_string(),
        }),
    )
    .await
    .into_response();
    // Insufficient scope → 403 from require_http_scopes.
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── ExecPlan crux-tenant-category-model-2026-05-22 M3 ────────────────────
// Write-side passport-category enforcement on /v1/facts, /v1/facts/bulk,
// /v1/console/facts/add. System category exempt; no-passport bypass for
// console-bridge envelope; passport.category must match entity effective
// category.

#[tokio::test]
async fn put_fact_personal_passport_blocked_on_work_entity() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let body = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: "work::team::status".to_string(),
        key: "x".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    let resp = facts::put_fact(
        State(state),
        dev_scope_passport_headers("facts:write", "personal-default"),
        Json(body),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn put_fact_work_passport_allowed_on_work_entity() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let body = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: "work::team::status".to_string(),
        key: "x".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    let resp = facts::put_fact(
        State(state),
        dev_scope_passport_headers("facts:write", "work-default"),
        Json(body),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn put_fact_personal_passport_blocked_on_untagged_entity_post_default_flip() {
    // Untagged entity → default Work; personal passport blocked.
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let body = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: "execplan::foo".to_string(),
        key: "x".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    let resp = facts::put_fact(
        State(state),
        dev_scope_passport_headers("facts:write", "personal-default"),
        Json(body),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn put_fact_no_passport_id_header_bypasses_enforcement() {
    // Console-bridge envelope: scope present but no passport-id header.
    // The check has nothing per-passport to gate; route-level access already
    // satisfied; write goes through.
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let body = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: "work::team::status".to_string(),
        key: "x".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    let resp = facts::put_fact(State(state), dev_scope_headers("admin:write"), Json(body))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn put_fact_system_entity_exempt_from_passport_category() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let body = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: "__bootstrap__::seed".to_string(),
        key: "x".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    // personal-default writing a __bootstrap__:: system entity must succeed.
    let resp = facts::put_fact(
        State(state),
        dev_scope_passport_headers("facts:write", "personal-default"),
        Json(body),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn put_fact_unknown_passport_id_rejected_as_legacy() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let body = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: "work::team::status".to_string(),
        key: "x".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    let resp = facts::put_fact(
        State(state),
        dev_scope_passport_headers("facts:write", "not-a-real-passport"),
        Json(body),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn put_facts_bulk_rejects_when_any_entity_violates_category() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let bulk = vec![
        corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "personal::a".to_string(),
            key: "x".to_string(),
            value: "1".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        },
        // This second entity is Work; personal-default cannot write it →
        // the entire bulk is refused.
        corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "work::b".to_string(),
            key: "x".to_string(),
            value: "1".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        },
    ];
    let resp = facts::put_facts_bulk(
        State(state),
        dev_scope_passport_headers("facts:write", "personal-default"),
        Json(bulk),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn console_fact_add_personal_passport_blocked_on_work_entity() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let body = console::ConsoleAddFactBody {
        entity: "work::team".to_string(),
        key: "x".to_string(),
        value: "v".to_string(),
        confidence: 1.0,
    };
    let resp = console::post_console_fact_add(
        State(state),
        dev_scope_passport_headers("facts:write", "personal-default"),
        Json(body),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn console_fact_add_override_to_personal_lets_personal_passport_write_again() {
    // After the operator overrides a tenant to Personal via the M2 PATCH
    // endpoint, a personal passport can write entities under it again, and
    // a work passport is blocked.
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    // PATCH: myproject → personal
    let _ = console::patch_console_tenant_category(
        State(state.clone()),
        axum::extract::Path("myproject".to_string()),
        dev_scope_headers("admin:write"),
        Json(crate::tenant_metadata::PatchTenantCategoryBody {
            category: "personal".to_string(),
        }),
    )
    .await
    .into_response();
    // personal-default writes myproject::foo → allowed (overridden to Personal)
    let body = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: "myproject::foo".to_string(),
        key: "x".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    let resp = facts::put_fact(
        State(state.clone()),
        dev_scope_passport_headers("facts:write", "personal-default"),
        Json(body),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED, "personal can write after override");
    // work-default writes myproject::bar → blocked now
    let body = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: "myproject::bar".to_string(),
        key: "x".to_string(),
        value: "v".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    let resp = facts::put_fact(
        State(state),
        dev_scope_passport_headers("facts:write", "work-default"),
        Json(body),
    )
    .await
    .into_response();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "work blocked after override to personal"
    );
}

#[tokio::test]
async fn console_settings_get_returns_running_and_chosen_state() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::get_console_settings(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["auth"]["running_mode"], "dev_scopes");
    assert!(body["embedding"]["active"].is_boolean());
    assert!(body["onboarding"]["completed_at_unix_ms"].is_null());
}

#[tokio::test]
async fn console_settings_put_persists_choices_and_flags_restart() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::put_console_settings(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(console::UpdateSettingsBody {
            auth_mode: Some("jwt_hs256".to_string()),
            embedding_enabled: Some(true),
            embedding_url: Some("http://localhost:11434".to_string()),
            embedding_model: Some("nomic-embed-text".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["restart_required"], true);
    assert_eq!(body["saved"]["chosen_auth_mode"], "jwt_hs256");
    assert_eq!(body["saved"]["chosen_embedding_url"], "http://localhost:11434");

    let reloaded = crate::onboarding::read_state(&state.data_dir).expect("reload");
    assert_eq!(reloaded.chosen_auth_mode.as_deref(), Some("jwt_hs256"));
    assert_eq!(reloaded.chosen_embedding_model.as_deref(), Some("nomic-embed-text"));
    assert_eq!(reloaded.embedding_enabled, Some(true));
}

#[tokio::test]
async fn console_settings_requires_admin_write() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::put_console_settings(
        State(state),
        dev_scope_headers("admin:read"),
        Json(console::UpdateSettingsBody {
            auth_mode: Some("jwt_hs256".to_string()),
            embedding_enabled: None,
            embedding_url: None,
            embedding_model: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn console_settings_put_rejects_off_on_non_loopback() {
    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    state.http_bind_loopback = false;
    state.allow_insecure_dev_auth_bind = false;
    let resp = console::put_console_settings(
        State(state),
        dev_scope_headers("admin:write"),
        Json(console::UpdateSettingsBody {
            auth_mode: Some("off".to_string()),
            embedding_enabled: None,
            embedding_url: None,
            embedding_model: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial]
async fn console_corecrux_lane_weights_get_requires_corecrux_base_url() {
    std::env::remove_var("CORECRUXD_CORECRUX_BASE_URL");
    std::env::remove_var("CORECRUXD_CORECRUX_URL");
    std::env::remove_var("CORECRUX_BASE_URL");
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::get_console_corecrux_lane_weights(
        State(state),
        dev_scope_headers("admin:read"),
        Query(console::CoreCruxLaneWeightsQuery { tenant_id: None }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn console_corecrux_lane_weights_put_validates_lanes_before_proxy() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::put_console_corecrux_lane_weights(
        State(state),
        dev_scope_headers("admin:write"),
        Json(console::UpdateCoreCruxLaneWeightsBody {
            tenant_id: None,
            weights: [("pgvector".to_string(), 1.0)].into_iter().collect(),
            fusion_rrf_enabled: true,
            reason: None,
            actor: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert!(body["detail"].as_str().unwrap_or_default().contains("unknown lane"));
}

#[tokio::test]
#[serial_test::serial]
async fn console_corecrux_lane_weights_put_tenant_proxies_boost_overlay() {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn read_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
        let mut bytes = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).expect("read request");
            bytes.extend_from_slice(&buf[..n]);
            if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let header_end = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
            .expect("headers end");
        let header = String::from_utf8_lossy(&bytes[..header_end]).to_string();
        let content_len = header
            .lines()
            .find_map(|line| {
                line.strip_prefix("Content-Length:")
                    .or_else(|| line.strip_prefix("content-length:"))
            })
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while bytes.len() < header_end + content_len {
            let n = stream.read(&mut buf).expect("read body");
            bytes.extend_from_slice(&buf[..n]);
        }
        (header, bytes[header_end..header_end + content_len].to_vec())
    }

    fn write_json(stream: &mut std::net::TcpStream, body: &str) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .expect("write mock response");
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock CoreCrux");
    let base_url = format!("http://{}", listener.local_addr().expect("addr"));
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for i in 0..3 {
            let (mut stream, _) = listener.accept().expect("accept mock request");
            let (header, body) = read_request(&mut stream);
            if i == 0 {
                assert!(header.starts_with("GET /v1/admin/boost-config "));
                write_json(
                    &mut stream,
                    r#"{"overlay":{"FEATURE_FUSION_RRF":"true","FUSION_RRF_LANE_WEIGHTS":"{\"bm25\":0.9,\"cosine\":1.2}"},"overlay_size":2}"#,
                );
            } else if i == 1 {
                assert!(header.starts_with("GET /v1/admin/boost-config/tenant?tenant_id=business%3A%3Aacme "));
                write_json(
                    &mut stream,
                    r#"{"ok":true,"tenant_id":"business::acme","overlay":{},"overlay_size":0}"#,
                );
            } else {
                assert!(header.starts_with("POST /v1/admin/boost-config/tenant "));
                tx.send(body).expect("send captured post body");
                write_json(
                    &mut stream,
                    r#"{"ok":true,"tenant_id":"business::acme","overlay_size":2,"overlay":{}}"#,
                );
            }
        }
    });

    std::env::set_var("CORECRUXD_CORECRUX_BASE_URL", &base_url);
    std::env::remove_var("CORECRUXD_CORECRUX_URL");
    std::env::remove_var("CORECRUX_BASE_URL");
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::put_console_corecrux_lane_weights(
        State(state),
        dev_scope_headers("admin:write"),
        Json(console::UpdateCoreCruxLaneWeightsBody {
            tenant_id: Some("business::acme".to_string()),
            weights: [("cosine".to_string(), 2.0)].into_iter().collect(),
            fusion_rrf_enabled: true,
            reason: Some("audit ii m7 test".to_string()),
            actor: Some("test-console".to_string()),
        }),
    )
    .await
    .into_response();
    std::env::remove_var("CORECRUXD_CORECRUX_BASE_URL");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["tenant_id"], "business::acme");
    assert_eq!(body["weights"]["bm25"], 0.9);
    assert_eq!(body["weights"]["cosine"], 2.0);

    let posted = rx.recv().expect("captured CoreCrux POST");
    let posted: serde_json::Value = serde_json::from_slice(&posted).expect("posted json");
    assert_eq!(posted["tenant_id"], "business::acme");
    assert_eq!(posted["set"]["FEATURE_FUSION_RRF"], "true");
    let weights: serde_json::Value = serde_json::from_str(
        posted["set"]["FUSION_RRF_LANE_WEIGHTS"]
            .as_str()
            .expect("weights string"),
    )
    .expect("weights json");
    assert_eq!(weights["bm25"], 0.9);
    assert_eq!(weights["cosine"], 2.0);
    assert!(weights["navtree"].is_number());
}

#[tokio::test]
#[serial_test::serial]
async fn console_corecrux_lane_weights_delete_clears_only_lane_keys() {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn read_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
        let mut bytes = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).expect("read request");
            bytes.extend_from_slice(&buf[..n]);
            if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let header_end = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
            .expect("headers end");
        let header = String::from_utf8_lossy(&bytes[..header_end]).to_string();
        let content_len = header
            .lines()
            .find_map(|line| {
                line.strip_prefix("Content-Length:")
                    .or_else(|| line.strip_prefix("content-length:"))
            })
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while bytes.len() < header_end + content_len {
            let n = stream.read(&mut buf).expect("read body");
            bytes.extend_from_slice(&buf[..n]);
        }
        (header, bytes[header_end..header_end + content_len].to_vec())
    }

    fn write_json(stream: &mut std::net::TcpStream, body: &str) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .expect("write mock response");
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock CoreCrux");
    let base_url = format!("http://{}", listener.local_addr().expect("addr"));
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for i in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept mock request");
            let (header, body) = read_request(&mut stream);
            if i == 0 {
                // The scoped reset: POST the clear of only the lane-weight keys.
                assert!(header.starts_with("POST /v1/admin/boost-config "));
                tx.send(body).expect("send captured post body");
                write_json(&mut stream, r#"{"ok":true,"overlay_size":1,"overlay":{}}"#);
            } else {
                // Re-read: lane keys gone, an unrelated key survives.
                assert!(header.starts_with("GET /v1/admin/boost-config "));
                write_json(
                    &mut stream,
                    r#"{"overlay":{"FEATURE_VERNACULAR_LANE":"true"},"overlay_size":1}"#,
                );
            }
        }
    });

    std::env::set_var("CORECRUXD_CORECRUX_BASE_URL", &base_url);
    std::env::remove_var("CORECRUXD_CORECRUX_URL");
    std::env::remove_var("CORECRUX_BASE_URL");
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::delete_console_corecrux_lane_weights(
        State(state),
        dev_scope_headers("admin:write"),
        Query(console::CoreCruxLaneWeightsQuery { tenant_id: None }),
    )
    .await
    .into_response();
    std::env::remove_var("CORECRUXD_CORECRUX_BASE_URL");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["reset"], true);
    assert_eq!(body["scope"], "global");
    // Post-reset weights fall back to defaults (no overlay lane keys remain).
    assert_eq!(body["source"], "default");
    assert_eq!(body["weights"]["bm25"], 1.0);

    let posted = rx.recv().expect("captured CoreCrux POST");
    let posted: serde_json::Value = serde_json::from_slice(&posted).expect("posted json");
    let cleared = posted["clear"].as_array().expect("clear array");
    assert!(cleared.iter().any(|v| v == "FUSION_RRF_LANE_WEIGHTS"));
    assert!(cleared.iter().any(|v| v == "FEATURE_FUSION_RRF"));
    // Scoped reset must not send a `set` payload or a whole-overlay reset.
    assert!(posted.get("set").is_none());
    assert!(posted.get("reset").is_none());
}

#[tokio::test]
async fn console_review_contradictions_returns_factstore_candidates() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let (first_id, second_id) = {
        let mut store = state.fact_store.write().await;
        let first = store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "service:api".to_string(),
            key: "enabled".to_string(),
            value: "enabled".to_string(),
            source_receipt: None,
            confidence: 0.7,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let second = store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "service:api".to_string(),
            key: "enabled".to_string(),
            value: "disabled".to_string(),
            source_receipt: None,
            confidence: 0.7,
            private: false,
            horizon_class: None,
            actor: None,
        });
        assert!(store.clear_superseded(&first.fact_id));
        (first.fact_id, second.fact_id)
    };

    let resp = console::get_console_review_contradictions(
        State(state),
        dev_scope_headers("admin:read"),
        Query(console::ConsoleReviewQuery { limit: Some(10) }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["schema"], "crux.console.review.contradictions.v1");
    assert_eq!(body["count"], 1);
    let ids = body["candidates"][0]["fact_ids"].as_array().expect("fact ids");
    assert!(ids.iter().any(|id| id.as_str() == Some(first_id.as_str())));
    assert!(ids.iter().any(|id| id.as_str() == Some(second_id.as_str())));
}

#[tokio::test]
async fn console_review_queue_lists_surfaced_expiry_runs() {
    // P1 widen: run the scheduler pass over a low-confidence fact to surface a
    // real `__consolidation_review__::` receipt, then read it back via the queue.
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "svc".to_string(),
            key: "flag".to_string(),
            value: "maybe".to_string(),
            source_receipt: None,
            confidence: 0.1,
            private: false,
            horizon_class: None,
            actor: None,
        });
    }
    let surfaced = crate::consolidation_scheduler::run_review_once(&state.fact_store, 200).await;
    assert_eq!(surfaced, 1, "one expiry proposal surfaced");

    let resp = console::get_console_review_queue(
        State(state),
        dev_scope_headers("admin:read"),
        Query(console::ConsoleReviewQuery { limit: Some(10) }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["schema"], "crux.console.review.queue.v1");
    assert_eq!(body["count"], 1);
    assert_eq!(body["scheduler_enabled"], false, "flag default-OFF (finding 6)");
    assert!(
        body["live_contradictions"].is_array(),
        "live fallback present (finding 6)"
    );
    assert_eq!(body["runs"][0]["review"]["expiry_count"], 1);
    assert_eq!(
        body["runs"][0]["review"]["expiry_candidates"][0]["reason"],
        "low_confidence"
    );
}

// Helper: store a fact with an explicit confidence + optional receipt, return id.
async fn seed_fact(state: &AppState, entity: &str, key: &str, confidence: f32, source_receipt: Option<&str>) -> String {
    state
        .fact_store
        .write()
        .await
        .store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: "v".to_string(),
            source_receipt: source_receipt.map(str::to_string),
            confidence,
            private: false,
            horizon_class: None,
            actor: None,
        })
        .fact_id
}

#[tokio::test]
async fn console_review_expiries_soft_deletes_reviewed_candidate() {
    // A genuine low-confidence candidate, requested by id, is soft-deleted.
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let id = seed_fact(&state, "svc", "flag", 0.1, None).await;

    let resp = console::post_console_review_expiries(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(console::ConsoleExpiryApplyRequest {
            fact_ids: vec![id.clone()],
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["schema"], "crux.console.review.expiries.v1");
    assert_eq!(body["expired_count"], 1);
    assert_eq!(body["expired"][0]["fact_id"], id);
    assert_eq!(body["expired"][0]["reason"], "low_confidence");
    assert!(
        state.fact_store.read().await.get(&id).is_none(),
        "candidate soft-deleted"
    );
}

/// Review findings 1 & 2: the apply must NEVER delete a pinned, receipt-linked,
/// or fresh/high-confidence fact — even when its id is explicitly requested and
/// even if it became protected after the proposal was surfaced.
#[tokio::test]
async fn console_review_expiries_never_deletes_protected_or_fresh() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    // Genuine candidate (low confidence, no protection) → SHOULD be expired.
    let victim = seed_fact(&state, "svc", "victim", 0.1, None).await;
    // Receipt-linked but low confidence → protected, MUST survive.
    let receipted = seed_fact(&state, "svc", "receipted", 0.1, Some("crown:rcpt-1")).await;
    // Fresh + high confidence → not a candidate, MUST survive.
    let fresh = seed_fact(&state, "svc", "fresh", 0.95, None).await;
    // Low confidence but PINNED → protected, MUST survive. Pin marker is a
    // `__memory_pin::<scope>::<fact_id>` fact with key "pinned" value "1".
    let pinned = seed_fact(&state, "svc", "pinned", 0.1, None).await;
    {
        let mut store = state.fact_store.write().await;
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: format!("__memory_pin::cli::{pinned}"),
            key: "pinned".to_string(),
            value: "1".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
    }

    let resp = console::post_console_review_expiries(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(console::ConsoleExpiryApplyRequest {
            fact_ids: vec![victim.clone(), receipted.clone(), fresh.clone(), pinned.clone()],
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    // Only the genuine candidate was deleted.
    assert_eq!(body["expired_count"], 1);
    assert_eq!(body["expired"][0]["fact_id"], victim);
    let store = state.fact_store.read().await;
    assert!(store.get(&victim).is_none(), "genuine candidate expired");
    // Every protected / fresh fact survives.
    assert!(store.get(&receipted).is_some(), "receipt-linked fact survives");
    assert!(store.get(&fresh).is_some(), "fresh high-confidence fact survives");
    assert!(store.get(&pinned).is_some(), "pinned fact survives");
    // …and each is reported as skipped with a reason.
    let skipped: Vec<&str> = body["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["fact_id"].as_str().unwrap())
        .collect();
    for id in [&receipted, &fresh, &pinned] {
        assert!(skipped.contains(&id.as_str()), "{id} reported skipped");
    }
}

#[tokio::test]
async fn console_review_expiries_rejects_empty_fact_ids() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::post_console_review_expiries(
        State(state),
        dev_scope_headers("admin:write"),
        Json(console::ConsoleExpiryApplyRequest { fact_ids: vec![] }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn console_review_consolidation_supersedes_targets_with_actor() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let (old_id, newer_id) = {
        let mut store = state.fact_store.write().await;
        let old = store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "blocked".to_string(),
            source_receipt: None,
            confidence: 0.4,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let newer = store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "active".to_string(),
            source_receipt: None,
            confidence: 0.5,
            private: false,
            horizon_class: None,
            actor: None,
        });
        assert!(store.clear_superseded(&old.fact_id));
        (old.fact_id, newer.fact_id)
    };

    let resp = console::post_console_review_consolidation(
        State(state.clone()),
        dev_scope_passport_headers("admin:write", "passport:reviewer"),
        Json(corecrux_memory::fact_store::ConsolidationRequestV1 {
            consolidation_id: "con-http-1".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            canonical_value: "active".to_string(),
            target_fact_ids: vec![old_id.clone(), newer_id.clone()],
            protected_fact_ids: vec![],
            confidence: 0.8,
            source_receipt: None,
            actor: None,
            horizon_class: Some(corecrux_memory::fact_store::HorizonClass::Stable),
            protected_confidence_floor: 0.99,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["schema"], "crux.console.review.consolidation.v1");
    let canonical_id = body["receipt"]["canonical_fact_id"]
        .as_str()
        .expect("canonical fact id")
        .to_string();
    let store = state.fact_store.read().await;
    assert_eq!(
        store.get(&old_id).unwrap().superseded_by.as_deref(),
        Some(canonical_id.as_str())
    );
    assert_eq!(
        store.get(&newer_id).unwrap().superseded_by.as_deref(),
        Some(canonical_id.as_str())
    );
    assert_eq!(
        store.get(&canonical_id).unwrap().actor.as_deref(),
        Some("passport:reviewer")
    );
}

#[tokio::test]
async fn console_review_consolidation_rejects_receipt_linked_targets() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let target_id = {
        let mut store = state.fact_store.write().await;
        store
            .store(corecrux_memory::fact_store::StoreFact {
                tenant_hash: "default".to_string(),
                entity: "proj".to_string(),
                key: "decision".to_string(),
                value: "approved".to_string(),
                source_receipt: Some("receipt:r1".to_string()),
                confidence: 0.5,
                private: false,
                horizon_class: None,
                actor: None,
            })
            .fact_id
    };

    let resp = console::post_console_review_consolidation(
        State(state),
        dev_scope_headers("admin:write"),
        Json(corecrux_memory::fact_store::ConsolidationRequestV1 {
            consolidation_id: "con-http-guard".to_string(),
            entity: "proj".to_string(),
            key: "decision".to_string(),
            canonical_value: "approved".to_string(),
            target_fact_ids: vec![target_id],
            protected_fact_ids: vec![],
            confidence: 0.8,
            source_receipt: None,
            actor: None,
            horizon_class: None,
            protected_confidence_floor: 0.99,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn console_storage_breakdown_returns_four_kinds_with_empty_defaults() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::get_console_storage_breakdown(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let kinds = body["kinds"].as_array().expect("kinds array");
    let names: Vec<&str> = kinds.iter().map(|k| k["kind"].as_str().unwrap_or_default()).collect();
    assert_eq!(names, vec!["text_search", "projections", "embedding", "graph"]);
    for kind in kinds {
        assert!(kind["chunks"].is_u64());
        assert!(kind["bytes"].is_u64());
        assert!(kind["available"].is_boolean());
        assert!(kind["tooltip"].is_string());
    }
    // Embedding always unavailable in the open distribution.
    let embedding = kinds.iter().find(|k| k["kind"] == "embedding").expect("embedding kind");
    assert_eq!(embedding["available"], false);
    // Graph empty by default — no relations posted yet.
    let graph = kinds.iter().find(|k| k["kind"] == "graph").expect("graph kind");
    assert_eq!(graph["chunks"], 0);
    assert_eq!(graph["available"], false);
}

#[tokio::test]
async fn console_storage_breakdown_requires_admin_read() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::get_console_storage_breakdown(State(state), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn relation_post_persists_then_list_returns_outgoing_edges() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    let resp = super::relations::post_relation(
        State(state.clone()),
        dev_scope_headers("facts:write"),
        Json(super::relations::PutRelationBody {
            tenant_id: "alpha".to_string(),
            from_id: 10,
            to_id: 20,
            edge_type: "cites".to_string(),
            confidence: 0.5,
            created_at_micros: None,
            updated_at_micros: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // JSONL on disk is the source of truth across restarts.
    let jsonl = state.data_dir.join("relations.jsonl");
    let contents = std::fs::read_to_string(&jsonl).expect("read jsonl");
    assert!(contents.contains("\"alpha\""), "edge should be persisted: {contents}");

    let list_resp = super::relations::get_relations(
        State(state.clone()),
        Query(super::relations::ListRelationsQuery {
            tenant_id: "alpha".to_string(),
            from_id: 10,
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let body = json_body(list_resp).await;
    let edges = body["edges"].as_array().expect("edges array");
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0]["to_id"], 20);
    assert_eq!(edges[0]["edge_type"], "cites");
}

#[tokio::test]
async fn relation_post_rejects_unknown_edge_type() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::relations::post_relation(
        State(state),
        dev_scope_headers("facts:write"),
        Json(super::relations::PutRelationBody {
            tenant_id: "alpha".to_string(),
            from_id: 1,
            to_id: 2,
            edge_type: "loves".to_string(),
            confidence: 1.0,
            created_at_micros: None,
            updated_at_micros: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn relation_expand_walks_two_hops() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    // Build a small chain: 1 -supports-> 2 -supports-> 3 -supports-> 4
    for (from, to) in [(1u32, 2u32), (2, 3), (3, 4)] {
        let resp = super::relations::post_relation(
            State(state.clone()),
            dev_scope_headers("facts:write"),
            Json(super::relations::PutRelationBody {
                tenant_id: "alpha".to_string(),
                from_id: from,
                to_id: to,
                edge_type: "supports".to_string(),
                confidence: 1.0,
                created_at_micros: None,
                updated_at_micros: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let expand_resp = super::relations::post_expand(
        State(state),
        dev_scope_headers("admin:read"),
        Json(super::relations::ExpandRelationsBody {
            tenant_id: "alpha".to_string(),
            seed_artifact_ids: vec![1],
            edge_types: vec![],
            max_hops: 2,
            budget: 50,
            min_confidence: 0.0,
        }),
    )
    .await
    .into_response();
    assert_eq!(expand_resp.status(), StatusCode::OK);
    let body = json_body(expand_resp).await;
    let artifact_ids: Vec<u64> = body["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .map(|a| a["artifact_id"].as_u64().unwrap_or_default())
        .collect();
    // graph_expand returns reached neighbours (seed itself is excluded by design).
    // 2 hops from seed 1 reaches 2 and 3 but not 4.
    assert!(
        !artifact_ids.contains(&1),
        "seed itself is not in result by graph_expand contract"
    );
    assert!(artifact_ids.contains(&2), "1-hop neighbour in result");
    assert!(artifact_ids.contains(&3), "2-hop neighbour in result");
    assert!(
        !artifact_ids.contains(&4),
        "3-hop neighbour NOT in result with max_hops=2"
    );
}

#[tokio::test]
async fn relation_incoming_paginates_filters_and_requires_admin_read() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut projection = state.projection_state.write().await;
        for from_id in 101u32..=107 {
            crate::relations::apply_record(
                &mut projection,
                &crate::relations::RelationRecord {
                    tenant_id: "alpha".to_string(),
                    from_id,
                    to_id: 500,
                    edge_type: "depends_on".to_string(),
                    confidence_bp: 7000,
                    created_at_micros: 1,
                    updated_at_micros: 2,
                },
            )
            .expect("apply depends_on");
        }
        crate::relations::apply_record(
            &mut projection,
            &crate::relations::RelationRecord {
                tenant_id: "alpha".to_string(),
                from_id: 201,
                to_id: 500,
                edge_type: "calls".to_string(),
                confidence_bp: 9000,
                created_at_micros: 3,
                updated_at_micros: 4,
            },
        )
        .expect("apply calls");
    }

    let unauthorized = super::relations::get_incoming_relations(
        State(state.clone()),
        Query(super::relations::IncomingRelationsQuery {
            tenant_id: "alpha".to_string(),
            to_id: 500,
            edge_type: Some("depends_on".to_string()),
            cursor: None,
            limit: Some(3),
        }),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let mut cursor = None;
    let mut pages = Vec::new();
    let mut all_from_ids = Vec::new();
    loop {
        let resp = super::relations::get_incoming_relations(
            State(state.clone()),
            Query(super::relations::IncomingRelationsQuery {
                tenant_id: "alpha".to_string(),
                to_id: 500,
                edge_type: Some("depends_on".to_string()),
                cursor: cursor.clone(),
                limit: Some(3),
            }),
            dev_scope_headers("admin:read"),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let edges = body["edges"].as_array().expect("edges");
        pages.push(edges.len());
        all_from_ids.extend(edges.iter().map(|edge| edge["from_id"].as_u64().unwrap_or_default()));
        cursor = body["next_cursor"].as_str().map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(pages, vec![3, 3, 1]);
    assert_eq!(all_from_ids, vec![101, 102, 103, 104, 105, 106, 107]);

    let calls = super::relations::get_incoming_relations(
        State(state),
        Query(super::relations::IncomingRelationsQuery {
            tenant_id: "alpha".to_string(),
            to_id: 500,
            edge_type: Some("calls".to_string()),
            cursor: None,
            limit: Some(500),
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    let body = json_body(calls).await;
    let edges = body["edges"].as_array().expect("edges");
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0]["from_id"], 201);
    assert_eq!(edges[0]["edge_type"], "calls");
}

#[tokio::test]
async fn relation_incoming_cursor_keeps_same_source_different_edge_types() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut projection = state.projection_state.write().await;
        for edge_type in ["calls", "depends_on"] {
            crate::relations::apply_record(
                &mut projection,
                &crate::relations::RelationRecord {
                    tenant_id: "alpha".to_string(),
                    from_id: 5,
                    to_id: 500,
                    edge_type: edge_type.to_string(),
                    confidence_bp: 9000,
                    created_at_micros: 1,
                    updated_at_micros: 2,
                },
            )
            .expect("apply relation");
        }
    }

    let page1 = super::relations::get_incoming_relations(
        State(state.clone()),
        Query(super::relations::IncomingRelationsQuery {
            tenant_id: "alpha".to_string(),
            to_id: 500,
            edge_type: None,
            cursor: None,
            limit: Some(1),
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(page1.status(), StatusCode::OK);
    let page1_body = json_body(page1).await;
    let page1_edges = page1_body["edges"].as_array().expect("page 1 edges");
    assert_eq!(page1_edges.len(), 1);
    assert_eq!(page1_edges[0]["from_id"], 5);
    let cursor = page1_body["next_cursor"]
        .as_str()
        .expect("page 1 next cursor")
        .to_string();
    assert!(cursor.starts_with("5:"), "cursor must carry the shared source id");

    let page2 = super::relations::get_incoming_relations(
        State(state),
        Query(super::relations::IncomingRelationsQuery {
            tenant_id: "alpha".to_string(),
            to_id: 500,
            edge_type: None,
            cursor: Some(cursor),
            limit: Some(1),
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(page2.status(), StatusCode::OK);
    let page2_body = json_body(page2).await;
    assert!(page2_body["next_cursor"].is_null());
    let page2_edges = page2_body["edges"].as_array().expect("page 2 edges");
    assert_eq!(page2_edges.len(), 1);
    assert_eq!(page2_edges[0]["from_id"], 5);

    let seen: std::collections::BTreeSet<_> = page1_edges
        .iter()
        .chain(page2_edges)
        .map(|edge| edge["edge_type"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(seen, std::collections::BTreeSet::from(["calls", "depends_on"]));
}

#[tokio::test]
async fn console_storage_breakdown_graph_kind_reflects_relation_posts() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    // Post two relations through the public endpoint so the path mirrors prod usage.
    for (from, to, edge_type) in [(1u32, 2u32, "supports"), (2, 3, "elaborates")] {
        let resp = super::relations::post_relation(
            State(state.clone()),
            dev_scope_headers("facts:write"),
            Json(super::relations::PutRelationBody {
                tenant_id: "tenant-x".to_string(),
                from_id: from,
                to_id: to,
                edge_type: edge_type.to_string(),
                confidence: 0.9,
                created_at_micros: None,
                updated_at_micros: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let resp = console::get_console_storage_breakdown(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let body = json_body(resp).await;
    let graph = body["kinds"]
        .as_array()
        .expect("kinds")
        .iter()
        .find(|k| k["kind"] == "graph")
        .expect("graph kind");
    assert_eq!(graph["chunks"], 2);
    assert!(graph["bytes"].as_u64().expect("bytes int") > 0);
    assert_eq!(graph["available"], true);
}

#[tokio::test]
async fn console_onboarding_restart_clears_completed_marker() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut current = state.onboarding.write().await;
        current.completed_at_unix_ms = Some(123);
        current.chosen_auth_mode = Some("dev_scopes".to_string());
        crate::onboarding::write_state(&state.data_dir, &current).expect("seed write");
    }
    let resp = console::post_console_onboarding_restart(State(state.clone()), dev_scope_headers("admin:write"))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let reloaded = crate::onboarding::read_state(&state.data_dir).expect("reload");
    assert!(reloaded.completed_at_unix_ms.is_none());
    assert_eq!(reloaded.chosen_auth_mode.as_deref(), Some("dev_scopes"));
}

#[tokio::test]
async fn onboarding_restart_requires_admin_write() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut current = state.onboarding.write().await;
        current.completed_at_unix_ms = Some(123);
        current.chosen_auth_mode = Some("dev_scopes".to_string());
        crate::onboarding::write_state(&state.data_dir, &current).expect("seed write");
    }
    let resp = console::post_console_onboarding_restart(State(state.clone()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let reloaded = crate::onboarding::read_state(&state.data_dir).expect("reload");
    assert_eq!(reloaded.completed_at_unix_ms, Some(123));
}

#[tokio::test]
async fn passports_list_after_seed_returns_three_defaults() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let resp = super::passports::get_passports(
        State(state),
        Query(super::passports::ListPassportsQuery { category: None }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let passports = body["passports"].as_array().expect("passports array");
    assert_eq!(passports.len(), 3);
    let ids: Vec<&str> = passports.iter().map(|p| p["id"].as_str().unwrap_or("")).collect();
    assert!(ids.contains(&"personal-default"));
    assert!(ids.contains(&"work-default"));
    assert!(ids.contains(&"public-default"));
}

#[tokio::test]
async fn passport_mint_requests_pending_lists_filed_request_without_minting() {
    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    state.passport_mint_requests_enabled = true;
    {
        let mut store = state.fact_store.write().await;
        let filed = crate::mint_requests::file_mint_request(
            &mut store,
            "codex-work".to_string(),
            "codex-work".to_string(),
            Some("work".to_string()),
            Some("Stamp the caller identity".to_string()),
            1_726_000_000_000,
        );
        assert!(filed.is_ok());
        assert!(!store.all_facts().any(|fact| fact.entity.starts_with("__passport__::")));
    }

    let resp = super::passports::get_pending_mint_requests(
        State(state.clone()),
        Query(super::passports::ListPendingMintRequestsQuery {
            by_passport: Some("codex-work".to_string()),
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = json_body(resp).await;
    assert_eq!(body["count"], 1);
    assert_eq!(body["pending"][0]["requester_id"], "codex-work");
    assert_eq!(body["pending"][0]["requested_by_passport"], "codex-work");
    assert_eq!(body["pending"][0]["requested_category"], "work");
    assert_eq!(body["pending"][0]["reason"], "Stamp the caller identity");
    assert_eq!(body["pending"][0]["status"], "pending");

    let store = state.fact_store.read().await;
    assert!(!store.all_facts().any(|fact| fact.entity.starts_with("__passport__::")));
}

async fn mint_test_state(
    auth_mode: AuthMode,
    requester_id: &str,
    requested_by_passport: &str,
    requested_category: Option<&str>,
) -> Result<(AppState, String), Box<dyn std::error::Error>> {
    let mut state = test_app_state_with_auth(16, auth_mode);
    bind_test_state_to_root_passport_key(&mut state);
    state.passport_mint_requests_enabled = true;
    let request_id = {
        let mut store = state.fact_store.write().await;
        crate::mint_requests::file_mint_request(
            &mut store,
            requester_id.to_string(),
            requested_by_passport.to_string(),
            requested_category.map(str::to_string),
            None,
            100,
        )?
        .request_id
    };
    Ok((state, request_id))
}

const MINT_TEST_HS256_SECRET: &str = "mint-approval-test-secret-32-bytes-minimum";
const MINT_TEST_ISSUER: &str = "corecrux-mint-test";
const MINT_TEST_AUDIENCE: &str = "corecrux";

fn mint_test_verified_app_state(action_max_pending: usize) -> AppState {
    let mut state = test_app_state_with_auth(action_max_pending, AuthMode::Off);
    state.auth =
        crate::auth::Authz::test_hs256(MINT_TEST_HS256_SECRET.as_bytes(), MINT_TEST_ISSUER, MINT_TEST_AUDIENCE);
    state
}

fn mint_test_jwt_headers(scopes: &str, identity_claim: (&str, &str)) -> HeaderMap {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
        .saturating_add(3_600) as usize;
    let mut claims = serde_json::json!({
        "exp": exp,
        "iss": MINT_TEST_ISSUER,
        "aud": MINT_TEST_AUDIENCE,
        "scope": scopes,
        "tenant_id": "default",
    });
    claims[identity_claim.0] = serde_json::json!(identity_claim.1);
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(MINT_TEST_HS256_SECRET.as_bytes()),
    )
    .expect("mint approval test JWT");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).expect("bearer header"),
    );
    headers
}

fn mint_test_verified_headers(scopes: &str, passport_id: &str) -> HeaderMap {
    mint_test_jwt_headers(scopes, ("passport_id", passport_id))
}

fn mint_test_sub_only_headers(scopes: &str, subject: &str) -> HeaderMap {
    mint_test_jwt_headers(scopes, ("sub", subject))
}

async fn mint_test_verified_state(
    requester_id: &str,
    requested_by_passport: &str,
    requested_category: Option<&str>,
) -> Result<(AppState, String), Box<dyn std::error::Error>> {
    let mut state = mint_test_verified_app_state(16);
    bind_test_state_to_root_passport_key(&mut state);
    state.passport_mint_requests_enabled = true;
    let request_id = {
        let mut store = state.fact_store.write().await;
        crate::mint_requests::file_mint_request(
            &mut store,
            requester_id.to_string(),
            requested_by_passport.to_string(),
            requested_category.map(str::to_string),
            None,
            100,
        )?
        .request_id
    };
    Ok((state, request_id))
}

async fn mint_test_resolve(
    state: &AppState,
    request_id: &str,
    headers: HeaderMap,
    approver_hint: Option<&str>,
    category: Option<&str>,
    approve: bool,
) -> Response {
    let body = super::passports::ResolveMintRequestBody {
        approver_passport: approver_hint.map(str::to_string),
        category: category.map(str::to_string),
        name: None,
    };
    if approve {
        super::passports::post_mint_request_approve(
            State(state.clone()),
            Path(request_id.to_string()),
            headers,
            Json(body),
        )
        .await
        .into_response()
    } else {
        super::passports::post_mint_request_reject(
            State(state.clone()),
            Path(request_id.to_string()),
            headers,
            Json(body),
        )
        .await
        .into_response()
    }
}

fn mint_test_observation_count(state: &AppState) -> Result<usize, Box<dyn std::error::Error>> {
    let path =
        super::observations::observation_file_path(&state.data_dir, super::approval_receipts::APPROVAL_RECEIPT_SESSION);
    Ok(super::observations::read_observations_strict(&path)?.len())
}

#[tokio::test]
async fn passport_mint_request_flag_off_hides_pending_list() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        let filed = crate::mint_requests::file_mint_request(
            &mut store,
            "codex-work".to_string(),
            "codex-work".to_string(),
            Some("work".to_string()),
            Some("operator review".to_string()),
            1_726_000_000_000,
        );
        assert!(filed.is_ok(), "seed pending request: {filed:?}");
    }

    let resp = super::passports::get_pending_mint_requests(
        State(state),
        Query(super::passports::ListPendingMintRequestsQuery { by_passport: None }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = json_body(resp).await;
    assert!(body["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("passport mint requests disabled")));
}

#[tokio::test]
async fn passport_mint_request_approve_http_mints_and_attributes_operator() -> Result<(), Box<dyn std::error::Error>> {
    let mut state = mint_test_verified_app_state(16);
    bind_test_state_to_root_passport_key(&mut state);
    state.passport_mint_requests_enabled = true;
    let request_id = {
        let mut store = state.fact_store.write().await;
        crate::mint_requests::file_mint_request(
            &mut store,
            "codex-work".to_string(),
            "codex-work".to_string(),
            Some("personal".to_string()),
            None,
            100,
        )?
        .request_id
    };

    let resp = super::passports::post_mint_request_approve(
        State(state.clone()),
        Path(request_id.clone()),
        mint_test_verified_headers("admin:write", "operator-work"),
        Json(super::passports::ResolveMintRequestBody {
            approver_passport: Some("operator-work".to_string()),
            category: Some("work".to_string()),
            name: Some("Codex work agent".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["request_id"], request_id);
    assert_eq!(body["requester_id"], "codex-work");
    assert_eq!(body["category"], "work");
    assert_eq!(body["minted"], true);
    assert_eq!(body["status"], "approved");
    assert_eq!(
        body["receipt_session_id"],
        super::approval_receipts::APPROVAL_RECEIPT_SESSION
    );
    let receipt_id = body["receipt_id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("mint approval receipt_id missing"))?
        .to_string();
    assert_eq!(receipt_id, format!("ad_{request_id}"));
    assert!(body["receipt_record_id"].is_string());

    let store = state.fact_store.read().await;
    let passport = crate::passports::get_passport(&store, "codex-work")
        .ok_or_else(|| std::io::Error::other("minted passport missing"))?;
    assert_eq!(passport.category, "work");
    assert_eq!(passport.name.as_deref(), Some("Codex work agent"));
    let resolved = crate::mint_requests::get_mint_request(&store, &request_id)
        .ok_or_else(|| std::io::Error::other("resolved request missing"))?;
    assert_eq!(resolved.status, crate::mint_requests::MINT_REQUEST_STATUS_APPROVED);
    assert_eq!(resolved.resolved_by_passport.as_deref(), Some("operator-work"));
    assert_eq!(resolved.resolution_receipt_id.as_deref(), Some(receipt_id.as_str()));
    assert_eq!(resolved.approved_category.as_deref(), Some("work"));
    assert_eq!(resolved.passport_operation.as_deref(), Some("create"));
    assert_eq!(
        resolved.passport_record_hash.as_deref(),
        body["passport_record_hash"].as_str()
    );
    assert_eq!(
        resolved.passport_mutation_hash.as_deref(),
        body["passport_mutation_hash"].as_str()
    );
    let passport_entity = format!("{}::codex-work", crate::passports::PASSPORT_ENTITY_PREFIX);
    let passport_fact = store
        .all_facts()
        .filter(|fact| fact.entity == passport_entity && fact.key == crate::passports::PASSPORT_RECORD_KEY)
        .max_by_key(|fact| fact.version)
        .ok_or_else(|| std::io::Error::other("minted passport fact missing"))?;
    let request_entity = format!("{}::{request_id}", crate::mint_requests::MINT_REQUEST_ENTITY_PREFIX);
    let request_fact = store
        .all_facts()
        .filter(|fact| fact.entity == request_entity && fact.key == crate::mint_requests::MINT_REQUEST_RECORD_KEY)
        .max_by_key(|fact| fact.version)
        .ok_or_else(|| std::io::Error::other("resolved mint request fact missing"))?;
    for fact in [passport_fact, request_fact] {
        assert_eq!(fact.actor.as_deref(), Some("operator-work"));
        assert_eq!(fact.source_receipt.as_deref(), Some(receipt_id.as_str()));
    }
    drop(store);

    let follow_up_request_id = {
        let mut store = state.fact_store.write().await;
        crate::mint_requests::file_mint_request(
            &mut store,
            "codex-work".to_string(),
            "codex-work".to_string(),
            Some("work".to_string()),
            Some("request after receipt-backed resolution".to_string()),
            101,
        )?
        .request_id
    };
    assert_ne!(follow_up_request_id, request_id);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(state.data_dir.join("passports/codex-work.key"))?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    let local = super::receipts::local_approval_receipt(&state, "default", &receipt_id)?
        .ok_or_else(|| std::io::Error::other("local mint approval receipt missing"))?;
    assert_eq!(local.reviewer_passport, "operator-work");
    assert_eq!(local.decision, "approve");
    assert_eq!(local.risk_tier, "high");
    assert!(local.action_summary.contains("category=work"));
    assert!(local.passport_issued_at_unix_ms.is_some());

    let body_response = super::receipts::get_receipt_body_v1(
        State(state.clone()),
        Path(receipt_id.clone()),
        Query(TenantQuery {
            tenant_id: "default".to_string(),
        }),
        mint_test_verified_headers("receipts:read", "operator-work"),
    )
    .await
    .into_response();
    assert_eq!(body_response.status(), StatusCode::OK);
    let signature_response = super::receipts::get_receipt_signature_v1(
        State(state.clone()),
        Path(receipt_id.clone()),
        Query(TenantQuery {
            tenant_id: "default".to_string(),
        }),
        mint_test_verified_headers("receipts:read", "operator-work"),
    )
    .await
    .into_response();
    assert_eq!(signature_response.status(), StatusCode::OK);
    let verification_response = super::receipts::get_receipt_verification_v1(
        State(state),
        Path(receipt_id),
        Query(TenantQuery {
            tenant_id: "default".to_string(),
        }),
        mint_test_verified_headers("receipts:read", "operator-work"),
    )
    .await
    .into_response();
    assert_eq!(verification_response.status(), StatusCode::OK);
    let verification = json_body(verification_response).await;
    assert_eq!(verification["signature_valid"], true);
    assert_eq!(verification["error_code"], "OK");
    Ok(())
}

#[tokio::test]
async fn passport_mint_request_resolution_requires_admin_write_without_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    bind_test_state_to_root_passport_key(&mut state);
    state.passport_mint_requests_enabled = true;
    let request_id = {
        let mut store = state.fact_store.write().await;
        crate::mint_requests::file_mint_request(
            &mut store,
            "codex-work".to_string(),
            "codex-work".to_string(),
            Some("work".to_string()),
            None,
            100,
        )?
        .request_id
    };

    let resp = super::passports::post_mint_request_approve(
        State(state.clone()),
        Path(request_id.clone()),
        dev_scope_headers("admin:read"),
        Json(super::passports::ResolveMintRequestBody {
            approver_passport: Some("operator-work".to_string()),
            category: Some("work".to_string()),
            name: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let reject = super::passports::post_mint_request_reject(
        State(state.clone()),
        Path(request_id.clone()),
        dev_scope_headers("admin:read"),
        Json(super::passports::ResolveMintRequestBody {
            approver_passport: Some("operator-work".to_string()),
            category: None,
            name: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(reject.status(), StatusCode::FORBIDDEN);

    let store = state.fact_store.read().await;
    assert!(crate::passports::get_passport(&store, "codex-work").is_none());
    let request = crate::mint_requests::get_mint_request(&store, &request_id)
        .ok_or_else(|| std::io::Error::other("pending request missing"))?;
    assert_eq!(request.status, crate::mint_requests::MINT_REQUEST_STATUS_PENDING);
    Ok(())
}

#[tokio::test]
async fn passport_mint_request_flag_off_approve_and_reject_are_noops() -> Result<(), Box<dyn std::error::Error>> {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let request_id = {
        let mut store = state.fact_store.write().await;
        crate::mint_requests::file_mint_request(
            &mut store,
            "codex-work".to_string(),
            "codex-work".to_string(),
            Some("work".to_string()),
            None,
            100,
        )?
        .request_id
    };
    let body = || super::passports::ResolveMintRequestBody {
        approver_passport: Some("operator-work".to_string()),
        category: Some("work".to_string()),
        name: None,
    };

    let approve = super::passports::post_mint_request_approve(
        State(state.clone()),
        Path(request_id.clone()),
        dev_scope_passport_headers("admin:write", "rejecting-operator"),
        Json(body()),
    )
    .await
    .into_response();
    assert_eq!(approve.status(), StatusCode::NOT_FOUND);

    let reject = super::passports::post_mint_request_reject(
        State(state.clone()),
        Path(request_id.clone()),
        dev_scope_headers("admin:write"),
        Json(body()),
    )
    .await
    .into_response();
    assert_eq!(reject.status(), StatusCode::NOT_FOUND);

    let store = state.fact_store.read().await;
    assert!(crate::passports::get_passport(&store, "codex-work").is_none());
    let request = crate::mint_requests::get_mint_request(&store, &request_id)
        .ok_or_else(|| std::io::Error::other("pending request missing"))?;
    assert_eq!(request.status, crate::mint_requests::MINT_REQUEST_STATUS_PENDING);
    assert_eq!(request.resolved_at_unix_ms, None);
    assert_eq!(request.resolved_by_passport, None);
    Ok(())
}

#[tokio::test]
async fn passport_mint_request_reject_http_mints_nothing_and_attributes_operator(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = mint_test_verified_app_state(16);
    bind_test_state_to_root_passport_key(&mut state);
    state.passport_mint_requests_enabled = true;
    let request_id = {
        let mut store = state.fact_store.write().await;
        crate::mint_requests::file_mint_request(
            &mut store,
            "rejected-agent".to_string(),
            "rejected-agent".to_string(),
            Some("work".to_string()),
            None,
            100,
        )?
        .request_id
    };

    let resp = super::passports::post_mint_request_reject(
        State(state.clone()),
        Path(request_id.clone()),
        mint_test_verified_headers("admin:write", "rejecting-operator"),
        Json(super::passports::ResolveMintRequestBody {
            approver_passport: Some("rejecting-operator".to_string()),
            category: Some("public".to_string()),
            name: Some("must be ignored".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["request_id"], request_id);
    assert_eq!(body["requester_id"], "rejected-agent");
    assert_eq!(body["minted"], false);
    assert_eq!(body["status"], "rejected");
    let receipt_id = body["receipt_id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("mint rejection receipt_id missing"))?
        .to_string();
    assert_eq!(receipt_id, format!("ad_{request_id}"));
    assert_eq!(
        body["receipt_session_id"],
        super::approval_receipts::APPROVAL_RECEIPT_SESSION
    );

    let store = state.fact_store.read().await;
    assert!(crate::passports::get_passport(&store, "rejected-agent").is_none());
    let request = crate::mint_requests::get_mint_request(&store, &request_id)
        .ok_or_else(|| std::io::Error::other("rejected request missing"))?;
    assert_eq!(request.status, crate::mint_requests::MINT_REQUEST_STATUS_REJECTED);
    assert_eq!(request.resolved_by_passport.as_deref(), Some("rejecting-operator"));
    assert_eq!(request.resolution_receipt_id.as_deref(), Some(receipt_id.as_str()));
    assert_eq!(request.approved_category, None);
    assert_eq!(request.passport_operation, None);
    assert_eq!(request.passport_record_hash, None);
    assert_eq!(request.passport_mutation_hash, None);
    let request_entity = format!("{}::{request_id}", crate::mint_requests::MINT_REQUEST_ENTITY_PREFIX);
    let request_fact = store
        .all_facts()
        .filter(|fact| fact.entity == request_entity && fact.key == crate::mint_requests::MINT_REQUEST_RECORD_KEY)
        .max_by_key(|fact| fact.version)
        .ok_or_else(|| std::io::Error::other("rejected mint request fact missing"))?;
    assert_eq!(request_fact.actor.as_deref(), Some("rejecting-operator"));
    assert_eq!(request_fact.source_receipt.as_deref(), Some(receipt_id.as_str()));
    drop(store);

    let local = super::receipts::local_approval_receipt(&state, "default", &receipt_id)?
        .ok_or_else(|| std::io::Error::other("local mint rejection receipt missing"))?;
    assert_eq!(local.reviewer_passport, "rejecting-operator");
    assert_eq!(local.decision, "reject");
    assert_eq!(local.passport_issued_at_unix_ms, None);
    let verification_response = super::receipts::get_receipt_verification_v1(
        State(state),
        Path(receipt_id),
        Query(TenantQuery {
            tenant_id: "default".to_string(),
        }),
        mint_test_verified_headers("receipts:read", "rejecting-operator"),
    )
    .await
    .into_response();
    assert_eq!(verification_response.status(), StatusCode::OK);
    let verification = json_body(verification_response).await;
    assert_eq!(verification["signature_valid"], true);
    assert_eq!(verification["error_code"], "OK");
    Ok(())
}

#[tokio::test]
async fn passport_mint_request_approve_http_maps_category_and_terminal_errors_without_minting(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = mint_test_verified_app_state(16);
    state.passport_mint_requests_enabled = true;
    let (missing_category_id, invalid_category_id, resolved_id) = {
        let mut store = state.fact_store.write().await;
        let missing = crate::mint_requests::file_mint_request(
            &mut store,
            "missing-category-agent".to_string(),
            "missing-category-agent".to_string(),
            Some("work".to_string()),
            None,
            100,
        )?;
        let invalid = crate::mint_requests::file_mint_request(
            &mut store,
            "invalid-category-agent".to_string(),
            "invalid-category-agent".to_string(),
            Some("work".to_string()),
            None,
            100,
        )?;
        let resolved = crate::mint_requests::file_mint_request(
            &mut store,
            "resolved-agent".to_string(),
            "resolved-agent".to_string(),
            Some("work".to_string()),
            None,
            100,
        )?;
        crate::mint_requests::reject_mint_request(
            &mut store,
            &resolved.request_id,
            "first-operator".to_string(),
            &format!("ad_{}", resolved.request_id),
            200,
        )?;
        (missing.request_id, invalid.request_id, resolved.request_id)
    };

    let call = |request_id: String, category: Option<String>| {
        super::passports::post_mint_request_approve(
            State(state.clone()),
            Path(request_id),
            mint_test_verified_headers("admin:write", "operator-work"),
            Json(super::passports::ResolveMintRequestBody {
                approver_passport: Some("operator-work".to_string()),
                category,
                name: None,
            }),
        )
    };

    let missing = call(missing_category_id.clone(), None).await.into_response();
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    let invalid = call(invalid_category_id.clone(), Some("private".to_string()))
        .await
        .into_response();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let non_pending = call(resolved_id.clone(), Some("public".to_string()))
        .await
        .into_response();
    assert_eq!(non_pending.status(), StatusCode::CONFLICT);

    let store = state.fact_store.read().await;
    for requester in ["missing-category-agent", "invalid-category-agent", "resolved-agent"] {
        assert!(
            crate::passports::get_passport(&store, requester).is_none(),
            "{requester}"
        );
    }
    let missing_category = crate::mint_requests::get_mint_request(&store, &missing_category_id)
        .ok_or_else(|| std::io::Error::other("missing-category request missing"))?;
    assert_eq!(
        missing_category.status,
        crate::mint_requests::MINT_REQUEST_STATUS_PENDING
    );
    let invalid_category = crate::mint_requests::get_mint_request(&store, &invalid_category_id)
        .ok_or_else(|| std::io::Error::other("invalid-category request missing"))?;
    assert_eq!(
        invalid_category.status,
        crate::mint_requests::MINT_REQUEST_STATUS_PENDING
    );
    let terminal = crate::mint_requests::get_mint_request(&store, &resolved_id)
        .ok_or_else(|| std::io::Error::other("terminal request missing"))?;
    assert_eq!(terminal.status, crate::mint_requests::MINT_REQUEST_STATUS_REJECTED);
    Ok(())
}

#[tokio::test]
async fn passport_mint_request_denies_missing_spoofed_and_self_reviewer_without_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    for approve in [true, false] {
        let (state, request_id) =
            mint_test_state(AuthMode::DevScopes, "requester-a", "requester-a", Some("work")).await?;

        let missing = mint_test_resolve(
            &state,
            &request_id,
            dev_scope_headers("admin:write"),
            Some("approver-a"),
            Some("work"),
            approve,
        )
        .await;
        assert_eq!(missing.status(), StatusCode::FORBIDDEN);

        let spoofed = mint_test_resolve(
            &state,
            &request_id,
            dev_scope_passport_headers("admin:write", "approver-a"),
            Some("approver-b"),
            Some("work"),
            approve,
        )
        .await;
        assert_eq!(spoofed.status(), StatusCode::FORBIDDEN);

        let unverified = mint_test_resolve(
            &state,
            &request_id,
            dev_scope_passport_headers("admin:write", "approver-a"),
            Some("approver-a"),
            Some("work"),
            approve,
        )
        .await;
        assert_eq!(unverified.status(), StatusCode::FORBIDDEN);

        let self_review = mint_test_resolve(
            &state,
            &request_id,
            dev_scope_passport_headers("admin:write", "requester-a"),
            Some("requester-a"),
            Some("work"),
            approve,
        )
        .await;
        assert_eq!(self_review.status(), StatusCode::FORBIDDEN);
        assert_eq!(mint_test_observation_count(&state)?, 0);

        let store = state.fact_store.read().await;
        let pending = crate::mint_requests::get_mint_request(&store, &request_id)
            .ok_or_else(|| std::io::Error::other("pending mint request missing"))?;
        assert_eq!(pending.status, crate::mint_requests::MINT_REQUEST_STATUS_PENDING);
        assert!(crate::passports::get_passport(&store, "requester-a").is_none());
        assert!(!state.data_dir.join("passports/requester-a.key").exists());

        let (verified_state, verified_request_id) =
            mint_test_verified_state("requester-a", "requester-a", Some("work")).await?;
        let verified_self_review = mint_test_resolve(
            &verified_state,
            &verified_request_id,
            mint_test_verified_headers("admin:write", "requester-a"),
            Some("requester-a"),
            Some("work"),
            approve,
        )
        .await;
        assert_eq!(verified_self_review.status(), StatusCode::FORBIDDEN);
        assert_eq!(mint_test_observation_count(&verified_state)?, 0);
        let verified_store = verified_state.fact_store.read().await;
        let verified_pending = crate::mint_requests::get_mint_request(&verified_store, &verified_request_id)
            .ok_or_else(|| std::io::Error::other("verified self-review request missing"))?;
        assert_eq!(
            verified_pending.status,
            crate::mint_requests::MINT_REQUEST_STATUS_PENDING
        );
        assert!(crate::passports::get_passport(&verified_store, "requester-a").is_none());
        assert!(!verified_state.data_dir.join("passports/requester-a.key").exists());
    }
    Ok(())
}

#[tokio::test]
async fn passport_mint_request_auth_off_is_rejected_without_mutation() -> Result<(), Box<dyn std::error::Error>> {
    for approve in [true, false] {
        let (state, request_id) = mint_test_state(AuthMode::Off, "requester-a", "requester-a", Some("work")).await?;

        for claimed in [None, Some("requester-a"), Some("approver-a")] {
            let denied = mint_test_resolve(&state, &request_id, HeaderMap::new(), claimed, Some("work"), approve).await;
            assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        }
        assert_eq!(mint_test_observation_count(&state)?, 0);

        let store = state.fact_store.read().await;
        let pending = crate::mint_requests::get_mint_request(&store, &request_id)
            .ok_or_else(|| std::io::Error::other("auth-off pending mint request missing"))?;
        assert_eq!(pending.status, crate::mint_requests::MINT_REQUEST_STATUS_PENDING);
        assert_eq!(pending.resolved_by_passport, None);
        assert_eq!(pending.resolution_receipt_id, None);
        assert!(crate::passports::get_passport(&store, "requester-a").is_none());
        assert!(!state.data_dir.join("passports/requester-a.key").exists());
    }
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn passport_mint_request_jwt_reviewer_binding_denies_body_and_header_impersonation(
) -> Result<(), Box<dyn std::error::Error>> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    let _secret = EnvVarGuard::set("CORECRUXD_JWT_HS256_SECRET", SECRET);
    let _issuer = EnvVarGuard::set("CORECRUXD_JWT_ISS", "corecrux-test");
    let _audience = EnvVarGuard::set("CORECRUXD_JWT_AUD", "corecrux");

    #[derive(serde::Serialize)]
    struct Claims<'a> {
        exp: usize,
        iss: &'a str,
        aud: &'a str,
        scope: &'a str,
        tenant_id: &'a str,
        passport_id: &'a str,
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let token = encode(
        &Header::new(Algorithm::HS256),
        &Claims {
            exp: now.as_secs().saturating_add(3_600) as usize,
            iss: "corecrux-test",
            aud: "corecrux",
            scope: "admin:write",
            tenant_id: "default",
            passport_id: "approver-a",
        },
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );

    let (state, request_id) = mint_test_state(AuthMode::JwtHs256, "requester-a", "requester-a", Some("work")).await?;
    let spoofed = mint_test_resolve(
        &state,
        &request_id,
        headers.clone(),
        Some("approver-b"),
        Some("work"),
        true,
    )
    .await;
    assert_eq!(spoofed.status(), StatusCode::FORBIDDEN);

    let mut override_headers = headers.clone();
    override_headers.insert("x-corecrux-passport-id", HeaderValue::from_static("approver-b"));
    let impersonated = mint_test_resolve(
        &state,
        &request_id,
        override_headers,
        Some("approver-b"),
        Some("work"),
        true,
    )
    .await;
    assert_eq!(impersonated.status(), StatusCode::FORBIDDEN);
    assert_eq!(mint_test_observation_count(&state)?, 0);

    let accepted = mint_test_resolve(&state, &request_id, headers, None, Some("work"), true).await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let body = json_body(accepted).await;
    let receipt_id = body["receipt_id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("JWT mint receipt id missing"))?;
    let receipt = super::receipts::local_approval_receipt(&state, "default", receipt_id)?
        .ok_or_else(|| std::io::Error::other("JWT mint receipt missing"))?;
    assert_eq!(receipt.reviewer_passport, "approver-a");
    let store = state.fact_store.read().await;
    let resolved = crate::mint_requests::get_mint_request(&store, &request_id)
        .ok_or_else(|| std::io::Error::other("JWT resolved mint request missing"))?;
    assert_eq!(resolved.resolved_by_passport.as_deref(), Some("approver-a"));
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn passport_mint_request_rejects_agent_token_as_human_approval() -> Result<(), Box<dyn std::error::Error>> {
    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const AGENT_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
    let _secret = EnvVarGuard::set("CORECRUXD_JWT_HS256_SECRET", SECRET);
    let _accept = EnvVarGuard::set("CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS", "1");
    let _tokens = EnvVarGuard::set("CRUX_AGENT_TOKENS", &format!("drivew:{AGENT_TOKEN}"));
    let _scopes = EnvVarGuard::set("CORECRUXD_AGENT_TOKEN_HTTP_SCOPES", "admin:write");
    let _tenant = EnvVarGuard::set("CORECRUXD_AGENT_TOKEN_HTTP_TENANT", "default");

    let (state, request_id) = mint_test_state(AuthMode::JwtHs256, "requester-a", "requester-a", Some("work")).await?;
    for approve in [true, false] {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {AGENT_TOKEN}"))?,
        );
        let denied = mint_test_resolve(&state, &request_id, headers, None, Some("work"), approve).await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(mint_test_observation_count(&state)?, 0);
    let store = state.fact_store.read().await;
    let pending = crate::mint_requests::get_mint_request(&store, &request_id)
        .ok_or_else(|| std::io::Error::other("agent-token pending mint request missing"))?;
    assert_eq!(pending.status, crate::mint_requests::MINT_REQUEST_STATUS_PENDING);
    assert!(crate::passports::get_passport(&store, "requester-a").is_none());
    Ok(())
}

#[tokio::test]
async fn passport_mint_request_rejects_sub_only_jwt_as_human_approval() -> Result<(), Box<dyn std::error::Error>> {
    let (state, request_id) = mint_test_verified_state("requester-a", "requester-a", Some("work")).await?;

    for approve in [true, false] {
        let denied = mint_test_resolve(
            &state,
            &request_id,
            mint_test_sub_only_headers("admin:write", "automation-subject"),
            None,
            Some("work"),
            approve,
        )
        .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }

    assert_eq!(mint_test_observation_count(&state)?, 0);
    let store = state.fact_store.read().await;
    let pending = crate::mint_requests::get_mint_request(&store, &request_id)
        .ok_or_else(|| std::io::Error::other("sub-only JWT pending mint request missing"))?;
    assert_eq!(pending.status, crate::mint_requests::MINT_REQUEST_STATUS_PENDING);
    assert_eq!(pending.resolved_by_passport, None);
    assert_eq!(pending.resolution_receipt_id, None);
    assert!(crate::passports::get_passport(&store, "requester-a").is_none());
    assert!(!state.data_dir.join("passports/requester-a.key").exists());
    Ok(())
}

#[tokio::test]
async fn passport_mint_request_receipt_failure_cleans_new_key_and_leaves_request_pending(
) -> Result<(), Box<dyn std::error::Error>> {
    let (state, request_id) = mint_test_verified_state("requester-a", "requester-a", Some("work")).await?;
    let receipt_path =
        super::observations::observation_file_path(&state.data_dir, super::approval_receipts::APPROVAL_RECEIPT_SESSION);
    std::fs::create_dir_all(&receipt_path)?;

    let failed = mint_test_resolve(
        &state,
        &request_id,
        mint_test_verified_headers("admin:write", "approver-a"),
        Some("approver-a"),
        Some("work"),
        true,
    )
    .await;
    assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!state.data_dir.join("passports/requester-a.key").exists());

    let store = state.fact_store.read().await;
    let pending = crate::mint_requests::get_mint_request(&store, &request_id)
        .ok_or_else(|| std::io::Error::other("pending request missing after receipt failure"))?;
    assert_eq!(pending.status, crate::mint_requests::MINT_REQUEST_STATUS_PENDING);
    assert!(crate::passports::get_passport(&store, "requester-a").is_none());
    drop(store);

    let duplicate = {
        let mut store = state.fact_store.write().await;
        crate::mint_requests::file_mint_request(
            &mut store,
            "requester-a".to_string(),
            "requester-a".to_string(),
            Some("work".to_string()),
            None,
            101,
        )
    };
    assert!(matches!(
        duplicate,
        Err(crate::mint_requests::MintRequestError::AlreadyPending {
            request_id: duplicate_request_id,
            ..
        }) if duplicate_request_id == request_id
    ));
    Ok(())
}

#[tokio::test]
async fn passport_mint_request_post_append_sync_failure_retains_key_for_exact_retry(
) -> Result<(), Box<dyn std::error::Error>> {
    let (state, request_id) = mint_test_verified_state("requester-a", "requester-a", Some("work")).await?;
    let receipt_path =
        super::observations::observation_file_path(&state.data_dir, super::approval_receipts::APPROVAL_RECEIPT_SESSION);
    let sync_failure_marker = receipt_path.with_extension("sync-fail");
    if let Some(parent) = sync_failure_marker.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&sync_failure_marker, b"fail after append")?;
    let headers = mint_test_verified_headers("admin:write", "approver-a");

    let failed = mint_test_resolve(
        &state,
        &request_id,
        headers.clone(),
        Some("approver-a"),
        Some("work"),
        true,
    )
    .await;
    assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(mint_test_observation_count(&state)?, 1);
    let key_path = state.data_dir.join("passports/requester-a.key");
    let receipt_bound_key = std::fs::read(&key_path)?;
    {
        let store = state.fact_store.read().await;
        let pending = crate::mint_requests::get_mint_request(&store, &request_id)
            .ok_or_else(|| std::io::Error::other("pending request missing after receipt sync failure"))?;
        assert_eq!(pending.status, crate::mint_requests::MINT_REQUEST_STATUS_PENDING);
        assert!(crate::passports::get_passport(&store, "requester-a").is_none());
    }

    std::fs::remove_file(&sync_failure_marker)?;
    let retried = mint_test_resolve(&state, &request_id, headers, Some("approver-a"), Some("work"), true).await;
    assert_eq!(retried.status(), StatusCode::OK);
    assert_eq!(mint_test_observation_count(&state)?, 1);
    assert_eq!(std::fs::read(&key_path)?, receipt_bound_key);
    let store = state.fact_store.read().await;
    assert!(crate::passports::get_passport(&store, "requester-a").is_some());
    Ok(())
}

#[tokio::test]
async fn passport_mint_request_quarantines_torn_receipt_tail_before_approval() -> Result<(), Box<dyn std::error::Error>>
{
    let (state, request_id) = mint_test_verified_state("requester-a", "requester-a", Some("work")).await?;
    let receipt_path =
        super::observations::observation_file_path(&state.data_dir, super::approval_receipts::APPROVAL_RECEIPT_SESSION);
    if let Some(parent) = receipt_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&receipt_path, br#"{"observation_id":"torn""#)?;

    let approved = mint_test_resolve(
        &state,
        &request_id,
        mint_test_verified_headers("admin:write", "approver-a"),
        Some("approver-a"),
        Some("work"),
        true,
    )
    .await;
    assert_eq!(approved.status(), StatusCode::OK);
    assert_eq!(mint_test_observation_count(&state)?, 1);
    let quarantine_count = std::fs::read_dir(
        receipt_path
            .parent()
            .ok_or_else(|| std::io::Error::other("receipt path parent missing"))?,
    )?
    .filter_map(Result::ok)
    .filter(|entry| entry.file_name().to_string_lossy().contains("jsonl.torn."))
    .count();
    assert_eq!(quarantine_count, 1);
    let store = state.fact_store.read().await;
    assert!(crate::passports::get_passport(&store, "requester-a").is_some());
    Ok(())
}

#[tokio::test]
async fn passport_mint_request_reuses_receipt_bound_key_after_fact_journal_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = mint_test_verified_app_state(16);
    bind_test_state_to_root_passport_key(&mut state);
    state.passport_mint_requests_enabled = true;
    let fact_dir = state.data_dir.join("mint-fact-journal");
    let mut persistent_store = corecrux_memory::FactStore::with_persistence(&fact_dir)?;
    let request_id = crate::mint_requests::file_mint_request(
        &mut persistent_store,
        "requester-a".to_string(),
        "requester-a".to_string(),
        Some("work".to_string()),
        None,
        100,
    )?
    .request_id;
    state.fact_store = Arc::new(RwLock::new(persistent_store));

    let journal_path = fact_dir.join("facts.jsonl");
    let journal_backup = fact_dir.join("facts.before-failure.jsonl");
    std::fs::rename(&journal_path, &journal_backup)?;
    std::fs::create_dir(&journal_path)?;
    let headers = mint_test_verified_headers("admin:write", "approver-a");

    let failed = mint_test_resolve(
        &state,
        &request_id,
        headers.clone(),
        Some("approver-a"),
        Some("work"),
        true,
    )
    .await;
    assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(mint_test_observation_count(&state)?, 1);
    let key_path = state.data_dir.join("passports/requester-a.key");
    let receipt_bound_key = std::fs::read(&key_path)?;
    {
        let store = state.fact_store.read().await;
        let pending = crate::mint_requests::get_mint_request(&store, &request_id)
            .ok_or_else(|| std::io::Error::other("pending request missing after fact failure"))?;
        assert_eq!(pending.status, crate::mint_requests::MINT_REQUEST_STATUS_PENDING);
        assert!(crate::passports::get_passport(&store, "requester-a").is_none());
    }
    let duplicate = {
        let mut store = state.fact_store.write().await;
        crate::mint_requests::file_mint_request(
            &mut store,
            "requester-a".to_string(),
            "requester-a".to_string(),
            Some("work".to_string()),
            None,
            101,
        )
    };
    assert!(matches!(
        duplicate,
        Err(crate::mint_requests::MintRequestError::AlreadyPending {
            request_id: duplicate_request_id,
            ..
        }) if duplicate_request_id == request_id
    ));
    let receipt_records = super::observations::read_observations_strict(&super::observations::observation_file_path(
        &state.data_dir,
        super::approval_receipts::APPROVAL_RECEIPT_SESSION,
    ))?;
    let receipt_record_id = receipt_records
        .first()
        .ok_or_else(|| std::io::Error::other("orphan mint receipt missing"))?
        .observation_id
        .clone();

    std::fs::remove_dir(&journal_path)?;
    std::fs::rename(&journal_backup, &journal_path)?;

    let changed_category = mint_test_resolve(
        &state,
        &request_id,
        headers.clone(),
        Some("approver-a"),
        Some("public"),
        true,
    )
    .await;
    assert_eq!(changed_category.status(), StatusCode::CONFLICT);
    let opposite_decision =
        mint_test_resolve(&state, &request_id, headers.clone(), Some("approver-a"), None, false).await;
    assert_eq!(opposite_decision.status(), StatusCode::CONFLICT);
    assert_eq!(mint_test_observation_count(&state)?, 1);

    let retried = mint_test_resolve(&state, &request_id, headers, Some("approver-a"), Some("work"), true).await;
    assert_eq!(retried.status(), StatusCode::OK);
    let retried_body = json_body(retried).await;
    assert_eq!(retried_body["receipt_record_id"], receipt_record_id);
    assert_eq!(mint_test_observation_count(&state)?, 1);
    assert_eq!(std::fs::read(&key_path)?, receipt_bound_key);

    let store = state.fact_store.read().await;
    let resolved = crate::mint_requests::get_mint_request(&store, &request_id)
        .ok_or_else(|| std::io::Error::other("retried mint request missing"))?;
    assert_eq!(resolved.status, crate::mint_requests::MINT_REQUEST_STATUS_APPROVED);
    assert!(crate::passports::get_passport(&store, "requester-a").is_some());
    Ok(())
}

#[tokio::test]
async fn passport_mint_request_conflicting_approve_cleans_key_after_reject_receipt_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = mint_test_verified_app_state(16);
    bind_test_state_to_root_passport_key(&mut state);
    state.passport_mint_requests_enabled = true;
    let fact_dir = state.data_dir.join("reject-fact-journal");
    let mut persistent_store = corecrux_memory::FactStore::with_persistence(&fact_dir)?;
    let request_id = crate::mint_requests::file_mint_request(
        &mut persistent_store,
        "requester-a".to_string(),
        "requester-a".to_string(),
        Some("work".to_string()),
        None,
        100,
    )?
    .request_id;
    state.fact_store = Arc::new(RwLock::new(persistent_store));
    let journal_path = fact_dir.join("facts.jsonl");
    let journal_backup = fact_dir.join("facts.before-failure.jsonl");
    std::fs::rename(&journal_path, &journal_backup)?;
    std::fs::create_dir(&journal_path)?;
    let headers = mint_test_verified_headers("admin:write", "approver-a");

    let failed_reject = mint_test_resolve(&state, &request_id, headers.clone(), Some("approver-a"), None, false).await;
    assert_eq!(failed_reject.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(mint_test_observation_count(&state)?, 1);
    assert!(!state.data_dir.join("passports/requester-a.key").exists());
    std::fs::remove_dir(&journal_path)?;
    std::fs::rename(&journal_backup, &journal_path)?;

    let conflicting_approve = mint_test_resolve(
        &state,
        &request_id,
        headers.clone(),
        Some("approver-a"),
        Some("work"),
        true,
    )
    .await;
    assert_eq!(conflicting_approve.status(), StatusCode::CONFLICT);
    let facts = state.fact_store.read().await;
    assert!(crate::passports::get_passport(&facts, "requester-a").is_none());
    drop(facts);
    assert!(!state.data_dir.join("passports/requester-a.key").exists());

    let retried_reject = mint_test_resolve(&state, &request_id, headers, Some("approver-a"), None, false).await;
    assert_eq!(retried_reject.status(), StatusCode::OK);
    assert_eq!(mint_test_observation_count(&state)?, 1);
    Ok(())
}

#[tokio::test]
async fn passport_mint_request_concurrent_opposite_decisions_have_one_winner() -> Result<(), Box<dyn std::error::Error>>
{
    let (state, request_id) = mint_test_verified_state("requester-a", "requester-a", Some("work")).await?;
    let headers = mint_test_verified_headers("admin:write", "approver-a");
    let approve = mint_test_resolve(
        &state,
        &request_id,
        headers.clone(),
        Some("approver-a"),
        Some("work"),
        true,
    );
    let reject = mint_test_resolve(&state, &request_id, headers, Some("approver-a"), None, false);
    let (approve, reject) = tokio::join!(approve, reject);
    let mut statuses = [approve.status(), reject.status()];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]);
    assert_eq!(mint_test_observation_count(&state)?, 1);

    let store = state.fact_store.read().await;
    let resolved = crate::mint_requests::get_mint_request(&store, &request_id)
        .ok_or_else(|| std::io::Error::other("concurrently resolved mint request missing"))?;
    assert!(matches!(
        resolved.status.as_str(),
        crate::mint_requests::MINT_REQUEST_STATUS_APPROVED | crate::mint_requests::MINT_REQUEST_STATUS_REJECTED
    ));
    assert_eq!(
        crate::passports::get_passport(&store, "requester-a").is_some(),
        resolved.status == crate::mint_requests::MINT_REQUEST_STATUS_APPROVED
    );
    Ok(())
}

#[tokio::test]
async fn passports_filter_by_category_returns_only_matching() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let resp = super::passports::get_passports(
        State(state),
        Query(super::passports::ListPassportsQuery {
            category: Some("work".to_string()),
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    let body = json_body(resp).await;
    let passports = body["passports"].as_array().expect("passports array");
    assert_eq!(passports.len(), 1);
    assert_eq!(passports[0]["id"], "work-default");
}

#[tokio::test]
async fn passports_filter_rejects_bogus_category() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::passports::get_passports(
        State(state),
        Query(super::passports::ListPassportsQuery {
            category: Some("bogus".to_string()),
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn passports_post_round_trip_to_get() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let post_resp = super::passports::post_passport(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::passports::CreatePassportBody {
            id: "alice".to_string(),
            category: "personal".to_string(),
            sponsor_id: None,
            agent_work_gate: false,
            is_default_for_category: false,
            name: None,
            owner: None,
            position: None,
            company: None,
            notes: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(post_resp.status(), StatusCode::CREATED);

    let get_resp =
        super::passports::get_passport(State(state), Path("alice".to_string()), dev_scope_headers("admin:read"))
            .await
            .into_response();
    assert_eq!(get_resp.status(), StatusCode::OK);
    let body = json_body(get_resp).await;
    assert_eq!(body["id"], "alice");
    assert_eq!(body["category"], "personal");
    assert!(body["principal_id"].as_str().unwrap_or("").starts_with("p_"));
}

#[tokio::test]
async fn passports_post_duplicate_id_returns_409() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let mk = || super::passports::CreatePassportBody {
        id: "alice".to_string(),
        category: "personal".to_string(),
        sponsor_id: None,
        agent_work_gate: false,
        is_default_for_category: false,
        name: None,
        owner: None,
        position: None,
        company: None,
        notes: None,
    };
    let first = super::passports::post_passport(State(state.clone()), dev_scope_headers("admin:write"), Json(mk()))
        .await
        .into_response();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = super::passports::post_passport(State(state), dev_scope_headers("admin:write"), Json(mk()))
        .await
        .into_response();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn passports_patch_updates_gate_and_default_flag() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let _ = super::passports::post_passport(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::passports::CreatePassportBody {
            id: "alice".to_string(),
            category: "personal".to_string(),
            sponsor_id: None,
            agent_work_gate: false,
            is_default_for_category: false,
            name: None,
            owner: None,
            position: None,
            company: None,
            notes: None,
        }),
    )
    .await
    .into_response();
    let resp = super::passports::patch_passport(
        State(state),
        Path("alice".to_string()),
        dev_scope_headers("admin:read"),
        Json(super::passports::UpdatePassportBody {
            category: Some("work".to_string()),
            agent_work_gate: Some(true),
            is_default_for_category: Some(true),
            sponsor_id: None,
            reputation_tier: None,
            receipt_count: None,
            name: None,
            owner: None,
            position: None,
            company: None,
            notes: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["category"], "work");
    assert_eq!(body["agent_work_gate"], true);
    assert_eq!(body["is_default_for_category"], true);
}

#[tokio::test]
async fn passports_delete_removes_record() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let _ = super::passports::post_passport(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::passports::CreatePassportBody {
            id: "alice".to_string(),
            category: "personal".to_string(),
            sponsor_id: None,
            agent_work_gate: false,
            is_default_for_category: false,
            name: None,
            owner: None,
            position: None,
            company: None,
            notes: None,
        }),
    )
    .await
    .into_response();
    let del_resp = super::passports::delete_passport(
        State(state.clone()),
        Path("alice".to_string()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);
    let get_resp =
        super::passports::get_passport(State(state), Path("alice".to_string()), dev_scope_headers("admin:read"))
            .await
            .into_response();
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn active_sessions_returns_seeded_bindings() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
        let b = crate::session_bindings::resolve(
            &store,
            crate::session_bindings::ResolveInput {
                session_id_hex: "deadbeef",
                project_id: Some("proj-x".to_string()),
                tenant_id: Some("work::team".to_string()),
                passport_id: None,
                now_unix_ms: 1_700_000_000_000,
            },
        )
        .expect("resolve");
        crate::session_bindings::write_binding(&mut store, &b).expect("write");
    }

    let resp = super::session::get_active_sessions(State(state), dev_scope_headers("admin:read")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["count"], 1);
    let s = &body["sessions"][0];
    assert_eq!(s["session_id_hex"], "deadbeef");
    assert_eq!(s["passport_id"], "work-default");
    assert_eq!(s["passport_category"], "work");
    assert_eq!(s["tenant_id"], "work::team");
    assert_eq!(s["project_id"], "proj-x");
    assert_eq!(s["agent_work_gate"], false);
}

#[tokio::test]
async fn active_sessions_requires_admin_read() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::session::get_active_sessions(State(state), HeaderMap::new()).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_plan_read_through_returns_sealed_v1_plan() {
    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    state.session = Some(Arc::new(super::session::SessionServices::local_default("node-a")));
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed passports");
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let create_resp = super::session::post_session(
        State(state.clone()),
        headers,
        axum::body::Bytes::from_static(
            br#"{"client_id":"test-agent","client_version":"0.1.0","accepts":["application/json"],"intent":"audit"}"#,
        ),
    )
    .await;
    assert_eq!(create_resp.status(), StatusCode::OK);
    let session_id = create_resp
        .headers()
        .get("x-cuecrux-session-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(session_id.len(), 32);

    let read_resp = super::session::get_session_plan(
        State(state),
        Path(session_id.clone()),
        dev_scope_passport_headers("sessions:read", "personal-default"),
    )
    .await;
    assert_eq!(read_resp.status(), StatusCode::OK);
    assert_eq!(
        read_resp
            .headers()
            .get("x-cuecrux-session-id")
            .and_then(|value| value.to_str().ok()),
        Some(session_id.as_str())
    );
    assert!(read_resp.headers().get("x-cuecrux-plan-hash").is_some());
    let body = json_body(read_resp).await;
    assert_eq!(body["schema"], "crux.session_plan.read.v2");
    assert_eq!(body["session_id"], session_id);
    assert_eq!(body["contract"], "cuecrux.shared.session_plan.v2");
    assert_eq!(body["legacy_contract"], "crux.session_plan.v1");
    assert_eq!(body["target_contract"], "cuecrux.shared.session_plan.v2");
    assert_eq!(body["status"], "current");
    assert_eq!(body["plan"]["plan_version"], 1);
    assert!(body["plan"]["capability_graph"].is_object());
    assert!(body["plan"]["capability_graph"]["nodes"].is_array());
    assert!(body["plan"]["capability_graph"]["edges"].is_array());
}

#[tokio::test]
async fn session_plan_read_through_requires_session_scope() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::session::get_session_plan(
        State(state),
        Path("00000000000000000000000000000000".to_string()),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invocation_verify_disabled_and_bad_request_paths() {
    let state = test_app_state(16);
    let disabled = super::invocation::post_invocation_verify(State(state), axum::body::Bytes::from_static(b"{}")).await;
    assert_eq!(disabled.status(), StatusCode::SERVICE_UNAVAILABLE);

    let mut state = test_app_state(16);
    state.session = Some(Arc::new(super::session::SessionServices::local_default("node-a")));
    let bad_json =
        super::invocation::post_invocation_verify(State(state.clone()), axum::body::Bytes::from_static(b"{")).await;
    assert_eq!(bad_json.status(), StatusCode::BAD_REQUEST);

    let invalid_wire = serde_json::json!({
        "invocation_id": "not-hex",
        "session_id": "00".repeat(16),
        "parent_plan_receipt_hash": "00".repeat(32),
        "capability": "retrieve",
        "channel": "mcp",
        "invoked_at": 1,
        "completed_at": 2,
        "input_hash": "00".repeat(32),
        "output_hash": "00".repeat(32),
        "outcome": "ok",
        "receipt_hash": "00".repeat(32)
    });
    let invalid = super::invocation::post_invocation_verify(
        State(state),
        axum::body::Bytes::from(serde_json::to_vec(&invalid_wire).unwrap()),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invocation_verify_parent_not_found_and_success_paths() {
    let mut state = test_app_state(16);
    let services = Arc::new(super::session::SessionServices::local_default("node-a"));
    state.session = Some(services.clone());

    let not_found_wire = serde_json::json!({
        "invocation_id": "11".repeat(16),
        "session_id": "22".repeat(16),
        "parent_plan_receipt_hash": "33".repeat(32),
        "capability": "retrieve",
        "channel": "mcp",
        "invoked_at": 1,
        "completed_at": 2,
        "input_hash": "44".repeat(32),
        "output_hash": "55".repeat(32),
        "outcome": "ok",
        "cost_crux": 7,
        "receipt_hash": "66".repeat(32),
        "receipt_signature": "77".repeat(64),
        "signer_kid": "kid-test"
    });
    let not_found = super::invocation::post_invocation_verify(
        State(state.clone()),
        axum::body::Bytes::from(serde_json::to_vec(&not_found_wire).unwrap()),
    )
    .await;
    assert_eq!(not_found.status(), StatusCode::OK);
    let not_found_body = json_body(not_found).await;
    assert_eq!(not_found_body["verified"], false);
    assert_eq!(not_found_body["parent_plan_found"], false);
    assert_eq!(not_found_body["governance_faults"][0], "parent_plan_not_found");

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let create = super::session::post_session(
        State(state.clone()),
        headers,
        axum::body::Bytes::from_static(
            br#"{"client_id":"test-agent","client_version":"0.1.0","accepts":["application/json"],"intent":"audit"}"#,
        ),
    )
    .await;
    assert_eq!(create.status(), StatusCode::OK);
    let session_id_hex = create
        .headers()
        .get("x-cuecrux-session-id")
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    let session_bytes: [u8; 16] = hex::decode(&session_id_hex).unwrap().try_into().unwrap();
    let entry = services.registry.get(&session_bytes).unwrap().unwrap();
    let plan = crux_session::SessionPlan::from_canonical_cbor(&entry.plan_cbor).unwrap();
    let cap = plan.capability_graph.first().unwrap();
    let receipt = crux_session::mint_invocation_receipt(crux_session::MintInvocation {
        invocation_id: [0x99; 16],
        parent_plan: &plan,
        capability: cap.cap.clone(),
        channel: cap.prefer.clone(),
        invoked_at_ms: 10,
        completed_at_ms: 11,
        input_hash: [0x44; 32],
        output_hash: [0x55; 32],
        outcome: "ok".to_string(),
        cost_crux: Some(7),
        signer_kid: Some("kid-test".to_string()),
    });
    let ok_wire = serde_json::json!({
        "invocation_id": hex::encode(receipt.invocation_id),
        "session_id": hex::encode(receipt.session_id),
        "parent_plan_receipt_hash": hex::encode(receipt.parent_plan_receipt_hash),
        "capability": receipt.capability,
        "channel": receipt.channel,
        "invoked_at": receipt.invoked_at,
        "completed_at": receipt.completed_at,
        "input_hash": hex::encode(receipt.input_hash),
        "output_hash": hex::encode(receipt.output_hash),
        "outcome": receipt.outcome,
        "cost_crux": receipt.cost_crux,
        "receipt_hash": hex::encode(receipt.receipt_hash),
        "signer_kid": receipt.signer_kid
    });
    let ok = super::invocation::post_invocation_verify(
        State(state),
        axum::body::Bytes::from(serde_json::to_vec(&ok_wire).unwrap()),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    let ok_body = json_body(ok).await;
    assert_eq!(ok_body["verified"], true);
    assert_eq!(ok_body["parent_plan_found"], true);
    assert!(ok_body["parent_plan_principal_id"].as_str().unwrap().starts_with("ce:"));
}

#[tokio::test]
async fn engram_list_session_init_and_resolve_match_hosted_shape() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    let list_resp = super::engrams::list_engrams(
        State(state.clone()),
        dev_scope_headers("query:read"),
        Query(super::engrams::ListEngramsQuery {
            intent_bucket: Some("developer_surface".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_body = json_body(list_resp).await;
    assert_eq!(list_body["schema"], "crux.local.engrams.list.v1");
    assert!(list_body["engrams"].as_array().expect("engrams").iter().any(|engram| {
        engram["name"] == "route-impact-preflight"
            && engram["version"] == "v1"
            && engram["content"].is_null()
            && engram["prompt_hash"]
                .as_str()
                .unwrap_or_default()
                .starts_with("blake3:")
    }));

    let init_resp = super::engrams::memory_session_init(
        State(state.clone()),
        dev_scope_headers("sessions:read"),
        Json(super::engrams::SessionInitBody {
            tenant_id: Some("tenant-a".to_string()),
            tenant_id_camel: None,
            agent_id: Some("codex".to_string()),
            agent_id_camel: None,
            model_id: Some("local-cpu".to_string()),
            model_id_camel: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(init_resp.status(), StatusCode::OK);
    let init_body = json_body(init_resp).await;
    assert_eq!(init_body["schema"], "crux.memory.session_init.v1");
    assert_eq!(
        init_body["session_procedure"]["schema"],
        "cuecrux.memory.session_procedure.v1"
    );
    assert!(init_body["session_procedure_hash"]
        .as_str()
        .unwrap_or_default()
        .starts_with("blake3:"));
    let manifest_hash = init_body["engram_manifest"]["manifest_hash"]
        .as_str()
        .expect("manifest hash")
        .to_string();

    let resolve_resp = super::engrams::resolve_engrams(
        State(state),
        dev_scope_headers("query:read"),
        Json(super::engrams::ResolveEngramsBody {
            tenant_id: Some("tenant-a".to_string()),
            tenant_id_camel: None,
            agent_id: Some("codex".to_string()),
            agent_id_camel: None,
            names: vec!["route-impact-preflight@v1".to_string()],
            manifest_hash: Some(manifest_hash),
            model_id: Some("local-cpu".to_string()),
            model_id_camel: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resolve_resp.status(), StatusCode::OK);
    let resolve_body = json_body(resolve_resp).await;
    assert_eq!(resolve_body["schema"], "crux.memory.engrams.resolve.v1");
    assert_eq!(resolve_body["manifest_status"], "current");
    assert_eq!(resolve_body["engrams"][0]["name"], "route-impact-preflight");
    assert!(resolve_body["engrams"][0]["content"]
        .as_str()
        .unwrap_or_default()
        .contains("HTTP/gRPC work"));
    assert!(resolve_body["engram_set_hash"]["hash"]
        .as_str()
        .unwrap_or_default()
        .starts_with("blake3:"));
    assert!(resolve_body["receipt_linkage"]["receipt_id"]
        .as_str()
        .unwrap_or_default()
        .starts_with("local-engram-dispatch:"));
}

#[tokio::test]
async fn rcx_publish_passport_preview_builds_signed_schema_record() {
    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    bind_test_state_to_root_passport_key(&mut state);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::create_passport(
            &state.data_dir,
            &mut store,
            crate::passports::CreatePassportInput {
                id: "personal_default".to_string(),
                category: "personal".to_string(),
                sponsor_id: None,
                agent_work_gate: true,
                is_default_for_category: true,
                name: None,
                owner: None,
                position: None,
                company: None,
                notes: None,
            },
            1_700_000_000_000,
        )
        .expect("create passport");
    }

    let resp = super::rcx_publish::preview_passport(
        State(state.clone()),
        Path("personal_default".to_string()),
        dev_scope_headers("admin:read"),
        Json(super::rcx_publish::PublishBody {
            registry_url: None,
            operator_metadata: Some(serde_json::json!({"channel": "test"})),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["schema"], "crux.rcx_publish.preview.v1");
    assert_eq!(
        body["record"]["schema_uri"],
        "https://static.rcxprotocol.org/schemas/2026-05-01/passport-publish.schema.json"
    );
    assert_eq!(body["record"]["publisher_passport"], state.passport_fpr);
    assert_eq!(body["record"]["passport_id"], "personal_default");
    assert_eq!(body["record"]["operator_metadata"]["channel"], "test");
    assert_eq!(body["record"]["passport_hash"].as_str().unwrap_or_default().len(), 64);
    assert_eq!(body["record"]["signature"].as_str().unwrap_or_default().len(), 128);
}

#[tokio::test]
async fn rcx_publish_project_emit_stores_local_receipt() {
    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    bind_test_state_to_root_passport_key(&mut state);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::create_passport(
            &state.data_dir,
            &mut store,
            crate::passports::CreatePassportInput {
                id: "work_default".to_string(),
                category: "work".to_string(),
                sponsor_id: None,
                agent_work_gate: true,
                is_default_for_category: true,
                name: None,
                owner: None,
                position: None,
                company: None,
                notes: None,
            },
            1_700_000_000_000,
        )
        .expect("create passport");
        crate::projects::create_project(
            &mut store,
            crate::projects::CreateProjectInput {
                id: "alpha".to_string(),
                name: "Alpha".to_string(),
                planning_target: Some("tenant://tenant-alpha".to_string()),
                default_passport_id: "work_default".to_string(),
                working_tenants: vec!["tenant-alpha".to_string()],
            },
            1_700_000_100_000,
        )
        .expect("create project");
        crate::project_repo_links::link_repo(
            &mut store,
            "alpha",
            "CueCrux/Crux",
            None,
            "work",
            Some("work_default".to_string()),
            1_700_000_200_000,
        )
        .expect("link repo");
    }

    let resp = super::rcx_publish::emit_project(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::rcx_publish::PublishBody {
            registry_url: None,
            operator_metadata: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert_eq!(body["schema"], "crux.rcx_publish.emit.v1");
    assert_eq!(body["submitted"], false);
    assert_eq!(body["receipt"]["kind"], "project");
    assert_eq!(body["receipt"]["record"]["project_id"], "alpha");
    assert_eq!(body["receipt"]["record"]["linked_github_repos"][0], "CueCrux/Crux");
    assert_eq!(
        body["receipt"]["record"]["project_hash"]
            .as_str()
            .unwrap_or_default()
            .len(),
        64
    );

    let store = state.fact_store.read().await;
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some("__rcx_publish__::project::alpha".to_string()),
        entity_prefix: None,
        top_k: 10,
        token_budget: None,
    });
    assert_eq!(result.facts.len(), 1);
    assert!(result.facts[0].private);
    assert!(result.facts[0].value.contains("crux.rcx_publish.receipt.v1"));
}

#[tokio::test]
async fn projects_create_then_list_then_get() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }

    let create_resp = super::projects::post_project(
        State(state.clone()),
        dev_scope_headers("admin:read"),
        Json(super::projects::CreateProjectBody {
            id: "alpha".to_string(),
            name: "Alpha".to_string(),
            planning_target: Some("tenant://alpha-planning".to_string()),
            default_passport_id: "personal-default".to_string(),
            working_tenants: vec!["personal::alpha".to_string()],
        }),
    )
    .await
    .into_response();
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let list_resp = super::projects::get_projects(State(state.clone()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let list_body = json_body(list_resp).await;
    let projects = list_body["projects"].as_array().expect("projects");
    assert_eq!(projects.len(), 1);

    let get_resp =
        super::projects::get_project(State(state), Path("alpha".to_string()), dev_scope_headers("admin:read"))
            .await
            .into_response();
    let detail = json_body(get_resp).await;
    assert_eq!(detail["id"], "alpha");
    assert_eq!(detail["members"].as_array().expect("members").len(), 1);
    assert_eq!(detail["tenants"].as_array().expect("tenants").len(), 1);
}

#[tokio::test]
async fn projects_invalid_planning_target_returns_400() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let resp = super::projects::post_project(
        State(state),
        dev_scope_headers("admin:read"),
        Json(super::projects::CreateProjectBody {
            id: "alpha".to_string(),
            name: "Alpha".to_string(),
            planning_target: Some("https://example.com".to_string()),
            default_passport_id: "personal-default".to_string(),
            working_tenants: vec![],
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn projects_add_unknown_passport_returns_404() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let _ = super::projects::post_project(
        State(state.clone()),
        dev_scope_headers("admin:read"),
        Json(super::projects::CreateProjectBody {
            id: "alpha".to_string(),
            name: "Alpha".to_string(),
            planning_target: None,
            default_passport_id: "personal-default".to_string(),
            working_tenants: vec![],
        }),
    )
    .await
    .into_response();

    let resp = super::projects::post_project_member(
        State(state),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read"),
        Json(super::projects::AddMemberBody {
            passport_id: "ghost".to_string(),
            role: "contributor".to_string(),
        }),
    )
    .await
    .into_response();
    // Hardening: missing passport now returns 404 (PassportNotFound) not 400.
    // Distinguishing "passport doesn't exist" from "exists but not allowed"
    // makes API errors actionable without reading source.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn projects_delete_removes_subentities() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let _ = super::projects::post_project(
        State(state.clone()),
        dev_scope_headers("admin:read"),
        Json(super::projects::CreateProjectBody {
            id: "alpha".to_string(),
            name: "Alpha".to_string(),
            planning_target: None,
            default_passport_id: "personal-default".to_string(),
            working_tenants: vec!["personal::alpha".to_string()],
        }),
    )
    .await
    .into_response();
    let del = super::projects::delete_project(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(del.status(), StatusCode::NO_CONTENT);
    let get = super::projects::get_project(State(state), Path("alpha".to_string()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(get.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn projects_members_tenants_layers_repos_and_graph_round_trip() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }

    let create_resp = super::projects::post_project(
        State(state.clone()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::projects::CreateProjectBody {
            id: "alpha".to_string(),
            name: "Alpha".to_string(),
            planning_target: Some("github://cuecrux/crux".to_string()),
            default_passport_id: "personal-default".to_string(),
            working_tenants: vec!["tenant-a".to_string()],
        }),
    )
    .await
    .into_response();
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let patch_resp = super::projects::patch_project(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read"),
        Json(super::projects::UpdateProjectBody {
            name: Some("Alpha Updated".to_string()),
            planning_target: Some(None),
            default_passport_id: None,
            archived: Some(false),
            is_default: Some(true),
        }),
    )
    .await
    .into_response();
    let patched = json_body(patch_resp).await;
    assert_eq!(patched["name"], "Alpha Updated");
    assert!(patched["planning_target"].is_null());

    let member_resp = super::projects::post_project_member(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read"),
        Json(super::projects::AddMemberBody {
            passport_id: "work-default".to_string(),
            role: "reviewer".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(member_resp.status(), StatusCode::CREATED);

    let tenant_resp = super::projects::post_project_tenant(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read"),
        Json(super::projects::AddTenantBody {
            tenant_id: "tenant-b".to_string(),
            default_passport_id: Some("public-default".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(tenant_resp.status(), StatusCode::CREATED);

    let layer_resp = super::projects::put_project_layer(
        State(state.clone()),
        Path(("alpha".to_string(), "vision".to_string())),
        dev_scope_headers("facts:write"),
        Json(super::projects::PutLayerBody {
            content: "project context".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(layer_resp.status(), StatusCode::OK);

    let layers = super::projects::get_project_layers(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    let layers_body = json_body(layers).await;
    assert_eq!(layers_body["count"], 1);

    let repo_resp = super::projects::post_project_repo(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_passport_headers("facts:write", "work-default"),
        Json(super::projects::LinkRepoBody {
            repo: "cuecrux/crux".to_string(),
            plane_id: Some("daemon".to_string()),
            role: "work".to_string(),
        }),
    )
    .await
    .into_response();
    let repo_body = json_body(repo_resp).await;
    assert_eq!(repo_body["owner"], "cuecrux");

    let repos = super::projects::get_project_repos(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(json_body(repos).await["count"], 1);

    let plane_repos = super::projects::get_plane_repos(
        State(state.clone()),
        Path(("alpha".to_string(), "daemon".to_string())),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(json_body(plane_repos).await["count"], 1);

    let graph = super::projects::get_context_graph(
        State(state.clone()),
        Path("alpha".to_string()),
        Query(super::projects::GraphQuery {
            include_workspace: false,
            include_symbols: false,
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(graph.status(), StatusCode::OK);
    let graph_body = json_body(graph).await;
    assert!(graph_body["nodes"].as_array().expect("nodes").len() >= 2);

    let delete_repo = super::projects::delete_project_repo(
        State(state.clone()),
        Path(("alpha".to_string(), "cuecrux".to_string(), "crux".to_string())),
        dev_scope_headers("facts:write"),
    )
    .await
    .into_response();
    assert_eq!(delete_repo.status(), StatusCode::NO_CONTENT);

    let delete_layer = super::projects::delete_project_layer(
        State(state.clone()),
        Path(("alpha".to_string(), "vision".to_string())),
        dev_scope_headers("facts:write"),
    )
    .await
    .into_response();
    assert_eq!(delete_layer.status(), StatusCode::OK);

    let delete_tenant = super::projects::delete_project_tenant(
        State(state.clone()),
        Path(("alpha".to_string(), "tenant-b".to_string())),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(delete_tenant.status(), StatusCode::NO_CONTENT);

    let delete_member = super::projects::delete_project_member(
        State(state),
        Path(("alpha".to_string(), "work-default".to_string())),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(delete_member.status(), StatusCode::NO_CONTENT);
}

#[serial_test::serial]
#[tokio::test]
async fn work_post_then_list_then_patch_state_round_trip() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
        crate::projects::seed_default_if_missing(&mut store, 1).expect("project seed");
    }

    let create_resp = super::work::post_work(
        State(state.clone()),
        dev_scope_headers("facts:write"),
        Json(super::work::CreateWorkBody {
            project_id: "default".to_string(),
            title: "fix the thing".to_string(),
            body: None,
            state: None,
            assignee_passport: Some("personal-default".to_string()),
            tenant_id: Some("personal".to_string()),
            linked_pr: None,
            linked_issue: None,
            created_by_passport: "personal-default".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let created = json_body(create_resp).await;
    let work_id = created["id"].as_str().expect("id").to_string();

    let list_resp = super::work::get_work(
        State(state.clone()),
        Query(super::work::ListWorkQuery {
            project_id: Some("default".to_string()),
            state: Some("planned".to_string()),
            tenant_id: None,
            assignee_passport: None,
            source: super::work::WorkSource::default(),
            orchestrator: None,
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    let list_body = json_body(list_resp).await;
    assert_eq!(list_body["count"], 1);

    let patch_resp = super::work::patch_work(
        State(state.clone()),
        Path(work_id.clone()),
        dev_scope_headers("facts:write"),
        Json(super::work::UpdateWorkBody {
            title: None,
            body: None,
            state: Some("in_progress".to_string()),
            assignee_passport: None,
            tenant_id: None,
            linked_pr: None,
            linked_issue: None,
            blocker_reason: None,
            blocker_kind: None,
            by_passport: "personal-default".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(patch_resp.status(), StatusCode::OK);
    let patched = json_body(patch_resp).await;
    assert_eq!(patched["applied"], true);
    assert_eq!(patched["work"]["state"], "in_progress");

    let txn_resp = super::work::get_transitions(State(state), Path(work_id), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let txn_body = json_body(txn_resp).await;
    let txns = txn_body["transitions"].as_array().expect("transitions");
    assert_eq!(txns.len(), 2, "create + transition");
    assert_eq!(txns[0]["from_state"], "(none)");
    assert_eq!(txns[1]["to_state"], "in_progress");
}

#[serial_test::serial]
#[tokio::test]
async fn work_source_all_handler_round_trips_plan_content_hash() -> Result<(), Box<dyn std::error::Error>> {
    const PLAN_BYTES: &[u8] = b"# Canonical handler fixture\n\nStatus: Planned\n";
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("canonical.md"), PLAN_BYTES)?;
    let root_display = root.path().display().to_string();
    let _execplans_root = EnvVarGuard::set(crate::work_execplans::EXECPLANS_ROOT_ENV, &root_display);
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    let response = super::work::get_work(
        State(state),
        Query(super::work::ListWorkQuery {
            project_id: None,
            state: Some("planned".to_string()),
            tenant_id: None,
            assignee_passport: None,
            source: super::work::WorkSource::All,
            orchestrator: None,
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);

    let body = json_body(response).await;
    let Some(work) = body["work"].as_array() else {
        return Err(std::io::Error::other("work response must contain an array").into());
    };
    let Some(item) = work.iter().find(|item| item["id"] == "execplan:canonical") else {
        return Err(std::io::Error::other("canonical ExecPlan missing from work response").into());
    };
    let expected = blake3::hash(PLAN_BYTES).to_hex().to_string();

    assert_eq!(body["source"], "all");
    assert_eq!(body["count"], 1);
    assert_eq!(item["plan_content_hash"].as_str(), Some(expected.as_str()));
    Ok(())
}

#[tokio::test]
async fn status_feed_disabled_returns_notice_not_error() {
    // With the feature flag unset (the default), the handler returns a 200
    // disabled-notice rather than an error — clients can probe it safely.
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::work::get_status_feed(
        State(state),
        axum::extract::Query(super::work::StatusFeedQuery {
            work_id: None,
            limit: None,
        }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["enabled"], false);
    assert_eq!(body["feature_flag"], "CORECRUXD_FEATURE_STATUS_FEED");
    assert!(body["events"].as_array().expect("events array").is_empty());
}

async fn gate_test_state(
    auth_mode: AuthMode,
    tenant_id: Option<&str>,
) -> Result<(AppState, String, String), Box<dyn std::error::Error>> {
    let mut state = test_app_state_with_auth(16, auth_mode);
    bind_test_state_to_root_passport_key(&mut state);
    let (work_id, action_id) = {
        let mut store = state.fact_store.write().await;
        seed_gate_test_store(&state.data_dir, &mut store, tenant_id)?
    };
    Ok((state, work_id, action_id))
}

fn seed_gate_test_store(
    data_dir: &std::path::Path,
    store: &mut corecrux_memory::FactStore,
    tenant_id: Option<&str>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    crate::passports::seed_defaults_if_missing(data_dir, store, 1)?;
    crate::projects::seed_default_if_missing(store, 1)?;
    let work = crate::work::create_work(
        store,
        crate::work::CreateWorkInput {
            project_id: "default".to_string(),
            title: "approval identity test".to_string(),
            body: None,
            state: None,
            assignee_passport: None,
            tenant_id: tenant_id.map(str::to_string),
            linked_pr: None,
            linked_issue: None,
            created_by_passport: "requester-a".to_string(),
        },
        1_000,
    )?;
    let outcome = crate::work::update_work(
        store,
        &work.id,
        crate::work::UpdateWorkInput {
            title: None,
            body: None,
            state: Some("complete".to_string()),
            assignee_passport: None,
            tenant_id: None,
            linked_pr: None,
            linked_issue: None,
            blocker_reason: None,
            blocker_kind: None,
        },
        crate::work::UpdateWorkContext {
            by_passport: "requester-a".to_string(),
            passport_gated: true,
            now_unix_ms: 2_000,
        },
    )?;
    let crate::work::UpdateOutcome::Queued(pending) = outcome else {
        return Err(std::io::Error::other("gate test update was not queued").into());
    };
    Ok((work.id, pending.action_id.clone()))
}

async fn gate_test_resolve(
    state: &AppState,
    action_id: &str,
    headers: HeaderMap,
    approver_hint: Option<&str>,
    approve: bool,
) -> Response {
    let body = super::work::GateResolutionBody {
        approver_passport: approver_hint.map(str::to_string),
    };
    if approve {
        super::work::post_gate_approve(State(state.clone()), Path(action_id.to_string()), headers, Json(body))
            .await
            .into_response()
    } else {
        super::work::post_gate_reject(State(state.clone()), Path(action_id.to_string()), headers, Json(body))
            .await
            .into_response()
    }
}

fn gate_test_latest_fact(
    store: &corecrux_memory::FactStore,
    entity: &str,
) -> Option<corecrux_memory::fact_store::Fact> {
    store
        .all_facts()
        .filter(|fact| fact.entity == entity && fact.key == crate::work::RECORD_KEY && !fact.deleted)
        .max_by_key(|fact| fact.version)
        .cloned()
}

fn gate_test_fact_count(store: &corecrux_memory::FactStore) -> usize {
    store.all_facts().count()
}

fn gate_test_observation_count(state: &AppState) -> Result<usize, Box<dyn std::error::Error>> {
    let path = super::observations::observation_file_path(&state.data_dir, super::work::WORK_GATE_RECEIPT_SESSION);
    Ok(super::observations::read_observations_strict(&path)?.len())
}

#[tokio::test]
async fn work_gate_spoofed_body_is_denied_and_bound_passport_is_stored() -> Result<(), Box<dyn std::error::Error>> {
    for approve in [true, false] {
        let (state, _work_id, action_id) = gate_test_state(AuthMode::DevScopes, Some("tenant-a")).await?;
        let spoofed = gate_test_resolve(
            &state,
            &action_id,
            dev_scope_passport_headers("facts:write", "approver-a"),
            Some("approver-b"),
            approve,
        )
        .await;
        assert_eq!(spoofed.status(), StatusCode::FORBIDDEN);

        {
            let store = state.fact_store.read().await;
            let entity = format!("{}::{action_id}", crate::work::WORK_GATE_ENTITY_PREFIX);
            let Some(fact) = gate_test_latest_fact(&store, &entity) else {
                return Err(std::io::Error::other("pending gate fact missing after spoof attempt").into());
            };
            let gate: crate::work::PendingGateAction = serde_json::from_str(&fact.value)?;
            assert_eq!(gate.status, "pending");
            assert_ne!(gate.resolved_by_passport.as_deref(), Some("approver-b"));
        }

        let accepted = gate_test_resolve(
            &state,
            &action_id,
            dev_scope_passport_headers("facts:write", "approver-a"),
            Some("approver-a"),
            approve,
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::OK);
        let store = state.fact_store.read().await;
        let entity = format!("{}::{action_id}", crate::work::WORK_GATE_ENTITY_PREFIX);
        let Some(fact) = gate_test_latest_fact(&store, &entity) else {
            return Err(std::io::Error::other("resolved gate fact missing").into());
        };
        let gate: crate::work::PendingGateAction = serde_json::from_str(&fact.value)?;
        assert_eq!(gate.resolved_by_passport.as_deref(), Some("approver-a"));
        assert_ne!(gate.resolved_by_passport.as_deref(), Some("approver-b"));
    }
    Ok(())
}

#[tokio::test]
async fn work_gate_read_only_token_is_denied_in_route_auth_shadow() -> Result<(), Box<dyn std::error::Error>> {
    for approve in [true, false] {
        let (state, _work_id, action_id) = gate_test_state(AuthMode::DevScopes, Some("tenant-a")).await?;
        let app = router_with_route_auth(state.clone(), test_case_store(), RouteAuthMode::Shadow);
        let uri = if approve {
            format!("/v1/work/gate/{action_id}/approve")
        } else {
            format!("/v1/work/gate/{action_id}/reject")
        };
        let payload = serde_json::to_vec(&serde_json::json!({"approver_passport": "approver-a"}))?;
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .body(axum::body::Body::from(payload))?;
        *request.headers_mut() = dev_scope_passport_headers("admin:read", "approver-a");
        request
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let response = app.oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let store = state.fact_store.read().await;
        let entity = format!("{}::{action_id}", crate::work::WORK_GATE_ENTITY_PREFIX);
        let Some(fact) = gate_test_latest_fact(&store, &entity) else {
            return Err(std::io::Error::other("pending gate fact missing after read-only attempt").into());
        };
        let gate: crate::work::PendingGateAction = serde_json::from_str(&fact.value)?;
        assert_eq!(gate.status, "pending");
    }
    Ok(())
}

#[tokio::test]
async fn work_gate_missing_passport_is_denied_closed() -> Result<(), Box<dyn std::error::Error>> {
    for approve in [true, false] {
        let (state, _work_id, action_id) = gate_test_state(AuthMode::DevScopes, Some("tenant-a")).await?;
        let response = gate_test_resolve(
            &state,
            &action_id,
            dev_scope_headers("facts:write"),
            Some("approver-a"),
            approve,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let store = state.fact_store.read().await;
        let entity = format!("{}::{action_id}", crate::work::WORK_GATE_ENTITY_PREFIX);
        let Some(fact) = gate_test_latest_fact(&store, &entity) else {
            return Err(std::io::Error::other("pending gate fact missing after anonymous attempt").into());
        };
        let gate: crate::work::PendingGateAction = serde_json::from_str(&fact.value)?;
        assert_eq!(gate.status, "pending");
    }
    Ok(())
}

#[tokio::test]
async fn work_gate_auth_off_succeeds_with_operator_unverified_attribution() -> Result<(), Box<dyn std::error::Error>> {
    for approve in [true, false] {
        let (state, work_id, action_id) = gate_test_state(AuthMode::Off, Some("tenant-a")).await?;

        let missing_identity = gate_test_resolve(&state, &action_id, HeaderMap::new(), None, approve).await;
        assert_eq!(missing_identity.status(), StatusCode::BAD_REQUEST);
        assert_eq!(gate_test_observation_count(&state)?, 0);

        // The durable actor is tagged, but the four-eyes comparison must use
        // the raw assertion so tagging cannot disguise requester self-review.
        let self_review = gate_test_resolve(&state, &action_id, HeaderMap::new(), Some("requester-a"), approve).await;
        assert_eq!(self_review.status(), StatusCode::FORBIDDEN);
        assert_eq!(gate_test_observation_count(&state)?, 0);

        let response = gate_test_resolve(&state, &action_id, HeaderMap::new(), Some("approver-a"), approve).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = json_body(response).await;
        let Some(receipt_id) = response_body["receipt_id"].as_str() else {
            return Err(std::io::Error::other("auth-off gate response receipt_id missing").into());
        };
        let receipt_id = receipt_id.to_string();
        let expected_actor = format!("{}approver-a", super::work::AUTH_OFF_APPROVER_PREFIX);
        assert_eq!(gate_test_observation_count(&state)?, 1);

        let Some(receipt) = super::receipts::local_approval_receipt(&state, "tenant-a", &receipt_id)? else {
            return Err(std::io::Error::other("auth-off gate receipt missing").into());
        };
        assert_eq!(receipt.reviewer_passport, expected_actor);
        assert_ne!(receipt.reviewer_passport, "approver-a");
        assert_eq!(receipt.decision, if approve { "approve" } else { "reject" });

        let store = state.fact_store.read().await;
        let entity = format!("{}::{action_id}", crate::work::WORK_GATE_ENTITY_PREFIX);
        let Some(fact) = gate_test_latest_fact(&store, &entity) else {
            return Err(std::io::Error::other("resolved auth-off gate fact missing").into());
        };
        assert_eq!(fact.actor.as_deref(), Some(expected_actor.as_str()));
        assert_ne!(fact.actor.as_deref(), Some("approver-a"));
        assert_eq!(fact.source_receipt.as_deref(), Some(receipt_id.as_str()));
        let gate: crate::work::PendingGateAction = serde_json::from_str(&fact.value)?;
        assert_eq!(gate.status, if approve { "approved" } else { "rejected" });
        assert_eq!(gate.resolved_by_passport.as_deref(), Some(expected_actor.as_str()));
        assert_ne!(gate.resolved_by_passport.as_deref(), Some("approver-a"));
        assert_eq!(gate.receipt_id.as_deref(), Some(receipt_id.as_str()));

        let expected_gate_status = if approve { "approved" } else { "rejected" };
        let transition_fact = store.all_facts().find(|fact| {
            fact.entity
                .starts_with(&format!("{}::{work_id}::", crate::work::WORK_TRANSITION_ENTITY_PREFIX))
                && serde_json::from_str::<crate::work::WorkTransition>(&fact.value)
                    .is_ok_and(|transition| transition.gate_status == expected_gate_status)
        });
        let Some(transition_fact) = transition_fact else {
            return Err(std::io::Error::other("auth-off gate resolution transition missing").into());
        };
        assert_eq!(transition_fact.actor.as_deref(), Some(expected_actor.as_str()));
        assert_ne!(transition_fact.actor.as_deref(), Some("approver-a"));
        assert_eq!(transition_fact.source_receipt.as_deref(), Some(receipt_id.as_str()));
        let transition: crate::work::WorkTransition = serde_json::from_str(&transition_fact.value)?;
        assert_eq!(transition.by_passport, expected_actor);
        assert_ne!(transition.by_passport, "approver-a");
        assert_eq!(transition.receipt_id.as_deref(), Some(receipt_id.as_str()));

        if approve {
            let work_entity = format!("{}::default::{work_id}", crate::work::WORK_ENTITY_PREFIX);
            let Some(work_fact) = gate_test_latest_fact(&store, &work_entity) else {
                return Err(std::io::Error::other("auth-off approved work fact missing").into());
            };
            assert_eq!(work_fact.actor.as_deref(), Some(expected_actor.as_str()));
            assert_ne!(work_fact.actor.as_deref(), Some("approver-a"));
            assert_eq!(work_fact.source_receipt.as_deref(), Some(receipt_id.as_str()));
        }
    }
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn work_gate_jwt_binding_and_cross_tenant_enforcement() -> Result<(), Box<dyn std::error::Error>> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    let _secret = EnvVarGuard::set("CORECRUXD_JWT_HS256_SECRET", SECRET);
    let _issuer = EnvVarGuard::set("CORECRUXD_JWT_ISS", "corecrux-test");
    let _audience = EnvVarGuard::set("CORECRUXD_JWT_AUD", "corecrux");

    #[derive(serde::Serialize)]
    struct Claims<'a> {
        exp: usize,
        iss: &'a str,
        aud: &'a str,
        scope: &'a str,
        tenant_id: &'a str,
        passport_id: &'a str,
    }

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let claims = Claims {
        exp: now.as_secs().saturating_add(3_600) as usize,
        iss: "corecrux-test",
        aud: "corecrux",
        scope: "facts:write",
        tenant_id: "tenant-x",
        passport_id: "approver-a",
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );

    let wrong_tenant_claims = Claims {
        exp: now.as_secs().saturating_add(3_600) as usize,
        iss: "corecrux-test",
        aud: "corecrux",
        scope: "facts:write",
        tenant_id: "tenant-y",
        passport_id: "approver-a",
    };
    let wrong_tenant_token = encode(
        &Header::new(Algorithm::HS256),
        &wrong_tenant_claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )?;
    let mut wrong_tenant_headers = HeaderMap::new();
    wrong_tenant_headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {wrong_tenant_token}"))?,
    );

    let override_claims = Claims {
        exp: now.as_secs().saturating_add(3_600) as usize,
        iss: "corecrux-test",
        aud: "corecrux",
        scope: "facts:write admin:write",
        tenant_id: "tenant-x",
        passport_id: "approver-a",
    };
    let override_token = encode(
        &Header::new(Algorithm::HS256),
        &override_claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )?;
    let mut override_headers = HeaderMap::new();
    override_headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {override_token}"))?,
    );
    override_headers.insert("x-corecrux-passport-id", HeaderValue::from_static("approver-b"));

    for approve in [true, false] {
        let (bound_state, _work_id, bound_action_id) = gate_test_state(AuthMode::JwtHs256, Some("tenant-x")).await?;
        let spoofed = gate_test_resolve(
            &bound_state,
            &bound_action_id,
            headers.clone(),
            Some("approver-b"),
            approve,
        )
        .await;
        assert_eq!(spoofed.status(), StatusCode::FORBIDDEN);
        let impersonated = gate_test_resolve(
            &bound_state,
            &bound_action_id,
            override_headers.clone(),
            Some("approver-b"),
            approve,
        )
        .await;
        assert_eq!(impersonated.status(), StatusCode::FORBIDDEN);
        let accepted = gate_test_resolve(
            &bound_state,
            &bound_action_id,
            headers.clone(),
            Some("approver-a"),
            approve,
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::OK);
        {
            let store = bound_state.fact_store.read().await;
            let entity = format!("{}::{bound_action_id}", crate::work::WORK_GATE_ENTITY_PREFIX);
            let Some(fact) = gate_test_latest_fact(&store, &entity) else {
                return Err(std::io::Error::other("JWT-bound resolved gate fact missing").into());
            };
            let gate: crate::work::PendingGateAction = serde_json::from_str(&fact.value)?;
            assert_eq!(gate.resolved_by_passport.as_deref(), Some("approver-a"));
            assert_ne!(gate.resolved_by_passport.as_deref(), Some("approver-b"));
        }
        let resolved_cross_tenant = gate_test_resolve(
            &bound_state,
            &bound_action_id,
            wrong_tenant_headers.clone(),
            Some("approver-a"),
            !approve,
        )
        .await;
        assert_eq!(resolved_cross_tenant.status(), StatusCode::FORBIDDEN);

        let (state, _work_id, action_id) = gate_test_state(AuthMode::JwtHs256, Some("tenant-y")).await?;
        let response = gate_test_resolve(&state, &action_id, headers.clone(), Some("approver-a"), approve).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        {
            let store = state.fact_store.read().await;
            let entity = format!("{}::{action_id}", crate::work::WORK_GATE_ENTITY_PREFIX);
            let Some(fact) = gate_test_latest_fact(&store, &entity) else {
                return Err(std::io::Error::other("pending cross-tenant gate fact missing").into());
            };
            let gate: crate::work::PendingGateAction = serde_json::from_str(&fact.value)?;
            assert_eq!(gate.status, "pending");
        }

        let (drift_state, drift_work_id, drift_action_id) =
            gate_test_state(AuthMode::JwtHs256, Some("tenant-y")).await?;
        {
            let mut store = drift_state.fact_store.write().await;
            let _ = crate::work::update_work(
                &mut store,
                &drift_work_id,
                crate::work::UpdateWorkInput {
                    title: None,
                    body: None,
                    state: None,
                    assignee_passport: None,
                    tenant_id: Some(Some("tenant-x".to_string())),
                    linked_pr: None,
                    linked_issue: None,
                    blocker_reason: None,
                    blocker_kind: None,
                },
                crate::work::UpdateWorkContext {
                    by_passport: "requester-a".to_string(),
                    passport_gated: false,
                    now_unix_ms: 2_500,
                },
            )?;
        }
        let current_tenant_attempt = gate_test_resolve(
            &drift_state,
            &drift_action_id,
            headers.clone(),
            Some("approver-a"),
            approve,
        )
        .await;
        assert_eq!(current_tenant_attempt.status(), StatusCode::FORBIDDEN);
        let original_tenant_attempt = gate_test_resolve(
            &drift_state,
            &drift_action_id,
            wrong_tenant_headers.clone(),
            Some("approver-a"),
            approve,
        )
        .await;
        assert_eq!(original_tenant_attempt.status(), StatusCode::CONFLICT);
        assert_eq!(gate_test_observation_count(&drift_state)?, 0);
    }
    Ok(())
}

#[tokio::test]
async fn work_gate_receipt_resolves_and_resolution_facts_are_attributed() -> Result<(), Box<dyn std::error::Error>> {
    for approve in [true, false] {
        let (mut state, work_id, action_id) = gate_test_state(AuthMode::DevScopes, Some("tenant-a")).await?;
        let response = gate_test_resolve(
            &state,
            &action_id,
            dev_scope_passport_headers("facts:write", "approver-a"),
            Some("approver-a"),
            approve,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = json_body(response).await;
        let Some(receipt_id) = response_body["receipt_id"].as_str() else {
            return Err(std::io::Error::other("gate response receipt_id missing").into());
        };
        assert!(receipt_id.starts_with("ad_ga_"));

        // A pre-seeded dataplane stream must not shadow the authoritative
        // local gate receipt namespace.
        state.http_dataplane = enabled_dataplane(
            vec![
                receipt_stored_event(EVT_RECEIPT_BODY_V1, 99, b"shadow body"),
                receipt_stored_event(EVT_RECEIPT_SIG_V1, 100, b"shadow signature"),
            ],
            Some(sample_verification_report("shadow-receipt", "tenant-a")),
        );

        let receipt_headers = dev_scope_headers("receipts:read");
        let body_response = super::receipts::get_receipt_body_v1(
            State(state.clone()),
            Path(receipt_id.to_string()),
            Query(TenantQuery {
                tenant_id: "tenant-a".to_string(),
            }),
            receipt_headers.clone(),
        )
        .await
        .into_response();
        assert_eq!(body_response.status(), StatusCode::OK);
        let body_envelope = json_body(body_response).await;
        assert_eq!(body_envelope["receipt_id"], receipt_id);
        assert_eq!(body_envelope["seq"], 0);
        assert_eq!(
            body_envelope["contentType"],
            corecrux_receipts::CONTENT_TYPE_RECEIPT_BODY_V1
        );
        let Some(payload_base64) = body_envelope["payloadBase64"].as_str() else {
            return Err(std::io::Error::other("receipt body payload missing").into());
        };
        let receipt_body = base64::engine::general_purpose::STANDARD.decode(payload_base64)?;
        let Some(receipt_fields) = super::receipts::approval_receipt_text_fields(&receipt_body) else {
            return Err(std::io::Error::other("receipt body is not text-keyed CBOR").into());
        };
        assert_eq!(
            receipt_fields.get("reviewer_passport").map(String::as_str),
            Some("approver-a")
        );
        assert_eq!(
            receipt_fields.get("decision").map(String::as_str),
            Some(if approve { "approve" } else { "reject" })
        );

        let signature_response = super::receipts::get_receipt_signature_v1(
            State(state.clone()),
            Path(receipt_id.to_string()),
            Query(TenantQuery {
                tenant_id: "tenant-a".to_string(),
            }),
            receipt_headers.clone(),
        )
        .await
        .into_response();
        assert_eq!(signature_response.status(), StatusCode::OK);

        let verification_response = super::receipts::get_receipt_verification_v1(
            State(state.clone()),
            Path(receipt_id.to_string()),
            Query(TenantQuery {
                tenant_id: "tenant-a".to_string(),
            }),
            receipt_headers,
        )
        .await
        .into_response();
        assert_eq!(verification_response.status(), StatusCode::OK);
        let verification = json_body(verification_response).await;
        assert_eq!(verification["receipt_id"], receipt_id);
        assert_eq!(verification["signature_valid"], true);
        assert_eq!(verification["error_code"], "OK");

        let wrong_tenant_receipt = super::receipts::get_receipt_body_v1(
            State(state.clone()),
            Path(receipt_id.to_string()),
            Query(TenantQuery {
                tenant_id: "tenant-b".to_string(),
            }),
            dev_scope_headers("receipts:read"),
        )
        .await
        .into_response();
        assert_eq!(wrong_tenant_receipt.status(), StatusCode::NOT_FOUND);

        let colliding_bundle_export = super::receipts::get_receipt_export_v1(
            State(state.clone()),
            Path(receipt_id.to_string()),
            Query(super::receipts::ExportQueryV1 {
                tenant_id: "tenant-a".to_string(),
                include: None,
                redaction: None,
                format: None,
            }),
            dev_scope_headers("exports:read receipts:read"),
        )
        .await
        .into_response();
        assert_eq!(colliding_bundle_export.status(), StatusCode::NOT_IMPLEMENTED);

        let store = state.fact_store.read().await;
        let gate_entity = format!("{}::{action_id}", crate::work::WORK_GATE_ENTITY_PREFIX);
        let Some(gate_fact) = gate_test_latest_fact(&store, &gate_entity) else {
            return Err(std::io::Error::other("resolved gate fact missing").into());
        };
        assert_eq!(gate_fact.actor.as_deref(), Some("approver-a"));
        assert_eq!(gate_fact.source_receipt.as_deref(), Some(receipt_id));
        let gate: crate::work::PendingGateAction = serde_json::from_str(&gate_fact.value)?;
        assert_eq!(gate.resolved_by_passport.as_deref(), Some("approver-a"));
        assert_eq!(gate.receipt_id.as_deref(), Some(receipt_id));

        let expected_gate_status = if approve { "approved" } else { "rejected" };
        let transition = store.all_facts().find(|fact| {
            if !fact
                .entity
                .starts_with(&format!("{}::{work_id}::", crate::work::WORK_TRANSITION_ENTITY_PREFIX))
            {
                return false;
            }
            serde_json::from_str::<crate::work::WorkTransition>(&fact.value)
                .is_ok_and(|transition| transition.gate_status == expected_gate_status)
        });
        let Some(transition_fact) = transition else {
            return Err(std::io::Error::other("gate resolution transition fact missing").into());
        };
        assert_eq!(transition_fact.actor.as_deref(), Some("approver-a"));
        assert_eq!(transition_fact.source_receipt.as_deref(), Some(receipt_id));
        let transition: crate::work::WorkTransition = serde_json::from_str(&transition_fact.value)?;
        assert_eq!(transition.by_passport, "approver-a");
        assert_eq!(transition.receipt_id.as_deref(), Some(receipt_id));

        if approve {
            let work_entity = format!("{}::default::{work_id}", crate::work::WORK_ENTITY_PREFIX);
            let Some(work_fact) = gate_test_latest_fact(&store, &work_entity) else {
                return Err(std::io::Error::other("approved work fact missing").into());
            };
            assert_eq!(work_fact.actor.as_deref(), Some("approver-a"));
            assert_eq!(work_fact.source_receipt.as_deref(), Some(receipt_id));
        }
    }
    Ok(())
}

#[tokio::test]
async fn work_gate_replay_conflicts_without_duplicate_facts_or_receipts() -> Result<(), Box<dyn std::error::Error>> {
    for approve in [true, false] {
        let (state, _work_id, action_id) = gate_test_state(AuthMode::DevScopes, Some("tenant-a")).await?;
        let headers = dev_scope_passport_headers("facts:write", "approver-a");
        let first = gate_test_resolve(&state, &action_id, headers.clone(), Some("approver-a"), approve).await;
        assert_eq!(first.status(), StatusCode::OK);
        let facts_after_first = {
            let store = state.fact_store.read().await;
            gate_test_fact_count(&store)
        };
        let receipts_after_first = gate_test_observation_count(&state)?;

        let replay = gate_test_resolve(&state, &action_id, headers, Some("approver-a"), !approve).await;
        assert_eq!(replay.status(), StatusCode::CONFLICT);
        let facts_after_replay = {
            let store = state.fact_store.read().await;
            gate_test_fact_count(&store)
        };
        assert_eq!(facts_after_replay, facts_after_first);
        assert_eq!(gate_test_observation_count(&state)?, receipts_after_first);
    }
    Ok(())
}

#[tokio::test]
async fn work_gate_receipt_is_reused_after_fact_journal_failure() -> Result<(), Box<dyn std::error::Error>> {
    for approve in [true, false] {
        let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
        bind_test_state_to_root_passport_key(&mut state);
        let fact_dir = state.data_dir.join("gate-fact-journal");
        let mut persistent_store = corecrux_memory::FactStore::with_persistence(&fact_dir)?;
        let (_work_id, action_id) = seed_gate_test_store(&state.data_dir, &mut persistent_store, Some("tenant-a"))?;
        state.fact_store = Arc::new(RwLock::new(persistent_store));

        let journal_path = fact_dir.join("facts.jsonl");
        let journal_backup = fact_dir.join("facts.before-failure.jsonl");
        std::fs::rename(&journal_path, &journal_backup)?;
        std::fs::create_dir(&journal_path)?;

        let headers = dev_scope_passport_headers("facts:write", "approver-a");
        let facts_before = {
            let store = state.fact_store.read().await;
            gate_test_fact_count(&store)
        };
        let failed = gate_test_resolve(&state, &action_id, headers.clone(), Some("approver-a"), approve).await;
        assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(gate_test_observation_count(&state)?, 1);
        {
            let store = state.fact_store.read().await;
            assert_eq!(gate_test_fact_count(&store), facts_before);
            let entity = format!("{}::{action_id}", crate::work::WORK_GATE_ENTITY_PREFIX);
            let Some(fact) = gate_test_latest_fact(&store, &entity) else {
                return Err(std::io::Error::other("pending gate missing after journal failure").into());
            };
            let gate: crate::work::PendingGateAction = serde_json::from_str(&fact.value)?;
            assert_eq!(gate.status, "pending");
        }

        let receipt_path =
            super::observations::observation_file_path(&state.data_dir, super::work::WORK_GATE_RECEIPT_SESSION);
        let receipt_records = super::observations::read_observations_strict(&receipt_path)?;
        let Some(orphan_record) = receipt_records.first() else {
            return Err(std::io::Error::other("orphan receipt record missing").into());
        };
        let orphan_observation_id = orphan_record.observation_id.clone();

        std::fs::remove_dir(&journal_path)?;
        std::fs::rename(&journal_backup, &journal_path)?;
        let conflicting_retry =
            gate_test_resolve(&state, &action_id, headers.clone(), Some("approver-a"), !approve).await;
        assert_eq!(conflicting_retry.status(), StatusCode::CONFLICT);
        assert_eq!(gate_test_observation_count(&state)?, 1);
        {
            let store = state.fact_store.read().await;
            assert_eq!(gate_test_fact_count(&store), facts_before);
        }

        let retried = gate_test_resolve(&state, &action_id, headers, Some("approver-a"), approve).await;
        assert_eq!(retried.status(), StatusCode::OK);
        let retried_body = json_body(retried).await;
        assert_eq!(retried_body["receipt_record_id"], orphan_observation_id);
        assert_eq!(gate_test_observation_count(&state)?, 1);
        let Some(retried_receipt_id) = retried_body["receipt_id"].as_str() else {
            return Err(std::io::Error::other("retried receipt id missing").into());
        };

        let verification = super::receipts::get_receipt_verification_v1(
            State(state),
            Path(retried_receipt_id.to_string()),
            Query(TenantQuery {
                tenant_id: "tenant-a".to_string(),
            }),
            dev_scope_headers("receipts:read"),
        )
        .await
        .into_response();
        assert_eq!(verification.status(), StatusCode::OK);
    }
    Ok(())
}

#[tokio::test]
async fn work_gate_concurrent_resolution_has_one_winner() -> Result<(), Box<dyn std::error::Error>> {
    for approve in [true, false] {
        let (state, _work_id, action_id) = gate_test_state(AuthMode::DevScopes, Some("tenant-a")).await?;
        let headers = dev_scope_passport_headers("facts:write", "approver-a");
        let first = gate_test_resolve(&state, &action_id, headers.clone(), Some("approver-a"), approve);
        let second = gate_test_resolve(&state, &action_id, headers, Some("approver-a"), !approve);
        let (first, second) = tokio::join!(first, second);
        let mut statuses = [first.status(), second.status()];
        statuses.sort();
        assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]);
        assert_eq!(gate_test_observation_count(&state)?, 1);
    }
    Ok(())
}

#[tokio::test]
async fn work_gate_requester_cannot_self_approve_or_self_reject() -> Result<(), Box<dyn std::error::Error>> {
    for approve in [true, false] {
        let (state, _work_id, action_id) = gate_test_state(AuthMode::DevScopes, Some("tenant-a")).await?;
        let response = gate_test_resolve(
            &state,
            &action_id,
            dev_scope_passport_headers("facts:write", "requester-a"),
            Some("requester-a"),
            approve,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(gate_test_observation_count(&state)?, 0);

        let store = state.fact_store.read().await;
        let entity = format!("{}::{action_id}", crate::work::WORK_GATE_ENTITY_PREFIX);
        let Some(fact) = gate_test_latest_fact(&store, &entity) else {
            return Err(std::io::Error::other("pending self-approval gate fact missing").into());
        };
        let gate: crate::work::PendingGateAction = serde_json::from_str(&fact.value)?;
        assert_eq!(gate.status, "pending");
    }
    Ok(())
}

#[tokio::test]
async fn work_gate_receipt_session_is_not_generic_observation_surface() -> Result<(), Box<dyn std::error::Error>> {
    let (state, _work_id, action_id) = gate_test_state(AuthMode::DevScopes, Some("tenant-a")).await?;
    let resolved = gate_test_resolve(
        &state,
        &action_id,
        dev_scope_passport_headers("facts:write", "approver-a"),
        Some("approver-a"),
        true,
    )
    .await;
    assert_eq!(resolved.status(), StatusCode::OK);
    let resolved_body = json_body(resolved).await;
    let Some(receipt_id) = resolved_body["receipt_id"].as_str() else {
        return Err(std::io::Error::other("gate response receipt_id missing").into());
    };

    let generic_body = super::observations::PostObservationBody {
        kind: "approval_decision".to_string(),
        provider: "attacker".to_string(),
        client_ts: None,
        payload: serde_json::json!({"receipt_id": receipt_id}),
    };
    let singleton = super::observations::post_observation(
        State(state.clone()),
        dev_scope_headers("sessions:write"),
        Path(super::work::WORK_GATE_RECEIPT_SESSION.to_string()),
        Json(generic_body.clone()),
    )
    .await;
    assert_eq!(singleton.status(), StatusCode::FORBIDDEN);
    let bound_singleton = super::observations::post_observation(
        State(state.clone()),
        dev_scope_passport_headers("sessions:write", "approver-a"),
        Path(super::work::WORK_GATE_RECEIPT_SESSION.to_string()),
        Json(generic_body.clone()),
    )
    .await;
    assert_eq!(bound_singleton.status(), StatusCode::FORBIDDEN);
    let batch = super::observations::post_observations_batch(
        State(state.clone()),
        dev_scope_headers("sessions:write"),
        Path(super::work::WORK_GATE_RECEIPT_SESSION.to_ascii_uppercase()),
        Json(super::observations::PostObservationsBatchBody {
            items: vec![generic_body],
        }),
    )
    .await;
    assert_eq!(batch.status(), StatusCode::FORBIDDEN);

    let direct_read = super::observations::get_observations(
        State(state.clone()),
        dev_scope_headers("query:read"),
        Path(super::work::WORK_GATE_RECEIPT_SESSION.to_string()),
        Query(super::observations::ListObservationsQuery {
            since: None,
            limit: None,
            provider: None,
        }),
    )
    .await;
    assert_eq!(direct_read.status(), StatusCode::FORBIDDEN);
    let bound_direct_read = super::observations::get_observations(
        State(state.clone()),
        dev_scope_passport_headers("query:read", "approver-a"),
        Path(super::work::WORK_GATE_RECEIPT_SESSION.to_string()),
        Query(super::observations::ListObservationsQuery {
            since: None,
            limit: None,
            provider: None,
        }),
    )
    .await;
    assert_eq!(bound_direct_read.status(), StatusCode::FORBIDDEN);
    let aggregate = super::observations::get_observations_aggregate(
        State(state.clone()),
        dev_scope_headers("query:read"),
        Query(super::observations::AggregateObservationsQuery {
            since: None,
            provider: None,
            kind: None,
            session_id: None,
            limit: None,
        }),
    )
    .await;
    assert_eq!(aggregate.status(), StatusCode::OK);
    let aggregate_body = json_body(aggregate).await;
    assert_eq!(aggregate_body["matched"], 0);

    let receipt_path =
        super::observations::observation_file_path(&state.data_dir, super::work::WORK_GATE_RECEIPT_SESSION);
    let (_archived, scanned) = super::observations::run_retention_pass(&state.data_dir, chrono::Duration::seconds(-1))?;
    assert_eq!(scanned, 0);
    assert!(receipt_path.exists());
    assert_eq!(gate_test_observation_count(&state)?, 1);

    let still_resolvable = super::receipts::get_receipt_verification_v1(
        State(state),
        Path(receipt_id.to_string()),
        Query(TenantQuery {
            tenant_id: "tenant-a".to_string(),
        }),
        dev_scope_headers("receipts:read"),
    )
    .await
    .into_response();
    assert_eq!(still_resolvable.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn work_gate_tampered_receipt_chain_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (state, _work_id, action_id) = gate_test_state(AuthMode::DevScopes, Some("tenant-a")).await?;
    let resolved = gate_test_resolve(
        &state,
        &action_id,
        dev_scope_passport_headers("facts:write", "approver-a"),
        Some("approver-a"),
        false,
    )
    .await;
    assert_eq!(resolved.status(), StatusCode::OK);
    let resolved_body = json_body(resolved).await;
    let Some(receipt_id) = resolved_body["receipt_id"].as_str() else {
        return Err(std::io::Error::other("gate response receipt_id missing").into());
    };
    let receipt_path =
        super::observations::observation_file_path(&state.data_dir, super::work::WORK_GATE_RECEIPT_SESSION);
    let original = std::fs::read_to_string(&receipt_path)?;
    let tampered = original.replacen("\"tenant_id\":\"tenant-a\"", "\"tenant_id\":\"tenant-b\"", 1);
    if tampered == original {
        return Err(std::io::Error::other("receipt tamper fixture did not find tenant field").into());
    }
    std::fs::write(&receipt_path, tampered)?;

    let response = super::receipts::get_receipt_body_v1(
        State(state),
        Path(receipt_id.to_string()),
        Query(TenantQuery {
            tenant_id: "tenant-a".to_string(),
        }),
        dev_scope_headers("receipts:read"),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}

#[tokio::test]
async fn work_patch_with_gated_passport_returns_202_queued() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let work_id = {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
        crate::projects::seed_default_if_missing(&mut store, 1).expect("project seed");
        // Flip the personal-default passport's gate ON.
        crate::passports::update_passport(
            &mut store,
            "personal-default",
            crate::passports::UpdatePassportInput {
                category: None,
                agent_work_gate: Some(true),
                is_default_for_category: None,
                sponsor_id: None,
                reputation_tier: None,
                receipt_count: None,
                name: None,
                owner: None,
                position: None,
                company: None,
                notes: None,
            },
        )
        .expect("flip gate");
        let item = crate::work::create_work(
            &mut store,
            crate::work::CreateWorkInput {
                project_id: "default".to_string(),
                title: "x".to_string(),
                body: None,
                state: None,
                assignee_passport: None,
                tenant_id: None,
                linked_pr: None,
                linked_issue: None,
                created_by_passport: "personal-default".to_string(),
            },
            1_000,
        )
        .expect("create");
        item.id
    };

    let patch_resp = super::work::patch_work(
        State(state.clone()),
        Path(work_id),
        dev_scope_headers("facts:write"),
        Json(super::work::UpdateWorkBody {
            title: None,
            body: None,
            state: Some("in_progress".to_string()),
            assignee_passport: None,
            tenant_id: None,
            linked_pr: None,
            linked_issue: None,
            blocker_reason: None,
            blocker_kind: None,
            by_passport: "personal-default".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(patch_resp.status(), StatusCode::ACCEPTED);
    let body = json_body(patch_resp).await;
    assert_eq!(body["applied"], false);
    assert!(body["queued"]["action_id"].is_string());

    let pending_resp = super::work::get_pending_gates(
        State(state),
        Query(super::work::GateListQuery { by_passport: None }),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    let pending_body = json_body(pending_resp).await;
    assert_eq!(pending_body["count"], 1);
}

#[tokio::test]
async fn work_comments_get_item_and_gate_resolution_paths() {
    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    bind_test_state_to_root_passport_key(&mut state);
    let work_id = {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
        crate::projects::seed_default_if_missing(&mut store, 1).expect("project seed");
        crate::work::create_work(
            &mut store,
            crate::work::CreateWorkInput {
                project_id: "default".to_string(),
                title: "gate me".to_string(),
                body: None,
                state: None,
                assignee_passport: None,
                tenant_id: None,
                linked_pr: None,
                linked_issue: None,
                created_by_passport: "personal-default".to_string(),
            },
            1_000,
        )
        .expect("create")
        .id
    };

    let item_resp = super::work::get_work_item(
        State(state.clone()),
        Path(work_id.clone()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(json_body(item_resp).await["id"], work_id);

    let comment_resp = super::work::post_comment(
        State(state.clone()),
        Path(work_id.clone()),
        dev_scope_headers("facts:write"),
        Json(super::work::CommentBody {
            author_passport: "personal-default".to_string(),
            body: "ready for review".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(comment_resp.status(), StatusCode::CREATED);

    let comments_resp = super::work::get_comments(
        State(state.clone()),
        Path(work_id.clone()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(json_body(comments_resp).await["comments"].as_array().unwrap().len(), 1);

    {
        let mut store = state.fact_store.write().await;
        crate::passports::update_passport(
            &mut store,
            "personal-default",
            crate::passports::UpdatePassportInput {
                category: None,
                agent_work_gate: Some(true),
                is_default_for_category: None,
                sponsor_id: None,
                reputation_tier: None,
                receipt_count: None,
                name: None,
                owner: None,
                position: None,
                company: None,
                notes: None,
            },
        )
        .expect("flip gate");
    }

    let queue_for_reject = super::work::patch_work(
        State(state.clone()),
        Path(work_id.clone()),
        dev_scope_headers("facts:write"),
        Json(super::work::UpdateWorkBody {
            title: Some("queued reject".to_string()),
            body: None,
            state: Some("blocked".to_string()),
            assignee_passport: None,
            tenant_id: None,
            linked_pr: None,
            linked_issue: None,
            blocker_reason: Some(Some("needs approval".to_string())),
            blocker_kind: Some(crate::work::BlockerKind::NeedsApproval),
            by_passport: "personal-default".to_string(),
        }),
    )
    .await
    .into_response();
    let reject_body = json_body(queue_for_reject).await;
    let reject_action = reject_body["queued"]["action_id"].as_str().unwrap().to_string();

    let rejected = super::work::post_gate_reject(
        State(state.clone()),
        Path(reject_action),
        dev_scope_passport_headers("facts:write", "work-default"),
        Json(super::work::GateResolutionBody {
            approver_passport: Some("work-default".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(rejected.status(), StatusCode::OK);

    let queue_for_approve = super::work::patch_work(
        State(state.clone()),
        Path(work_id),
        dev_scope_headers("facts:write"),
        Json(super::work::UpdateWorkBody {
            title: None,
            body: None,
            state: Some("complete".to_string()),
            assignee_passport: None,
            tenant_id: None,
            linked_pr: None,
            linked_issue: None,
            blocker_reason: None,
            blocker_kind: None,
            by_passport: "personal-default".to_string(),
        }),
    )
    .await
    .into_response();
    let approve_body = json_body(queue_for_approve).await;
    let approve_action = approve_body["queued"]["action_id"].as_str().unwrap().to_string();

    let approved = super::work::post_gate_approve(
        State(state),
        Path(approve_action),
        dev_scope_passport_headers("facts:write", "work-default"),
        Json(super::work::GateResolutionBody {
            approver_passport: Some("work-default".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(json_body(approved).await["state"], "complete");
}

#[tokio::test]
async fn github_status_reports_disconnected_by_default() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::integrations_github::get_status(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["connected"], false);
    assert!(body["username"].is_null());
}

#[tokio::test]
async fn github_connect_with_skip_verify_persists_then_status_reports_connected() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    let connect_resp = super::integrations_github::post_connect(
        State(state.clone()),
        dev_scope_headers("integrations:install"),
        Json(super::integrations_github::ConnectGithubBody {
            pat: "github_pat_test_value_xyz".to_string(),
            skip_verify: true,
            username_override: Some("smoke-test-user".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(connect_resp.status(), StatusCode::OK);

    let status_resp = super::integrations_github::get_status(State(state.clone()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let body = json_body(status_resp).await;
    assert_eq!(body["connected"], true);
    assert_eq!(body["username"], "smoke-test-user");

    let creds = crate::integrations_github::read_credentials(&state.data_dir).expect("read creds");
    let pat =
        crate::integrations_github::decrypt_pat(&creds, state.integration_encryption_key.as_ref()).expect("decrypt");
    assert_eq!(pat, "github_pat_test_value_xyz");
}

#[tokio::test]
async fn github_connect_rejects_empty_pat() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::integrations_github::post_connect(
        State(state),
        dev_scope_headers("integrations:install"),
        Json(super::integrations_github::ConnectGithubBody {
            pat: "   ".to_string(),
            skip_verify: true,
            username_override: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn github_connect_requires_install_scope() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::integrations_github::post_connect(
        State(state),
        dev_scope_headers("admin:read"),
        Json(super::integrations_github::ConnectGithubBody {
            pat: "x".to_string(),
            skip_verify: true,
            username_override: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn github_disconnect_clears_credentials() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    let _ = super::integrations_github::post_connect(
        State(state.clone()),
        dev_scope_headers("integrations:install"),
        Json(super::integrations_github::ConnectGithubBody {
            pat: "x".to_string(),
            skip_verify: true,
            username_override: Some("u".to_string()),
        }),
    )
    .await
    .into_response();

    let resp =
        super::integrations_github::post_disconnect(State(state.clone()), dev_scope_headers("integrations:disable"))
            .await
            .into_response();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let status_resp = super::integrations_github::get_status(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let body = json_body(status_resp).await;
    assert_eq!(body["connected"], false);
}

#[tokio::test]
async fn github_repo_selection_requires_connection() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    // Not connected — accessible should fail with 412.
    let resp = super::integrations_github::get_accessible_repos(State(state.clone()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);

    // Same for select.
    let sel = super::integrations_github::post_select_repo(
        State(state),
        Path(("cuecrux".to_string(), "Crux".to_string())),
        dev_scope_headers("integrations:install"),
    )
    .await
    .into_response();
    assert_eq!(sel.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn github_repo_select_then_list_then_delete_round_trip() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    // Connect first (skip_verify so no network).
    let _ = super::integrations_github::post_connect(
        State(state.clone()),
        dev_scope_headers("integrations:install"),
        Json(super::integrations_github::ConnectGithubBody {
            pat: "fake-pat".to_string(),
            skip_verify: true,
            username_override: Some("u".to_string()),
        }),
    )
    .await
    .into_response();

    // Select a repo.
    let sel = super::integrations_github::post_select_repo(
        State(state.clone()),
        Path(("cuecrux".to_string(), "Crux".to_string())),
        dev_scope_headers("integrations:install"),
    )
    .await
    .into_response();
    assert_eq!(sel.status(), StatusCode::CREATED);

    // List.
    let list = super::integrations_github::get_selected_repos(State(state.clone()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let body = json_body(list).await;
    assert_eq!(body["count"], 1);
    assert_eq!(body["repos"][0]["owner"], "cuecrux");
    assert_eq!(body["repos"][0]["repo"], "Crux");

    // Delete.
    let del = super::integrations_github::delete_selected_repo(
        State(state.clone()),
        Path(("cuecrux".to_string(), "Crux".to_string())),
        dev_scope_headers("integrations:disable"),
    )
    .await
    .into_response();
    assert_eq!(del.status(), StatusCode::NO_CONTENT);

    let after = super::integrations_github::get_selected_repos(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let after_body = json_body(after).await;
    assert_eq!(after_body["count"], 0);
}

#[tokio::test]
async fn github_disconnect_clears_selected_repos_too() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let _ = super::integrations_github::post_connect(
        State(state.clone()),
        dev_scope_headers("integrations:install"),
        Json(super::integrations_github::ConnectGithubBody {
            pat: "x".to_string(),
            skip_verify: true,
            username_override: Some("u".to_string()),
        }),
    )
    .await
    .into_response();
    let _ = super::integrations_github::post_select_repo(
        State(state.clone()),
        Path(("a".to_string(), "b".to_string())),
        dev_scope_headers("integrations:install"),
    )
    .await
    .into_response();

    let _ =
        super::integrations_github::post_disconnect(State(state.clone()), dev_scope_headers("integrations:disable"))
            .await
            .into_response();

    let list = super::integrations_github::get_selected_repos(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let body = json_body(list).await;
    assert_eq!(body["count"], 0);
}

#[tokio::test]
async fn github_sync_returns_412_when_not_connected() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::integrations_github::post_sync(State(state), dev_scope_headers("integrations:install"))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn openai_connect_settings_chat_precondition_and_disconnect() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    let status = super::integrations_openai::get_status(State(state.clone()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(json_body(status).await["connected"], false);

    let chat_precondition = super::integrations_openai::post_chat(
        State(state.clone()),
        dev_scope_headers("integrations:install"),
        Json(super::integrations_openai::ChatBody {
            messages: serde_json::json!([]),
            model: None,
            max_tokens: None,
            temperature: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(chat_precondition.status(), StatusCode::PRECONDITION_FAILED);

    let bad_connect = super::integrations_openai::post_connect(
        State(state.clone()),
        dev_scope_headers("integrations:install"),
        Json(super::integrations_openai::ConnectOpenAiBody {
            api_key: " ".to_string(),
            organization_id: None,
            default_model: None,
            skip_verify: true,
        }),
    )
    .await
    .into_response();
    assert_eq!(bad_connect.status(), StatusCode::BAD_REQUEST);

    let forbidden = super::integrations_openai::post_connect(
        State(state.clone()),
        dev_scope_headers("admin:read"),
        Json(super::integrations_openai::ConnectOpenAiBody {
            api_key: "sk-test".to_string(),
            organization_id: None,
            default_model: None,
            skip_verify: true,
        }),
    )
    .await
    .into_response();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let connected = super::integrations_openai::post_connect(
        State(state.clone()),
        dev_scope_headers("integrations:install"),
        Json(super::integrations_openai::ConnectOpenAiBody {
            api_key: "sk-test".to_string(),
            organization_id: Some("org-test".to_string()),
            default_model: Some("gpt-4o-mini".to_string()),
            skip_verify: true,
        }),
    )
    .await
    .into_response();
    let connected_body = json_body(connected).await;
    assert_eq!(connected_body["connected"], true);
    assert_eq!(connected_body["organization_id"], "org-test");

    let settings = super::integrations_openai::patch_settings(
        State(state.clone()),
        dev_scope_headers("integrations:install"),
        Json(super::integrations_openai::UpdateOpenAiBody {
            default_model: Some("gpt-4.1-mini".to_string()),
            organization_id: Some(" ".to_string()),
        }),
    )
    .await
    .into_response();
    let settings_body = json_body(settings).await;
    assert_eq!(settings_body["default_model"], "gpt-4.1-mini");
    assert!(settings_body.get("organization_id").is_none());

    let disconnected =
        super::integrations_openai::post_disconnect(State(state.clone()), dev_scope_headers("integrations:disable"))
            .await
            .into_response();
    assert_eq!(disconnected.status(), StatusCode::NO_CONTENT);

    let status = super::integrations_openai::get_status(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(json_body(status).await["connected"], false);
}

#[tokio::test]
async fn workspace_routes_report_catalog_and_missing_scan_states() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    let tools = super::workspace::get_mcp_tools(State(state.clone()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let tools_body = json_body(tools).await;
    assert!(tools_body["count"].as_u64().unwrap() >= 35);

    let missing_scan = super::workspace::get_scan(State(state.clone()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(missing_scan.status(), StatusCode::NOT_FOUND);

    let missing_storyline = super::workspace::get_storyline(
        State(state.clone()),
        dev_scope_headers("admin:read"),
        Query(super::workspace::StorylineQuery {
            root: None,
            format: Some("json".to_string()),
            include_tests: Some("yes".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(missing_storyline.status(), StatusCode::NOT_FOUND);

    std::env::remove_var("CORECRUXD_WORKSPACE_PATH");
    let unconfigured = super::workspace::post_scan(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(unconfigured.status(), StatusCode::PRECONDITION_FAILED);
}

fn tiny_rust_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).expect("src dir");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"repo-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("manifest");
    std::fs::write(src.join("lib.rs"), "pub struct Used;\npub fn call() -> Used { Used }\n").expect("lib");
    dir
}

async fn repo_scan_job_json(state: AppState, tenant_id: &str, job_id: &str) -> (StatusCode, serde_json::Value) {
    let resp = super::repos::get_repo_scan_job(
        State(state),
        dev_scope_headers("admin:read"),
        Path(job_id.to_string()),
        Query(super::repos::RepoTenantQuery {
            tenant_id: tenant_id.to_string(),
        }),
    )
    .await
    .into_response();
    let status = resp.status();
    let body = json_body(resp).await;
    (status, body)
}

async fn wait_for_repo_scan_job(
    state: AppState,
    tenant_id: &str,
    job_id: &str,
    expected_status: &str,
) -> serde_json::Value {
    for _ in 0..100 {
        let (status, body) = repo_scan_job_json(state.clone(), tenant_id, job_id).await;
        assert_eq!(status, StatusCode::OK);
        if body["status"] == expected_status {
            return body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let (_, body) = repo_scan_job_json(state, tenant_id, job_id).await;
    panic!("repo scan job {job_id} did not reach {expected_status}; last body: {body}");
}

#[tokio::test]
async fn repo_add_local_path_persists_registration_and_scan() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let repo = tiny_rust_repo();
    let root_path = repo.path().to_string_lossy().to_string();

    let resp = super::repos::post_repo(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::repos::CreateRepoBody {
            repo_id: Some("fixture".to_string()),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root_path),
            clone_url: None,
            languages: vec!["rust".to_string()],
            scan_mode: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["repo"]["repo_id"], "fixture");
    assert!(body["repo"]["last_scan_id"].as_str().is_some());

    let store = state.fact_store.read().await;
    let registry_entity = crate::repo_registry::registry_entity("tenant-a", "fixture");
    let scan_entity = crate::repo_registry::scan_entity("tenant-a", "fixture");
    assert!(!store.get_by_entity(&registry_entity).is_empty());
    assert!(!store.get_by_entity(&scan_entity).is_empty());
    let persisted = crate::repo_registry::get_repo(&store, "tenant-a", "fixture").expect("repo persisted");
    assert_eq!(persisted.repo_id, "fixture");
    assert!(persisted.last_scan_id.is_some());
}

#[tokio::test]
async fn repo_add_local_path_async_persists_registration_scan_and_codemap() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let repo = tiny_rust_workspace();
    let root_path = repo.path().to_string_lossy().to_string();

    let resp = super::repos::post_repo(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::repos::CreateRepoBody {
            repo_id: Some("async-fixture".to_string()),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root_path),
            clone_url: None,
            languages: vec!["rust".to_string()],
            scan_mode: Some("async".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = json_body(resp).await;
    let job_id = body["job_id"].as_str().expect("job id").to_string();
    assert_eq!(body["note"], "scan queued");
    assert_eq!(body["repo"]["scan_status"], "pending");
    assert!(body["repo"]["last_scan_id"].is_null());

    let job = wait_for_repo_scan_job(state.clone(), "tenant-a", &job_id, "succeeded").await;
    assert!(job["started_at_unix_ms"].as_u64().is_some());
    assert!(job["finished_at_unix_ms"].as_u64().is_some());

    let scan_id = {
        let store = state.fact_store.read().await;
        let persisted = crate::repo_registry::get_repo(&store, "tenant-a", "async-fixture").expect("repo persisted");
        assert_eq!(persisted.scan_status.as_deref(), Some("done"));
        assert!(persisted.scan_error.is_none());
        persisted.last_scan_id.expect("last scan id")
    };

    let summary = super::repos::get_repo_codemap(
        State(state),
        Path("async-fixture".to_string()),
        dev_scope_headers("admin:read"),
        Query(super::repos::CodemapQuery {
            tenant_id: "tenant-a".to_string(),
            format: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(summary.status(), StatusCode::OK);
    let summary_body = json_body(summary).await;
    assert_eq!(summary_body["scan_id"], scan_id);
    assert!(summary_body["stats"]["symbol_count"].as_u64().unwrap_or(0) >= 1);
}

#[tokio::test]
#[serial_test::serial]
async fn repo_add_local_path_async_failure_keeps_registered_repo() {
    let mut hook = super::repos::RepoScanTestHook::default();
    hook.errors_by_repo.insert(
        "async-fail".to_string(),
        "forced repo scan failure for test".to_string(),
    );
    let _guard = super::repos::RepoScanTestHookGuard::install(hook);
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let repo = tiny_rust_repo();
    let root_path = repo.path().to_string_lossy().to_string();

    let resp = super::repos::post_repo(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::repos::CreateRepoBody {
            repo_id: Some("async-fail".to_string()),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root_path),
            clone_url: None,
            languages: vec!["rust".to_string()],
            scan_mode: Some("async".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = json_body(resp).await;
    let job_id = body["job_id"].as_str().expect("job id").to_string();

    let job = wait_for_repo_scan_job(state.clone(), "tenant-a", &job_id, "failed").await;
    assert_eq!(job["error"], "forced repo scan failure for test");

    let store = state.fact_store.read().await;
    let persisted = crate::repo_registry::get_repo(&store, "tenant-a", "async-fail").expect("repo persisted");
    assert_eq!(persisted.scan_status.as_deref(), Some("failed"));
    assert_eq!(
        persisted.scan_error.as_deref(),
        Some("forced repo scan failure for test")
    );
    assert!(persisted.last_scan_id.is_none());
}

#[tokio::test]
async fn repo_add_local_path_async_backpressure_rejects_when_queue_full() {
    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    state.repo_scan_max_pending = 1;
    let permit = state
        .repo_scan_semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("hold repo scan semaphore");
    let repo_a = tiny_rust_repo();
    let repo_b = tiny_rust_repo();

    let first = super::repos::post_repo(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::repos::CreateRepoBody {
            repo_id: Some("queued-a".to_string()),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(repo_a.path().to_string_lossy().to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            scan_mode: Some("async".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(first.status(), StatusCode::ACCEPTED);

    let second = super::repos::post_repo(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::repos::CreateRepoBody {
            repo_id: Some("queued-b".to_string()),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(repo_b.path().to_string_lossy().to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            scan_mode: Some("async".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);

    {
        let store = state.fact_store.read().await;
        assert!(crate::repo_registry::get_repo(&store, "tenant-a", "queued-a").is_some());
        assert!(crate::repo_registry::get_repo(&store, "tenant-a", "queued-b").is_none());
    }
    drop(permit);
    let first_body = json_body(first).await;
    let job_id = first_body["job_id"].as_str().expect("job id").to_string();
    let _ = wait_for_repo_scan_job(state, "tenant-a", &job_id, "succeeded").await;
}

#[tokio::test]
#[serial_test::serial]
async fn repo_add_local_path_async_jobs_are_serialized() {
    let mut hook = super::repos::RepoScanTestHook::default();
    hook.delay_ms_by_repo.insert("slow-scan".to_string(), 1_000);
    let _guard = super::repos::RepoScanTestHookGuard::install(hook);
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let slow_repo = tiny_rust_repo();
    let fast_repo = tiny_rust_repo();

    let slow = super::repos::post_repo(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::repos::CreateRepoBody {
            repo_id: Some("slow-scan".to_string()),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(slow_repo.path().to_string_lossy().to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            scan_mode: Some("async".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(slow.status(), StatusCode::ACCEPTED);
    let slow_body = json_body(slow).await;
    let slow_job_id = slow_body["job_id"].as_str().expect("slow job id").to_string();
    let _ = wait_for_repo_scan_job(state.clone(), "tenant-a", &slow_job_id, "running").await;

    let fast = super::repos::post_repo(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::repos::CreateRepoBody {
            repo_id: Some("fast-scan".to_string()),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(fast_repo.path().to_string_lossy().to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            scan_mode: Some("async".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(fast.status(), StatusCode::ACCEPTED);
    let fast_body = json_body(fast).await;
    let fast_job_id = fast_body["job_id"].as_str().expect("fast job id").to_string();

    let (_, queued_fast) = repo_scan_job_json(state.clone(), "tenant-a", &fast_job_id).await;
    assert_eq!(queued_fast["status"], "submitted");
    assert!(queued_fast["started_at_unix_ms"].is_null());

    let slow_done = wait_for_repo_scan_job(state.clone(), "tenant-a", &slow_job_id, "succeeded").await;
    let fast_done = wait_for_repo_scan_job(state, "tenant-a", &fast_job_id, "succeeded").await;
    let slow_finished = slow_done["finished_at_unix_ms"].as_u64().expect("slow finished");
    let fast_started = fast_done["started_at_unix_ms"].as_u64().expect("fast started");
    assert!(fast_started >= slow_finished);
}

#[tokio::test]
async fn repo_list_get_and_delete_are_tenant_scoped() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    for (tenant, repo_id) in [("tenant-a", "alpha"), ("tenant-b", "bravo")] {
        let resp = super::repos::post_repo(
            State(state.clone()),
            dev_scope_headers("admin:write"),
            Json(super::repos::CreateRepoBody {
                repo_id: Some(repo_id.to_string()),
                tenant_id: tenant.to_string(),
                root_path: None,
                clone_url: Some(format!("https://example.invalid/{repo_id}.git")),
                languages: vec!["rust".to_string()],
                scan_mode: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let list_a = super::repos::get_repos(
        State(state.clone()),
        dev_scope_headers("admin:read"),
        Query(super::repos::RepoTenantQuery {
            tenant_id: "tenant-a".to_string(),
        }),
    )
    .await
    .into_response();
    let body = json_body(list_a).await;
    let repos = body["repos"].as_array().expect("repos array");
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0]["repo_id"], "alpha");

    let cross_read = super::repos::get_repo(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read"),
        Query(super::repos::RepoTenantQuery {
            tenant_id: "tenant-b".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(cross_read.status(), StatusCode::NOT_FOUND);

    let delete = super::repos::delete_repo(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:write"),
        Query(super::repos::RepoTenantQuery {
            tenant_id: "tenant-a".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let store = state.fact_store.read().await;
    assert!(crate::repo_registry::get_repo(&store, "tenant-a", "alpha").is_none());
    assert!(store
        .get_by_entity(&crate::repo_registry::scan_entity("tenant-a", "alpha"))
        .is_empty());
    assert!(crate::repo_registry::get_repo(&store, "tenant-b", "bravo").is_some());
}

/// A workspace-layout fixture: the scanner intentionally skips the root
/// manifest, so symbols only appear for member crates.
fn tiny_rust_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("Cargo.toml"), "[workspace]\nmembers = [\"mini\"]\n").expect("ws manifest");
    let member = dir.path().join("mini");
    std::fs::create_dir_all(member.join("src")).expect("member src");
    std::fs::write(
        member.join("Cargo.toml"),
        "[package]\nname = \"mini\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("member manifest");
    std::fs::write(
        member.join("src").join("lib.rs"),
        "pub struct Used;\npub fn call() -> Used { Used }\n",
    )
    .expect("member lib");
    dir
}

fn tiny_cargo_dep_workspace(dep_name: &str, version_req: &str, locked_version: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("Cargo.toml"), "[workspace]\nmembers = [\"mini\"]\n").expect("ws manifest");
    let member = dir.path().join("mini");
    std::fs::create_dir_all(member.join("src")).expect("member src");
    std::fs::write(
        member.join("Cargo.toml"),
        format!(
            r#"[package]
name = "mini"
version = "0.1.0"
edition = "2021"

[dependencies]
{dep_name} = "{version_req}"
"#
        ),
    )
    .expect("member manifest");
    std::fs::write(
        member.join("src").join("lib.rs"),
        "pub struct Used;\npub fn call() -> Used { Used }\n",
    )
    .expect("member lib");
    std::fs::write(
        dir.path().join("Cargo.lock"),
        format!(
            r#"version = 3

[[package]]
name = "{dep_name}"
version = "{locked_version}"
"#
        ),
    )
    .expect("lock");
    dir
}

async fn register_local_repo(state: &AppState, tenant_id: &str, repo_id: &str, repo: &tempfile::TempDir) {
    let root_path = repo.path().to_string_lossy().to_string();
    let created = super::repos::post_repo(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::repos::CreateRepoBody {
            repo_id: Some(repo_id.to_string()),
            tenant_id: tenant_id.to_string(),
            root_path: Some(root_path),
            clone_url: None,
            languages: vec!["rust".to_string()],
            scan_mode: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(created.status(), StatusCode::OK);
}

async fn seed_dependents_graph(
    state: &AppState,
    tenant_id: &str,
    ecosystem: &str,
    name: &str,
    package_node_id: u32,
    repos: &[(&str, u32)],
) {
    let mut map = std::collections::BTreeMap::new();
    map.insert(crate::repo_codegraph::pkg_key(ecosystem, name), package_node_id);
    for (repo_id, repo_node_id) in repos {
        map.insert(crate::repo_codegraph::repo_key(repo_id), *repo_node_id);
    }
    let id_store = crate::repo_codegraph::CodeGraphIdStore {
        next_id: package_node_id.saturating_sub(1),
        initialized: true,
        map,
    };
    {
        let mut store = state.fact_store.write().await;
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: crate::repo_codegraph::shared_ids_entity(tenant_id),
            key: crate::repo_codegraph::CODEGRAPH_IDS_KEY.to_string(),
            value: serde_json::to_string(&id_store).expect("id store json"),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
    }
    let mut projection = state.projection_state.write().await;
    for (_, repo_node_id) in repos {
        crate::relations::apply_record(
            &mut projection,
            &crate::relations::RelationRecord {
                tenant_id: tenant_id.to_string(),
                from_id: *repo_node_id,
                to_id: package_node_id,
                edge_type: "depends_on".to_string(),
                confidence_bp: 7000,
                created_at_micros: 1,
                updated_at_micros: 2,
            },
        )
        .expect("apply depends_on");
    }
}

#[tokio::test]
async fn repo_codemap_serves_summary_and_full() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let repo = tiny_rust_workspace();
    let root_path = repo.path().to_string_lossy().to_string();

    let created = super::repos::post_repo(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::repos::CreateRepoBody {
            repo_id: Some("fixture".to_string()),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root_path),
            clone_url: None,
            languages: vec!["rust".to_string()],
            scan_mode: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(created.status(), StatusCode::OK);
    let created_body = json_body(created).await;
    let scan_id = created_body["repo"]["last_scan_id"]
        .as_str()
        .expect("scan id")
        .to_string();

    // Default format is the summary: stats + per-crate rollup, no file list.
    let summary = super::repos::get_repo_codemap(
        State(state.clone()),
        Path("fixture".to_string()),
        dev_scope_headers("admin:read"),
        Query(super::repos::CodemapQuery {
            tenant_id: "tenant-a".to_string(),
            format: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(summary.status(), StatusCode::OK);
    let summary_body = json_body(summary).await;
    assert_eq!(summary_body["repo_id"], "fixture");
    assert_eq!(summary_body["scan_id"], scan_id.as_str());
    assert!(summary_body["stats"]["symbol_count"].as_u64().unwrap() >= 1);
    assert!(summary_body["crates"].as_array().is_some_and(|c| !c.is_empty()));
    assert!(summary_body.get("scan").is_none());

    // Full format round-trips the persisted WorkspaceScan.
    let full = super::repos::get_repo_codemap(
        State(state.clone()),
        Path("fixture".to_string()),
        dev_scope_headers("admin:read"),
        Query(super::repos::CodemapQuery {
            tenant_id: "tenant-a".to_string(),
            format: Some("full".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(full.status(), StatusCode::OK);
    let full_body = json_body(full).await;
    assert_eq!(full_body["scan"]["scan_id"], scan_id.as_str());
    assert!(full_body["scan"]["files"].as_array().is_some_and(|f| !f.is_empty()));
    assert!(full_body["scan"]["symbols"].as_array().is_some_and(|s| !s.is_empty()));

    // Unknown format is rejected, not silently defaulted.
    let bad_format = super::repos::get_repo_codemap(
        State(state.clone()),
        Path("fixture".to_string()),
        dev_scope_headers("admin:read"),
        Query(super::repos::CodemapQuery {
            tenant_id: "tenant-a".to_string(),
            format: Some("csv".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(bad_format.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial]
async fn repo_codemap_summary_counts_external_deps_by_ecosystem() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let repo = tiny_rust_workspace();
    let manifest = repo.path().join("mini/Cargo.toml");
    let mut manifest_body = std::fs::read_to_string(&manifest).expect("read manifest");
    manifest_body.push_str("\n[dependencies]\nserde = \"1\"\n");
    std::fs::write(&manifest, manifest_body).expect("write manifest");
    let root_path = repo.path().to_string_lossy().to_string();

    let _env = EnvVarGuard::set("CORECRUXD_EXTERNAL_DEPS", "1");
    let created = super::repos::post_repo(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::repos::CreateRepoBody {
            repo_id: Some("fixture-deps".to_string()),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root_path),
            clone_url: None,
            languages: vec!["rust".to_string()],
            scan_mode: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(created.status(), StatusCode::OK);

    let summary = super::repos::get_repo_codemap(
        State(state),
        Path("fixture-deps".to_string()),
        dev_scope_headers("admin:read"),
        Query(super::repos::CodemapQuery {
            tenant_id: "tenant-a".to_string(),
            format: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(summary.status(), StatusCode::OK);
    let summary_body = json_body(summary).await;
    assert_eq!(summary_body["stats"]["external_dep_count"], 1);
    assert_eq!(summary_body["external_deps_by_ecosystem"]["cargo"], 1);
}

#[tokio::test]
#[serial_test::serial]
async fn repo_codemap_summary_omits_external_deps_when_flag_off() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let repo = tiny_rust_workspace();
    let manifest = repo.path().join("mini/Cargo.toml");
    let mut manifest_body = std::fs::read_to_string(&manifest).expect("read manifest");
    manifest_body.push_str("\n[dependencies]\nserde = \"1\"\n");
    std::fs::write(&manifest, manifest_body).expect("write manifest");
    let root_path = repo.path().to_string_lossy().to_string();

    let _env = EnvVarGuard::unset("CORECRUXD_EXTERNAL_DEPS");
    let created = super::repos::post_repo(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::repos::CreateRepoBody {
            repo_id: Some("fixture-deps-off".to_string()),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root_path),
            clone_url: None,
            languages: vec!["rust".to_string()],
            scan_mode: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(created.status(), StatusCode::OK);

    let summary = super::repos::get_repo_codemap(
        State(state),
        Path("fixture-deps-off".to_string()),
        dev_scope_headers("admin:read"),
        Query(super::repos::CodemapQuery {
            tenant_id: "tenant-a".to_string(),
            format: Some("summary".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(summary.status(), StatusCode::OK);
    let summary_body = json_body(summary).await;
    assert!(summary_body.get("external_deps_by_ecosystem").is_none());
    let stats = summary_body["stats"].as_object().expect("stats object");
    assert!(!stats.contains_key("external_dep_count"));
}

#[tokio::test]
#[serial_test::serial]
async fn repo_dependents_real_scans_return_version_rows() {
    let _deps = EnvVarGuard::set("CORECRUXD_EXTERNAL_DEPS", "1");
    let _edges = EnvVarGuard::set("CORECRUXD_CODEGRAPH_EDGES", "1");
    let _external_graph = EnvVarGuard::set("CORECRUXD_CODEGRAPH_EXTERNAL", "1");
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let repo_a = tiny_cargo_dep_workspace("serde", "1", "1.0.200");
    let repo_b = tiny_cargo_dep_workspace("serde", "1", "1.0.201");
    register_local_repo(&state, "tenant-a", "repo-a", &repo_a).await;
    register_local_repo(&state, "tenant-a", "repo-b", &repo_b).await;

    let resp = super::repos::get_repo_dependents(
        State(state),
        dev_scope_headers("admin:read"),
        Query(super::repos::RepoDependentsQuery {
            tenant_id: "tenant-a".to_string(),
            ecosystem: "Cargo".to_string(),
            name: "Serde".to_string(),
            cursor: None,
            limit: Some(10),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["tenant_id"], "tenant-a");
    assert_eq!(body["ecosystem"], "cargo");
    assert_eq!(body["name"], "serde");
    assert_eq!(body["package_known"], true);
    assert!(body["next_cursor"].is_null());

    let dependents = body["dependents"].as_array().expect("dependents array");
    assert_eq!(dependents.len(), 2);
    let by_repo: std::collections::BTreeMap<_, _> = dependents
        .iter()
        .map(|row| (row["repo_id"].as_str().unwrap_or_default(), row))
        .collect();
    assert_eq!(by_repo["repo-a"]["version_req"], "1");
    assert_eq!(by_repo["repo-a"]["version_locked"], "1.0.200");
    assert_eq!(by_repo["repo-a"]["kind"], "normal");
    assert_eq!(by_repo["repo-a"]["source_manifest"], "mini/Cargo.toml");
    assert_eq!(by_repo["repo-b"]["version_req"], "1");
    assert_eq!(by_repo["repo-b"]["version_locked"], "1.0.201");
    assert_eq!(by_repo["repo-b"]["kind"], "normal");
    assert_eq!(by_repo["repo-b"]["source_manifest"], "mini/Cargo.toml");
}

#[tokio::test]
async fn repo_dependents_unknown_package_returns_empty_known_false() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::repos::get_repo_dependents(
        State(state),
        dev_scope_headers("admin:read"),
        Query(super::repos::RepoDependentsQuery {
            tenant_id: "tenant-a".to_string(),
            ecosystem: "npm".to_string(),
            name: "missing".to_string(),
            cursor: None,
            limit: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["package_known"], false);
    assert!(body["dependents"].as_array().expect("dependents").is_empty());
    assert!(body["next_cursor"].is_null());
}

#[tokio::test]
async fn repo_dependents_paginates_without_duplicates_or_gaps() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    seed_dependents_graph(
        &state,
        "tenant-a",
        "cargo",
        "serde",
        500,
        &[
            ("repo-a", 101),
            ("repo-b", 102),
            ("repo-c", 103),
            ("repo-d", 104),
            ("repo-e", 105),
        ],
    )
    .await;

    let mut cursor = None;
    let mut page_sizes = Vec::new();
    let mut repo_ids = Vec::new();
    loop {
        let resp = super::repos::get_repo_dependents(
            State(state.clone()),
            dev_scope_headers("admin:read"),
            Query(super::repos::RepoDependentsQuery {
                tenant_id: "tenant-a".to_string(),
                ecosystem: "cargo".to_string(),
                name: "serde".to_string(),
                cursor: cursor.clone(),
                limit: Some(2),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let dependents = body["dependents"].as_array().expect("dependents");
        page_sizes.push(dependents.len());
        repo_ids.extend(
            dependents
                .iter()
                .map(|row| row["repo_id"].as_str().unwrap_or_default().to_string()),
        );
        cursor = body["next_cursor"].as_str().map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }

    assert_eq!(page_sizes, vec![2, 2, 1]);
    assert_eq!(repo_ids, vec!["repo-a", "repo-b", "repo-c", "repo-d", "repo-e"]);
    let unique: std::collections::BTreeSet<_> = repo_ids.iter().collect();
    assert_eq!(unique.len(), repo_ids.len(), "no duplicate repos across pages");
}

#[tokio::test]
async fn repo_dependents_missing_extdeps_fact_keeps_null_version_fields() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    seed_dependents_graph(
        &state,
        "tenant-a",
        "cargo",
        "serde",
        500,
        &[("repo-missing-versions", 101)],
    )
    .await;

    let resp = super::repos::get_repo_dependents(
        State(state),
        dev_scope_headers("admin:read"),
        Query(super::repos::RepoDependentsQuery {
            tenant_id: "tenant-a".to_string(),
            ecosystem: "cargo".to_string(),
            name: "serde".to_string(),
            cursor: None,
            limit: Some(10),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let row = &body["dependents"].as_array().expect("dependents")[0];
    assert_eq!(row["repo_id"], "repo-missing-versions");
    assert!(row["version_req"].is_null());
    assert!(row["version_locked"].is_null());
    assert!(row["kind"].is_null());
    assert!(row["source_manifest"].is_null());
}

#[tokio::test]
async fn repo_dependents_requires_admin_read() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::repos::get_repo_dependents(
        State(state),
        HeaderMap::new(),
        Query(super::repos::RepoDependentsQuery {
            tenant_id: "tenant-a".to_string(),
            ecosystem: "cargo".to_string(),
            name: "serde".to_string(),
            cursor: None,
            limit: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn repo_dependents_validates_ecosystem_and_name() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let bad_ecosystem = super::repos::get_repo_dependents(
        State(state.clone()),
        dev_scope_headers("admin:read"),
        Query(super::repos::RepoDependentsQuery {
            tenant_id: "tenant-a".to_string(),
            ecosystem: "rubygems".to_string(),
            name: "rails".to_string(),
            cursor: None,
            limit: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(bad_ecosystem.status(), StatusCode::BAD_REQUEST);

    let empty_name = super::repos::get_repo_dependents(
        State(state),
        dev_scope_headers("admin:read"),
        Query(super::repos::RepoDependentsQuery {
            tenant_id: "tenant-a".to_string(),
            ecosystem: "cargo".to_string(),
            name: "   ".to_string(),
            cursor: None,
            limit: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(empty_name.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn repo_codemap_not_found_paths_are_distinct() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);

    // Unregistered repo → repo not found.
    let missing = super::repos::get_repo_codemap(
        State(state.clone()),
        Path("ghost".to_string()),
        dev_scope_headers("admin:read"),
        Query(super::repos::CodemapQuery {
            tenant_id: "tenant-a".to_string(),
            format: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    // clone_url-only registration → registered but never scanned; the 404
    // hint tells the caller how to get a scan.
    let created = super::repos::post_repo(
        State(state.clone()),
        dev_scope_headers("admin:write"),
        Json(super::repos::CreateRepoBody {
            repo_id: Some("deferred".to_string()),
            tenant_id: "tenant-a".to_string(),
            root_path: None,
            clone_url: Some("https://example.invalid/deferred.git".to_string()),
            languages: vec![],
            scan_mode: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(created.status(), StatusCode::OK);

    let unscanned = super::repos::get_repo_codemap(
        State(state.clone()),
        Path("deferred".to_string()),
        dev_scope_headers("admin:read"),
        Query(super::repos::CodemapQuery {
            tenant_id: "tenant-a".to_string(),
            format: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(unscanned.status(), StatusCode::NOT_FOUND);

    // Cross-tenant read cannot see another tenant's repo (or its scan).
    let cross = super::repos::get_repo_codemap(
        State(state.clone()),
        Path("deferred".to_string()),
        dev_scope_headers("admin:read"),
        Query(super::repos::CodemapQuery {
            tenant_id: "tenant-b".to_string(),
            format: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(cross.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn embedding_probe_rejects_empty_url() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::post_console_embedding_probe(
        State(state),
        dev_scope_headers("admin:write"),
        Json(console::ProbeEmbeddingBody { url: "".to_string() }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn embedding_probe_rejects_non_http_url() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::post_console_embedding_probe(
        State(state),
        dev_scope_headers("admin:write"),
        Json(console::ProbeEmbeddingBody {
            url: "ftp://example.com".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn embedding_probe_requires_admin_write() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::post_console_embedding_probe(
        State(state),
        HeaderMap::new(),
        Json(console::ProbeEmbeddingBody {
            url: "http://localhost:11434".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn embedding_probe_rejects_admin_read() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = console::post_console_embedding_probe(
        State(state),
        dev_scope_headers("admin:read"),
        Json(console::ProbeEmbeddingBody {
            url: "http://example.com".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Coverage-lift batch (PR #66) ───────────────────────────────────────────
// These exercise the http/planes.rs and http/dossier.rs handlers, which
// shipped at 0% test coverage. They mirror the projects:: test patterns
// above — direct handler calls with dev-scope headers, asserting status +
// shape only (deeper assertions live in the per-module unit tests).

async fn seed_project_for_planes_tests(state: &AppState) {
    {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }
    let resp = super::projects::post_project(
        State(state.clone()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::projects::CreateProjectBody {
            id: "alpha".to_string(),
            name: "Alpha".to_string(),
            planning_target: Some("tenant://alpha-planning".to_string()),
            default_passport_id: "personal-default".to_string(),
            working_tenants: vec![],
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn planes_create_then_list_then_get() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    seed_project_for_planes_tests(&state).await;

    // Create a plane.
    let create_resp = super::planes::post_plane(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::planes::CreatePlaneBody {
            id: "daemon".to_string(),
            name: "Crux Daemon".to_string(),
            description: Some("Daemon plane".to_string()),
            default_passport_id: Some("personal-default".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    // List planes.
    let list_resp = super::planes::get_planes(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    let body = json_body(list_resp).await;
    assert_eq!(body["project_id"], "alpha");
    assert_eq!(body["count"], 1);

    // Get the specific plane.
    let get_resp = super::planes::get_plane(
        State(state),
        Path(("alpha".to_string(), "daemon".to_string())),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    let detail = json_body(get_resp).await;
    assert_eq!(detail["id"], "daemon");
    assert_eq!(detail["name"], "Crux Daemon");
}

#[tokio::test]
async fn planes_list_requires_admin_read() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::planes::get_planes(State(state), Path("alpha".to_string()), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn planes_member_round_trip() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    seed_project_for_planes_tests(&state).await;
    let _ = super::planes::post_plane(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::planes::CreatePlaneBody {
            id: "daemon".to_string(),
            name: "Daemon".to_string(),
            description: None,
            default_passport_id: Some("personal-default".to_string()),
        }),
    )
    .await
    .into_response();

    // Add a second member, then remove it.
    let add_resp = super::planes::post_plane_member(
        State(state.clone()),
        Path(("alpha".to_string(), "daemon".to_string())),
        dev_scope_headers("admin:read facts:write"),
        Json(super::planes::PlaneMemberBody {
            passport_id: "work-default".to_string(),
            role: "contributor".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(add_resp.status(), StatusCode::CREATED);

    let rm_resp = super::planes::delete_plane_member(
        State(state),
        Path(("alpha".to_string(), "daemon".to_string(), "work-default".to_string())),
        dev_scope_headers("admin:read facts:write"),
    )
    .await
    .into_response();
    assert_eq!(rm_resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn planes_layer_put_then_get_then_delete() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    seed_project_for_planes_tests(&state).await;
    let _ = super::planes::post_plane(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::planes::CreatePlaneBody {
            id: "daemon".to_string(),
            name: "Daemon".to_string(),
            description: None,
            default_passport_id: Some("personal-default".to_string()),
        }),
    )
    .await
    .into_response();

    let put_resp = super::planes::put_plane_layer(
        State(state.clone()),
        Path(("alpha".to_string(), "daemon".to_string(), "vision".to_string())),
        dev_scope_headers("admin:read facts:write"),
        Json(super::planes::PutPlaneLayerBody {
            content: "Daemon plane vision: local-first.".to_string(),
        }),
    )
    .await
    .into_response();
    assert!(matches!(put_resp.status(), StatusCode::OK | StatusCode::CREATED));

    let list_resp = super::planes::get_plane_layers(
        State(state.clone()),
        Path(("alpha".to_string(), "daemon".to_string())),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    let body = json_body(list_resp).await;
    let layers = body["layers"].as_object().expect("layers map");
    assert!(layers.contains_key("vision"));
    assert_eq!(body["count"], 1);

    let del_resp = super::planes::delete_plane_layer(
        State(state),
        Path(("alpha".to_string(), "daemon".to_string(), "vision".to_string())),
        dev_scope_headers("admin:read facts:write"),
    )
    .await
    .into_response();
    // Some delete handlers return 200 with a body, others 204; both indicate
    // success — assert non-erroring status code.
    assert!(del_resp.status().is_success(), "delete: {}", del_resp.status());
}

#[tokio::test]
async fn planes_delete_removes_record() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    seed_project_for_planes_tests(&state).await;
    let _ = super::planes::post_plane(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::planes::CreatePlaneBody {
            id: "daemon".to_string(),
            name: "Daemon".to_string(),
            description: None,
            default_passport_id: Some("personal-default".to_string()),
        }),
    )
    .await
    .into_response();

    let resp = super::planes::delete_plane(
        State(state.clone()),
        Path(("alpha".to_string(), "daemon".to_string())),
        dev_scope_headers("admin:read facts:write"),
    )
    .await
    .into_response();
    assert!(resp.status().is_success(), "delete: {}", resp.status());

    let list_resp = super::planes::get_planes(State(state), Path("alpha".to_string()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let body = json_body(list_resp).await;
    assert_eq!(body["count"], 0);
}

#[tokio::test]
async fn dossier_list_when_empty_returns_empty_array() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::dossier::list_dossiers(State(state), Path("alpha".to_string()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let body = json_body(resp).await;
    assert!(body["dossiers"].is_array());
}

#[tokio::test]
async fn dossier_list_requires_admin_read() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::dossier::list_dossiers(State(state), Path("alpha".to_string()), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn storybook_post_generate_then_get_latest() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    seed_project_for_planes_tests(&state).await;

    let gen_resp = super::storybook::post_generate(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read facts:write"),
    )
    .await
    .into_response();
    assert!(gen_resp.status().is_success(), "post_generate: {}", gen_resp.status());

    let latest_resp = super::storybook::get_latest(
        State(state.clone()),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert!(
        latest_resp.status().is_success(),
        "get_latest: {}",
        latest_resp.status()
    );

    let versions_resp =
        super::storybook::list_versions(State(state), Path("alpha".to_string()), dev_scope_headers("admin:read"))
            .await
            .into_response();
    let body = json_body(versions_resp).await;
    assert!(body["versions"].is_array());
}

#[tokio::test]
async fn storybook_get_latest_when_none_returns_404() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::storybook::get_latest(
        State(state),
        Path("nonexistent".to_string()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn storybook_post_generate_requires_facts_write() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::storybook::post_generate(
        State(state),
        Path("alpha".to_string()),
        dev_scope_headers("admin:read"), // missing facts:write
    )
    .await
    .into_response();
    assert!(resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn dossier_get_unknown_returns_404() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::dossier::get_dossier(
        State(state),
        Path(("alpha".to_string(), "nonexistent".to_string())),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Community extensions (M2) ──────────────────────────────────────────

fn build_signed_manifest(
    id: &str,
    signing_key: &ed25519_dalek::SigningKey,
    publisher_fpr: &str,
) -> crux_integrations::IntegrationManifest {
    use crux_integrations::{
        sign_manifest, DataAccess, EntryKind, IntegrationEntry, IntegrationManifest, ManifestHashes, NetworkAccess,
        SafetyPolicy, INTEGRATION_SCHEMA_V1,
    };
    let mut manifest = IntegrationManifest {
        schema: INTEGRATION_SCHEMA_V1.to_string(),
        id: id.to_string(),
        name: "Quote of the Day".to_string(),
        version: "0.1.0".to_string(),
        publisher_passport_fpr: publisher_fpr.to_string(),
        summary: "Returns a quote.".to_string(),
        entry: IntegrationEntry {
            kind: EntryKind::HttpRecipe,
            path: "tools/quote.json".to_string(),
        },
        capabilities: vec!["facts:read".to_string()],
        network: NetworkAccess::default(),
        data_access: DataAccess::default(),
        safety: SafetyPolicy::default(),
        hashes: ManifestHashes::default(),
        signature: None,
        external_tool_endpoint: None,
        tools: Vec::new(),
        wasm_module_path: None,
        wasm_module_url: None,
        wasm_module_sha256: None,
    };
    sign_manifest(&mut manifest, signing_key, publisher_fpr).expect("sign");
    manifest
}

async fn add_test_key(state: &AppState, fpr: &str, public_key_hex: String) {
    let key_resp = super::extensions::add_trusted_key(
        State(state.clone()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::AddTrustedKeyBody {
            passport_fpr: fpr.to_string(),
            public_key_hex,
            trust_tier: crux_integrations::TrustTier::CommunityReviewed,
            added_by: "test".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(key_resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn extensions_list_when_empty_returns_zero_count() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::extensions::list_extensions(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let body = json_body(resp).await;
    assert_eq!(body["count"], 0);
    assert!(body["extensions"].as_array().expect("array").is_empty());
}

#[tokio::test]
async fn extensions_list_requires_admin_read() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::extensions::list_extensions(State(state), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn extensions_register_then_list_then_get_then_delete() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xab; 32]);
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    add_test_key(&state, "p_test_alice", public_key_hex).await;

    let manifest = build_signed_manifest("ext.example.quote", &signing_key, "p_test_alice");
    let reg_resp = super::extensions::register_extension(
        State(state.clone()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::RegisterExtensionBody { manifest }),
    )
    .await
    .into_response();
    assert_eq!(reg_resp.status(), StatusCode::CREATED);

    let list_resp = super::extensions::list_extensions(State(state.clone()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let body = json_body(list_resp).await;
    assert_eq!(body["count"], 1);
    assert_eq!(body["extensions"][0]["manifest"]["id"], "ext.example.quote");
    assert_eq!(body["extensions"][0]["trust_tier"], "community_reviewed");

    let get_resp = super::extensions::get_extension(
        State(state.clone()),
        Path("ext.example.quote".to_string()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(get_resp.status(), StatusCode::OK);

    let del_resp = super::extensions::delete_extension(
        State(state.clone()),
        Path("ext.example.quote".to_string()),
        dev_scope_headers("admin:read facts:write"),
    )
    .await
    .into_response();
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

    let list2 = super::extensions::list_extensions(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(json_body(list2).await["count"], 0);
}

#[tokio::test]
async fn extensions_install_from_registry_verifies_index_and_manifest_sha() {
    use crux_integrations::{CommunityExtensionEntry, CommunityExtensionsIndex, EntryKind, TrustTier};
    use sha2::Digest as _;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xac; 32]);
    let publisher_fpr = "p_test_registry";
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    add_test_key(&state, publisher_fpr, public_key_hex).await;

    let manifest = build_signed_manifest("ext.example.registry", &signing_key, publisher_fpr);
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest bytes");
    let mut hasher = sha2::Sha256::new();
    hasher.update(&manifest_bytes);
    let manifest_sha256 = hex::encode(hasher.finalize());

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind manifest server");
    let manifest_url = format!("http://{}", listener.local_addr().expect("addr"));
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept manifest request");
        let mut request_buf = [0u8; 512];
        let _ = stream.read(&mut request_buf);
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            manifest_bytes.len()
        )
        .expect("write response head");
        stream.write_all(&manifest_bytes).expect("write response body");
    });

    let mut index = CommunityExtensionsIndex::new(publisher_fpr, 1_700_000_000_000);
    index.entries.push(CommunityExtensionEntry {
        id: "ext.example.registry".to_string(),
        name: "Registry Extension".to_string(),
        version: "0.1.0".to_string(),
        summary: "Installed from a signed registry index.".to_string(),
        manifest_url,
        manifest_sha256: manifest_sha256.clone(),
        repo_url: "https://example.invalid/ext.example.registry".to_string(),
        kind: EntryKind::HttpRecipe,
        trust_tier: TrustTier::CommunityReviewed,
    });
    index.sign(&signing_key).expect("sign index");
    let index_path = state.data_dir.join("extensions/registry/index.json");
    std::fs::create_dir_all(index_path.parent().expect("index parent")).expect("index dir");
    std::fs::write(&index_path, serde_json::to_vec(&index).expect("index bytes")).expect("write index");

    let resp = super::extensions::install_from_registry(
        State(state),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::InstallFromRegistryBody {
            id: "ext.example.registry".to_string(),
            index_path: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert_eq!(body["schema"], "crux.extensions.registry_install.v1");
    assert_eq!(body["manifest_sha256"], manifest_sha256);
    assert_eq!(body["installed"]["manifest"]["id"], "ext.example.registry");
    assert_eq!(body["installed"]["trust_tier"], "community_reviewed");
}

#[tokio::test]
async fn extensions_register_unsigned_returns_400_with_dev_hint() {
    use crux_integrations::{
        DataAccess, EntryKind, IntegrationEntry, IntegrationManifest, ManifestHashes, NetworkAccess, SafetyPolicy,
        INTEGRATION_SCHEMA_V1,
    };
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let manifest = IntegrationManifest {
        schema: INTEGRATION_SCHEMA_V1.to_string(),
        id: "ext.example.unsigned".to_string(),
        name: "Unsigned".to_string(),
        version: "0.1.0".to_string(),
        publisher_passport_fpr: "p_unsigned".to_string(),
        summary: "Unsigned manifest.".to_string(),
        entry: IntegrationEntry {
            kind: EntryKind::HttpRecipe,
            path: "tools/u.json".to_string(),
        },
        capabilities: vec![],
        network: NetworkAccess::default(),
        data_access: DataAccess::default(),
        safety: SafetyPolicy::default(),
        hashes: ManifestHashes::default(),
        signature: None,
        external_tool_endpoint: None,
        tools: Vec::new(),
        wasm_module_path: None,
        wasm_module_url: None,
        wasm_module_sha256: None,
    };
    let resp = super::extensions::register_extension(
        State(state),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::RegisterExtensionBody { manifest }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED"),
        "expected dev-bypass hint in error, got: {detail}"
    );
}

#[tokio::test]
async fn extensions_register_duplicate_returns_409() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xab; 32]);
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    add_test_key(&state, "p_test_alice", public_key_hex).await;

    let manifest = build_signed_manifest("ext.example.dup", &signing_key, "p_test_alice");
    let _ = super::extensions::register_extension(
        State(state.clone()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::RegisterExtensionBody {
            manifest: manifest.clone(),
        }),
    )
    .await
    .into_response();
    let resp = super::extensions::register_extension(
        State(state),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::RegisterExtensionBody { manifest }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn extensions_get_unknown_returns_404() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::extensions::get_extension(
        State(state),
        Path("ext.does-not-exist".to_string()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn extensions_keyring_add_list_remove_round_trip() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let pubkey_hex = "00".repeat(32);

    let add_resp = super::extensions::add_trusted_key(
        State(state.clone()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::AddTrustedKeyBody {
            passport_fpr: "p_alice".to_string(),
            public_key_hex: pubkey_hex.clone(),
            trust_tier: crux_integrations::TrustTier::LocallySigned,
            added_by: "operator-test".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(add_resp.status(), StatusCode::CREATED);

    let list_resp = super::extensions::list_trusted_keys(State(state.clone()), dev_scope_headers("admin:read"))
        .await
        .into_response();
    let body = json_body(list_resp).await;
    assert_eq!(body["count"], 1);
    assert_eq!(body["keys"]["p_alice"]["public_key_hex"], pubkey_hex);
    assert_eq!(body["keys"]["p_alice"]["trust_tier"], "locally_signed");

    let del_resp = super::extensions::delete_trusted_key(
        State(state.clone()),
        Path("p_alice".to_string()),
        dev_scope_headers("admin:read facts:write"),
    )
    .await
    .into_response();
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

    let list2 = super::extensions::list_trusted_keys(State(state), dev_scope_headers("admin:read"))
        .await
        .into_response();
    assert_eq!(json_body(list2).await["count"], 0);
}

#[tokio::test]
async fn extensions_keyring_delete_unknown_returns_404() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::extensions::delete_trusted_key(
        State(state),
        Path("p_nobody".to_string()),
        dev_scope_headers("admin:read facts:write"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Per-passport grants (M3) ───────────────────────────────────────────

async fn install_test_extension_for_grants(state: &AppState, id: &str) {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xab; 32]);
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    add_test_key(state, "p_test_alice", public_key_hex).await;
    let manifest = build_signed_manifest(id, &signing_key, "p_test_alice");
    let _ = super::extensions::register_extension(
        State(state.clone()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::RegisterExtensionBody { manifest }),
    )
    .await
    .into_response();
}

#[tokio::test]
async fn grants_issue_then_list_then_revoke() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    install_test_extension_for_grants(&state, "ext.example.quote").await;

    let issue_resp = super::extensions::issue_grant(
        State(state.clone()),
        Path("ext.example.quote".to_string()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::IssueGrantBody {
            passport_fpr: "p_grantee".to_string(),
            allowed_tool_names: vec!["quote.daily".to_string()],
            allowed_prefixes_read: vec!["personal::quotes::".to_string()],
            allowed_prefixes_write: vec!["personal::quotes::".to_string()],
            rate_limit_per_min: Some(30),
        }),
    )
    .await
    .into_response();
    assert_eq!(issue_resp.status(), StatusCode::CREATED);

    let list_resp = super::extensions::list_grants(
        State(state.clone()),
        Path("ext.example.quote".to_string()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    let body = json_body(list_resp).await;
    assert_eq!(body["count"], 1);
    assert_eq!(body["grants"][0]["passport_fpr"], "p_grantee");

    let revoke_resp = super::extensions::revoke_grant(
        State(state.clone()),
        Path(("ext.example.quote".to_string(), "p_grantee".to_string())),
        dev_scope_headers("admin:read facts:write"),
    )
    .await
    .into_response();
    assert_eq!(revoke_resp.status(), StatusCode::NO_CONTENT);

    let list2 = super::extensions::list_grants(
        State(state),
        Path("ext.example.quote".to_string()),
        dev_scope_headers("admin:read"),
    )
    .await
    .into_response();
    assert_eq!(json_body(list2).await["count"], 0);
}

#[tokio::test]
async fn grants_issue_when_extension_not_installed_returns_404() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::extensions::issue_grant(
        State(state),
        Path("ext.does-not-exist".to_string()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::IssueGrantBody {
            passport_fpr: "p_grantee".to_string(),
            allowed_tool_names: vec![],
            allowed_prefixes_read: vec![],
            allowed_prefixes_write: vec![],
            rate_limit_per_min: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn grants_issue_with_privacy_gated_prefix_returns_400() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    install_test_extension_for_grants(&state, "ext.example.bad").await;
    let resp = super::extensions::issue_grant(
        State(state),
        Path("ext.example.bad".to_string()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::IssueGrantBody {
            passport_fpr: "p_grantee".to_string(),
            allowed_tool_names: vec![],
            allowed_prefixes_read: vec![],
            allowed_prefixes_write: vec!["__ax__::".to_string()],
            rate_limit_per_min: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert!(body["detail"].as_str().unwrap_or_default().contains("privacy-gated"));
}

#[tokio::test]
async fn grants_issue_duplicate_returns_409() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    install_test_extension_for_grants(&state, "ext.example.dup").await;
    let body_fn = || {
        Json(super::extensions::IssueGrantBody {
            passport_fpr: "p_grantee".to_string(),
            allowed_tool_names: vec![],
            allowed_prefixes_read: vec![],
            allowed_prefixes_write: vec![],
            rate_limit_per_min: None,
        })
    };
    let _ = super::extensions::issue_grant(
        State(state.clone()),
        Path("ext.example.dup".to_string()),
        dev_scope_headers("admin:read facts:write"),
        body_fn(),
    )
    .await
    .into_response();
    let resp = super::extensions::issue_grant(
        State(state),
        Path("ext.example.dup".to_string()),
        dev_scope_headers("admin:read facts:write"),
        body_fn(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn grants_revoke_unknown_returns_404() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::extensions::revoke_grant(
        State(state),
        Path(("ext.example.x".to_string(), "p_nobody".to_string())),
        dev_scope_headers("admin:read facts:write"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn grants_list_requires_admin_read() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::extensions::list_grants(State(state), Path("ext.example.x".to_string()), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invoke_tool_requires_facts_write() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::extensions::invoke_extension_tool(
        State(state),
        Path(("ext.example.x".to_string(), "quote.daily".to_string())),
        dev_scope_headers("admin:read"),
        Json(super::extensions::InvokeToolBody {
            passport_fpr: Some("p_alice".to_string()),
            args: serde_json::json!({}),
        }),
    )
    .await
    .into_response();
    assert!(matches!(
        resp.status(),
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED
    ));
}

#[tokio::test]
async fn invoke_tool_requires_passport_in_header_or_body() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::extensions::invoke_extension_tool(
        State(state),
        Path(("ext.example.x".to_string(), "quote.daily".to_string())),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::InvokeToolBody {
            passport_fpr: None,
            args: serde_json::json!({}),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invoke_tool_when_extension_not_installed_returns_404() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = super::extensions::invoke_extension_tool(
        State(state),
        Path(("ext.does-not-exist".to_string(), "quote.daily".to_string())),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::InvokeToolBody {
            passport_fpr: Some("p_alice".to_string()),
            args: serde_json::json!({}),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invoke_tool_without_grant_returns_403() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    install_test_extension_for_grants(&state, "ext.example.nogrant").await;
    let resp = super::extensions::invoke_extension_tool(
        State(state),
        Path(("ext.example.nogrant".to_string(), "quote.daily".to_string())),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::InvokeToolBody {
            passport_fpr: Some("p_unauthorised".to_string()),
            args: serde_json::json!({}),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── M6.3: wasm dispatch via HTTP ────────────────────────────────────────

#[cfg(feature = "wasm-extensions")]
fn build_wasm_test_module() -> Vec<u8> {
    // Tiny wat module that responds with `{"result":"ok","fact_writes":[]}`
    // — same shape as a real wasm extension would, just hard-coded so the
    // test asserts on dispatch wiring rather than module behaviour.
    let body = r#"{"result":"ok","fact_writes":[]}"#;
    let body_lit = body.replace('\\', "\\\\").replace('"', "\\\"");
    let wat = format!(
        r#"
        (module
          (memory (export "memory") 1)
          (data (i32.const 5000) "{body_lit}")
          (func (export "extension_call")
            (param $req_ptr i32) (param $req_len i32)
            (param $resp_ptr i32) (param $resp_cap i32)
            (result i32)
            (memory.copy (local.get $resp_ptr) (i32.const 5000) (i32.const {len}))
            (i32.const {len})
          )
        )
        "#,
        body_lit = body_lit,
        len = body.len(),
    );
    wat::parse_str(&wat).expect("wat parse")
}

#[cfg(feature = "wasm-extensions")]
#[tokio::test]
async fn wasm_install_then_invoke_returns_module_result() {
    use crate::wasm_dispatcher::sha256_hex;
    use crux_integrations::{
        sign_manifest, DataAccess, EntryKind, ExternalToolDefinition, IntegrationEntry, IntegrationManifest,
        ManifestHashes, NetworkAccess, SafetyPolicy, INTEGRATION_SCHEMA_V1,
    };

    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    // Wire a real wasm engine for this test.
    state.wasm_engine = Some(std::sync::Arc::new(
        crate::wasm_host::WasmEngine::new(std::time::Duration::from_millis(5)).expect("engine"),
    ));

    // 1. Author a kind=wasm manifest, signed by a freshly-trusted key.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xcd; 32]);
    let publisher_fpr = "p_wasm_test".to_string();
    add_test_key(
        &state,
        &publisher_fpr,
        hex::encode(signing_key.verifying_key().to_bytes()),
    )
    .await;

    let module_bytes = build_wasm_test_module();
    let module_sha = sha256_hex(&module_bytes);

    let mut manifest = IntegrationManifest {
        schema: INTEGRATION_SCHEMA_V1.to_string(),
        id: "ext.wasm.test".to_string(),
        name: "Wasm Test".to_string(),
        version: "0.1.0".to_string(),
        publisher_passport_fpr: publisher_fpr.clone(),
        summary: "Test wasm extension.".to_string(),
        entry: IntegrationEntry {
            kind: EntryKind::Wasm,
            path: "wasm".to_string(),
        },
        capabilities: vec![],
        network: NetworkAccess::default(),
        data_access: DataAccess::default(),
        safety: SafetyPolicy::default(),
        hashes: ManifestHashes::default(),
        signature: None,
        external_tool_endpoint: None,
        tools: vec![ExternalToolDefinition {
            name: "ext.wasm.test.tool".to_string(),
            description: "Test tool.".to_string(),
            input_schema: serde_json::json!({"type":"object"}),
            consequence_metadata: None,
            auth_shared_secret_id: None,
        }],
        wasm_module_path: Some("extension.wasm".to_string()),
        wasm_module_url: None,
        wasm_module_sha256: Some(module_sha),
    };
    sign_manifest(&mut manifest, &signing_key, &publisher_fpr).expect("sign");

    // 2. Place the bytes where the dispatcher will find them.
    let module_dir = state.data_dir.join("extensions").join("ext.wasm.test");
    std::fs::create_dir_all(&module_dir).expect("mkdir");
    std::fs::write(module_dir.join("extension.wasm"), &module_bytes).expect("write module");

    // 3. Install the manifest.
    let install = super::extensions::register_extension(
        State(state.clone()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::RegisterExtensionBody {
            manifest: manifest.clone(),
        }),
    )
    .await
    .into_response();
    assert_eq!(install.status(), StatusCode::CREATED, "install failed");

    // 4. Issue a grant for a calling passport.
    let grantee = "p_wasm_caller".to_string();
    let grant_resp = super::extensions::issue_grant(
        State(state.clone()),
        Path("ext.wasm.test".to_string()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::IssueGrantBody {
            passport_fpr: grantee.clone(),
            allowed_tool_names: vec!["ext.wasm.test.tool".to_string()],
            allowed_prefixes_read: vec!["__test__::".to_string()],
            allowed_prefixes_write: vec!["__test__::".to_string()],
            rate_limit_per_min: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(grant_resp.status(), StatusCode::CREATED, "grant failed");

    // 5. Invoke the tool — should hit the wasm dispatcher and return
    //    {"result":"ok","fact_writes":[]} translated into a
    //    WasmDispatchOutcome.
    let invoke = super::extensions::invoke_extension_tool(
        State(state.clone()),
        Path(("ext.wasm.test".to_string(), "ext.wasm.test.tool".to_string())),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::InvokeToolBody {
            passport_fpr: Some(grantee),
            args: serde_json::json!({"hello": "world"}),
        }),
    )
    .await
    .into_response();
    assert_eq!(invoke.status(), StatusCode::OK, "invoke failed");
    let body = json_body(invoke).await;
    assert_eq!(body["result"], serde_json::Value::String("ok".into()));
}

#[cfg(feature = "wasm-extensions")]
#[tokio::test]
async fn wasm_invoke_with_sha_mismatch_returns_409() {
    use crate::wasm_dispatcher::sha256_hex;
    use crux_integrations::{
        sign_manifest, DataAccess, EntryKind, ExternalToolDefinition, IntegrationEntry, IntegrationManifest,
        ManifestHashes, NetworkAccess, SafetyPolicy, INTEGRATION_SCHEMA_V1,
    };

    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    state.wasm_engine = Some(std::sync::Arc::new(
        crate::wasm_host::WasmEngine::new(std::time::Duration::from_millis(5)).expect("engine"),
    ));

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xcd; 32]);
    let publisher_fpr = "p_wasm_test_sha".to_string();
    add_test_key(
        &state,
        &publisher_fpr,
        hex::encode(signing_key.verifying_key().to_bytes()),
    )
    .await;

    let module_bytes = build_wasm_test_module();
    // Lie about the sha256 — should land as a 409 on invoke.
    let bogus_sha = sha256_hex(b"not the real bytes");

    let mut manifest = IntegrationManifest {
        schema: INTEGRATION_SCHEMA_V1.to_string(),
        id: "ext.wasm.bad".to_string(),
        name: "Wasm Bad".to_string(),
        version: "0.1.0".to_string(),
        publisher_passport_fpr: publisher_fpr.clone(),
        summary: "Mismatched-sha extension.".to_string(),
        entry: IntegrationEntry {
            kind: EntryKind::Wasm,
            path: "wasm".to_string(),
        },
        capabilities: vec![],
        network: NetworkAccess::default(),
        data_access: DataAccess::default(),
        safety: SafetyPolicy::default(),
        hashes: ManifestHashes::default(),
        signature: None,
        external_tool_endpoint: None,
        tools: vec![ExternalToolDefinition {
            name: "ext.wasm.bad.tool".to_string(),
            description: "Mismatch.".to_string(),
            input_schema: serde_json::json!({"type":"object"}),
            consequence_metadata: None,
            auth_shared_secret_id: None,
        }],
        wasm_module_path: Some("extension.wasm".to_string()),
        wasm_module_url: None,
        wasm_module_sha256: Some(bogus_sha),
    };
    sign_manifest(&mut manifest, &signing_key, &publisher_fpr).expect("sign");

    let module_dir = state.data_dir.join("extensions").join("ext.wasm.bad");
    std::fs::create_dir_all(&module_dir).expect("mkdir");
    std::fs::write(module_dir.join("extension.wasm"), &module_bytes).expect("write");

    let install = super::extensions::register_extension(
        State(state.clone()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::RegisterExtensionBody {
            manifest: manifest.clone(),
        }),
    )
    .await
    .into_response();
    assert_eq!(install.status(), StatusCode::CREATED);

    let grantee = "p_wasm_caller_sha".to_string();
    let _ = super::extensions::issue_grant(
        State(state.clone()),
        Path("ext.wasm.bad".to_string()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::IssueGrantBody {
            passport_fpr: grantee.clone(),
            allowed_tool_names: vec!["ext.wasm.bad.tool".to_string()],
            allowed_prefixes_read: vec![],
            allowed_prefixes_write: vec![],
            rate_limit_per_min: None,
        }),
    )
    .await
    .into_response();

    let invoke = super::extensions::invoke_extension_tool(
        State(state.clone()),
        Path(("ext.wasm.bad".to_string(), "ext.wasm.bad.tool".to_string())),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::InvokeToolBody {
            passport_fpr: Some(grantee),
            args: serde_json::json!({}),
        }),
    )
    .await
    .into_response();
    assert_eq!(invoke.status(), StatusCode::CONFLICT, "expected 409 on sha mismatch");
}

// ── M7: real-world WASM summarise extension end-to-end ─────────────────

#[cfg(feature = "wasm-extensions")]
fn locate_summarise_artefacts() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let candidates = [
        "../../../Community-Projects/example-extension-wasm-summarise",
        "../../Community-Projects/example-extension-wasm-summarise",
        "Community-Projects/example-extension-wasm-summarise",
        "/home/myles/CueCrux/Community-Projects/example-extension-wasm-summarise",
    ];
    for c in candidates {
        let dir = std::path::PathBuf::from(c);
        let manifest = dir.join("manifest.json");
        let wasm = dir.join("extension.wasm");
        if manifest.exists() && wasm.exists() {
            return Some((manifest, wasm));
        }
    }
    None
}

/// End-to-end smoke against the real built artefact: install the signed
/// `manifest.json` from the example-extension-wasm-summarise repo,
/// place the matching `extension.wasm` bytes, issue a grant, write
/// some seed facts under the prefix, then invoke and assert the
/// summary is non-empty and the summary fact got persisted.
///
/// Skipped (with a warning) when the artefacts can't be found — the
/// repo lives outside Crux/ so this is best-effort rather than a hard
/// dependency on the layout.
#[cfg(feature = "wasm-extensions")]
#[tokio::test]
async fn wasm_summarise_extension_end_to_end_or_skip() {
    let Some((manifest_path, wasm_path)) = locate_summarise_artefacts() else {
        eprintln!("SKIP: example-extension-wasm-summarise artefacts not found; run `cargo build --release -p summarise-module --target wasm32-unknown-unknown && cargo run -p summarise-signer` in the example repo to produce them");
        return;
    };
    let manifest_bytes = std::fs::read(&manifest_path).expect("read manifest");
    let manifest: crux_integrations::IntegrationManifest =
        serde_json::from_slice(&manifest_bytes).expect("parse manifest");
    let wasm_bytes = std::fs::read(&wasm_path).expect("read wasm");

    let mut state = test_app_state_with_auth(16, AuthMode::DevScopes);
    state.wasm_engine = Some(std::sync::Arc::new(
        crate::wasm_host::WasmEngine::new(std::time::Duration::from_millis(5)).expect("engine"),
    ));

    // 1. Trust the publisher key (taken from the manifest signature).
    let sig = manifest.signature.as_ref().expect("signed");
    let public_key_hex = sig.public_key_hex.clone().expect("inline pubkey");
    add_test_key(&state, &sig.passport_fpr, public_key_hex).await;

    // 2. Place the wasm bytes where the dispatcher will find them.
    let module_dir = state.data_dir.join("extensions").join("ext.summarise");
    std::fs::create_dir_all(&module_dir).expect("mkdir");
    std::fs::write(module_dir.join("extension.wasm"), &wasm_bytes).expect("write module");

    // 3. Install the signed manifest.
    let install = super::extensions::register_extension(
        State(state.clone()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::RegisterExtensionBody {
            manifest: manifest.clone(),
        }),
    )
    .await
    .into_response();
    assert_eq!(install.status(), StatusCode::CREATED, "install");

    // 4. Issue a grant: read+write `summarise::personal::notes::` and
    //    read `personal::notes::`.
    let grantee = "p_summarise_caller".to_string();
    let grant = super::extensions::issue_grant(
        State(state.clone()),
        Path("ext.summarise".to_string()),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::IssueGrantBody {
            passport_fpr: grantee.clone(),
            allowed_tool_names: vec!["ext.summarise.prefix".to_string()],
            allowed_prefixes_read: vec!["personal::notes::".to_string()],
            allowed_prefixes_write: vec!["summarise::personal::notes".to_string()],
            rate_limit_per_min: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(grant.status(), StatusCode::CREATED, "grant");

    // 5. Seed a couple of facts under personal::notes::.
    {
        let mut store = state.fact_store.write().await;
        for (key, val) in [
            (
                "note1",
                "Cats are excellent companions. They purr a lot. The cats also chase laser pointers.",
            ),
            (
                "note2",
                "Dogs are loyal pets. Cats and dogs both bring joy. Cats are independent.",
            ),
        ] {
            let mut sf = corecrux_memory::fact_store::StoreFact {
                tenant_hash: "default".to_string(),
                entity: "personal::notes::misc".to_string(),
                key: key.to_string(),
                value: val.to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
            };
            crate::fact_privacy::enforce_global(&mut sf);
            store.store(sf);
        }
    }

    // 6. Invoke.
    let invoke = super::extensions::invoke_extension_tool(
        State(state.clone()),
        Path(("ext.summarise".to_string(), "ext.summarise.prefix".to_string())),
        dev_scope_headers("admin:read facts:write"),
        Json(super::extensions::InvokeToolBody {
            passport_fpr: Some(grantee),
            args: serde_json::json!({"prefix": "personal::notes::", "top_sentences": 2}),
        }),
    )
    .await
    .into_response();
    let status = invoke.status();
    let body = json_body(invoke).await;
    assert_eq!(status, StatusCode::OK, "invoke status (body={body:#?})");
    let result = &body["result"];
    assert!(
        result["summary"].as_str().is_some_and(|s| !s.is_empty()),
        "summary empty: {body:#?}"
    );
    assert!(
        result["fact_count"].as_u64().unwrap_or(0) >= 2,
        "fact_count too low: {body:#?}"
    );
}

// ── upgrade-aware 501s ──────────────────────────────────────────
//
// Platform-only endpoints keep status 501 but return RFC 7807 problem
// details with structured upgrade extensions instead of bare errors.

async fn assert_platform_upgrade_501(resp: Response, capability: &str) {
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    let body = json_body(resp).await;
    assert_eq!(body["status"], 501, "problem status mismatch: {body:#?}");
    assert_eq!(
        body["platform_available"], true,
        "missing platform_available: {body:#?}"
    );
    assert_eq!(body["capability"], capability, "capability mismatch: {body:#?}");
    assert_eq!(
        body["docs"],
        format!("https://crux.cuecrux.com/docs/platform/{capability}"),
        "docs link mismatch: {body:#?}"
    );
    assert_eq!(body["requires"], "rcx_capability_token", "missing requires: {body:#?}");
}

#[allow(deprecated)]
#[serial_test::serial]
#[tokio::test]
async fn post_query_graph_expand_501_is_platform_upgrade_aware() {
    std::env::set_var("CORECRUXD_QUERY_GRAPH_EXPAND", "1");
    let state = test_app_state(16); // dataplane disabled by default
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
    assert_platform_upgrade_501(resp, "graph_expand").await;
}

#[allow(deprecated)]
#[serial_test::serial]
#[tokio::test]
async fn post_query_time_range_501_is_platform_upgrade_aware() {
    std::env::set_var("CORECRUXD_QUERY_TIME_RANGE", "1");
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
    std::env::remove_var("CORECRUXD_QUERY_TIME_RANGE");
    assert_platform_upgrade_501(resp, "time_range").await;
}

#[tokio::test]
async fn post_admin_append_501_is_platform_upgrade_aware() {
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
    assert_platform_upgrade_501(resp, "admin_append").await;
}

#[tokio::test]
async fn get_proj_meta_501_is_platform_upgrade_aware() {
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
    assert_platform_upgrade_501(resp, "projections_meta").await;
}

#[tokio::test]
async fn get_gpus_501_is_platform_upgrade_aware() {
    let state = test_app_state(16);
    let resp = routing::get_gpus(State(state), HeaderMap::new()).await.into_response();
    assert_platform_upgrade_501(resp, "gpus").await;
}

// ── OpenAPI contract: /v1/openapi.json (integration-surface plan M0) ─────

#[tokio::test]
async fn openapi_json_route_serves_valid_openapi_3_document() {
    use tower::ServiceExt;

    let state = test_app_state(16);
    let app = router(state, test_case_store());
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/v1/openapi.json")
                .body(axum::body::Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router response");
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("content-type header")
        .to_str()
        .expect("content-type str")
        .to_string();
    assert!(
        content_type.starts_with("application/json"),
        "unexpected content-type: {content_type}"
    );

    let doc = json_body(resp).await;

    // Valid OpenAPI 3.x document shape.
    let version = doc["openapi"].as_str().expect("openapi version field");
    assert!(version.starts_with("3."), "expected OpenAPI 3.x, got {version}");
    assert_eq!(doc["info"]["title"], "Crux Daemon API");
    assert!(doc["info"]["version"].as_str().is_some_and(|v| !v.is_empty()));

    // Every annotated route group is present in `paths`.
    let paths = doc["paths"].as_object().expect("paths object");
    for expected in [
        // Health
        "/healthz",
        "/readyz",
        "/metrics",
        "/v1/version",
        // Facts
        "/v1/facts",
        "/v1/facts/bulk",
        "/v1/facts/{factId}",
        "/v1/facts/entity/{entity}",
        "/v1/facts/export",
        // Sessions
        "/v1/sessions/{sessionId}/state",
        // Events
        "/v1/events/stream",
        // Query
        "/v1/query/text-search",
        "/v1/query/text-search/expand",
        "/v1/query/graph-expand",
        "/v1/query/time-range",
        // Receipts
        "/v1/receipts/{receiptId}",
        "/v1/receipts/{receiptId}/signature",
        "/v1/receipts/{receiptId}/verification",
    ] {
        assert!(paths.contains_key(expected), "missing path in OpenAPI spec: {expected}");
    }

    // Component schemas + the bearer security scheme survive serialization.
    let schemas = doc["components"]["schemas"].as_object().expect("components.schemas");
    for expected in ["Fact", "StoreFact", "FactQuery", "SessionState"] {
        assert!(schemas.contains_key(expected), "missing schema: {expected}");
    }
    assert!(
        doc["components"]["securitySchemes"]["bearer_auth"].is_object(),
        "missing bearer_auth security scheme"
    );
}

// ── Activity log: /v1/activity (crux-dual-surface-activity-log M1+M2) ─────

/// `POST /v1/activity` then `GET /v1/activity` round-trips an entry, and the
/// agent-lane row carries the append id as a receipt reference (T.4). Also
/// proves the cheap row reaches the same receipt id the human deref would.
#[tokio::test]
#[serial_test::serial]
async fn activity_post_then_get_round_trip() {
    use tower::ServiceExt;
    std::env::set_var("CORECRUXD_FEATURE_ACTIVITY_LOG", "1");
    let app = router(test_app_state(16), test_case_store());

    let post = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/activity")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "tenant_id": "rt-tenant",
                        "session_id": "rt-sess",
                        "turn_id": "turn-rt-1",
                        "kind": "question",
                        "text": "what changed in __ops::config-audit today?"
                    })
                    .to_string(),
                ))
                .expect("build post"),
        )
        .await
        .expect("post response");
    assert_eq!(post.status(), StatusCode::CREATED);
    let created = json_body(post).await;
    let entry_id = created["entry_id"].as_str().expect("entry_id").to_string();
    // T.1 — reserved prefix redacted from verbatim text on persist.
    assert!(!created["text"].as_str().unwrap().contains("__ops::"));
    // T.4 — append id present as a receipt reference.
    assert!(created["refs"]["receipt_ids"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str() == Some(&entry_id)));

    let get = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/v1/activity?tenant_id=rt-tenant&session=rt-sess&token_budget=500")
                .body(axum::body::Body::empty())
                .expect("build get"),
        )
        .await
        .expect("get response");
    assert_eq!(get.status(), StatusCode::OK);
    let pulled = json_body(get).await;
    assert_eq!(pulled["returned"].as_u64(), Some(1));
    let row = &pulled["rows"][0];
    assert_eq!(row["kind"], "question");
    assert_eq!(row["turn_id"], "turn-rt-1");
    // Parity seed (M4): the agent-lane row references the same append receipt.
    assert!(row["receipt_ids"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str() == Some(&entry_id)));
    std::env::remove_var("CORECRUXD_FEATURE_ACTIVITY_LOG");
}

/// QC.2 — the agent pull is rejected without a `token_budget`.
#[tokio::test]
#[serial_test::serial]
async fn activity_get_without_token_budget_is_400() {
    use tower::ServiceExt;
    std::env::set_var("CORECRUXD_FEATURE_ACTIVITY_LOG", "1");
    let app = router(test_app_state(16), test_case_store());
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/v1/activity?tenant_id=t&session=s")
                .body(axum::body::Body::empty())
                .expect("build get"),
        )
        .await
        .expect("get response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    std::env::remove_var("CORECRUXD_FEATURE_ACTIVITY_LOG");
}

/// Flag off ⇒ the route is a 404 disabled-problem (the daemon behaves as
/// today).
#[tokio::test]
#[serial_test::serial]
async fn activity_get_when_flag_off_is_404() {
    use tower::ServiceExt;
    std::env::remove_var("CORECRUXD_FEATURE_ACTIVITY_LOG");
    let app = router(test_app_state(16), test_case_store());
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/v1/activity?tenant_id=t&session=s&token_budget=500")
                .body(axum::body::Body::empty())
                .expect("build get"),
        )
        .await
        .expect("get response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// T.1 — a pull for a different tenant never returns another tenant's rows.
#[tokio::test]
#[serial_test::serial]
async fn activity_get_cross_tenant_is_empty() {
    use tower::ServiceExt;
    std::env::set_var("CORECRUXD_FEATURE_ACTIVITY_LOG", "1");
    let app = router(test_app_state(16), test_case_store());
    let _ = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/activity")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "tenant_id": "xt-tenant-a",
                        "session_id": "xt-sess",
                        "kind": "answer",
                        "text": "tenant A only"
                    })
                    .to_string(),
                ))
                .expect("build post"),
        )
        .await
        .expect("post response");

    let get = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/v1/activity?tenant_id=xt-tenant-b&session=xt-sess&token_budget=500")
                .body(axum::body::Body::empty())
                .expect("build get"),
        )
        .await
        .expect("get response");
    assert_eq!(get.status(), StatusCode::OK);
    let pulled = json_body(get).await;
    assert_eq!(pulled["returned"].as_u64(), Some(0));
    std::env::remove_var("CORECRUXD_FEATURE_ACTIVITY_LOG");
}

/// M4 parity invariant — "both lanes join on turn_id and point at one
/// receipt". The agent-lane row's `receipt_ids` for a turn must be
/// byte-identical to the human-lane deref's `refs.receipt_ids` for the same
/// `turn_id`. This is the cross-walk the console ✓verify badge relies on.
#[tokio::test]
#[serial_test::serial]
async fn activity_turn_id_parity_agent_vs_human_lane() {
    use tower::ServiceExt;
    std::env::set_var("CORECRUXD_FEATURE_ACTIVITY_LOG", "1");
    let app = router(test_app_state(16), test_case_store());

    let post = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/activity")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "tenant_id": "par-tenant",
                        "session_id": "par-sess",
                        "turn_id": "turn-parity",
                        "kind": "answer",
                        "text": "the parity answer"
                    })
                    .to_string(),
                ))
                .expect("build post"),
        )
        .await
        .expect("post response");
    assert_eq!(post.status(), StatusCode::CREATED);

    // Agent lane row.
    let get = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/v1/activity?tenant_id=par-tenant&session=par-sess&token_budget=500")
                .body(axum::body::Body::empty())
                .expect("build get"),
        )
        .await
        .expect("get response");
    let pulled = json_body(get).await;
    let agent_receipts = pulled["rows"][0]["receipt_ids"].clone();

    // Human-lane deref by turn_id.
    let deref = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/v1/activity/turn/turn-parity?tenant_id=par-tenant&session=par-sess")
                .body(axum::body::Body::empty())
                .expect("build deref"),
        )
        .await
        .expect("deref response");
    assert_eq!(deref.status(), StatusCode::OK);
    let expanded = json_body(deref).await;
    let human_receipts = expanded["entries"][0]["refs"]["receipt_ids"].clone();

    assert_eq!(
        agent_receipts, human_receipts,
        "agent-lane and human-lane receipt_ids must be byte-identical for the same turn_id"
    );
    // And the human lane carries the verbatim text the agent lane only previews.
    assert_eq!(expanded["entries"][0]["text"], "the parity answer");
    std::env::remove_var("CORECRUXD_FEATURE_ACTIVITY_LOG");
}

/// M2 end-to-end: with `CORECRUXD_FEATURE_ACTIVITY_SIGN=1`, a posted entry
/// carries an embedded Ed25519 receipt, and the turn verify endpoint reports
/// it green against the daemon passport key. With the sign flag off, the same
/// entry reports `signed:false / status:recorded` (no regression).
#[tokio::test]
#[serial_test::serial]
async fn activity_co_sign_then_verify_green_end_to_end() {
    use tower::ServiceExt;
    std::env::set_var("CORECRUXD_FEATURE_ACTIVITY_LOG", "1");
    std::env::set_var("CORECRUXD_FEATURE_ACTIVITY_SIGN", "1");
    let mut state = test_app_state(16);
    bind_test_state_to_root_passport_key(&mut state);
    let app = router(state, test_case_store());

    let post = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/activity")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "tenant_id": "sign-tenant",
                        "session_id": "sign-sess",
                        "turn_id": "turn-sign",
                        "kind": "answer",
                        "text": "the signed answer"
                    })
                    .to_string(),
                ))
                .expect("build post"),
        )
        .await
        .expect("post response");
    assert_eq!(post.status(), StatusCode::CREATED);
    let created = json_body(post).await;
    assert_eq!(
        created["receipt"]["alg"], "ed25519",
        "sign flag on ⇒ embedded receipt: {created}"
    );

    let verify = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/v1/activity/turn/turn-sign/verify?tenant_id=sign-tenant&session=sign-sess")
                .body(axum::body::Body::empty())
                .expect("build verify"),
        )
        .await
        .expect("verify response");
    assert_eq!(verify.status(), StatusCode::OK);
    let v = json_body(verify).await;
    assert_eq!(v["entries"][0]["signed"], true);
    assert_eq!(
        v["entries"][0]["verified"], true,
        "co-signed entry must verify green: {v}"
    );

    std::env::remove_var("CORECRUXD_FEATURE_ACTIVITY_SIGN");
    std::env::remove_var("CORECRUXD_FEATURE_ACTIVITY_LOG");
}

// ── Agent usage rollup: /v1/agents/{passport}/usage (action-ledger M3) ────

fn usage_query(window_hours: Option<u32>) -> axum::extract::Query<agent_usage::UsageQuery> {
    axum::extract::Query(agent_usage::UsageQuery { window_hours })
}

fn seed_ledger_file(state: &AppState, passport: &str, payloads: &[serde_json::Value]) {
    let obs_dir = state.data_dir.join("observations");
    std::fs::create_dir_all(&obs_dir).expect("mkdir observations");
    let body = payloads
        .iter()
        .map(|p| {
            serde_json::json!({
                "kind": "agent.tool_invocation.v1",
                "ts": chrono::Utc::now().to_rfc3339(),
                "session_id": format!("ledger::{passport}"),
                "provider": "crux-mcp",
                "principal": passport,
                "payload": p,
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(obs_dir.join(format!("ledger__{passport}.jsonl")), body).expect("write ledger jsonl");
}

#[tokio::test]
async fn agent_usage_unauthenticated_denied_401() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = agent_usage::get_agent_usage(
        State(state),
        HeaderMap::new(),
        axum::extract::Path("alice".to_string()),
        usage_query(None),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_usage_insufficient_scope_denied_403() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = agent_usage::get_agent_usage(
        State(state),
        dev_scope_headers("facts:read"),
        axum::extract::Path("alice".to_string()),
        usage_query(None),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn agent_usage_other_passport_denied_403() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    // bob (passport-bound, read scope) asks for alice's usage → 403,
    // even though the scope would otherwise pass.
    let resp = agent_usage::get_agent_usage(
        State(state),
        dev_scope_passport_headers("sessions:read", "bob"),
        axum::extract::Path("alice".to_string()),
        usage_query(None),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn agent_usage_own_passport_allowed_200() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    seed_ledger_file(
        &state,
        "alice",
        &[
            serde_json::json!({"tool": "query_facts", "est_tokens_in": 10, "est_tokens_out": 90, "latency_ms": 4, "outcome": "ok"}),
            serde_json::json!({"tool": "store_fact", "est_tokens_in": 20, "est_tokens_out": 30, "latency_ms": 2, "outcome": "error"}),
        ],
    );
    let resp = agent_usage::get_agent_usage(
        State(state),
        dev_scope_passport_headers("sessions:read", "alice"),
        axum::extract::Path("alice".to_string()),
        usage_query(None),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["passport"], "alice");
    assert_eq!(body["calls_total"], 2);
    assert_eq!(body["tokens_total"], 150);
    assert_eq!(body["errors_total"], 1);
    assert_eq!(body["window"], "all");
    assert_eq!(body["tools"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn agent_usage_raw_admin_reads_others_200() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    seed_ledger_file(
        &state,
        "alice",
        &[
            serde_json::json!({"tool": "query", "est_tokens_in": 5, "est_tokens_out": 5, "latency_ms": 1, "outcome": "ok"}),
        ],
    );
    // Raw admin (admin:read, NO passport binding) may read anyone's.
    let resp = agent_usage::get_agent_usage(
        State(state),
        dev_scope_headers("admin:read"),
        axum::extract::Path("alice".to_string()),
        usage_query(Some(24)),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["calls_total"], 1);
    assert_eq!(body["window"], "24h");
}

#[tokio::test]
async fn agent_usage_empty_ledger_is_200_zeroes() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let resp = agent_usage::get_agent_usage(
        State(state),
        dev_scope_passport_headers("sessions:read", "ghost"),
        axum::extract::Path("ghost".to_string()),
        usage_query(None),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["calls_total"], 0);
    assert_eq!(body["error_rate"], 0.0);
}

// ── ingress hardening M1: SSE longevity gate ──────────────────────────
//
// Gate for crux-http-ingress-hardening-2026-06-11 M1: an idle SSE session
// must survive >30s (the router-wide TimeoutLayer + the new shutdown drain
// cap must not kill long-lived streams). Long-running, so ignored by
// default — run with:
//   cargo test -p corecruxd sse_session_survives_30s_idle -- --ignored
#[tokio::test]
#[ignore = "long-running (>35s wall clock); M1 gate, re-run during M5 sidecar validation"]
async fn sse_session_survives_30s_idle() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let state = test_app_state(1);
    let app = super::ingress::apply_ingress_limits(
        router(state, test_case_store()),
        &crate::config::IngressConfig::default(),
        None,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    tokio::spawn(crate::serve_http_listener(
        listener,
        app,
        shutdown_rx,
        Some(std::time::Duration::from_secs(30)),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
    conn.write_all(b"GET /v1/events/stream HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\n\r\n")
        .await
        .unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(35);
    let mut received = Vec::new();
    let mut closed = false;
    while std::time::Instant::now() < deadline {
        let mut buf = [0u8; 1024];
        match tokio::time::timeout(std::time::Duration::from_secs(20), conn.read(&mut buf)).await {
            Ok(Ok(0)) => {
                closed = true;
                break;
            }
            Ok(Ok(n)) => received.extend_from_slice(&buf[..n]),
            Ok(Err(err)) => panic!("SSE connection errored before 35s elapsed: {err}"),
            // No bytes for 20s is fine in itself (keep-alive cadence is 15s);
            // keep waiting until the deadline.
            Err(_elapsed) => {}
        }
    }
    assert!(!closed, "SSE connection was closed before 35s of idle time");
    let text = String::from_utf8_lossy(&received);
    assert!(text.starts_with("HTTP/1.1 200"), "unexpected SSE response: {text}");
    // 15s keep-alive cadence → at least two keep-alive comment frames in 35s.
    assert!(
        text.matches(':').count() >= 2,
        "expected SSE keep-alive frames over 35s idle, got: {text}"
    );
}

// ── /v1/memory/import — .cruxpack import (identity-memory-portability M4) ──

fn cruxpack_test_signer() -> crux_session::LocalPassportKey {
    crux_session::LocalPassportKey::from_seed([7_u8; 32]).expect("seed key")
}

/// Build a signed pack from a throwaway source store.
fn build_test_pack(facts: Vec<(&str, &str, &str)>, tenant: &str) -> corecrux_memory::cruxpack::CruxPack {
    use corecrux_memory::cruxpack as cp;
    let mut source = corecrux_memory::FactStore::new();
    for (entity, key, value) in facts {
        source.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: Some("agent:source".to_string()),
        });
    }
    let signer = cruxpack_test_signer();
    let opts = cp::ExportOptions {
        tenant_id: tenant.to_string(),
        ..cp::ExportOptions::default()
    };
    let (sections, _) = cp::build_pack_sections(&source, None, &opts);
    let manifest = cp::build_manifest(&sections, signer.passport_fpr(), signer.public_key_hex(), &opts);
    cp::sign_pack(manifest, sections, |hash| signer.sign_hash(hash)).expect("sign pack")
}

fn import_request(
    pack: corecrux_memory::cruxpack::CruxPack,
    tenant: &str,
    dry_run: bool,
) -> Json<memory_import::MemoryImportRequest> {
    Json(memory_import::MemoryImportRequest {
        tenant_id: tenant.to_string(),
        dry_run,
        principal_map: std::collections::BTreeMap::new(),
        pack,
    })
}

#[tokio::test]
async fn memory_import_round_trip_applies_pack() {
    let state = test_app_state(16);
    let pack = build_test_pack(vec![("project-alpha", "status", "phase 1 complete")], "local");
    let resp = memory_import::post_memory_import(
        State(state.clone()),
        HeaderMap::new(),
        import_request(pack, "local", false),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["imported_facts"], 1);
    assert_eq!(body["collisions_superseded"], 0);

    // The fact landed through the journaled path with pack provenance.
    let store = state.fact_store.read().await;
    let facts = store.get_by_entity("project-alpha");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].value, "phase 1 complete");
    assert!(facts[0]
        .source_receipt
        .as_deref()
        .expect("provenance stamp")
        .starts_with("cruxpack:blake3:"));
}

#[tokio::test]
async fn memory_import_disabled_returns_404() {
    let mut state = test_app_state(16);
    state.memory_import_enabled = false;
    let pack = build_test_pack(vec![("e", "k", "v")], "local");
    let resp = memory_import::post_memory_import(State(state), HeaderMap::new(), import_request(pack, "local", false))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn memory_import_unauthenticated_denied_t3() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let pack = build_test_pack(vec![("e", "k", "v")], "local");
    let resp = memory_import::post_memory_import(State(state), HeaderMap::new(), import_request(pack, "local", false))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn memory_import_tampered_pack_rejected() {
    let state = test_app_state(16);
    let mut pack = build_test_pack(vec![("e", "k", "honest-value")], "local");
    pack.sections.facts[0].value = "tampered-value".to_string();
    let resp = memory_import::post_memory_import(
        State(state.clone()),
        HeaderMap::new(),
        import_request(pack, "local", false),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // Nothing was written.
    assert_eq!(state.fact_store.read().await.count(), 0);
}

#[tokio::test]
async fn memory_import_cross_tenant_pack_rejected_t1() {
    let state = test_app_state(16);
    let pack = build_test_pack(vec![("e", "k", "v")], "tenant-a");
    let resp = memory_import::post_memory_import(
        State(state.clone()),
        HeaderMap::new(),
        import_request(pack, "tenant-b", false),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(state.fact_store.read().await.count(), 0);
}

#[tokio::test]
async fn memory_import_collision_supersedes_never_overwrites() {
    let state = test_app_state(16);
    {
        let mut store = state.fact_store.write().await;
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "shared".to_string(),
            key: "k".to_string(),
            value: "local-value".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
    }
    let pack = build_test_pack(vec![("shared", "k", "incoming-value")], "local");
    let resp = memory_import::post_memory_import(
        State(state.clone()),
        HeaderMap::new(),
        import_request(pack, "local", false),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["collisions_superseded"], 1);

    let store = state.fact_store.read().await;
    let history = store.fact_history("shared", "k");
    assert_eq!(history.len(), 2, "local value retired, never destroyed");
    assert_eq!(history[0].value, "local-value");
    assert!(history[0].superseded_by.is_some());
    assert_eq!(history[1].value, "incoming-value");
}

#[tokio::test]
async fn memory_import_dry_run_writes_nothing() {
    let state = test_app_state(16);
    let pack = build_test_pack(vec![("e", "k", "v")], "local");
    let resp = memory_import::post_memory_import(
        State(state.clone()),
        HeaderMap::new(),
        import_request(pack, "local", true),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["imported_facts"], 1, "plan reports what WOULD be written");
    assert_eq!(state.fact_store.read().await.count(), 0);
}

#[tokio::test]
async fn memory_import_double_import_is_idempotent() {
    let state = test_app_state(16);
    let pack = build_test_pack(vec![("e", "k", "v")], "local");
    for expected_imported in [1_i64, 0_i64] {
        let resp = memory_import::post_memory_import(
            State(state.clone()),
            HeaderMap::new(),
            import_request(pack.clone(), "local", false),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["imported_facts"], expected_imported);
    }
    assert_eq!(state.fact_store.read().await.count(), 1);
}

// ── /v1/identity/links — identity federation (identity-memory-portability M5) ──

/// Seed default passports on `state` and build a fully cross-signed
/// CreateLinkRequest from `personal-default` to a synthetic remote passport.
async fn signed_link_request(state: &AppState) -> (crate::identity_links::CreateLinkRequest, String) {
    use ed25519_dalek::{Signer, SigningKey};
    seed_default_passports(state).await;
    let store = state.fact_store.read().await;
    let local = crate::passports::get_passport(&store, "personal-default").expect("local passport");
    drop(store);
    let local_key =
        crux_session::LocalPassportKey::from_path(&state.data_dir.join("passports").join("personal-default.key"))
            .expect("local key");

    let remote_key = SigningKey::from_bytes(&[42_u8; 32]);
    let remote_pub = remote_key.verifying_key().to_bytes();
    let remote_fpr = corecrux_memory::cruxpack::passport_fpr_from_public_key(&remote_pub);

    let created_at = "2026-06-12T00:00:00Z";
    let statement =
        corecrux_memory::identity_link::LinkStatement::memory_read(&local.principal_id, &remote_fpr, created_at);
    let hash = corecrux_memory::identity_link::statement_hash(&statement);
    (
        crate::identity_links::CreateLinkRequest {
            local_passport_id: "personal-default".to_string(),
            remote_fpr: remote_fpr.clone(),
            remote_public_key_hex: hex::encode(remote_pub),
            created_at: created_at.to_string(),
            sig_local: hex::encode(local_key.sign_hash(&hash)),
            sig_remote: hex::encode(remote_key.sign(&hash).to_bytes()),
        },
        remote_fpr,
    )
}

async fn candidate_for_signed_request(state: &AppState, remote_fpr: &str) -> String {
    let facts = state.fact_store.read().await;
    let local = crate::passports::get_passport(&facts, "personal-default").expect("local passport");
    let mut entities = state.entity_store.write().await;
    let (candidate_id, _) = crate::candidate_links::create_candidate(
        &mut entities,
        &facts,
        crate::candidate_links::CreateCandidateInput {
            local_passport_fpr: local.principal_id,
            observed_subject: remote_fpr.to_string(),
            signals: vec![corecrux_memory::candidate_link::CandidateLinkSignal {
                kind: "temporal_adjacency".to_string(),
                confidence: 0.82,
                evidence_ref: Some("session_binding:test-a|session_binding:test-b".to_string()),
            }],
            confidence: 0.82,
            evidence_refs: vec![
                "session_binding:test-a".to_string(),
                "session_binding:test-b".to_string(),
            ],
            proposed_at: Some("2026-06-15T00:00:00Z".to_string()),
        },
        "operator",
    )
    .expect("candidate");
    candidate_id
}

#[tokio::test]
async fn identity_links_disabled_returns_404() {
    let mut state = test_app_state(16);
    state.identity_links_enabled = false;
    let (req, _) = signed_link_request(&state).await;
    let resp = identity_links::post_identity_link(State(state.clone()), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = identity_links::get_identity_links(State(state), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn identity_link_create_requires_admin_write_t3() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let (req, _) = signed_link_request(&state).await;
    // No credentials → 401.
    let resp = identity_links::post_identity_link(State(state.clone()), HeaderMap::new(), Json(req.clone()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // facts:write is not enough — link creation is an operator action.
    let resp = identity_links::post_identity_link(State(state), dev_scope_headers("facts:write"), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn identity_candidate_confirm_promotes_to_resolving_link() {
    let state = test_app_state(16);
    let (req, remote_fpr) = signed_link_request(&state).await;
    let candidate_id = candidate_for_signed_request(&state, &remote_fpr).await;

    let resp = identity_links::post_identity_candidate_confirm(
        State(state.clone()),
        HeaderMap::new(),
        Path(candidate_id.clone()),
        Json(req),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    let link_id = body["link_id"].as_str().expect("link id").to_string();
    assert_eq!(body["candidate"]["status"], "confirmed");
    assert_eq!(body["candidate"]["resolved_link_id"], link_id);

    {
        let entities = state.entity_store.read().await;
        let candidate_history = entities.history(corecrux_memory::candidate_link::CANDIDATE_LINK_KIND, &candidate_id);
        assert_eq!(candidate_history.len(), 2, "proposal + confirmation are versioned");
        let link_history = entities.history(corecrux_memory::identity_link::IDENTITY_LINK_KIND, &link_id);
        assert_eq!(link_history.len(), 1);
    }

    let resp = principal::get_resolve_principal(State(state), resolve_query(&remote_fpr), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn identity_candidate_confirm_rejects_mismatched_remote_fpr() {
    let state = test_app_state(16);
    let (req, remote_fpr) = signed_link_request(&state).await;
    let candidate_id = candidate_for_signed_request(&state, "p_observed-but-not-signed").await;

    let resp = identity_links::post_identity_candidate_confirm(
        State(state.clone()),
        HeaderMap::new(),
        Path(candidate_id),
        Json(req),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let entities = state.entity_store.read().await;
    assert!(
        crate::identity_links::find_live_link_for_remote(&entities, &remote_fpr).is_none(),
        "mismatched candidate must not create a resolving edge"
    );
}

#[tokio::test]
async fn identity_candidate_reject_is_versioned_and_non_resolving() {
    let state = test_app_state(16);
    let (_req, remote_fpr) = signed_link_request(&state).await;
    let candidate_id = candidate_for_signed_request(&state, &remote_fpr).await;

    let resp = identity_links::post_identity_candidate_reject(
        State(state.clone()),
        HeaderMap::new(),
        Path(candidate_id.clone()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["candidate"]["status"], "rejected");
    assert!(body["candidate"]["resolved_link_id"].is_null());

    {
        let entities = state.entity_store.read().await;
        let candidate_history = entities.history(corecrux_memory::candidate_link::CANDIDATE_LINK_KIND, &candidate_id);
        assert_eq!(candidate_history.len(), 2, "proposal + rejection are versioned");
        assert!(crate::identity_links::find_live_link_for_remote(&entities, &remote_fpr).is_none());
    }

    let resp = principal::get_resolve_principal(State(state), resolve_query(&remote_fpr), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn identity_candidates_list_requires_admin_read_and_filters() {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let (_req, remote_fpr) = signed_link_request(&state).await;
    let candidate_id = candidate_for_signed_request(&state, &remote_fpr).await;

    let resp = identity_links::get_identity_candidates(
        State(state.clone()),
        HeaderMap::new(),
        Query(identity_links::ListIdentityCandidatesQuery { status: None }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = identity_links::get_identity_candidates(
        State(state.clone()),
        dev_scope_headers("facts:read"),
        Query(identity_links::ListIdentityCandidatesQuery { status: None }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = identity_links::get_identity_candidates(
        State(state.clone()),
        dev_scope_headers("admin:read"),
        Query(identity_links::ListIdentityCandidatesQuery {
            status: Some("proposed".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let candidates = body["candidates"].as_array().expect("candidates");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0]["candidate_id"], candidate_id);

    let resp = identity_links::get_identity_candidates(
        State(state.clone()),
        dev_scope_headers("admin:read"),
        Query(identity_links::ListIdentityCandidatesQuery {
            status: Some("rejected".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(json_body(resp).await["candidates"]
        .as_array()
        .expect("candidates")
        .is_empty());

    let resp = identity_links::get_identity_candidates(
        State(state),
        dev_scope_headers("admin:read"),
        Query(identity_links::ListIdentityCandidatesQuery {
            status: Some("bogus".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn resolve_principal_include_candidates_surfaces_suggestions_without_resolving() {
    let state = test_app_state(16);
    let (_req, remote_fpr) = signed_link_request(&state).await;
    let candidate_id = candidate_for_signed_request(&state, &remote_fpr).await;

    let resp = principal::get_resolve_principal(
        State(state.clone()),
        resolve_query_with_candidates(&remote_fpr),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = json_body(resp).await;
    assert_eq!(body["candidates_resolve"], false);
    let candidates = body["candidates"].as_array().expect("candidate suggestions");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0]["candidate_id"], candidate_id);
    assert_eq!(candidates[0]["resolving"], false);

    let resp = principal::get_resolve_principal(State(state), resolve_query(&remote_fpr), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "candidate remains non-resolving without confirmation"
    );
}

#[tokio::test]
async fn synthetic_anonymous_session_resolution_demo_m6() {
    let state = test_app_state(16);
    let (req, remote_fpr) = signed_link_request(&state).await;
    let local_fpr = {
        let facts = state.fact_store.read().await;
        crate::passports::get_passport(&facts, "personal-default")
            .expect("local passport")
            .principal_id
    };

    let observations = vec![
        crate::candidate_links::CandidateObservation {
            local_passport_fpr: local_fpr.clone(),
            observed_subject: local_fpr,
            tenant_id: "work::team".to_string(),
            project_id: Some("alpha".to_string()),
            observed_at_unix_ms: 1_000,
            evidence_ref: "synthetic:session-a".to_string(),
            cruxpack_source_receipt: None,
        },
        crate::candidate_links::CandidateObservation {
            local_passport_fpr: {
                let facts = state.fact_store.read().await;
                crate::passports::get_passport(&facts, "personal-default")
                    .expect("local passport")
                    .principal_id
            },
            observed_subject: remote_fpr.clone(),
            tenant_id: "work::team".to_string(),
            project_id: Some("alpha".to_string()),
            observed_at_unix_ms: 2_000,
            evidence_ref: "synthetic:session-b".to_string(),
            cruxpack_source_receipt: None,
        },
        crate::candidate_links::CandidateObservation {
            local_passport_fpr: {
                let facts = state.fact_store.read().await;
                crate::passports::get_passport(&facts, "personal-default")
                    .expect("local passport")
                    .principal_id
            },
            observed_subject: "p_decoy_remote".to_string(),
            tenant_id: "work::other-team".to_string(),
            project_id: Some("alpha".to_string()),
            observed_at_unix_ms: 2_100,
            evidence_ref: "synthetic:decoy".to_string(),
            cruxpack_source_receipt: None,
        },
    ];

    let created = {
        let facts = state.fact_store.read().await;
        let mut entities = state.entity_store.write().await;
        crate::candidate_links::propose_from_observations(
            &mut entities,
            &facts,
            &observations,
            "m6-demo",
            &crate::candidate_links::ProposerConfig::default(),
        )
        .expect("propose")
    };
    assert_eq!(created.len(), 1, "decoy pair must not emit a candidate");
    let candidate_id = created[0].0.clone();
    assert_eq!(created[0].1.observed_subject, remote_fpr);

    let resp = principal::get_resolve_principal(
        State(state.clone()),
        resolve_query_with_candidates(&remote_fpr),
        HeaderMap::new(),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "candidate is a suggestion only");
    let body = json_body(resp).await;
    assert_eq!(body["candidates"][0]["candidate_id"], candidate_id);
    assert_eq!(body["candidates_resolve"], false);

    let resp = identity_links::post_identity_candidate_confirm(
        State(state.clone()),
        HeaderMap::new(),
        Path(candidate_id),
        Json(req),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = principal::get_resolve_principal(State(state.clone()), resolve_query(&remote_fpr), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let principal = json_body(resp).await;
    assert_eq!(principal["passport_id"], "personal-default");
    assert!(principal["resolved_via"]
        .as_str()
        .unwrap_or_default()
        .starts_with("identity_link:"));

    let resp = principal::get_resolve_principal(State(state), resolve_query("p_decoy_remote"), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "decoy never resolves");
}

#[tokio::test]
async fn identity_link_lifecycle_create_resolve_revoke_deny() {
    let state = test_app_state(16);
    let (req, remote_fpr) = signed_link_request(&state).await;

    // Unlinked remote fpr → 404 (resolver fallback finds nothing).
    let resp = principal::get_resolve_principal(State(state.clone()), resolve_query(&remote_fpr), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "unlinked passport must be denied");

    // Create the link (201).
    let resp = identity_links::post_identity_link(State(state.clone()), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    let link_id = body["link_id"].as_str().expect("link_id").to_string();

    // The remote fpr now resolves — capped to memory.read, hop attributed.
    let resp = principal::get_resolve_principal(State(state.clone()), resolve_query(&remote_fpr), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let principal = json_body(resp).await;
    assert_eq!(principal["passport_id"], "personal-default");
    assert_eq!(principal["resolved_via"], format!("identity_link:{link_id}"));
    let caps: Vec<String> = principal["capabilities"]
        .as_array()
        .expect("caps")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(caps, crate::policy::federation_read_allowed_capabilities());
    assert_eq!(
        principal["federation_grant"]["capability"],
        crate::policy::FEDERATION_READ_CAPABILITY
    );
    assert_eq!(
        principal["federation_grant"]["scope"],
        crate::policy::FEDERATION_READ_SCOPE
    );

    // List shows it.
    let resp = identity_links::get_identity_links(State(state.clone()), HeaderMap::new())
        .await
        .into_response();
    let listed = json_body(resp).await;
    assert_eq!(listed["links"].as_array().expect("links").len(), 1);

    // Revoke (200) — receipts: version chain grew, record not deleted.
    let resp = identity_links::post_identity_link_revoke(State(state.clone()), HeaderMap::new(), Path(link_id.clone()))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    {
        let entities = state.entity_store.read().await;
        let history = entities.history("identity_link", &link_id);
        assert_eq!(history.len(), 2, "create + revoke = two receipted versions");
    }

    // Revoked → denied again (T.3: same 404 as unlinked).
    let resp = principal::get_resolve_principal(State(state.clone()), resolve_query(&remote_fpr), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "revoked link must be denied");
}

#[tokio::test]
async fn identity_link_resolution_consumes_rcx_federation_read_grant() {
    let mut state = test_app_state(16);
    state.rcx_router = Some(test_rcx_router(vec![crate::policy::FEDERATION_READ_CAPABILITY]));
    let (req, remote_fpr) = signed_link_request(&state).await;

    let resp = identity_links::post_identity_link(State(state.clone()), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = principal::get_resolve_principal(State(state), resolve_query(&remote_fpr), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-crux-mode").unwrap(), "local");
    let principal = json_body(resp).await;
    assert_eq!(
        principal["federation_grant"]["capability"],
        crate::policy::FEDERATION_READ_CAPABILITY
    );
}

#[tokio::test]
async fn identity_link_resolution_denied_when_rcx_federation_read_missing() {
    let mut state = test_app_state(16);
    state.rcx_router = Some(test_rcx_router(vec!["corecrux.query.local"]));
    let (req, remote_fpr) = signed_link_request(&state).await;

    let resp = principal::get_resolve_principal(State(state.clone()), resolve_query(&remote_fpr), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "unlinked passport stays 404 before RCX"
    );

    let resp = identity_links::post_identity_link(State(state.clone()), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = principal::get_resolve_principal(State(state), resolve_query(&remote_fpr), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.headers().get("x-crux-mode").unwrap(), "refused");
    let body = json_body(resp).await;
    assert_eq!(body["error"], "rcx_capability_denied");
    assert_eq!(
        body["refusal_receipt"]["capability"],
        crate::policy::FEDERATION_READ_CAPABILITY
    );
}

#[tokio::test]
async fn identity_link_forged_signature_rejected() {
    use ed25519_dalek::{Signer, SigningKey};
    let state = test_app_state(16);
    let (mut req, remote_fpr) = signed_link_request(&state).await;
    // Forge the remote signature with an attacker key.
    let attacker = SigningKey::from_bytes(&[99_u8; 32]);
    let store = state.fact_store.read().await;
    let local = crate::passports::get_passport(&store, "personal-default").expect("local");
    drop(store);
    let statement =
        corecrux_memory::identity_link::LinkStatement::memory_read(&local.principal_id, &remote_fpr, &req.created_at);
    let hash = corecrux_memory::identity_link::statement_hash(&statement);
    req.sig_remote = hex::encode(attacker.sign(&hash).to_bytes());

    let resp = identity_links::post_identity_link(State(state.clone()), HeaderMap::new(), Json(req))
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // And the forged remote never resolves.
    let resp = principal::get_resolve_principal(State(state), resolve_query(&remote_fpr), HeaderMap::new())
        .await
        .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─────────────────────────────────────────────────────────────────────────
// M3 — deny-by-default route authorization middleware
// (ExecPlan crux-external-findings-remediation-2026-07-10).
//
// The contract-classification tests (matrix completeness, scope hygiene) live
// in `route_auth::tests`; these exercise the runtime middleware end-to-end via
// `oneshot`, following the router-test idiom used throughout this file.
// ─────────────────────────────────────────────────────────────────────────

use super::route_auth::RouteAuthMode;

/// A trivial always-200 handler for the isolated route-auth test routers.
async fn route_auth_ok_handler() -> StatusCode {
    StatusCode::OK
}

/// Dev-scope header string broad enough to satisfy every contract's any-of set
/// (and the downstream handler's own scope check) so the "sufficient" leg is
/// admitted by the middleware and not rejected by the handler for auth reasons.
const ROUTE_AUTH_BROAD_SCOPES: &str = "admin:read admin:write query:read facts:read facts:write \
sessions:read sessions:write replication:write integrations:install compute:embed";

/// A scope no contract accepts — guarantees the middleware's insufficient-scope
/// path regardless of which route it is applied to.
const ROUTE_AUTH_BOGUS_SCOPE: &str = "totally:bogus";

/// Mount a single route with NO entry in the `classify_route` contract table,
/// wrapped by the route-auth middleware in `mode`. Isolates fail-closed / shadow
/// behaviour on an uncontracted route from the real (fully classified) route set.
fn route_auth_uncontracted_app(mode: RouteAuthMode) -> Router {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    Router::new()
        .route("/totally/unregistered/{id}", get(route_auth_ok_handler))
        .layer(middleware::from_fn_with_state(
            (state.clone(), mode),
            super::route_auth::route_auth_middleware,
        ))
        .with_state(state)
}

/// Mount our own always-200 handler at a path the contract DOES recognise
/// (`GET /v1/facts` ⇒ Read, any-of {query:read, admin:read}). Because the
/// handler ignores auth, only the MIDDLEWARE can reject — isolating its decision
/// from any handler-level check so shadow vs enforce is unambiguous.
fn route_auth_contracted_app(mode: RouteAuthMode) -> Router {
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    Router::new()
        .route("/v1/facts", get(route_auth_ok_handler))
        .layer(middleware::from_fn_with_state(
            (state.clone(), mode),
            super::route_auth::route_auth_middleware,
        ))
        .with_state(state)
}

fn route_auth_request(method: &str, uri: &str, scopes: Option<&str>) -> axum::http::Request<axum::body::Body> {
    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    if let Some(s) = scopes {
        builder = builder.header("x-corecrux-scopes", s);
    }
    builder.body(axum::body::Body::empty()).expect("build request")
}

/// (b) Enforce mode fails closed on a route with no contract entry, even when
/// the caller presents ample scopes.
#[tokio::test]
async fn route_auth_enforce_fails_closed_on_uncontracted_route() {
    use tower::ServiceExt;
    let app = route_auth_uncontracted_app(RouteAuthMode::Enforce);
    let resp = app
        .oneshot(route_auth_request(
            "GET",
            "/totally/unregistered/xyz",
            Some(ROUTE_AUTH_BROAD_SCOPES),
        ))
        .await
        .expect("resp");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "an uncontracted route must fail closed (403) in enforce mode"
    );
}

/// (d) Shadow mode never blocks: the SAME uncontracted request that fails closed
/// in enforce reaches the handler (200) in shadow — the middleware did not
/// produce a rejection.
#[tokio::test]
async fn route_auth_shadow_passes_uncontracted_route_through() {
    use tower::ServiceExt;
    let app = route_auth_uncontracted_app(RouteAuthMode::Shadow);
    let resp = app
        .oneshot(route_auth_request(
            "GET",
            "/totally/unregistered/xyz",
            Some(ROUTE_AUTH_BROAD_SCOPES),
        ))
        .await
        .expect("resp");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "shadow mode must pass an uncontracted route through to the handler"
    );
}

/// (d) Shadow never blocks an insufficient-scope request either: on a contracted
/// route whose handler ignores auth, the exact request that 403s in enforce
/// passes through (200) in shadow.
#[tokio::test]
async fn route_auth_shadow_passes_insufficient_scope_through() {
    use tower::ServiceExt;

    let enforce = route_auth_contracted_app(RouteAuthMode::Enforce);
    let denied = enforce
        .oneshot(route_auth_request("GET", "/v1/facts", Some(ROUTE_AUTH_BOGUS_SCOPE)))
        .await
        .expect("resp");
    assert_eq!(
        denied.status(),
        StatusCode::FORBIDDEN,
        "insufficient scope must be denied by the middleware in enforce mode"
    );

    let shadow = route_auth_contracted_app(RouteAuthMode::Shadow);
    let admitted = shadow
        .oneshot(route_auth_request("GET", "/v1/facts", Some(ROUTE_AUTH_BOGUS_SCOPE)))
        .await
        .expect("resp");
    assert_eq!(
        admitted.status(),
        StatusCode::OK,
        "shadow mode must not produce the rejection — the handler is reached"
    );
}

/// (e) Public routes pass with NO auth headers in enforce mode — monitors depend
/// on this.
#[tokio::test]
async fn route_auth_enforce_admits_public_routes_without_auth() {
    use tower::ServiceExt;
    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let app = router_with_route_auth(state, test_case_store(), RouteAuthMode::Enforce);

    let healthz = app
        .clone()
        .oneshot(route_auth_request("GET", "/healthz", None))
        .await
        .expect("healthz");
    assert_eq!(
        healthz.status(),
        StatusCode::OK,
        "healthz must pass with no auth in enforce"
    );

    let readyz = app
        .oneshot(route_auth_request("GET", "/readyz", None))
        .await
        .expect("readyz");
    assert!(
        readyz.status() != StatusCode::UNAUTHORIZED && readyz.status() != StatusCode::FORBIDDEN,
        "readyz must not be blocked by route auth in enforce, got {}",
        readyz.status()
    );
}

/// (c) Contract-driven matrix over the REAL router in enforce mode, one route
/// per `RouteAuthClass`: no token ⇒ 401/403; a sufficient scope ⇒ NOT 401/403
/// (the middleware admits; the handler may return any other status); an
/// insufficient-only scope ⇒ 401/403.
#[tokio::test]
async fn route_auth_enforce_contract_matrix() {
    use tower::ServiceExt;

    // (class label, method, uri) — one representative per class. Public is
    // covered by the dedicated smoke test above.
    let cases: &[(&str, &str, &str)] = &[
        ("Read", "GET", "/v1/facts?tenant_id=t&token_budget=500"),
        ("Write", "PUT", "/v1/facts"),
        ("AdminRead", "GET", "/v1/identity/candidates"),
        ("AdminWrite", "POST", "/v1/console/embedding/probe"),
        ("InternalReplication", "POST", "/v1/internal/replication/segments"),
        // FeatureGated representative. The GPU-1 compute bridge is compiled out
        // of CE (ExecPlan crux-external-findings-remediation M4), so under the
        // default build the router has no `/v1/gpu1/*` route and enforce mode
        // would 403 on the missing MatchedPath even with a sufficient scope.
        // Use the always-compiled (runtime-flag-gated) `/v1/context` surface as
        // the CE stand-in; both classify FeatureGated with the same scope set.
        #[cfg(feature = "hosted-surfaces")]
        ("FeatureGated", "POST", "/v1/gpu1/answer"),
        #[cfg(not(feature = "hosted-surfaces"))]
        ("FeatureGated", "GET", "/v1/context"),
    ];

    let state = test_app_state_with_auth(16, AuthMode::DevScopes);
    let app = router_with_route_auth(state, test_case_store(), RouteAuthMode::Enforce);

    for (label, method, uri) in cases {
        // No token ⇒ middleware rejects before the handler (401 in DevScopes).
        let no_token = app
            .clone()
            .oneshot(route_auth_request(method, uri, None))
            .await
            .expect("no-token resp");
        assert!(
            no_token.status() == StatusCode::UNAUTHORIZED || no_token.status() == StatusCode::FORBIDDEN,
            "[{label}] {method} {uri} with no token must be 401/403, got {}",
            no_token.status()
        );

        // Insufficient scope ⇒ middleware 403 before the handler.
        let insufficient = app
            .clone()
            .oneshot(route_auth_request(method, uri, Some(ROUTE_AUTH_BOGUS_SCOPE)))
            .await
            .expect("insufficient resp");
        assert!(
            insufficient.status() == StatusCode::UNAUTHORIZED || insufficient.status() == StatusCode::FORBIDDEN,
            "[{label}] {method} {uri} with insufficient scope must be 401/403, got {}",
            insufficient.status()
        );

        // Sufficient scope ⇒ middleware admits; the handler may return any other
        // status, but never 401/403 for an auth reason.
        let sufficient = app
            .clone()
            .oneshot(route_auth_request(method, uri, Some(ROUTE_AUTH_BROAD_SCOPES)))
            .await
            .expect("sufficient resp");
        assert!(
            sufficient.status() != StatusCode::UNAUTHORIZED && sufficient.status() != StatusCode::FORBIDDEN,
            "[{label}] {method} {uri} with a sufficient scope must be admitted (not 401/403), got {}",
            sufficient.status()
        );
    }
}
