// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! gRPC integration tests for Crux Daemon.
//! Run: ./scripts/run-integration-tests.sh --test grpc -- --test-threads=1
//!
//! These tests verify that the gRPC server is listening, that all data-plane
//! RPCs correctly return `UNIMPLEMENTED` in Crux Daemon, and that the
//! observe service is accessible.

use std::sync::OnceLock;

use corecrux_proto::dataplane_v1::core_crux_data_plane_v1_client::CoreCruxDataPlaneV1Client;
use corecrux_proto::dataplane_v1::core_crux_export_v1_client::CoreCruxExportV1Client;
use corecrux_proto::dataplane_v1::{
    AppendBatchRequest, AppendEvent, ExportReceiptBundleRequest, ReadFramesRequest, ReadManyBatchedRequest,
    ReadManyFramesBatchedRequest, ReadStreamBatchedRequest, ReadStreamRequest, ReplaySessionRequest,
};
use crux_integration_tests::TestDaemon;

fn daemon() -> &'static TestDaemon {
    static INSTANCE: OnceLock<TestDaemon> = OnceLock::new();
    INSTANCE.get_or_init(TestDaemon::start)
}

fn grpc_endpoint() -> String {
    format!("http://127.0.0.1:{}", daemon().grpc_port)
}

// ── Connection ──────────────────────────────────────────────────────

#[tokio::test]
async fn grpc_connect() {
    let _client = CoreCruxDataPlaneV1Client::connect(grpc_endpoint())
        .await
        .expect("gRPC connection should succeed");
}

#[tokio::test]
async fn export_service_connect() {
    let _client = CoreCruxExportV1Client::connect(grpc_endpoint())
        .await
        .expect("Export service connection should succeed");
}

// ── DataPlane RPCs: all return UNIMPLEMENTED in Crux Daemon ────

#[tokio::test]
async fn append_batch_returns_unimplemented() {
    let mut client = CoreCruxDataPlaneV1Client::connect(grpc_endpoint())
        .await
        .expect("connect");

    let status = client
        .append_batch(tonic::Request::new(AppendBatchRequest {
            tenant_id: "test".into(),
            stream_type: "test".into(),
            stream_id: "s1".into(),
            events: vec![AppendEvent {
                event_id: "e1".into(),
                occurred_at: "2026-04-07T00:00:00Z".into(),
                event_type: "test".into(),
                content_type: "text/plain".into(),
                payload: b"hello".to_vec(),
            }],
            expected_next_seq: 0,
            client_shard_map_version: None,
        }))
        .await
        .expect_err("should be unimplemented");

    assert_eq!(status.code(), tonic::Code::Unimplemented);
    assert!(
        status.message().contains("proprietary"),
        "error message should mention proprietary edition: {}",
        status.message()
    );
}

#[tokio::test]
async fn read_stream_returns_unimplemented() {
    let mut client = CoreCruxDataPlaneV1Client::connect(grpc_endpoint())
        .await
        .expect("connect");

    let status = client
        .read_stream(tonic::Request::new(ReadStreamRequest {
            tenant_id: "test".into(),
            stream_type: "test".into(),
            stream_id: "s1".into(),
            ..Default::default()
        }))
        .await
        .expect_err("should be unimplemented");

    assert_eq!(status.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn read_stream_batched_returns_unimplemented() {
    let mut client = CoreCruxDataPlaneV1Client::connect(grpc_endpoint())
        .await
        .expect("connect");

    let status = client
        .read_stream_batched(tonic::Request::new(ReadStreamBatchedRequest {
            base: Some(ReadStreamRequest {
                tenant_id: "test".into(),
                stream_type: "test".into(),
                stream_id: "s1".into(),
                ..Default::default()
            }),
            max_events_per_message: 100,
            max_bytes_per_message: 0,
        }))
        .await
        .expect_err("should be unimplemented");

    assert_eq!(status.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn read_stream_batched_unary_returns_unimplemented() {
    let mut client = CoreCruxDataPlaneV1Client::connect(grpc_endpoint())
        .await
        .expect("connect");

    let status = client
        .read_stream_batched_unary(tonic::Request::new(ReadStreamBatchedRequest {
            base: Some(ReadStreamRequest {
                tenant_id: "test".into(),
                stream_type: "test".into(),
                stream_id: "s1".into(),
                ..Default::default()
            }),
            max_events_per_message: 100,
            max_bytes_per_message: 0,
        }))
        .await
        .expect_err("should be unimplemented");

    assert_eq!(status.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn read_many_batched_unary_returns_unimplemented() {
    let mut client = CoreCruxDataPlaneV1Client::connect(grpc_endpoint())
        .await
        .expect("connect");

    let status = client
        .read_many_batched_unary(tonic::Request::new(ReadManyBatchedRequest { reads: vec![] }))
        .await
        .expect_err("should be unimplemented");

    assert_eq!(status.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn read_many_frames_batched_unary_returns_unimplemented() {
    let mut client = CoreCruxDataPlaneV1Client::connect(grpc_endpoint())
        .await
        .expect("connect");

    let status = client
        .read_many_frames_batched_unary(tonic::Request::new(ReadManyFramesBatchedRequest { reads: vec![] }))
        .await
        .expect_err("should be unimplemented");

    assert_eq!(status.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn read_frames_batched_unary_returns_unimplemented() {
    let mut client = CoreCruxDataPlaneV1Client::connect(grpc_endpoint())
        .await
        .expect("connect");

    let status = client
        .read_frames_batched_unary(tonic::Request::new(ReadStreamBatchedRequest {
            base: None,
            max_events_per_message: 0,
            max_bytes_per_message: 0,
        }))
        .await
        .expect_err("should be unimplemented");

    assert_eq!(status.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn replay_session_returns_unimplemented() {
    let mut client = CoreCruxDataPlaneV1Client::connect(grpc_endpoint())
        .await
        .expect("connect");

    let request_stream = tokio_stream::once(ReplaySessionRequest {
        request_id: 1,
        request: None,
    });

    let status = client
        .replay_session(tonic::Request::new(request_stream))
        .await
        .expect_err("should be unimplemented");

    assert_eq!(status.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn read_frames_returns_unimplemented() {
    let mut client = CoreCruxDataPlaneV1Client::connect(grpc_endpoint())
        .await
        .expect("connect");

    let status = client
        .read_frames(tonic::Request::new(ReadFramesRequest { locations: vec![] }))
        .await
        .expect_err("should be unimplemented");

    assert_eq!(status.code(), tonic::Code::Unimplemented);
}

// ── Export service: returns UNIMPLEMENTED ────────────────────────────

#[tokio::test]
async fn export_receipt_bundle_returns_unimplemented() {
    let mut client = CoreCruxExportV1Client::connect(grpc_endpoint()).await.expect("connect");

    let status = client
        .export_receipt_bundle(tonic::Request::new(ExportReceiptBundleRequest {
            receipt_id: "rcpt_nonexistent".into(),
            ..Default::default()
        }))
        .await
        .expect_err("should be unimplemented");

    assert_eq!(status.code(), tonic::Code::Unimplemented);
}

// ── Error message consistency ───────────────────────────────────────

#[tokio::test]
async fn unimplemented_messages_mention_proprietary_edition() {
    let mut client = CoreCruxDataPlaneV1Client::connect(grpc_endpoint())
        .await
        .expect("connect");

    // Sample several RPCs and verify consistent messaging.
    let rpcs: Vec<(&str, tonic::Code, String)> = vec![(
        "AppendBatch",
        client
            .append_batch(tonic::Request::new(AppendBatchRequest {
                tenant_id: "t".into(),
                stream_type: "t".into(),
                stream_id: "s".into(),
                events: vec![],
                expected_next_seq: 0,
                client_shard_map_version: None,
            }))
            .await
            .unwrap_err()
            .code(),
        client
            .append_batch(tonic::Request::new(AppendBatchRequest {
                tenant_id: "t".into(),
                stream_type: "t".into(),
                stream_id: "s".into(),
                events: vec![],
                expected_next_seq: 0,
                client_shard_map_version: None,
            }))
            .await
            .unwrap_err()
            .message()
            .to_string(),
    )];

    for (name, code, msg) in &rpcs {
        assert_eq!(*code, tonic::Code::Unimplemented, "{name} should return Unimplemented");
        assert!(
            msg.contains("proprietary"),
            "{name} error should mention 'proprietary': {msg}"
        );
    }
}
