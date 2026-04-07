// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! gRPC smoke tests for CoreCrux Community Edition.
//!
//! These tests verify that the gRPC server is listening and that CUDA-gated
//! RPCs correctly return `UNIMPLEMENTED` in Community Edition builds.

use std::sync::OnceLock;

use corecrux_proto::dataplane_v1::core_crux_data_plane_v1_client::CoreCruxDataPlaneV1Client;
use corecrux_proto::dataplane_v1::{AppendBatchRequest, AppendEvent};
use crux_integration_tests::TestDaemon;

fn daemon() -> &'static TestDaemon {
    static INSTANCE: OnceLock<TestDaemon> = OnceLock::new();
    INSTANCE.get_or_init(TestDaemon::start)
}

/// Verify the gRPC server is listening and accepts a connection.
#[tokio::test]
async fn grpc_connect() {
    let d = daemon();
    let endpoint = format!("http://127.0.0.1:{}", d.grpc_port);
    let _client = CoreCruxDataPlaneV1Client::connect(endpoint)
        .await
        .expect("gRPC connection should succeed");
}

/// In Community Edition (no CUDA), AppendBatch should return UNIMPLEMENTED.
#[tokio::test]
async fn append_batch_returns_unimplemented() {
    let d = daemon();
    let endpoint = format!("http://127.0.0.1:{}", d.grpc_port);
    let mut client = CoreCruxDataPlaneV1Client::connect(endpoint).await.expect("connect");

    let request = tonic::Request::new(AppendBatchRequest {
        tenant_id: "test-tenant".into(),
        stream_type: "test".into(),
        stream_id: "test-stream".into(),
        events: vec![AppendEvent {
            event_id: "evt-1".into(),
            occurred_at: "2026-04-06T00:00:00Z".into(),
            event_type: "test.event".into(),
            content_type: "text/plain".into(),
            payload: b"hello".to_vec(),
        }],
        expected_next_seq: 0,
        client_shard_map_version: None,
    });

    let status = client.append_batch(request).await.expect_err("should be unimplemented");

    assert_eq!(
        status.code(),
        tonic::Code::Unimplemented,
        "Community Edition should return UNIMPLEMENTED for AppendBatch"
    );
}

/// In Community Edition, ReadStream should return UNIMPLEMENTED.
#[tokio::test]
async fn read_stream_returns_unimplemented() {
    let d = daemon();
    let endpoint = format!("http://127.0.0.1:{}", d.grpc_port);
    let mut client = CoreCruxDataPlaneV1Client::connect(endpoint).await.expect("connect");

    let request = tonic::Request::new(corecrux_proto::dataplane_v1::ReadStreamRequest {
        tenant_id: "test-tenant".into(),
        stream_type: "test".into(),
        stream_id: "test-stream".into(),
        ..Default::default()
    });

    let status = client.read_stream(request).await.expect_err("should be unimplemented");

    assert_eq!(
        status.code(),
        tonic::Code::Unimplemented,
        "Community Edition should return UNIMPLEMENTED for ReadStream"
    );
}
