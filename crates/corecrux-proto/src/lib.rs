// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecrux-proto` — Protocol buffer definitions for the CoreCrux gRPC data plane.
//!
//! This crate contains auto-generated Rust types from the `.proto` files in `proto/`.
//! It uses `tonic` for gRPC code generation and `prost` for message serialisation.
//!
//! ## Modules
//!
//! - [`dataplane_v1`] — Append, read, replay, and export RPCs. This is the primary
//!   data plane used by `corecruxd` for high-throughput event ingestion.
//! - [`observe_v1`] — Observability and health-check RPCs.
//!
//! Proto source files live in `proto/` at the repository root. Regenerate with
//! `cargo build` (the build script runs `tonic-build` automatically).

pub mod dataplane_v1 {
    tonic::include_proto!("corecrux.dataplane.v1");
}

pub mod observe_v1 {
    tonic::include_proto!("corecrux.observe.v1");
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::dataplane_v1;

    #[test]
    fn append_batch_roundtrip_preserves_fields() {
        let req = dataplane_v1::AppendBatchRequest {
            tenant_id: "tenant-1".to_string(),
            stream_type: "answers".to_string(),
            stream_id: "stream-42".to_string(),
            events: vec![dataplane_v1::AppendEvent {
                event_id: "evt-1".to_string(),
                occurred_at: "2026-02-21T00:00:00Z".to_string(),
                event_type: "answer.created".to_string(),
                content_type: "application/json".to_string(),
                payload: br#"{"ok":true}"#.to_vec(),
            }],
            expected_next_seq: 7,
            client_shard_map_version: Some(3),
        };

        let mut buf = Vec::new();
        req.encode(&mut buf).expect("encode append batch");
        let decoded = dataplane_v1::AppendBatchRequest::decode(buf.as_slice()).expect("decode append batch");

        assert_eq!(decoded.stream_id, "stream-42");
        assert_eq!(decoded.expected_next_seq, 7);
        assert_eq!(decoded.client_shard_map_version, Some(3));
        assert_eq!(decoded.events.len(), 1);
        assert_eq!(decoded.events[0].payload, br#"{"ok":true}"#.to_vec());
    }

    #[test]
    fn status_enum_and_replay_oneof_wire_correctly() {
        let status = dataplane_v1::append_result::Status::Appended;
        let result = dataplane_v1::AppendResult {
            status: status as i32,
            seq: 11,
            location: Some(dataplane_v1::FrameLocation {
                shard_id: 1,
                segment_id: 2,
                offset: 3,
                epoch: 4,
            }),
            payload_hash: vec![0xaa; 32],
            header_hash: vec![0xbb; 32],
            shard_map_version: 3,
            error_code: String::new(),
            error_message: String::new(),
        };
        let status_back = dataplane_v1::append_result::Status::try_from(result.status).expect("status enum conversion");
        assert_eq!(status_back, dataplane_v1::append_result::Status::Appended);

        let replay_req = dataplane_v1::ReplaySessionRequest {
            request_id: 9,
            request: Some(dataplane_v1::replay_session_request::Request::DecodedReads(
                dataplane_v1::ReadManyBatchedRequest { reads: vec![] },
            )),
        };
        let mut buf = Vec::new();
        replay_req.encode(&mut buf).expect("encode replay request");
        let decoded = dataplane_v1::ReplaySessionRequest::decode(buf.as_slice()).expect("decode replay request");

        assert!(matches!(
            decoded.request,
            Some(dataplane_v1::replay_session_request::Request::DecodedReads(_))
        ));
    }
}
