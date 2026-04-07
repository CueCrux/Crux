// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::str::FromStr;

use corecrux_proto::dataplane_v1::{
    append_result, core_crux_data_plane_v1_client::CoreCruxDataPlaneV1Client, AppendBatchRequest, AppendEvent,
};
use corecrux_types::OPS_EVIDENCE_CONTENT_TYPE_V1;
use serde::Serialize;
use tonic::metadata::MetadataValue;

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone)]
pub struct OpsAppendOptions {
    pub grpc: String,
    pub scopes: Option<String>,
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpsAppendReceipt {
    #[serde(rename = "commitSeq", skip_serializing_if = "Option::is_none")]
    pub commit_seq: Option<u64>,
    #[serde(rename = "segmentId", skip_serializing_if = "Option::is_none")]
    pub segment_id: Option<u64>,
    #[serde(rename = "unsigned", skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<bool>,
    #[serde(rename = "keyId", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

pub fn append_ops_event<T: Serialize>(
    opts: &OpsAppendOptions,
    event_type: &str,
    event_id: &str,
    payload: &T,
) -> Result<OpsAppendReceipt, DynError> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;

    rt.block_on(async {
        let payload_bytes = serde_json::to_vec(payload)?;
        let mut client = CoreCruxDataPlaneV1Client::connect(opts.grpc.clone()).await?;
        let request = AppendBatchRequest {
            tenant_id: "system".to_string(),
            stream_type: "__ops__".to_string(),
            stream_id: opts.node_id.clone(),
            events: vec![AppendEvent {
                event_id: event_id.to_string(),
                occurred_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                event_type: event_type.to_string(),
                content_type: OPS_EVIDENCE_CONTENT_TYPE_V1.to_string(),
                payload: payload_bytes,
            }],
            expected_next_seq: 0,
            client_shard_map_version: None,
        };
        let mut request = tonic::Request::new(request);
        maybe_set_scopes(&mut request, opts.scopes.as_deref())?;

        let response = client.append_batch(request).await?.into_inner();
        for result in &response.results {
            let status = append_result::Status::try_from(result.status).unwrap_or(append_result::Status::Rejected);
            if status == append_result::Status::Rejected {
                let code = result.error_code.trim();
                let message = result.error_message.trim();
                let detail = if code.is_empty() && message.is_empty() {
                    "append rejected".to_string()
                } else if code.is_empty() {
                    message.to_string()
                } else if message.is_empty() {
                    code.to_string()
                } else {
                    format!("{code}: {message}")
                };
                return Err(detail.into());
            }
        }

        Ok(OpsAppendReceipt {
            commit_seq: response.write_confirmation.as_ref().map(|value| value.commit_seq),
            segment_id: response.write_confirmation.as_ref().map(|value| value.segment_id),
            unsigned: response.write_confirmation.as_ref().map(|value| value.unsigned),
            key_id: response.write_confirmation.and_then(|value| {
                let trimmed = value.key_id.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }),
        })
    })
}

fn maybe_set_scopes<T>(request: &mut tonic::Request<T>, scopes: Option<&str>) -> Result<(), DynError> {
    if let Some(scopes) = scopes {
        let value = MetadataValue::from_str(scopes).map_err(|err| format!("invalid scopes metadata value: {err}"))?;
        request.metadata_mut().insert("x-corecrux-scopes", value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_append_receipt_serializes_full() {
        let receipt = OpsAppendReceipt {
            commit_seq: Some(42),
            segment_id: Some(7),
            unsigned: Some(false),
            key_id: Some("key-1".to_string()),
        };
        let json = serde_json::to_value(&receipt).unwrap();
        assert_eq!(json["commitSeq"], 42);
        assert_eq!(json["segmentId"], 7);
        assert_eq!(json["unsigned"], false);
        assert_eq!(json["keyId"], "key-1");
    }

    #[test]
    fn ops_append_receipt_omits_none_fields() {
        let receipt = OpsAppendReceipt {
            commit_seq: None,
            segment_id: None,
            unsigned: None,
            key_id: None,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("commitSeq"));
        assert!(!json.contains("segmentId"));
        assert!(!json.contains("unsigned"));
        assert!(!json.contains("keyId"));
    }

    #[test]
    fn maybe_set_scopes_none_is_noop() {
        let mut req = tonic::Request::new(());
        maybe_set_scopes(&mut req, None).unwrap();
        assert!(req.metadata().get("x-corecrux-scopes").is_none());
    }

    #[test]
    fn maybe_set_scopes_sets_header() {
        let mut req = tonic::Request::new(());
        maybe_set_scopes(&mut req, Some("read,write")).unwrap();
        let val = req.metadata().get("x-corecrux-scopes").unwrap();
        assert_eq!(val.to_str().unwrap(), "read,write");
    }

    #[test]
    fn ops_append_options_debug() {
        let opts = OpsAppendOptions {
            grpc: "http://localhost:50051".to_string(),
            scopes: Some("admin".to_string()),
            node_id: "node-1".to_string(),
        };
        let dbg = format!("{:?}", opts);
        assert!(dbg.contains("node-1"));
        assert!(dbg.contains("admin"));
    }

    #[test]
    fn ops_append_receipt_serializes_partial_fields() {
        let receipt = OpsAppendReceipt {
            commit_seq: Some(10),
            segment_id: None,
            unsigned: Some(true),
            key_id: None,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"commitSeq\":10"));
        assert!(json.contains("\"unsigned\":true"));
        assert!(!json.contains("segmentId"));
        assert!(!json.contains("keyId"));
    }

    #[test]
    fn ops_append_options_clone() {
        let opts = OpsAppendOptions {
            grpc: "http://localhost:50051".to_string(),
            scopes: None,
            node_id: "node-2".to_string(),
        };
        let cloned = opts.clone();
        assert_eq!(cloned.grpc, "http://localhost:50051");
        assert!(cloned.scopes.is_none());
        assert_eq!(cloned.node_id, "node-2");
    }

    #[test]
    fn maybe_set_scopes_empty_string_sets_header() {
        let mut req = tonic::Request::new(());
        maybe_set_scopes(&mut req, Some("")).unwrap();
        let val = req.metadata().get("x-corecrux-scopes").unwrap();
        assert_eq!(val.to_str().unwrap(), "");
    }

    #[test]
    fn ops_append_receipt_full_json_keys_present() {
        let receipt = OpsAppendReceipt {
            commit_seq: Some(1),
            segment_id: Some(2),
            unsigned: Some(false),
            key_id: Some("k1".to_string()),
        };
        let json = serde_json::to_value(&receipt).unwrap();
        assert!(json.get("commitSeq").is_some());
        assert!(json.get("segmentId").is_some());
        assert!(json.get("unsigned").is_some());
        assert!(json.get("keyId").is_some());
    }

    #[test]
    fn ops_append_receipt_empty_is_empty_json_object() {
        let receipt = OpsAppendReceipt {
            commit_seq: None,
            segment_id: None,
            unsigned: None,
            key_id: None,
        };
        let json = serde_json::to_value(&receipt).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.is_empty());
    }

    // ── maybe_set_scopes: whitespace value ──────────────────────────

    #[test]
    fn maybe_set_scopes_whitespace_sets_header() {
        let mut req = tonic::Request::new(());
        maybe_set_scopes(&mut req, Some("  read  ")).unwrap();
        let val = req.metadata().get("x-corecrux-scopes").unwrap();
        assert_eq!(val.to_str().unwrap(), "  read  ");
    }

    // ── OpsAppendOptions: scopes None ───────────────────────────────

    #[test]
    fn ops_append_options_no_scopes_debug() {
        let opts = OpsAppendOptions {
            grpc: "http://localhost:50051".to_string(),
            scopes: None,
            node_id: "node-x".to_string(),
        };
        let dbg = format!("{:?}", opts);
        assert!(dbg.contains("None"));
        assert!(dbg.contains("node-x"));
    }

    // ── OpsAppendReceipt: selective fields ──────────────────────────

    #[test]
    fn ops_append_receipt_only_unsigned() {
        let receipt = OpsAppendReceipt {
            commit_seq: None,
            segment_id: None,
            unsigned: Some(true),
            key_id: None,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"unsigned\":true"));
        assert!(!json.contains("commitSeq"));
        assert!(!json.contains("segmentId"));
        assert!(!json.contains("keyId"));
    }

    #[test]
    fn ops_append_receipt_only_key_id() {
        let receipt = OpsAppendReceipt {
            commit_seq: None,
            segment_id: None,
            unsigned: None,
            key_id: Some("my-key".to_string()),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"keyId\":\"my-key\""));
        assert!(!json.contains("commitSeq"));
    }

    // ── maybe_set_scopes: multiple calls ────────────────────────────

    // ── OpsAppendReceipt: deserialization round-trip ───────────────────

    #[test]
    fn ops_append_receipt_round_trip() {
        let receipt = OpsAppendReceipt {
            commit_seq: Some(42),
            segment_id: Some(7),
            unsigned: Some(true),
            key_id: Some("k-abc".to_string()),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["commitSeq"], 42);
        assert_eq!(parsed["segmentId"], 7);
        assert_eq!(parsed["unsigned"], true);
        assert_eq!(parsed["keyId"], "k-abc");
    }

    // ── OpsAppendOptions: all fields ────────────────────────────────

    #[test]
    fn ops_append_options_with_scopes_clone() {
        let opts = OpsAppendOptions {
            grpc: "http://example:50051".to_string(),
            scopes: Some("admin:read,admin:write".to_string()),
            node_id: "node-42".to_string(),
        };
        let cloned = opts.clone();
        assert_eq!(cloned.grpc, "http://example:50051");
        assert_eq!(cloned.scopes.as_deref(), Some("admin:read,admin:write"));
        assert_eq!(cloned.node_id, "node-42");
    }

    // ── maybe_set_scopes: comma-separated values ────────────────────

    #[test]
    fn maybe_set_scopes_comma_separated() {
        let mut req = tonic::Request::new(());
        maybe_set_scopes(&mut req, Some("read,write,admin")).unwrap();
        let val = req.metadata().get("x-corecrux-scopes").unwrap();
        assert_eq!(val.to_str().unwrap(), "read,write,admin");
    }

    #[test]
    fn maybe_set_scopes_overwrites_on_second_call() {
        let mut req = tonic::Request::new(());
        maybe_set_scopes(&mut req, Some("read")).unwrap();
        maybe_set_scopes(&mut req, Some("write")).unwrap();
        // tonic insert overwrites
        let val = req.metadata().get("x-corecrux-scopes").unwrap();
        assert_eq!(val.to_str().unwrap(), "write");
    }

    // ── OpsAppendReceipt: deserialize from JSON ──────────────────────

    #[test]
    fn ops_append_receipt_deserialize_from_json() {
        let json = r#"{"commitSeq":10,"segmentId":3,"unsigned":false,"keyId":"k1"}"#;
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(parsed["commitSeq"], 10);
        assert_eq!(parsed["keyId"], "k1");
    }

    // ── OpsAppendReceipt: only segment_id ────────────────────────────

    #[test]
    fn ops_append_receipt_only_segment_id() {
        let receipt = OpsAppendReceipt {
            commit_seq: None,
            segment_id: Some(99),
            unsigned: None,
            key_id: None,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"segmentId\":99"));
        assert!(!json.contains("commitSeq"));
        assert!(!json.contains("unsigned"));
        assert!(!json.contains("keyId"));
    }

    // ── OpsAppendOptions: fields accessible ──────────────────────────

    #[test]
    fn ops_append_options_field_access() {
        let opts = OpsAppendOptions {
            grpc: "http://host:50051".to_string(),
            scopes: Some("read".to_string()),
            node_id: "node-1".to_string(),
        };
        assert_eq!(opts.grpc, "http://host:50051");
        assert_eq!(opts.scopes.as_deref(), Some("read"));
        assert_eq!(opts.node_id, "node-1");
    }

    // ── OpsAppendReceipt: large values ───────────────────────────────

    #[test]
    fn ops_append_receipt_large_values() {
        let receipt = OpsAppendReceipt {
            commit_seq: Some(u64::MAX),
            segment_id: Some(u64::MAX),
            unsigned: Some(true),
            key_id: Some("very-long-key-id-abc-123-xyz-789".to_string()),
        };
        let json = serde_json::to_value(&receipt).unwrap();
        assert_eq!(json["commitSeq"], u64::MAX);
        assert_eq!(json["segmentId"], u64::MAX);
    }

    // ── maybe_set_scopes: special characters ─────────────────────────

    #[test]
    fn maybe_set_scopes_alphanumeric_with_colons() {
        let mut req = tonic::Request::new(());
        maybe_set_scopes(&mut req, Some("admin:read:write")).unwrap();
        let val = req.metadata().get("x-corecrux-scopes").unwrap();
        assert_eq!(val.to_str().unwrap(), "admin:read:write");
    }
}
