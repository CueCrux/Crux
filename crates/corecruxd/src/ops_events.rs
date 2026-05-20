// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Self-observation event helpers — builds `corecrux.ops.*.v1` events for the daemon's own state changes.

use corecrux_proto::dataplane_v1::AppendEvent;
use corecrux_types::{BuildInfo, EvidenceNodeContextV1, OPS_EVIDENCE_CONTENT_TYPE_V1};

use crate::dataplane_store::AppendError;
use crate::pool::DataPlanePool;

pub fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn build_node_context(
    build: &BuildInfo,
    node_id: &str,
    http_listen_addr: Option<String>,
    grpc_listen_addr: Option<String>,
) -> EvidenceNodeContextV1 {
    EvidenceNodeContextV1 {
        node_id: node_id.to_string(),
        build: build.clone(),
        http_listen_addr,
        grpc_listen_addr,
    }
}

pub async fn append_ops_event<T: serde::Serialize>(
    pool: &DataPlanePool,
    node_id: &str,
    event_type: &str,
    event_id: String,
    payload: &T,
) -> Result<(), AppendError> {
    let payload_bytes = serde_json::to_vec(payload).unwrap_or_default();
    let event = AppendEvent {
        event_id,
        occurred_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        event_type: event_type.to_string(),
        content_type: OPS_EVIDENCE_CONTENT_TYPE_V1.to_string(),
        payload: payload_bytes,
    };

    let (_decision, store) = pool.store_for_stream("system", "__ops__", node_id, None).await?;
    let store = store.read().await;
    let _ = store
        .append_batch("system", "__ops__", node_id, 0, None, &[event])
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use corecrux_types::BuildInfo;

    use super::*;

    #[test]
    fn now_unix_ms_returns_plausible_value() {
        let ms = now_unix_ms();
        // Should be after 2020-01-01 in milliseconds
        assert!(ms > 1_577_836_800_000);
    }

    #[test]
    fn now_unix_ms_is_monotonic() {
        let a = now_unix_ms();
        let b = now_unix_ms();
        assert!(b >= a);
    }

    #[test]
    fn build_node_context_populates_all_fields() {
        let build = BuildInfo {
            version: "1.2.3".to_string(),
            commit: "abc123".to_string(),
        };
        let ctx = build_node_context(&build, "node-42", Some("0.0.0.0:14800".to_string()), None);
        assert_eq!(ctx.node_id, "node-42");
        assert_eq!(ctx.build.version, "1.2.3");
        assert_eq!(ctx.build.commit, "abc123");
        assert_eq!(ctx.http_listen_addr.as_deref(), Some("0.0.0.0:14800"));
        assert!(ctx.grpc_listen_addr.is_none());
    }

    #[test]
    fn build_node_context_with_both_addrs() {
        let build = BuildInfo {
            version: "0.1.0".to_string(),
            commit: "def456".to_string(),
        };
        let ctx = build_node_context(
            &build,
            "node-1",
            Some("0.0.0.0:14800".to_string()),
            Some("0.0.0.0:14801".to_string()),
        );
        assert_eq!(ctx.http_listen_addr.as_deref(), Some("0.0.0.0:14800"));
        assert_eq!(ctx.grpc_listen_addr.as_deref(), Some("0.0.0.0:14801"));
    }

    #[test]
    fn build_node_context_with_no_addrs() {
        let build = BuildInfo {
            version: "0.0.0".to_string(),
            commit: "000000".to_string(),
        };
        let ctx = build_node_context(&build, "node-0", None, None);
        assert!(ctx.http_listen_addr.is_none());
        assert!(ctx.grpc_listen_addr.is_none());
    }

    #[test]
    fn build_node_context_preserves_build_info_clone() {
        let build = BuildInfo {
            version: "2.0.0".to_string(),
            commit: "abcdef".to_string(),
        };
        let ctx = build_node_context(&build, "n", None, None);
        // build info should be cloned, not moved
        assert_eq!(build.version, "2.0.0");
        assert_eq!(ctx.build.version, "2.0.0");
        assert_eq!(ctx.build.commit, "abcdef");
    }

    #[test]
    fn build_node_context_empty_node_id() {
        let build = BuildInfo {
            version: "1.0.0".to_string(),
            commit: "abc".to_string(),
        };
        let ctx = build_node_context(&build, "", Some("http".to_string()), Some("grpc".to_string()));
        assert_eq!(ctx.node_id, "");
        assert_eq!(ctx.http_listen_addr.as_deref(), Some("http"));
        assert_eq!(ctx.grpc_listen_addr.as_deref(), Some("grpc"));
    }

    #[test]
    fn now_unix_ms_after_2025() {
        let ms = now_unix_ms();
        // Should be after 2025-01-01 in milliseconds
        assert!(ms > 1_735_689_600_000);
    }

    #[test]
    fn now_unix_ms_precision_within_second() {
        let ms1 = now_unix_ms();
        let ms2 = now_unix_ms();
        // Two consecutive calls should differ by less than 1 second
        assert!(ms2 - ms1 < 1000);
    }

    #[test]
    fn build_node_context_clone_preserves_original() {
        let build = BuildInfo {
            version: "3.0.0".to_string(),
            commit: "xyz789".to_string(),
        };
        let _ctx = build_node_context(&build, "n1", None, None);
        // Original should not be consumed
        assert_eq!(build.version, "3.0.0");
        assert_eq!(build.commit, "xyz789");
    }

    #[test]
    fn build_node_context_long_node_id() {
        let build = BuildInfo {
            version: "1.0.0".to_string(),
            commit: "abc".to_string(),
        };
        let long_id = "a".repeat(1000);
        let ctx = build_node_context(&build, &long_id, None, None);
        assert_eq!(ctx.node_id.len(), 1000);
    }

    #[test]
    fn build_node_context_special_chars_in_addrs() {
        let build = BuildInfo {
            version: "1.0.0".to_string(),
            commit: "abc".to_string(),
        };
        let ctx = build_node_context(
            &build,
            "node-1",
            Some("0.0.0.0:14800/path?q=1".to_string()),
            Some("[::1]:50051".to_string()),
        );
        assert_eq!(ctx.http_listen_addr.as_deref(), Some("0.0.0.0:14800/path?q=1"));
        assert_eq!(ctx.grpc_listen_addr.as_deref(), Some("[::1]:50051"));
    }
}
