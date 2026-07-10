// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Admin client — wraps `/v1/admin/*` HTTP routes for `corecruxctl admin` subcommands.

use serde::Serialize;

#[derive(Debug)]
pub struct AdminClient {
    base: String,
}

impl AdminClient {
    pub fn new(base: &str) -> Self {
        let base = base.trim_end_matches('/').to_string();
        Self { base }
    }

    fn url(&self, path: &str) -> String {
        let path = path.trim_start_matches('/');
        format!("{}/{}", self.base, path)
    }

    pub fn get_control(&self) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.url("/v1/admin/control");
        let text = ureq::get(&url).call()?.into_body().read_to_string()?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn set_valves(
        &self,
        req: SetValvesReq<'_>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.url("/v1/admin/valves");
        let body = serde_json::to_value(req)?;
        let text = ureq::post(&url).send_json(body)?.into_body().read_to_string()?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn update_stream_meta(
        &self,
        req: StreamMetaReq<'_>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.url("/v1/admin/stream-meta");
        let body = serde_json::to_value(req)?;
        let text = ureq::post(&url).send_json(body)?.into_body().read_to_string()?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn submit_action(
        &self,
        req: SubmitActionReq<'_>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.url("/v1/admin/actions");
        let body = serde_json::to_value(req)?;
        let text = ureq::post(&url).send_json(body)?.into_body().read_to_string()?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn action_status(
        &self,
        action_id: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.url(&format!("/v1/admin/actions/{action_id}"));
        let text = ureq::get(&url).call()?.into_body().read_to_string()?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn ops_log(&self, query: OpsLogReq<'_>) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let mut req = ureq::get(&self.url("/v1/admin/ops-log"));
        if let Some(node_id) = query.node_id {
            req = req.query("nodeId", node_id);
        }
        if let Some(since) = query.since {
            req = req.query("since", since);
        }
        if let Some(until) = query.until {
            req = req.query("until", until);
        }
        if let Some(from_seq) = query.from_seq {
            req = req.query("fromSeq", from_seq.to_string());
        }
        if let Some(max_events) = query.max_events {
            req = req.query("maxEvents", max_events.to_string());
        }
        let text = req.call()?.into_body().read_to_string()?;
        Ok(serde_json::from_str(&text)?)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SetThrottleReq {
    pub enabled: bool,
    #[serde(rename = "retryAfterMs", skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u32>,
    #[serde(rename = "eventsPerSec", skip_serializing_if = "Option::is_none")]
    pub events_per_sec: Option<u64>,
    #[serde(rename = "bytesPerSec", skip_serializing_if = "Option::is_none")]
    pub bytes_per_sec: Option<u64>,
    #[serde(rename = "maxInFlight", skip_serializing_if = "Option::is_none")]
    pub max_in_flight: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetValvesReq<'a> {
    pub actor: &'a str,
    pub reason: &'a str,
    #[serde(rename = "pauseIngest", skip_serializing_if = "Option::is_none")]
    pub pause_ingest: Option<bool>,
    #[serde(rename = "pauseCompaction", skip_serializing_if = "Option::is_none")]
    pub pause_compaction: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttle: Option<SetThrottleReq>,
    #[serde(rename = "readOnly", skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    #[serde(rename = "emergencyBrake", skip_serializing_if = "Option::is_none")]
    pub emergency_brake: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamMetaReq<'a> {
    #[serde(rename = "tenantId")]
    pub tenant_id: &'a str,
    #[serde(rename = "streamType")]
    pub stream_type: &'a str,
    #[serde(rename = "streamId")]
    pub stream_id: &'a str,
    #[serde(rename = "minLiveSeq", skip_serializing_if = "Option::is_none")]
    pub min_live_seq: Option<u64>,
    #[serde(rename = "tombstoneSeq", skip_serializing_if = "Option::is_none")]
    pub tombstone_seq: Option<u64>,
    pub actor: &'a str,
    pub reason: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubmitActionReq<'a> {
    #[serde(rename = "actionId", skip_serializing_if = "Option::is_none")]
    pub action_id: Option<&'a str>,
    #[serde(rename = "actionType")]
    pub action_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy)]
pub struct OpsLogReq<'a> {
    pub node_id: Option<&'a str>,
    pub since: Option<&'a str>,
    pub until: Option<&'a str>,
    pub from_seq: Option<u64>,
    pub max_events: Option<u32>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn admin_client_url_strips_trailing_slash() {
        let client = AdminClient::new("http://localhost:14800/");
        assert_eq!(
            client.url("/v1/admin/control"),
            "http://localhost:14800/v1/admin/control"
        );
    }

    #[test]
    fn admin_client_url_no_trailing_slash() {
        let client = AdminClient::new("http://localhost:14800");
        assert_eq!(
            client.url("/v1/admin/control"),
            "http://localhost:14800/v1/admin/control"
        );
    }

    #[test]
    fn admin_client_url_strips_leading_slash_from_path() {
        let client = AdminClient::new("http://localhost:14800");
        // Both leading-slash and no-leading-slash should produce the same result
        let with_slash = client.url("/foo/bar");
        let without_slash = client.url("foo/bar");
        assert_eq!(with_slash, without_slash);
        assert_eq!(with_slash, "http://localhost:14800/foo/bar");
    }

    #[test]
    fn set_valves_req_serializes() {
        let req = SetValvesReq {
            actor: "admin",
            reason: "maintenance",
            pause_ingest: Some(true),
            pause_compaction: None,
            throttle: None,
            read_only: None,
            emergency_brake: Some(false),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["actor"], "admin");
        assert_eq!(json["reason"], "maintenance");
        assert_eq!(json["pauseIngest"], true);
        assert_eq!(json["emergencyBrake"], false);
        // None fields should be absent
        assert!(json.get("pauseCompaction").is_none());
        assert!(json.get("throttle").is_none());
        assert!(json.get("readOnly").is_none());
    }

    #[test]
    fn set_throttle_req_serializes() {
        let req = SetThrottleReq {
            enabled: true,
            retry_after_ms: Some(1000),
            events_per_sec: Some(500),
            bytes_per_sec: None,
            max_in_flight: Some(10),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["retryAfterMs"], 1000);
        assert_eq!(json["eventsPerSec"], 500);
        assert!(json.get("bytesPerSec").is_none());
        assert_eq!(json["maxInFlight"], 10);
    }

    #[test]
    fn stream_meta_req_serializes() {
        let req = StreamMetaReq {
            tenant_id: "t1",
            stream_type: "artifact",
            stream_id: "s1",
            min_live_seq: Some(100),
            tombstone_seq: None,
            actor: "admin",
            reason: "cleanup",
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["tenantId"], "t1");
        assert_eq!(json["streamType"], "artifact");
        assert_eq!(json["streamId"], "s1");
        assert_eq!(json["minLiveSeq"], 100);
        assert!(json.get("tombstoneSeq").is_none());
    }

    #[test]
    fn submit_action_req_serializes() {
        let req = SubmitActionReq {
            action_id: Some("act-1"),
            action_type: "compaction",
            actor: Some("cli"),
            reason: Some("manual trigger"),
            params: Some(serde_json::json!({"shard": 0})),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["actionId"], "act-1");
        assert_eq!(json["actionType"], "compaction");
        assert_eq!(json["actor"], "cli");
        assert_eq!(json["params"]["shard"], 0);
    }

    #[test]
    fn submit_action_req_omits_none_fields() {
        let req = SubmitActionReq {
            action_id: None,
            action_type: "seal",
            actor: None,
            reason: None,
            params: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("actionId").is_none());
        assert!(json.get("actor").is_none());
        assert!(json.get("reason").is_none());
        assert!(json.get("params").is_none());
        assert_eq!(json["actionType"], "seal");
    }

    // ── SetValvesReq: full serialization ────────────────────────────

    #[test]
    fn set_valves_req_with_throttle_serializes() {
        let req = SetValvesReq {
            actor: "ops",
            reason: "load test",
            pause_ingest: None,
            pause_compaction: Some(true),
            throttle: Some(SetThrottleReq {
                enabled: true,
                retry_after_ms: None,
                events_per_sec: Some(1000),
                bytes_per_sec: Some(1_000_000),
                max_in_flight: None,
            }),
            read_only: Some(false),
            emergency_brake: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["actor"], "ops");
        assert_eq!(json["reason"], "load test");
        assert!(json.get("pauseIngest").is_none());
        assert_eq!(json["pauseCompaction"], true);
        assert!(json["throttle"].is_object());
        assert_eq!(json["throttle"]["enabled"], true);
        assert_eq!(json["throttle"]["eventsPerSec"], 1000);
        assert_eq!(json["throttle"]["bytesPerSec"], 1_000_000);
        assert!(json["throttle"].get("retryAfterMs").is_none());
        assert!(json["throttle"].get("maxInFlight").is_none());
        assert_eq!(json["readOnly"], false);
        assert!(json.get("emergencyBrake").is_none());
    }

    // ── SetThrottleReq: all None fields ─────────────────────────────

    #[test]
    fn set_throttle_req_all_none_omits() {
        let req = SetThrottleReq {
            enabled: false,
            retry_after_ms: None,
            events_per_sec: None,
            bytes_per_sec: None,
            max_in_flight: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("retryAfterMs"));
        assert!(!json.contains("eventsPerSec"));
        assert!(!json.contains("bytesPerSec"));
        assert!(!json.contains("maxInFlight"));
        assert!(json.contains("\"enabled\":false"));
    }

    // ── StreamMetaReq: full fields ──────────────────────────────────

    #[test]
    fn stream_meta_req_full_fields() {
        let req = StreamMetaReq {
            tenant_id: "t1",
            stream_type: "knowledge",
            stream_id: "s1",
            min_live_seq: Some(100),
            tombstone_seq: Some(200),
            actor: "admin",
            reason: "cleanup",
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["tenantId"], "t1");
        assert_eq!(json["streamType"], "knowledge");
        assert_eq!(json["streamId"], "s1");
        assert_eq!(json["minLiveSeq"], 100);
        assert_eq!(json["tombstoneSeq"], 200);
        assert_eq!(json["actor"], "admin");
        assert_eq!(json["reason"], "cleanup");
    }

    // ── OpsLogReq: Debug impl ───────────────────────────────────────

    #[test]
    fn ops_log_req_debug() {
        let req = OpsLogReq {
            node_id: Some("node-1"),
            since: Some("2026-01-01"),
            until: None,
            from_seq: Some(42),
            max_events: Some(100),
        };
        let dbg = format!("{:?}", req);
        assert!(dbg.contains("node-1"));
        assert!(dbg.contains("42"));
    }

    // ── AdminClient: multiple trailing slashes ──────────────────────

    #[test]
    fn admin_client_url_multiple_path_components() {
        let client = AdminClient::new("http://host:1234///");
        // trim_end_matches '/' removes all trailing slashes
        assert_eq!(
            client.url("/v1/admin/actions/act-123"),
            "http://host:1234/v1/admin/actions/act-123"
        );
    }

    #[test]
    fn admin_client_url_empty_path() {
        let client = AdminClient::new("http://host:1234");
        let url = client.url("");
        assert_eq!(url, "http://host:1234/");
    }

    // ── AdminClient: base normalization ─────────────────────────────

    #[test]
    fn admin_client_preserves_port() {
        let client = AdminClient::new("http://10.0.0.1:14800");
        assert_eq!(
            client.url("/v1/admin/control"),
            "http://10.0.0.1:14800/v1/admin/control"
        );
    }

    #[test]
    fn admin_client_deep_base_path() {
        let client = AdminClient::new("http://host:1234/api/v2/");
        assert_eq!(client.url("/test"), "http://host:1234/api/v2/test");
    }

    // ── SetValvesReq: minimal (all None) ────────────────────────────

    #[test]
    fn set_valves_req_all_none_omits_optionals() {
        let req = SetValvesReq {
            actor: "a",
            reason: "r",
            pause_ingest: None,
            pause_compaction: None,
            throttle: None,
            read_only: None,
            emergency_brake: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"actor\":\"a\""));
        assert!(json.contains("\"reason\":\"r\""));
        assert!(!json.contains("pauseIngest"));
        assert!(!json.contains("pauseCompaction"));
        assert!(!json.contains("throttle"));
        assert!(!json.contains("readOnly"));
        assert!(!json.contains("emergencyBrake"));
    }

    // ── StreamMetaReq: both optional fields None ────────────────────

    #[test]
    fn stream_meta_req_no_optional_fields() {
        let req = StreamMetaReq {
            tenant_id: "t",
            stream_type: "s",
            stream_id: "i",
            min_live_seq: None,
            tombstone_seq: None,
            actor: "a",
            reason: "r",
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("minLiveSeq"));
        assert!(!json.contains("tombstoneSeq"));
    }

    // ── SubmitActionReq: all fields set ─────────────────────────────

    #[test]
    fn submit_action_req_all_fields_present() {
        let req = SubmitActionReq {
            action_id: Some("a1"),
            action_type: "seal",
            actor: Some("cli"),
            reason: Some("manual"),
            params: Some(serde_json::json!({"key": "value"})),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["actionId"], "a1");
        assert_eq!(json["actionType"], "seal");
        assert_eq!(json["actor"], "cli");
        assert_eq!(json["reason"], "manual");
        assert_eq!(json["params"]["key"], "value");
    }

    // ── SetThrottleReq: all fields set ──────────────────────────────

    #[test]
    fn set_throttle_req_all_fields_set() {
        let req = SetThrottleReq {
            enabled: true,
            retry_after_ms: Some(500),
            events_per_sec: Some(1000),
            bytes_per_sec: Some(1_000_000),
            max_in_flight: Some(50),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["retryAfterMs"], 500);
        assert_eq!(json["eventsPerSec"], 1000);
        assert_eq!(json["bytesPerSec"], 1_000_000);
        assert_eq!(json["maxInFlight"], 50);
    }

    // ── OpsLogReq: all None ─────────────────────────────────────────

    #[test]
    fn ops_log_req_all_none_debug() {
        let req = OpsLogReq {
            node_id: None,
            since: None,
            until: None,
            from_seq: None,
            max_events: None,
        };
        let dbg = format!("{:?}", req);
        assert!(dbg.contains("None"));
    }

    // ── AdminClient: Debug impl ─────────────────────────────────────

    #[test]
    fn admin_client_debug() {
        let client = AdminClient::new("http://localhost:14800");
        let dbg = format!("{:?}", client);
        assert!(dbg.contains("localhost:14800"));
    }

    // ── AdminClient: url edge cases ─────────────────────────────────

    #[test]
    fn admin_client_url_only_slashes() {
        let client = AdminClient::new("///");
        // trim_end_matches('/') removes all trailing slashes
        let url = client.url("test");
        assert!(url.ends_with("/test"));
    }

    // ── SetThrottleReq: round-trip serialization ────────────────────

    #[test]
    fn set_throttle_req_round_trip() {
        let req = SetThrottleReq {
            enabled: true,
            retry_after_ms: Some(2000),
            events_per_sec: Some(500),
            bytes_per_sec: Some(1_000_000),
            max_in_flight: Some(25),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["enabled"], true);
        assert_eq!(parsed["retryAfterMs"], 2000);
        assert_eq!(parsed["eventsPerSec"], 500);
        assert_eq!(parsed["bytesPerSec"], 1_000_000);
        assert_eq!(parsed["maxInFlight"], 25);
    }

    // ── SetValvesReq: all valves set ────────────────────────────────

    #[test]
    fn set_valves_req_all_fields_present() {
        let req = SetValvesReq {
            actor: "admin",
            reason: "deploy",
            pause_ingest: Some(true),
            pause_compaction: Some(false),
            throttle: Some(SetThrottleReq {
                enabled: false,
                retry_after_ms: None,
                events_per_sec: None,
                bytes_per_sec: None,
                max_in_flight: None,
            }),
            read_only: Some(true),
            emergency_brake: Some(false),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["actor"], "admin");
        assert_eq!(json["reason"], "deploy");
        assert_eq!(json["pauseIngest"], true);
        assert_eq!(json["pauseCompaction"], false);
        assert!(json["throttle"].is_object());
        assert_eq!(json["readOnly"], true);
        assert_eq!(json["emergencyBrake"], false);
    }

    // ── SubmitActionReq: with params object ─────────────────────────

    #[test]
    fn submit_action_req_nested_params() {
        let req = SubmitActionReq {
            action_id: Some("a-1"),
            action_type: "compaction",
            actor: Some("system"),
            reason: Some("periodic"),
            params: Some(serde_json::json!({
                "shard_id": 1,
                "force": true,
                "options": {"level": 2}
            })),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["params"]["shard_id"], 1);
        assert_eq!(json["params"]["force"], true);
        assert_eq!(json["params"]["options"]["level"], 2);
    }

    // ── OpsLogReq: all fields set ───────────────────────────────────

    #[test]
    fn ops_log_req_all_fields_debug() {
        let req = OpsLogReq {
            node_id: Some("n1"),
            since: Some("2026-01-01"),
            until: Some("2026-12-31"),
            from_seq: Some(100),
            max_events: Some(500),
        };
        let dbg = format!("{:?}", req);
        assert!(dbg.contains("n1"));
        assert!(dbg.contains("2026-01-01"));
        assert!(dbg.contains("2026-12-31"));
        assert!(dbg.contains("100"));
        assert!(dbg.contains("500"));
    }

    // ── StreamMetaReq: tombstone_seq set ────────────────────────────

    #[test]
    fn stream_meta_req_only_tombstone() {
        let req = StreamMetaReq {
            tenant_id: "t1",
            stream_type: "knowledge",
            stream_id: "s1",
            min_live_seq: None,
            tombstone_seq: Some(500),
            actor: "gc",
            reason: "ttl",
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("minLiveSeq").is_none());
        assert_eq!(json["tombstoneSeq"], 500);
    }

    // ── AdminClient: new stores base ────────────────────────────────

    #[test]
    fn admin_client_new_stores_trimmed_base() {
        let client = AdminClient::new("http://host:1234/path/");
        // The base should have trailing slash removed
        assert_eq!(client.url("test"), "http://host:1234/path/test");
    }

    // ── OpsLogReq: Clone ────────────────────────────────────────────

    #[test]
    fn ops_log_req_clone() {
        let req = OpsLogReq {
            node_id: Some("n1"),
            since: Some("2026-01-01"),
            until: Some("2026-12-31"),
            from_seq: Some(100),
            max_events: Some(500),
        };
        let cloned = req;
        assert_eq!(cloned.node_id, Some("n1"));
        assert_eq!(cloned.since, Some("2026-01-01"));
        assert_eq!(cloned.until, Some("2026-12-31"));
        assert_eq!(cloned.from_seq, Some(100));
        assert_eq!(cloned.max_events, Some(500));
    }

    // ── SetThrottleReq: Debug ───────────────────────────────────────

    #[test]
    fn set_throttle_req_debug() {
        let req = SetThrottleReq {
            enabled: true,
            retry_after_ms: Some(100),
            events_per_sec: None,
            bytes_per_sec: None,
            max_in_flight: None,
        };
        let dbg = format!("{:?}", req);
        assert!(dbg.contains("enabled"));
        assert!(dbg.contains("100"));
    }

    // ── SetValvesReq: Clone ─────────────────────────────────────────

    #[test]
    fn set_valves_req_clone() {
        let req = SetValvesReq {
            actor: "admin",
            reason: "test",
            pause_ingest: Some(true),
            pause_compaction: None,
            throttle: None,
            read_only: None,
            emergency_brake: None,
        };
        let cloned = req.clone();
        assert_eq!(cloned.actor, "admin");
        assert_eq!(cloned.pause_ingest, Some(true));
    }

    // ── StreamMetaReq: Debug ────────────────────────────────────────

    #[test]
    fn stream_meta_req_debug() {
        let req = StreamMetaReq {
            tenant_id: "t1",
            stream_type: "artifact",
            stream_id: "s1",
            min_live_seq: Some(100),
            tombstone_seq: None,
            actor: "admin",
            reason: "cleanup",
        };
        let dbg = format!("{:?}", req);
        assert!(dbg.contains("t1"));
        assert!(dbg.contains("artifact"));
    }

    // ── SubmitActionReq: Debug ──────────────────────────────────────

    #[test]
    fn submit_action_req_debug() {
        let req = SubmitActionReq {
            action_id: Some("a1"),
            action_type: "seal",
            actor: None,
            reason: None,
            params: None,
        };
        let dbg = format!("{:?}", req);
        assert!(dbg.contains("seal"));
    }

    // ── AdminClient: url with query-like path ───────────────────────

    #[test]
    fn admin_client_url_with_query_params() {
        let client = AdminClient::new("http://localhost:14800");
        let url = client.url("/v1/admin/ops-log?nodeId=node-1");
        assert_eq!(url, "http://localhost:14800/v1/admin/ops-log?nodeId=node-1");
    }

    // ── SetThrottleReq: partial fields serialization ────────────────

    #[test]
    fn set_throttle_req_partial_fields() {
        let req = SetThrottleReq {
            enabled: true,
            retry_after_ms: None,
            events_per_sec: Some(100),
            bytes_per_sec: None,
            max_in_flight: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["eventsPerSec"], 100);
        assert!(json.get("retryAfterMs").is_none());
        assert!(json.get("bytesPerSec").is_none());
        assert!(json.get("maxInFlight").is_none());
    }

    // ── SubmitActionReq: round-trip serialization ───────────────────

    #[test]
    fn submit_action_req_round_trip() {
        let req = SubmitActionReq {
            action_id: Some("act-42"),
            action_type: "compaction",
            actor: Some("system"),
            reason: Some("periodic"),
            params: Some(serde_json::json!({"force": true})),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["actionId"], "act-42");
        assert_eq!(parsed["actionType"], "compaction");
        assert_eq!(parsed["params"]["force"], true);
    }
}
