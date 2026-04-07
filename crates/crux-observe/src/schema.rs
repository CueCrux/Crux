// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Event type constants and structs for self-observation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Event type constants ────────────────────────────────────────────────────

pub const EVT_OPS_ERROR_V1: &str = "ops.error.v1";
pub const EVT_OPS_WARNING_V1: &str = "ops.warning.v1";
pub const EVT_OPS_METRIC_V1: &str = "ops.metric.v1";
pub const EVT_OPS_HEALTH_V1: &str = "ops.health.v1";
pub const EVT_OPS_QUERY_COVERAGE_V1: &str = "ops.query_coverage.v1";

pub const EVT_BOOTSTRAP_DOC_V1: &str = "bootstrap.doc.v1";
pub const EVT_BOOTSTRAP_PATTERN_V1: &str = "bootstrap.pattern.v1";
pub const EVT_BOOTSTRAP_RESOLUTION_V1: &str = "bootstrap.resolution.v1";

// ── Entity prefix constants ─────────────────────────────────────────────────

pub const OPS_PREFIX: &str = "__ops__::";
pub const BOOTSTRAP_PREFIX: &str = "__bootstrap__::";

// ── Helper functions ────────────────────────────────────────────────────────

/// Build an ops entity identifier: `__ops__::{kind}:{id}`.
pub fn ops_entity(kind: &str, id: &str) -> String {
    format!("{}{kind}:{id}", OPS_PREFIX)
}

/// Build a bootstrap entity identifier: `__bootstrap__::{kind}:{slug}`.
pub fn bootstrap_entity(kind: &str, slug: &str) -> String {
    format!("{}{kind}:{slug}", BOOTSTRAP_PREFIX)
}

// ── Ops event structs ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsErrorEvent {
    pub event_type: String,
    pub node_id: String,
    pub message: String,
    pub target: Option<String>,
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub fields: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsWarningEvent {
    pub event_type: String,
    pub node_id: String,
    pub message: String,
    pub target: Option<String>,
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub fields: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsMetricSnapshot {
    pub event_type: String,
    pub node_id: String,
    pub metric_name: String,
    pub value: f64,
    pub labels: Vec<(String, String)>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsHealthChange {
    pub event_type: String,
    pub node_id: String,
    pub component: String,
    pub status: String,
    pub previous_status: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsQueryCoverage {
    pub event_type: String,
    pub node_id: String,
    pub total_queries: u64,
    pub covered_queries: u64,
    pub coverage_ratio: f64,
    pub timestamp: DateTime<Utc>,
}

// ── Bootstrap event structs ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapDoc {
    pub event_type: String,
    pub slug: String,
    pub title: String,
    pub content: String,
    pub source_path: Option<String>,
    pub timestamp: DateTime<Utc>,
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_entity_formatting() {
        assert_eq!(ops_entity("error", "abc123"), "__ops__::error:abc123");
        assert_eq!(ops_entity("warning", "w1"), "__ops__::warning:w1");
    }

    #[test]
    fn bootstrap_entity_formatting() {
        assert_eq!(bootstrap_entity("doc", "readme"), "__bootstrap__::doc:readme");
    }

    #[test]
    fn serde_roundtrip_ops_error_event() {
        let evt = OpsErrorEvent {
            event_type: EVT_OPS_ERROR_V1.to_string(),
            node_id: "node-1".to_string(),
            message: "connection refused".to_string(),
            target: Some("corecrux_storage".to_string()),
            timestamp: Utc::now(),
            fields: serde_json::json!({"retry_count": 3}),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let roundtrip: OpsErrorEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.event_type, EVT_OPS_ERROR_V1);
        assert_eq!(roundtrip.message, "connection refused");
        assert_eq!(roundtrip.node_id, "node-1");
    }

    #[test]
    fn serde_roundtrip_ops_warning_event() {
        let evt = OpsWarningEvent {
            event_type: EVT_OPS_WARNING_V1.to_string(),
            node_id: "node-2".to_string(),
            message: "high latency detected".to_string(),
            target: None,
            timestamp: Utc::now(),
            fields: serde_json::Value::Null,
        };
        let json = serde_json::to_string(&evt).unwrap();
        let roundtrip: OpsWarningEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.event_type, EVT_OPS_WARNING_V1);
        assert_eq!(roundtrip.message, "high latency detected");
    }

    #[test]
    fn serde_roundtrip_ops_metric_snapshot() {
        let evt = OpsMetricSnapshot {
            event_type: EVT_OPS_METRIC_V1.to_string(),
            node_id: "node-1".to_string(),
            metric_name: "query_duration_seconds".to_string(),
            value: 0.042,
            labels: vec![("method".to_string(), "GET".to_string())],
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let roundtrip: OpsMetricSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.metric_name, "query_duration_seconds");
        assert!((roundtrip.value - 0.042).abs() < f64::EPSILON);
    }

    #[test]
    fn serde_roundtrip_ops_health_change() {
        let evt = OpsHealthChange {
            event_type: EVT_OPS_HEALTH_V1.to_string(),
            node_id: "node-1".to_string(),
            component: "shard_store".to_string(),
            status: "degraded".to_string(),
            previous_status: Some("healthy".to_string()),
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let roundtrip: OpsHealthChange = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.component, "shard_store");
        assert_eq!(roundtrip.status, "degraded");
        assert_eq!(roundtrip.previous_status.as_deref(), Some("healthy"));
    }

    #[test]
    fn serde_roundtrip_ops_query_coverage() {
        let evt = OpsQueryCoverage {
            event_type: EVT_OPS_QUERY_COVERAGE_V1.to_string(),
            node_id: "node-1".to_string(),
            total_queries: 1000,
            covered_queries: 950,
            coverage_ratio: 0.95,
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let roundtrip: OpsQueryCoverage = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.total_queries, 1000);
        assert!((roundtrip.coverage_ratio - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn serde_roundtrip_bootstrap_doc() {
        let evt = BootstrapDoc {
            event_type: EVT_BOOTSTRAP_DOC_V1.to_string(),
            slug: "readme".to_string(),
            title: "Project README".to_string(),
            content: "# CoreCrux\nSelf-observing event store.".to_string(),
            source_path: Some("README.md".to_string()),
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let roundtrip: BootstrapDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.slug, "readme");
        assert_eq!(roundtrip.title, "Project README");
        assert!(roundtrip.content.contains("CoreCrux"));
    }

    #[test]
    fn event_type_constants() {
        assert!(EVT_OPS_ERROR_V1.starts_with("ops."));
        assert!(EVT_OPS_WARNING_V1.starts_with("ops."));
        assert!(EVT_OPS_METRIC_V1.starts_with("ops."));
        assert!(EVT_OPS_HEALTH_V1.starts_with("ops."));
        assert!(EVT_OPS_QUERY_COVERAGE_V1.starts_with("ops."));
        assert!(EVT_BOOTSTRAP_DOC_V1.starts_with("bootstrap."));
        assert!(EVT_BOOTSTRAP_PATTERN_V1.starts_with("bootstrap."));
        assert!(EVT_BOOTSTRAP_RESOLUTION_V1.starts_with("bootstrap."));
    }

    #[test]
    fn prefix_constants() {
        assert!(OPS_PREFIX.starts_with("__ops__"));
        assert!(BOOTSTRAP_PREFIX.starts_with("__bootstrap__"));
    }
}
