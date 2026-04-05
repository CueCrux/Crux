// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use chrono::Utc;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CommandLogEvent {
    pub ts: String,
    pub level: String,
    pub request_id: String,
    pub op: String,
    pub outcome: String,
    pub took_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hash_prefix: Option<String>,
}

pub fn payload_hash_prefix(payload: &[u8]) -> String {
    let digest = blake3::hash(payload).to_hex().to_string();
    digest.chars().take(12).collect()
}

pub fn emit_command_log(
    op: &str,
    outcome: &str,
    took_ms: u64,
    error_code: Option<&str>,
    error_detail: Option<&str>,
) {
    let event = CommandLogEvent {
        ts: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        level: if outcome == "ok" {
            "info".to_string()
        } else {
            "warn".to_string()
        },
        request_id: uuid::Uuid::new_v4().to_string(),
        op: op.to_string(),
        outcome: outcome.to_string(),
        took_ms,
        error_code: error_code.map(ToOwned::to_owned),
        error_detail: error_detail.map(ToOwned::to_owned),
        payload_hash_prefix: None,
    };
    if let Ok(line) = serde_json::to_string(&event) {
        eprintln!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::{payload_hash_prefix, CommandLogEvent};

    #[test]
    fn payload_hash_prefix_is_stable_and_redacted() {
        let p1 = payload_hash_prefix(b"secret-payload");
        let p2 = payload_hash_prefix(b"secret-payload");
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), 12);
    }

    #[test]
    fn command_log_schema_contains_required_fields() {
        let event = CommandLogEvent {
            ts: "2026-03-04T21:00:00.000Z".to_string(),
            level: "info".to_string(),
            request_id: "req-1".to_string(),
            op: "verify_store".to_string(),
            outcome: "ok".to_string(),
            took_ms: 5,
            error_code: None,
            error_detail: None,
            payload_hash_prefix: Some(payload_hash_prefix(b"payload")),
        };
        let value = serde_json::to_value(&event).expect("json value");
        assert!(value.get("ts").is_some());
        assert!(value.get("level").is_some());
        assert!(value.get("request_id").is_some());
        assert!(value.get("op").is_some());
        assert!(value.get("outcome").is_some());
        assert!(value.get("took_ms").is_some());
        assert!(value.get("payload").is_none());
        assert!(value.get("payload_bytes").is_none());
    }
}
