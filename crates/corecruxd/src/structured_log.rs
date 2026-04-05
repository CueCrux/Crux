// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use axum::http::HeaderMap;
use chrono::Utc;
use serde::Serialize;
use tonic::metadata::MetadataMap;

const MAX_CORRELATION_LEN: usize = 128;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    IoReadFailed,
    IoWriteFailed,
    IoFsyncFailed,
    SegmentCorrupt,
    InvalidFrame,
    InvalidToc,
    ShardNotOwner,
    EpochMismatch,
    Backpressure,
    Timeout,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IoReadFailed => "IO_READ_FAILED",
            Self::IoWriteFailed => "IO_WRITE_FAILED",
            Self::IoFsyncFailed => "IO_FSYNC_FAILED",
            Self::SegmentCorrupt => "SEGMENT_CORRUPT",
            Self::InvalidFrame => "INVALID_FRAME",
            Self::InvalidToc => "INVALID_TOC",
            Self::ShardNotOwner => "SHARD_NOT_OWNER",
            Self::EpochMismatch => "EPOCH_MISMATCH",
            Self::Backpressure => "BACKPRESSURE",
            Self::Timeout => "TIMEOUT",
            Self::Internal => "INTERNAL",
        }
    }
}

fn sanitize_token(raw: &str) -> Option<String> {
    if raw.chars().any(|ch| ch.is_ascii_control()) {
        return None;
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_CORRELATION_LEN {
        return None;
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '/' | '='))
    {
        return None;
    }
    Some(trimmed.to_string())
}

pub fn sanitize_request_id(raw: &str) -> Option<String> {
    sanitize_token(raw)
}

pub fn sanitize_traceparent(raw: &str) -> Option<String> {
    let token = sanitize_token(raw)?;
    if token.len() < 16 {
        return None;
    }
    Some(token)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorrelationIds {
    pub request_id: Option<String>,
    pub traceparent: Option<String>,
}

impl CorrelationIds {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let request_id = headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .and_then(sanitize_request_id);
        let traceparent = headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .and_then(sanitize_traceparent);
        Self {
            request_id,
            traceparent,
        }
    }

    pub fn from_metadata(meta: &MetadataMap) -> Self {
        let request_id = meta
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .and_then(sanitize_request_id);
        let traceparent = meta
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .and_then(sanitize_traceparent);
        Self {
            request_id,
            traceparent,
        }
    }

    pub fn request_id_or_new(&self) -> String {
        self.request_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    }
}

#[allow(dead_code)]
pub fn payload_hash_prefix(payload: &[u8]) -> String {
    let digest = blake3::hash(payload).to_hex().to_string();
    digest.chars().take(12).collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct StructuredOpLog {
    pub ts: String,
    pub level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
    pub op: String,
    pub outcome: String,
    pub took_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shard_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hash_prefix: Option<String>,
}

impl StructuredOpLog {
    pub fn new(level: &str, op: &str, outcome: &str, took_ms: u64) -> Self {
        Self {
            ts: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            level: level.to_string(),
            request_id: None,
            trace_id: None,
            traceparent: None,
            op: op.to_string(),
            outcome: outcome.to_string(),
            took_ms,
            shard_id: None,
            epoch: None,
            error_code: None,
            retryable: None,
            retry_after_ms: None,
            error_detail: None,
            payload_hash_prefix: None,
        }
    }

    #[allow(dead_code)]
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({"op": self.op}))
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;
    use tonic::metadata::MetadataMap;

    use super::{payload_hash_prefix, sanitize_request_id, CorrelationIds, StructuredOpLog};

    #[test]
    fn sanitize_request_id_rejects_invalid_values() {
        assert_eq!(sanitize_request_id("req-123"), Some("req-123".to_string()));
        assert_eq!(sanitize_request_id(""), None);
        assert_eq!(sanitize_request_id("   "), None);
        assert_eq!(sanitize_request_id("\nabc"), None);
        assert_eq!(sanitize_request_id(&"x".repeat(129)), None);
    }

    #[test]
    fn extracts_and_sanitizes_correlation_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", "req_abc-123".parse().expect("header"));
        headers.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .expect("header"),
        );

        let corr = CorrelationIds::from_headers(&headers);
        assert_eq!(corr.request_id.as_deref(), Some("req_abc-123"));
        assert!(corr.traceparent.is_some());
    }

    #[test]
    fn extracts_and_sanitizes_correlation_from_metadata() {
        let mut meta = MetadataMap::new();
        meta.insert("x-request-id", "req-42".parse().expect("meta"));
        meta.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .expect("meta"),
        );

        let corr = CorrelationIds::from_metadata(&meta);
        assert_eq!(corr.request_id.as_deref(), Some("req-42"));
        assert!(corr.traceparent.is_some());
    }

    #[test]
    fn structured_log_schema_has_required_fields_and_no_payload_bytes() {
        let mut log = StructuredOpLog::new("info", "verify_store", "ok", 12);
        log.request_id = Some("req_1".to_string());
        log.payload_hash_prefix = Some(payload_hash_prefix(b"sensitive-payload"));

        let value = log.to_json_value();
        assert!(value.get("ts").is_some());
        assert_eq!(value.get("level").and_then(|v| v.as_str()), Some("info"));
        assert_eq!(
            value.get("op").and_then(|v| v.as_str()),
            Some("verify_store")
        );
        assert_eq!(value.get("outcome").and_then(|v| v.as_str()), Some("ok"));
        assert_eq!(value.get("took_ms").and_then(|v| v.as_u64()), Some(12));
        assert!(value.get("payload").is_none());
        assert!(value.get("payload_bytes").is_none());
    }

    #[test]
    fn error_code_as_str_covers_all_variants() {
        use super::ErrorCode;

        let cases = [
            (ErrorCode::IoReadFailed, "IO_READ_FAILED"),
            (ErrorCode::IoWriteFailed, "IO_WRITE_FAILED"),
            (ErrorCode::IoFsyncFailed, "IO_FSYNC_FAILED"),
            (ErrorCode::SegmentCorrupt, "SEGMENT_CORRUPT"),
            (ErrorCode::InvalidFrame, "INVALID_FRAME"),
            (ErrorCode::InvalidToc, "INVALID_TOC"),
            (ErrorCode::ShardNotOwner, "SHARD_NOT_OWNER"),
            (ErrorCode::EpochMismatch, "EPOCH_MISMATCH"),
            (ErrorCode::Backpressure, "BACKPRESSURE"),
            (ErrorCode::Timeout, "TIMEOUT"),
            (ErrorCode::Internal, "INTERNAL"),
        ];
        for (code, expected) in cases {
            assert_eq!(code.as_str(), expected);
        }
    }

    #[test]
    fn error_code_serde_is_screaming_snake() {
        use super::ErrorCode;

        let json = serde_json::to_string(&ErrorCode::SegmentCorrupt).unwrap();
        assert_eq!(json, r#""SEGMENT_CORRUPT""#);
        let json = serde_json::to_string(&ErrorCode::IoFsyncFailed).unwrap();
        assert_eq!(json, r#""IO_FSYNC_FAILED""#);
    }

    #[test]
    fn error_code_variant_count_matches_constants() {
        // Community edition: 11 error codes, no GPU variants.
        assert_eq!(corecrux_types::CORE_ERROR_CODES.len(), 11);
    }

    #[test]
    fn sanitize_traceparent_rejects_short_token() {
        use super::sanitize_traceparent;

        // Less than 16 chars
        assert_eq!(sanitize_traceparent("abc"), None);
        assert_eq!(sanitize_traceparent("0123456789abcde"), None); // 15 chars
    }

    #[test]
    fn sanitize_traceparent_accepts_valid_traceparent() {
        use super::sanitize_traceparent;

        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert!(sanitize_traceparent(tp).is_some());
    }

    #[test]
    fn sanitize_traceparent_rejects_control_chars() {
        use super::sanitize_traceparent;

        assert_eq!(sanitize_traceparent("00-\x01bad-traceparent-string-01"), None);
    }

    #[test]
    fn sanitize_request_id_accepts_allowed_special_chars() {
        assert_eq!(
            sanitize_request_id("req/path:val=1_test-id.v2"),
            Some("req/path:val=1_test-id.v2".to_string())
        );
    }

    #[test]
    fn sanitize_request_id_rejects_disallowed_chars() {
        assert_eq!(sanitize_request_id("req id with spaces"), None);
        assert_eq!(sanitize_request_id("req;drop"), None);
        assert_eq!(sanitize_request_id("req@host"), None);
    }

    #[test]
    fn correlation_ids_default_is_empty() {
        let corr = CorrelationIds::default();
        assert!(corr.request_id.is_none());
        assert!(corr.traceparent.is_none());
    }

    #[test]
    fn correlation_ids_request_id_or_new_uses_existing() {
        let corr = CorrelationIds {
            request_id: Some("existing-id".to_string()),
            traceparent: None,
        };
        assert_eq!(corr.request_id_or_new(), "existing-id");
    }

    #[test]
    fn correlation_ids_request_id_or_new_generates_uuid_when_missing() {
        let corr = CorrelationIds::default();
        let id = corr.request_id_or_new();
        // UUID v4 format: 8-4-4-4-12 hex chars
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn correlation_ids_from_empty_headers() {
        let headers = HeaderMap::new();
        let corr = CorrelationIds::from_headers(&headers);
        assert!(corr.request_id.is_none());
        assert!(corr.traceparent.is_none());
    }

    #[test]
    fn correlation_ids_from_empty_metadata() {
        let meta = MetadataMap::new();
        let corr = CorrelationIds::from_metadata(&meta);
        assert!(corr.request_id.is_none());
        assert!(corr.traceparent.is_none());
    }

    #[test]
    fn payload_hash_prefix_is_12_chars() {
        let prefix = payload_hash_prefix(b"hello world");
        assert_eq!(prefix.len(), 12);
        // Should be deterministic
        assert_eq!(prefix, payload_hash_prefix(b"hello world"));
    }

    #[test]
    fn payload_hash_prefix_differs_for_different_input() {
        let a = payload_hash_prefix(b"aaa");
        let b = payload_hash_prefix(b"bbb");
        assert_ne!(a, b);
    }

    #[test]
    fn structured_op_log_optional_fields_omitted_when_none() {
        let log = StructuredOpLog::new("warn", "compact", "timeout", 500);
        let value = log.to_json_value();
        // Optional fields should not appear
        assert!(value.get("shard_id").is_none());
        assert!(value.get("epoch").is_none());
        assert!(value.get("error_code").is_none());
        assert!(value.get("retryable").is_none());
        assert!(value.get("retry_after_ms").is_none());
        assert!(value.get("error_detail").is_none());
        assert!(value.get("payload_hash_prefix").is_none());
        assert!(value.get("request_id").is_none());
        assert!(value.get("trace_id").is_none());
        assert!(value.get("traceparent").is_none());
    }

    #[test]
    fn structured_op_log_with_all_optional_fields() {
        let mut log = StructuredOpLog::new("error", "append", "fail", 100);
        log.request_id = Some("req-1".to_string());
        log.trace_id = Some("trace-1".to_string());
        log.traceparent = Some("00-abc-def-01".to_string());
        log.shard_id = Some(3);
        log.epoch = Some(42);
        log.error_code = Some("IO_WRITE_FAILED".to_string());
        log.retryable = Some(true);
        log.retry_after_ms = Some(1000);
        log.error_detail = Some("disk full".to_string());
        log.payload_hash_prefix = Some("abcdef012345".to_string());

        let value = log.to_json_value();
        assert_eq!(value["request_id"], "req-1");
        assert_eq!(value["trace_id"], "trace-1");
        assert_eq!(value["traceparent"], "00-abc-def-01");
        assert_eq!(value["shard_id"], 3);
        assert_eq!(value["epoch"], 42);
        assert_eq!(value["error_code"], "IO_WRITE_FAILED");
        assert_eq!(value["retryable"], true);
        assert_eq!(value["retry_after_ms"], 1000);
        assert_eq!(value["error_detail"], "disk full");
        assert_eq!(value["payload_hash_prefix"], "abcdef012345");
    }

    #[test]
    fn sanitize_token_rejects_max_length_exceeded() {
        // 129 chars should be rejected (MAX_CORRELATION_LEN = 128)
        let long = "a".repeat(129);
        assert_eq!(sanitize_request_id(&long), None);
        // 128 chars should be accepted
        let exact = "a".repeat(128);
        assert!(sanitize_request_id(&exact).is_some());
    }
}
