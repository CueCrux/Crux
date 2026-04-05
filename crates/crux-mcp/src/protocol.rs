// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! JSON-RPC 2.0 types for the MCP protocol layer.

use serde::{Deserialize, Serialize};

// ── Error codes (JSON-RPC 2.0 §5.1) ───────────────────────────────────────

/// Invalid JSON was received by the server.
pub const PARSE_ERROR: i32 = -32700;

/// The JSON sent is not a valid Request object.
pub const INVALID_REQUEST: i32 = -32600;

/// The method does not exist / is not available.
pub const METHOD_NOT_FOUND: i32 = -32601;

/// Invalid method parameter(s).
pub const INVALID_PARAMS: i32 = -32602;

/// Internal JSON-RPC error.
pub const INTERNAL_ERROR: i32 = -32603;

// ── Request ────────────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 request (or notification when `id` is `None`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

// ── Response ───────────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// Build a successful response.
    pub fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response.
    pub fn error(id: Option<serde_json::Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// Build an error response with additional structured data.
    pub fn error_with_data(
        id: Option<serde_json::Value>,
        code: i32,
        message: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: Some(data),
            }),
        }
    }
}

// ── Error object ───────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_roundtrip() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tools/list".to_string(),
            params: json!({}),
        };
        let serialized = serde_json::to_string(&req).unwrap();
        let deserialized: JsonRpcRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.method, "tools/list");
        assert_eq!(deserialized.id, Some(json!(1)));
    }

    #[test]
    fn request_without_id_or_params() {
        let raw = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req: JsonRpcRequest = serde_json::from_str(raw).unwrap();
        assert!(req.id.is_none());
        assert_eq!(req.params, json!(null));
    }

    #[test]
    fn success_response_roundtrip() {
        let resp = JsonRpcResponse::success(Some(json!(42)), json!({"ok": true}));
        let serialized = serde_json::to_string(&resp).unwrap();
        let deserialized: JsonRpcResponse = serde_json::from_str(&serialized).unwrap();
        assert!(deserialized.error.is_none());
        assert_eq!(deserialized.result, Some(json!({"ok": true})));
        assert_eq!(deserialized.id, Some(json!(42)));
    }

    #[test]
    fn error_response_omits_result() {
        let resp = JsonRpcResponse::error(Some(json!(1)), METHOD_NOT_FOUND, "not found");
        let serialized = serde_json::to_string(&resp).unwrap();
        assert!(!serialized.contains("\"result\""));
        let deserialized: JsonRpcResponse = serde_json::from_str(&serialized).unwrap();
        let err = deserialized.error.unwrap();
        assert_eq!(err.code, METHOD_NOT_FOUND);
        assert_eq!(err.message, "not found");
        assert!(err.data.is_none());
    }

    #[test]
    fn error_response_with_data() {
        let resp = JsonRpcResponse::error_with_data(
            Some(json!("abc")),
            INVALID_PARAMS,
            "bad params",
            json!({"field": "name"}),
        );
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data, Some(json!({"field": "name"})));
    }

    #[test]
    fn success_response_omits_error() {
        let resp = JsonRpcResponse::success(None, json!("hello"));
        let serialized = serde_json::to_string(&resp).unwrap();
        assert!(!serialized.contains("\"error\""));
    }

    #[test]
    fn error_code_constants() {
        assert_eq!(PARSE_ERROR, -32700);
        assert_eq!(INVALID_REQUEST, -32600);
        assert_eq!(METHOD_NOT_FOUND, -32601);
        assert_eq!(INVALID_PARAMS, -32602);
        assert_eq!(INTERNAL_ERROR, -32603);
    }

    #[test]
    fn json_rpc_error_roundtrip() {
        let err = JsonRpcError {
            code: INTERNAL_ERROR,
            message: "boom".to_string(),
            data: Some(json!({"trace": "abc123"})),
        };
        let serialized = serde_json::to_string(&err).unwrap();
        let deserialized: JsonRpcError = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.code, INTERNAL_ERROR);
        assert_eq!(deserialized.message, "boom");
    }
}
