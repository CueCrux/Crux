// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Sync client — pushes outbox contributions to VaultCrux API.

use serde::{Deserialize, Serialize};

/// Result of a sync push.
#[derive(Debug, Serialize, Deserialize)]
pub struct SyncResult {
    pub accepted: usize,
    pub rejected: usize,
    pub quarantined: usize,
    pub credits_awarded: usize,
    pub new_sync_cursor: String,
}

/// Build the contributions push request body.
pub fn build_contributions_body(contributions: &[serde_json::Value], sync_cursor: &str) -> serde_json::Value {
    serde_json::json!({
        "contributions": contributions,
        "sync_cursor": sync_cursor
    })
}

/// Build the commons query request body.
pub fn build_commons_query_body(query: &str, top_k: usize) -> serde_json::Value {
    serde_json::json!({
        "query": query,
        "top_k": top_k,
        "include_receipts": true
    })
}

/// Build the API URL for a given path.
pub fn api_url(endpoint: &str, path: &str) -> String {
    format!("{}{}", endpoint, path)
}

/// Push contributions to VaultCrux.
pub fn push_contributions(
    endpoint: &str,
    sync_token: &str,
    contributions: &[serde_json::Value],
    sync_cursor: &str,
) -> Result<SyncResult, Box<dyn std::error::Error + Send + Sync>> {
    let body = build_contributions_body(contributions, sync_cursor);
    let url = api_url(endpoint, "/api/v1/community/contributions");
    let resp: SyncResult = ureq::post(&url)
        .set("Authorization", &format!("Bearer {}", sync_token))
        .send_json(body)?
        .into_json()?;

    Ok(resp)
}

/// Query the commons.
pub fn query_commons(
    endpoint: &str,
    sync_token: &str,
    query: &str,
    top_k: usize,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let body = build_commons_query_body(query, top_k);
    let url = api_url(endpoint, "/api/v1/community/query");
    let resp: serde_json::Value = ureq::post(&url)
        .set("Authorization", &format!("Bearer {}", sync_token))
        .send_json(body)?
        .into_json()?;

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_result_serde_roundtrip() {
        let result = SyncResult {
            accepted: 10,
            rejected: 2,
            quarantined: 1,
            credits_awarded: 8,
            new_sync_cursor: "cursor_abc123".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: SyncResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.accepted, 10);
        assert_eq!(deserialized.rejected, 2);
        assert_eq!(deserialized.quarantined, 1);
        assert_eq!(deserialized.credits_awarded, 8);
        assert_eq!(deserialized.new_sync_cursor, "cursor_abc123");
    }

    #[test]
    fn sync_result_deserialize_from_api_json() {
        let json = r#"{
            "accepted": 5,
            "rejected": 0,
            "quarantined": 0,
            "credits_awarded": 5,
            "new_sync_cursor": "cur_2026040300"
        }"#;

        let result: SyncResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.accepted, 5);
        assert_eq!(result.rejected, 0);
        assert_eq!(result.new_sync_cursor, "cur_2026040300");
    }

    #[test]
    fn sync_result_zero_values() {
        let result = SyncResult {
            accepted: 0,
            rejected: 0,
            quarantined: 0,
            credits_awarded: 0,
            new_sync_cursor: "".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: SyncResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.accepted, 0);
        assert_eq!(deserialized.credits_awarded, 0);
        assert!(deserialized.new_sync_cursor.is_empty());
    }

    #[test]
    fn build_contributions_body_structure() {
        let contribs = vec![
            serde_json::json!({"type": "correction", "id": "c1"}),
            serde_json::json!({"type": "citation", "id": "c2"}),
        ];

        let body = build_contributions_body(&contribs, "cursor_prev");
        assert_eq!(body["sync_cursor"], "cursor_prev");
        assert_eq!(body["contributions"].as_array().unwrap().len(), 2);
        assert_eq!(body["contributions"][0]["type"], "correction");
    }

    #[test]
    fn build_contributions_body_empty() {
        let body = build_contributions_body(&[], "");
        assert!(body["contributions"].as_array().unwrap().is_empty());
        assert_eq!(body["sync_cursor"], "");
    }

    #[test]
    fn build_commons_query_body_structure() {
        let body = build_commons_query_body("deployment strategy", 5);
        assert_eq!(body["query"], "deployment strategy");
        assert_eq!(body["top_k"], 5);
        assert_eq!(body["include_receipts"], true);
    }

    #[test]
    fn api_url_construction() {
        let url = api_url("https://vaultcrux.com", "/api/v1/community/auth");
        assert_eq!(url, "https://vaultcrux.com/api/v1/community/auth");
    }

    #[test]
    fn api_url_no_trailing_slash() {
        let url = api_url("http://localhost:14333", "/api/v1/community/contributions");
        assert_eq!(url, "http://localhost:14333/api/v1/community/contributions");
    }

    #[test]
    fn push_contributions_with_mock_server() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/api/v1/community/contributions")
            .match_header("authorization", "Bearer vcx_tok")
            .match_header("content-type", "application/json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"accepted": 2, "rejected": 0, "quarantined": 0, "credits_awarded": 5, "new_sync_cursor": "cur_new"}"#)
            .create();

        let contribs = vec![
            serde_json::json!({"type": "fact", "body": "a"}),
            serde_json::json!({"type": "fact", "body": "b"}),
        ];

        let result = push_contributions(&server.url(), "vcx_tok", &contribs, "cur_old").unwrap();
        assert_eq!(result.accepted, 2);
        assert_eq!(result.rejected, 0);
        assert_eq!(result.quarantined, 0);
        assert_eq!(result.credits_awarded, 5);
        assert_eq!(result.new_sync_cursor, "cur_new");

        mock.assert();
    }

    #[test]
    fn push_contributions_server_error() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/api/v1/community/contributions")
            .with_status(503)
            .with_body("Service Unavailable")
            .create();

        let result = push_contributions(&server.url(), "tok", &[], "cur");
        assert!(result.is_err());

        mock.assert();
    }

    #[test]
    fn query_commons_with_mock_server() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/api/v1/community/query")
            .match_header("authorization", "Bearer vcx_tok")
            .match_header("content-type", "application/json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"results": [], "remaining_queries_today": 95}"#)
            .create();

        let resp = query_commons(&server.url(), "vcx_tok", "test query", 10).unwrap();
        assert_eq!(resp["results"].as_array().unwrap().len(), 0);
        assert_eq!(resp["remaining_queries_today"], 95);

        mock.assert();
    }

    #[test]
    fn query_commons_server_error() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/api/v1/community/query")
            .with_status(401)
            .with_body("Unauthorized")
            .create();

        let result = query_commons(&server.url(), "bad_tok", "query", 5);
        assert!(result.is_err());

        mock.assert();
    }
}
