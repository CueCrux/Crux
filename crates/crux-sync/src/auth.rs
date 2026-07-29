// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Sync authentication — token management for VaultCrux community sync.

use serde::{Deserialize, Serialize};

/// Sync token issued by VaultCrux.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncToken {
    pub token: String,
    pub scopes: Vec<String>,
    pub expires_at: String,
}

/// Failure parsing a VaultCrux auth response. A missing or non-string
/// `sync_token` / `expires_at` fails fast here at the auth boundary rather than
/// coercing to an empty string and constructing a token that fails confusingly
/// downstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncAuthError {
    /// `sync_token` was absent or not a JSON string.
    MissingSyncToken,
    /// `expires_at` was absent or not a JSON string.
    MissingExpiresAt,
}

impl std::fmt::Display for SyncAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSyncToken => f.write_str("auth response missing a string `sync_token`"),
            Self::MissingExpiresAt => f.write_str("auth response missing a string `expires_at`"),
        }
    }
}

impl std::error::Error for SyncAuthError {}

/// Parse a VaultCrux auth response JSON into a `SyncToken`, failing fast when
/// the token or its expiry are absent or non-string. `scopes` stays lenient
/// (absent/null → empty).
pub fn parse_auth_response(resp: &serde_json::Value) -> Result<SyncToken, SyncAuthError> {
    let token = resp["sync_token"].as_str().ok_or(SyncAuthError::MissingSyncToken)?;
    let expires_at = resp["expires_at"].as_str().ok_or(SyncAuthError::MissingExpiresAt)?;
    Ok(SyncToken {
        token: token.to_string(),
        scopes: resp["scopes"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        expires_at: expires_at.to_string(),
    })
}

/// Authenticate with VaultCrux to obtain a sync token.
pub fn authenticate(endpoint: &str, email: &str) -> Result<SyncToken, Box<dyn std::error::Error + Send + Sync>> {
    let resp: serde_json::Value = ureq::post(&format!("{}/api/v1/community/auth", endpoint))
        .send_json(serde_json::json!({
            "email": email,
            "grant_type": "community_sync"
        }))?
        .into_body()
        .read_json()?;

    parse_auth_response(&resp).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_token_serde_roundtrip() {
        let token = SyncToken {
            token: "crx_test_token_abc123".to_string(),
            scopes: vec!["read".to_string(), "write".to_string(), "community".to_string()],
            expires_at: "2026-12-31T23:59:59Z".to_string(),
        };

        let json = serde_json::to_string(&token).unwrap();
        let deserialized: SyncToken = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.token, "crx_test_token_abc123");
        assert_eq!(deserialized.scopes.len(), 3);
        assert_eq!(deserialized.scopes[0], "read");
        assert_eq!(deserialized.scopes[2], "community");
        assert_eq!(deserialized.expires_at, "2026-12-31T23:59:59Z");
    }

    #[test]
    fn sync_token_deserialize_from_json() {
        let json = r#"{
            "token": "tok_xyz",
            "scopes": ["sync"],
            "expires_at": "2026-06-01T00:00:00Z"
        }"#;

        let token: SyncToken = serde_json::from_str(json).unwrap();
        assert_eq!(token.token, "tok_xyz");
        assert_eq!(token.scopes, vec!["sync"]);
        assert_eq!(token.expires_at, "2026-06-01T00:00:00Z");
    }

    #[test]
    fn sync_token_empty_scopes() {
        let token = SyncToken {
            token: "t".to_string(),
            scopes: vec![],
            expires_at: "".to_string(),
        };

        let json = serde_json::to_string(&token).unwrap();
        let deserialized: SyncToken = serde_json::from_str(&json).unwrap();
        assert!(deserialized.scopes.is_empty());
    }

    #[test]
    fn sync_token_clone() {
        let token = SyncToken {
            token: "original".to_string(),
            scopes: vec!["s1".to_string()],
            expires_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let cloned = token.clone();
        assert_eq!(cloned.token, token.token);
        assert_eq!(cloned.scopes, token.scopes);
    }

    #[test]
    fn parse_auth_response_full() {
        let resp = serde_json::json!({
            "sync_token": "vcx_cs_abc123",
            "scopes": ["community:sync", "commons:read", "contributions:write"],
            "expires_at": "2027-04-03T00:00:00Z"
        });

        let token = parse_auth_response(&resp).unwrap();
        assert_eq!(token.token, "vcx_cs_abc123");
        assert_eq!(token.scopes.len(), 3);
        assert_eq!(token.scopes[0], "community:sync");
        assert_eq!(token.expires_at, "2027-04-03T00:00:00Z");
    }

    #[test]
    fn parse_auth_response_missing_sync_token_fails_fast() {
        // A missing `sync_token` now errors at the auth boundary instead of
        // yielding an empty-token client.
        let resp = serde_json::json!({});
        assert_eq!(parse_auth_response(&resp), Err(SyncAuthError::MissingSyncToken));
    }

    #[test]
    fn parse_auth_response_missing_expires_at_fails_fast() {
        let resp = serde_json::json!({ "sync_token": "tok" });
        assert_eq!(parse_auth_response(&resp), Err(SyncAuthError::MissingExpiresAt));
    }

    #[test]
    fn parse_auth_response_null_scopes() {
        let resp = serde_json::json!({
            "sync_token": "tok",
            "scopes": null,
            "expires_at": "2027-01-01T00:00:00Z"
        });

        let token = parse_auth_response(&resp).unwrap();
        assert_eq!(token.token, "tok");
        assert!(token.scopes.is_empty());
    }

    #[test]
    fn authenticate_with_mock_server() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/api/v1/community/auth")
            .match_header(
                "content-type",
                mockito::Matcher::Regex("application/json.*".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"sync_token": "vcx_test", "scopes": ["sync"], "expires_at": "2027-01-01T00:00:00Z"}"#)
            .create();

        let token = authenticate(&server.url(), "user@example.com").unwrap();
        assert_eq!(token.token, "vcx_test");
        assert_eq!(token.scopes, vec!["sync"]);
        assert_eq!(token.expires_at, "2027-01-01T00:00:00Z");

        mock.assert();
    }

    #[test]
    fn authenticate_server_error() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/api/v1/community/auth")
            .with_status(500)
            .with_body("Internal Server Error")
            .create();

        let result = authenticate(&server.url(), "user@example.com");
        assert!(result.is_err());

        mock.assert();
    }
}
