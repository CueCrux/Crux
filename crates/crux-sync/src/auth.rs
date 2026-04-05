// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Sync authentication — token management for VaultCrux community sync.

use serde::{Deserialize, Serialize};

/// Sync token issued by VaultCrux.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncToken {
    pub token: String,
    pub scopes: Vec<String>,
    pub expires_at: String,
}

/// Parse a VaultCrux auth response JSON into a `SyncToken`.
pub fn parse_auth_response(resp: &serde_json::Value) -> SyncToken {
    SyncToken {
        token: resp["sync_token"].as_str().unwrap_or("").to_string(),
        scopes: resp["scopes"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        expires_at: resp["expires_at"].as_str().unwrap_or("").to_string(),
    }
}

/// Authenticate with VaultCrux to obtain a sync token.
pub fn authenticate(endpoint: &str, email: &str) -> Result<SyncToken, Box<dyn std::error::Error + Send + Sync>> {
    let resp: serde_json::Value = ureq::post(&format!("{}/api/v1/community/auth", endpoint))
        .send_json(serde_json::json!({
            "email": email,
            "grant_type": "community_sync"
        }))?
        .into_json()?;

    Ok(parse_auth_response(&resp))
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

        let token = parse_auth_response(&resp);
        assert_eq!(token.token, "vcx_cs_abc123");
        assert_eq!(token.scopes.len(), 3);
        assert_eq!(token.scopes[0], "community:sync");
        assert_eq!(token.expires_at, "2027-04-03T00:00:00Z");
    }

    #[test]
    fn parse_auth_response_missing_fields() {
        let resp = serde_json::json!({});

        let token = parse_auth_response(&resp);
        assert_eq!(token.token, "");
        assert!(token.scopes.is_empty());
        assert_eq!(token.expires_at, "");
    }

    #[test]
    fn parse_auth_response_null_scopes() {
        let resp = serde_json::json!({
            "sync_token": "tok",
            "scopes": null,
            "expires_at": "2027-01-01T00:00:00Z"
        });

        let token = parse_auth_response(&resp);
        assert_eq!(token.token, "tok");
        assert!(token.scopes.is_empty());
    }

    #[test]
    fn authenticate_with_mock_server() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/api/v1/community/auth")
            .match_header("content-type", "application/json")
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
