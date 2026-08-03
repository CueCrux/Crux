// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Load an externally-minted RCX capability token (ExecPlan
//! `crux-hosted-relay-gateway-2026-07-30`, M4a).
//!
//! # Why this exists
//!
//! Before this module the daemon had **no way to load a CruxEngine-minted
//! token at all**. `state.rcx_router` is built from a *self-minted,
//! self-signed* free-local token whose only backend is `"local"`
//! (`main.rs`, `crux_router::mint_signed_free_local_token`), and the sole
//! ingestion path for anything externally minted was
//! `CORECRUXD_SYNC_PEER_TOKEN`, consumed only at the sync boundary. So a daemon
//! could be granted a hosted relay backend by the account plane and never see
//! it. That, not the token schema, was the real blocker on the relay work.
//!
//! # What it deliberately does not do
//!
//! It does **not** feed the loaded token to [`crux_router::RcxRouter`]. A token
//! carrying a `delegation_policy` makes `requires_contextual_verification()`
//! true, and `RcxRouter::decide` then refuses *every* capability on it. The
//! hosted token is therefore held to one side and presented contextually at the
//! relay handshake (contract v1 §8) — never routed.
//!
//! Loading is also not authorization. [`rcx_capability_token::verify_issuer_provenance`]
//! establishes only that the trust root signed these bytes; the relay still has
//! to verify proof-of-possession per session.
//!
//! # Configuration
//!
//! | Var | Meaning |
//! |---|---|
//! | `CORECRUXD_RCX_HOSTED_TOKEN_FILE` | path to canonical token JSON (**preferred** — a Vault agent can render it, and it keeps a long credential out of the process environment) |
//! | `CORECRUXD_RCX_HOSTED_TOKEN` | the same JSON inline (fallback, matches the `CORECRUXD_SYNC_PEER_TOKEN` idiom) |
//! | `CORECRUXD_RCX_TRUST_ROOT_PUBKEY` | 64-hex Ed25519 public key of the issuer |
//!
//! All absent ⇒ feature off, daemon unchanged. Present but broken ⇒ **off with a
//! warning**, never partially on: a daemon that believed it held a hosted grant
//! it could not prove would fail confusingly at the relay instead of at boot.

use rcx_capability_token::{RcxCapabilityToken, VerifyOutcome, RCX_RELAY_BACKEND_ID};

const TOKEN_FILE_ENV: &str = "CORECRUXD_RCX_HOSTED_TOKEN_FILE";
const TOKEN_INLINE_ENV: &str = "CORECRUXD_RCX_HOSTED_TOKEN";
const TRUST_ROOT_ENV: &str = "CORECRUXD_RCX_TRUST_ROOT_PUBKEY";

/// A verified hosted token plus the relay grant extracted from it.
#[derive(Debug, Clone)]
pub struct HostedToken {
    pub token: RcxCapabilityToken,
    /// The relay backend, when the account was granted one. `None` is the
    /// ordinary Free-tier case, not an error.
    pub relay: Option<RelayGrant>,
}

/// What the daemon needs in order to dial the relay (M4b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayGrant {
    pub endpoint_url: String,
    pub trust_root_kid: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostedTokenError {
    #[error("{TRUST_ROOT_ENV} is required when a hosted token is configured")]
    MissingTrustRoot,
    #[error("{TRUST_ROOT_ENV} must be 64 hex characters (32 bytes)")]
    BadTrustRoot,
    #[error("hosted token is not valid capability-token JSON: {0}")]
    Malformed(String),
    #[error("hosted token could not be read from {path}: {reason}")]
    Unreadable { path: String, reason: String },
    #[error("hosted token failed issuer verification: {0}")]
    NotIssuerSigned(String),
}

/// Parse and verify a hosted token. Pure — no env, no filesystem, no clock.
///
/// # Errors
/// Returns [`HostedTokenError`] when the JSON is unparseable or the trust root
/// did not sign it.
pub fn parse_and_verify(
    token_json: &str,
    trust_root_pubkey: &[u8; 32],
    now_unix_seconds: u64,
) -> Result<HostedToken, HostedTokenError> {
    let token: RcxCapabilityToken =
        serde_json::from_str(token_json).map_err(|err| HostedTokenError::Malformed(err.to_string()))?;
    verify_loaded(token, trust_root_pubkey, now_unix_seconds)
}

/// Verification core, over an already-parsed token.
///
/// Split from [`parse_and_verify`] because `RcxCapabilityToken` implements
/// `Deserialize` but not `Serialize` — tokens are minted by CruxEngine and only
/// ever *read* here — so tests cannot round-trip one through JSON and must build
/// the struct directly.
///
/// # Errors
/// Returns [`HostedTokenError::NotIssuerSigned`] when the trust root did not
/// sign this token, or the base envelope is invalid or expired.
pub fn verify_loaded(
    token: RcxCapabilityToken,
    trust_root_pubkey: &[u8; 32],
    now_unix_seconds: u64,
) -> Result<HostedToken, HostedTokenError> {
    // Provenance only. This is NOT the authorization step — the relay verifies
    // proof-of-possession per session. Using `verify_token` here would be wrong
    // in the other direction: it fails every delegation-bearing token closed.
    match rcx_capability_token::verify_issuer_provenance(&token, trust_root_pubkey, now_unix_seconds) {
        VerifyOutcome::Verified => {}
        VerifyOutcome::BadSignature => {
            return Err(HostedTokenError::NotIssuerSigned("bad signature".to_string()));
        }
        VerifyOutcome::BadTrustRoot => {
            return Err(HostedTokenError::NotIssuerSigned("bad trust root".to_string()));
        }
        VerifyOutcome::StructuralFailure(issues) => {
            return Err(HostedTokenError::NotIssuerSigned(issues.join(", ")));
        }
    }

    let relay = extract_relay_grant(&token);
    Ok(HostedToken { token, relay })
}

/// Pull the relay backend out of `backends[]`, if the account was granted one.
fn extract_relay_grant(token: &RcxCapabilityToken) -> Option<RelayGrant> {
    let backend = token
        .backends
        .iter()
        .find(|backend| backend.backend_id == RCX_RELAY_BACKEND_ID)?;
    // A relay backend without an endpoint cannot be dialled. Treat it as absent
    // rather than carrying a half-grant that fails later at connect time.
    let endpoint_url = backend.endpoint_url.clone()?;
    Some(RelayGrant {
        endpoint_url,
        trust_root_kid: backend.trust_root_kid.clone(),
        capabilities: backend
            .permitted_capabilities
            .iter()
            .map(|capability| capability.capability.clone())
            .collect(),
    })
}

/// Decode a 64-hex trust root.
///
/// # Errors
/// Returns [`HostedTokenError::BadTrustRoot`] when the value is not 32 bytes of hex.
pub fn parse_trust_root(value: &str) -> Result<[u8; 32], HostedTokenError> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(value.trim(), &mut out).map_err(|_| HostedTokenError::BadTrustRoot)?;
    Ok(out)
}

/// Read the configured token source, if any. `Ok(None)` means "not configured".
///
/// # Errors
/// Returns [`HostedTokenError::Unreadable`] when a configured file cannot be read.
fn read_configured_token() -> Result<Option<String>, HostedTokenError> {
    if let Ok(path) = std::env::var(TOKEN_FILE_ENV) {
        let path = path.trim().to_string();
        if !path.is_empty() {
            return std::fs::read_to_string(&path)
                .map(Some)
                .map_err(|err| HostedTokenError::Unreadable {
                    path,
                    reason: err.to_string(),
                });
        }
    }
    Ok(std::env::var(TOKEN_INLINE_ENV)
        .ok()
        .filter(|raw| !raw.trim().is_empty()))
}

/// Load the hosted token from the environment.
///
/// Returns `None` when the feature is not configured **or** when it is
/// configured but unusable — the latter logs a warning. Failing closed and loud
/// beats a daemon that half-believes it holds a hosted grant.
#[must_use]
pub fn load_from_env(now_unix_seconds: u64) -> Option<HostedToken> {
    let token_json = match read_configured_token() {
        Ok(Some(json)) => json,
        Ok(None) => return None,
        Err(err) => {
            tracing::warn!(error = %err, "hosted RCX token disabled");
            return None;
        }
    };

    let Ok(trust_root_hex) = std::env::var(TRUST_ROOT_ENV) else {
        tracing::warn!(error = %HostedTokenError::MissingTrustRoot, "hosted RCX token disabled");
        return None;
    };
    let trust_root = match parse_trust_root(&trust_root_hex) {
        Ok(key) => key,
        Err(err) => {
            tracing::warn!(error = %err, "hosted RCX token disabled");
            return None;
        }
    };

    match parse_and_verify(&token_json, &trust_root, now_unix_seconds) {
        Ok(hosted) => {
            // Log the grant's shape, never the token. `daemon_instance_id` is
            // the identity the relay will attribute the session to, so an
            // operator wants to see it agree with the device they paired.
            let instance = hosted.token.subject.daemon_instance_id.as_deref().unwrap_or("<none>");
            match &hosted.relay {
                Some(relay) => tracing::info!(
                    tier = %hosted.token.tier.as_str(),
                    daemon_instance_id = %instance,
                    endpoint = %relay.endpoint_url,
                    capabilities = ?relay.capabilities,
                    "hosted RCX token loaded; relay backend granted"
                ),
                None => tracing::info!(
                    tier = %hosted.token.tier.as_str(),
                    daemon_instance_id = %instance,
                    "hosted RCX token loaded; no relay backend in this grant"
                ),
            }
            Some(hosted)
        }
        Err(err) => {
            // Never log the token itself — it is a credential.
            tracing::warn!(error = %err, "hosted RCX token disabled");
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use rcx_capability_token::{Backend, DataEgressClass, PermittedCapability};

    fn issuer() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    /// A signed hosted token, optionally carrying a relay backend.
    fn hosted_token(with_relay: bool, endpoint: Option<&str>) -> RcxCapabilityToken {
        let key = issuer();
        let mut token = crux_router::mint_signed_free_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "acme",
            vec!["corecrux.query.local".to_string()],
            1_700_000_000,
            1_900_000_000,
            |hash| key.sign(hash).to_bytes(),
        );
        if with_relay {
            token.backends.push(Backend {
                backend_id: RCX_RELAY_BACKEND_ID.to_string(),
                trust_root_kid: "p_0123456789abcdef0123456789abcdef".to_string(),
                endpoint_url: endpoint.map(str::to_string),
                permitted_capabilities: vec![PermittedCapability {
                    capability: rcx_capability_token::RCX_RELAY_SESSION_CAPABILITY.to_string(),
                    data_egress_classes: vec![DataEgressClass::Text],
                    required_attestations: vec!["passport_bound".to_string()],
                    credit_cost: None,
                }],
            });
            // Re-sign: backends are inside the signing bytes.
            token.signature.sig = key.sign(&token.token_hash()).to_bytes();
        }
        token
    }

    fn trust_root() -> [u8; 32] {
        issuer().verifying_key().to_bytes()
    }

    #[test]
    fn a_grant_with_a_relay_backend_yields_a_dialable_endpoint() {
        let token = hosted_token(true, Some("wss://relay.cuecrux.com"));

        let hosted = verify_loaded(token, &trust_root(), 1_800_000_000).expect("token must verify");

        let relay = hosted.relay.expect("relay backend must be extracted");
        assert_eq!(relay.endpoint_url, "wss://relay.cuecrux.com");
        assert!(relay
            .capabilities
            .contains(&rcx_capability_token::RCX_RELAY_SESSION_CAPABILITY.to_string()));
    }

    #[test]
    fn a_grant_without_a_relay_backend_loads_cleanly_with_no_relay() {
        // The ordinary Free-tier shape. Must not be an error — the daemon still
        // wants the token for everything else it carries.
        let token = hosted_token(false, None);

        let hosted = verify_loaded(token, &trust_root(), 1_800_000_000).expect("token must verify");

        assert!(hosted.relay.is_none());
    }

    #[test]
    fn a_relay_backend_with_no_endpoint_is_treated_as_absent() {
        // A half-grant would otherwise surface as a dial failure much later,
        // far from the misconfiguration that caused it.
        let token = hosted_token(true, None);

        let hosted = verify_loaded(token, &trust_root(), 1_800_000_000).expect("token must verify");

        assert!(hosted.relay.is_none(), "an endpoint-less relay grant is not dialable");
    }

    #[test]
    fn a_token_signed_by_the_wrong_issuer_is_refused() {
        let token = hosted_token(true, Some("wss://relay.cuecrux.com"));
        let attacker = SigningKey::from_bytes(&[11u8; 32]).verifying_key().to_bytes();

        let err = verify_loaded(token, &attacker, 1_800_000_000).expect_err("wrong issuer must be refused");

        assert!(matches!(err, HostedTokenError::NotIssuerSigned(_)));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let token = hosted_token(true, Some("wss://relay.cuecrux.com"));

        // Well past `expires_at`, and past the crate's 30s leeway.
        let err = verify_loaded(token, &trust_root(), 2_000_000_000).expect_err("expired token must be refused");

        assert!(matches!(err, HostedTokenError::NotIssuerSigned(_)));
    }

    #[test]
    fn malformed_json_is_refused_without_panicking() {
        let err = parse_and_verify("{not json", &trust_root(), 1_800_000_000).expect_err("must be refused");
        assert!(matches!(err, HostedTokenError::Malformed(_)));
    }

    #[test]
    fn trust_root_must_be_thirty_two_bytes_of_hex() {
        assert!(parse_trust_root(&"ab".repeat(32)).is_ok());
        assert_eq!(parse_trust_root("not-hex"), Err(HostedTokenError::BadTrustRoot));
        assert_eq!(parse_trust_root(&"ab".repeat(31)), Err(HostedTokenError::BadTrustRoot));
    }
}
