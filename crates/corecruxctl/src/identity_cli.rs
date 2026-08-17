// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl identity ...` — operator-side half of the identity-federation
//! cross-signature ceremony (G4, Identity-Federation-v1 §3).
//!
//! - `identity fpr --data-dir <dir>` — print this daemon's passport
//!   fingerprint + public key (what the *other* machine needs to draft a
//!   link statement).
//! - `identity sign-link --data-dir <dir> --local-fpr … --remote-fpr …
//!   --created-at …` — canonicalize the link statement, sign its blake3
//!   hash with this machine's passport key, print the signature bundle the
//!   operator shuttles to the granting daemon's `POST /v1/identity/links`.
//! - `identity confirm-candidate <id> --sig-local … --sig-remote …` — submit
//!   the completed cross-signature proof to the granting daemon and promote a
//!   candidate into a resolving `identity_link`.
//!
//! The statement layout is shared with the daemon via
//! `corecrux_memory::identity_link` — one canonical byte layout, one
//! signature idiom. Private keys never leave `data_dir/passport.key`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use corecrux_memory::identity_link::{statement_hash, LinkStatement};
use crux_session::passport::LocalPassportKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum IdentityCliError {
    #[error("passport key error: {0}")]
    Passport(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("daemon returned status {status}: {body}")]
    UpstreamStatus { status: u16, body: String },
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl IdentityCliError {
    fn transport(err: impl std::fmt::Display) -> Self {
        Self::Transport(err.to_string())
    }
}

fn load_key(data_dir: &Path, key_file: Option<&Path>) -> Result<LocalPassportKey, IdentityCliError> {
    let result = match key_file {
        Some(path) => LocalPassportKey::from_path(path),
        None => LocalPassportKey::from_data_dir(data_dir),
    };
    result.map_err(|e| IdentityCliError::Passport(format!("{e:?}")))
}

/// `identity fpr` — the identity card the operator carries to the peer.
pub fn run_identity_fpr(data_dir: &Path, key_file: Option<&Path>) -> Result<serde_json::Value, IdentityCliError> {
    let key = load_key(data_dir, key_file)?;
    Ok(serde_json::json!({
        "passport_fpr": key.passport_fpr(),
        "public_key_hex": key.public_key_hex(),
    }))
}

#[derive(Debug)]
pub struct SignLinkArgs {
    pub data_dir: PathBuf,
    pub key_file: Option<PathBuf>,
    /// Fingerprint of the passport on the GRANTING daemon.
    pub local_fpr: String,
    /// Fingerprint of the passport being granted memory.read.
    pub remote_fpr: String,
    /// RFC 3339 statement timestamp — must be identical on both sides.
    pub created_at: String,
}

/// `identity sign-link` — sign the canonical statement hash with this
/// machine's key. Works for either side of the ceremony: the granting
/// daemon signs as `sig_local`, the linked daemon signs as `sig_remote`.
pub fn run_identity_sign_link(args: &SignLinkArgs) -> Result<serde_json::Value, IdentityCliError> {
    let key = load_key(&args.data_dir, args.key_file.as_deref())?;
    let statement = LinkStatement::memory_read(&args.local_fpr, &args.remote_fpr, &args.created_at);
    let hash = statement_hash(&statement);
    let signature = key.sign_hash(&hash);
    Ok(serde_json::json!({
        "statement": statement,
        "statement_hash": format!("blake3:{}", hex::encode(hash)),
        "signed_by_fpr": key.passport_fpr(),
        "signed_by_public_key_hex": key.public_key_hex(),
        "signature": hex::encode(signature),
    }))
}

#[derive(Debug, Clone)]
pub struct ConfirmCandidateArgs {
    pub http_url: Option<String>,
    pub token: Option<String>,
    pub candidate_id: String,
    pub local_passport_id: String,
    pub remote_fpr: String,
    pub remote_public_key_hex: String,
    pub created_at: String,
    pub sig_local: String,
    pub sig_remote: String,
}

#[derive(Debug, Clone)]
pub struct RejectCandidateArgs {
    pub http_url: Option<String>,
    pub token: Option<String>,
    pub candidate_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfirmCandidateRequest {
    pub local_passport_id: String,
    pub remote_fpr: String,
    pub remote_public_key_hex: String,
    pub created_at: String,
    pub sig_local: String,
    pub sig_remote: String,
}

pub fn confirm_candidate_request(args: &ConfirmCandidateArgs) -> ConfirmCandidateRequest {
    ConfirmCandidateRequest {
        local_passport_id: args.local_passport_id.clone(),
        remote_fpr: args.remote_fpr.clone(),
        remote_public_key_hex: args.remote_public_key_hex.clone(),
        created_at: args.created_at.clone(),
        sig_local: args.sig_local.clone(),
        sig_remote: args.sig_remote.clone(),
    }
}

pub fn candidate_action_url(base: &str, candidate_id: &str, action: &str) -> String {
    format!(
        "{}/v1/identity/candidates/{candidate_id}/{action}",
        base.trim_end_matches('/')
    )
}

fn http_base(explicit: Option<&str>) -> String {
    explicit.map_or_else(
        || std::env::var("CORECRUXD_HTTP_URL").unwrap_or_else(|_| "http://127.0.0.1:14800".to_string()),
        ToString::to_string,
    )
}

fn bearer_token(explicit: Option<&str>) -> Option<String> {
    explicit
        .map(ToString::to_string)
        .or_else(|| std::env::var("CRUX_AGENT_TOKEN").ok())
        .filter(|token| !token.is_empty())
}

fn post_json(token: Option<&str>, path: &str, body: impl Serialize) -> Result<serde_json::Value, IdentityCliError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .build()
        .into();
    let mut req = agent.post(path);
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = req.send_json(body).map_err(|e| match e {
        ureq::Error::StatusCode(code) => IdentityCliError::UpstreamStatus {
            status: code,
            body: String::new(),
        },
        other => IdentityCliError::transport(other),
    })?;
    let status = resp.status().as_u16();
    let text = resp.into_body().read_to_string().map_err(IdentityCliError::transport)?;
    if status >= 400 {
        return Err(IdentityCliError::UpstreamStatus { status, body: text });
    }
    serde_json::from_str(&text).map_err(IdentityCliError::from)
}

pub fn run_identity_confirm_candidate(args: &ConfirmCandidateArgs) -> Result<serde_json::Value, IdentityCliError> {
    let base = http_base(args.http_url.as_deref());
    let token = bearer_token(args.token.as_deref());
    let url = candidate_action_url(&base, &args.candidate_id, "confirm");
    post_json(token.as_deref(), &url, confirm_candidate_request(args))
}

pub fn run_identity_reject_candidate(args: &RejectCandidateArgs) -> Result<serde_json::Value, IdentityCliError> {
    let base = http_base(args.http_url.as_deref());
    let token = bearer_token(args.token.as_deref());
    let url = candidate_action_url(&base, &args.candidate_id, "reject");
    post_json(token.as_deref(), &url, serde_json::json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_memory::identity_link::verify_link_signature;

    #[test]
    fn fpr_and_sign_link_round_trip() {
        let dir = tempfile::tempdir().expect("dir");
        let card = run_identity_fpr(dir.path(), None).expect("fpr");
        let fpr = card["passport_fpr"].as_str().expect("fpr str").to_string();
        let pub_hex = card["public_key_hex"].as_str().expect("pub str").to_string();
        assert!(fpr.starts_with("p_"));

        let out = run_identity_sign_link(&SignLinkArgs {
            data_dir: dir.path().to_path_buf(),
            key_file: None,
            local_fpr: "p_granting00000000000000000000000".into(),
            remote_fpr: fpr.clone(),
            created_at: "2026-06-12T00:00:00Z".into(),
        })
        .expect("sign");

        // The emitted signature verifies against the emitted key over the
        // canonical statement hash — exactly what the daemon recomputes.
        let statement = LinkStatement::memory_read("p_granting00000000000000000000000", &fpr, "2026-06-12T00:00:00Z");
        let hash = statement_hash(&statement);
        assert_eq!(
            out["statement_hash"].as_str().expect("hash"),
            format!("blake3:{}", hex::encode(hash))
        );
        verify_link_signature(&pub_hex, &hash, out["signature"].as_str().expect("sig"), "remote").expect("verifies");
    }

    #[test]
    fn confirm_candidate_body_and_url_are_stable() {
        let args = ConfirmCandidateArgs {
            http_url: Some("http://127.0.0.1:14800/".to_string()),
            token: None,
            candidate_id: "cl_abc".to_string(),
            local_passport_id: "personal-default".to_string(),
            remote_fpr: "p_remote".to_string(),
            remote_public_key_hex: "aa".repeat(32),
            created_at: "2026-06-15T00:00:00Z".to_string(),
            sig_local: "bb".repeat(64),
            sig_remote: "cc".repeat(64),
        };
        assert_eq!(
            candidate_action_url(args.http_url.as_deref().expect("url"), &args.candidate_id, "confirm"),
            "http://127.0.0.1:14800/v1/identity/candidates/cl_abc/confirm"
        );
        assert_eq!(
            confirm_candidate_request(&args),
            ConfirmCandidateRequest {
                local_passport_id: "personal-default".to_string(),
                remote_fpr: "p_remote".to_string(),
                remote_public_key_hex: "aa".repeat(32),
                created_at: "2026-06-15T00:00:00Z".to_string(),
                sig_local: "bb".repeat(64),
                sig_remote: "cc".repeat(64),
            }
        );
    }
}
