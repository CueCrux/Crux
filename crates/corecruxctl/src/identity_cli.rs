// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
//!
//! The statement layout is shared with the daemon via
//! `corecrux_memory::identity_link` — one canonical byte layout, one
//! signature idiom. Private keys never leave `data_dir/passport.key`.

use std::path::{Path, PathBuf};

use corecrux_memory::identity_link::{statement_hash, LinkStatement};
use crux_session::passport::LocalPassportKey;

#[derive(Debug, thiserror::Error)]
pub enum IdentityCliError {
    #[error("passport key error: {0}")]
    Passport(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
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
}
