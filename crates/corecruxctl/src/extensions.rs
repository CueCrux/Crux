// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl extensions ...` — operator-side tooling for the
//! community-extensions registry (M8 of the community-extensions
//! ExecPlan).
//!
//! Subcommands:
//!
//! - `extensions sync --url ... --pubkey-fpr p_... --pubkey-hex ...`
//!   — HTTPS GET the curator-signed registry index, verify the
//!   signature, and cache the verified document at
//!   `<data-dir>/extensions/registry/index.json`.
//!
//! - `extensions list-registry --data-dir <path>`
//!   — pretty-print the cached registry, including kind + trust tier
//!   + the manifest URL the operator would install from.
//!
//! - `extensions install <id> [--index-path <path>]`
//!   — ask the daemon to install one entry from its verified cached
//!   index (`POST /v1/extensions/install-from-registry`). Install stays
//!   an explicit per-extension action so the operator reviews the
//!   registry entry (`list-registry`) before granting anything; the
//!   daemon, not the CLI, re-verifies the index signature and the
//!   curator-published `manifest_sha256`.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crux_integrations::{CommunityExtensionsIndex, ValidationPolicy};

const REGISTRY_DIR: &str = "extensions/registry";
const REGISTRY_FILENAME: &str = "index.json";

#[derive(Debug, thiserror::Error)]
pub enum ExtensionsCliError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("upstream returned status {0}")]
    UpstreamStatus(u16),
    #[error("download exceeded {0}-byte cap")]
    TooLarge(usize),
    #[error("public_key_hex must be 64 lowercase hex chars")]
    InvalidPubKey,
    #[error("daemon returned {status}: {detail}")]
    DaemonRejected { status: u16, detail: String },
    #[error(transparent)]
    Index(#[from] crux_integrations::IntegrationError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Cap on how large the index document can be. The current planned
/// shape (a few dozen entries × ~200 bytes each) is well under 100 KiB;
/// 1 MiB gives plenty of headroom while bounding a malicious mirror.
pub const REGISTRY_INDEX_DOWNLOAD_LIMIT_BYTES: usize = 1_048_576;

/// Cache path on disk (operator overrides via `--data-dir`).
pub fn cached_index_path(data_dir: &Path) -> PathBuf {
    data_dir.join(REGISTRY_DIR).join(REGISTRY_FILENAME)
}

/// `extensions sync`. Downloads the index from `url`, builds a
/// `ValidationPolicy` whose trusted-keys map carries the operator-
/// supplied curator key, verifies the signature, and writes the
/// verified bytes to the cache path. Returns the verified parsed
/// index for callers (and `corecruxctl` to print a summary).
pub fn sync(
    url: &str,
    curator_passport_fpr: &str,
    curator_public_key_hex: &str,
    data_dir: &Path,
) -> Result<CommunityExtensionsIndex, ExtensionsCliError> {
    if curator_public_key_hex.len() != 64
        || !curator_public_key_hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(ExtensionsCliError::InvalidPubKey);
    }

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .into();
    let mut response = agent
        .get(url)
        .call()
        .map_err(|e| ExtensionsCliError::Transport(e.to_string()))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(ExtensionsCliError::UpstreamStatus(status));
    }

    let mut reader = response.body_mut().as_reader();
    let mut buf = Vec::with_capacity(64 * 1024);
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut chunk).map_err(ExtensionsCliError::Io)?;
        if n == 0 {
            break;
        }
        if buf.len() + n > REGISTRY_INDEX_DOWNLOAD_LIMIT_BYTES {
            return Err(ExtensionsCliError::TooLarge(REGISTRY_INDEX_DOWNLOAD_LIMIT_BYTES));
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    // Parse + verify.
    let index: CommunityExtensionsIndex = serde_json::from_slice(&buf)?;
    let mut policy = ValidationPolicy::default();
    policy
        .trusted_public_keys
        .insert(curator_passport_fpr.to_string(), curator_public_key_hex.to_string());
    index.verify(&policy)?;

    // Persist verified bytes (atomic via .tmp + rename).
    let dest = cached_index_path(data_dir);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = dest.with_extension("json.tmp");
    fs::write(&tmp, &buf)?;
    fs::rename(&tmp, &dest)?;

    Ok(index)
}

/// `extensions list-registry`. Reads the cached index from disk and
/// returns it (caller is `corecruxctl` which prints to stdout).
pub fn list_registry(data_dir: &Path) -> Result<CommunityExtensionsIndex, ExtensionsCliError> {
    let path = cached_index_path(data_dir);
    let bytes = fs::read(&path)?;
    let index: CommunityExtensionsIndex = serde_json::from_slice(&bytes)?;
    Ok(index)
}

/// Inputs for `extensions install`. `index_path` is the daemon-side
/// override (relative paths resolve under the daemon's `data_dir`), not a
/// local path — the CLI never reads the index itself.
#[derive(Debug, Clone)]
pub struct InstallArgs {
    pub id: String,
    pub http_url: Option<String>,
    pub token: Option<String>,
    pub index_path: Option<PathBuf>,
}

/// Daemon base URL: explicit flag → `CORECRUXD_HTTP_URL` → local default.
/// Same precedence as the other daemon-calling subcommands.
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

/// Build the install request body the daemon's `InstallFromRegistryBody`
/// deserialises. Split out so a unit test can freeze the wire shape.
pub fn install_request_body(args: &InstallArgs) -> serde_json::Value {
    match &args.index_path {
        Some(path) => serde_json::json!({ "id": args.id, "index_path": path }),
        None => serde_json::json!({ "id": args.id }),
    }
}

pub fn install_url(base: &str) -> String {
    format!("{}/v1/extensions/install-from-registry", base.trim_end_matches('/'))
}

/// `extensions install`. POSTs to the daemon and returns the parsed
/// response body on 2xx. Non-2xx surfaces the problem+json `detail`
/// verbatim rather than a bare status code.
pub fn install(args: &InstallArgs) -> Result<serde_json::Value, ExtensionsCliError> {
    let base = http_base(args.http_url.as_deref());
    let token = bearer_token(args.token.as_deref());
    let url = install_url(&base);

    // `http_status_as_error(false)` so a 4xx still yields a readable body —
    // the daemon's problem+json `detail` is the whole point of this call.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(60)))
        .http_status_as_error(false)
        .build()
        .into();
    let mut req = agent.post(&url);
    if let Some(token) = &token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let response = req
        .send_json(install_request_body(args))
        .map_err(|e| ExtensionsCliError::Transport(e.to_string()))?;
    let status = response.status().as_u16();
    let text = response
        .into_body()
        .read_to_string()
        .map_err(|e| ExtensionsCliError::Transport(e.to_string()))?;
    if !(200..300).contains(&status) {
        let detail = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("detail").and_then(|d| d.as_str()).map(ToString::to_string))
            .unwrap_or(text);
        return Err(ExtensionsCliError::DaemonRejected { status, detail });
    }
    Ok(serde_json::from_str(&text)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crux_integrations::{CommunityExtensionEntry, EntryKind, TrustTier};
    use std::io::Write as _;
    use std::net::TcpListener;

    fn signed_index_bytes(curator_fpr: &str, signing_key: &ed25519_dalek::SigningKey) -> Vec<u8> {
        let mut idx = CommunityExtensionsIndex::new(curator_fpr, 1_700_000_000_000);
        idx.entries.push(CommunityExtensionEntry {
            id: "ext.example".to_string(),
            name: "Example".to_string(),
            version: "0.1.0".to_string(),
            summary: "Test entry.".to_string(),
            manifest_url: "https://example.com/m.json".to_string(),
            manifest_sha256: "0".repeat(64),
            repo_url: "https://example.com/repo".to_string(),
            kind: EntryKind::ExternalTool,
            trust_tier: TrustTier::CommunityReviewed,
        });
        idx.sign(signing_key).expect("sign");
        serde_json::to_vec(&idx).expect("serialise")
    }

    fn serve_once(bytes: Vec<u8>) -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let _ = crate::test_support::read_full_request(&mut stream);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                bytes.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&bytes);
            let _ = stream.flush();
        });
        (port, handle)
    }

    #[test]
    fn sync_downloads_verifies_and_caches() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xab_u8; 32]);
        let curator_fpr = "p_curator_test";
        let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let bytes = signed_index_bytes(curator_fpr, &signing_key);
        let (port, h) = serve_once(bytes.clone());

        let dir = std::env::temp_dir().join(format!("corecruxctl-sync-{}", uuid::Uuid::new_v4()));
        let url = format!("http://127.0.0.1:{port}/index.json");
        let index = sync(&url, curator_fpr, &pub_hex, &dir).expect("sync");
        h.join().ok();

        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].id, "ext.example");
        // Cached file should exist and parse back.
        let cached = list_registry(&dir).expect("list");
        assert_eq!(cached, index);
    }

    #[test]
    fn sync_rejects_index_signed_by_wrong_key() {
        let real_key = ed25519_dalek::SigningKey::from_bytes(&[0x11_u8; 32]);
        let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0x22_u8; 32]);
        let curator_fpr = "p_real_curator";
        let real_pub = hex::encode(real_key.verifying_key().to_bytes());

        // Index signed by attacker but body claims curator_fpr; the
        // operator's keyring entry holds the REAL curator's key.
        let bytes = signed_index_bytes(curator_fpr, &attacker_key);
        let (port, h) = serve_once(bytes);

        let dir = std::env::temp_dir().join(format!("corecruxctl-sync-bad-{}", uuid::Uuid::new_v4()));
        let url = format!("http://127.0.0.1:{port}/index.json");
        let err = sync(&url, curator_fpr, &real_pub, &dir).err().expect("must fail");
        h.join().ok();

        match err {
            ExtensionsCliError::Index(crux_integrations::IntegrationError::SignatureInvalid)
            | ExtensionsCliError::Index(crux_integrations::IntegrationError::InvalidSignatureMaterial(_)) => {}
            other => panic!("expected SignatureInvalid or InvalidSignatureMaterial, got {other:?}"),
        }
        // Cache must NOT have been written on a verify failure.
        assert!(!cached_index_path(&dir).exists());
    }

    fn install_args(port: u16, id: &str, index_path: Option<PathBuf>) -> InstallArgs {
        InstallArgs {
            id: id.to_string(),
            http_url: Some(format!("http://127.0.0.1:{port}")),
            token: Some("tok-test".to_string()),
            index_path,
        }
    }

    #[test]
    fn install_posts_id_with_bearer_and_returns_body() {
        let body = r#"{"schema":"crux.extensions.registry_install.v1","manifest_sha256":"ab","installed":{"manifest":{"id":"ext.example","version":"0.1.0"},"trust_tier":"community_reviewed"}}"#;
        let (port, h) = crate::test_support::serve_responses(vec![(201, body.to_string())]);

        let out = install(&install_args(port, "ext.example", None)).expect("install");
        let requests = h.join().expect("join stub");

        assert_eq!(out["schema"], "crux.extensions.registry_install.v1");
        assert_eq!(out["installed"]["manifest"]["version"], "0.1.0");
        let req = &requests[0];
        assert!(req.starts_with("POST /v1/extensions/install-from-registry "), "{req}");
        assert!(req.to_lowercase().contains("authorization: bearer tok-test"), "{req}");
        // ureq pretty-prints the JSON body, so match on the field pair
        // rather than a compact-serialised substring.
        assert!(req.contains(r#""id""#) && req.contains(r#""ext.example""#), "{req}");
        // Absent override must not send a null index_path — the daemon's
        // Option<PathBuf> would deserialise it, but the wire stays minimal.
        assert!(!req.contains("index_path"), "{req}");
    }

    #[test]
    fn install_forwards_index_path_override() {
        let (port, h) = crate::test_support::serve_responses(vec![(201, "{}".to_string())]);
        install(&install_args(
            port,
            "ext.example",
            Some(PathBuf::from("mirrors/private/index.json")),
        ))
        .expect("install");
        let requests = h.join().expect("join stub");
        assert!(
            requests[0].contains(r#""index_path""#) && requests[0].contains("mirrors/private/index.json"),
            "{}",
            requests[0]
        );
    }

    #[test]
    fn install_surfaces_problem_json_detail_on_non_2xx() {
        let body = r#"{"type":"about:blank","title":"Not Found","status":404,"detail":"extension 'ext.missing' not found in registry index"}"#;
        let (port, h) = crate::test_support::serve_responses(vec![(404, body.to_string())]);

        let err = install(&install_args(port, "ext.missing", None))
            .err()
            .expect("must fail");
        h.join().ok();

        match err {
            ExtensionsCliError::DaemonRejected { status, detail } => {
                assert_eq!(status, 404);
                assert!(detail.contains("not found in registry index"), "{detail}");
            }
            other => panic!("expected DaemonRejected, got {other:?}"),
        }
    }

    #[test]
    fn install_url_is_stable_and_trims_trailing_slash() {
        assert_eq!(
            install_url("http://127.0.0.1:14800/"),
            "http://127.0.0.1:14800/v1/extensions/install-from-registry"
        );
    }

    #[test]
    fn sync_rejects_invalid_pubkey_format() {
        let dir = std::env::temp_dir().join(format!("corecruxctl-bad-key-{}", uuid::Uuid::new_v4()));
        let err = sync("http://localhost:1", "p_x", "not-hex", &dir)
            .err()
            .expect("must fail");
        assert!(matches!(err, ExtensionsCliError::InvalidPubKey));
    }
}
