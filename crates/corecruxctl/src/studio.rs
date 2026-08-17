// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl studio ...` — operator-side tooling for the central Studio
//! template library (L2 of the `crux-integrations-and-template-library-2026-07-25`
//! ExecPlan).
//!
//! A deliberate mirror of [`crate::extensions`]: same fetch/verify/cache
//! ceremony, same download cap, same atomic-write discipline. Only the schema
//! and the cache directory differ.
//!
//! Subcommands:
//!
//! - `studio sync --url ... --pubkey-fpr p_... --pubkey-hex ...`
//!   — HTTPS GET the curator-signed library index, verify the signature
//!   against the operator-supplied curator key, and cache the verified bytes
//!   at `<data-dir>/studio/library/index.json`.
//!
//! - `studio list-library --data-dir <path>`
//!   — pretty-print the cached library: kind, version, tags, advisory tier,
//!   and the pack URL + sha256 an install would pin against.
//!
//! - `studio install <id>`
//!   — ask the daemon to install one entry from its verified cached index
//!   (`POST /v1/studio/library/{id}/install`). Install stays an explicit
//!   per-entry action so the operator reviews the row (`list-library`) first;
//!   the DAEMON, not the CLI, re-verifies the index signature, pins
//!   `pack_sha256`, and requires the pack itself to be signed.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crux_integrations::{StudioLibraryIndex, ValidationPolicy};

const LIBRARY_DIR: &str = "studio/library";
const LIBRARY_FILENAME: &str = "index.json";

#[derive(Debug, thiserror::Error)]
pub enum StudioCliError {
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

/// Cap on the index document size. Same 1 MiB headroom the community-extensions
/// registry uses — bounds what a malicious mirror can make the CLI buffer.
pub const LIBRARY_INDEX_DOWNLOAD_LIMIT_BYTES: usize = 1_048_576;

/// Cache path on disk (operator overrides via `--data-dir`).
pub fn cached_index_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LIBRARY_DIR).join(LIBRARY_FILENAME)
}

/// `studio sync`. Downloads the index from `url`, builds a [`ValidationPolicy`]
/// carrying the operator-supplied curator key, verifies signature + entry
/// shapes, and only then writes the verified bytes to the cache path (atomic
/// `.tmp` + rename). A verify failure leaves any previously cached index
/// untouched.
pub fn sync(
    url: &str,
    curator_passport_fpr: &str,
    curator_public_key_hex: &str,
    data_dir: &Path,
) -> Result<StudioLibraryIndex, StudioCliError> {
    if curator_public_key_hex.len() != 64
        || !curator_public_key_hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(StudioCliError::InvalidPubKey);
    }

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .into();
    let mut response = agent
        .get(url)
        .call()
        .map_err(|e| StudioCliError::Transport(e.to_string()))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(StudioCliError::UpstreamStatus(status));
    }

    let mut reader = response.body_mut().as_reader();
    let mut buf = Vec::with_capacity(64 * 1024);
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut chunk).map_err(StudioCliError::Io)?;
        if n == 0 {
            break;
        }
        if buf.len() + n > LIBRARY_INDEX_DOWNLOAD_LIMIT_BYTES {
            return Err(StudioCliError::TooLarge(LIBRARY_INDEX_DOWNLOAD_LIMIT_BYTES));
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    // Parse + verify (signature THEN entry shapes — see StudioLibraryIndex::verify).
    let index: StudioLibraryIndex = serde_json::from_slice(&buf)?;
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

/// `studio list-library`. Reads the cached index from disk and returns it
/// (caller is `corecruxctl`, which prints to stdout).
pub fn list_library(data_dir: &Path) -> Result<StudioLibraryIndex, StudioCliError> {
    let path = cached_index_path(data_dir);
    let bytes = fs::read(&path)?;
    let index: StudioLibraryIndex = serde_json::from_slice(&bytes)?;
    Ok(index)
}

/// Inputs for `studio install`. `index_path` is the DAEMON-side override
/// (relative paths resolve under the daemon's `data_dir`), not a local path —
/// the CLI never reads the index itself.
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

/// The install route puts the library id in the PATH, so the body carries only
/// the optional daemon-side index override. Split out so a unit test can freeze
/// the wire shape.
pub fn install_request_body(args: &InstallArgs) -> serde_json::Value {
    match &args.index_path {
        Some(path) => serde_json::json!({ "index_path": path }),
        None => serde_json::json!({}),
    }
}

pub fn install_url(base: &str, id: &str) -> String {
    format!("{}/v1/studio/library/{}/install", base.trim_end_matches('/'), id)
}

/// `studio install`. POSTs to the daemon and returns the parsed response body
/// on 2xx. Non-2xx surfaces the problem+json `detail` verbatim (that is where
/// the "pack is unsigned" / "sha256 mismatch" explanation lives).
pub fn install(args: &InstallArgs) -> Result<serde_json::Value, StudioCliError> {
    let base = http_base(args.http_url.as_deref());
    let token = bearer_token(args.token.as_deref());
    let url = install_url(&base, &args.id);

    // `http_status_as_error(false)` so a 4xx still yields a readable body — the
    // daemon's problem+json `detail` is the whole point of this call.
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
        .map_err(|e| StudioCliError::Transport(e.to_string()))?;
    let status = response.status().as_u16();
    let text = response
        .into_body()
        .read_to_string()
        .map_err(|e| StudioCliError::Transport(e.to_string()))?;
    if !(200..300).contains(&status) {
        let detail = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("detail").and_then(|d| d.as_str()).map(ToString::to_string))
            .unwrap_or(text);
        return Err(StudioCliError::DaemonRejected { status, detail });
    }
    Ok(serde_json::from_str(&text)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crux_integrations::{RcxTier, StudioEntryKind, StudioLibraryEntry};
    use std::io::Write as _;
    use std::net::TcpListener;

    fn signed_index_bytes(curator_fpr: &str, signing_key: &ed25519_dalek::SigningKey) -> Vec<u8> {
        let mut idx = StudioLibraryIndex::new(curator_fpr, 1_700_000_000_000);
        idx.entries.push(StudioLibraryEntry {
            id: "studio.ops-overview".to_string(),
            kind: StudioEntryKind::Pack,
            name: "Ops Overview".to_string(),
            version: "0.1.0".to_string(),
            summary: "Test entry.".to_string(),
            publisher_passport_fpr: "p_publisher".to_string(),
            tags: vec!["ops".to_string()],
            required_tier: Some(RcxTier::Pro),
            pack_url: "https://example.com/pack.json".to_string(),
            pack_sha256: "0".repeat(64),
            repo_url: Some("https://example.com/repo".to_string()),
            preview: Some("12 tiles.".to_string()),
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
        let curator_fpr = "p_curator_studio";
        let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let bytes = signed_index_bytes(curator_fpr, &signing_key);
        let (port, h) = serve_once(bytes);

        let dir = std::env::temp_dir().join(format!("corecruxctl-studio-sync-{}", uuid::Uuid::new_v4()));
        let url = format!("http://127.0.0.1:{port}/index.json");
        let index = sync(&url, curator_fpr, &pub_hex, &dir).expect("sync");
        h.join().ok();

        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].id, "studio.ops-overview");
        assert_eq!(index.entries[0].required_tier_str(), Some("pro"));
        // Cached file should exist and parse back byte-identically.
        let cached = list_library(&dir).expect("list");
        assert_eq!(cached, index);
    }

    #[test]
    fn sync_rejects_index_signed_by_wrong_key() {
        let real_key = ed25519_dalek::SigningKey::from_bytes(&[0x11_u8; 32]);
        let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0x22_u8; 32]);
        let curator_fpr = "p_real_studio_curator";
        let real_pub = hex::encode(real_key.verifying_key().to_bytes());

        // Index signed by the attacker but the body claims curator_fpr; the
        // operator's keyring entry holds the REAL curator's key.
        let bytes = signed_index_bytes(curator_fpr, &attacker_key);
        let (port, h) = serve_once(bytes);

        let dir = std::env::temp_dir().join(format!("corecruxctl-studio-bad-{}", uuid::Uuid::new_v4()));
        let url = format!("http://127.0.0.1:{port}/index.json");
        let err = sync(&url, curator_fpr, &real_pub, &dir).err().expect("must fail");
        h.join().ok();

        match err {
            StudioCliError::Index(crux_integrations::IntegrationError::SignatureInvalid)
            | StudioCliError::Index(crux_integrations::IntegrationError::InvalidSignatureMaterial(_)) => {}
            other => panic!("expected SignatureInvalid or InvalidSignatureMaterial, got {other:?}"),
        }
        // Cache must NOT have been written on a verify failure.
        assert!(!cached_index_path(&dir).exists());
    }

    #[test]
    fn sync_rejects_invalid_pubkey_format() {
        let dir = std::env::temp_dir().join(format!("corecruxctl-studio-key-{}", uuid::Uuid::new_v4()));
        let err = sync("http://localhost:1", "p_x", "not-hex", &dir)
            .err()
            .expect("must fail");
        assert!(matches!(err, StudioCliError::InvalidPubKey));
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
    fn install_posts_id_in_path_with_bearer_and_returns_body() {
        let body = r#"{"schema":"crux.studio.library_install.v1","library_id":"studio.ops-overview","version":"0.1.0","signed":true,"tier_enforcement":"advisory","written":[],"remaps":[]}"#;
        let (port, h) = crate::test_support::serve_responses(vec![(201, body.to_string())]);

        let out = install(&install_args(port, "studio.ops-overview", None)).expect("install");
        let requests = h.join().expect("join stub");

        assert_eq!(out["schema"], "crux.studio.library_install.v1");
        assert_eq!(out["tier_enforcement"], "advisory");
        let req = &requests[0];
        assert!(
            req.starts_with("POST /v1/studio/library/studio.ops-overview/install "),
            "{req}"
        );
        assert!(req.to_lowercase().contains("authorization: bearer tok-test"), "{req}");
        // Absent override keeps the wire minimal — no null index_path.
        assert!(!req.contains("index_path"), "{req}");
    }

    #[test]
    fn install_forwards_index_path_override() {
        let (port, h) = crate::test_support::serve_responses(vec![(201, "{}".to_string())]);
        install(&install_args(
            port,
            "studio.ops-overview",
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
        let body = r#"{"type":"about:blank","title":"Forbidden","status":403,"detail":"pack for 'studio.x' is unsigned; set CORECRUXD_STUDIO_ALLOW_UNSIGNED=1 to bypass in dev"}"#;
        let (port, h) = crate::test_support::serve_responses(vec![(403, body.to_string())]);

        let err = install(&install_args(port, "studio.x", None)).err().expect("must fail");
        h.join().ok();

        match err {
            StudioCliError::DaemonRejected { status, detail } => {
                assert_eq!(status, 403);
                assert!(detail.contains("CORECRUXD_STUDIO_ALLOW_UNSIGNED"), "{detail}");
            }
            other => panic!("expected DaemonRejected, got {other:?}"),
        }
    }

    #[test]
    fn install_url_is_stable_and_trims_trailing_slash() {
        assert_eq!(
            install_url("http://127.0.0.1:14800/", "studio.ops-overview"),
            "http://127.0.0.1:14800/v1/studio/library/studio.ops-overview/install"
        );
    }

    #[test]
    fn cached_index_path_is_under_studio_library() {
        let path = cached_index_path(Path::new("/srv/data"));
        assert!(path.ends_with("studio/library/index.json"), "{}", path.display());
    }
}
