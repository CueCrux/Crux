// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Bridge between [`crate::http::extensions::invoke_extension_tool`] and
//! [`crate::wasm_host`] for `kind: wasm` manifests (M6.3 of the
//! community-extensions ExecPlan).
//!
//! Three responsibilities:
//! 1. **Locate the module bytes** — resolve `manifest.wasm_module_path`
//!    relative to `<data_dir>/extensions/{id}/`, with traversal-safety
//!    checks (the validator already rejects absolute / `..` paths but we
//!    re-check belt-and-braces).
//! 2. **Verify SHA-256** of the bytes against
//!    `manifest.wasm_module_sha256`. The daemon refuses to instantiate a
//!    module whose disk bytes don't match the manifest's pinned hash.
//! 3. **Run the call** — `Arc<tokio::sync::RwLock<FactStore>>` is
//!    bridged into a [`HostFactStore`] adapter, the call is wrapped in
//!    `tokio::task::spawn_blocking`, and the resulting outcome is shaped
//!    to match Phase A's [`extension_outbound::DispatchOutcome`] so the
//!    HTTP response is uniform across both kinds.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use corecrux_memory::fact_store::{FactQuery, FactStore, StoreFact};
use crux_integrations::{EntryKind, IntegrationManifest};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::extension_grants::ExtensionGrant;
use crate::wasm_host::{
    dispatch_wasm_tool_with_context, HostFact, HostFactQuery, HostFactStore, HostStoreFact, WasmCallContext,
    WasmConfig, WasmDispatchOutcome, WasmEngine, WasmError,
};

#[derive(Debug, thiserror::Error)]
pub enum WasmDispatchError {
    #[error("manifest entry.kind is not 'wasm' for extension '{0}'")]
    NotWasmKind(String),
    #[error("wasm_module_path or wasm_module_url required; none set")]
    NoModuleSource,
    #[error("wasm_module_url is set but never resolved to a cached path; install path may have skipped the M6.4 download step")]
    UrlNotResolved,
    #[error("wasm_module_sha256 missing in manifest")]
    MissingSha256,
    #[error("wasm module file not found at '{0}'")]
    ModuleFileMissing(PathBuf),
    #[error("module sha256 mismatch: manifest says {expected}, on-disk is {actual}")]
    Sha256Mismatch { expected: String, actual: String },
    #[error("dispatch error: {0}")]
    Dispatch(#[from] WasmError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Resolve the absolute filesystem path to the module bytes for a
/// given installed extension. Traversal-safe (the manifest validator
/// already enforces this; we double-check at the egress).
pub fn module_path_for(data_dir: &Path, extension_id: &str, manifest: &IntegrationManifest) -> Option<PathBuf> {
    let rel = manifest.wasm_module_path.as_deref()?;
    if rel.starts_with('/') || rel.contains("..") {
        return None;
    }
    Some(data_dir.join("extensions").join(extension_id).join(rel))
}

/// Hex-encoded lowercase SHA-256 of the input bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Top-level entry point used by the HTTP dispatcher when
/// `manifest.entry.kind == EntryKind::Wasm`. Caller has already verified
/// that the calling passport holds a grant for the extension and that
/// the tool name is in the grant's allow-list.
///
/// The function spawns a blocking task internally so callers don't have
/// to bridge `tokio` + `wasmtime` themselves.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_wasm_via_http(
    engine: Arc<WasmEngine>,
    config: WasmConfig,
    data_dir: PathBuf,
    fact_store: Arc<RwLock<FactStore>>,
    extension_id: String,
    manifest: IntegrationManifest,
    grant: ExtensionGrant,
    tool_name: String,
    args: serde_json::Value,
    calling_passport_id: String,
    request_id: String,
) -> Result<WasmDispatchOutcome, WasmDispatchError> {
    if manifest.entry.kind != EntryKind::Wasm {
        return Err(WasmDispatchError::NotWasmKind(extension_id));
    }
    let expected_sha = manifest
        .wasm_module_sha256
        .clone()
        .ok_or(WasmDispatchError::MissingSha256)?;

    // The install handler (M6.4) resolves URL→path before persistence.
    // By the time the dispatcher sees a manifest, `wasm_module_path`
    // should always be set; `wasm_module_url` only sticks around if
    // someone bypassed the install flow by writing the record directly,
    // in which case we refuse rather than re-download mid-dispatch.
    let module_path = if manifest.wasm_module_path.is_some() {
        module_path_for(&data_dir, &extension_id, &manifest)
            .ok_or_else(|| WasmDispatchError::ModuleFileMissing(PathBuf::from("(invalid path)")))?
    } else if manifest.wasm_module_url.is_some() {
        return Err(WasmDispatchError::UrlNotResolved);
    } else {
        return Err(WasmDispatchError::NoModuleSource);
    };

    if !module_path.exists() {
        return Err(WasmDispatchError::ModuleFileMissing(module_path));
    }
    let module_bytes = std::fs::read(&module_path)?;
    let actual_sha = sha256_hex(&module_bytes);
    if actual_sha != expected_sha {
        return Err(WasmDispatchError::Sha256Mismatch {
            expected: expected_sha,
            actual: actual_sha,
        });
    }

    let adapter: Arc<dyn HostFactStore> = Arc::new(WasmFactStoreAdapter {
        store: Arc::clone(&fact_store),
    });
    let grant_arc = Arc::new(grant);

    // wasmtime is sync — wrap in spawn_blocking so we don't stall the
    // tokio runtime while the module runs (up to ~1s wall-clock).
    let outcome = tokio::task::spawn_blocking(move || {
        dispatch_wasm_tool_with_context(
            &engine,
            &config,
            &module_bytes,
            WasmCallContext {
                tool_name: &tool_name,
                args: &args,
                calling_passport_id: &calling_passport_id,
                request_id: &request_id,
                extension_id: &extension_id,
                grant: Some(grant_arc),
                fact_store: Some(adapter),
            },
        )
    })
    .await
    .map_err(|e| WasmDispatchError::Dispatch(WasmError::Trap(format!("join error: {e}"))))?
    .map(|(outcome, _)| outcome)?;

    Ok(outcome)
}

/// Adapter from the daemon's real `FactStore` to the wasm host's
/// [`HostFactStore`] trait. Lives entirely inside `spawn_blocking`, so
/// the `tokio::sync::RwLock::blocking_{read,write}` calls are valid.
pub struct WasmFactStoreAdapter {
    pub store: Arc<RwLock<FactStore>>,
}

impl HostFactStore for WasmFactStoreAdapter {
    fn read_fact(&self, entity: &str, key: &str) -> Option<HostFact> {
        let store = self.store.blocking_read();
        let result = store.query(&FactQuery {
            tenant_hash: None,
            query: None,
            entity: Some(entity.to_string()),
            entity_prefix: None,
            top_k: 32,
            token_budget: None,
        });
        let fact = result.facts.iter().find(|f| f.key == key && !f.deleted)?;
        Some(to_host_fact(fact))
    }

    fn store_fact(&self, req: HostStoreFact) -> Result<HostFact, String> {
        let mut store = self.store.blocking_write();
        let mut sf = StoreFact {
            tenant_hash: "default".to_string(),
            entity: req.entity,
            key: req.key,
            value: req.value,
            source_receipt: None,
            confidence: req.confidence,
            private: false,
            horizon_class: None,
        };
        // Final belt-and-braces: even if the grant allowed the prefix,
        // privacy gate has the last word over private prefixes.
        crate::fact_privacy::enforce_global(&mut sf);
        let fact = store.store(sf);
        Ok(to_host_fact(&fact))
    }

    fn query_facts(&self, q: HostFactQuery) -> Vec<HostFact> {
        let store = self.store.blocking_read();
        let result = store.query(&FactQuery {
            tenant_hash: None,
            query: q.query,
            entity: None,
            entity_prefix: q.entity_prefix,
            top_k: if q.top_k == 0 { 16 } else { q.top_k },
            token_budget: None,
        });
        result.facts.iter().filter(|f| !f.deleted).map(to_host_fact).collect()
    }
}

fn to_host_fact(fact: &corecrux_memory::fact_store::Fact) -> HostFact {
    HostFact {
        fact_id: fact.fact_id.clone(),
        entity: fact.entity.clone(),
        key: fact.key.clone(),
        value: fact.value.clone(),
        confidence: fact.confidence,
        stored_at_unix_ms: fact.stored_at.timestamp_millis() as u64,
    }
}

// ── M6.4: install-time module download ───────────────────────────────────

/// Cap on how big a downloaded `.wasm` can be. Real community modules
/// are typically <1 MiB; 16 MiB gives plenty of headroom while
/// stopping a malicious or accidentally-huge URL from filling the
/// daemon's data dir.
pub const WASM_MODULE_DOWNLOAD_LIMIT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum WasmDownloadError {
    #[error("module download failed: {0}")]
    Transport(String),
    #[error("module download upstream returned status {0}")]
    UpstreamStatus(u16),
    #[error("module download exceeded the {WASM_MODULE_DOWNLOAD_LIMIT_BYTES}-byte cap")]
    TooLarge,
    #[error("module sha256 mismatch: manifest says {expected}, downloaded bytes are {actual}")]
    Sha256Mismatch { expected: String, actual: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Sync (blocking) download of a `.wasm` module URL into the per-extension
/// cache directory. Designed to be called from inside
/// `tokio::task::spawn_blocking`.
///
/// On success, returns the absolute path to the cached file (always
/// `<data_dir>/extensions/{id}/extension.wasm`) so the caller can
/// mutate the in-memory manifest to use `wasm_module_path` instead of
/// the URL form before persisting. The original URL is dropped from
/// the persisted record — once cached, the daemon never re-fetches.
///
/// Sha256 is verified against `expected_sha256` BEFORE bytes are
/// written to the destination; a mismatch leaves no partial file.
pub fn download_module_to_cache(
    url: &str,
    expected_sha256: &str,
    data_dir: &Path,
    extension_id: &str,
) -> Result<PathBuf, WasmDownloadError> {
    use std::io::Read as _;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .into();
    let mut response = agent
        .get(url)
        .call()
        .map_err(|e| WasmDownloadError::Transport(e.to_string()))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(WasmDownloadError::UpstreamStatus(status));
    }
    let mut reader = response.body_mut().as_reader();
    let mut buf = Vec::with_capacity(64 * 1024);
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut chunk).map_err(WasmDownloadError::Io)?;
        if n == 0 {
            break;
        }
        if buf.len() + n > WASM_MODULE_DOWNLOAD_LIMIT_BYTES {
            return Err(WasmDownloadError::TooLarge);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let actual = sha256_hex(&buf);
    if actual != expected_sha256 {
        return Err(WasmDownloadError::Sha256Mismatch {
            expected: expected_sha256.to_string(),
            actual,
        });
    }
    let dest_dir = data_dir.join("extensions").join(extension_id);
    std::fs::create_dir_all(&dest_dir).map_err(WasmDownloadError::Io)?;
    let dest = dest_dir.join("extension.wasm");
    let tmp = dest.with_extension("wasm.tmp");
    std::fs::write(&tmp, &buf).map_err(WasmDownloadError::Io)?;
    std::fs::rename(&tmp, &dest).map_err(WasmDownloadError::Io)?;
    Ok(dest)
}

/// Spawn-blocking wrapper for [`download_module_to_cache`] so the HTTP
/// install handler can call it from an async context without holding
/// the tokio runtime.
pub async fn download_module_to_cache_async(
    url: String,
    expected_sha256: String,
    data_dir: PathBuf,
    extension_id: String,
) -> Result<PathBuf, WasmDownloadError> {
    tokio::task::spawn_blocking(move || download_module_to_cache(&url, &expected_sha256, &data_dir, &extension_id))
        .await
        .map_err(|e| WasmDownloadError::Transport(format!("join error: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        // RFC 6234: SHA-256 of "abc"
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn module_path_rejects_traversal() {
        let mut manifest = sample_wasm_manifest();
        manifest.wasm_module_path = Some("../../../etc/passwd".to_string());
        let p = module_path_for(Path::new("/data"), "ext.test", &manifest);
        assert!(p.is_none(), "traversal must be rejected, got {p:?}");
    }

    #[test]
    fn module_path_rejects_absolute() {
        let mut manifest = sample_wasm_manifest();
        manifest.wasm_module_path = Some("/etc/passwd".to_string());
        let p = module_path_for(Path::new("/data"), "ext.test", &manifest);
        assert!(p.is_none(), "absolute path must be rejected, got {p:?}");
    }

    #[test]
    fn module_path_resolves_relative() {
        let mut manifest = sample_wasm_manifest();
        manifest.wasm_module_path = Some("extension.wasm".to_string());
        let p = module_path_for(Path::new("/data"), "ext.test", &manifest).unwrap();
        assert_eq!(p, PathBuf::from("/data/extensions/ext.test/extension.wasm"));
    }

    /// Spin up a one-shot HTTP/1.1 listener on 127.0.0.1:0 that serves
    /// the given bytes as `application/wasm`. Returns the bound port +
    /// a join handle. Used by the M6.4 download tests.
    fn serve_once(bytes: Vec<u8>) -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let handle = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};
            let (mut stream, _) = listener.accept().expect("accept");
            let mut req_buf = [0u8; 4096];
            // Read until we see end-of-headers (we don't actually care
            // about the request beyond consuming it so the writer can
            // proceed without blocking the client on read-after-write).
            let _ = stream.read(&mut req_buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/wasm\r\nContent-Length: {}\r\n\r\n",
                bytes.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&bytes);
            let _ = stream.flush();
        });
        (port, handle)
    }

    /// Same as [`serve_once`] but always returns 404. Used to test the
    /// upstream-status branch.
    fn serve_404() -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let handle = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};
            let (mut stream, _) = listener.accept().expect("accept");
            let _ = stream.read(&mut [0u8; 4096]);
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        });
        (port, handle)
    }

    #[test]
    fn download_happy_path_writes_to_cache_after_sha_check() {
        let bytes = b"\0asm\x01\x00\x00\x00".to_vec(); // minimal wasm header (not a real module, but bytes are bytes for the sha)
        let expected = sha256_hex(&bytes);
        let (port, h) = serve_once(bytes.clone());
        let dir = std::env::temp_dir().join(format!("wasm-dl-test-{}", uuid::Uuid::new_v4()));
        let url = format!("http://127.0.0.1:{port}/module.wasm");
        let dest = download_module_to_cache(&url, &expected, &dir, "ext.dl").expect("download");
        h.join().ok();
        assert_eq!(dest, dir.join("extensions").join("ext.dl").join("extension.wasm"));
        let on_disk = std::fs::read(&dest).expect("read");
        assert_eq!(on_disk, bytes);
    }

    #[test]
    fn download_sha_mismatch_leaves_no_partial_file() {
        let bytes = b"\0asm\x01\x00\x00\x00".to_vec();
        let bogus_sha = sha256_hex(b"different bytes");
        let (port, h) = serve_once(bytes);
        let dir = std::env::temp_dir().join(format!("wasm-dl-bad-{}", uuid::Uuid::new_v4()));
        let url = format!("http://127.0.0.1:{port}/module.wasm");
        let err = download_module_to_cache(&url, &bogus_sha, &dir, "ext.dl-bad")
            .err()
            .expect("err");
        h.join().ok();
        assert!(matches!(err, WasmDownloadError::Sha256Mismatch { .. }), "got {err:?}");
        // Final file must not exist; .tmp may or may not (rename is atomic).
        assert!(!dir
            .join("extensions")
            .join("ext.dl-bad")
            .join("extension.wasm")
            .exists());
    }

    #[test]
    fn download_upstream_404_classifies() {
        let (port, h) = serve_404();
        let dir = std::env::temp_dir().join(format!("wasm-dl-404-{}", uuid::Uuid::new_v4()));
        let url = format!("http://127.0.0.1:{port}/missing.wasm");
        let err = download_module_to_cache(&url, "0".repeat(64).as_str(), &dir, "ext.dl-404")
            .err()
            .expect("err");
        h.join().ok();
        // ureq surfaces 4xx as a Transport error containing the status,
        // older versions surface it via UpstreamStatus — accept either.
        let msg = err.to_string();
        assert!(
            msg.contains("404") || matches!(err, WasmDownloadError::UpstreamStatus(404)),
            "got {msg}"
        );
    }

    fn sample_wasm_manifest() -> IntegrationManifest {
        IntegrationManifest {
            schema: crux_integrations::INTEGRATION_SCHEMA_V1.to_string(),
            id: "ext.test".to_string(),
            name: "Test".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: "p_test".to_string(),
            summary: "Test extension.".to_string(),
            entry: crux_integrations::IntegrationEntry {
                kind: EntryKind::Wasm,
                path: "wasm".to_string(),
            },
            capabilities: vec![],
            network: Default::default(),
            data_access: Default::default(),
            safety: Default::default(),
            hashes: Default::default(),
            signature: None,
            external_tool_endpoint: None,
            tools: vec![],
            wasm_module_path: None,
            wasm_module_url: None,
            wasm_module_sha256: None,
        }
    }
}
