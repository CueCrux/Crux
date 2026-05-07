// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
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
    #[error("wasm_module_path or wasm_module_url required (M6.4 will add url support); none set")]
    NoModuleSource,
    #[error("wasm_module_url is set but URL download is not yet implemented (M6.4)")]
    UrlDownloadNotYetImplemented,
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

    // M6.3 only handles the local-path case. The url case lands in M6.4
    // (download + verify at install time, then this code path picks up
    // the cached bytes the same way).
    let module_path = if manifest.wasm_module_path.is_some() {
        module_path_for(&data_dir, &extension_id, &manifest)
            .ok_or_else(|| WasmDispatchError::ModuleFileMissing(PathBuf::from("(invalid path)")))?
    } else if manifest.wasm_module_url.is_some() {
        return Err(WasmDispatchError::UrlDownloadNotYetImplemented);
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
            entity: req.entity,
            key: req.key,
            value: req.value,
            source_receipt: None,
            confidence: req.confidence,
            private: false,
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
