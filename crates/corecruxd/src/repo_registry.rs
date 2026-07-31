// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Tenant-scoped repository registry stored as reserved daemon facts.

use corecrux_memory::fact_store::{FactStore, StoreFact};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

pub const REPO_REGISTRY_PREFIX: &str = "__repo_registry__";
pub const REPO_SCAN_PREFIX: &str = "__repo_scan__";
pub const REPO_FACT_KEY: &str = "content";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoRegistration {
    pub repo_id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clone_url: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    pub enabled: bool,
    pub added_at_unix_ms: u64,
    /// Opaque identity for this exact registration incarnation. Async scans
    /// and watcher completions must match it before persisting.
    #[serde(default)]
    pub generation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_scan_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_queued_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_finished_at_unix_ms: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum RepoRegistryError {
    #[error("invalid tenant id '{0}'")]
    InvalidTenantId(String),
    #[error("invalid repo id '{0}': must be lowercase alphanumeric with - or _, length 1..=96")]
    InvalidRepoId(String),
    #[error("repo '{repo_id}' already exists for tenant '{tenant_id}'")]
    Duplicate { tenant_id: String, repo_id: String },
    #[error("repo '{repo_id}' not found for tenant '{tenant_id}'")]
    NotFound { tenant_id: String, repo_id: String },
    #[error("repo '{repo_id}' for tenant '{tenant_id}' is covered by an active legal hold")]
    LegalHold { tenant_id: String, repo_id: String },
    #[error("repo scan snapshot exceeds its 64 MiB serialized-byte ceiling")]
    SnapshotTooLarge,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn registry_entity(tenant_id: &str, repo_id: &str) -> String {
    format!("{REPO_REGISTRY_PREFIX}::{tenant_id}::{repo_id}")
}

pub fn scan_entity(tenant_id: &str, repo_id: &str) -> String {
    format!("{REPO_SCAN_PREFIX}::{tenant_id}::{repo_id}::latest")
}

pub fn slug(input: &str) -> String {
    let trimmed = input.trim().trim_end_matches('/');
    let leaf = trimmed.rsplit(['/', '\\', ':']).next().unwrap_or(trimmed);
    let leaf = leaf.strip_suffix(".git").unwrap_or(leaf);
    let mut out = String::new();
    let mut last_dash = false;
    for ch in leaf.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let slug = out.trim_matches('-').to_string();
    if slug.is_empty() {
        "repo".to_string()
    } else {
        slug
    }
}

pub fn validate_tenant_id(id: &str) -> Result<(), RepoRegistryError> {
    if id.is_empty() || id.len() > 128 || id.contains("::") {
        return Err(RepoRegistryError::InvalidTenantId(id.to_string()));
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'));
    if ok {
        Ok(())
    } else {
        Err(RepoRegistryError::InvalidTenantId(id.to_string()))
    }
}

pub fn validate_repo_id(id: &str) -> Result<(), RepoRegistryError> {
    if id.is_empty() || id.len() > 96 {
        return Err(RepoRegistryError::InvalidRepoId(id.to_string()));
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(RepoRegistryError::InvalidRepoId(id.to_string()))
    }
}

pub fn list_repos(store: &FactStore, tenant_id: &str) -> Vec<RepoRegistration> {
    let prefix = format!("{REPO_REGISTRY_PREFIX}::{tenant_id}::");
    let mut repos = Vec::new();
    for fact in store.latest_by_entity_prefix("default", &prefix, Some(REPO_FACT_KEY)) {
        if let Ok(registration) = serde_json::from_str::<RepoRegistration>(&fact.value) {
            repos.push(registration);
        }
    }
    repos.sort_by(|a, b| a.repo_id.cmp(&b.repo_id));
    repos
}

pub fn list_all_repos(store: &FactStore) -> Vec<RepoRegistration> {
    let mut repos = Vec::new();
    for fact in store.latest_by_entity_prefix("default", &format!("{REPO_REGISTRY_PREFIX}::"), Some(REPO_FACT_KEY)) {
        if let Ok(registration) = serde_json::from_str::<RepoRegistration>(&fact.value) {
            repos.push(registration);
        }
    }
    repos.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id).then_with(|| a.repo_id.cmp(&b.repo_id)));
    repos
}

fn list_all_repos_for_recovery(store: &FactStore) -> Result<Vec<RepoRegistration>, RepoRegistryError> {
    let mut repos = Vec::new();
    for fact in store.latest_by_entity_prefix("default", &format!("{REPO_REGISTRY_PREFIX}::"), Some(REPO_FACT_KEY)) {
        let registration = serde_json::from_str::<RepoRegistration>(&fact.value).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "cannot decode live repository registration '{}' from fact '{}': {error}",
                    fact.entity, fact.fact_id
                ),
            )
        })?;
        validate_tenant_id(&registration.tenant_id).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid tenant identity in live repository registration '{}': {error}",
                    fact.entity
                ),
            )
        })?;
        validate_repo_id(&registration.repo_id).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid repo identity in live repository registration '{}': {error}",
                    fact.entity
                ),
            )
        })?;
        let expected_entity = registry_entity(&registration.tenant_id, &registration.repo_id);
        if fact.entity != expected_entity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "repository registration identity mismatch: fact entity '{}' encodes a different repository than '{}'",
                    fact.entity, expected_entity
                ),
            )
            .into());
        }
        repos.push(registration);
    }
    repos.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id).then_with(|| a.repo_id.cmp(&b.repo_id)));
    Ok(repos)
}

pub fn get_repo(store: &FactStore, tenant_id: &str, repo_id: &str) -> Option<RepoRegistration> {
    let entity = registry_entity(tenant_id, repo_id);
    store
        .latest_by_entity_prefix("default", &entity, Some(REPO_FACT_KEY))
        .into_iter()
        .filter(|fact| fact.entity == entity)
        .find_map(|fact| serde_json::from_str::<RepoRegistration>(&fact.value).ok())
}

pub fn store_repo(store: &mut FactStore, registration: &RepoRegistration) -> Result<(), RepoRegistryError> {
    validate_tenant_id(&registration.tenant_id)?;
    validate_repo_id(&registration.repo_id)?;
    if get_repo(store, &registration.tenant_id, &registration.repo_id).is_some()
        && scan_storage_held(store, &registration.tenant_id, &registration.repo_id)
    {
        return Err(RepoRegistryError::LegalHold {
            tenant_id: registration.tenant_id.clone(),
            repo_id: registration.repo_id.clone(),
        });
    }
    let value = serde_json::to_string(registration)?;
    store.try_replace_latest_daemon_control(StoreFact {
        tenant_hash: "default".to_string(),
        entity: registry_entity(&registration.tenant_id, &registration.repo_id),
        key: REPO_FACT_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
    })?;
    Ok(())
}

pub fn create_repo(store: &mut FactStore, registration: &RepoRegistration) -> Result<(), RepoRegistryError> {
    if get_repo(store, &registration.tenant_id, &registration.repo_id).is_some() {
        return Err(RepoRegistryError::Duplicate {
            tenant_id: registration.tenant_id.clone(),
            repo_id: registration.repo_id.clone(),
        });
    }
    store_repo(store, registration)
}

pub fn fail_incomplete_scans(
    store: &mut FactStore,
    error: &str,
    finished_at_unix_ms: u64,
) -> Result<usize, RepoRegistryError> {
    let mut updated = 0usize;
    for mut registration in list_all_repos(store) {
        let Some(status) = registration.scan_status.as_deref() else {
            continue;
        };
        if !matches!(status, "pending" | "running") {
            continue;
        }
        registration.scan_status = Some("failed".to_string());
        registration.scan_error = Some(error.to_string());
        registration.scan_finished_at_unix_ms = Some(finished_at_unix_ms);
        store_repo(store, &registration)?;
        updated = updated.saturating_add(1);
    }
    Ok(updated)
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanPointer {
    schema_version: u8,
    scan_id: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RepoScanRecoveryReport {
    pub registrations_compacted: usize,
    pub legacy_scans_migrated: usize,
    pub legacy_scans_quarantined: usize,
    pub orphan_files_removed: usize,
}

pub(crate) const MAX_SCAN_SNAPSHOT_BYTES: u64 = crate::repo_scan_policy::MAX_DURABLE_SCAN_OUTPUT_BYTES;
const SNAPSHOT_TOO_LARGE_IO_MESSAGE: &str = "repo scan snapshot exceeds its serialized-byte ceiling";

fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct CappedWriter<W> {
    inner: W,
    written: u64,
    limit: u64,
}

impl<W: std::io::Write> std::io::Write for CappedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if (bytes.len() as u64) > self.limit.saturating_sub(self.written) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                SNAPSHOT_TOO_LARGE_IO_MESSAGE,
            ));
        }
        let written = self.inner.write(bytes)?;
        self.written = self.written.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn scan_snapshot_path(data_dir: &Path, tenant_id: &str, repo_id: &str, scan_id: &str) -> PathBuf {
    let mut repo_hasher = blake3::Hasher::new();
    repo_hasher.update(tenant_id.as_bytes());
    repo_hasher.update(b"\0");
    repo_hasher.update(repo_id.as_bytes());
    let repo_key = repo_hasher.finalize().to_hex();
    let scan_key = blake3::hash(scan_id.as_bytes()).to_hex();
    data_dir
        .join("repo-scans-v1")
        .join(repo_key.as_str())
        .join(format!("{scan_key}.json"))
}

/// Sidecars live below a daemon-owned data directory. Local principals able to
/// replace components inside that directory are already inside the daemon's
/// trusted-storage boundary; nevertheless, reject pre-existing linked roots
/// and per-repository parents before any path-based I/O so an accidental or
/// stale link cannot redirect recovery, publication, reads, or cleanup.
fn validate_scan_storage_root(data_dir: &Path) -> Result<(), RepoRegistryError> {
    let root = data_dir.join("repo-scans-v1");
    match std::fs::symlink_metadata(&root) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "repo scan storage root is not a real directory",
        )
        .into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn reject_scan_repo_directory_symlink(path: &Path) -> Result<(), RepoRegistryError> {
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::other("scan snapshot path has no parent").into());
    };
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "repo scan storage repository component must not be a symlink",
        )
        .into()),
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn publish_scan_snapshot(
    final_path: &Path,
    write_payload: impl FnOnce(&mut CappedWriter<std::io::BufWriter<std::fs::File>>) -> Result<(), RepoRegistryError>,
) -> Result<(), RepoRegistryError> {
    publish_scan_snapshot_with_parent_sync(final_path, write_payload, |parent| {
        std::fs::File::open(parent)?.sync_all()
    })
}

fn publish_scan_snapshot_with_parent_sync(
    final_path: &Path,
    write_payload: impl FnOnce(&mut CappedWriter<std::io::BufWriter<std::fs::File>>) -> Result<(), RepoRegistryError>,
    sync_parent: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<(), RepoRegistryError> {
    let parent = final_path
        .parent()
        .ok_or_else(|| std::io::Error::other("scan snapshot path has no parent"))?;
    ensure_private_directory_durable(parent)?;
    let temp_path = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    let mut published = false;
    let write_result = (|| -> Result<(), RepoRegistryError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&temp_path)?;
        let mut writer = CappedWriter {
            inner: std::io::BufWriter::new(file),
            written: 0,
            limit: MAX_SCAN_SNAPSHOT_BYTES,
        };
        write_payload(&mut writer)?;
        writer.flush()?;
        writer.inner.get_ref().sync_all()?;
        drop(writer);
        std::fs::rename(&temp_path, final_path)?;
        published = true;
        sync_parent(parent)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
        if published {
            tracing::warn!(
                path=%final_path.display(),
                "repo-scan-snapshot-published-with-indeterminate-parent-durability"
            );
        }
    }
    write_result?;
    Ok(())
}

fn ensure_private_directory_durable(path: &Path) -> Result<(), RepoRegistryError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => return Ok(()),
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("repo scan storage component is not a directory: {}", path.display()),
            )
            .into())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("repo scan storage directory has no parent"))?;
    ensure_private_directory_durable(parent)?;
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.file_type().is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("repo scan storage component is not a directory: {}", path.display()),
                )
                .into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    std::fs::File::open(path)?.sync_all()?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Serialize one scan directly to a private, atomically-published sidecar.
/// The scan never becomes a nested FactStore JSON string.
pub fn write_scan_snapshot(
    data_dir: &Path,
    tenant_id: &str,
    repo_id: &str,
    scan: &crate::workspace_scan::WorkspaceScan,
) -> Result<PendingScanSnapshot, RepoRegistryError> {
    validate_tenant_id(tenant_id)?;
    validate_repo_id(repo_id)?;
    validate_scan_storage_root(data_dir)?;
    let final_path = scan_snapshot_path(data_dir, tenant_id, repo_id, &scan.scan_id);
    reject_scan_repo_directory_symlink(&final_path)?;
    let result = publish_scan_snapshot(&final_path, |writer| {
        serde_json::to_writer(writer, scan)?;
        Ok(())
    });
    if result
        .as_ref()
        .is_err_and(|error| error.to_string().contains(SNAPSHOT_TOO_LARGE_IO_MESSAGE))
    {
        return Err(RepoRegistryError::SnapshotTooLarge);
    }
    result?;
    Ok(PendingScanSnapshot {
        data_dir: data_dir.to_path_buf(),
        tenant_id: tenant_id.to_string(),
        repo_id: repo_id.to_string(),
        scan_id: scan.scan_id.clone(),
        armed: true,
    })
}

pub struct PendingScanSnapshot {
    data_dir: PathBuf,
    tenant_id: String,
    repo_id: String,
    scan_id: String,
    armed: bool,
}

impl PendingScanSnapshot {
    /// Disarm rollback only after the registration selecting this sidecar has
    /// been durably committed.
    pub fn commit(mut self) {
        self.armed = false;
    }

    /// Preserve an orphan candidate when the registration append reached an
    /// indeterminate durability outcome. Startup reconciliation will either
    /// find a replayed selector for it or remove it as an orphan.
    pub fn preserve_for_recovery(mut self) {
        self.armed = false;
    }

    /// Explicitly remove an unselected candidate while the caller holds the
    /// FactStore lock that serializes this decision with legal-hold changes.
    fn rollback(mut self) {
        if let Err(error) = remove_scan_snapshot(&self.data_dir, &self.tenant_id, &self.repo_id, &self.scan_id) {
            tracing::warn!(
                ?error,
                tenant_id=%self.tenant_id,
                repo_id=%self.repo_id,
                scan_id=%self.scan_id,
                "pending-repo-scan-snapshot-rollback-failed"
            );
        }
        self.armed = false;
    }

    /// Resolve a failed selector commit while the caller still holds the
    /// FactStore write lock used by legal-hold mutations.
    ///
    /// A sidecar that was present when a covering hold landed, or whose
    /// selector append has an indeterminate durability outcome, must survive
    /// for startup reconciliation. Every other unselected candidate is
    /// rolled back before the store lock is released so a hold cannot land
    /// between the decision and the unlink.
    pub(crate) fn settle_failed_commit(self, store: &FactStore, error: Option<&RepoRegistryError>) {
        let preserve = store.journal_durability_poisoned()
            || scan_storage_held(store, &self.tenant_id, &self.repo_id)
            || error.is_some_and(|error| {
                matches!(
                    error,
                    RepoRegistryError::Io(io)
                        if corecrux_memory::fact_store::is_durability_indeterminate(io)
                )
            });
        if preserve {
            self.preserve_for_recovery();
        } else {
            self.rollback();
        }
    }
}

impl Drop for PendingScanSnapshot {
    fn drop(&mut self) {
        if self.armed {
            // Cancellation and panic may drop this guard without the
            // FactStore lock that serializes cleanup against legal-hold
            // placement. Preserve the orphan fail-closed; bounded startup
            // reconciliation removes it when no hold or selector covers it.
            tracing::warn!(
                tenant_id=%self.tenant_id,
                repo_id=%self.repo_id,
                scan_id=%self.scan_id,
                "pending-repo-scan-snapshot-preserved-after-owner-drop"
            );
        }
    }
}

fn write_legacy_scan_snapshot(
    data_dir: &Path,
    registration: &RepoRegistration,
    scan_id: &str,
    json: &str,
) -> Result<PathBuf, RepoRegistryError> {
    if json.len() as u64 > MAX_SCAN_SNAPSHOT_BYTES {
        return Err(RepoRegistryError::SnapshotTooLarge);
    }
    let scan: crate::workspace_scan::WorkspaceScan = serde_json::from_str(json)?;
    if scan.scan_id != scan_id {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "legacy repo scan id does not match its registration",
        )
        .into());
    }
    validate_scan_storage_root(data_dir)?;
    let final_path = scan_snapshot_path(data_dir, &registration.tenant_id, &registration.repo_id, scan_id);
    reject_scan_repo_directory_symlink(&final_path)?;
    publish_scan_snapshot(&final_path, |writer| {
        writer.write_all(json.as_bytes())?;
        Ok(())
    })?;
    Ok(final_path)
}

pub fn remove_scan_snapshot(
    data_dir: &Path,
    tenant_id: &str,
    repo_id: &str,
    scan_id: &str,
) -> Result<(), RepoRegistryError> {
    validate_scan_storage_root(data_dir)?;
    let path = scan_snapshot_path(data_dir, tenant_id, repo_id, scan_id);
    reject_scan_repo_directory_symlink(&path)?;
    match std::fs::remove_file(&path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)?.sync_all()?;
                match std::fs::remove_dir(parent) {
                    Ok(()) => {
                        if let Some(root) = parent.parent() {
                            std::fs::File::open(root)?.sync_all()?;
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::NotFound
                        ) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub async fn remove_scan_snapshot_if_unheld_async(
    store: std::sync::Arc<tokio::sync::RwLock<FactStore>>,
    data_dir: PathBuf,
    tenant_id: String,
    repo_id: String,
    scan_id: String,
) -> Result<bool, RepoRegistryError> {
    remove_scan_snapshot_if_unheld_async_with(store, data_dir, tenant_id, repo_id, scan_id, || {}).await
}

async fn remove_scan_snapshot_if_unheld_async_with(
    store: std::sync::Arc<tokio::sync::RwLock<FactStore>>,
    data_dir: PathBuf,
    tenant_id: String,
    repo_id: String,
    scan_id: String,
    before_remove: impl FnOnce() + Send + 'static,
) -> Result<bool, RepoRegistryError> {
    let store_guard = store.read_owned().await;
    if store_guard.journal_durability_poisoned() || scan_storage_held(&store_guard, &tenant_id, &repo_id) {
        return Ok(false);
    }
    tokio::task::spawn_blocking(move || {
        // Keep the owned guard inside the irreversible worker. Cancelling the
        // async caller cannot let a legal-hold writer commit while this unlink
        // is still queued or running.
        let _store_guard = store_guard;
        before_remove();
        remove_scan_snapshot(&data_dir, &tenant_id, &repo_id, &scan_id)
    })
    .await
    .map_err(|error| {
        RepoRegistryError::Io(std::io::Error::other(format!("repo scan cleanup task failed: {error}")))
    })??;
    Ok(true)
}

/// Replace a legacy nested scan fact with a small migration marker.
///
/// New runtime scans are selected exclusively by the durably committed
/// registration and do not write this second control entity.
pub fn store_scan_pointer(
    store: &mut FactStore,
    tenant_id: &str,
    repo_id: &str,
    scan_id: &str,
) -> Result<(), RepoRegistryError> {
    ensure_scan_writable(store, tenant_id, repo_id)?;
    let value = serde_json::to_string(&ScanPointer {
        schema_version: 1,
        scan_id: scan_id.to_string(),
    })?;
    store.try_replace_latest_daemon_control(StoreFact {
        tenant_hash: "default".to_string(),
        entity: scan_entity(tenant_id, repo_id),
        key: REPO_FACT_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
    })?;
    Ok(())
}

pub fn ensure_scan_writable(store: &FactStore, tenant_id: &str, repo_id: &str) -> Result<(), RepoRegistryError> {
    if scan_storage_held(store, tenant_id, repo_id) {
        return Err(RepoRegistryError::LegalHold {
            tenant_id: tenant_id.to_string(),
            repo_id: repo_id.to_string(),
        });
    }
    Ok(())
}

pub fn scan_storage_held(store: &FactStore, tenant_id: &str, repo_id: &str) -> bool {
    [registry_entity(tenant_id, repo_id), scan_entity(tenant_id, repo_id)]
        .iter()
        .any(|entity| !store.covering_legal_holds("default", entity).is_empty())
}

fn is_preservation_backpressure(error: &RepoRegistryError) -> bool {
    matches!(error, RepoRegistryError::LegalHold { .. })
        || matches!(
            error,
            RepoRegistryError::Io(io)
                if matches!(
                    io.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::WouldBlock
                )
        )
}

/// Read the registration-selected scan sidecar, falling back to legacy
/// FactStore payloads written before sidecar migration.
#[cfg(test)]
pub fn load_scan_json(
    data_dir: &Path,
    store: &FactStore,
    registration: &RepoRegistration,
) -> Result<Option<String>, RepoRegistryError> {
    if let Some(snapshot) = load_scan_snapshot_json(data_dir, registration)? {
        return Ok(Some(snapshot));
    }
    Ok(load_legacy_scan_json(store, registration))
}

/// Read and decode a registration-selected scan without blocking an async
/// executor worker on filesystem I/O or a potentially large JSON parse.
pub async fn load_workspace_scan_async(
    data_dir: PathBuf,
    registration: RepoRegistration,
    legacy_json: Option<String>,
    admission: tokio::sync::OwnedSemaphorePermit,
) -> Result<
    (
        Option<crate::workspace_scan::WorkspaceScan>,
        tokio::sync::OwnedSemaphorePermit,
    ),
    RepoRegistryError,
> {
    tokio::task::spawn_blocking(move || {
        let scan: Option<crate::workspace_scan::WorkspaceScan> =
            if let Some(file) = open_scan_snapshot_file(&data_dir, &registration)? {
                let reader = std::io::BufReader::new(file).take(MAX_SCAN_SNAPSHOT_BYTES.saturating_add(1));
                match serde_json::from_reader::<_, crate::workspace_scan::WorkspaceScan>(reader) {
                    Ok(scan) if registration.last_scan_id.as_deref() == Some(scan.scan_id.as_str()) => Some(scan),
                    Ok(_) => match legacy_json {
                        Some(json) => {
                            tracing::warn!(
                                tenant_id=%registration.tenant_id,
                                repo_id=%registration.repo_id,
                                "repo-scan-sidecar-id-mismatch-trying-selected-legacy-fallback"
                            );
                            Some(serde_json::from_str(&json)?)
                        }
                        None => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "repo scan snapshot id does not match its registration",
                            )
                            .into())
                        }
                    },
                    Err(sidecar_error) => match legacy_json {
                        Some(json) => {
                            tracing::warn!(
                                ?sidecar_error,
                                tenant_id=%registration.tenant_id,
                                repo_id=%registration.repo_id,
                                "repo-scan-sidecar-invalid-trying-selected-legacy-fallback"
                            );
                            Some(serde_json::from_str(&json)?)
                        }
                        None => return Err(RepoRegistryError::Json(sidecar_error)),
                    },
                }
            } else {
                legacy_json
                    .map(|json| serde_json::from_str(&json).map_err(RepoRegistryError::from))
                    .transpose()?
            };
        if let (Some(scan), Some(expected_scan_id)) = (scan.as_ref(), registration.last_scan_id.as_deref()) {
            if scan.scan_id != expected_scan_id {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "repo scan snapshot id does not match its registration",
                )
                .into());
            }
        }
        Ok((scan, admission))
    })
    .await
    .map_err(|error| {
        RepoRegistryError::Io(std::io::Error::other(format!(
            "repo scan snapshot task failed: {error}"
        )))
    })?
}

fn open_scan_snapshot_file(
    data_dir: &Path,
    registration: &RepoRegistration,
) -> Result<Option<std::fs::File>, RepoRegistryError> {
    let Some(scan_id) = registration.last_scan_id.as_deref() else {
        return Ok(None);
    };
    validate_scan_storage_root(data_dir)?;
    let path = scan_snapshot_path(data_dir, &registration.tenant_id, &registration.repo_id, scan_id);
    reject_scan_repo_directory_symlink(&path)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    match options.open(&path) {
        Ok(file) => {
            let metadata = file.metadata()?;
            if !metadata.file_type().is_file() || metadata.len() > MAX_SCAN_SNAPSHOT_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "repo scan snapshot is not a bounded regular file",
                )
                .into());
            }
            Ok(Some(file))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn validate_scan_snapshot_identity(
    data_dir: &Path,
    registration: &RepoRegistration,
) -> Result<bool, RepoRegistryError> {
    let Some(file) = open_scan_snapshot_file(data_dir, registration)? else {
        return Ok(false);
    };
    let reader = std::io::BufReader::new(file).take(MAX_SCAN_SNAPSHOT_BYTES.saturating_add(1));
    let scan: crate::workspace_scan::WorkspaceScan = serde_json::from_reader(reader)?;
    Ok(registration.last_scan_id.as_deref() == Some(scan.scan_id.as_str()))
}

/// Load the scan selected by the current registration, retrying when a watcher
/// replaces that registration between the control-plane read and sidecar open.
pub async fn load_registered_workspace_scan_async(
    store: &std::sync::Arc<tokio::sync::RwLock<FactStore>>,
    admission: std::sync::Arc<tokio::sync::Semaphore>,
    data_dir: &Path,
    tenant_id: &str,
    repo_id: &str,
) -> Result<Option<LoadedRepoScan>, RepoRegistryError> {
    let mut admission = admission.try_acquire_owned().map_err(|_| {
        RepoRegistryError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "repository scan admission is busy",
        ))
    })?;
    for _ in 0..3 {
        let (registration, legacy_json) = {
            let store = store.read().await;
            let Some(registration) = get_repo(&store, tenant_id, repo_id) else {
                return Ok(None);
            };
            let legacy_json = registration
                .last_scan_id
                .as_ref()
                .and_then(|_| load_legacy_scan_json(&store, &registration));
            (registration, legacy_json)
        };
        let (loaded, returned_admission) =
            load_workspace_scan_async(data_dir.to_path_buf(), registration.clone(), legacy_json, admission).await?;
        admission = returned_admission;
        let selection_is_current = {
            let store = store.read().await;
            get_repo(&store, tenant_id, repo_id).is_some_and(|current| {
                current.generation_id == registration.generation_id && current.last_scan_id == registration.last_scan_id
            })
        };
        if selection_is_current {
            return Ok(Some(LoadedRepoScan {
                registration,
                scan: loaded,
                admission,
            }));
        }
    }
    Err(RepoRegistryError::Io(std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "repo scan changed repeatedly while it was being loaded",
    )))
}

pub struct LoadedRepoScan {
    pub registration: RepoRegistration,
    pub scan: Option<crate::workspace_scan::WorkspaceScan>,
    pub admission: tokio::sync::OwnedSemaphorePermit,
}

#[cfg(test)]
pub fn load_scan_snapshot_json(
    data_dir: &Path,
    registration: &RepoRegistration,
) -> Result<Option<String>, RepoRegistryError> {
    let Some(file) = open_scan_snapshot_file(data_dir, registration)? else {
        return Ok(None);
    };
    let metadata = file.metadata()?;
    let initial_capacity = usize::try_from(metadata.len().min(16 * 1024 * 1024)).unwrap_or(16 * 1024 * 1024);
    let mut json = String::with_capacity(initial_capacity);
    let mut reader = std::io::BufReader::new(file).take(MAX_SCAN_SNAPSHOT_BYTES.saturating_add(1));
    reader.read_to_string(&mut json)?;
    if json.len() as u64 > MAX_SCAN_SNAPSHOT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "repo scan snapshot exceeds its serialized-byte ceiling",
        )
        .into());
    }
    Ok(Some(json))
}

pub fn load_legacy_scan_json(store: &FactStore, registration: &RepoRegistration) -> Option<String> {
    let json = legacy_scan_json_ref(store, registration)?;
    if json.len() as u64 > MAX_SCAN_SNAPSHOT_BYTES {
        tracing::warn!(
            tenant_id=%registration.tenant_id,
            repo_id=%registration.repo_id,
            bytes=json.len(),
            "legacy-repo-scan-read-blocked-by-size-cap"
        );
        return None;
    }
    Some(json.to_owned())
}

fn legacy_scan_json_ref<'a>(store: &'a FactStore, registration: &RepoRegistration) -> Option<&'a str> {
    let entity = scan_entity(&registration.tenant_id, &registration.repo_id);
    store
        .latest_by_entity_prefix("default", &entity, Some(REPO_FACT_KEY))
        .into_iter()
        .find(|fact| fact.entity == entity)
        .and_then(|fact| {
            serde_json::from_str::<ScanPointer>(&fact.value)
                .err()
                .map(|_| fact.value.as_str())
        })
}

/// Reconcile the daemon-owned scan sidecar directory at startup.
///
/// This is the load-at-startup wiring for `repo-scans-v1`: it migrates legacy
/// nested FactStore scans, collapses old registration histories, removes
/// crash-window temporary/orphan files, and never follows directory symlinks.
/// These files are daemon service state, not content-store companion
/// artifacts, so the content storage allowlist and projection registry do not
/// apply.
pub fn recover_repo_scan_storage(
    data_dir: &Path,
    store: &mut FactStore,
) -> Result<RepoScanRecoveryReport, RepoRegistryError> {
    validate_scan_storage_root(data_dir)?;
    // Recovery is destructive: unlike best-effort list endpoints, it must
    // prove that every live selector decoded with the same tenant/repo
    // identity as its fact envelope before classifying any sidecar as orphan.
    let registrations = list_all_repos_for_recovery(store)?;
    // Validate every selected intermediate component before compacting any
    // registration history or migrating any payload. A linked component is a
    // startup-fatal storage-boundary violation, not quarantinable scan data.
    for registration in &registrations {
        if let Some(scan_id) = registration.last_scan_id.as_deref() {
            let path = scan_snapshot_path(data_dir, &registration.tenant_id, &registration.repo_id, scan_id);
            reject_scan_repo_directory_symlink(&path)?;
        }
    }
    let mut report = RepoScanRecoveryReport::default();
    let mut live_paths = HashSet::new();
    let mut held_repo_dirs = HashSet::new();

    for mut registration in registrations {
        // Rewriting through replace-latest collapses every legacy resident
        // registration version before the daemon starts accepting requests.
        let registration_entity = registry_entity(&registration.tenant_id, &registration.repo_id);
        let registration_versions = store
            .get_by_entity(&registration_entity)
            .into_iter()
            .filter(|fact| fact.tenant_hash == "default" && fact.key == REPO_FACT_KEY)
            .count();
        if registration_versions > 1 {
            if store.covering_legal_holds("default", &registration_entity).is_empty() {
                match store_repo(store, &registration) {
                    Ok(()) => {
                        report.registrations_compacted = report.registrations_compacted.saturating_add(1);
                    }
                    Err(error) if is_preservation_backpressure(&error) => {
                        tracing::warn!(
                            ?error,
                            tenant_id=%registration.tenant_id,
                            repo_id=%registration.repo_id,
                            "repo-registration-history-compaction-deferred-by-preservation-barrier"
                        );
                    }
                    Err(error) => return Err(error),
                }
            } else {
                tracing::warn!(
                    tenant_id=%registration.tenant_id,
                    repo_id=%registration.repo_id,
                    "repo-registration-history-compaction-skipped-for-legal-hold"
                );
            }
        }

        let Some(scan_id) = registration.last_scan_id.clone() else {
            continue;
        };
        let path = scan_snapshot_path(data_dir, &registration.tenant_id, &registration.repo_id, &scan_id);
        let selected_scan_entity = scan_entity(&registration.tenant_id, &registration.repo_id);
        if !store.covering_legal_holds("default", &selected_scan_entity).is_empty() {
            if let Some(parent) = path.parent() {
                held_repo_dirs.insert(parent.to_path_buf());
            }
        }
        let (mut snapshot_exists, snapshot_quarantined) = match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() && metadata.len() <= MAX_SCAN_SNAPSHOT_BYTES => {
                match validate_scan_snapshot_identity(data_dir, &registration) {
                    Ok(true) => (true, false),
                    Ok(false) => {
                        if let Some(parent) = path.parent() {
                            held_repo_dirs.insert(parent.to_path_buf());
                        }
                        report.legacy_scans_quarantined = report.legacy_scans_quarantined.saturating_add(1);
                        tracing::warn!(
                            path=%path.display(),
                            tenant_id=%registration.tenant_id,
                            repo_id=%registration.repo_id,
                            "repo-scan-sidecar-id-mismatch-quarantined"
                        );
                        (false, true)
                    }
                    Err(error) => {
                        if let Some(parent) = path.parent() {
                            held_repo_dirs.insert(parent.to_path_buf());
                        }
                        report.legacy_scans_quarantined = report.legacy_scans_quarantined.saturating_add(1);
                        tracing::warn!(
                            ?error,
                            path=%path.display(),
                            tenant_id=%registration.tenant_id,
                            repo_id=%registration.repo_id,
                            "repo-scan-sidecar-decode-failed"
                        );
                        (false, true)
                    }
                }
            }
            Ok(_) => {
                if let Some(parent) = path.parent() {
                    held_repo_dirs.insert(parent.to_path_buf());
                }
                report.legacy_scans_quarantined = report.legacy_scans_quarantined.saturating_add(1);
                tracing::warn!(
                    path=%path.display(),
                    tenant_id=%registration.tenant_id,
                    repo_id=%registration.repo_id,
                    "repo-scan-sidecar-quarantined"
                );
                (false, true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (false, false),
            Err(error) => {
                if let Some(parent) = path.parent() {
                    held_repo_dirs.insert(parent.to_path_buf());
                }
                report.legacy_scans_quarantined = report.legacy_scans_quarantined.saturating_add(1);
                tracing::warn!(
                    ?error,
                    path=%path.display(),
                    tenant_id=%registration.tenant_id,
                    repo_id=%registration.repo_id,
                    "repo-scan-sidecar-inspection-failed"
                );
                (false, true)
            }
        };
        let mut legacy_scan_present = false;
        if !snapshot_exists && !snapshot_quarantined {
            if let Some(legacy_json) = legacy_scan_json_ref(store, &registration) {
                legacy_scan_present = true;
                match write_legacy_scan_snapshot(data_dir, &registration, &scan_id, legacy_json) {
                    Ok(_) => {
                        snapshot_exists = true;
                        report.legacy_scans_migrated = report.legacy_scans_migrated.saturating_add(1);
                    }
                    Err(error) => {
                        if let Some(parent) = path.parent() {
                            held_repo_dirs.insert(parent.to_path_buf());
                        }
                        report.legacy_scans_quarantined = report.legacy_scans_quarantined.saturating_add(1);
                        tracing::warn!(
                            ?error,
                            tenant_id=%registration.tenant_id,
                            repo_id=%registration.repo_id,
                            "legacy-repo-scan-quarantined"
                        );
                    }
                }
            }
        } else {
            legacy_scan_present = legacy_scan_json_ref(store, &registration).is_some();
        }
        if !snapshot_exists && !snapshot_quarantined && !legacy_scan_present {
            if scan_storage_held(store, &registration.tenant_id, &registration.repo_id) {
                if let Some(parent) = path.parent() {
                    held_repo_dirs.insert(parent.to_path_buf());
                }
            } else {
                registration.last_scan_id = None;
                registration.scan_status = Some("failed".to_string());
                registration.scan_error =
                    Some("selected scan snapshot was unavailable during bounded startup recovery".to_string());
                registration.scan_finished_at_unix_ms = Some(current_unix_ms());
                match store_repo(store, &registration) {
                    Ok(()) => {
                        report.legacy_scans_quarantined = report.legacy_scans_quarantined.saturating_add(1);
                    }
                    Err(error) if is_preservation_backpressure(&error) => {
                        if let Some(parent) = path.parent() {
                            held_repo_dirs.insert(parent.to_path_buf());
                        }
                        tracing::warn!(
                            ?error,
                            tenant_id=%registration.tenant_id,
                            repo_id=%registration.repo_id,
                            "missing-repo-scan-selector-repair-deferred-by-preservation-barrier"
                        );
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        if snapshot_exists {
            live_paths.insert(path);
            if legacy_scan_present {
                if let Err(error) = store_scan_pointer(store, &registration.tenant_id, &registration.repo_id, &scan_id)
                {
                    if is_preservation_backpressure(&error) {
                        tracing::warn!(
                            tenant_id=%registration.tenant_id,
                            repo_id=%registration.repo_id,
                            "repo-scan-pointer-migration-skipped-for-legal-hold"
                        );
                    } else {
                        return Err(error);
                    }
                }
            }
        }
    }

    let root = data_dir.join("repo-scans-v1");
    let root_metadata = match std::fs::symlink_metadata(&root) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if root_metadata
        .as_ref()
        .is_some_and(|metadata| !metadata.file_type().is_dir())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "repo scan storage root is not a real directory",
        )
        .into());
    }
    if !store.active_legal_holds().is_empty() {
        tracing::warn!(
            root=%root.display(),
            "repo-scan-orphan-gc-suppressed-while-legal-holds-are-active"
        );
        return Ok(report);
    }
    if let Some(metadata) = root_metadata {
        debug_assert!(metadata.file_type().is_dir());
        for repo_entry in std::fs::read_dir(&root)? {
            let repo_entry = repo_entry?;
            if held_repo_dirs.contains(&repo_entry.path()) {
                continue;
            }
            if !repo_entry.file_type()?.is_dir() {
                std::fs::remove_file(repo_entry.path())?;
                report.orphan_files_removed = report.orphan_files_removed.saturating_add(1);
                continue;
            }
            for scan_entry in std::fs::read_dir(repo_entry.path())? {
                let scan_entry = scan_entry?;
                let path = scan_entry.path();
                if scan_entry.file_type()?.is_file() && live_paths.contains(&path) {
                    continue;
                }
                if scan_entry.file_type()?.is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unexpected nested directory in repo scan storage",
                    )
                    .into());
                }
                std::fs::remove_file(path)?;
                report.orphan_files_removed = report.orphan_files_removed.saturating_add(1);
            }
            match std::fs::remove_dir(repo_entry.path()) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(report)
}

/// Run destructive startup reconciliation only when the FactStore journal
/// that supplies selectors and legal holds was actually replayed.
///
/// Ephemeral fact mode intentionally leaves any existing durable scan
/// sidecars untouched. An empty in-memory store has no authority to classify
/// them as orphaned.
pub fn recover_repo_scan_storage_on_startup(
    data_dir: &Path,
    store: &mut FactStore,
    fact_persistence_enabled: bool,
) -> Result<RepoScanRecoveryReport, RepoRegistryError> {
    if !fact_persistence_enabled {
        return Ok(RepoScanRecoveryReport::default());
    }
    recover_repo_scan_storage(data_dir, store)
}

pub fn delete_repo(store: &mut FactStore, tenant_id: &str, repo_id: &str) -> Result<(), RepoRegistryError> {
    if get_repo(store, tenant_id, repo_id).is_none() {
        return Err(RepoRegistryError::NotFound {
            tenant_id: tenant_id.to_string(),
            repo_id: repo_id.to_string(),
        });
    }
    if scan_storage_held(store, tenant_id, repo_id) {
        return Err(RepoRegistryError::LegalHold {
            tenant_id: tenant_id.to_string(),
            repo_id: repo_id.to_string(),
        });
    }
    for entity in [
        scan_entity(tenant_id, repo_id),
        crate::repo_codegraph::ids_entity(tenant_id, repo_id),
        crate::repo_codegraph::extdeps_entity(tenant_id, repo_id),
        // Delete the authority-bearing registration last. If an earlier
        // durable tombstone fails, the repo remains visible and retryable.
        registry_entity(tenant_id, repo_id),
    ] {
        let facts = store.get_by_entity(&entity);
        let ids: Vec<(String, String)> = facts
            .into_iter()
            .filter(|fact| !fact.deleted)
            .map(|fact| (fact.tenant_hash.clone(), fact.fact_id.clone()))
            .collect();
        for (tenant_hash, fact_id) in ids {
            store.try_delete(&tenant_hash, &fact_id)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(scan_id: &str) -> crate::workspace_scan::WorkspaceScan {
        crate::workspace_scan::WorkspaceScan {
            scan_id: scan_id.to_string(),
            root_path: "/tmp/repo".to_string(),
            ..Default::default()
        }
    }

    fn registration(repo_id: &str, status: Option<&str>) -> RepoRegistration {
        RepoRegistration {
            repo_id: repo_id.to_string(),
            tenant_id: "tenant-a".to_string(),
            root_path: Some("/tmp/repo".to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            enabled: true,
            added_at_unix_ms: 1,
            generation_id: format!("fixture-{repo_id}"),
            last_scan_id: None,
            scan_status: status.map(str::to_string),
            scan_error: None,
            scan_queued_at_unix_ms: Some(2),
            scan_finished_at_unix_ms: None,
        }
    }

    #[test]
    fn old_registration_json_decodes_without_scan_fields() {
        let json = r#"{
            "repo_id":"fixture",
            "tenant_id":"tenant-a",
            "root_path":"/tmp/fixture",
            "languages":["rust"],
            "enabled":true,
            "added_at_unix_ms":1,
            "last_scan_id":"ws_1"
        }"#;
        let decoded: RepoRegistration = serde_json::from_str(json).expect("decode old registration");
        assert_eq!(decoded.repo_id, "fixture");
        assert_eq!(decoded.last_scan_id.as_deref(), Some("ws_1"));
        assert!(decoded.scan_status.is_none());
        assert!(decoded.scan_error.is_none());
        assert!(decoded.scan_queued_at_unix_ms.is_none());
        assert!(decoded.scan_finished_at_unix_ms.is_none());
    }

    #[test]
    fn fail_incomplete_scans_marks_pending_and_running_failed() {
        let mut store = FactStore::new();
        for reg in [
            registration("pending", Some("pending")),
            registration("running", Some("running")),
            registration("done", Some("done")),
            registration("legacy", None),
        ] {
            store_repo(&mut store, &reg).expect("store repo");
        }

        let count = fail_incomplete_scans(&mut store, "daemon restarted before scan completed", 99)
            .expect("recover incomplete scans");
        assert_eq!(count, 2);

        let pending = get_repo(&store, "tenant-a", "pending").expect("pending repo");
        assert_eq!(pending.scan_status.as_deref(), Some("failed"));
        assert_eq!(
            pending.scan_error.as_deref(),
            Some("daemon restarted before scan completed")
        );
        assert_eq!(pending.scan_finished_at_unix_ms, Some(99));

        let running = get_repo(&store, "tenant-a", "running").expect("running repo");
        assert_eq!(running.scan_status.as_deref(), Some("failed"));

        let done = get_repo(&store, "tenant-a", "done").expect("done repo");
        assert_eq!(done.scan_status.as_deref(), Some("done"));

        let legacy = get_repo(&store, "tenant-a", "legacy").expect("legacy repo");
        assert!(legacy.scan_status.is_none());
    }

    #[test]
    fn fail_incomplete_scans_surfaces_latest_only_backpressure_to_startup() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let mut store = FactStore::with_persistence(data_dir.path()).expect("durable fact store");
        let mut pending = registration("stale-pending", Some("pending"));
        let mut ceiling_reached = false;
        for version in 0_u64..1024 {
            pending.added_at_unix_ms = version;
            match store_repo(&mut store, &pending) {
                Ok(()) => {}
                Err(RepoRegistryError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    ceiling_reached = true;
                    break;
                }
                Err(error) => panic!("unexpected registration churn failure: {error}"),
            }
        }
        assert!(ceiling_reached, "fixture must reach the bounded stale-history ceiling");

        let error = fail_incomplete_scans(&mut store, "daemon restarted before scan completed", 99)
            .expect_err("startup must not leave an orphaned pending status when repair cannot persist");
        assert!(matches!(
            error,
            RepoRegistryError::Io(ref io) if io.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert_eq!(
            get_repo(&store, "tenant-a", "stale-pending")
                .expect("pending registration remains visible")
                .scan_status
                .as_deref(),
            Some("pending")
        );
    }

    #[test]
    fn exact_registry_and_scan_lookup_do_not_match_prefix_collisions() {
        let mut store = FactStore::new();
        store_repo(&mut store, &registration("repo2", None)).expect("store repo2");
        assert!(get_repo(&store, "tenant-a", "repo").is_none());

        let scan_json = serde_json::to_string(&crate::workspace_scan::WorkspaceScan::default()).expect("scan json");
        store
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: scan_entity("tenant-a", "repo2"),
                key: REPO_FACT_KEY.to_string(),
                value: scan_json,
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            })
            .expect("store repo2 scan");
        assert!(load_legacy_scan_json(&store, &registration("repo", None)).is_none());
    }

    #[test]
    fn pending_snapshot_requires_locked_rollback_and_survives_uncoordinated_drop() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let candidate = scan("scan-pending");
        let path = scan_snapshot_path(data_dir.path(), "tenant-a", "pending", &candidate.scan_id);
        let pending =
            write_scan_snapshot(data_dir.path(), "tenant-a", "pending", &candidate).expect("write pending snapshot");
        assert!(path.is_file());
        drop(pending);
        assert!(
            path.is_file(),
            "an uncoordinated owner drop must preserve the candidate for startup reconciliation"
        );

        remove_scan_snapshot(data_dir.path(), "tenant-a", "pending", &candidate.scan_id).expect("cleanup");
        let rollback =
            write_scan_snapshot(data_dir.path(), "tenant-a", "pending", &candidate).expect("rewrite snapshot");
        rollback.rollback();
        assert!(
            !path.exists(),
            "an explicit locked rollback removes an ordinary failed candidate"
        );

        let committed =
            write_scan_snapshot(data_dir.path(), "tenant-a", "pending", &candidate).expect("rewrite snapshot");
        committed.commit();
        assert!(path.is_file(), "committed sidecar must survive its guard");

        remove_scan_snapshot(data_dir.path(), "tenant-a", "pending", &candidate.scan_id).expect("cleanup");
        let indeterminate =
            write_scan_snapshot(data_dir.path(), "tenant-a", "pending", &candidate).expect("rewrite snapshot");
        indeterminate.preserve_for_recovery();
        assert!(
            path.is_file(),
            "indeterminate commit candidate must survive for startup reconciliation"
        );
    }

    #[test]
    fn cancellation_drop_after_covering_hold_never_unlinks_published_candidate() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let candidate = scan("scan-cancelled-under-hold");
        let path = scan_snapshot_path(data_dir.path(), "tenant-a", "cancelled-under-hold", &candidate.scan_id);
        let pending = write_scan_snapshot(data_dir.path(), "tenant-a", "cancelled-under-hold", &candidate)
            .expect("publish pending snapshot");
        let mut store = FactStore::new();
        store
            .place_legal_hold(corecrux_memory::legal_hold::PlaceLegalHold {
                tenant_id: "tenant-a".to_string(),
                entity_prefixes: vec![scan_entity("tenant-a", "cancelled-under-hold")],
                reason: "fixture cancellation hold".to_string(),
                actor: Some("fixture".to_string()),
            })
            .expect("place hold");

        drop(pending);

        assert!(scan_storage_held(&store, "tenant-a", "cancelled-under-hold"));
        assert!(
            path.is_file(),
            "cancellation cleanup outside the store lock must fail closed"
        );
    }

    #[test]
    fn hold_landing_after_publish_preserves_failed_commit_candidate() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let candidate = scan("scan-held-before-selector");
        let path = scan_snapshot_path(data_dir.path(), "tenant-a", "held-before-selector", &candidate.scan_id);
        let pending = write_scan_snapshot(data_dir.path(), "tenant-a", "held-before-selector", &candidate)
            .expect("publish pending snapshot");
        let mut store = FactStore::new();
        store
            .place_legal_hold(corecrux_memory::legal_hold::PlaceLegalHold {
                tenant_id: "tenant-a".to_string(),
                entity_prefixes: vec![scan_entity("tenant-a", "held-before-selector")],
                reason: "hold lands between sidecar publication and selector commit".to_string(),
                actor: Some("fixture".to_string()),
            })
            .expect("place hold");
        let error = ensure_scan_writable(&store, "tenant-a", "held-before-selector")
            .expect_err("covering hold must reject the selector commit");

        pending.settle_failed_commit(&store, Some(&error));

        assert!(
            path.is_file(),
            "a sidecar already present when the hold landed must not be unlinked"
        );
    }

    #[tokio::test]
    async fn indeterminate_hold_append_preserves_all_coordinated_sidecar_cleanup_until_replay() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let pending_scan = scan("scan-pending-poison");
        let pending_path = scan_snapshot_path(data_dir.path(), "tenant-a", "pending-poison", &pending_scan.scan_id);
        let pending = write_scan_snapshot(data_dir.path(), "tenant-a", "pending-poison", &pending_scan)
            .expect("publish pending candidate");

        let cleanup_scan = scan("scan-cleanup-poison");
        let cleanup_path = scan_snapshot_path(data_dir.path(), "tenant-a", "cleanup-poison", &cleanup_scan.scan_id);
        write_scan_snapshot(data_dir.path(), "tenant-a", "cleanup-poison", &cleanup_scan)
            .expect("publish cleanup candidate")
            .commit();

        let mut store = FactStore::with_persistence(data_dir.path()).expect("durable fact store");
        store.fail_next_durable_append_after_write_for_test();
        store
            .place_legal_hold(corecrux_memory::legal_hold::PlaceLegalHold {
                tenant_id: "tenant-a".to_string(),
                entity_prefixes: vec![format!("{REPO_SCAN_PREFIX}::tenant-a::")],
                reason: "indeterminate hold append fixture".to_string(),
                actor: Some("fixture".to_string()),
            })
            .expect_err("injected post-write failure must be indeterminate");
        assert!(store.journal_durability_poisoned());
        assert!(
            store.active_legal_holds().is_empty(),
            "failed caller must not observe a resident hold before replay"
        );

        pending.settle_failed_commit(&store, None);
        assert!(
            pending_path.is_file(),
            "poisoned selector state must preserve a newly published candidate"
        );

        let store = std::sync::Arc::new(tokio::sync::RwLock::new(store));
        let removed = remove_scan_snapshot_if_unheld_async(
            store.clone(),
            data_dir.path().to_path_buf(),
            "tenant-a".to_string(),
            "cleanup-poison".to_string(),
            cleanup_scan.scan_id,
        )
        .await
        .expect("poison barrier check");
        assert!(!removed);
        assert!(
            cleanup_path.is_file(),
            "poisoned authority must suppress old-sidecar cleanup"
        );
        drop(store);

        let replayed = FactStore::with_persistence(data_dir.path()).expect("replay indeterminate append");
        assert!(
            scan_storage_held(&replayed, "tenant-a", "pending-poison"),
            "the possibly committed hold must become authoritative after replay"
        );
        assert!(scan_storage_held(&replayed, "tenant-a", "cleanup-poison"));
    }

    #[test]
    fn ephemeral_startup_does_not_gc_durable_scan_storage_without_replayed_authority() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let candidate = scan("scan-from-persistent-run");
        let path = scan_snapshot_path(data_dir.path(), "tenant-a", "persistent-run", &candidate.scan_id);
        write_scan_snapshot(data_dir.path(), "tenant-a", "persistent-run", &candidate)
            .expect("publish durable sidecar")
            .preserve_for_recovery();
        let mut empty_ephemeral_store = FactStore::new();

        let report = recover_repo_scan_storage_on_startup(data_dir.path(), &mut empty_ephemeral_store, false)
            .expect("ephemeral startup must skip reconciliation");

        assert_eq!(report, RepoScanRecoveryReport::default());
        assert!(
            path.is_file(),
            "an empty ephemeral store has no authority to unlink durable sidecars"
        );
    }

    #[test]
    fn post_rename_parent_sync_failure_preserves_candidate_for_recovery() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let final_path = data_dir.path().join("repo-scans-v1").join("fixture").join("scan.json");
        let error = publish_scan_snapshot_with_parent_sync(
            &final_path,
            |writer| {
                writer.write_all(br#"{"scan_id":"fixture"}"#)?;
                Ok(())
            },
            |_| Err(std::io::Error::other("injected parent sync failure")),
        )
        .expect_err("failed durability fence must not publish");
        assert!(error.to_string().contains("injected parent sync failure"));
        assert!(
            final_path.is_file(),
            "a renamed candidate with indeterminate directory durability must survive for startup reconciliation"
        );
        let parent = final_path.parent().expect("snapshot parent");
        assert!(
            std::fs::read_dir(parent)
                .expect("read snapshot parent")
                .all(|entry| !entry.expect("entry").file_name().to_string_lossy().ends_with(".tmp")),
            "rollback must remove temporary files"
        );
    }

    #[tokio::test]
    async fn runtime_loader_rejects_snapshot_id_mismatch() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let mut registration = registration("mismatch", Some("done"));
        registration.last_scan_id = Some("expected".to_string());
        let path = scan_snapshot_path(data_dir.path(), "tenant-a", "mismatch", "expected");
        publish_scan_snapshot(&path, |writer| {
            serde_json::to_writer(writer, &scan("different"))?;
            Ok(())
        })
        .expect("publish mismatched fixture");
        let permit = std::sync::Arc::new(tokio::sync::Semaphore::new(1))
            .acquire_owned()
            .await
            .expect("permit");
        let error = load_workspace_scan_async(data_dir.path().to_path_buf(), registration, None, permit)
            .await
            .expect_err("mismatched identity must fail");
        assert!(error.to_string().contains("id does not match"));
    }

    #[tokio::test]
    async fn registration_selecting_no_scan_never_serves_stale_legacy_payload() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let mut store = FactStore::new();
        let registration = registration("no-selection", Some("pending"));
        store_repo(&mut store, &registration).expect("store registration");
        store
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: scan_entity("tenant-a", "no-selection"),
                key: REPO_FACT_KEY.to_string(),
                value: serde_json::to_string(&scan("stale")).expect("legacy scan"),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            })
            .expect("store stale legacy scan");
        let loaded = load_registered_workspace_scan_async(
            &std::sync::Arc::new(tokio::sync::RwLock::new(store)),
            std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            data_dir.path(),
            "tenant-a",
            "no-selection",
        )
        .await
        .expect("load registration")
        .expect("registration exists");
        assert!(
            loaded.scan.is_none(),
            "last_scan_id=None is authoritative and must not fall back to legacy content"
        );
    }

    #[test]
    fn startup_recovery_quarantines_corrupt_or_mismatched_sidecars() {
        for (repo_id, payload) in [
            ("corrupt", b"{not-json".as_slice()),
            ("mismatch", br#"{"scan_id":"different"}"#.as_slice()),
        ] {
            let data_dir = tempfile::tempdir().expect("temp data dir");
            let mut store = FactStore::new();
            let mut registration = registration(repo_id, Some("done"));
            registration.last_scan_id = Some("expected".to_string());
            store_repo(&mut store, &registration).expect("store registration");
            let path = scan_snapshot_path(data_dir.path(), "tenant-a", repo_id, "expected");
            publish_scan_snapshot(&path, |writer| {
                writer.write_all(payload)?;
                Ok(())
            })
            .expect("publish invalid fixture");

            let report = recover_repo_scan_storage(data_dir.path(), &mut store).expect("recover scan storage");
            assert_eq!(report.legacy_scans_quarantined, 1, "{repo_id}");
            assert!(path.exists(), "quarantine must preserve evidence for {repo_id}");
        }
    }

    #[tokio::test]
    async fn schema_invalid_same_id_sidecar_falls_back_to_valid_selected_legacy_scan() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let mut store = FactStore::new();
        let mut registration = registration("schema-invalid", Some("done"));
        registration.last_scan_id = Some("expected".to_string());
        store_repo(&mut store, &registration).expect("store registration");
        store
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: scan_entity("tenant-a", "schema-invalid"),
                key: REPO_FACT_KEY.to_string(),
                value: serde_json::to_string(&scan("expected")).expect("valid legacy scan"),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            })
            .expect("store legacy scan");
        let path = scan_snapshot_path(data_dir.path(), "tenant-a", "schema-invalid", "expected");
        publish_scan_snapshot(&path, |writer| {
            writer.write_all(br#"{"scan_id":"expected"}"#)?;
            Ok(())
        })
        .expect("publish schema-invalid sidecar");

        let report = recover_repo_scan_storage(data_dir.path(), &mut store).expect("recover scan storage");
        assert_eq!(report.legacy_scans_quarantined, 1);
        assert!(
            load_legacy_scan_json(&store, &registration).is_some(),
            "valid legacy evidence must remain selected until a full sidecar validates"
        );
        let loaded = load_registered_workspace_scan_async(
            &std::sync::Arc::new(tokio::sync::RwLock::new(store)),
            std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            data_dir.path(),
            "tenant-a",
            "schema-invalid",
        )
        .await
        .expect("load recovered registration")
        .expect("registration exists")
        .scan
        .expect("valid selected legacy fallback");
        assert_eq!(loaded.scan_id, "expected");
    }

    #[tokio::test]
    async fn wrong_id_valid_sidecar_falls_back_to_valid_selected_legacy_scan() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let mut store = FactStore::new();
        let mut registration = registration("wrong-id-valid", Some("done"));
        registration.last_scan_id = Some("expected".to_string());
        store_repo(&mut store, &registration).expect("store registration");
        store
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: scan_entity("tenant-a", "wrong-id-valid"),
                key: REPO_FACT_KEY.to_string(),
                value: serde_json::to_string(&scan("expected")).expect("valid legacy scan"),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            })
            .expect("store legacy scan");
        let path = scan_snapshot_path(data_dir.path(), "tenant-a", "wrong-id-valid", "expected");
        publish_scan_snapshot(&path, |writer| {
            serde_json::to_writer(writer, &scan("different"))?;
            Ok(())
        })
        .expect("publish valid wrong-id sidecar");

        let report = recover_repo_scan_storage(data_dir.path(), &mut store).expect("recover scan storage");
        assert_eq!(report.legacy_scans_quarantined, 1);
        let loaded = load_registered_workspace_scan_async(
            &std::sync::Arc::new(tokio::sync::RwLock::new(store)),
            std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            data_dir.path(),
            "tenant-a",
            "wrong-id-valid",
        )
        .await
        .expect("load recovered registration")
        .expect("registration exists")
        .scan
        .expect("valid selected legacy fallback");
        assert_eq!(loaded.scan_id, "expected");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_async_cleanup_keeps_hold_barrier_inside_blocking_worker() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let candidate = scan("scan-cleanup-cancellation");
        let path = scan_snapshot_path(data_dir.path(), "tenant-a", "cleanup-cancellation", &candidate.scan_id);
        write_scan_snapshot(data_dir.path(), "tenant-a", "cleanup-cancellation", &candidate)
            .expect("publish selected snapshot")
            .commit();
        let store = std::sync::Arc::new(tokio::sync::RwLock::new(FactStore::new()));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let cleanup = tokio::spawn(remove_scan_snapshot_if_unheld_async_with(
            store.clone(),
            data_dir.path().to_path_buf(),
            "tenant-a".to_string(),
            "cleanup-cancellation".to_string(),
            candidate.scan_id,
            move || {
                started_tx.send(()).expect("signal cleanup start");
                release_rx.recv().expect("release cleanup");
            },
        ));
        tokio::task::spawn_blocking(move || {
            started_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("cleanup worker starts")
        })
        .await
        .expect("join start waiter");
        cleanup.abort();

        let writer_store = store.clone();
        let mut writer = tokio::spawn(async move { writer_store.write_owned().await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut writer)
                .await
                .is_err(),
            "cancelling the async owner must not release the worker's read barrier"
        );
        release_tx.send(()).expect("release cleanup worker");
        let mut store_guard = tokio::time::timeout(std::time::Duration::from_secs(1), &mut writer)
            .await
            .expect("writer proceeds after cleanup")
            .expect("join legal-hold writer");
        store_guard
            .place_legal_hold(corecrux_memory::legal_hold::PlaceLegalHold {
                tenant_id: "tenant-a".to_string(),
                entity_prefixes: vec![scan_entity("tenant-a", "cleanup-cancellation")],
                reason: "hold after serialized cleanup".to_string(),
                actor: Some("fixture".to_string()),
            })
            .expect("place hold");
        drop(store_guard);
        assert!(!path.exists(), "unlink completes before the hold can commit");
    }

    #[test]
    fn active_hold_suppresses_orphan_gc_for_non_directory_repo_component() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let mut store = FactStore::new();
        let mut registration = registration("held-shape", Some("done"));
        registration.last_scan_id = Some("expected".to_string());
        store_repo(&mut store, &registration).expect("store registration");
        store
            .place_legal_hold(corecrux_memory::legal_hold::PlaceLegalHold {
                tenant_id: "tenant-a".to_string(),
                entity_prefixes: vec![scan_entity("tenant-a", "held-shape")],
                reason: "preserve malformed scan storage".to_string(),
                actor: Some("fixture".to_string()),
            })
            .expect("place hold");
        let selected = scan_snapshot_path(data_dir.path(), "tenant-a", "held-shape", "expected");
        let repo_component = selected.parent().expect("repo component");
        std::fs::create_dir_all(repo_component.parent().expect("scan root")).expect("create scan root");
        std::fs::write(repo_component, b"quarantined shape").expect("write non-directory repo component");

        let report = recover_repo_scan_storage(data_dir.path(), &mut store).expect("recover scan storage");
        assert_eq!(report.legacy_scans_quarantined, 1);
        assert!(
            repo_component.is_file(),
            "held quarantine evidence must not be unlinked"
        );
    }

    #[test]
    fn logical_tenant_hold_blocks_rescan_delete_recovery_gc_and_compaction() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let selected = scan("selected-before-hold");
        let orphan = scan("published-before-hold");
        let selected_path = scan_snapshot_path(data_dir.path(), "tenant-a", "logical-hold", &selected.scan_id);
        let orphan_path = scan_snapshot_path(data_dir.path(), "tenant-a", "logical-hold", &orphan.scan_id);
        {
            let mut store = FactStore::with_persistence(data_dir.path()).expect("persistent fact store");
            let mut registration = registration("logical-hold", Some("done"));
            store_repo(&mut store, &registration).expect("store initial registration");
            registration.last_scan_id = Some(selected.scan_id.clone());
            store_repo(&mut store, &registration).expect("select scan");
            write_scan_snapshot(data_dir.path(), "tenant-a", "logical-hold", &selected)
                .expect("publish selected scan")
                .commit();
            store_scan_pointer(&mut store, "tenant-a", "logical-hold", "legacy-pointer")
                .expect("store first legacy pointer");
            store_scan_pointer(&mut store, "tenant-a", "logical-hold", &selected.scan_id)
                .expect("replace legacy pointer");
            write_scan_snapshot(data_dir.path(), "tenant-a", "logical-hold", &orphan)
                .expect("publish pre-hold orphan")
                .preserve_for_recovery();
            store
                .place_legal_hold(corecrux_memory::legal_hold::PlaceLegalHold {
                    tenant_id: "tenant-a".to_string(),
                    entity_prefixes: vec![format!("{REPO_SCAN_PREFIX}::tenant-a::logical-hold")],
                    reason: "preserve tenant-a repository evidence".to_string(),
                    actor: Some("fixture".to_string()),
                })
                .expect("place logical tenant hold");

            assert!(scan_storage_held(&store, "tenant-a", "logical-hold"));
            assert!(matches!(
                ensure_scan_writable(&store, "tenant-a", "logical-hold"),
                Err(RepoRegistryError::LegalHold { .. })
            ));
            assert!(matches!(
                store_repo(&mut store, &registration),
                Err(RepoRegistryError::LegalHold { .. })
            ));
            assert!(matches!(
                delete_repo(&mut store, "tenant-a", "logical-hold"),
                Err(RepoRegistryError::LegalHold { .. })
            ));
        }

        let mut replayed = FactStore::with_persistence(data_dir.path()).expect("replay held store");
        assert!(scan_storage_held(&replayed, "tenant-a", "logical-hold"));
        let report = recover_repo_scan_storage(data_dir.path(), &mut replayed).expect("held startup recovery");
        assert_eq!(report.orphan_files_removed, 0);
        assert!(selected_path.is_file());
        assert!(
            orphan_path.is_file(),
            "restart recovery must preserve pre-hold orphan evidence"
        );
        assert!(matches!(
            delete_repo(&mut replayed, "tenant-a", "logical-hold"),
            Err(RepoRegistryError::LegalHold { .. })
        ));
        let compaction = replayed
            .compact_journal()
            .expect_err("logical tenant hold must cover pruned default-tenant scan controls");
        assert_eq!(compaction.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_open_rejects_symlink_and_sparse_oversize_file() {
        use std::os::unix::fs::symlink;

        let data_dir = tempfile::tempdir().expect("temp data dir");
        let mut registration = registration("bounded", Some("done"));
        registration.last_scan_id = Some("expected".to_string());
        let path = scan_snapshot_path(data_dir.path(), "tenant-a", "bounded", "expected");
        ensure_private_directory_durable(path.parent().expect("snapshot parent")).expect("create parent");
        let target = data_dir.path().join("target.json");
        std::fs::write(&target, br#"{"scan_id":"expected"}"#).expect("write target");
        symlink(&target, &path).expect("symlink fixture");
        assert!(open_scan_snapshot_file(data_dir.path(), &registration).is_err());

        std::fs::remove_file(&path).expect("remove symlink");
        let file = std::fs::File::create(&path).expect("create sparse fixture");
        file.set_len(MAX_SCAN_SNAPSHOT_BYTES + 1)
            .expect("extend sparse fixture");
        assert!(open_scan_snapshot_file(data_dir.path(), &registration).is_err());
    }

    #[test]
    fn strict_startup_registry_decode_preserves_sidecars_on_malformed_or_misdirected_values() {
        let assert_rejected = |repo_id: &str, value: String, expected_error: &str| {
            let data_dir = tempfile::tempdir().expect("temp data dir");
            let candidate = scan("strict-recovery");
            let path = scan_snapshot_path(data_dir.path(), "tenant-a", repo_id, &candidate.scan_id);
            write_scan_snapshot(data_dir.path(), "tenant-a", repo_id, &candidate)
                .expect("publish sidecar")
                .commit();
            let mut store = FactStore::new();
            store
                .try_replace_latest_daemon_control(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: registry_entity("tenant-a", repo_id),
                    key: REPO_FACT_KEY.to_string(),
                    value,
                    source_receipt: None,
                    confidence: 1.0,
                    private: true,
                    horizon_class: None,
                    actor: None,
                })
                .expect("store syntactically valid journal envelope");

            let error =
                recover_repo_scan_storage(data_dir.path(), &mut store).expect_err("strict recovery must fail closed");
            assert!(error.to_string().contains(expected_error), "{error}");
            assert!(
                path.is_file(),
                "strict decode failure must occur before orphan classification or GC"
            );
        };

        assert_rejected(
            "malformed",
            "{not-json".to_string(),
            "cannot decode live repository registration",
        );
        assert_rejected(
            "misdirected",
            serde_json::to_string(&registration("different-repo", Some("done"))).expect("registration json"),
            "registration identity mismatch",
        );
    }

    #[cfg(unix)]
    #[test]
    fn startup_recovery_rejects_intermediate_repo_directory_symlink() {
        use std::os::unix::fs::symlink;

        let data_dir = tempfile::tempdir().expect("temp data dir");
        let outside = tempfile::tempdir().expect("outside dir");
        let mut store = FactStore::new();
        let mut registration = registration("linked-parent", Some("done"));
        registration.last_scan_id = Some("expected".to_string());
        store_repo(&mut store, &registration).expect("store registration");
        let selected = scan_snapshot_path(data_dir.path(), "tenant-a", "linked-parent", "expected");
        std::fs::create_dir_all(selected.parent().unwrap().parent().unwrap()).expect("create scan root");
        symlink(outside.path(), selected.parent().unwrap()).expect("link repo component");
        std::fs::write(outside.path().join(selected.file_name().unwrap()), b"outside").expect("outside evidence");

        let error = recover_repo_scan_storage(data_dir.path(), &mut store)
            .expect_err("linked repository storage component must fail startup");
        assert!(error.to_string().contains("must not be a symlink"));
        assert!(
            outside.path().join(selected.file_name().unwrap()).is_file(),
            "recovery must not touch the linked target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn active_hold_does_not_mask_symlinked_scan_storage_root() {
        use std::os::unix::fs::symlink;

        let data_dir = tempfile::tempdir().expect("temp data dir");
        let outside = tempfile::tempdir().expect("outside dir");
        let mut store = FactStore::new();
        store
            .place_legal_hold(corecrux_memory::legal_hold::PlaceLegalHold {
                tenant_id: "default".to_string(),
                entity_prefixes: vec!["unrelated-held-entity".to_string()],
                reason: "fixture".to_string(),
                actor: Some("fixture".to_string()),
            })
            .expect("place hold");
        symlink(outside.path(), data_dir.path().join("repo-scans-v1")).expect("link storage root");

        let error = recover_repo_scan_storage(data_dir.path(), &mut store)
            .expect_err("active hold must not activate a linked storage root");
        assert!(error.to_string().contains("not a real directory"));
    }

    #[test]
    fn startup_recovery_migrates_legacy_scan_and_removes_orphans() {
        let data_dir = tempfile::tempdir().expect("temp data dir");
        let mut store = FactStore::new();
        let mut registration = registration("migrate", Some("done"));
        registration.last_scan_id = Some("scan-fixture".to_string());
        store_repo(&mut store, &registration).expect("store registration");
        let scan = scan("scan-fixture");
        store
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: scan_entity("tenant-a", "migrate"),
                key: REPO_FACT_KEY.to_string(),
                value: serde_json::to_string(&scan).expect("scan json"),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            })
            .expect("store legacy scan");

        let orphan_dir = data_dir.path().join("repo-scans-v1").join("orphan");
        std::fs::create_dir_all(&orphan_dir).expect("create orphan dir");
        let orphan = orphan_dir.join(".crash.tmp");
        std::fs::write(&orphan, b"partial").expect("write orphan");

        let report = recover_repo_scan_storage(data_dir.path(), &mut store).expect("recover scan storage");
        assert_eq!(report.legacy_scans_migrated, 1);
        assert_eq!(report.orphan_files_removed, 1);
        assert!(!orphan.exists());
        assert!(load_legacy_scan_json(&store, &registration).is_none());
        let restored = load_scan_json(data_dir.path(), &store, &registration)
            .expect("load migrated scan")
            .expect("migrated scan");
        let restored: crate::workspace_scan::WorkspaceScan =
            serde_json::from_str(&restored).expect("decode migrated scan");
        assert_eq!(restored.scan_id, "scan-fixture");
    }
}
