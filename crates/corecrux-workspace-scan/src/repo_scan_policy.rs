// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Startup-frozen containment policy for tenant-triggered repository scans.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::workspace_scan::ScanError;

pub const ALLOWED_ROOTS_ENV: &str = "CORECRUXD_REPO_SCAN_ALLOWED_ROOTS";
pub const MAX_DEPTH_ENV: &str = "CORECRUXD_REPO_SCAN_MAX_DEPTH";
pub const MAX_FILES_ENV: &str = "CORECRUXD_REPO_SCAN_MAX_FILES";
pub const MAX_BYTES_ENV: &str = "CORECRUXD_REPO_SCAN_MAX_BYTES";
pub const MAX_FILE_BYTES_ENV: &str = "CORECRUXD_REPO_SCAN_MAX_FILE_BYTES";
pub const TIMEOUT_SECS_ENV: &str = "CORECRUXD_REPO_SCAN_TIMEOUT_SECS";
pub const MAX_PARSER_ITEMS_ENV: &str = "CORECRUXD_REPO_SCAN_MAX_PARSER_ITEMS";
pub const MAX_GENERATED_ITEMS_ENV: &str = "CORECRUXD_REPO_SCAN_MAX_GENERATED_ITEMS";
pub const MAX_DURABLE_SCAN_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

const DEFAULT_MAX_DEPTH: usize = 64;
const DEFAULT_MAX_FILES: usize = 100_000;
const DEFAULT_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const DEFAULT_TIMEOUT_SECS: u64 = 300;
const DEFAULT_MAX_PARSER_ITEMS: usize = 5_000_000;
const DEFAULT_MAX_GENERATED_ITEMS: usize = 2_000_000;
const MAX_CONFIGURED_PARSER_ITEMS: usize = 20_000_000;
const MAX_CONFIGURED_GENERATED_ITEMS: usize = 10_000_000;
const MAX_CONFIGURED_FILES: usize = 1_000_000;
pub const MAX_CONFIGURED_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepoScanLimits {
    pub max_depth: usize,
    pub max_files: usize,
    pub max_bytes: u64,
    pub max_file_bytes: u64,
    pub max_parser_items: usize,
    pub max_generated_items: usize,
    pub timeout: Duration,
}

impl Default for RepoScanLimits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_files: DEFAULT_MAX_FILES,
            max_bytes: DEFAULT_MAX_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_parser_items: DEFAULT_MAX_PARSER_ITEMS,
            max_generated_items: DEFAULT_MAX_GENERATED_ITEMS,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RepoScanPolicy {
    allowed_roots: Vec<RootAnchor>,
    workspace_root: Option<RootAnchor>,
    limits: RepoScanLimits,
    allow_any_root: bool,
}

#[derive(Debug, Clone)]
struct RootAnchor {
    path: PathBuf,
    directory: Arc<File>,
}

impl RepoScanPolicy {
    pub fn from_env() -> Result<Self, std::io::Error> {
        let mut allowed_roots = match std::env::var_os(ALLOWED_ROOTS_ENV) {
            None => Vec::new(),
            Some(raw) if raw.is_empty() => Vec::new(),
            Some(raw) => std::env::split_paths(&raw)
                .map(|path| root_anchor(&path))
                .collect::<Result<Vec<_>, _>>()?,
        };
        allowed_roots.sort_by(|left, right| left.path.cmp(&right.path));
        allowed_roots.dedup_by(|left, right| left.path == right.path);
        let workspace_root = std::env::var_os("CORECRUXD_WORKSPACE_PATH")
            .filter(|value| !value.is_empty())
            .map(|workspace| root_anchor(Path::new(&workspace)))
            .transpose()?;
        let limits = RepoScanLimits {
            max_depth: parse_positive_env(MAX_DEPTH_ENV, DEFAULT_MAX_DEPTH)?,
            max_files: parse_positive_env(MAX_FILES_ENV, DEFAULT_MAX_FILES)?,
            max_bytes: parse_positive_env(MAX_BYTES_ENV, DEFAULT_MAX_BYTES)?,
            max_file_bytes: parse_positive_env(MAX_FILE_BYTES_ENV, DEFAULT_MAX_FILE_BYTES)?,
            max_parser_items: parse_positive_env(MAX_PARSER_ITEMS_ENV, DEFAULT_MAX_PARSER_ITEMS)?,
            max_generated_items: parse_positive_env(MAX_GENERATED_ITEMS_ENV, DEFAULT_MAX_GENERATED_ITEMS)?,
            timeout: Duration::from_secs(parse_positive_env(TIMEOUT_SECS_ENV, DEFAULT_TIMEOUT_SECS)?),
        };
        if limits.max_file_bytes > limits.max_bytes {
            return Err(invalid_config(format!(
                "{MAX_FILE_BYTES_ENV} must not exceed {MAX_BYTES_ENV}"
            )));
        }
        if limits.max_depth > MAX_CONFIGURED_DEPTH {
            return Err(invalid_config(format!(
                "{MAX_DEPTH_ENV} must not exceed {MAX_CONFIGURED_DEPTH}"
            )));
        }
        if limits.max_files > MAX_CONFIGURED_FILES {
            return Err(invalid_config(format!(
                "{MAX_FILES_ENV} must not exceed {MAX_CONFIGURED_FILES}"
            )));
        }
        if limits.max_parser_items > MAX_CONFIGURED_PARSER_ITEMS {
            return Err(invalid_config(format!(
                "{MAX_PARSER_ITEMS_ENV} must not exceed {MAX_CONFIGURED_PARSER_ITEMS}"
            )));
        }
        if limits.max_generated_items > MAX_CONFIGURED_GENERATED_ITEMS {
            return Err(invalid_config(format!(
                "{MAX_GENERATED_ITEMS_ENV} must not exceed {MAX_CONFIGURED_GENERATED_ITEMS}"
            )));
        }
        Ok(Self {
            allowed_roots,
            workspace_root,
            limits,
            allow_any_root: false,
        })
    }

    /// Direct/operator-owned scans still receive all traversal and work caps,
    /// but their exact root is the allowlist. Tenant HTTP paths never use this
    /// constructor; they receive the startup-frozen `AppState` policy.
    pub fn for_exact_root(root: &Path) -> Result<Self, ScanError> {
        let anchor = root_anchor(root).map_err(ScanError::Io)?;
        Ok(Self {
            allowed_roots: vec![anchor],
            workspace_root: None,
            limits: RepoScanLimits::default(),
            allow_any_root: false,
        })
    }

    #[cfg(test)]
    pub fn allow_any_for_tests() -> Self {
        Self {
            allowed_roots: Vec::new(),
            workspace_root: None,
            limits: RepoScanLimits::default(),
            allow_any_root: true,
        }
    }

    #[cfg(test)]
    pub fn for_test_roots(allowed_roots: Vec<PathBuf>, limits: RepoScanLimits) -> Self {
        Self {
            allowed_roots: allowed_roots
                .into_iter()
                .map(|root| root_anchor(&root).expect("test scan root anchor"))
                .collect(),
            workspace_root: None,
            limits,
            allow_any_root: false,
        }
    }

    pub fn limits(&self) -> RepoScanLimits {
        self.limits
    }

    pub fn allowed_root_count(&self) -> usize {
        self.allowed_roots.len()
    }

    pub fn resolve_root(&self, root: &Path) -> Result<PathBuf, ScanError> {
        if !self.allow_any_root && self.allowed_roots.is_empty() {
            return Err(ScanError::Policy(format!(
                "repository scanning is disabled until {ALLOWED_ROOTS_ENV} is configured"
            )));
        }
        let lexical = normalize_absolute_lexically(root)?;
        if !self.allow_any_root
            && !self
                .allowed_roots
                .iter()
                .any(|allowed| lexical.starts_with(&allowed.path))
        {
            return Err(ScanError::Policy(
                "repository root is outside CORECRUXD_REPO_SCAN_ALLOWED_ROOTS".to_string(),
            ));
        }
        if self.allow_any_root {
            return canonical_scan_root(root);
        }
        // Validate the full descendant through the startup-pinned allowlist
        // descriptor. This rejects symlinks in every component and deliberately
        // maps missing and linked descendants to the same policy error.
        self.open_scan_root(&lexical)?;
        Ok(lexical)
    }

    /// Re-resolve the root and install one shared work budget for the complete
    /// scan. Every walker and scanner read on this thread charges this budget.
    pub fn execute<T>(
        &self,
        root: &Path,
        scan: impl FnOnce(&Path) -> Result<T, ScanError>,
    ) -> Result<T, ScanError> {
        let started = Instant::now();
        let canonical = self.resolve_root(root)?;
        if started.elapsed() > self.limits.timeout {
            return Err(ScanError::Policy(format!(
                "repository scan exceeded {} seconds while resolving its root",
                self.limits.timeout.as_secs()
            )));
        }
        let directory = self.open_scan_root(&canonical)?;
        self.execute_canonical(canonical, directory, started, scan)
    }

    pub fn execute_workspace<T>(
        &self,
        scan: impl FnOnce(&Path) -> Result<T, ScanError>,
    ) -> Result<T, ScanError> {
        let workspace = self.workspace_root.as_ref().ok_or(ScanError::NotConfigured)?;
        let canonical = workspace.path.clone();
        let started = Instant::now();
        self.execute_canonical(canonical, workspace.directory.clone(), started, scan)
    }

    fn open_scan_root(&self, canonical: &Path) -> Result<Arc<File>, ScanError> {
        if self.allow_any_root {
            return root_anchor(canonical)
                .map(|anchor| anchor.directory)
                .map_err(ScanError::Io);
        }
        let anchor = self
            .allowed_roots
            .iter()
            .filter(|anchor| canonical.starts_with(&anchor.path))
            .max_by_key(|anchor| anchor.path.components().count())
            .ok_or_else(|| ScanError::Policy("repository root is outside configured anchors".to_string()))?;
        if canonical == anchor.path {
            let current = std::fs::symlink_metadata(canonical).map_err(|_| {
                ScanError::Policy("repository root is unavailable or changed after configuration".to_string())
            })?;
            if current.file_type().is_symlink() {
                return Err(ScanError::Policy("repository root must not be a symlink".to_string()));
            }
            if !current.is_dir() {
                return Err(ScanError::Policy("repository root must be a directory".to_string()));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;

                let anchored = anchor.directory.metadata().map_err(ScanError::Io)?;
                if current.dev() != anchored.dev() || current.ino() != anchored.ino() {
                    return Err(ScanError::Policy(
                        "repository root changed after its startup anchor was configured".to_string(),
                    ));
                }
            }
            return Ok(anchor.directory.clone());
        }
        let relative = canonical
            .strip_prefix(&anchor.path)
            .map_err(|_| ScanError::Policy("repository root escaped its configured anchor".to_string()))?;
        open_relative_directory(&anchor.directory, relative)
            .map(Arc::new)
            .map_err(|_| {
                ScanError::Policy("repository root is unavailable or contains an unsupported link".to_string())
            })
    }

    fn execute_canonical<T>(
        &self,
        canonical: PathBuf,
        directory: Arc<File>,
        started: Instant,
        scan: impl FnOnce(&Path) -> Result<T, ScanError>,
    ) -> Result<T, ScanError> {
        if self.limits.max_depth > MAX_CONFIGURED_DEPTH {
            return Err(ScanError::Policy(format!(
                "repository scan depth must not exceed {MAX_CONFIGURED_DEPTH}"
            )));
        }
        if self.limits.max_files > MAX_CONFIGURED_FILES {
            return Err(ScanError::Policy(format!(
                "repository scan file limit must not exceed {MAX_CONFIGURED_FILES}"
            )));
        }
        if self.limits.max_parser_items > MAX_CONFIGURED_PARSER_ITEMS
            || self.limits.max_generated_items > MAX_CONFIGURED_GENERATED_ITEMS
        {
            return Err(ScanError::Policy(
                "repository scan parser/generated item limit exceeds its hard ceiling".to_string(),
            ));
        }
        let budget = Rc::new(RefCell::new(ExecutionBudget::new(
            canonical.clone(),
            directory,
            self.limits,
            started,
        )));
        let previous = ACTIVE_SCAN_BUDGET.with(|slot| slot.replace(Some(budget.clone())));
        if previous.is_some() {
            ACTIVE_SCAN_BUDGET.with(|slot| {
                slot.replace(previous);
            });
            return Err(ScanError::Policy("nested repository scan budget".to_string()));
        }
        let guard = ActiveBudgetGuard;

        let result = scan(&canonical);
        let final_check = budget.borrow_mut().check_deadline();
        drop(guard);
        let violation = budget.borrow().violation.clone().map(ScanError::Policy);
        match violation {
            Some(error) => Err(error),
            None => {
                final_check?;
                result
            }
        }
    }
}

fn normalize_absolute_lexically(path: &Path) -> Result<PathBuf, ScanError> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(ScanError::Policy(
            "repository root must be an absolute path".to_string(),
        ));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Ok(normalized)
}

fn canonical_allowed_root(path: &Path) -> Result<PathBuf, std::io::Error> {
    if !path.is_absolute() {
        return Err(invalid_config(format!(
            "{ALLOWED_ROOTS_ENV} entries must be absolute: {}",
            path.display()
        )));
    }
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        invalid_config(format!(
            "cannot canonicalize {ALLOWED_ROOTS_ENV} entry {}: {error}",
            path.display()
        ))
    })?;
    if !canonical.is_dir() {
        return Err(invalid_config(format!(
            "{ALLOWED_ROOTS_ENV} entry is not a directory: {}",
            path.display()
        )));
    }
    Ok(canonical)
}

fn root_anchor(path: &Path) -> Result<RootAnchor, std::io::Error> {
    let canonical = canonical_allowed_root(path)?;
    let directory = open_root_directory(&canonical)?;
    Ok(RootAnchor {
        path: canonical,
        directory: Arc::new(directory),
    })
}

#[cfg(target_os = "linux")]
fn open_root_directory(canonical: &Path) -> Result<File, std::io::Error> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(canonical)?;
    let opened_path = std::fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd()))?;
    if opened_path != canonical {
        return Err(invalid_config(format!(
            "repository scan root changed while its directory anchor was opened: expected {}, opened {}",
            canonical.display(),
            opened_path.display()
        )));
    }
    Ok(directory)
}

#[cfg(not(target_os = "linux"))]
fn open_root_directory(_canonical: &Path) -> Result<File, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "root-anchored repository scanning requires Linux openat2",
    ))
}

#[cfg(target_os = "linux")]
fn open_beneath(directory: &File, relative: &Path, flags: i32) -> Result<File, std::io::Error> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};

    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "repository scan path is not a strict relative path",
        ));
    }
    let flags = OFlags::from_bits(flags as u32)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid openat2 flags"))?;
    rustix::fs::openat2(
        directory,
        relative,
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )
    .map(File::from)
    .map_err(std::io::Error::from)
}

#[cfg(not(target_os = "linux"))]
fn open_beneath(_directory: &File, _relative: &Path, _flags: i32) -> Result<File, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "root-anchored repository scanning requires Linux openat2",
    ))
}

fn open_relative_directory(directory: &File, relative: &Path) -> Result<File, std::io::Error> {
    open_beneath(
        directory,
        relative,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )
}

fn canonical_scan_root(root: &Path) -> Result<PathBuf, ScanError> {
    if !root.is_absolute() {
        return Err(ScanError::Policy(
            "repository root must be an absolute path".to_string(),
        ));
    }
    let metadata = std::fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() {
        return Err(ScanError::Policy("repository root must not be a symlink".to_string()));
    }
    let canonical = std::fs::canonicalize(root)?;
    if !canonical.is_dir() {
        return Err(ScanError::Policy("repository root must be a directory".to_string()));
    }
    Ok(canonical)
}

fn parse_positive_env<T>(name: &str, default: T) -> Result<T, std::io::Error>
where
    T: std::str::FromStr + Copy + PartialOrd + From<u8>,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    let Some(raw) = std::env::var_os(name) else {
        return Ok(default);
    };
    let raw = raw
        .into_string()
        .map_err(|_| invalid_config(format!("{name} must be valid UTF-8")))?;
    let value = raw
        .trim()
        .parse::<T>()
        .map_err(|error| invalid_config(format!("invalid {name}: {error}")))?;
    if value < T::from(1) {
        return Err(invalid_config(format!("{name} must be greater than zero")));
    }
    Ok(value)
}

fn invalid_config(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

thread_local! {
    static ACTIVE_SCAN_BUDGET: RefCell<Option<Rc<RefCell<ExecutionBudget>>>> = const { RefCell::new(None) };
}

struct ActiveBudgetGuard;

impl Drop for ActiveBudgetGuard {
    fn drop(&mut self) {
        ACTIVE_SCAN_BUDGET.with(|slot| {
            slot.replace(None);
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    nlink: u64,
    #[cfg(unix)]
    mtime: i64,
    #[cfg(unix)]
    mtime_nsec: i64,
    #[cfg(unix)]
    ctime: i64,
    #[cfg(unix)]
    ctime_nsec: i64,
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            Self {
                len: metadata.len(),
                dev: metadata.dev(),
                ino: metadata.ino(),
                mode: metadata.mode(),
                nlink: metadata.nlink(),
                mtime: metadata.mtime(),
                mtime_nsec: metadata.mtime_nsec(),
                ctime: metadata.ctime(),
                ctime_nsec: metadata.ctime_nsec(),
            }
        }
        #[cfg(not(unix))]
        {
            Self { len: metadata.len() }
        }
    }

    fn has_single_link(self) -> bool {
        #[cfg(unix)]
        {
            self.nlink == 1
        }
        #[cfg(not(unix))]
        {
            true
        }
    }
}

struct ExecutionBudget {
    root: PathBuf,
    directory: Arc<File>,
    limits: RepoScanLimits,
    started: Instant,
    unique_entries: HashSet<[u8; 32]>,
    unique_files: HashMap<[u8; 32], FileIdentity>,
    discovered_bytes: u64,
    read_bytes: u64,
    generated_items: usize,
    generated_bytes: u64,
    parser_items: usize,
    parser_bytes: u64,
    violation: Option<String>,
}

impl ExecutionBudget {
    fn new(root: PathBuf, directory: Arc<File>, limits: RepoScanLimits, started: Instant) -> Self {
        Self {
            root,
            directory,
            limits,
            started,
            unique_entries: HashSet::new(),
            unique_files: HashMap::new(),
            discovered_bytes: 0,
            read_bytes: 0,
            generated_items: 0,
            generated_bytes: 0,
            parser_items: 0,
            parser_bytes: 0,
            violation: None,
        }
    }

    fn fail<T>(&mut self, message: String) -> Result<T, ScanError> {
        self.violation.get_or_insert_with(|| message.clone());
        Err(ScanError::Policy(message))
    }

    fn check_deadline(&mut self) -> Result<(), ScanError> {
        if let Some(message) = self.violation.clone() {
            return Err(ScanError::Policy(message));
        }
        if self.started.elapsed() > self.limits.timeout {
            return self.fail(format!(
                "repository scan exceeded {} seconds",
                self.limits.timeout.as_secs()
            ));
        }
        Ok(())
    }

    fn authorize_path(&mut self, path: &Path, metadata: &std::fs::Metadata) -> Result<PathBuf, ScanError> {
        self.check_deadline()?;
        if metadata.file_type().is_symlink() {
            return self.fail(format!("repository scan rejects symlink: {}", path.display()));
        }
        let canonical = std::fs::canonicalize(path)?;
        if !canonical.starts_with(&self.root) {
            return self.fail("repository scan path escaped its canonical root".to_string());
        }
        Ok(canonical)
    }

    fn path_key(&mut self, path: &Path) -> Result<[u8; 32], ScanError> {
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| ScanError::Policy("repository scan entry escaped its execution root".to_string()))?;
        Ok(*blake3::hash(relative.as_os_str().as_encoded_bytes()).as_bytes())
    }

    fn discover_entry(&mut self, path: &Path) -> Result<[u8; 32], ScanError> {
        let key = self.path_key(path)?;
        if self.unique_entries.insert(key) && self.unique_entries.len() > self.limits.max_files {
            return self.fail(format!(
                "repository scan exceeded {} filesystem entries",
                self.limits.max_files
            ));
        }
        Ok(key)
    }

    fn discover_path_entry(&mut self, path: &Path) -> Result<(), ScanError> {
        self.check_deadline()?;
        if !path.starts_with(&self.root) {
            return self.fail("repository scan entry escaped its canonical root".to_string());
        }
        self.discover_entry(path).map(|_| ())
    }

    fn discover_directory(&mut self, path: &Path, metadata: &std::fs::Metadata) -> Result<PathBuf, ScanError> {
        let canonical = self.authorize_path(path, metadata)?;
        if !metadata.is_dir() {
            return self.fail(format!("repository scan expected a directory: {}", path.display()));
        }
        if canonical != self.root {
            self.discover_entry(&canonical)?;
        }
        Ok(canonical)
    }

    fn discover_file(&mut self, path: &Path, metadata: &std::fs::Metadata) -> Result<(), ScanError> {
        let canonical = self.authorize_path(path, metadata)?;
        if !metadata.is_file() {
            return self.fail(format!(
                "repository scan encountered non-regular file: {}",
                path.display()
            ));
        }
        let key = self.discover_entry(&canonical)?;
        let identity = FileIdentity::from_metadata(metadata);
        if !identity.has_single_link() {
            return self.fail(format!(
                "repository scan rejects multiply-linked file: {}",
                path.display()
            ));
        }
        if let Some(expected) = self.unique_files.get(&key) {
            if *expected != identity {
                return self.fail(format!(
                    "repository scan file identity changed after discovery: {}",
                    path.display()
                ));
            }
        } else {
            self.unique_files.insert(key, identity);
            self.discovered_bytes = self.discovered_bytes.saturating_add(metadata.len());
            if self.discovered_bytes > self.limits.max_bytes {
                return self.fail(format!(
                    "repository scan corpus exceeded {} bytes",
                    self.limits.max_bytes
                ));
            }
        }
        Ok(())
    }

    fn authorize_read(&mut self, path: &Path, metadata: &std::fs::Metadata) -> Result<(), ScanError> {
        if metadata.len() > self.limits.max_file_bytes {
            return self.fail(format!(
                "repository scan file exceeds {} bytes: {}",
                self.limits.max_file_bytes,
                path.display()
            ));
        }
        self.discover_file(path, metadata)?;
        Ok(())
    }

    fn authorize_opened_read(&mut self, path: &Path, metadata: &std::fs::Metadata) -> Result<(), ScanError> {
        self.check_deadline()?;
        if !path.starts_with(&self.root) {
            return self.fail("repository scan opened file escaped its execution root".to_string());
        }
        if !metadata.is_file() {
            return self.fail(format!(
                "repository scan encountered non-regular file: {}",
                path.display()
            ));
        }
        if metadata.len() > self.limits.max_file_bytes {
            return self.fail(format!(
                "repository scan file exceeds {} bytes: {}",
                self.limits.max_file_bytes,
                path.display()
            ));
        }
        let key = self.discover_entry(path)?;
        let identity = FileIdentity::from_metadata(metadata);
        if !identity.has_single_link() {
            return self.fail(format!(
                "repository scan rejects multiply-linked file: {}",
                path.display()
            ));
        }
        if let Some(expected) = self.unique_files.get(&key) {
            if *expected != identity {
                return self.fail(format!(
                    "repository scan file identity changed after discovery: {}",
                    path.display()
                ));
            }
        } else {
            self.unique_files.insert(key, identity);
            self.discovered_bytes = self.discovered_bytes.saturating_add(metadata.len());
            if self.discovered_bytes > self.limits.max_bytes {
                return self.fail(format!(
                    "repository scan corpus exceeded {} bytes",
                    self.limits.max_bytes
                ));
            }
        }
        Ok(())
    }

    fn remaining_read_bytes(&mut self) -> Result<u64, ScanError> {
        self.check_deadline()?;
        Ok(self.limits.max_bytes.saturating_sub(self.read_bytes))
    }

    fn charge_read_bytes(&mut self, bytes: u64) -> Result<(), ScanError> {
        self.check_deadline()?;
        self.read_bytes = self.read_bytes.saturating_add(bytes);
        if self.read_bytes > self.limits.max_bytes {
            return self.fail(format!(
                "repository scan read work exceeded {} bytes",
                self.limits.max_bytes
            ));
        }
        Ok(())
    }

    fn charge_generated_work(&mut self, items: usize, bytes: u64, label: &str) -> Result<(), ScanError> {
        self.check_deadline()?;
        self.generated_items = self.generated_items.saturating_add(items);
        if self.generated_items > self.limits.max_generated_items {
            return self.fail(format!(
                "repository scan exceeded {} generated {label} items",
                self.limits.max_generated_items
            ));
        }
        self.generated_bytes = self.generated_bytes.saturating_add(bytes);
        // Durable scans are published to a 64 MiB sidecar. Do not allow an
        // admitted scan to build substantially more generated state than can
        // ever be committed, even when its source-corpus budget is larger.
        let generated_byte_limit = self.limits.max_bytes.min(MAX_DURABLE_SCAN_OUTPUT_BYTES);
        if self.generated_bytes > generated_byte_limit {
            return self.fail(format!(
                "repository scan exceeded {} generated bytes for {label}",
                generated_byte_limit
            ));
        }
        Ok(())
    }

    fn charge_parser_work(&mut self, items: usize, bytes: u64, label: &str) -> Result<(), ScanError> {
        self.check_deadline()?;
        self.parser_items = self.parser_items.saturating_add(items);
        if self.parser_items > self.limits.max_parser_items {
            return self.fail(format!(
                "repository scan exceeded {} {label} items",
                self.limits.max_parser_items
            ));
        }
        self.parser_bytes = self.parser_bytes.saturating_add(bytes);
        if self.parser_bytes > self.limits.max_bytes {
            return self.fail(format!(
                "repository scan exceeded {} parser bytes for {label}",
                self.limits.max_bytes
            ));
        }
        Ok(())
    }
}

fn with_active_budget<T>(
    operation: impl FnOnce(&mut ExecutionBudget) -> Result<T, ScanError>,
) -> Result<Option<T>, ScanError> {
    ACTIVE_SCAN_BUDGET.with(|slot| {
        let budget = slot.borrow().clone();
        budget.map(|budget| operation(&mut budget.borrow_mut())).transpose()
    })
}

pub fn active_root() -> Option<PathBuf> {
    ACTIVE_SCAN_BUDGET.with(|slot| slot.borrow().as_ref().map(|budget| budget.borrow().root.clone()))
}

pub struct OpenedScanEntry {
    pub metadata: std::fs::Metadata,
    pub directory: Option<File>,
}

/// Open a directory relative to the execution's startup-anchored root.
///
/// Returning the descriptor (rather than reopening the pathname in the
/// walker) keeps every later enumeration attached to the object that was
/// authorized, even if an attacker renames or replaces an ancestor.
#[cfg(target_os = "linux")]
pub fn open_active_scan_directory(path: &Path) -> Result<Option<File>, ScanError> {
    let active = ACTIVE_SCAN_BUDGET.with(|slot| {
        slot.borrow().as_ref().map(|budget| {
            let budget = budget.borrow();
            (budget.root.clone(), budget.directory.clone())
        })
    });
    let Some((root, directory)) = active else {
        return Ok(None);
    };
    let relative = path
        .strip_prefix(&root)
        .map_err(|_| reject_violation("repository scan directory escaped its execution root".to_string()))?;
    if relative.as_os_str().is_empty() {
        return directory
            .try_clone()
            .map(Some)
            .map_err(|error| reject_read_io(path, "clone root directory descriptor", &error));
    }
    open_relative_directory(&directory, relative)
        .map(Some)
        .map_err(|error| reject_read_io(path, "root-anchored directory open", &error))
}

#[cfg(not(target_os = "linux"))]
pub fn open_active_scan_directory(path: &Path) -> Result<Option<File>, ScanError> {
    if active_root().is_some() {
        Err(reject_unsupported_secure_open(path))
    } else {
        Ok(None)
    }
}

/// Enumerate one already-open directory. Entry names are charged before they
/// enter the temporary sort buffer, so a wide directory cannot allocate past
/// the configured entry cap.
#[cfg(target_os = "linux")]
pub fn read_opened_scan_directory_names(directory: &File, parent: &Path) -> Result<Vec<OsString>, ScanError> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut stream = rustix::fs::Dir::read_from(directory)
        .map_err(|error| reject_read_io(parent, "read directory descriptor", &std::io::Error::from(error)))?;
    let mut names = Vec::new();
    while let Some(entry) = stream.read() {
        let entry =
            entry.map_err(|error| reject_read_io(parent, "read directory entry", &std::io::Error::from(error)))?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        charge_generated_work(
            1,
            bytes.len().saturating_add(std::mem::size_of::<OsString>()),
            "directory entry sort buffer",
        )?;
        let name = std::ffi::OsStr::from_bytes(bytes).to_os_string();
        discover_entry(&parent.join(&name))?;
        names.push(name);
    }
    names.sort();
    Ok(names)
}

/// Open one enumerated child relative to its stable parent descriptor.
/// `openat2(RESOLVE_BENEATH|NO_SYMLINKS)` rejects a symlink in any component;
/// O_PATH lets us inspect special files without activating them.
#[cfg(target_os = "linux")]
pub fn open_scan_entry(
    directory: &File,
    parent: &Path,
    name: &std::ffi::OsStr,
) -> Result<OpenedScanEntry, ScanError> {
    use std::os::unix::fs::MetadataExt as _;

    check_deadline()?;
    let path = parent.join(name);
    let handle = open_beneath(
        directory,
        Path::new(name),
        libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )
    .map_err(|error| reject_read_io(&path, "descriptor-relative entry open", &error))?;
    let metadata = handle
        .metadata()
        .map_err(|error| reject_read_io(&path, "descriptor-relative entry metadata", &error))?;
    if metadata.file_type().is_symlink() {
        return Err(reject_violation(format!(
            "repository scan rejects symlink: {}",
            path.display()
        )));
    }
    let child_directory = if metadata.is_dir() {
        let child = open_relative_directory(directory, Path::new(name))
            .map_err(|error| reject_read_io(&path, "descriptor-relative child directory open", &error))?;
        let child_metadata = child
            .metadata()
            .map_err(|error| reject_read_io(&path, "opened child directory metadata", &error))?;
        if !child_metadata.is_dir() || child_metadata.dev() != metadata.dev() || child_metadata.ino() != metadata.ino()
        {
            return Err(reject_file_change(&path));
        }
        Some(child)
    } else {
        None
    };
    Ok(OpenedScanEntry {
        metadata,
        directory: child_directory,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn read_opened_scan_directory_names(_directory: &File, parent: &Path) -> Result<Vec<OsString>, ScanError> {
    Err(reject_unsupported_secure_open(parent))
}

#[cfg(not(target_os = "linux"))]
pub fn open_scan_entry(
    _directory: &File,
    parent: &Path,
    _name: &std::ffi::OsStr,
) -> Result<OpenedScanEntry, ScanError> {
    Err(reject_unsupported_secure_open(parent))
}

/// Open a scanner file relative to the execution's already-open root
/// directory. Linux `openat2` resolves every component beneath that stable
/// descriptor and rejects symlinks, closing ancestor-swap races that
/// `O_NOFOLLOW` on the final component alone cannot prevent.
#[cfg(target_os = "linux")]
pub fn open_active_scan_file(path: &Path) -> Result<Option<File>, ScanError> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let active = ACTIVE_SCAN_BUDGET.with(|slot| {
        slot.borrow().as_ref().map(|budget| {
            let budget = budget.borrow();
            (budget.root.clone(), budget.directory.clone())
        })
    });
    let Some((root, directory)) = active else {
        return Ok(None);
    };
    let relative = path
        .strip_prefix(&root)
        .map_err(|_| reject_violation("repository scan read escaped its execution root".to_string()))?;
    let pinned = open_beneath(&directory, relative, libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .map_err(|error| reject_read_io(path, "root-anchored metadata open", &error))?;
    let pinned_metadata = pinned
        .metadata()
        .map_err(|error| reject_read_io(path, "root-anchored metadata", &error))?;
    charge_opened_read(path, &pinned_metadata)?;

    // The constructed procfs link names the already-pinned descriptor, not an
    // attacker-controlled path. Opening it yields a readable handle to that
    // exact regular inode without ever activating an unverified FIFO/device.
    let proc_path = format!("/proc/self/fd/{}", pinned.as_raw_fd());
    let readable = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&proc_path)
        .map_err(|error| reject_read_io(path, "open pinned regular file", &error))?;
    let readable_metadata = readable
        .metadata()
        .map_err(|error| reject_read_io(path, "pinned readable metadata", &error))?;
    if FileIdentity::from_metadata(&pinned_metadata) != FileIdentity::from_metadata(&readable_metadata) {
        return Err(reject_file_change(path));
    }
    Ok(Some(readable))
}

#[cfg(target_os = "linux")]
fn probe_scan_path(path: &Path) -> Result<Option<std::fs::Metadata>, ScanError> {
    let active = ACTIVE_SCAN_BUDGET.with(|slot| {
        slot.borrow().as_ref().map(|budget| {
            let budget = budget.borrow();
            (budget.root.clone(), budget.directory.clone())
        })
    });
    let Some((root, directory)) = active else {
        return match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(ScanError::Policy(format!(
                "repository scan rejects symlink: {}",
                path.display()
            ))),
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(reject_read_io(path, "optional metadata", &error)),
        };
    };
    let relative = path
        .strip_prefix(&root)
        .map_err(|_| reject_violation("repository scan probe escaped its execution root".to_string()))?;
    let opened = match open_beneath(&directory, relative, libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) {
        Ok(opened) => opened,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(reject_read_io(path, "root-anchored optional metadata", &error)),
    };
    opened
        .metadata()
        .map(Some)
        .map_err(|error| reject_read_io(path, "root-anchored optional metadata", &error))
}

#[cfg(not(target_os = "linux"))]
fn probe_scan_path(path: &Path) -> Result<Option<std::fs::Metadata>, ScanError> {
    Err(reject_unsupported_secure_open(path))
}

pub fn scan_path_is_file(path: &Path) -> Result<bool, ScanError> {
    Ok(probe_scan_path(path)?.is_some_and(|metadata| metadata.is_file()))
}

/// Inspect and admit a regular file without authorizing a content read.
///
/// Parsers use this to reject inputs above a narrower format-specific ceiling
/// before the global per-file read ceiling is consulted. The descriptor-rooted
/// probe and discovery charge still reject links, special files, root escapes,
/// identity changes, and corpus-budget overflow.
pub fn scan_file_metadata_for_admission(path: &Path) -> Result<Option<std::fs::Metadata>, ScanError> {
    let Some(metadata) = probe_scan_path(path)? else {
        return Ok(None);
    };
    if !metadata.is_file() {
        return Ok(None);
    }
    discover_file(path, &metadata)?;
    Ok(Some(metadata))
}

pub fn scan_file_metadata(path: &Path) -> Result<Option<std::fs::Metadata>, ScanError> {
    let Some(metadata) = scan_file_metadata_for_admission(path)? else {
        return Ok(None);
    };
    charge_opened_read(path, &metadata)?;
    Ok(Some(metadata))
}

pub fn scan_path_is_directory(path: &Path) -> Result<bool, ScanError> {
    Ok(probe_scan_path(path)?.is_some_and(|metadata| metadata.is_dir()))
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn open_active_scan_file(path: &Path) -> Result<Option<File>, ScanError> {
    Err(reject_unsupported_secure_open(path))
}

pub fn check_depth(depth: usize) -> Result<(), ScanError> {
    with_active_budget(|budget| {
        budget.check_deadline()?;
        if depth > budget.limits.max_depth {
            return budget.fail(format!(
                "repository scan exceeded directory depth {}",
                budget.limits.max_depth
            ));
        }
        Ok(())
    })?;
    Ok(())
}

pub fn check_deadline() -> Result<(), ScanError> {
    with_active_budget(ExecutionBudget::check_deadline)?;
    Ok(())
}

pub fn discover_entry(path: &Path) -> Result<(), ScanError> {
    with_active_budget(|budget| budget.discover_path_entry(path))?;
    Ok(())
}

pub fn authorize_directory(path: &Path, metadata: &std::fs::Metadata) -> Result<PathBuf, ScanError> {
    if let Some(result) = with_active_budget(|budget| budget.discover_directory(path, metadata))? {
        return Ok(result);
    }
    if metadata.file_type().is_symlink() {
        return Err(ScanError::Policy(format!(
            "repository scan rejects symlink: {}",
            path.display()
        )));
    }
    Ok(std::fs::canonicalize(path)?)
}

pub fn discover_file(path: &Path, metadata: &std::fs::Metadata) -> Result<(), ScanError> {
    let charged = with_active_budget(|budget| budget.discover_file(path, metadata))?;
    if charged.is_none() && metadata.file_type().is_symlink() {
        return Err(ScanError::Policy(format!(
            "repository scan rejects symlink: {}",
            path.display()
        )));
    }
    Ok(())
}

pub fn charge_read(path: &Path, metadata: &std::fs::Metadata) -> Result<(), ScanError> {
    let charged = with_active_budget(|budget| budget.authorize_read(path, metadata))?;
    if charged.is_none() && metadata.file_type().is_symlink() {
        return Err(ScanError::Policy(format!(
            "repository scan rejects symlink: {}",
            path.display()
        )));
    }
    Ok(())
}

pub fn charge_opened_read(path: &Path, metadata: &std::fs::Metadata) -> Result<(), ScanError> {
    with_active_budget(|budget| budget.authorize_opened_read(path, metadata))?;
    Ok(())
}

pub fn max_file_bytes() -> u64 {
    ACTIVE_SCAN_BUDGET.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(DEFAULT_MAX_FILE_BYTES, |budget| budget.borrow().limits.max_file_bytes)
    })
}

pub fn remaining_read_bytes() -> Result<u64, ScanError> {
    Ok(with_active_budget(ExecutionBudget::remaining_read_bytes)?.unwrap_or(DEFAULT_MAX_FILE_BYTES))
}

pub fn charge_read_bytes(bytes: usize) -> Result<(), ScanError> {
    with_active_budget(|budget| budget.charge_read_bytes(bytes as u64))?;
    Ok(())
}

pub fn charge_generated_work(items: usize, bytes: usize, label: &str) -> Result<(), ScanError> {
    with_active_budget(|budget| budget.charge_generated_work(items, bytes as u64, label))?;
    Ok(())
}

pub fn charge_parser_work(items: usize, bytes: usize, label: &str) -> Result<(), ScanError> {
    with_active_budget(|budget| budget.charge_parser_work(items, bytes as u64, label))?;
    Ok(())
}

/// Pre-admit native parser work before an AST is allocated. Identifier runs
/// count once and each non-whitespace delimiter/operator counts once. The
/// per-token byte estimate covers parser nodes and small secondary vectors;
/// durable outputs and cloned indexes are charged again at their own sites.
pub fn charge_source_parse_work(source: &str, label: &str) -> Result<(), ScanError> {
    let mut items = 0usize;
    let mut in_word = false;
    for byte in source.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'_' {
            if !in_word {
                items = items.saturating_add(1);
                in_word = true;
            }
        } else {
            in_word = false;
            if !byte.is_ascii_whitespace() {
                items = items.saturating_add(1);
            }
        }
    }
    let estimated_bytes = source.len().saturating_add(items.saturating_mul(64));
    with_active_budget(|budget| budget.charge_parser_work(items.max(1), estimated_bytes as u64, label))?;
    Ok(())
}

pub fn reject_file_growth(path: &Path) -> ScanError {
    reject_violation(format!(
        "repository scan file exceeded {} bytes while reading: {}",
        max_file_bytes(),
        path.display()
    ))
}

pub fn reject_file_change(path: &Path) -> ScanError {
    reject_violation(format!(
        "repository scan file changed during secure open: {}",
        path.display()
    ))
}

#[cfg(not(unix))]
pub fn reject_unsupported_secure_open(path: &Path) -> ScanError {
    reject_violation(format!(
        "repository scan secure-open verification is unavailable on this platform: {}",
        path.display()
    ))
}

pub fn reject_read_budget(path: &Path) -> ScanError {
    reject_violation(format!(
        "repository scan read work exceeded its cumulative byte budget before reading: {}",
        path.display()
    ))
}

pub fn reject_read_io(path: &Path, operation: &str, error: &std::io::Error) -> ScanError {
    reject_violation(format!(
        "repository scan secure read failed during {operation} for {}: {error}",
        path.display()
    ))
}

fn reject_violation(message: String) -> ScanError {
    let _ = with_active_budget::<()>(|budget| budget.fail(message.clone()));
    ScanError::Policy(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(root: &Path, limits: RepoScanLimits) -> RepoScanPolicy {
        RepoScanPolicy::for_test_roots(vec![root.canonicalize().expect("canonical root")], limits)
    }

    fn walk(policy: &RepoScanPolicy, root: &Path) -> Result<Vec<PathBuf>, ScanError> {
        policy.execute(root, |canonical| {
            let mut files = Vec::new();
            crate::workspace_scan::walk_dir(canonical, canonical, &mut |_rel, path| {
                files.push(path.to_path_buf());
            })?;
            Ok(files)
        })
    }

    #[test]
    fn root_must_be_allowed_and_not_a_symlink() {
        let allowed = tempfile::tempdir().expect("allowed");
        let outside = tempfile::tempdir().expect("outside");
        let policy = RepoScanPolicy::for_test_roots(
            vec![allowed.path().canonicalize().expect("canonical")],
            RepoScanLimits::default(),
        );
        assert_eq!(
            policy.resolve_root(allowed.path()).expect("allowed"),
            allowed.path().canonicalize().expect("canonical")
        );
        assert!(policy.resolve_root(outside.path()).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = outside.path().join("root-link");
            symlink(allowed.path(), &link).expect("symlink");
            assert!(policy.resolve_root(&link).is_err());
        }
    }

    #[test]
    fn empty_allowlist_disables_tenant_scans() {
        let root = tempfile::tempdir().expect("root");
        let policy = RepoScanPolicy::for_test_roots(Vec::new(), RepoScanLimits::default());
        let error = policy.resolve_root(root.path()).expect_err("empty allowlist must deny");
        assert!(error.to_string().contains("scanning is disabled"));

        let missing = root.path().join("host-path-oracle-must-not-be-statted");
        let error = policy
            .resolve_root(&missing)
            .expect_err("missing path must receive the same denial");
        assert!(error.to_string().contains("scanning is disabled"));
    }

    #[test]
    fn generated_work_never_exceeds_durable_snapshot_ceiling() {
        let root = tempfile::tempdir().expect("root");
        let scan_policy = policy(root.path(), RepoScanLimits::default());
        let error = scan_policy
            .execute(root.path(), |_| {
                charge_generated_work(
                    1,
                    MAX_DURABLE_SCAN_OUTPUT_BYTES as usize + 1,
                    "fixture output",
                )
            })
            .expect_err("generated output larger than its durable sidecar must be rejected");
        assert!(error
            .to_string()
            .contains(&MAX_DURABLE_SCAN_OUTPUT_BYTES.to_string()));
    }

    #[test]
    fn workspace_root_never_expands_tenant_scan_authority() {
        let workspace = tempfile::tempdir().expect("workspace");
        std::fs::write(workspace.path().join("lib.rs"), "pub fn fixture() {}").expect("source");
        let mut policy = RepoScanPolicy::for_test_roots(Vec::new(), RepoScanLimits::default());
        policy.workspace_root = Some(root_anchor(workspace.path()).expect("workspace anchor"));

        assert!(policy
            .resolve_root(workspace.path())
            .expect_err("workspace is not a tenant grant")
            .to_string()
            .contains("scanning is disabled"));
        policy
            .execute_workspace(|canonical| {
                assert_eq!(canonical, workspace.path().canonicalize().expect("canonical workspace"));
                Ok(())
            })
            .expect("operator workspace policy remains available");
    }

    #[test]
    fn canonical_containment_rejects_parent_traversal_and_sibling_prefixes() {
        let parent = tempfile::tempdir().expect("parent");
        let allowed = parent.path().join("repo");
        let child = allowed.join("child");
        let sibling = parent.path().join("repo-escape");
        std::fs::create_dir_all(&child).expect("allowed child");
        std::fs::create_dir_all(&sibling).expect("sibling");
        let policy = policy(&allowed, RepoScanLimits::default());

        assert_eq!(
            policy
                .resolve_root(&allowed.join("child").join(".."))
                .expect("contained"),
            allowed.canonicalize().expect("canonical allowed")
        );
        assert!(policy.resolve_root(&allowed.join("..").join("repo-escape")).is_err());
        assert!(policy.resolve_root(&sibling).is_err());

        let missing_sibling = parent.path().join("repo-escape-missing");
        let existing_error = policy.resolve_root(&sibling).expect_err("existing sibling denied");
        let missing_error = policy
            .resolve_root(&missing_sibling)
            .expect_err("missing sibling denied");
        assert_eq!(existing_error.to_string(), missing_error.to_string());
    }

    #[cfg(unix)]
    #[test]
    fn walker_rejects_symlink_escape_and_cycle() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("secret.rs"), "secret").expect("outside file");
        symlink(outside.path().join("secret.rs"), root.path().join("escape.rs")).expect("file symlink");
        let policy = policy(root.path(), RepoScanLimits::default());
        let error = walk(&policy, root.path()).expect_err("symlink escape must fail");
        assert!(error.to_string().contains("rejects symlink"));

        std::fs::remove_file(root.path().join("escape.rs")).expect("remove escape");
        let loop_dir = root.path().join("loop");
        std::fs::create_dir(&loop_dir).expect("loop dir");
        symlink(root.path(), loop_dir.join("back")).expect("cycle symlink");
        let error = walk(&policy, root.path()).expect_err("symlink cycle must fail");
        assert!(error.to_string().contains("rejects symlink"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_walker_rejects_ancestor_swap_after_enumeration() {
        use std::os::unix::fs::symlink;
        use std::sync::atomic::{AtomicBool, Ordering};

        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        std::fs::create_dir(root.path().join("aaa")).expect("earlier directory");
        let slot = root.path().join("slot");
        std::fs::create_dir(&slot).expect("slot");
        std::fs::write(slot.join("inside.rs"), "inside").expect("inside source");
        std::fs::write(outside.path().join("secret.rs"), "secret").expect("outside source");
        let policy = policy(root.path(), RepoScanLimits::default());
        let swapped = AtomicBool::new(false);
        let outside_read = AtomicBool::new(false);

        let error = policy
            .execute(root.path(), |canonical| {
                crate::workspace_scan::walk_dir_filtered(
                    canonical,
                    canonical,
                    None,
                    |name| {
                        if name == "aaa" && !swapped.swap(true, Ordering::SeqCst) {
                            std::fs::rename(&slot, root.path().join("slot-before-swap"))
                                .expect("rename authorized ancestor");
                            symlink(outside.path(), &slot).expect("replace ancestor with outside symlink");
                        }
                        false
                    },
                    &mut |_rel, path| {
                        if crate::workspace_scan::read_scan_bytes(path).is_ok_and(|bytes| bytes == b"secret") {
                            outside_read.store(true, Ordering::SeqCst);
                        }
                    },
                )
            })
            .expect_err("ancestor swap must fail closed");

        assert!(swapped.load(Ordering::SeqCst));
        assert!(!outside_read.load(Ordering::SeqCst));
        assert!(error.to_string().contains("rejects symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn policy_rejects_non_regular_files_without_opening_them() {
        let root = Path::new("/dev");
        let device = Path::new("/dev/null");
        let policy = policy(root, RepoScanLimits::default());
        let error = policy
            .execute(root, |_canonical| {
                let metadata = std::fs::symlink_metadata(device)?;
                discover_file(device, &metadata)
            })
            .expect_err("device must fail");
        assert!(error.to_string().contains("non-regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn secure_scanner_read_rejects_hard_linked_files() {
        let root = tempfile::tempdir().expect("root");
        let source = root.path().join("source.rs");
        let alias = root.path().join("alias.rs");
        std::fs::write(&source, "pub fn fixture() {}\n").expect("source");
        std::fs::hard_link(&source, &alias).expect("hard link");
        let policy = policy(root.path(), RepoScanLimits::default());

        let error = policy
            .execute(root.path(), |_canonical| {
                crate::workspace_scan::read_scan_bytes(&source)?;
                Ok(())
            })
            .expect_err("hard-linked source must fail closed");
        assert!(error.to_string().contains("multiply-linked file"));
    }

    #[cfg(unix)]
    #[test]
    fn secure_scanner_read_rejects_replacement_after_metadata_admission() {
        let root = tempfile::tempdir().expect("root");
        let source = root.path().join("package.json");
        std::fs::write(&source, br#"{"name":"before"}"#).expect("source");
        let policy = policy(root.path(), RepoScanLimits::default());

        let error = policy
            .execute(root.path(), |_canonical| {
                scan_file_metadata_for_admission(&source)?.expect("regular admitted file");
                let replacement = root.path().join("replacement");
                std::fs::write(&replacement, br#"{"name":"after!"}"#).expect("same-length replacement");
                std::fs::rename(&replacement, &source).expect("replace admitted inode");
                crate::workspace_scan::read_scan_bytes(&source)?;
                Ok(())
            })
            .expect_err("replacement after admission must fail the whole scan");

        assert!(error.to_string().contains("identity changed"));
    }

    #[test]
    fn depth_and_entry_limits_are_inclusive_at_the_boundary() {
        let root = tempfile::tempdir().expect("root");
        let nested = root.path().join("one").join("two");
        std::fs::create_dir_all(&nested).expect("nested");
        std::fs::write(nested.join("lib.rs"), "pub fn ok() {}").expect("source");

        let mut limits = RepoScanLimits {
            max_depth: 2,
            max_files: 3,
            max_bytes: 1024,
            max_file_bytes: 1024,
            timeout: Duration::from_secs(5),
            ..RepoScanLimits::default()
        };
        assert_eq!(
            walk(&policy(root.path(), limits), root.path())
                .expect("at boundary")
                .len(),
            1
        );

        limits.max_depth = 1;
        assert!(walk(&policy(root.path(), limits), root.path())
            .expect_err("depth over cap")
            .to_string()
            .contains("directory depth"));

        limits.max_depth = 2;
        limits.max_files = 2;
        assert!(walk(&policy(root.path(), limits), root.path())
            .expect_err("entry over cap")
            .to_string()
            .contains("filesystem entries"));
    }

    #[test]
    fn ignored_entries_still_consume_the_preallocation_cap() {
        let root = tempfile::tempdir().expect("root");
        std::fs::create_dir(root.path().join(".ignored-a")).expect("ignored a");
        std::fs::create_dir(root.path().join(".ignored-b")).expect("ignored b");
        let limits = RepoScanLimits {
            max_files: 1,
            ..RepoScanLimits::default()
        };
        let error = walk(&policy(root.path(), limits), root.path()).expect_err("ignored entry overflow");
        assert!(error.to_string().contains("filesystem entries"));
    }

    #[test]
    fn byte_and_per_file_limits_share_one_execution_budget() {
        let root = tempfile::tempdir().expect("root");
        let source = root.path().join("lib.rs");
        std::fs::write(&source, b"1234").expect("source");
        let exact = RepoScanLimits {
            max_depth: 1,
            max_files: 1,
            max_bytes: 4,
            max_file_bytes: 4,
            timeout: Duration::from_secs(5),
            ..RepoScanLimits::default()
        };
        policy(root.path(), exact)
            .execute(root.path(), |_canonical| {
                assert_eq!(crate::workspace_scan::read_scan_bytes(&source)?, b"1234");
                Ok(())
            })
            .expect("exact byte boundary");

        let error = policy(root.path(), exact)
            .execute(root.path(), |_canonical| {
                crate::workspace_scan::read_scan_bytes(&source)?;
                crate::workspace_scan::read_scan_bytes(&source)?;
                Ok(())
            })
            .expect_err("repeated scanner lanes share read budget");
        assert!(error.to_string().contains("read work exceeded"));

        std::fs::write(&source, b"12345").expect("grow source");
        let error = policy(root.path(), exact)
            .execute(root.path(), |_canonical| {
                crate::workspace_scan::read_scan_bytes(&source)?;
                Ok(())
            })
            .expect_err("per-file cap");
        assert!(error.to_string().contains("file exceeds"));
    }

    #[test]
    fn elapsed_limit_and_nested_scans_fail_closed() {
        let root = tempfile::tempdir().expect("root");
        let timeout_policy = policy(
            root.path(),
            RepoScanLimits {
                timeout: Duration::ZERO,
                ..RepoScanLimits::default()
            },
        );
        assert!(timeout_policy
            .execute(root.path(), |_canonical| Ok(()))
            .expect_err("zero timeout")
            .to_string()
            .contains("seconds"));

        let policy = policy(root.path(), RepoScanLimits::default());
        let error = policy
            .execute(root.path(), |_canonical| policy.execute(root.path(), |_nested| Ok(())))
            .expect_err("nested budget");
        assert!(error.to_string().contains("nested repository scan budget"));
    }

    #[test]
    fn zero_timeout_wraps_the_real_polyglot_scanner() {
        let root = tempfile::tempdir().expect("root");
        std::fs::write(root.path().join("fixture.ts"), "export function fixture() {}\n").expect("source");
        let timeout_policy = policy(
            root.path(),
            RepoScanLimits {
                timeout: Duration::ZERO,
                ..RepoScanLimits::default()
            },
        );
        let error = crate::workspace_scan_polyglot::run_repo_scan_at_with_policy(root.path(), &timeout_policy)
            .expect_err("real scanner must inherit the timeout budget");
        assert!(error.to_string().contains("seconds"));
    }

    #[test]
    fn panic_does_not_poison_reused_scanner_thread() {
        let root = tempfile::tempdir().expect("root");
        let policy = policy(root.path(), RepoScanLimits::default());
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), ScanError> = policy.execute(root.path(), |_canonical| panic!("fixture panic"));
        }));
        assert!(unwind.is_err());
        policy
            .execute(root.path(), |_canonical| Ok(()))
            .expect("budget guard cleaned up");
    }
}
