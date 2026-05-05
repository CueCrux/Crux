// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Manifest contract for Crux Daemon integration packs.
//!
//! Version 1 is intentionally declarative: packs can describe MCP, HTTP, SDK,
//! CLI, file watcher, and webhook recipes, but they do not execute code inside
//! the daemon process.

pub mod signing;

pub use signing::{
    fingerprint_from_public_key, sign_manifest, TrustedKeyEntry, TrustedKeyring,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const INTEGRATION_SCHEMA_V1: &str = "crux.integration.v1";
pub const FIRST_PARTY_PASSPORT: &str = "cuecrux:first-party";
pub const INTEGRATION_INDEX_SCHEMA_V1: &str = "crux.integration.index.v1";

const ALLOWED_CAPABILITIES: &[&str] = &[
    "integrations:read",
    "integrations:install",
    "integrations:grant",
    "integrations:disable",
    "facts:read",
    "facts:write",
    "facts:private:read",
    "sessions:read",
    "sessions:write",
    "passport:read",
    "tenant:metadata:read",
    "tenant:chunks:read",
    "tenant:content:preview",
    "admin:read",
];

#[derive(Debug, thiserror::Error)]
pub enum IntegrationError {
    #[error("invalid integration schema '{0}'")]
    InvalidSchema(String),
    #[error("field '{0}' is required")]
    MissingField(&'static str),
    #[error("invalid identifier '{0}'")]
    InvalidIdentifier(String),
    #[error("unknown capability '{0}'")]
    UnknownCapability(String),
    #[error("external helpers are disabled by policy")]
    ExternalHelperDisabled,
    #[error("manifest hash mismatch: expected {expected}, actual {actual}")]
    ManifestHashMismatch { expected: String, actual: String },
    #[error("signature is required")]
    SignatureRequired,
    #[error("unsupported signature algorithm '{0}'")]
    UnsupportedSignatureAlgorithm(String),
    #[error("no trusted public key for passport '{0}'")]
    MissingTrustedKey(String),
    #[error("invalid signature material: {0}")]
    InvalidSignatureMaterial(String),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("pack '{pack_id}' version '{version}' is not installed")]
    PackNotInstalled { pack_id: String, version: String },
    #[error("grant for pack '{pack_id}' and passport '{passport_fpr}' was not found")]
    GrantNotFound { pack_id: String, passport_fpr: String },
    #[error("capability '{capability}' is not declared by pack '{pack_id}'")]
    CapabilityNotDeclared { pack_id: String, capability: String },
    #[error("invalid path component '{0}'")]
    InvalidPathComponent(String),
    #[error("invalid index schema '{0}'")]
    InvalidIndexSchema(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationManifest {
    pub schema: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher_passport_fpr: String,
    pub summary: String,
    pub entry: IntegrationEntry,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub network: NetworkAccess,
    #[serde(default)]
    pub data_access: DataAccess,
    #[serde(default)]
    pub safety: SafetyPolicy,
    #[serde(default)]
    pub hashes: ManifestHashes,
    #[serde(default)]
    pub signature: Option<SignatureEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationEntry {
    pub kind: EntryKind,
    pub path: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    McpConfig,
    HttpRecipe,
    SdkRecipe,
    CliRecipe,
    FileWatcher,
    WebhookAdapter,
    ExternalHelper,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkAccess {
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub requires_user_token: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataAccess {
    #[serde(default)]
    pub tenant_scopes: Vec<String>,
    #[serde(default)]
    pub content_preview: bool,
    #[serde(default)]
    pub private_facts: bool,
}

impl Default for DataAccess {
    fn default() -> Self {
        Self {
            tenant_scopes: vec!["selected".to_string()],
            content_preview: false,
            private_facts: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SafetyPolicy {
    pub sandbox: SandboxKind,
    pub max_runtime_ms: u64,
    pub max_output_bytes: u64,
}

impl Default for SafetyPolicy {
    fn default() -> Self {
        Self {
            sandbox: SandboxKind::None,
            max_runtime_ms: 0,
            max_output_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxKind {
    None,
    Command,
    Wasm,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestHashes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub alg: String,
    pub passport_fpr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
    pub sig: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    FirstParty,
    LocallySigned,
    CommunityReviewed,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallState {
    Available,
    Installed,
    Enabled,
    Blocked,
    UpdateAvailable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationPackDescriptor {
    pub manifest: IntegrationManifest,
    pub manifest_hash: String,
    pub trust_tier: TrustTier,
    pub install_state: InstallState,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledPackRecord {
    pub id: String,
    pub version: String,
    pub manifest_hash: String,
    pub trust_tier: TrustTier,
    pub installed_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationGrant {
    pub passport_fpr: String,
    pub pack_id: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub enabled: bool,
    pub granted_by_passport_fpr: String,
    pub granted_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationAuditEvent {
    pub ts_unix_ms: u64,
    pub action: String,
    pub passport_fpr: String,
    pub pack_id: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationLibrarySnapshot {
    pub packs: Vec<IntegrationPackDescriptor>,
    pub grants: Vec<IntegrationGrant>,
    pub audit_tail: Vec<IntegrationAuditEvent>,
}

#[derive(Debug, Clone)]
pub struct GrantPackRequest<'a> {
    pub passport_fpr: &'a str,
    pub granted_by_passport_fpr: &'a str,
    pub pack_id: &'a str,
    pub version: &'a str,
    pub capabilities: &'a [String],
    pub reason: Option<String>,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IntegrationIndex {
    schema: String,
    updated_at_unix_ms: u64,
    #[serde(default)]
    packs: Vec<InstalledPackRecord>,
}

#[derive(Debug, Clone)]
pub struct ValidationPolicy {
    pub allow_unsigned_first_party: bool,
    pub allow_executable_helpers: bool,
    pub trusted_public_keys: BTreeMap<String, String>,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            allow_unsigned_first_party: true,
            allow_executable_helpers: false,
            trusted_public_keys: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ManifestSigningPayload<'a> {
    schema: &'a str,
    id: &'a str,
    name: &'a str,
    version: &'a str,
    publisher_passport_fpr: &'a str,
    summary: &'a str,
    entry: &'a IntegrationEntry,
    capabilities: &'a [String],
    network: &'a NetworkAccess,
    data_access: &'a DataAccess,
    safety: &'a SafetyPolicy,
}

impl IntegrationManifest {
    pub fn validate(&self, policy: &ValidationPolicy) -> Result<(), IntegrationError> {
        if self.schema != INTEGRATION_SCHEMA_V1 {
            return Err(IntegrationError::InvalidSchema(self.schema.clone()));
        }
        validate_non_empty("id", &self.id)?;
        validate_non_empty("name", &self.name)?;
        validate_non_empty("version", &self.version)?;
        validate_non_empty("publisher_passport_fpr", &self.publisher_passport_fpr)?;
        validate_identifier(&self.id)?;
        validate_non_empty("entry.path", &self.entry.path)?;

        for capability in &self.capabilities {
            if !ALLOWED_CAPABILITIES.contains(&capability.as_str()) {
                return Err(IntegrationError::UnknownCapability(capability.clone()));
            }
        }

        if self.entry.kind == EntryKind::ExternalHelper && !policy.allow_executable_helpers {
            return Err(IntegrationError::ExternalHelperDisabled);
        }

        if let Some(expected) = &self.hashes.manifest {
            let actual = self.manifest_hash()?;
            if expected != &actual {
                return Err(IntegrationError::ManifestHashMismatch {
                    expected: expected.clone(),
                    actual,
                });
            }
        }

        if let Some(signature) = &self.signature {
            verify_signature(self, signature, policy)?;
        } else if !(policy.allow_unsigned_first_party && self.publisher_passport_fpr == FIRST_PARTY_PASSPORT) {
            return Err(IntegrationError::SignatureRequired);
        }

        Ok(())
    }

    pub fn signing_payload(&self) -> Result<Vec<u8>, IntegrationError> {
        let payload = ManifestSigningPayload {
            schema: &self.schema,
            id: &self.id,
            name: &self.name,
            version: &self.version,
            publisher_passport_fpr: &self.publisher_passport_fpr,
            summary: &self.summary,
            entry: &self.entry,
            capabilities: &self.capabilities,
            network: &self.network,
            data_access: &self.data_access,
            safety: &self.safety,
        };
        Ok(serde_json::to_vec(&payload)?)
    }

    pub fn manifest_hash(&self) -> Result<String, IntegrationError> {
        let bytes = self.signing_payload()?;
        Ok(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
    }
}

pub fn allowed_capabilities() -> &'static [&'static str] {
    ALLOWED_CAPABILITIES
}

pub fn builtin_packs() -> Result<Vec<IntegrationPackDescriptor>, IntegrationError> {
    let mut out = Vec::new();
    for manifest in builtin_manifests() {
        manifest.validate(&ValidationPolicy::default())?;
        let manifest_hash = manifest.manifest_hash()?;
        out.push(IntegrationPackDescriptor {
            risk_level: risk_level(&manifest),
            manifest,
            manifest_hash,
            trust_tier: TrustTier::FirstParty,
            install_state: InstallState::Available,
        });
    }
    Ok(out)
}

pub fn integration_root(data_dir: impl AsRef<Path>) -> PathBuf {
    data_dir.as_ref().join("integrations")
}

pub fn library_snapshot(
    data_dir: impl AsRef<Path>,
    passport_fpr: &str,
    policy: &ValidationPolicy,
) -> Result<IntegrationLibrarySnapshot, IntegrationError> {
    let root = integration_root(data_dir);
    let index = read_index(&root)?;
    let grants = load_grants_from_root(&root, passport_fpr)?;
    let enabled_keys: BTreeSet<(String, String)> = grants
        .iter()
        .filter(|grant| grant.enabled)
        .map(|grant| (grant.pack_id.clone(), grant.version.clone()))
        .collect();
    let installed_keys: BTreeSet<(String, String)> = index
        .packs
        .iter()
        .map(|record| (record.id.clone(), record.version.clone()))
        .collect();

    let mut descriptors = Vec::new();
    for mut descriptor in builtin_packs()? {
        let key = (descriptor.manifest.id.clone(), descriptor.manifest.version.clone());
        descriptor.install_state = if enabled_keys.contains(&key) {
            InstallState::Enabled
        } else if installed_keys.contains(&key) {
            InstallState::Installed
        } else {
            InstallState::Available
        };
        descriptors.push(descriptor);
    }

    let builtin_keys: BTreeSet<(String, String)> = descriptors
        .iter()
        .map(|descriptor| (descriptor.manifest.id.clone(), descriptor.manifest.version.clone()))
        .collect();
    for record in index.packs {
        let key = (record.id.clone(), record.version.clone());
        if builtin_keys.contains(&key) {
            continue;
        }
        let manifest = read_installed_manifest(&root, &record.id, &record.version)?;
        manifest.validate(policy)?;
        let manifest_hash = manifest.manifest_hash()?;
        let install_state = if enabled_keys.contains(&key) {
            InstallState::Enabled
        } else {
            InstallState::Installed
        };
        descriptors.push(IntegrationPackDescriptor {
            risk_level: risk_level(&manifest),
            manifest,
            manifest_hash,
            trust_tier: record.trust_tier,
            install_state,
        });
    }

    descriptors.sort_by(|a, b| {
        a.manifest
            .id
            .cmp(&b.manifest.id)
            .then_with(|| a.manifest.version.cmp(&b.manifest.version))
    });

    Ok(IntegrationLibrarySnapshot {
        packs: descriptors,
        grants,
        audit_tail: read_audit_tail(&root, 50)?,
    })
}

pub fn install_pack(
    data_dir: impl AsRef<Path>,
    manifest: &IntegrationManifest,
    trust_tier: TrustTier,
    installed_at_unix_ms: u64,
    policy: &ValidationPolicy,
) -> Result<IntegrationPackDescriptor, IntegrationError> {
    manifest.validate(policy)?;
    let root = integration_root(data_dir);
    let manifest_hash = manifest.manifest_hash()?;
    let id_component = safe_path_component(&manifest.id)?;
    let version_component = safe_path_component(&manifest.version)?;
    let manifest_path = root
        .join("packs")
        .join(id_component)
        .join(version_component)
        .join("manifest.json");
    write_json_atomic(&manifest_path, manifest)?;

    let mut index = read_index(&root)?;
    index.packs.retain(|record| {
        !(record.id == manifest.id && record.version == manifest.version && record.manifest_hash != manifest_hash)
    });
    if let Some(existing) = index
        .packs
        .iter_mut()
        .find(|record| record.id == manifest.id && record.version == manifest.version)
    {
        existing.manifest_hash.clone_from(&manifest_hash);
        existing.trust_tier = trust_tier;
        existing.installed_at_unix_ms = installed_at_unix_ms;
    } else {
        index.packs.push(InstalledPackRecord {
            id: manifest.id.clone(),
            version: manifest.version.clone(),
            manifest_hash: manifest_hash.clone(),
            trust_tier,
            installed_at_unix_ms,
        });
    }
    index.updated_at_unix_ms = installed_at_unix_ms;
    index
        .packs
        .sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.version.cmp(&b.version)));
    write_json_atomic(&root.join("index.json"), &index)?;
    append_audit_event(
        &root,
        &IntegrationAuditEvent {
            ts_unix_ms: installed_at_unix_ms,
            action: "install".to_string(),
            passport_fpr: manifest.publisher_passport_fpr.clone(),
            pack_id: manifest.id.clone(),
            version: manifest.version.clone(),
            capabilities: manifest.capabilities.clone(),
            outcome: "installed".to_string(),
            detail: Some(format!("manifest_hash={manifest_hash}")),
        },
    )?;

    Ok(IntegrationPackDescriptor {
        risk_level: risk_level(manifest),
        manifest: manifest.clone(),
        manifest_hash,
        trust_tier,
        install_state: InstallState::Installed,
    })
}

pub fn grant_pack(
    data_dir: impl AsRef<Path>,
    request: GrantPackRequest<'_>,
) -> Result<IntegrationGrant, IntegrationError> {
    let root = integration_root(data_dir);
    let manifest = read_installed_manifest(&root, request.pack_id, request.version)?;
    validate_capability_list(request.pack_id, request.capabilities)?;
    for capability in request.capabilities {
        if !manifest.capabilities.contains(capability) {
            return Err(IntegrationError::CapabilityNotDeclared {
                pack_id: request.pack_id.to_string(),
                capability: capability.clone(),
            });
        }
    }

    let mut requested = request.capabilities.to_vec();
    requested.sort();
    requested.dedup();
    let grant = IntegrationGrant {
        passport_fpr: request.passport_fpr.to_string(),
        pack_id: request.pack_id.to_string(),
        version: request.version.to_string(),
        capabilities: requested.clone(),
        enabled: true,
        granted_by_passport_fpr: request.granted_by_passport_fpr.to_string(),
        granted_at_unix_ms: request.now_unix_ms,
        disabled_at_unix_ms: None,
        reason: request.reason,
    };
    write_json_atomic(&grant_path(&root, request.passport_fpr, request.pack_id)?, &grant)?;
    append_audit_event(
        &root,
        &IntegrationAuditEvent {
            ts_unix_ms: request.now_unix_ms,
            action: "grant".to_string(),
            passport_fpr: request.passport_fpr.to_string(),
            pack_id: request.pack_id.to_string(),
            version: request.version.to_string(),
            capabilities: requested,
            outcome: "enabled".to_string(),
            detail: None,
        },
    )?;
    Ok(grant)
}

pub fn disable_pack(
    data_dir: impl AsRef<Path>,
    passport_fpr: &str,
    pack_id: &str,
    reason: Option<String>,
    now_unix_ms: u64,
) -> Result<IntegrationGrant, IntegrationError> {
    let root = integration_root(data_dir);
    let path = grant_path(&root, passport_fpr, pack_id)?;
    if !path.exists() {
        return Err(IntegrationError::GrantNotFound {
            pack_id: pack_id.to_string(),
            passport_fpr: passport_fpr.to_string(),
        });
    }
    let bytes = fs::read(&path)?;
    let mut grant: IntegrationGrant = serde_json::from_slice(&bytes)?;
    grant.enabled = false;
    grant.disabled_at_unix_ms = Some(now_unix_ms);
    if reason.is_some() {
        grant.reason = reason;
    }
    write_json_atomic(&path, &grant)?;
    append_audit_event(
        &root,
        &IntegrationAuditEvent {
            ts_unix_ms: now_unix_ms,
            action: "disable".to_string(),
            passport_fpr: passport_fpr.to_string(),
            pack_id: pack_id.to_string(),
            version: grant.version.clone(),
            capabilities: grant.capabilities.clone(),
            outcome: "disabled".to_string(),
            detail: None,
        },
    )?;
    Ok(grant)
}

pub fn builtin_manifests() -> Vec<IntegrationManifest> {
    vec![
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "mcp.claude-desktop".to_string(),
            name: "Claude Desktop MCP".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: FIRST_PARTY_PASSPORT.to_string(),
            summary: "Generate a Claude Desktop MCP server entry for the local Crux Daemon.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::McpConfig,
                path: "recipes/mcp/claude-desktop.json".to_string(),
            },
            capabilities: vec!["integrations:read".to_string(), "passport:read".to_string()],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
        },
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "mcp.cursor".to_string(),
            name: "Cursor MCP".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: FIRST_PARTY_PASSPORT.to_string(),
            summary: "Generate a Cursor .cursor/mcp.json entry for the local Crux MCP endpoint.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::McpConfig,
                path: "recipes/mcp/cursor.json".to_string(),
            },
            capabilities: vec!["integrations:read".to_string(), "passport:read".to_string()],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
        },
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "sdk.typescript.quickstart".to_string(),
            name: "TypeScript SDK Quickstart".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: FIRST_PARTY_PASSPORT.to_string(),
            summary: "Set up TypeScript examples for facts, sessions, and event streaming.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::SdkRecipe,
                path: "recipes/sdk/typescript-quickstart.json".to_string(),
            },
            capabilities: vec![
                "integrations:read".to_string(),
                "facts:read".to_string(),
                "facts:write".to_string(),
                "sessions:read".to_string(),
            ],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
        },
        // Note: a `github.pr-facts` declarative recipe used to live here.
        // Removed in favour of the live GitHub indexer integration which
        // already pulls PRs (alongside commits + issues + comments) into
        // the fact store via /v1/integrations/github/sync. The recipe
        // entry was redundant and confusing in the Integrations panel.
    ]
}

fn read_index(root: &Path) -> Result<IntegrationIndex, IntegrationError> {
    let path = root.join("index.json");
    if !path.exists() {
        return Ok(IntegrationIndex {
            schema: INTEGRATION_INDEX_SCHEMA_V1.to_string(),
            updated_at_unix_ms: 0,
            packs: Vec::new(),
        });
    }
    let bytes = fs::read(path)?;
    let index: IntegrationIndex = serde_json::from_slice(&bytes)?;
    if index.schema != INTEGRATION_INDEX_SCHEMA_V1 {
        return Err(IntegrationError::InvalidIndexSchema(index.schema));
    }
    Ok(index)
}

fn load_grants_from_root(root: &Path, passport_fpr: &str) -> Result<Vec<IntegrationGrant>, IntegrationError> {
    let passport_dir = root.join("grants").join(safe_path_component(passport_fpr)?);
    if !passport_dir.exists() {
        return Ok(Vec::new());
    }
    let mut grants = Vec::new();
    for entry in fs::read_dir(passport_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry.path().extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let bytes = fs::read(entry.path())?;
            grants.push(serde_json::from_slice(&bytes)?);
        }
    }
    grants.sort_by(|a: &IntegrationGrant, b| a.pack_id.cmp(&b.pack_id).then_with(|| a.version.cmp(&b.version)));
    Ok(grants)
}

fn read_installed_manifest(root: &Path, pack_id: &str, version: &str) -> Result<IntegrationManifest, IntegrationError> {
    let path = root
        .join("packs")
        .join(safe_path_component(pack_id)?)
        .join(safe_path_component(version)?)
        .join("manifest.json");
    if !path.exists() {
        return Err(IntegrationError::PackNotInstalled {
            pack_id: pack_id.to_string(),
            version: version.to_string(),
        });
    }
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_audit_tail(root: &Path, max_events: usize) -> Result<Vec<IntegrationAuditEvent>, IntegrationError> {
    let path = root.join("audit.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path)?;
    let lines: Vec<&str> = text.lines().rev().take(max_events).collect();
    let mut events = Vec::new();
    for line in lines.into_iter().rev() {
        events.push(serde_json::from_str(line)?);
    }
    Ok(events)
}

fn append_audit_event(root: &Path, event: &IntegrationAuditEvent) -> Result<(), IntegrationError> {
    fs::create_dir_all(root)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("audit.jsonl"))?;
    serde_json::to_writer(&mut file, event)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn grant_path(root: &Path, passport_fpr: &str, pack_id: &str) -> Result<PathBuf, IntegrationError> {
    Ok(root
        .join("grants")
        .join(safe_path_component(passport_fpr)?)
        .join(format!("{}.json", safe_path_component(pack_id)?)))
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<(), IntegrationError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn safe_path_component(value: &str) -> Result<String, IntegrationError> {
    let valid = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if valid {
        Ok(value.to_string())
    } else {
        Err(IntegrationError::InvalidPathComponent(value.to_string()))
    }
}

fn validate_capability_list(pack_id: &str, capabilities: &[String]) -> Result<(), IntegrationError> {
    for capability in capabilities {
        if !ALLOWED_CAPABILITIES.contains(&capability.as_str()) {
            return Err(IntegrationError::UnknownCapability(capability.clone()));
        }
        validate_non_empty("capability", capability)?;
        if capability.contains('/') || capability.contains('\\') {
            return Err(IntegrationError::CapabilityNotDeclared {
                pack_id: pack_id.to_string(),
                capability: capability.clone(),
            });
        }
    }
    Ok(())
}

fn validate_non_empty(field: &'static str, value: &str) -> Result<(), IntegrationError> {
    if value.trim().is_empty() {
        return Err(IntegrationError::MissingField(field));
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), IntegrationError> {
    let valid = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if valid {
        Ok(())
    } else {
        Err(IntegrationError::InvalidIdentifier(value.to_string()))
    }
}

fn verify_signature(
    manifest: &IntegrationManifest,
    signature: &SignatureEnvelope,
    policy: &ValidationPolicy,
) -> Result<(), IntegrationError> {
    if signature.alg != "ed25519" {
        return Err(IntegrationError::UnsupportedSignatureAlgorithm(signature.alg.clone()));
    }

    let key_hex = signature
        .public_key_hex
        .as_ref()
        .or_else(|| policy.trusted_public_keys.get(&signature.passport_fpr))
        .ok_or_else(|| IntegrationError::MissingTrustedKey(signature.passport_fpr.clone()))?;
    let public_key = decode_fixed_hex::<32>(key_hex, "public key")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|e| IntegrationError::InvalidSignatureMaterial(format!("public key: {e}")))?;

    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&signature.sig)
        .map_err(|e| IntegrationError::InvalidSignatureMaterial(format!("signature base64: {e}")))?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| IntegrationError::InvalidSignatureMaterial("signature must be 64 bytes".to_string()))?;
    let sig = Signature::from_bytes(&signature_array);
    verifying_key
        .verify(&manifest.signing_payload()?, &sig)
        .map_err(|_| IntegrationError::SignatureInvalid)
}

pub(crate) fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], IntegrationError> {
    let decoded =
        hex::decode(value).map_err(|e| IntegrationError::InvalidSignatureMaterial(format!("{label} hex: {e}")))?;
    decoded
        .try_into()
        .map_err(|_| IntegrationError::InvalidSignatureMaterial(format!("{label} must be {N} bytes")))
}

fn risk_level(manifest: &IntegrationManifest) -> RiskLevel {
    if manifest.entry.kind == EntryKind::ExternalHelper {
        return RiskLevel::Blocked;
    }
    if manifest.data_access.content_preview
        || manifest.data_access.private_facts
        || manifest.capabilities.iter().any(|c| c == "admin:read")
    {
        return RiskLevel::High;
    }
    if manifest
        .capabilities
        .iter()
        .any(|c| c.ends_with(":write") || c == "integrations:grant" || c == "integrations:install")
    {
        return RiskLevel::Medium;
    }
    RiskLevel::Low
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_manifest() -> IntegrationManifest {
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "test.pack".to_string(),
            name: "Test Pack".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: "p_test".to_string(),
            summary: "A test integration pack.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::HttpRecipe,
                path: "recipes/test.json".to_string(),
            },
            capabilities: vec!["facts:read".to_string()],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
        }
    }

    fn temp_data_dir(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "crux-integrations-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create temp integration dir");
        root
    }

    #[test]
    fn builtin_manifests_validate() -> Result<(), IntegrationError> {
        let packs = builtin_packs()?;
        // 3 first-party packs ship by default after `github.pr-facts` was
        // dropped (live GitHub indexer integration covers PR fact capture).
        assert_eq!(packs.len(), 3);
        assert!(packs.iter().all(|pack| pack.trust_tier == TrustTier::FirstParty));
        Ok(())
    }

    #[test]
    fn rejects_unknown_capability() {
        let mut manifest = sample_manifest();
        manifest.capabilities.push("secrets:read".to_string());
        let err = manifest
            .validate(&ValidationPolicy {
                allow_unsigned_first_party: false,
                allow_executable_helpers: false,
                trusted_public_keys: BTreeMap::new(),
            })
            .err();
        assert!(matches!(err, Some(IntegrationError::UnknownCapability(cap)) if cap == "secrets:read"));
    }

    #[test]
    fn rejects_external_helper_by_default() {
        let mut manifest = sample_manifest();
        manifest.entry.kind = EntryKind::ExternalHelper;
        let err = manifest
            .validate(&ValidationPolicy {
                allow_unsigned_first_party: false,
                allow_executable_helpers: false,
                trusted_public_keys: BTreeMap::new(),
            })
            .err();
        assert!(matches!(err, Some(IntegrationError::ExternalHelperDisabled)));
    }

    #[test]
    fn detects_manifest_hash_mismatch() {
        let mut manifest = sample_manifest();
        manifest.hashes.manifest = Some("blake3:not-the-hash".to_string());
        let err = manifest.validate(&ValidationPolicy::default()).err();
        assert!(matches!(err, Some(IntegrationError::ManifestHashMismatch { .. })));
    }

    #[test]
    fn verifies_signature_with_keyring() -> Result<(), IntegrationError> {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.to_bytes());
        let mut manifest = sample_manifest();
        let signature = signing_key.sign(&manifest.signing_payload()?);
        manifest.signature = Some(SignatureEnvelope {
            alg: "ed25519".to_string(),
            passport_fpr: "p_test".to_string(),
            public_key_hex: None,
            sig: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        });
        let mut trusted_public_keys = BTreeMap::new();
        trusted_public_keys.insert("p_test".to_string(), public_key_hex);

        manifest.validate(&ValidationPolicy {
            allow_unsigned_first_party: false,
            allow_executable_helpers: false,
            trusted_public_keys,
        })?;
        Ok(())
    }

    #[test]
    fn rejects_tampered_signature() -> Result<(), IntegrationError> {
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut manifest = sample_manifest();
        let signature = signing_key.sign(&manifest.signing_payload()?);
        manifest.summary = "Tampered after signing.".to_string();
        manifest.signature = Some(SignatureEnvelope {
            alg: "ed25519".to_string(),
            passport_fpr: "p_test".to_string(),
            public_key_hex: Some(hex::encode(verifying_key.to_bytes())),
            sig: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        });
        let err = manifest
            .validate(&ValidationPolicy {
                allow_unsigned_first_party: false,
                allow_executable_helpers: false,
                trusted_public_keys: BTreeMap::new(),
            })
            .err();
        assert!(matches!(err, Some(IntegrationError::SignatureInvalid)));
        Ok(())
    }

    #[test]
    fn install_grant_disable_roundtrip_persists() -> Result<(), IntegrationError> {
        let root = temp_data_dir("grant-roundtrip");
        let mut manifest = builtin_manifests()
            .into_iter()
            .find(|manifest| manifest.id == "sdk.typescript.quickstart")
            .expect("builtin manifest");
        manifest.hashes.manifest = Some(manifest.manifest_hash()?);

        let descriptor = install_pack(
            &root,
            &manifest,
            TrustTier::FirstParty,
            1_000,
            &ValidationPolicy::default(),
        )?;
        assert_eq!(descriptor.install_state, InstallState::Installed);

        let grant = grant_pack(
            &root,
            GrantPackRequest {
                passport_fpr: "p_local",
                granted_by_passport_fpr: "p_local",
                pack_id: "sdk.typescript.quickstart",
                version: "0.1.0",
                capabilities: &["facts:read".to_string(), "facts:write".to_string()],
                reason: Some("test".to_string()),
                now_unix_ms: 2_000,
            },
        )?;
        assert!(grant.enabled);

        let snapshot = library_snapshot(&root, "p_local", &ValidationPolicy::default())?;
        let pack = snapshot
            .packs
            .iter()
            .find(|pack| pack.manifest.id == "sdk.typescript.quickstart")
            .expect("installed pack in snapshot");
        assert_eq!(pack.install_state, InstallState::Enabled);
        assert_eq!(snapshot.grants.len(), 1);
        assert_eq!(snapshot.audit_tail.len(), 2);

        let disabled = disable_pack(
            &root,
            "p_local",
            "sdk.typescript.quickstart",
            Some("off".to_string()),
            3_000,
        )?;
        assert!(!disabled.enabled);
        assert_eq!(disabled.disabled_at_unix_ms, Some(3_000));

        let snapshot = library_snapshot(&root, "p_local", &ValidationPolicy::default())?;
        let pack = snapshot
            .packs
            .iter()
            .find(|pack| pack.manifest.id == "sdk.typescript.quickstart")
            .expect("disabled pack in snapshot");
        assert_eq!(pack.install_state, InstallState::Installed);
        assert_eq!(snapshot.audit_tail.len(), 3);
        Ok(())
    }

    #[test]
    fn grant_rejects_capability_not_declared_by_pack() -> Result<(), IntegrationError> {
        let root = temp_data_dir("capability-subset");
        let manifest = builtin_manifests()
            .into_iter()
            .find(|manifest| manifest.id == "mcp.cursor")
            .expect("builtin manifest");
        install_pack(
            &root,
            &manifest,
            TrustTier::FirstParty,
            1_000,
            &ValidationPolicy::default(),
        )?;

        let err = grant_pack(
            &root,
            GrantPackRequest {
                passport_fpr: "p_local",
                granted_by_passport_fpr: "p_local",
                pack_id: "mcp.cursor",
                version: "0.1.0",
                capabilities: &["facts:write".to_string()],
                reason: None,
                now_unix_ms: 2_000,
            },
        )
        .err();
        assert!(matches!(
            err,
            Some(IntegrationError::CapabilityNotDeclared {
                pack_id,
                capability
            }) if pack_id == "mcp.cursor" && capability == "facts:write"
        ));
        Ok(())
    }
}
